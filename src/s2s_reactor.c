/*
 * epoll Reactor：握手 + 会话两条路径都由事件驱动。
 *
 * 设计要点（Phase 3）：
 *   - 每条连接在 accept/connect 时初始化 ns2s_handshake，并预置 3s deadline；
 *   - 握手报文（magic "NS2H" + 定长 body）由 conn_hs_pump() 增量解析，
 *     解出事件后交给 ns2s_handshake_step() 推进 FSM；
 *   - X-Wing keypair/Encaps/Decaps 一律进 KEM pool，Reactor 线程只消费结果
 *     （wake_fd/eventfd 唤醒），符合"KEM 不阻塞 epoll"的约束；
 *   - 所有发送（握手报文、数据帧）统一进 tx ring，EAGAIN 时挂 EPOLLOUT；
 *   - FSM 到 ESTABLISHED 时：ns2s_conn_upgrade() → ns2s_session_init() →
 *     session_ready = 1 → on_established()；
 *   - 任何错误只置 dead 标记，由 reactor_sweep() 在本批事件处理完后统一回收，
 *     避免在遍历 events[] 时释放连接造成 UAF。
 */
#include "neura/s2s_reactor.h"

#include "neura/s2s_crypto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <time.h>

#define NS2S_HS_HEAD_PEEK 7u /* magic4 + ver + type + dir */

static uint64_t reactor_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) (ts.tv_nsec / 1000000);
}

/* ============================ KEM worker pool ============================ */

static void *kem_worker(void *arg) {
    ns2s_kem_pool *p = (ns2s_kem_pool *) arg;
    for (;;) {
        pthread_mutex_lock(&p->mu);
        while (p->head == NULL && !p->stopping) {
            pthread_cond_wait(&p->cv, &p->mu);
        }
        if (p->stopping && p->head == NULL) {
            pthread_mutex_unlock(&p->mu);
            return NULL;
        }
        ns2s_kem_job *job = p->head;
        p->head = job->next;
        if (p->head == NULL) {
            p->tail = NULL;
        }
        pthread_mutex_unlock(&p->mu);

        ns2s_kem_job_execute(job);

        pthread_mutex_lock(&p->mu);
        job->next = NULL;
        if (p->done_tail == NULL) {
            p->done_head = job;
        } else {
            p->done_tail->next = job;
        }
        p->done_tail = job;
        pthread_mutex_unlock(&p->mu);
        if (p->completion_fd >= 0) {
            uint64_t one = 1;
            ssize_t n = write(p->completion_fd, &one, sizeof(one));
            (void) n;
        }
    }
}

int ns2s_kem_pool_init(ns2s_kem_pool *p, size_t workers, int completion_fd) {
    if (p == NULL || workers == 0) {
        return NS2S_ERR_INVALID;
    }
    memset(p, 0, sizeof(*p));
    p->completion_fd = completion_fd;
    if (pthread_mutex_init(&p->mu, NULL) != 0) {
        return NS2S_ERR_CRYPTO;
    }
    if (pthread_cond_init(&p->cv, NULL) != 0) {
        pthread_mutex_destroy(&p->mu);
        return NS2S_ERR_CRYPTO;
    }
    p->threads = (pthread_t *) calloc(workers, sizeof(pthread_t));
    if (p->threads == NULL) {
        pthread_cond_destroy(&p->cv);
        pthread_mutex_destroy(&p->mu);
        return NS2S_ERR_NOMEM;
    }
    p->nthreads = workers;
    for (size_t i = 0; i < workers; i++) {
        if (pthread_create(&p->threads[i], NULL, kem_worker, p) != 0) {
            p->stopping = 1;
            pthread_cond_broadcast(&p->cv);
            for (size_t j = 0; j < i; j++) {
                pthread_join(p->threads[j], NULL);
            }
            free(p->threads);
            pthread_cond_destroy(&p->cv);
            pthread_mutex_destroy(&p->mu);
            memset(p, 0, sizeof(*p));
            return NS2S_ERR_CRYPTO;
        }
    }
    return NS2S_OK;
}

int ns2s_kem_pool_submit(ns2s_kem_pool *p, ns2s_kem_job *job) {
    if (p == NULL || job == NULL || p->stopping) {
        return NS2S_ERR_STATE;
    }
    job->next = NULL;
    pthread_mutex_lock(&p->mu);
    if (p->tail == NULL) {
        p->head = job;
    } else {
        p->tail->next = job;
    }
    p->tail = job;
    pthread_cond_signal(&p->cv);
    pthread_mutex_unlock(&p->mu);
    return NS2S_OK;
}

void ns2s_kem_pool_take_done(ns2s_kem_pool *p, ns2s_kem_job **list) {
    if (list == NULL) {
        return;
    }
    *list = NULL;
    if (p == NULL) {
        return;
    }
    pthread_mutex_lock(&p->mu);
    *list = p->done_head;
    p->done_head = NULL;
    p->done_tail = NULL;
    pthread_mutex_unlock(&p->mu);
}

void ns2s_kem_pool_destroy(ns2s_kem_pool *p) {
    if (p == NULL || p->threads == NULL) {
        return;
    }
    pthread_mutex_lock(&p->mu);
    p->stopping = 1;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
    for (size_t i = 0; i < p->nthreads; i++) {
        pthread_join(p->threads[i], NULL);
    }
    /*
     * 关机时队列里可能还有未消费的 job：它们含有 root_key / sk / ss / rk0 /
     * 方向密钥。所有权归调用方（job 由其分配），这里只做零化。
     */
    ns2s_kem_job *pend = p->head;
    while (pend != NULL) {
        ns2s_kem_job *nx = pend->next;
        ns2s_kem_job_destroy(pend);
        pend = nx;
    }
    pend = p->done_head;
    while (pend != NULL) {
        ns2s_kem_job *nx = pend->next;
        ns2s_kem_job_destroy(pend);
        pend = nx;
    }
    p->head = p->tail = p->done_head = p->done_tail = NULL;
    free(p->threads);
    pthread_cond_destroy(&p->cv);
    pthread_mutex_destroy(&p->mu);
    memset(p, 0, sizeof(*p));
}

/* ============================== 连接生命周期 ============================== */

static size_t conn_frame_cap(uint32_t max_frame) {
    return (size_t) max_frame + NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + NS2S_TAG_BYTES;
}

static size_t conn_ring_cap(uint32_t max_frame) {
    return (size_t) max_frame + 4096u;
}

int ns2s_conn_init(ns2s_conn *c,
                   int fd,
                   ns2s_role role,
                   uint32_t max_frame,
                   uint64_t id) {
    if (c == NULL || fd < 0 || max_frame == 0) {
        return NS2S_ERR_INVALID;
    }
    sodium_memzero(c, sizeof(*c));
    c->fd = fd;
    c->role = role;
    c->max_frame = max_frame;
    c->id = id;
    c->created_ms = reactor_now_ms();
    c->last_active_ms = c->created_ms;

    /*
     * 预认证阶段只分配够握手用的小缓冲（NS2S_PREAUTH_CAP）。
     * 握手报文最大 2384 B（ack），8 KiB 足够；会话建立后由
     * ns2s_conn_upgrade() 一次性升级到 max_frame 对应容量。
     */
    size_t full_frame = conn_frame_cap(max_frame);
    size_t cap = full_frame < NS2S_PREAUTH_CAP ? full_frame : (size_t) NS2S_PREAUTH_CAP;
    if (ns2s_ring_init(&c->rx, cap) != 0) {
        return NS2S_ERR_NOMEM;
    }
    if (ns2s_ring_init(&c->tx, cap) != 0) {
        ns2s_ring_free(&c->rx);
        return NS2S_ERR_NOMEM;
    }
    c->frame_cap = cap;
    c->frame_buf = (uint8_t *) malloc(cap);
    c->app_buf = NULL;
    c->app_cap = 0;
    c->tx_frame = (uint8_t *) malloc(cap);
    c->tx_frame_cap = cap;
    if (c->frame_buf == NULL || c->tx_frame == NULL) {
        ns2s_ring_free(&c->tx);
        ns2s_ring_free(&c->rx);
        free(c->frame_buf);
        free(c->tx_frame);
        memset(c, 0, sizeof(*c));
        c->fd = -1;
        return NS2S_ERR_NOMEM;
    }
    if (ns2s_secure_alloc(&c->hs_region, sizeof(ns2s_handshake)) != NS2S_OK) {
        sodium_memzero(c->frame_buf, c->frame_cap);
        free(c->frame_buf);
        sodium_memzero(c->tx_frame, c->tx_frame_cap);
        free(c->tx_frame);
        ns2s_ring_free(&c->tx);
        ns2s_ring_free(&c->rx);
        memset(c, 0, sizeof(*c));
        c->fd = -1;
        return NS2S_ERR_LOCKED;
    }
    c->hs = (ns2s_handshake *) c->hs_region.ptr;
    return NS2S_OK;
}

/*
 * 把预认证缓冲升级为会话缓冲（幂等）。
 * 关键点：app_cap 必须等于实际分配大小，否则 ns2s_session_open() 的
 * out_cap 检查会拒绝所有非空帧，且 destroy 时的零化长度会变成 0。
 */
int ns2s_conn_upgrade(ns2s_conn *c) {
    if (c == NULL || c->max_frame == 0) {
        return NS2S_ERR_INVALID;
    }
    size_t want_frame = conn_frame_cap(c->max_frame);
    size_t want_ring = conn_ring_cap(c->max_frame);
    if (c->app_buf != NULL && c->app_cap >= want_frame && c->frame_cap >= want_frame &&
        c->tx_frame_cap >= want_frame && ns2s_ring_capacity(&c->rx) >= want_ring &&
        ns2s_ring_capacity(&c->tx) >= want_ring) {
        return NS2S_OK;
    }

    uint8_t *nb = (uint8_t *) malloc(want_frame);
    uint8_t *na = (uint8_t *) malloc(want_frame);
    uint8_t *nt = (uint8_t *) malloc(want_frame);
    ns2s_ring nrx;
    ns2s_ring ntx;
    memset(&nrx, 0, sizeof(nrx));
    memset(&ntx, 0, sizeof(ntx));
    if (nb == NULL || na == NULL || nt == NULL ||
        ns2s_ring_init(&nrx, want_ring) != 0 || ns2s_ring_init(&ntx, want_ring) != 0) {
        free(nb);
        free(na);
        free(nt);
        ns2s_ring_free(&nrx);
        ns2s_ring_free(&ntx);
        return NS2S_ERR_NOMEM;
    }
    /* 迁移 rx 中可能残留的字节（正常情况为空）。 */
    size_t pending = ns2s_ring_readable(&c->rx);
    if (pending > want_ring) {
        pending = want_ring;
    }
    if (pending > 0) {
        if (ns2s_ring_read(&c->rx, nrx.data, pending) != (ssize_t) pending) {
            ns2s_ring_free(&nrx);
            ns2s_ring_free(&ntx);
            free(nb);
            free(na);
            free(nt);
            return NS2S_ERR_NOMEM;
        }
        nrx.len = pending;
    }
    /* tx 中排队的数据（握手最后一条报文）也要带过去。 */
    size_t tpend = ns2s_ring_readable(&c->tx);
    if (tpend > want_ring) {
        tpend = want_ring;
    }
    if (tpend > 0) {
        if (ns2s_ring_read(&c->tx, ntx.data, tpend) != (ssize_t) tpend) {
            ns2s_ring_free(&nrx);
            ns2s_ring_free(&ntx);
            free(nb);
            free(na);
            free(nt);
            return NS2S_ERR_NOMEM;
        }
        ntx.len = tpend;
    }
    ns2s_ring_free(&c->rx);
    ns2s_ring_free(&c->tx);
    c->rx = nrx;
    c->tx = ntx;
    if (c->frame_buf != NULL) {
        sodium_memzero(c->frame_buf, c->frame_cap);
        free(c->frame_buf);
    }
    if (c->app_buf != NULL) {
        sodium_memzero(c->app_buf, c->app_cap);
        free(c->app_buf);
    }
    if (c->tx_frame != NULL) {
        sodium_memzero(c->tx_frame, c->tx_frame_cap);
        free(c->tx_frame);
    }
    c->frame_buf = nb;
    c->frame_cap = want_frame;
    c->app_buf = na;
    c->app_cap = want_frame;
    c->tx_frame = nt;
    c->tx_frame_cap = want_frame;
    return NS2S_OK;
}

void ns2s_conn_destroy(ns2s_conn *c) {
    if (c == NULL) {
        return;
    }
    if (c->hs != NULL) {
        ns2s_handshake_destroy(c->hs);
        c->hs = NULL;
    }
    ns2s_secure_free(&c->hs_region);
    if (c->frame_buf != NULL) {
        sodium_memzero(c->frame_buf, c->frame_cap);
        free(c->frame_buf);
    }
    if (c->app_buf != NULL) {
        sodium_memzero(c->app_buf, c->app_cap);
        free(c->app_buf);
    }
    if (c->tx_frame != NULL) {
        sodium_memzero(c->tx_frame, c->tx_frame_cap);
        free(c->tx_frame);
    }
    if (c->rx.data != NULL) {
        sodium_memzero(c->rx.data, c->rx.cap);
    }
    if (c->tx.data != NULL) {
        sodium_memzero(c->tx.data, c->tx.cap);
    }
    ns2s_ring_free(&c->tx);
    ns2s_ring_free(&c->rx);
    if (c->fd >= 0) {
        close(c->fd);
    }
    sodium_memzero(&c->session, sizeof(c->session));
    sodium_memzero(c, sizeof(*c));
    c->fd = -1;
}

ns2s_session *ns2s_conn_session(ns2s_conn *c) {
    if (c == NULL || !c->session_ready) {
        return NULL;
    }
    return &c->session;
}

/* ============================== 发送路径 ============================== */

static int conn_update_events(ns2s_conn *c) {
    if (c->owner == NULL || c->fd < 0) {
        return NS2S_ERR_STATE;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLRDHUP;
    if (c->connecting || ns2s_ring_readable(&c->tx) > 0) {
        ev.events |= EPOLLOUT;
    }
    ev.data.ptr = c;
    if (epoll_ctl(c->owner->epfd, EPOLL_CTL_MOD, c->fd, &ev) != 0) {
        return NS2S_ERR_IO;
    }
    return NS2S_OK;
}

static int conn_flush_tx(ns2s_conn *c) {
    while (ns2s_ring_readable(&c->tx) > 0) {
        ssize_t n = ns2s_ring_write_fd(&c->tx, c->fd);
        if (n > 0) {
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return conn_update_events(c); /* 等 EPOLLOUT */
        }
        return NS2S_ERR_IO;
    }
    return conn_update_events(c); /* 队列清空 → 取消 EPOLLOUT */
}

static int conn_queue_tx(ns2s_conn *c, const uint8_t *buf, size_t len) {
    if (len == 0) {
        return NS2S_OK;
    }
    if (ns2s_ring_writable(&c->tx) < len) {
        return NS2S_ERR_LENGTH; /* 不静默截断 */
    }
    if (ns2s_ring_write(&c->tx, buf, len) != (ssize_t) len) {
        return NS2S_ERR_IO;
    }
    c->last_active_ms = reactor_now_ms();
    return conn_flush_tx(c);
}

int ns2s_conn_send(ns2s_conn *c, const uint8_t *plaintext, size_t len) {
    if (c == NULL || !c->session_ready) {
        return NS2S_ERR_STATE;
    }
    if (plaintext == NULL && len > 0) {
        return NS2S_ERR_INVALID;
    }
    if (c->tx_frame == NULL) {
        return NS2S_ERR_STATE;
    }
    size_t flen = 0;
    int rc = ns2s_session_seal(&c->session, plaintext, len,
                               c->tx_frame, c->tx_frame_cap, &flen, reactor_now_ms());
    if (rc != NS2S_OK) {
        return rc;
    }
    rc = conn_queue_tx(c, c->tx_frame, flen);
    sodium_memzero(c->tx_frame, c->tx_frame_cap); /* 密文也按敏感数据处理 */
    return rc;
}

/* ============================== 握手胶水层 ============================== */

static int reactor_submit_job(ns2s_reactor *r, ns2s_conn *c, ns2s_kem_job *job);
static int reactor_dispatch_session(ns2s_reactor *r, ns2s_conn *c);

static int conn_hs_submit(ns2s_reactor *r, ns2s_conn *c, ns2s_kem_phase phase) {
    ns2s_kem_job *job = (ns2s_kem_job *) calloc(1, sizeof(*job));
    if (job == NULL) {
        return NS2S_ERR_NOMEM;
    }
    if (ns2s_kem_job_from_handshake(job, c->hs, phase) != NS2S_OK) {
        free(job);
        return NS2S_ERR_STATE;
    }
    return reactor_submit_job(r, c, job);
}

typedef int (*hs_encode_fn)(ns2s_handshake *, uint8_t *, size_t, size_t *);

static int conn_send_hs(ns2s_conn *c, hs_encode_fn enc) {
    /* 编码到 frame_buf：此时 rx 里当前握手报文已被消费，缓冲区空闲。 */
    size_t len = 0;
    int rc = enc(c->hs, c->frame_buf, c->frame_cap, &len);
    if (rc != NS2S_OK) {
        return rc;
    }
    return conn_queue_tx(c, c->frame_buf, len);
}

static int conn_apply_hs_action(ns2s_reactor *r, ns2s_conn *c, ns2s_hs_action act) {
    switch (act) {
    case NS2S_HS_ACT_NONE:
        return NS2S_OK;
    case NS2S_HS_ACT_START_KEM_CLIENT_HELLO:
        return conn_hs_submit(r, c, NS2S_KEM_PHASE_CLIENT_HELLO);
    case NS2S_HS_ACT_SEND_HELLO:
        return conn_send_hs(c, ns2s_hs_encode_hello);
    case NS2S_HS_ACT_START_KEM_SERVER_ACK:
        return conn_hs_submit(r, c, NS2S_KEM_PHASE_SERVER_ACK);
    case NS2S_HS_ACT_SEND_ACK:
        return conn_send_hs(c, ns2s_hs_encode_ack);
    case NS2S_HS_ACT_START_KEM_CLIENT_FINISH:
        return conn_hs_submit(r, c, NS2S_KEM_PHASE_CLIENT_FINISH);
    case NS2S_HS_ACT_SEND_FINISH:
        return conn_send_hs(c, ns2s_hs_encode_finish);
    case NS2S_HS_ACT_START_KEM_SERVER_FINISH:
        return conn_hs_submit(r, c, NS2S_KEM_PHASE_SERVER_FINISH);
    case NS2S_HS_ACT_SEND_READY: {
        int rc = conn_send_hs(c, ns2s_hs_encode_ready);
        if (rc != NS2S_OK) {
            return rc;
        }
        /* ready 已入队 = 服务端密钥确认已发出 → 允许进入 ESTABLISHED。 */
        (void) ns2s_handshake_step(c->hs, NS2S_HS_EV_READY_SENT, 0);
        return NS2S_OK;
    }
    case NS2S_HS_ACT_ESTABLISHED:
        return NS2S_OK;
    case NS2S_HS_ACT_FAIL_CLOSE:
    default:
        return NS2S_ERR_AUTH;
    }
}

/*
 * 握手完成 → 建立业务会话。
 * 严格按 README：先 ns2s_conn_upgrade()，再 ns2s_session_init()，最后置
 * session_ready 并回调 on_established()。
 */
static int conn_establish(ns2s_reactor *r, ns2s_conn *c) {
    if (c->hs == NULL || c->hs->state != NS2S_HS_ESTABLISHED) {
        return NS2S_ERR_STATE;
    }
    c->last_active_ms = reactor_now_ms();
    if (ns2s_conn_upgrade(c) != NS2S_OK) {
        return NS2S_ERR_NOMEM;
    }
    if (ns2s_session_init(&c->session, c->role, c->hs->alg, c->max_frame,
                          c->hs->rk0, c->hs->c2s_key, c->hs->s2c_key,
                          reactor_now_ms()) != NS2S_OK) {
        return NS2S_ERR_STATE;
    }
    /* 与 Go 版一致：0.3s KEM 重置由服务端发起。 */
    c->session.auto_ratchet = (c->role == NS2S_ROLE_SERVER) ? 1 : 0;
    c->session_ready = 1;

    /* 握手密钥已进入 session，擦掉 handshake 里的副本。 */
    sodium_memzero(c->hs->root_key, sizeof(c->hs->root_key));
    sodium_memzero(c->hs->rk0, sizeof(c->hs->rk0));
    sodium_memzero(c->hs->c2s_key, sizeof(c->hs->c2s_key));
    sodium_memzero(c->hs->s2c_key, sizeof(c->hs->s2c_key));
    sodium_memzero(c->hs->client_sk, sizeof(c->hs->client_sk));
    sodium_memzero(c->hs->server_sk, sizeof(c->hs->server_sk));
    sodium_memzero(c->hs->ss_client, sizeof(c->hs->ss_client));
    sodium_memzero(c->hs->ss_server, sizeof(c->hs->ss_server));

    if (r->on_established != NULL) {
        r->on_established(c);
    }
    return NS2S_OK;
}

static int conn_hs_handle(ns2s_reactor *r, ns2s_conn *c, const uint8_t *msg, size_t len) {
    int rc;
    ns2s_hs_event ev;
    uint8_t type = msg[5];

    if (c->role == NS2S_ROLE_SERVER) {
        if (type == NS2S_HS_TYPE_HELLO) {
            ev = NS2S_HS_EV_HELLO_RX;
            rc = ns2s_hs_decode_hello(c->hs, msg, len);
        } else if (type == NS2S_HS_TYPE_FINISH) {
            ev = NS2S_HS_EV_FINISH_RX;
            rc = ns2s_hs_decode_finish(c->hs, msg, len);
        } else {
            return NS2S_ERR_STATE; /* 服务端不接受 ack/ready */
        }
    } else {
        if (type == NS2S_HS_TYPE_ACK) {
            ev = NS2S_HS_EV_ACK_RX;
            rc = ns2s_hs_decode_ack(c->hs, msg, len);
        } else if (type == NS2S_HS_TYPE_READY) {
            ev = NS2S_HS_EV_READY_RX;
            rc = ns2s_hs_decode_ready(c->hs, msg, len);
        } else {
            return NS2S_ERR_STATE;
        }
    }
    if (rc != NS2S_OK) {
        return rc;
    }
    ns2s_hs_action act = ns2s_handshake_step(c->hs, ev, 0);
    rc = conn_apply_hs_action(r, c, act);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (c->hs->state == NS2S_HS_FAILED) {
        return NS2S_ERR_AUTH;
    }
    if (c->hs->state == NS2S_HS_ESTABLISHED && !c->session_ready) {
        return conn_establish(r, c);
    }
    return NS2S_OK;
}

/* 增量解析握手报文：magic 校验 → type 定长 → 凑齐后交给 FSM。 */
static int conn_hs_pump(ns2s_reactor *r, ns2s_conn *c) {
    for (;;) {
        size_t avail = ns2s_ring_readable(&c->rx);
        if (avail < NS2S_HS_HEAD_PEEK) {
            return NS2S_OK;
        }
        uint8_t head[NS2S_HS_HEAD_PEEK];
        if (ns2s_ring_peek(&c->rx, head, sizeof(head)) < 0) {
            return NS2S_ERR_INVALID;
        }
        if (head[0] != 'N' || head[1] != 'S' || head[2] != '2' || head[3] != 'H') {
            return NS2S_ERR_INVALID; /* 未握手就发非握手数据 → fail-close */
        }
        size_t need = ns2s_hs_msg_len(head[5]);
        if (need == 0 || need > c->frame_cap) {
            return NS2S_ERR_INVALID;
        }
        if (avail < need) {
            return NS2S_OK; /* 等更多数据，不分配内存 */
        }
        if (ns2s_ring_peek(&c->rx, c->frame_buf, need) < 0) {
            return NS2S_ERR_INVALID;
        }
        ns2s_ring_consume(&c->rx, need);
        int rc = conn_hs_handle(r, c, c->frame_buf, need);
        if (rc != NS2S_OK) {
            return rc;
        }
        if (c->session_ready) {
            /* 握手完成；同一批读里可能已经带了业务帧。 */
            return reactor_dispatch_session(r, c);
        }
    }
}

/* ============================== 会话数据路径 ============================== */

static int reactor_dispatch_session(ns2s_reactor *r, ns2s_conn *c) {
    /* 会话路径必须用满尺寸缓冲（预认证阶段是小缓冲）。 */
    if (ns2s_conn_upgrade(c) != NS2S_OK) {
        return NS2S_ERR_NOMEM;
    }
    for (;;) {
        if (ns2s_ring_readable(&c->rx) < NS2S_FRAME_HEADER_BYTES) {
            return NS2S_OK;
        }
        uint8_t hdr[NS2S_FRAME_HEADER_BYTES];
        if (ns2s_ring_peek(&c->rx, hdr, sizeof(hdr)) < 0) {
            return NS2S_ERR_INVALID;
        }
        ns2s_frame_header h;
        if (ns2s_frame_header_decode(hdr, &h, c->max_frame) != NS2S_OK) {
            return NS2S_ERR_INVALID;
        }
        size_t total = NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES +
                       (size_t) h.plaintext_len + NS2S_TAG_BYTES;
        if (total > c->frame_cap) {
            return NS2S_ERR_LENGTH;
        }
        if (ns2s_ring_readable(&c->rx) < total) {
            return NS2S_OK; /* 等更多数据 */
        }
        if (ns2s_ring_peek(&c->rx, c->frame_buf, total) < 0) {
            return NS2S_ERR_INVALID;
        }
        ns2s_ring_consume(&c->rx, total);
        size_t app_len = 0;
        int rc = ns2s_session_open(&c->session, c->frame_buf, total,
                                   c->app_buf, c->app_cap, &app_len);
        if (rc != NS2S_OK) {
            return rc;
        }
        c->last_active_ms = reactor_now_ms();
        if (c->session.ctrl_in_len > 0) {
            ns2s_kem_job *job = (ns2s_kem_job *) calloc(1, sizeof(*job));
            if (job == NULL) {
                return NS2S_ERR_NOMEM;
            }
            int submit = 0;
            rc = ns2s_session_consume_control(&c->session, reactor_now_ms(), job, &submit);
            if (rc != NS2S_OK) {
                free(job);
                return rc;
            }
            if (submit) {
                if (reactor_submit_job(r, c, job) != NS2S_OK) {
                    return NS2S_ERR_NOMEM;
                }
            } else {
                free(job);
            }
        }
        if (r->on_app != NULL) {
            r->on_app(c, c->app_buf, app_len);
        }
    }
}

/* ============================== 事件循环 ============================== */

static ns2s_conn *reactor_find_conn(ns2s_reactor *r, uint64_t id) {
    ns2s_conn *found = NULL;
    for (size_t i = 0; i < r->nconns; i++) {
        if (r->conns[i] != NULL && r->conns[i]->id == id) {
            if (found != NULL) {
                return NULL; /* id 冲突：宁可不应用，也不投错会话 */
            }
            found = r->conns[i];
        }
    }
    return found;
}

static void reactor_remove_conn(ns2s_reactor *r, size_t idx) {
    ns2s_conn *c = r->conns[idx];
    epoll_ctl(r->epfd, EPOLL_CTL_DEL, c->fd, NULL);
    ns2s_conn_destroy(c);
    free(c);
    r->conns[idx] = r->conns[r->nconns - 1];
    r->conns[r->nconns - 1] = NULL;
    r->nconns--;
}

/* 统一回收 dead 连接：只在"本批事件全部处理完"之后调用，避免 UAF。 */
static void reactor_sweep(ns2s_reactor *r) {
    for (size_t i = r->nconns; i > 0; i--) {
        if (r->conns[i - 1] != NULL && r->conns[i - 1]->dead) {
            reactor_remove_conn(r, i - 1);
        }
    }
}

static int reactor_submit_job(ns2s_reactor *r, ns2s_conn *c, ns2s_kem_job *job) {
    if (job == NULL) {
        return NS2S_ERR_NOMEM;
    }
    job->conn_id = c->id;
    job->completion_fd = r->wake_fd;
    int rc = ns2s_kem_pool_submit(&r->kem, job);
    if (rc != NS2S_OK) {
        ns2s_kem_job_destroy(job);
        free(job);
    }
    return rc;
}

/* 握手阶段 KEM 完成：apply → (server) verify_finish → step → 发送/建会话。 */
static int conn_hs_kem_done(ns2s_reactor *r, ns2s_conn *c, const ns2s_kem_job *job) {
    int rc;
    if (job->status != NS2S_OK) {
        (void) ns2s_handshake_step(c->hs, NS2S_HS_EV_KEM_DONE, job->status);
        return NS2S_ERR_AUTH;
    }
    rc = ns2s_hs_apply_kem_job(c->hs, job);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (job->phase == NS2S_KEM_PHASE_SERVER_FINISH) {
        /* finish 的密钥确认必须在状态机进入 READY 之前完成（C-04）。 */
        rc = ns2s_hs_verify_finish(c->hs);
        if (rc != NS2S_OK) {
            return rc;
        }
    }
    ns2s_hs_action act = ns2s_handshake_step(c->hs, NS2S_HS_EV_KEM_DONE, NS2S_OK);
    rc = conn_apply_hs_action(r, c, act);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (c->hs->state == NS2S_HS_FAILED) {
        return NS2S_ERR_AUTH;
    }
    if (c->hs->state == NS2S_HS_ESTABLISHED && !c->session_ready) {
        return conn_establish(r, c);
    }
    return NS2S_OK;
}

/* KEM 完成 → 推进握手或应用 ratchet。失败只 mark dead，不在此处释放连接。 */
static void reactor_drain_kem(ns2s_reactor *r) {
    ns2s_kem_job *jobs = NULL;
    ns2s_kem_pool_take_done(&r->kem, &jobs);
    while (jobs != NULL) {
        ns2s_kem_job *next = jobs->next;
        ns2s_conn *c = reactor_find_conn(r, jobs->conn_id);
        if (c != NULL && !c->dead) {
            int rc;
            if (jobs->phase == NS2S_KEM_PHASE_RATCHET_OFFER ||
                jobs->phase == NS2S_KEM_PHASE_RATCHET_ENC ||
                jobs->phase == NS2S_KEM_PHASE_RATCHET_DEC) {
                rc = ns2s_session_apply_ratchet_job(&c->session, jobs, reactor_now_ms());
            } else {
                rc = conn_hs_kem_done(r, c, jobs);
            }
            if (rc != NS2S_OK) {
                c->dead = 1;
            }
        }
        ns2s_kem_job_destroy(jobs);
        free(jobs);
        jobs = next;
    }
}

static void reactor_tick(ns2s_reactor *r, uint64_t now_ms) {
    /* 预认证阶段超时的连接：不允许长期占用连接槽位（C-05）。 */
    for (size_t i = 0; i < r->nconns; i++) {
        ns2s_conn *c = r->conns[i];
        if (c == NULL || c->dead || c->session_ready) {
            continue;
        }
        int expired = 0;
        if (c->hs != NULL && c->hs->deadline_ms != 0 &&
            ns2s_hs_check_deadline(c->hs, now_ms) != NS2S_OK) {
            expired = 1;
        }
        if (c->created_ms != 0 && now_ms > c->created_ms &&
            now_ms - c->created_ms > NS2S_HANDSHAKE_TIMEOUT_MS) {
            expired = 1;
        }
        if (expired) {
            c->dead = 1;
        }
    }
    for (size_t i = 0; i < r->nconns; i++) {
        ns2s_conn *c = r->conns[i];
        if (c == NULL || c->dead || !c->session_ready) {
            continue;
        }
        ns2s_kem_job *job = (ns2s_kem_job *) calloc(1, sizeof(*job));
        if (job == NULL) {
            continue;
        }
        int need = ns2s_session_ratchet_tick(&c->session, now_ms, job);
        if (need == 1) {
            if (reactor_submit_job(r, c, job) != NS2S_OK) {
                continue;
            }
        } else {
            free(job);
        }
    }
    reactor_sweep(r);
}

static void reactor_accept(ns2s_reactor *r) {
    for (;;) {
        int fd = accept4(r->listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            return;
        }
        if (!r->have_root || r->nconns >= r->max_conns) {
            close(fd); /* 没有 RootKey 就绝不进入握手（无明文降级） */
            continue;
        }
        ns2s_conn *c = (ns2s_conn *) calloc(1, sizeof(*c));
        if (c == NULL) {
            close(fd);
            continue;
        }
        if (ns2s_conn_init(c, fd, NS2S_ROLE_SERVER, r->max_frame, r->next_conn_id++) != NS2S_OK) {
            close(fd);
            free(c);
            continue;
        }
        c->owner = r;
        ns2s_handshake_init(c->hs, NS2S_ROLE_SERVER, r->root_key, 0, reactor_now_ms());
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = c;
        if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
            ns2s_conn_destroy(c);
            free(c);
            continue;
        }
        r->conns[r->nconns++] = c;
    }
}

static void reactor_read_conn(ns2s_reactor *r, ns2s_conn *c) {
    ssize_t n = ns2s_ring_read_fd(&c->rx, c->fd);
    if (n == 0) {
        c->dead = 1; /* EOF */
        return;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            return; /* 暂不可读 / ring 满：等下次 EPOLLIN */
        }
        c->dead = 1;
        return;
    }
    int rc = c->session_ready ? reactor_dispatch_session(r, c) : conn_hs_pump(r, c);
    if (rc != NS2S_OK) {
        c->dead = 1;
    }
}

/* 非阻塞 connect 完成：检查 SO_ERROR，然后开始客户端握手。 */
static int conn_finish_connect(ns2s_conn *c) {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
        return NS2S_ERR_IO;
    }
    c->connecting = 0;
    ns2s_hs_action act = ns2s_handshake_step(c->hs, NS2S_HS_EV_START, 0);
    return conn_apply_hs_action(c->owner, c, act);
}

int ns2s_reactor_init(ns2s_reactor *r,
                      uint32_t max_frame,
                      size_t max_conns,
                      size_t kem_workers,
                      ns2s_frame_cb on_frame,
                      ns2s_app_cb on_app) {
    if (r == NULL || max_frame == 0 || max_conns == 0 || kem_workers == 0) {
        return NS2S_ERR_INVALID;
    }
    memset(r, 0, sizeof(*r));
    r->listen_fd = -1;
    r->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (r->wake_fd < 0) {
        return NS2S_ERR_IO;
    }
    r->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (r->epfd < 0) {
        close(r->wake_fd);
        return NS2S_ERR_IO;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = &r->wake_fd;
    if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, r->wake_fd, &ev) != 0) {
        close(r->epfd);
        close(r->wake_fd);
        return NS2S_ERR_IO;
    }
    r->max_frame = max_frame;
    r->max_conns = max_conns;
    r->next_conn_id = 1; /* 单调递增，回收连接后也不复用 */
    r->on_frame = on_frame;
    r->on_app = on_app;
    r->conns = (ns2s_conn **) calloc(max_conns, sizeof(ns2s_conn *));
    if (r->conns == NULL) {
        close(r->epfd);
        close(r->wake_fd);
        return NS2S_ERR_NOMEM;
    }
    if (pthread_mutex_init(&r->task_mu, NULL) != 0) {
        free(r->conns);
        close(r->epfd);
        close(r->wake_fd);
        return NS2S_ERR_CRYPTO;
    }
    if (ns2s_kem_pool_init(&r->kem, kem_workers, r->wake_fd) != NS2S_OK) {
        pthread_mutex_destroy(&r->task_mu);
        free(r->conns);
        close(r->epfd);
        close(r->wake_fd);
        return NS2S_ERR_CRYPTO;
    }
    r->running = 1;
    return NS2S_OK;
}

int ns2s_reactor_set_root_key(ns2s_reactor *r, const uint8_t root_key[NS2S_ROOT_KEY_BYTES]) {
    if (r == NULL || root_key == NULL) {
        return NS2S_ERR_INVALID;
    }
    memcpy(r->root_key, root_key, NS2S_ROOT_KEY_BYTES);
    r->have_root = 1;
    return NS2S_OK;
}

void ns2s_reactor_set_on_established(ns2s_reactor *r, ns2s_established_cb cb) {
    if (r != NULL) {
        r->on_established = cb;
    }
}

int ns2s_reactor_listen(ns2s_reactor *r, const char *host, uint16_t port) {
    if (r == NULL) {
        return NS2S_ERR_INVALID;
    }
    if (!r->have_root) {
        return NS2S_ERR_STATE; /* 没有 RootKey 不允许进入网络模式 */
    }
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned) port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return NS2S_ERR_IO;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 128) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        return NS2S_ERR_IO;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = &r->listen_fd;
    if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        close(fd);
        return NS2S_ERR_IO;
    }
    r->listen_fd = fd;
    return NS2S_OK;
}

uint16_t ns2s_reactor_port(const ns2s_reactor *r) {
    if (r == NULL || r->listen_fd < 0) {
        return 0;
    }
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(r->listen_fd, (struct sockaddr *) &ss, &sl) != 0) {
        return 0;
    }
    if (ss.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *) &ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) &ss)->sin6_port);
    }
    return 0;
}

int ns2s_reactor_connect(ns2s_reactor *r, const char *host, uint16_t port,
                         const uint8_t root_key[NS2S_ROOT_KEY_BYTES], uint64_t *out_id) {
    if (r == NULL || host == NULL || root_key == NULL || r->nconns >= r->max_conns) {
        return NS2S_ERR_INVALID;
    }
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned) port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return NS2S_ERR_IO;
    }
    int fd = -1;
    int inprogress = 0;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            inprogress = 0;
            break;
        }
        if (errno == EINPROGRESS) {
            inprogress = 1;
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        return NS2S_ERR_IO;
    }
    ns2s_conn *c = (ns2s_conn *) calloc(1, sizeof(*c));
    if (c == NULL) {
        close(fd);
        return NS2S_ERR_NOMEM;
    }
    if (ns2s_conn_init(c, fd, NS2S_ROLE_CLIENT, r->max_frame, r->next_conn_id++) != NS2S_OK) {
        close(fd);
        free(c);
        return NS2S_ERR_NOMEM;
    }
    c->owner = r;
    c->connecting = inprogress ? 1 : 0;
    ns2s_handshake_init(c->hs, NS2S_ROLE_CLIENT, root_key, 0, reactor_now_ms());
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT;
    ev.data.ptr = c;
    if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        ns2s_conn_destroy(c);
        free(c);
        close(fd);
        return NS2S_ERR_IO;
    }
    r->conns[r->nconns++] = c;
    if (out_id != NULL) {
        *out_id = c->id;
    }
    if (c->connecting == 0) {
        ns2s_hs_action act = ns2s_handshake_step(c->hs, NS2S_HS_EV_START, 0);
        if (conn_apply_hs_action(r, c, act) != NS2S_OK) {
            c->dead = 1;
            return NS2S_ERR_STATE;
        }
    }
    return NS2S_OK;
}

static void reactor_run_tasks(ns2s_reactor *r) {
    struct ns2s_task *list;
    pthread_mutex_lock(&r->task_mu);
    list = r->task_head;
    r->task_head = NULL;
    r->task_tail = NULL;
    pthread_mutex_unlock(&r->task_mu);
    while (list != NULL) {
        struct ns2s_task *next = list->next;
        list->fn(r, list->arg);
        free(list);
        list = next;
    }
}

int ns2s_reactor_run(ns2s_reactor *r) {
    if (r == NULL || r->epfd < 0) {
        return NS2S_ERR_INVALID;
    }
    struct epoll_event events[64];
    r->running = 1;
    while (r->running) {
        uint64_t now_ms = reactor_now_ms();
        reactor_tick(r, now_ms);
        int n = epoll_wait(r->epfd, events, 64, 50);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NS2S_ERR_IO;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.ptr == &r->wake_fd) {
                uint64_t v;
                while (read(r->wake_fd, &v, sizeof(v)) > 0) {
                }
                reactor_run_tasks(r);
                reactor_drain_kem(r);
                continue;
            }
            if (events[i].data.ptr == &r->listen_fd) {
                reactor_accept(r);
                continue;
            }
            ns2s_conn *c = (ns2s_conn *) events[i].data.ptr;
            if (c == NULL || c->dead) {
                continue;
            }
            if ((events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
                c->dead = 1;
                continue;
            }
            if ((events[i].events & EPOLLOUT) != 0) {
                if (c->connecting) {
                    if (conn_finish_connect(c) != NS2S_OK) {
                        c->dead = 1;
                        continue;
                    }
                }
                if (conn_flush_tx(c) != NS2S_OK) {
                    c->dead = 1;
                    continue;
                }
            }
            if ((events[i].events & EPOLLIN) != 0 && !c->dead) {
                reactor_read_conn(r, c);
            }
        }
        reactor_sweep(r);
    }
    return NS2S_OK;
}

int ns2s_reactor_post(ns2s_reactor *r, ns2s_task_fn fn, void *arg) {
    if (r == NULL || fn == NULL) {
        return NS2S_ERR_INVALID;
    }
    struct ns2s_task *t = (struct ns2s_task *) calloc(1, sizeof(*t));
    if (t == NULL) {
        return NS2S_ERR_NOMEM;
    }
    t->fn = fn;
    t->arg = arg;
    pthread_mutex_lock(&r->task_mu);
    if (r->task_tail == NULL) {
        r->task_head = t;
    } else {
        r->task_tail->next = t;
    }
    r->task_tail = t;
    pthread_mutex_unlock(&r->task_mu);
    uint64_t one = 1;
    ssize_t n = write(r->wake_fd, &one, sizeof(one));
    (void) n;
    return NS2S_OK;
}

void ns2s_reactor_stop(ns2s_reactor *r) {
    if (r != NULL) {
        r->running = 0;
        uint64_t one = 1;
        ssize_t n = write(r->wake_fd, &one, sizeof(one));
        (void) n;
    }
}

void ns2s_reactor_destroy(ns2s_reactor *r) {
    if (r == NULL) {
        return;
    }
    ns2s_kem_pool_destroy(&r->kem);
    {
        struct ns2s_task *t = r->task_head;
        while (t != NULL) {
            struct ns2s_task *nx = t->next;
            free(t);
            t = nx;
        }
        pthread_mutex_destroy(&r->task_mu);
    }
    for (size_t i = 0; i < r->nconns; i++) {
        if (r->conns[i] != NULL) {
            epoll_ctl(r->epfd, EPOLL_CTL_DEL, r->conns[i]->fd, NULL);
            ns2s_conn_destroy(r->conns[i]);
            free(r->conns[i]);
        }
    }
    free(r->conns);
    if (r->listen_fd >= 0) {
        close(r->listen_fd);
    }
    if (r->epfd >= 0) {
        close(r->epfd);
    }
    if (r->wake_fd >= 0) {
        close(r->wake_fd);
    }
    sodium_memzero(r->root_key, sizeof(r->root_key));
    memset(r, 0, sizeof(*r));
    r->epfd = r->listen_fd = r->wake_fd = -1;
}

/* --------- 自管理帧格式的应用仍可使用下面这个解析器（Reactor 不再调用） --------- */

int ns2s_conn_parse_frames(ns2s_conn *c, ns2s_frame_cb cb) {
    if (c == NULL) {
        return NS2S_ERR_INVALID;
    }
    for (;;) {
        if (ns2s_ring_readable(&c->rx) < NS2S_FRAME_HEADER_BYTES) {
            return NS2S_OK;
        }
        uint8_t header_bytes[NS2S_FRAME_HEADER_BYTES];
        if (ns2s_ring_peek(&c->rx, header_bytes, sizeof(header_bytes)) < 0) {
            return NS2S_ERR_INVALID;
        }
        ns2s_frame_header h;
        int rc = ns2s_frame_header_decode(header_bytes, &h, c->max_frame);
        if (rc != NS2S_OK) {
            return rc;
        }
        size_t total = NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES +
                       (size_t) h.plaintext_len + NS2S_TAG_BYTES;
        if (total > c->frame_cap) {
            return NS2S_ERR_LENGTH;
        }
        if (ns2s_ring_readable(&c->rx) < total) {
            return NS2S_OK;
        }
        if (ns2s_ring_peek(&c->rx, c->frame_buf, total) < 0) {
            return NS2S_ERR_INVALID;
        }
        ns2s_ring_consume(&c->rx, total);
        if (cb != NULL) {
            const uint8_t *payload = c->frame_buf + NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES;
            cb(c, &h, payload, (size_t) h.plaintext_len + NS2S_TAG_BYTES);
        }
    }
}
