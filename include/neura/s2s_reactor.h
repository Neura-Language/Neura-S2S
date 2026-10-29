/* epoll Reactor + 固定 Ring Buffer + KEM worker pool + 握手胶水层。 */
#ifndef NEURA_S2S_REACTOR_H
#define NEURA_S2S_REACTOR_H

#include "neura/s2s_handshake.h"
#include "neura/s2s_ring.h"
#include "neura/s2s_secure_mem.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ns2s_conn ns2s_conn;
typedef struct ns2s_reactor ns2s_reactor;

/*
 * KEM worker pool。Reactor 只 submit + 等待 eventfd，不在 epoll 线程内
 * 执行 X-Wing keypair/Encaps/Decaps。
 */
typedef struct ns2s_kem_pool {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    ns2s_kem_job *head;
    ns2s_kem_job *tail;
    ns2s_kem_job *done_head;
    ns2s_kem_job *done_tail;
    pthread_t *threads;
    size_t nthreads;
    int completion_fd;
    int stopping;
} ns2s_kem_pool;

/* 连接上下文。hs 必须位于 secure region；ring/frame_buf 是普通缓冲区。 */
struct ns2s_conn {
    int fd;
    uint64_t id;
    ns2s_role role;
    uint32_t max_frame;

    uint64_t created_ms;     /* accept/connect 时刻，用于预认证超时回收 */
    uint64_t last_active_ms; /* 最近一次收发时刻（观测用） */

    ns2s_ring rx;
    ns2s_ring tx; /* 写回队列：握手报文与业务帧都由它排队 */
    uint8_t *frame_buf;
    size_t frame_cap;
    uint8_t *app_buf; /* 解密输出 */
    size_t app_cap;
    uint8_t *tx_frame; /* 加密输出暂存（seal 需要连续缓冲） */
    size_t tx_frame_cap;

    int session_ready; /* 1 = 握手完成，业务帧走 AEAD 路径 */
    int connecting;    /* 1 = TCP 连接建立中（客户端） */
    int dead;          /* 1 = 待回收（延后到本批事件处理完） */

    ns2s_secure_region hs_region;
    ns2s_handshake *hs;
    ns2s_session session;
    ns2s_reactor *owner;
    void *user;
};

/* 回调都在 Reactor 线程执行；payload/plaintext 生命周期仅本次回调。 */
typedef void (*ns2s_frame_cb)(ns2s_conn *conn,
                              const ns2s_frame_header *h,
                              const uint8_t *payload,
                              size_t payload_len);
typedef void (*ns2s_app_cb)(ns2s_conn *conn, const uint8_t *plaintext, size_t len);
/* 握手完成、session 可用时回调（之后可以调用 ns2s_conn_send）。 */
typedef void (*ns2s_established_cb)(ns2s_conn *conn);

/*
 * 跨线程投递任务到 Reactor 线程执行（内部走 eventfd 唤醒）。
 * 用途：应用需要从其他线程安全地调用 ns2s_conn_send() 时（session 非线程安全）。
 */
typedef void (*ns2s_task_fn)(ns2s_reactor *r, void *arg);

struct ns2s_task {
    ns2s_task_fn fn;
    void *arg;
    struct ns2s_task *next;
};

struct ns2s_reactor {
    int epfd;
    int listen_fd;
    int wake_fd; /* eventfd：KEM worker 完成唤醒 */
    int running;

    uint32_t max_frame;
    size_t max_conns;
    size_t nconns;
    uint64_t next_conn_id; /* 单调递增，避免回收后 id 复用 */
    ns2s_conn **conns;

    uint8_t root_key[NS2S_ROOT_KEY_BYTES]; /* 握手信任锚；未设置则拒绝 listen/accept */
    uint8_t have_root;

    ns2s_kem_pool kem;
    ns2s_frame_cb on_frame; /* 仅用于自管理帧格式的应用；Reactor 内部不再使用 */
    ns2s_app_cb on_app;
    ns2s_established_cb on_established;

    pthread_mutex_t task_mu;
    struct ns2s_task *task_head;
    struct ns2s_task *task_tail;
};

int ns2s_reactor_init(ns2s_reactor *r,
                      uint32_t max_frame,
                      size_t max_conns,
                      size_t kem_workers,
                      ns2s_frame_cb on_frame,
                      ns2s_app_cb on_app);

/* RootKey：必须在 listen/connect 之前设置；没有它不可能完成握手（无明文降级）。 */
int ns2s_reactor_set_root_key(ns2s_reactor *r, const uint8_t root_key[NS2S_ROOT_KEY_BYTES]);
void ns2s_reactor_set_on_established(ns2s_reactor *r, ns2s_established_cb cb);

/*
 * 监听。要求已经 set_root_key：未配置 RootKey 的节点拒绝进入网络模式。
 * 端口可以是 0（内核分配），用 ns2s_reactor_port() 取实际端口。
 */
int ns2s_reactor_listen(ns2s_reactor *r, const char *host, uint16_t port);
uint16_t ns2s_reactor_port(const ns2s_reactor *r);

/*
 * 主动连接（客户端）。root_key 用于握手；连接完成 + 握手完成后走 on_established。
 * 非阻塞 connect：立即返回，进度由 epoll 驱动。
 */
int ns2s_reactor_connect(ns2s_reactor *r, const char *host, uint16_t port,
                         const uint8_t root_key[NS2S_ROOT_KEY_BYTES], uint64_t *out_id);

/* 把 fn(arg) 投递到 Reactor 线程执行；线程安全。 */
int ns2s_reactor_post(ns2s_reactor *r, ns2s_task_fn fn, void *arg);

int ns2s_reactor_run(ns2s_reactor *r);
void ns2s_reactor_stop(ns2s_reactor *r);
void ns2s_reactor_destroy(ns2s_reactor *r);

int ns2s_conn_init(ns2s_conn *c,
                   int fd,
                   ns2s_role role,
                   uint32_t max_frame,
                   uint64_t id);
void ns2s_conn_destroy(ns2s_conn *c);

/*
 * 握手成功后把预认证小缓冲升级到 max_frame 对应的容量（幂等）。
 * Reactor 在进入会话路径前会自动调用；自管理帧格式的应用也可自行调用。
 */
int ns2s_conn_upgrade(ns2s_conn *c);

/* 已建立会话的连接：加密并排队一条业务帧（Reactor 线程内外均可调用）。 */
int ns2s_conn_send(ns2s_conn *c, const uint8_t *plaintext, size_t len);

/* 已建立会话时的 session（未建立返回 NULL）。 */
ns2s_session *ns2s_conn_session(ns2s_conn *c);

/*
 * 从 rx ring 解析一条"数据帧"（AEAD 帧头格式）。
 * Reactor 内部已改用握手/会话两条路径，此函数保留给自管理帧格式的应用。
 * 严格顺序：可读长度 >= header → decode 校验长度 → 可读长度 >= 整帧 →
 * 复制到固定 frame_buf 后回调；解析路径不 malloc。
 */
int ns2s_conn_parse_frames(ns2s_conn *c, ns2s_frame_cb cb);

int ns2s_kem_pool_init(ns2s_kem_pool *p, size_t workers, int completion_fd);
int ns2s_kem_pool_submit(ns2s_kem_pool *p, ns2s_kem_job *job);
void ns2s_kem_pool_take_done(ns2s_kem_pool *p, ns2s_kem_job **list);
void ns2s_kem_pool_destroy(ns2s_kem_pool *p);

#ifdef __cplusplus
}
#endif

#endif /* NEURA_S2S_REACTOR_H */
