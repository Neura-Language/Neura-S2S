/*
 * Neura-S2S 握手状态机。
 *
 * 协议（X-Wing = X25519 + ML-KEM-768）：
 *
 *   C -> S  hello : magic|ver|alg_mask|nonce|pk_c|HMAC_RK(transcript)
 *   S -> C  ack   : magic|ver|alg|nonce|pk_s|ct_s|HMAC_RK(transcript)
 *   C -> S  finish: magic|ver|alg|nonce|ct_c|HMAC_SK_c2s(transcript)
 *   S -> C  ready : magic|ver|alg|nonce|HMAC_SK_s2c(transcript)
 *
 *   ss = ss_s || ss_c
 *   RK0 = HKDF-SHA512(ikm=ss, salt=RK, info="neura-s2s-v1/init-root", 64)
 *   SK_c2s / SK_s2c = HKDF-SHA512(RK0, info=".../c2s" / ".../s2c", 32)
 *
 * 关键并发约束：
 *   - Reactor 线程只做 epoll/帧解析/状态推进；
 *   - X-Wing keypair/Encaps/Decaps 全部投递给 ns2s_kem_pool 的后台 worker；
 *   - worker 完成后通过 eventfd 唤醒 Reactor，Reactor 只消费结果，
 *     绝不在 epoll 线程里执行 KEM。
 */
#ifndef NEURA_S2S_HANDSHAKE_H
#define NEURA_S2S_HANDSHAKE_H

#include "neura/s2s.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NS2S_HS_MAGIC 0x4e533248u /* "NS2H" */
#define NS2S_HS_TYPE_HELLO 0x01u
#define NS2S_HS_TYPE_ACK 0x02u
#define NS2S_HS_TYPE_FINISH 0x03u
#define NS2S_HS_TYPE_READY 0x04u

#define NS2S_HS_NONCE_BYTES 16u
#define NS2S_HS_MAC_BYTES NS2S_HMAC_BYTES
#define NS2S_HS_MAX_PEERS 2u
#define NS2S_HS_FLAG_KEM_INFLIGHT 0x01u
#define NS2S_HS_FLAG_VERIFIED 0x02u

#define NS2S_HS_COMMON_BYTES 32u /* magic4|ver1|type1|dir1|alg1|ts8|nonce16 */
#define NS2S_HS_HELLO_BYTES (NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES + NS2S_HMAC_BYTES)
#define NS2S_HS_ACK_BYTES (NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES + NS2S_HMAC_BYTES)
#define NS2S_HS_FINISH_BYTES (NS2S_HS_COMMON_BYTES + NS2S_XWING_CT_BYTES + NS2S_HMAC_BYTES)
#define NS2S_HS_READY_BYTES (NS2S_HS_COMMON_BYTES + NS2S_HMAC_BYTES)
#define NS2S_HS_MAX_BODY (NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES)
#define NS2S_HS_SALT_BYTES (2u * NS2S_XWING_PK_BYTES + 2u * NS2S_XWING_CT_BYTES)

typedef enum {
    NS2S_HS_INIT = 0,
    NS2S_HS_KEM_CLIENT_HELLO,  /* client: 后台生成 X-Wing keypair */
    NS2S_HS_HELLO_SENT,        /* client: hello 已发出 */
    NS2S_HS_KEM_CLIENT_FINISH, /* client: Decaps(ct_s)+Encaps(pk_s)+KDF 后台执行 */
    NS2S_HS_FINISH_SENT,       /* client: finish 已发出 */
    NS2S_HS_READY_RX,          /* client: ready 已收到 */
    NS2S_HS_KEM_SERVER_ACK,    /* server: keypair+Encaps(pk_c) 后台执行 */
    NS2S_HS_ACK_SENT,          /* server: ack 已发出 */
    NS2S_HS_KEM_SERVER_FINISH, /* server: Decaps(ct_c)+KDF 后台执行 */
    NS2S_HS_READY_SENT,        /* server: ready 已发出 */
    NS2S_HS_ESTABLISHED,
    NS2S_HS_FAILED
} ns2s_hs_state;

typedef enum {
    NS2S_HS_EV_START = 1,
    NS2S_HS_EV_HELLO_RX,
    NS2S_HS_EV_ACK_RX,
    NS2S_HS_EV_FINISH_RX,
    NS2S_HS_EV_READY_RX,
    NS2S_HS_EV_READY_SENT,
    NS2S_HS_EV_KEM_DONE,
    NS2S_HS_EV_IO_ERROR,
    NS2S_HS_EV_TIMEOUT,
    NS2S_HS_EV_PROTO_ERROR
} ns2s_hs_event;

typedef enum {
    NS2S_HS_ACT_NONE = 0,
    NS2S_HS_ACT_START_KEM_CLIENT_HELLO,
    NS2S_HS_ACT_SEND_HELLO,
    NS2S_HS_ACT_START_KEM_SERVER_ACK,
    NS2S_HS_ACT_SEND_ACK,
    NS2S_HS_ACT_START_KEM_CLIENT_FINISH,
    NS2S_HS_ACT_SEND_FINISH,
    NS2S_HS_ACT_START_KEM_SERVER_FINISH,
    NS2S_HS_ACT_SEND_READY,
    NS2S_HS_ACT_ESTABLISHED,
    NS2S_HS_ACT_FAIL_CLOSE
} ns2s_hs_action;

typedef enum {
    NS2S_KEM_PHASE_NONE = 0,
    NS2S_KEM_PHASE_CLIENT_HELLO,
    NS2S_KEM_PHASE_SERVER_ACK,
    NS2S_KEM_PHASE_CLIENT_FINISH,
    NS2S_KEM_PHASE_SERVER_FINISH,
    NS2S_KEM_PHASE_RATCHET_OFFER,
    NS2S_KEM_PHASE_RATCHET_ENC,
    NS2S_KEM_PHASE_RATCHET_DEC
} ns2s_kem_phase;

typedef enum {
    NS2S_KEM_OP_KEYPAIR = 1,
    NS2S_KEM_OP_ENC,
    NS2S_KEM_OP_DEC
} ns2s_kem_op;

/* 握手过程中公开传输的 KEM 材料。它们不是秘密，但参与 transcript/KDF salt。 */
typedef struct {
    uint8_t client_pk[NS2S_XWING_PK_BYTES];
    uint8_t server_pk[NS2S_XWING_PK_BYTES];
    uint8_t client_ct[NS2S_XWING_CT_BYTES];
    uint8_t server_ct[NS2S_XWING_CT_BYTES];
} ns2s_hs_transcript_keys;

/*
 * 核心握手上下文。
 *
 * 该结构包含 RootKey、X-Wing 私钥、共享秘密、RK0、方向密钥，
 * 必须由 ns2s_secure_alloc() 分配（mlock + MADV_DONTDUMP），
 * 生命周期结束时 ns2s_handshake_destroy() 使用 sodium_memzero 清理。
 */
typedef struct {
    ns2s_role role;
    ns2s_hs_state state;
    ns2s_hs_event last_event;
    ns2s_hs_action pending_action;
    ns2s_kem_phase kem_phase;
    uint32_t flags;

    uint8_t alg_mask;       /* client: 支持的 alg 位图；server: 选择结果 */
    uint8_t alg;            /* 实际协商结果 */
    uint8_t hello_nonce[NS2S_HS_NONCE_BYTES];
    uint8_t ack_nonce[NS2S_HS_NONCE_BYTES];
    uint8_t finish_nonce[NS2S_HS_NONCE_BYTES];
    uint8_t ready_nonce[NS2S_HS_NONCE_BYTES];

    uint8_t root_key[NS2S_ROOT_KEY_BYTES];

    uint8_t client_sk[NS2S_XWING_SK_BYTES];
    uint8_t server_sk[NS2S_XWING_SK_BYTES];
    uint8_t ss_client[NS2S_XWING_SS_BYTES];
    uint8_t ss_server[NS2S_XWING_SS_BYTES];

    uint8_t rk0[NS2S_ROOT_BYTES];
    uint8_t c2s_key[NS2S_KEY_BYTES];
    uint8_t s2c_key[NS2S_KEY_BYTES];

    ns2s_hs_transcript_keys tx;
    uint8_t transcript[NS2S_SHA512_BYTES];
    uint8_t seen_nonce[NS2S_HS_NONCE_BYTES]; /* hello 重放去重（同一连接内） */
    uint8_t seen_nonce_valid;
    uint8_t th_before_finish[NS2S_SHA512_BYTES];
    uint8_t pending_body[NS2S_HS_MAX_BODY];
    size_t pending_body_len;
    uint8_t pending_mac[NS2S_HMAC_BYTES];

    uint64_t started_ms;
    uint64_t deadline_ms;
    uint64_t kem_epoch;
    int last_status;

    struct ns2s_kem_job *kem_inflight;
} ns2s_handshake;

/*
 * 后台 KEM 任务。job 拥有所有输入/输出缓冲区，避免 worker 读取
 * 可能已被 Reactor 释放的 handshake 内存。
 */
typedef struct ns2s_kem_job {
    ns2s_kem_op op;
    ns2s_kem_phase phase;
    uint64_t epoch;

    uint8_t pk[NS2S_XWING_PK_BYTES];
    uint8_t sk[NS2S_XWING_SK_BYTES];
    uint8_t ct[NS2S_XWING_CT_BYTES];
    uint8_t ss[NS2S_XWING_SS_BYTES];
    uint8_t ss_peer[NS2S_XWING_SS_BYTES];

    uint8_t peer_pk[NS2S_XWING_PK_BYTES];
    uint8_t peer_ct[NS2S_XWING_CT_BYTES];

    /* 用于把手握 KDF 也放到 worker：公开材料 + RootKey + 派生结果。 */
    uint8_t own_pk[NS2S_XWING_PK_BYTES];
    uint8_t client_pk[NS2S_XWING_PK_BYTES];
    uint8_t server_pk[NS2S_XWING_PK_BYTES];
    uint8_t client_ct[NS2S_XWING_CT_BYTES];
    uint8_t server_ct[NS2S_XWING_CT_BYTES];
    uint8_t root_key[NS2S_ROOT_KEY_BYTES];
    uint8_t old_root[NS2S_ROOT_BYTES];
    uint32_t ratchet_id;
    uint8_t ratchet_mac[NS2S_HMAC_BYTES];
    uint8_t rk0[NS2S_ROOT_BYTES];
    uint8_t c2s_key[NS2S_KEY_BYTES];
    uint8_t s2c_key[NS2S_KEY_BYTES];
    uint8_t derive_keys;

    void *owner;       /* 可选的 Reactor/连接上下文 */
    uint64_t conn_id;

    int status;
    int completion_fd; /* eventfd：worker 写 1 唤醒 Reactor */
    struct ns2s_kem_job *next;
} ns2s_kem_job;

/* 初始化/销毁必须通过 secure region；init 不分配内存。 */
void ns2s_handshake_init(ns2s_handshake *hs,
                         ns2s_role role,
                         const uint8_t root_key[NS2S_ROOT_KEY_BYTES],
                         uint8_t alg_mask,
                         uint64_t now_ms);
void ns2s_handshake_reset(ns2s_handshake *hs);
void ns2s_handshake_destroy(ns2s_handshake *hs);

/*
 * 纯状态推进。返回调用方需要执行的动作；不执行网络/KEM 本身。
 * kem_status 仅在 NS2S_HS_EV_KEM_DONE 时使用。
 * 任何非法事件都会把状态置为 FAILED 并返回 FAIL_CLOSE。
 */
ns2s_hs_action ns2s_handshake_step(ns2s_handshake *hs,
                                   ns2s_hs_event ev,
                                   int kem_status);

const char *ns2s_hs_state_name(ns2s_hs_state s);
const char *ns2s_hs_action_name(ns2s_hs_action a);

/* 供 Reactor 使用：把 handshake 中的 KEM 材料/秘密复制到 job。 */
int ns2s_kem_job_from_handshake(ns2s_kem_job *job,
                                const ns2s_handshake *hs,
                                ns2s_kem_phase phase);

/* KEM worker 入口；不直接调用 libsodium 之外的密码学。 */
void ns2s_kem_job_execute(ns2s_kem_job *job);
void ns2s_kem_job_destroy(ns2s_kem_job *job);

/* ---------------- 握手二进制编解码（HMAC transcript） ---------------- */

size_t ns2s_hs_msg_len(uint8_t type);
int ns2s_hs_encode_hello(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len);
int ns2s_hs_decode_hello(ns2s_handshake *hs, const uint8_t *in, size_t len);
int ns2s_hs_encode_ack(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len);
int ns2s_hs_decode_ack(ns2s_handshake *hs, const uint8_t *in, size_t len);
int ns2s_hs_encode_finish(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len);
int ns2s_hs_decode_finish(ns2s_handshake *hs, const uint8_t *in, size_t len);
/*
 * 校验 finish 的 HMAC。必须在 ns2s_hs_apply_kem_job(SERVER_FINISH) 之后调用；
 * 成功后置 NS2S_HS_FLAG_VERIFIED，状态机才会允许进入 READY（漏调即 fail-close）。
 */
int ns2s_hs_verify_finish(ns2s_handshake *hs);

/* 握手超时检查：now_ms 使用与 ns2s_handshake_init 相同的时钟；超时则 FAIL_CLOSE。 */
int ns2s_hs_check_deadline(ns2s_handshake *hs, uint64_t now_ms);
int ns2s_hs_encode_ready(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len);
int ns2s_hs_decode_ready(ns2s_handshake *hs, const uint8_t *in, size_t len);

/* 把 worker 的 KEM/KDF 结果写回 handshake（不执行密码学）。 */
int ns2s_hs_apply_kem_job(ns2s_handshake *hs, const ns2s_kem_job *job);

#ifdef __cplusplus
}
#endif

#endif /* NEURA_S2S_HANDSHAKE_H */
