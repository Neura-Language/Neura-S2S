/*
 * Neura-S2S C11 公共定义。
 *
 * 设计约束：
 *   - 所有密码学原语来自 libsodium 1.0.22（X-Wing = X25519 + ML-KEM-768、
 *     AES-256-GCM / ChaCha20-Poly1305 IETF、HKDF-SHA512、HMAC-SHA512）；
 *   - 任何密钥字节只能通过 sodium_memzero 清理；
 *   - 帧解析必须先校验长度，再分配/解密；
 *   - 网络层使用 epoll Reactor，KEM 在独立 worker pool 执行。
 */
#ifndef NEURA_S2S_H
#define NEURA_S2S_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NS2S_VERSION 0x01u

#define NS2S_ROOT_KEY_BYTES 32u
#define NS2S_KEY_BYTES 32u
#define NS2S_ROOT_BYTES 64u
#define NS2S_NONCE_BYTES 12u
#define NS2S_TAG_BYTES 16u
#define NS2S_HMAC_BYTES 64u
#define NS2S_SHA512_BYTES 64u
#define NS2S_RANDOM_NONCE_BYTES 16u

/* libsodium 1.0.22 crypto_kem_xwing 参数（见 s2s_crypto.c 的 _Static_assert）。 */
#define NS2S_XWING_PK_BYTES 1216u
#define NS2S_XWING_SK_BYTES 32u
#define NS2S_XWING_CT_BYTES 1120u
#define NS2S_XWING_SS_BYTES 32u

/* 帧头：[ver][alg][dir][seq:4][ratchet_id:4][plaintext_len:4] */
#define NS2S_FRAME_HEADER_BYTES 15u
#define NS2S_FRAME_VERSION 0x01u

/*
 * 默认最大明文帧 1 MiB。连接建立时一次性分配 Ring/帧缓冲；
 * 任何线上长度字段都必须先与此值比较，禁止“先 malloc 再校验”。
 */
#define NS2S_DEFAULT_MAX_FRAME (1u << 20)
#define NS2S_DEFAULT_RING_CAPACITY (NS2S_DEFAULT_MAX_FRAME + 4096u)

/*
 * 预认证阶段（尚未完成握手）每条连接只分配这么多缓冲：
 * 握手消息最大 NS2S_HS_ACK_BYTES（2384 B），8 KiB 足够。
 * 会话建立后由 ns2s_conn_upgrade() 一次性升级到 max_frame 对应的容量，
 * 避免"未认证的 connect() 就吃掉 4 MiB"的内存放大。
 */
#define NS2S_PREAUTH_CAP (8u << 10)

/* 握手超时：预认证连接超过该时长未完成握手即回收。 */
#define NS2S_HANDSHAKE_TIMEOUT_MS 3000u

/* session 生命周期哨兵：destroy 后为 0，任何继续调用都被拒绝。 */
#define NS2S_SESSION_MAGIC 0x4e533253u /* "NS2S" */

#define NS2S_HANDSHAKE_MAGIC 0x4e533248u /* "NS2H" */

typedef enum {
    NS2S_OK = 0,
    NS2S_ERR_INVALID = -1,
    NS2S_ERR_LENGTH = -2,
    NS2S_ERR_AUTH = -3,
    NS2S_ERR_STATE = -4,
    NS2S_ERR_AGAIN = -5,
    NS2S_ERR_NOMEM = -6,
    NS2S_ERR_CRYPTO = -7,
    NS2S_ERR_WOULD_BLOCK = -8,
    NS2S_ERR_REPLAY = -9,
    NS2S_ERR_DOWNGRADE = -10,
    NS2S_ERR_LOCKED = -11,
    NS2S_ERR_IO = -12
} ns2s_status;

typedef enum {
    NS2S_ROLE_CLIENT = 0x01,
    NS2S_ROLE_SERVER = 0x02
} ns2s_role;

typedef enum {
    NS2S_DIR_C2S = 0x01,
    NS2S_DIR_S2C = 0x02
} ns2s_dir;

typedef enum {
    NS2S_ALG_AES256GCM = 0x01,
    NS2S_ALG_CHACHA20POLY1305 = 0x02
} ns2s_alg;

typedef struct {
    uint8_t version;
    uint8_t alg;
    uint8_t dir;
    uint32_t seq;
    uint32_t ratchet_id;
    uint32_t plaintext_len;
} ns2s_frame_header;

/* 单方向消息链。key 是当前消息密钥，每发/收一帧后立即 HKDF 棘轮。 */
typedef struct {
    uint32_t ratchet_id;
    uint32_t seq;
    uint8_t key[NS2S_KEY_BYTES];
} ns2s_chain_key;

/* 会话 AEAD/消息链棘轮。密钥必须位于 secure region。 */
typedef enum {
    NS2S_RATCHET_IDLE = 0,
    NS2S_RATCHET_OFFER_KEM,   /* server: X-Wing keypair 后台生成中 */
    NS2S_RATCHET_OFFER_READY, /* server: 可捎带 offer */
    NS2S_RATCHET_CIPHER_KEM,  /* client: Encaps / server: Decaps 后台中 */
    NS2S_RATCHET_CIPHER_READY,/* client: ct 已就绪，可捎带 cipher */
    NS2S_RATCHET_CONFIRM_READY/* server: confirm 已就绪 */
} ns2s_ratchet_phase;

#define NS2S_CTRL_MAX (1u + 4u + NS2S_XWING_PK_BYTES)

typedef enum {
    NS2S_CTRL_OFFER = 1,
    NS2S_CTRL_CIPHER = 2,
    NS2S_CTRL_CONFIRM = 3
} ns2s_ctrl_kind;

typedef struct {
    ns2s_ratchet_phase phase;
    uint32_t id;
    uint64_t started_ms;
    uint8_t server_pk[NS2S_XWING_PK_BYTES];
    uint8_t server_sk[NS2S_XWING_SK_BYTES];
    uint8_t server_ct[NS2S_XWING_CT_BYTES];
    uint8_t client_pk[NS2S_XWING_PK_BYTES];
    uint8_t client_ct[NS2S_XWING_CT_BYTES];
    uint8_t peer_ct[NS2S_XWING_CT_BYTES];
    uint8_t new_root[NS2S_ROOT_BYTES];
    uint8_t new_c2s[NS2S_KEY_BYTES];
    uint8_t new_s2c[NS2S_KEY_BYTES];
    uint8_t confirm_mac[NS2S_HMAC_BYTES];
    uint8_t transcript[NS2S_SHA512_BYTES];
    uint8_t offer_sent;
    uint8_t cipher_sent;
    uint8_t confirm_sent;
} ns2s_ratchet_state;

typedef struct {
    uint32_t magic; /* NS2S_SESSION_MAGIC；destroy 后归零，用于拒绝误用 */
    ns2s_role role;
    uint8_t alg;
    uint32_t max_frame;

    uint8_t root[NS2S_ROOT_BYTES];
    ns2s_chain_key send;
    ns2s_chain_key recv;

    uint32_t current_ratchet_id;
    uint32_t next_ratchet_id;
    uint64_t last_reset_ms;
    uint64_t ratchet_timeout_ms;
    uint8_t auto_ratchet;
    uint8_t closed;
    uint8_t reserved[6];

    ns2s_ratchet_state ratchet;
    uint8_t ctrl_in[NS2S_CTRL_MAX];
    size_t ctrl_in_len;
} ns2s_session;

int ns2s_session_init(ns2s_session *s,
                      ns2s_role role,
                      uint8_t alg,
                      uint32_t max_frame,
                      const uint8_t root[NS2S_ROOT_BYTES],
                      const uint8_t c2s[NS2S_KEY_BYTES],
                      const uint8_t s2c[NS2S_KEY_BYTES],
                      uint64_t now_ms);
void ns2s_session_destroy(ns2s_session *s);

/*
 * 发送/接收应用帧。返回 NS2S_OK 或错误。
 * 发送成功后旧链密钥立即 sodium_memzero，并用 HKDF-SHA512 推进 seq||dir。
 */
int ns2s_session_seal(ns2s_session *s,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *out, size_t out_cap, size_t *out_len,
                      uint64_t now_ms);

int ns2s_session_open(ns2s_session *s,
                      const uint8_t *frame, size_t frame_len,
                      uint8_t *out, size_t out_cap, size_t *out_len);

struct ns2s_kem_job;

/*
 * 0.3s KEM 重置：
 *   ratchet_tick       返回 1 表示已填充 job，需要调用方提交到 KEM pool；
 *                      返回 0 表示无需动作。
 *   consume_control    解析 open() 缓存的 control，返回 1 表示需要提交 job。
 *   apply_ratchet_job  KEM worker 完成后由 Reactor 调用，不执行 KEM。
 */
int ns2s_session_ratchet_tick(ns2s_session *s, uint64_t now_ms, struct ns2s_kem_job *job);
int ns2s_session_consume_control(ns2s_session *s, uint64_t now_ms,
                                 struct ns2s_kem_job *job, int *need_submit);
int ns2s_session_apply_ratchet_job(ns2s_session *s,
                                   const struct ns2s_kem_job *job,
                                   uint64_t now_ms);


/* 仅用于日志/观测的常量指纹，不包含密钥。 */
typedef struct {
    uint8_t bytes[16];
} ns2s_fingerprint;

int ns2s_init(void);

int ns2s_frame_header_encode(uint8_t out[NS2S_FRAME_HEADER_BYTES],
                             const ns2s_frame_header *h);

/*
 * 解析并校验帧头。这是所有 malloc/解密之前的唯一入口。
 * max_frame 必须由连接配置提供，禁止使用线上字段作为上限。
 */
int ns2s_frame_header_decode(const uint8_t in[NS2S_FRAME_HEADER_BYTES],
                             ns2s_frame_header *out,
                             uint32_t max_frame);

/* 期望 dir 与当前角色匹配；seq 必须精确等于 expect_seq。 */
int ns2s_frame_validate(const ns2s_frame_header *h,
                        ns2s_role role,
                        uint32_t expect_seq,
                        uint32_t current_ratchet_id);

#ifdef __cplusplus
}
#endif

#endif /* NEURA_S2S_H */
