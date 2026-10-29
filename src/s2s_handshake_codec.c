#include "neura/s2s_handshake.h"

#include "neura/s2s_crypto.h"

#include <string.h>
#include <time.h>

#define HS_TYPE_HELLO NS2S_HS_TYPE_HELLO
#define HS_TYPE_ACK NS2S_HS_TYPE_ACK
#define HS_TYPE_FINISH NS2S_HS_TYPE_FINISH
#define HS_TYPE_READY NS2S_HS_TYPE_READY

#define HS_MAGIC NS2S_HS_MAGIC
#define HS_CLOCK_SKEW_MS 3000u

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) (ts.tv_nsec / 1000000);
}

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static void put_u64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t) v;
        v >>= 8;
    }
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

size_t ns2s_hs_msg_len(uint8_t type) {
    switch (type) {
    case HS_TYPE_HELLO: return NS2S_HS_HELLO_BYTES;
    case HS_TYPE_ACK: return NS2S_HS_ACK_BYTES;
    case HS_TYPE_FINISH: return NS2S_HS_FINISH_BYTES;
    case HS_TYPE_READY: return NS2S_HS_READY_BYTES;
    default: return 0;
    }
}

static void write_common(uint8_t *p, uint8_t type, uint8_t dir, uint8_t alg,
                         uint64_t ts, const uint8_t nonce[NS2S_HS_NONCE_BYTES]) {
    put_u32(p, HS_MAGIC);
    p[4] = NS2S_VERSION;
    p[5] = type;
    p[6] = dir;
    p[7] = alg;
    put_u64(p + 8, ts);
    memcpy(p + 16, nonce, NS2S_HS_NONCE_BYTES);
}

static int parse_common(const uint8_t *in, size_t len, uint8_t type, uint8_t dir,
                        uint8_t *alg, uint64_t *ts,
                        uint8_t nonce[NS2S_HS_NONCE_BYTES]) {
    if (in == NULL || len != ns2s_hs_msg_len(type) || len < NS2S_HS_COMMON_BYTES) {
        return NS2S_ERR_LENGTH;
    }
    if (get_u32(in) != HS_MAGIC || in[4] != NS2S_VERSION ||
        in[5] != type || in[6] != dir) {
        return NS2S_ERR_INVALID;
    }
    if (alg != NULL) {
        *alg = in[7];
    }
    if (ts != NULL) {
        *ts = get_u64(in + 8);
        uint64_t n = now_ms();
        uint64_t d = *ts > n ? *ts - n : n - *ts;
        if (*ts == 0 || d > HS_CLOCK_SKEW_MS) {
            return NS2S_ERR_INVALID;
        }
    }
    if (nonce != NULL) {
        memcpy(nonce, in + 16, NS2S_HS_NONCE_BYTES);
    }
    return NS2S_OK;
}

static int mac_hex(uint8_t out[NS2S_HMAC_BYTES],
                   const uint8_t *key, size_t key_len,
                   const char *label,
                   const uint8_t *th, size_t th_len,
                   const uint8_t *body, size_t body_len) {
    ns2s_hmac_sha512 h;
    ns2s_hmac_sha512_init(&h, key, key_len);
    ns2s_hmac_sha512_update(&h, (const uint8_t *) label, strlen(label));
    if (th != NULL && th_len > 0) {
        ns2s_hmac_sha512_update(&h, th, th_len);
    }
    ns2s_hmac_sha512_update(&h, body, body_len);
    int rc = ns2s_hmac_sha512_final(&h, out);
    sodium_memzero(&h, sizeof(h));
    return rc;
}

static void transcript_next(uint8_t out[NS2S_SHA512_BYTES],
                            const uint8_t *th, size_t th_len,
                            const uint8_t *body, size_t body_len) {
    ns2s_sha512 h;
    ns2s_sha512_init(&h);
    if (th != NULL && th_len > 0) {
        ns2s_sha512_update(&h, th, th_len);
    }
    ns2s_sha512_update(&h, body, body_len);
    ns2s_sha512_final(&h, out);
}

static int check_downgrade(const ns2s_handshake *hs, uint8_t alg) {
    if (!ns2s_alg_supported(alg)) {
        return NS2S_ERR_DOWNGRADE;
    }
    if ((hs->alg_mask & alg) == 0u) {
        return NS2S_ERR_DOWNGRADE;
    }
    return NS2S_OK;
}

int ns2s_hs_encode_hello(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len) {
    if (hs == NULL || out == NULL || out_len == NULL ||
        cap < NS2S_HS_HELLO_BYTES || hs->role != NS2S_ROLE_CLIENT) {
        return NS2S_ERR_INVALID;
    }
    ns2s_random_bytes(hs->hello_nonce, sizeof(hs->hello_nonce));
    write_common(out, HS_TYPE_HELLO, NS2S_DIR_C2S, hs->alg_mask, now_ms(), hs->hello_nonce);
    memcpy(out + NS2S_HS_COMMON_BYTES, hs->tx.client_pk, NS2S_XWING_PK_BYTES);
    size_t body_len = NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES;
    int rc = mac_hex(out + body_len, hs->root_key, sizeof(hs->root_key),
                     "neura-s2s-v1/hello", NULL, 0, out, body_len);
    if (rc != NS2S_OK) {
        return rc;
    }
    transcript_next(hs->transcript, NULL, 0, out, body_len);
    *out_len = body_len + NS2S_HMAC_BYTES;
    return NS2S_OK;
}

int ns2s_hs_decode_hello(ns2s_handshake *hs, const uint8_t *in, size_t len) {
    if (hs == NULL || hs->role != NS2S_ROLE_SERVER) {
        return NS2S_ERR_INVALID;
    }
    ns2s_hs_state saved = hs->state;
    uint8_t alg = 0;
    uint64_t ts = 0;
    int rc = parse_common(in, len, HS_TYPE_HELLO, NS2S_DIR_C2S, &alg, &ts, hs->hello_nonce);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (alg == 0) {
        return NS2S_ERR_DOWNGRADE;
    }
    uint8_t supported = 0;
    if ((alg & NS2S_ALG_AES256GCM) != 0u && ns2s_alg_supported(NS2S_ALG_AES256GCM)) {
        supported = 1;
    }
    if ((alg & NS2S_ALG_CHACHA20POLY1305) != 0u &&
        ns2s_alg_supported(NS2S_ALG_CHACHA20POLY1305)) {
        supported = 1;
    }
    if (!supported) {
        return NS2S_ERR_DOWNGRADE;
    }
    size_t body_len = NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES;
    uint8_t want[NS2S_HMAC_BYTES];
    rc = mac_hex(want, hs->root_key, sizeof(hs->root_key),
                 "neura-s2s-v1/hello", NULL, 0, in, body_len);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (ns2s_hmac_sha512_verify(want, in + body_len) != NS2S_OK) {
        return NS2S_ERR_AUTH;
    }
    /* MAC 通过后再做 nonce 去重，避免未认证流量污染状态。
     * 单条目即可挡住"同一连接上重放同一条 hello"这一实际攻击。 */
    if (hs->seen_nonce_valid != 0 &&
        sodium_memcmp(hs->seen_nonce, in + 16, NS2S_HS_NONCE_BYTES) == 0) {
        return NS2S_ERR_REPLAY;
    }
    memcpy(hs->seen_nonce, in + 16, NS2S_HS_NONCE_BYTES);
    hs->seen_nonce_valid = 1;

    hs->alg_mask = alg;
    hs->alg = ns2s_alg_select(alg);
    if (hs->alg == 0) {
        return NS2S_ERR_DOWNGRADE;
    }
    memcpy(hs->tx.client_pk, in + NS2S_HS_COMMON_BYTES, NS2S_XWING_PK_BYTES);
    transcript_next(hs->transcript, NULL, 0, in, body_len);
    hs->state = saved;
    (void) ts;
    return NS2S_OK;
}

int ns2s_hs_encode_ack(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len) {
    if (hs == NULL || out == NULL || out_len == NULL ||
        cap < NS2S_HS_ACK_BYTES || hs->role != NS2S_ROLE_SERVER || hs->alg == 0) {
        return NS2S_ERR_INVALID;
    }
    ns2s_random_bytes(hs->ack_nonce, sizeof(hs->ack_nonce));
    write_common(out, HS_TYPE_ACK, NS2S_DIR_S2C, hs->alg, now_ms(), hs->ack_nonce);
    memcpy(out + NS2S_HS_COMMON_BYTES, hs->tx.server_pk, NS2S_XWING_PK_BYTES);
    memcpy(out + NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES,
           hs->tx.server_ct, NS2S_XWING_CT_BYTES);
    size_t body_len = NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES;
    int rc = mac_hex(out + body_len, hs->root_key, sizeof(hs->root_key),
                     "neura-s2s-v1/ack", hs->transcript, sizeof(hs->transcript), out, body_len);
    if (rc != NS2S_OK) {
        return rc;
    }
    transcript_next(hs->transcript, hs->transcript, sizeof(hs->transcript), out, body_len);
    *out_len = body_len + NS2S_HMAC_BYTES;
    return NS2S_OK;
}

int ns2s_hs_decode_ack(ns2s_handshake *hs, const uint8_t *in, size_t len) {
    if (hs == NULL || hs->role != NS2S_ROLE_CLIENT) {
        return NS2S_ERR_INVALID;
    }
    uint8_t alg = 0;
    uint64_t ts = 0;
    int rc = parse_common(in, len, HS_TYPE_ACK, NS2S_DIR_S2C, &alg, &ts, hs->ack_nonce);
    if (rc != NS2S_OK) {
        return rc;
    }
    rc = check_downgrade(hs, alg);
    if (rc != NS2S_OK) {
        return rc;
    }
    size_t body_len = NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES;
    uint8_t want[NS2S_HMAC_BYTES];
    rc = mac_hex(want, hs->root_key, sizeof(hs->root_key),
                 "neura-s2s-v1/ack", hs->transcript, sizeof(hs->transcript), in, body_len);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (ns2s_hmac_sha512_verify(want, in + body_len) != NS2S_OK) {
        return NS2S_ERR_AUTH;
    }
    hs->flags &= (uint32_t) ~NS2S_HS_FLAG_VERIFIED;
    hs->alg = alg;
    memcpy(hs->tx.server_pk, in + NS2S_HS_COMMON_BYTES, NS2S_XWING_PK_BYTES);
    memcpy(hs->tx.server_ct, in + NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES,
           NS2S_XWING_CT_BYTES);
    transcript_next(hs->transcript, hs->transcript, sizeof(hs->transcript), in, body_len);
    (void) ts;
    return NS2S_OK;
}

int ns2s_hs_encode_finish(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len) {
    if (hs == NULL || out == NULL || out_len == NULL ||
        cap < NS2S_HS_FINISH_BYTES || hs->role != NS2S_ROLE_CLIENT || hs->alg == 0) {
        return NS2S_ERR_INVALID;
    }
    ns2s_random_bytes(hs->finish_nonce, sizeof(hs->finish_nonce));
    write_common(out, HS_TYPE_FINISH, NS2S_DIR_C2S, hs->alg, now_ms(), hs->finish_nonce);
    memcpy(out + NS2S_HS_COMMON_BYTES, hs->tx.client_ct, NS2S_XWING_CT_BYTES);
    size_t body_len = NS2S_HS_COMMON_BYTES + NS2S_XWING_CT_BYTES;
    int rc = mac_hex(out + body_len, hs->c2s_key, sizeof(hs->c2s_key),
                     "neura-s2s-v1/finish", hs->transcript, sizeof(hs->transcript), out, body_len);
    if (rc != NS2S_OK) {
        return rc;
    }
    transcript_next(hs->transcript, hs->transcript, sizeof(hs->transcript), out, body_len);
    *out_len = body_len + NS2S_HMAC_BYTES;
    return NS2S_OK;
}

int ns2s_hs_decode_finish(ns2s_handshake *hs, const uint8_t *in, size_t len) {
    if (hs == NULL || hs->role != NS2S_ROLE_SERVER) {
        return NS2S_ERR_INVALID;
    }
    uint8_t alg = 0;
    uint64_t ts = 0;
    int rc = parse_common(in, len, HS_TYPE_FINISH, NS2S_DIR_C2S, &alg, &ts, hs->finish_nonce);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (alg != hs->alg) {
        return NS2S_ERR_DOWNGRADE;
    }
    size_t body_len = NS2S_HS_COMMON_BYTES + NS2S_XWING_CT_BYTES;
    /* 新的 finish 到达 → 之前的验证结果立即失效，必须重新 verify。 */
    hs->flags &= (uint32_t) ~NS2S_HS_FLAG_VERIFIED;
    memcpy(hs->tx.client_ct, in + NS2S_HS_COMMON_BYTES, NS2S_XWING_CT_BYTES);
    memcpy(hs->pending_body, in, body_len);
    hs->pending_body_len = body_len;
    memcpy(hs->pending_mac, in + body_len, NS2S_HMAC_BYTES);
    memcpy(hs->th_before_finish, hs->transcript, sizeof(hs->th_before_finish));
    (void) ts;
    return NS2S_OK;
}

int ns2s_hs_verify_finish(ns2s_handshake *hs) {
    if (hs == NULL || hs->pending_body_len == 0 ||
        hs->pending_body_len > sizeof(hs->pending_body)) {
        return NS2S_ERR_STATE;
    }
    uint8_t want[NS2S_HMAC_BYTES];
    int rc = mac_hex(want, hs->c2s_key, sizeof(hs->c2s_key),
                     "neura-s2s-v1/finish",
                     hs->th_before_finish, sizeof(hs->th_before_finish),
                     hs->pending_body, hs->pending_body_len);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (ns2s_hmac_sha512_verify(want, hs->pending_mac) != NS2S_OK) {
        hs->flags &= (uint32_t) ~NS2S_HS_FLAG_VERIFIED;
        return NS2S_ERR_AUTH;
    }
    transcript_next(hs->transcript, hs->th_before_finish, sizeof(hs->th_before_finish),
                    hs->pending_body, hs->pending_body_len);
    hs->flags |= NS2S_HS_FLAG_VERIFIED;
    return NS2S_OK;
}

int ns2s_hs_encode_ready(ns2s_handshake *hs, uint8_t *out, size_t cap, size_t *out_len) {
    if (hs == NULL || out == NULL || out_len == NULL ||
        cap < NS2S_HS_READY_BYTES || hs->role != NS2S_ROLE_SERVER || hs->alg == 0) {
        return NS2S_ERR_INVALID;
    }
    ns2s_random_bytes(hs->ready_nonce, sizeof(hs->ready_nonce));
    write_common(out, HS_TYPE_READY, NS2S_DIR_S2C, hs->alg, now_ms(), hs->ready_nonce);
    int rc = mac_hex(out + NS2S_HS_COMMON_BYTES, hs->s2c_key, sizeof(hs->s2c_key),
                     "neura-s2s-v1/ready", hs->transcript, sizeof(hs->transcript),
                     out, NS2S_HS_COMMON_BYTES);
    if (rc != NS2S_OK) {
        return rc;
    }
    transcript_next(hs->transcript, hs->transcript, sizeof(hs->transcript),
                    out, NS2S_HS_COMMON_BYTES);
    *out_len = NS2S_HS_READY_BYTES;
    return NS2S_OK;
}

int ns2s_hs_decode_ready(ns2s_handshake *hs, const uint8_t *in, size_t len) {
    if (hs == NULL || hs->role != NS2S_ROLE_CLIENT) {
        return NS2S_ERR_INVALID;
    }
    uint8_t alg = 0;
    uint64_t ts = 0;
    int rc = parse_common(in, len, HS_TYPE_READY, NS2S_DIR_S2C, &alg, &ts, hs->ready_nonce);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (alg != hs->alg) {
        return NS2S_ERR_DOWNGRADE;
    }
    uint8_t want[NS2S_HMAC_BYTES];
    rc = mac_hex(want, hs->s2c_key, sizeof(hs->s2c_key),
                 "neura-s2s-v1/ready", hs->transcript, sizeof(hs->transcript),
                 in, NS2S_HS_COMMON_BYTES);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (ns2s_hmac_sha512_verify(want, in + NS2S_HS_COMMON_BYTES) != NS2S_OK) {
        hs->flags &= (uint32_t) ~NS2S_HS_FLAG_VERIFIED;
        return NS2S_ERR_AUTH;
    }
    /* ready 的 HMAC 就是客户端侧的"密钥确认"；据此置位 VERIFIED，
     * 状态机才允许 READY_RX → ESTABLISHED（服务端对应 finish 的 verify）。 */
    hs->flags |= NS2S_HS_FLAG_VERIFIED;
    transcript_next(hs->transcript, hs->transcript, sizeof(hs->transcript),
                    in, NS2S_HS_COMMON_BYTES);
    (void) ts;
    return NS2S_OK;
}
