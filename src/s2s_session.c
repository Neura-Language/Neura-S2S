#include "neura/s2s.h"

#include "neura/s2s_crypto.h"
#include "neura/s2s_handshake.h"

#include <string.h>

#define RATCHET_PERIOD_MS 300u

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t) (v >> 8);
    p[1] = (uint8_t) v;
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t) ((uint16_t) p[0] << 8 | p[1]);
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

static int chain_advance(ns2s_chain_key *c, uint8_t dir) {
    uint8_t salt[5];
    salt[0] = (uint8_t) (c->seq >> 24);
    salt[1] = (uint8_t) (c->seq >> 16);
    salt[2] = (uint8_t) (c->seq >> 8);
    salt[3] = (uint8_t) c->seq;
    salt[4] = dir;
    uint8_t next[NS2S_KEY_BYTES];
    int rc = ns2s_hkdf_sha512(c->key, sizeof(c->key), salt, sizeof(salt),
                              "neura-s2s-v1/chain", strlen("neura-s2s-v1/chain"),
                              next, sizeof(next));
    /* 旧消息密钥立即清零，不论 HKDF 是否成功。 */
    sodium_memzero(c->key, sizeof(c->key));
    if (rc != NS2S_OK) {
        sodium_memzero(next, sizeof(next));
        return NS2S_ERR_CRYPTO;
    }
    memcpy(c->key, next, sizeof(c->key));
    sodium_memzero(next, sizeof(next));
    c->seq++;
    return NS2S_OK;
}

int ns2s_session_init(ns2s_session *s,
                      ns2s_role role,
                      uint8_t alg,
                      uint32_t max_frame,
                      const uint8_t root[NS2S_ROOT_BYTES],
                      const uint8_t c2s[NS2S_KEY_BYTES],
                      const uint8_t s2c[NS2S_KEY_BYTES],
                      uint64_t now_ms) {
    if (s == NULL || root == NULL || c2s == NULL || s2c == NULL ||
        max_frame == 0 || !ns2s_alg_supported(alg)) {
        return NS2S_ERR_INVALID;
    }
    sodium_memzero(s, sizeof(*s));
    s->role = role;
    s->alg = alg;
    s->max_frame = max_frame;
    memcpy(s->root, root, NS2S_ROOT_BYTES);
    s->current_ratchet_id = 0;
    s->next_ratchet_id = 0;
    s->last_reset_ms = now_ms;
    s->ratchet_timeout_ms = 2000;
    if (role == NS2S_ROLE_CLIENT) {
        memcpy(s->send.key, c2s, NS2S_KEY_BYTES);
        memcpy(s->recv.key, s2c, NS2S_KEY_BYTES);
    } else {
        memcpy(s->send.key, s2c, NS2S_KEY_BYTES);
        memcpy(s->recv.key, c2s, NS2S_KEY_BYTES);
    }
    s->send.ratchet_id = 0;
    s->recv.ratchet_id = 0;
    s->magic = NS2S_SESSION_MAGIC;
    return NS2S_OK;
}

void ns2s_session_destroy(ns2s_session *s) {
    if (s != NULL) {
        /* 先失效哨兵，再整体清零：destroy 之后的任何调用都会被 *_valid() 拒绝，
         * 不会出现"全零密钥继续跑"的静默降级。 */
        s->magic = 0;
        sodium_memzero(s, sizeof(*s));
    }
}

static void session_switch(ns2s_session *s, uint32_t id, uint64_t now_ms) {
    if (s->ratchet.id != id) {
        return;
    }
    sodium_memzero(s->root, sizeof(s->root));
    memcpy(s->root, s->ratchet.new_root, sizeof(s->root));
    s->current_ratchet_id = id;
    s->next_ratchet_id = id;
    sodium_memzero(&s->send, sizeof(s->send));
    sodium_memzero(&s->recv, sizeof(s->recv));
    if (s->role == NS2S_ROLE_CLIENT) {
        memcpy(s->send.key, s->ratchet.new_c2s, NS2S_KEY_BYTES);
        memcpy(s->recv.key, s->ratchet.new_s2c, NS2S_KEY_BYTES);
    } else {
        memcpy(s->send.key, s->ratchet.new_s2c, NS2S_KEY_BYTES);
        memcpy(s->recv.key, s->ratchet.new_c2s, NS2S_KEY_BYTES);
    }
    s->send.ratchet_id = id;
    s->recv.ratchet_id = id;
    s->last_reset_ms = now_ms;
    sodium_memzero(&s->ratchet, sizeof(s->ratchet));
}

static size_t build_offer(ns2s_session *s, uint8_t *out) {
    out[0] = NS2S_CTRL_OFFER;
    put_u32(out + 1, s->ratchet.id);
    memcpy(out + 5, s->ratchet.server_pk, NS2S_XWING_PK_BYTES);
    s->ratchet.offer_sent = 1;
    return 5u + NS2S_XWING_PK_BYTES;
}

static size_t build_cipher(ns2s_session *s, uint8_t *out) {
    out[0] = NS2S_CTRL_CIPHER;
    put_u32(out + 1, s->ratchet.id);
    memcpy(out + 5, s->ratchet.client_ct, NS2S_XWING_CT_BYTES);
    s->ratchet.cipher_sent = 1;
    return 5u + NS2S_XWING_CT_BYTES;
}

static size_t build_confirm(ns2s_session *s, uint8_t *out) {
    out[0] = NS2S_CTRL_CONFIRM;
    put_u32(out + 1, s->ratchet.id);
    memcpy(out + 5, s->ratchet.confirm_mac, NS2S_HMAC_BYTES);
    s->ratchet.confirm_sent = 1;
    return 5u + NS2S_HMAC_BYTES;
}

/* 结构体哨兵：init 之后为 magic，destroy 之后为 0。 */
static int session_valid(const ns2s_session *s) {
    return s != NULL && s->magic == NS2S_SESSION_MAGIC;
}

int ns2s_session_seal(ns2s_session *s,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *out, size_t out_cap, size_t *out_len,
                      uint64_t now_ms) {
    if (!session_valid(s) || out == NULL || out_len == NULL || s->closed) {
        return NS2S_ERR_STATE;
    }
    if (plaintext == NULL && plaintext_len > 0) {
        return NS2S_ERR_INVALID;
    }
    uint8_t ctrl[NS2S_CTRL_MAX];
    size_t ctrl_len = 0;
    int switch_after = 0;
    if (s->role == NS2S_ROLE_SERVER) {
        if (s->ratchet.phase == NS2S_RATCHET_OFFER_READY && !s->ratchet.offer_sent) {
            ctrl_len = build_offer(s, ctrl);
        } else if (s->ratchet.phase == NS2S_RATCHET_CONFIRM_READY &&
                   !s->ratchet.confirm_sent) {
            ctrl_len = build_confirm(s, ctrl);
            switch_after = 1;
        }
    } else if (s->ratchet.phase == NS2S_RATCHET_CIPHER_READY &&
               !s->ratchet.cipher_sent) {
        ctrl_len = build_cipher(s, ctrl);
    }

    size_t env_len = 2u + ctrl_len + plaintext_len;
    if (env_len > s->max_frame || env_len > UINT32_MAX) {
        return NS2S_ERR_LENGTH;
    }
    size_t need = NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + env_len + NS2S_TAG_BYTES;
    if (out_cap < need) {
        return NS2S_ERR_LENGTH;
    }
    uint8_t *env = out + NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES;
    put_u16(env, (uint16_t) ctrl_len);
    if (ctrl_len > 0) {
        memcpy(env + 2, ctrl, ctrl_len);
    }
    if (plaintext_len > 0) {
        memcpy(env + 2 + ctrl_len, plaintext, plaintext_len);
    }

    ns2s_frame_header h;
    h.version = NS2S_FRAME_VERSION;
    h.alg = s->alg;
    h.dir = s->role == NS2S_ROLE_CLIENT ? NS2S_DIR_C2S : NS2S_DIR_S2C;
    h.seq = s->send.seq;
    h.ratchet_id = s->send.ratchet_id;
    h.plaintext_len = (uint32_t) env_len;
    int rc = ns2s_frame_header_encode(out, &h);
    if (rc != NS2S_OK) {
        sodium_memzero(out, need);
        return rc;
    }
    uint8_t *nonce = out + NS2S_FRAME_HEADER_BYTES;
    ns2s_random_bytes(nonce, NS2S_NONCE_BYTES);
    size_t ct_len = 0;
    /* libsodium AEAD 支持 in-place：明文与密文同一地址。 */
    rc = ns2s_aead_seal(s->alg, s->send.key, nonce,
                        out, NS2S_FRAME_HEADER_BYTES,
                        env, env_len,
                        env, out_cap - NS2S_FRAME_HEADER_BYTES - NS2S_NONCE_BYTES,
                        &ct_len);
    if (rc != NS2S_OK) {
        sodium_memzero(out, need);
        return rc;
    }
    rc = chain_advance(&s->send, h.dir);
    if (rc != NS2S_OK) {
        s->closed = 1;
        sodium_memzero(out, need);
        sodium_memzero(s, sizeof(*s));
        return rc;
    }
    if (switch_after) {
        session_switch(s, s->ratchet.id, now_ms);
    }
    *out_len = NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + ct_len;
    return NS2S_OK;
}

int ns2s_session_open(ns2s_session *s,
                      const uint8_t *frame, size_t frame_len,
                      uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!session_valid(s) || frame == NULL || out == NULL || out_len == NULL || s->closed) {
        return NS2S_ERR_STATE;
    }
    if (frame_len < NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + NS2S_TAG_BYTES) {
        return NS2S_ERR_LENGTH;
    }
    ns2s_frame_header h;
    int rc = ns2s_frame_header_decode(frame, &h, s->max_frame);
    if (rc != NS2S_OK) {
        return rc;
    }
    if (h.alg != s->alg) {
        return NS2S_ERR_DOWNGRADE;
    }
    rc = ns2s_frame_validate(&h, s->role, s->recv.seq, s->recv.ratchet_id);
    if (rc != NS2S_OK) {
        return rc;
    }
    size_t total = NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES +
                   (size_t) h.plaintext_len + NS2S_TAG_BYTES;
    if (frame_len != total) {
        return NS2S_ERR_LENGTH;
    }
    const uint8_t *nonce = frame + NS2S_FRAME_HEADER_BYTES;
    const uint8_t *ct = nonce + NS2S_NONCE_BYTES;
    size_t ct_len = (size_t) h.plaintext_len + NS2S_TAG_BYTES;
    rc = ns2s_aead_open(s->alg, s->recv.key, nonce,
                        frame, NS2S_FRAME_HEADER_BYTES,
                        ct, ct_len, out, out_cap, out_len);
    if (rc != NS2S_OK) {
        return rc;
    }
    rc = chain_advance(&s->recv, h.dir);
    if (rc != NS2S_OK) {
        s->closed = 1;
        sodium_memzero(out, *out_len);
        sodium_memzero(s, sizeof(*s));
        return rc;
    }
    if (*out_len < 2) {
        sodium_memzero(out, *out_len);
        return NS2S_ERR_LENGTH;
    }
    size_t clen = get_u16(out);
    if (2u + clen > *out_len || clen > NS2S_CTRL_MAX) {
        sodium_memzero(out, *out_len);
        return NS2S_ERR_LENGTH;
    }
    s->ctrl_in_len = clen;
    if (clen > 0) {
        memcpy(s->ctrl_in, out + 2, clen);
    }
    size_t app_len = *out_len - 2u - clen;
    if (app_len > 0) {
        memmove(out, out + 2 + clen, app_len);
    }
    sodium_memzero(out + app_len, *out_len - app_len);
    *out_len = app_len;
    return NS2S_OK;
}

int ns2s_session_ratchet_tick(ns2s_session *s, uint64_t now_ms, ns2s_kem_job *job) {
    if (!session_valid(s) || job == NULL || s->role != NS2S_ROLE_SERVER || !s->auto_ratchet) {
        return 0;
    }
    if (s->ratchet.phase != NS2S_RATCHET_IDLE) {
        if (now_ms > s->ratchet.started_ms &&
            now_ms - s->ratchet.started_ms > s->ratchet_timeout_ms) {
            sodium_memzero(&s->ratchet, sizeof(s->ratchet));
        }
        return 0;
    }
    if (now_ms < s->last_reset_ms || now_ms - s->last_reset_ms < RATCHET_PERIOD_MS) {
        return 0;
    }
    uint32_t id = s->next_ratchet_id + 1;
    s->next_ratchet_id = id;
    s->ratchet.id = id;
    s->ratchet.started_ms = now_ms;
    s->ratchet.phase = NS2S_RATCHET_OFFER_KEM;
    s->last_reset_ms = now_ms;

    sodium_memzero(job, sizeof(*job));
    job->phase = NS2S_KEM_PHASE_RATCHET_OFFER;
    job->op = NS2S_KEM_OP_KEYPAIR;
    job->ratchet_id = id;
    memcpy(job->old_root, s->root, NS2S_ROOT_BYTES);
    job->completion_fd = -1;
    return 1;
}

int ns2s_session_consume_control(ns2s_session *s, uint64_t now_ms,
                                 ns2s_kem_job *job, int *need_submit) {
    if (!session_valid(s) || job == NULL || need_submit == NULL) {
        return NS2S_ERR_INVALID;
    }
    *need_submit = 0;
    if (s->ctrl_in_len == 0) {
        return 0;
    }
    if (s->ctrl_in_len < 5) {
        return NS2S_ERR_INVALID;
    }
    uint8_t kind = s->ctrl_in[0];
    uint32_t id = get_u32(s->ctrl_in + 1);
    int rc = NS2S_OK;
    if (kind == NS2S_CTRL_OFFER) {
        if (s->role != NS2S_ROLE_CLIENT || s->ctrl_in_len != 5u + NS2S_XWING_PK_BYTES ||
            s->ratchet.phase != NS2S_RATCHET_IDLE || id <= s->current_ratchet_id) {
            rc = NS2S_ERR_STATE;
        } else {
            s->ratchet.id = id;
            s->ratchet.started_ms = now_ms;
            memcpy(s->ratchet.server_pk, s->ctrl_in + 5, NS2S_XWING_PK_BYTES);
            s->ratchet.phase = NS2S_RATCHET_CIPHER_KEM;
            sodium_memzero(job, sizeof(*job));
            job->phase = NS2S_KEM_PHASE_RATCHET_ENC;
            job->op = NS2S_KEM_OP_ENC;
            job->ratchet_id = id;
            memcpy(job->peer_pk, s->ratchet.server_pk, NS2S_XWING_PK_BYTES);
            memcpy(job->old_root, s->root, NS2S_ROOT_BYTES);
            job->completion_fd = -1;
            *need_submit = 1;
        }
    } else if (kind == NS2S_CTRL_CIPHER) {
        if (s->role != NS2S_ROLE_SERVER || s->ctrl_in_len != 5u + NS2S_XWING_CT_BYTES ||
            s->ratchet.phase != NS2S_RATCHET_OFFER_READY || id != s->ratchet.id) {
            rc = NS2S_ERR_STATE;
        } else {
            memcpy(s->ratchet.peer_ct, s->ctrl_in + 5, NS2S_XWING_CT_BYTES);
            s->ratchet.phase = NS2S_RATCHET_CIPHER_KEM;
            sodium_memzero(job, sizeof(*job));
            job->phase = NS2S_KEM_PHASE_RATCHET_DEC;
            job->op = NS2S_KEM_OP_DEC;
            job->ratchet_id = id;
            memcpy(job->sk, s->ratchet.server_sk, NS2S_XWING_SK_BYTES);
            memcpy(job->peer_ct, s->ratchet.peer_ct, NS2S_XWING_CT_BYTES);
            memcpy(job->old_root, s->root, NS2S_ROOT_BYTES);
            job->completion_fd = -1;
            *need_submit = 1;
        }
    } else if (kind == NS2S_CTRL_CONFIRM) {
        if (s->role != NS2S_ROLE_CLIENT || s->ctrl_in_len != 5u + NS2S_HMAC_BYTES ||
            s->ratchet.phase != NS2S_RATCHET_CIPHER_READY || id != s->ratchet.id) {
            rc = NS2S_ERR_STATE;
        } else if (sodium_memcmp(s->ratchet.confirm_mac, s->ctrl_in + 5, NS2S_HMAC_BYTES) != 0) {
            rc = NS2S_ERR_AUTH;
        } else {
            session_switch(s, id, now_ms);
        }
    } else {
        rc = NS2S_ERR_INVALID;
    }
    sodium_memzero(s->ctrl_in, sizeof(s->ctrl_in));
    s->ctrl_in_len = 0;
    return rc;
}

int ns2s_session_apply_ratchet_job(ns2s_session *s,
                                   const ns2s_kem_job *job,
                                   uint64_t now_ms) {
    (void) now_ms;
    if (!session_valid(s) || job == NULL || job->status != NS2S_OK ||
        job->ratchet_id != s->ratchet.id) {
        return NS2S_ERR_STATE;
    }
    if (job->phase == NS2S_KEM_PHASE_RATCHET_OFFER) {
        memcpy(s->ratchet.server_pk, job->pk, NS2S_XWING_PK_BYTES);
        memcpy(s->ratchet.server_sk, job->sk, NS2S_XWING_SK_BYTES);
        s->ratchet.phase = NS2S_RATCHET_OFFER_READY;
    } else if (job->phase == NS2S_KEM_PHASE_RATCHET_ENC) {
        memcpy(s->ratchet.client_ct, job->ct, NS2S_XWING_CT_BYTES);
        memcpy(s->ratchet.new_root, job->rk0, NS2S_ROOT_BYTES);
        memcpy(s->ratchet.new_c2s, job->c2s_key, NS2S_KEY_BYTES);
        memcpy(s->ratchet.new_s2c, job->s2c_key, NS2S_KEY_BYTES);
        memcpy(s->ratchet.confirm_mac, job->ratchet_mac, NS2S_HMAC_BYTES);
        s->ratchet.phase = NS2S_RATCHET_CIPHER_READY;
    } else if (job->phase == NS2S_KEM_PHASE_RATCHET_DEC) {
        memcpy(s->ratchet.new_root, job->rk0, NS2S_ROOT_BYTES);
        memcpy(s->ratchet.new_c2s, job->c2s_key, NS2S_KEY_BYTES);
        memcpy(s->ratchet.new_s2c, job->s2c_key, NS2S_KEY_BYTES);
        memcpy(s->ratchet.confirm_mac, job->ratchet_mac, NS2S_HMAC_BYTES);
        s->ratchet.phase = NS2S_RATCHET_CONFIRM_READY;
    } else {
        return NS2S_ERR_STATE;
    }
    return NS2S_OK;
}
