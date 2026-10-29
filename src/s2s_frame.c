#include "neura/s2s.h"

#include "neura/s2s_crypto.h"

#include <string.h>

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

int ns2s_init(void) {
    return ns2s_crypto_init();
}

int ns2s_frame_header_encode(uint8_t out[NS2S_FRAME_HEADER_BYTES],
                             const ns2s_frame_header *h) {
    if (out == NULL || h == NULL || h->version != NS2S_FRAME_VERSION) {
        return NS2S_ERR_INVALID;
    }
    if (h->dir != NS2S_DIR_C2S && h->dir != NS2S_DIR_S2C) {
        return NS2S_ERR_INVALID;
    }
    if (!ns2s_alg_supported(h->alg)) {
        return NS2S_ERR_DOWNGRADE;
    }
    out[0] = NS2S_FRAME_VERSION;
    out[1] = h->alg;
    out[2] = h->dir;
    put_u32(out + 3, h->seq);
    put_u32(out + 7, h->ratchet_id);
    put_u32(out + 11, h->plaintext_len);
    return NS2S_OK;
}

int ns2s_frame_header_decode(const uint8_t in[NS2S_FRAME_HEADER_BYTES],
                             ns2s_frame_header *out,
                             uint32_t max_frame) {
    if (in == NULL || out == NULL || max_frame == 0) {
        return NS2S_ERR_INVALID;
    }
    memset(out, 0, sizeof(*out));
    out->version = in[0];
    out->alg = in[1];
    out->dir = in[2];
    out->seq = get_u32(in + 3);
    out->ratchet_id = get_u32(in + 7);
    out->plaintext_len = get_u32(in + 11);

    if (out->version != NS2S_FRAME_VERSION) {
        return NS2S_ERR_INVALID;
    }
    if (out->dir != NS2S_DIR_C2S && out->dir != NS2S_DIR_S2C) {
        return NS2S_ERR_INVALID;
    }
    if (!ns2s_alg_supported(out->alg)) {
        return NS2S_ERR_DOWNGRADE;
    }
    /*
     * 关键顺序：先做长度上限校验，任何 malloc/解密都在此之后。
     * 同时防止 plaintext_len + header/nonce/tag 的整数溢出。
     */
    if (out->plaintext_len > max_frame) {
        return NS2S_ERR_LENGTH;
    }
    if (out->plaintext_len > UINT32_MAX - NS2S_FRAME_HEADER_BYTES - NS2S_NONCE_BYTES -
                               NS2S_TAG_BYTES) {
        return NS2S_ERR_LENGTH;
    }
    return NS2S_OK;
}

int ns2s_frame_validate(const ns2s_frame_header *h,
                        ns2s_role role,
                        uint32_t expect_seq,
                        uint32_t current_ratchet_id) {
    if (h == NULL) {
        return NS2S_ERR_INVALID;
    }
    uint8_t want = role == NS2S_ROLE_CLIENT ? NS2S_DIR_S2C : NS2S_DIR_C2S;
    if (h->dir != want) {
        return NS2S_ERR_INVALID;
    }
    if (h->seq != expect_seq) {
        return NS2S_ERR_REPLAY;
    }
    if (h->ratchet_id != current_ratchet_id) {
        return NS2S_ERR_REPLAY;
    }
    return NS2S_OK;
}
