/* libsodium 封装：项目内禁止出现自研密码学原语。 */
#ifndef NEURA_S2S_CRYPTO_H
#define NEURA_S2S_CRYPTO_H

#include "neura/s2s.h"

#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    crypto_auth_hmacsha512_state st;
} ns2s_hmac_sha512;

typedef struct {
    crypto_hash_sha512_state st;
} ns2s_sha512;

int ns2s_crypto_init(void);

int ns2s_xwing_keypair(uint8_t pk[NS2S_XWING_PK_BYTES],
                       uint8_t sk[NS2S_XWING_SK_BYTES]);
int ns2s_xwing_enc(uint8_t ct[NS2S_XWING_CT_BYTES],
                   uint8_t ss[NS2S_XWING_SS_BYTES],
                   const uint8_t pk[NS2S_XWING_PK_BYTES]);
int ns2s_xwing_dec(uint8_t ss[NS2S_XWING_SS_BYTES],
                   const uint8_t ct[NS2S_XWING_CT_BYTES],
                   const uint8_t sk[NS2S_XWING_SK_BYTES]);

int ns2s_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const char *info, size_t info_len,
                     uint8_t *out, size_t out_len);

void ns2s_hmac_sha512_init(ns2s_hmac_sha512 *h,
                           const uint8_t *key, size_t key_len);
void ns2s_hmac_sha512_update(ns2s_hmac_sha512 *h,
                             const uint8_t *data, size_t len);
int ns2s_hmac_sha512_final(ns2s_hmac_sha512 *h,
                           uint8_t out[NS2S_HMAC_BYTES]);
int ns2s_hmac_sha512_verify(const uint8_t expected[NS2S_HMAC_BYTES],
                            const uint8_t actual[NS2S_HMAC_BYTES]);

void ns2s_sha512_init(ns2s_sha512 *h);
void ns2s_sha512_update(ns2s_sha512 *h, const uint8_t *data, size_t len);
void ns2s_sha512_final(ns2s_sha512 *h, uint8_t out[NS2S_SHA512_BYTES]);

void ns2s_random_bytes(void *buf, size_t len);

int ns2s_alg_supported(uint8_t alg);
uint8_t ns2s_alg_select(uint8_t client_mask);

int ns2s_aead_seal(uint8_t alg,
                   const uint8_t key[NS2S_KEY_BYTES],
                   const uint8_t nonce[NS2S_NONCE_BYTES],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *out, size_t out_cap, size_t *out_len);

int ns2s_aead_open(uint8_t alg,
                   const uint8_t key[NS2S_KEY_BYTES],
                   const uint8_t nonce[NS2S_NONCE_BYTES],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NEURA_S2S_CRYPTO_H */
