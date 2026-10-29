#include "neura/s2s_crypto.h"

#include <string.h>

_Static_assert(NS2S_XWING_PK_BYTES == crypto_kem_xwing_PUBLICKEYBYTES, "xwing pk size");
_Static_assert(NS2S_XWING_SK_BYTES == crypto_kem_xwing_SECRETKEYBYTES, "xwing sk size");
_Static_assert(NS2S_XWING_CT_BYTES == crypto_kem_xwing_CIPHERTEXTBYTES, "xwing ct size");
_Static_assert(NS2S_XWING_SS_BYTES == crypto_kem_xwing_SHAREDSECRETBYTES, "xwing ss size");
_Static_assert(NS2S_HMAC_BYTES == crypto_auth_hmacsha512_BYTES, "hmac size");
_Static_assert(NS2S_SHA512_BYTES == crypto_hash_sha512_BYTES, "sha512 size");
_Static_assert(NS2S_KEY_BYTES == crypto_aead_chacha20poly1305_ietf_KEYBYTES, "aead key size");
_Static_assert(NS2S_NONCE_BYTES == crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "nonce size");
_Static_assert(NS2S_TAG_BYTES == crypto_aead_chacha20poly1305_ietf_ABYTES, "tag size");

int ns2s_crypto_init(void) {
    if (sodium_init() < 0) {
        return NS2S_ERR_CRYPTO;
    }
    return NS2S_OK;
}

int ns2s_xwing_keypair(uint8_t pk[NS2S_XWING_PK_BYTES],
                       uint8_t sk[NS2S_XWING_SK_BYTES]) {
    if (crypto_kem_xwing_keypair(pk, sk) != 0) {
        return NS2S_ERR_CRYPTO;
    }
    return NS2S_OK;
}

int ns2s_xwing_enc(uint8_t ct[NS2S_XWING_CT_BYTES],
                   uint8_t ss[NS2S_XWING_SS_BYTES],
                   const uint8_t pk[NS2S_XWING_PK_BYTES]) {
    if (crypto_kem_xwing_enc(ct, ss, pk) != 0) {
        return NS2S_ERR_CRYPTO;
    }
    return NS2S_OK;
}

int ns2s_xwing_dec(uint8_t ss[NS2S_XWING_SS_BYTES],
                   const uint8_t ct[NS2S_XWING_CT_BYTES],
                   const uint8_t sk[NS2S_XWING_SK_BYTES]) {
    if (crypto_kem_xwing_dec(ss, ct, sk) != 0) {
        return NS2S_ERR_AUTH;
    }
    return NS2S_OK;
}

int ns2s_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const char *info, size_t info_len,
                     uint8_t *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return NS2S_ERR_INVALID;
    }
    uint8_t prk[crypto_kdf_hkdf_sha512_KEYBYTES];
    int rc = crypto_kdf_hkdf_sha512_extract(prk, salt, salt_len, ikm, ikm_len);
    if (rc != 0) {
        sodium_memzero(prk, sizeof(prk));
        return NS2S_ERR_CRYPTO;
    }
    rc = crypto_kdf_hkdf_sha512_expand(out, out_len, info, info_len, prk);
    sodium_memzero(prk, sizeof(prk));
    if (rc != 0) {
        sodium_memzero(out, out_len);
        return NS2S_ERR_CRYPTO;
    }
    return NS2S_OK;
}

void ns2s_hmac_sha512_init(ns2s_hmac_sha512 *h,
                           const uint8_t *key, size_t key_len) {
    crypto_auth_hmacsha512_init(&h->st, key, key_len);
}

void ns2s_hmac_sha512_update(ns2s_hmac_sha512 *h,
                             const uint8_t *data, size_t len) {
    crypto_auth_hmacsha512_update(&h->st, data, len);
}

int ns2s_hmac_sha512_final(ns2s_hmac_sha512 *h,
                           uint8_t out[NS2S_HMAC_BYTES]) {
    return crypto_auth_hmacsha512_final(&h->st, out) == 0 ? NS2S_OK : NS2S_ERR_CRYPTO;
}

int ns2s_hmac_sha512_verify(const uint8_t expected[NS2S_HMAC_BYTES],
                            const uint8_t actual[NS2S_HMAC_BYTES]) {
    return sodium_memcmp(expected, actual, NS2S_HMAC_BYTES) == 0 ? NS2S_OK : NS2S_ERR_AUTH;
}

void ns2s_sha512_init(ns2s_sha512 *h) {
    crypto_hash_sha512_init(&h->st);
}

void ns2s_sha512_update(ns2s_sha512 *h, const uint8_t *data, size_t len) {
    crypto_hash_sha512_update(&h->st, data, len);
}

void ns2s_sha512_final(ns2s_sha512 *h, uint8_t out[NS2S_SHA512_BYTES]) {
    crypto_hash_sha512_final(&h->st, out);
}

void ns2s_random_bytes(void *buf, size_t len) {
    randombytes_buf(buf, len);
}

int ns2s_alg_supported(uint8_t alg) {
    if (alg == NS2S_ALG_CHACHA20POLY1305) {
        return 1;
    }
    if (alg == NS2S_ALG_AES256GCM) {
        return crypto_aead_aes256gcm_is_available() ? 1 : 0;
    }
    return 0;
}

uint8_t ns2s_alg_select(uint8_t client_mask) {
    if ((client_mask & NS2S_ALG_AES256GCM) != 0u &&
        crypto_aead_aes256gcm_is_available()) {
        return NS2S_ALG_AES256GCM;
    }
    if ((client_mask & NS2S_ALG_CHACHA20POLY1305) != 0u) {
        return NS2S_ALG_CHACHA20POLY1305;
    }
    return 0;
}

static int aead_ok(uint8_t alg) {
    return ns2s_alg_supported(alg) ? NS2S_OK : NS2S_ERR_DOWNGRADE;
}

int ns2s_aead_seal(uint8_t alg,
                   const uint8_t key[NS2S_KEY_BYTES],
                   const uint8_t nonce[NS2S_NONCE_BYTES],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *out, size_t out_cap, size_t *out_len) {
    if (aead_ok(alg) != NS2S_OK || out == NULL || out_len == NULL ||
        out_cap < plaintext_len + NS2S_TAG_BYTES) {
        return NS2S_ERR_LENGTH;
    }
    unsigned long long clen = 0;
    int rc;
    if (alg == NS2S_ALG_AES256GCM) {
        rc = crypto_aead_aes256gcm_encrypt(out, &clen, plaintext,
                                           (unsigned long long) plaintext_len,
                                           aad, (unsigned long long) aad_len,
                                           NULL, nonce, key);
    } else {
        rc = crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, plaintext,
                                                       (unsigned long long) plaintext_len,
                                                       aad, (unsigned long long) aad_len,
                                                       NULL, nonce, key);
    }
    if (rc != 0) {
        return NS2S_ERR_CRYPTO;
    }
    *out_len = (size_t) clen;
    return NS2S_OK;
}

int ns2s_aead_open(uint8_t alg,
                   const uint8_t key[NS2S_KEY_BYTES],
                   const uint8_t nonce[NS2S_NONCE_BYTES],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t *out, size_t out_cap, size_t *out_len) {
    if (aead_ok(alg) != NS2S_OK || out == NULL || out_len == NULL ||
        ciphertext_len < NS2S_TAG_BYTES ||
        out_cap < ciphertext_len - NS2S_TAG_BYTES) {
        return NS2S_ERR_LENGTH;
    }
    unsigned long long mlen = 0;
    int rc;
    if (alg == NS2S_ALG_AES256GCM) {
        rc = crypto_aead_aes256gcm_decrypt(out, &mlen, NULL, ciphertext,
                                           (unsigned long long) ciphertext_len,
                                           aad, (unsigned long long) aad_len,
                                           nonce, key);
    } else {
        rc = crypto_aead_chacha20poly1305_ietf_decrypt(out, &mlen, NULL, ciphertext,
                                                       (unsigned long long) ciphertext_len,
                                                       aad, (unsigned long long) aad_len,
                                                       nonce, key);
    }
    if (rc != 0) {
        return NS2S_ERR_AUTH;
    }
    *out_len = (size_t) mlen;
    return NS2S_OK;
}
