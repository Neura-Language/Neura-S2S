#include "neura/s2s_handshake.h"

#include "neura/s2s_crypto.h"
#include "neura/s2s_secure_mem.h"

#include <string.h>

static ns2s_hs_action fail(ns2s_handshake *hs, int status) {
    hs->last_status = status;
    hs->state = NS2S_HS_FAILED;
    hs->pending_action = NS2S_HS_ACT_FAIL_CLOSE;
    return NS2S_HS_ACT_FAIL_CLOSE;
}

void ns2s_handshake_init(ns2s_handshake *hs,
                         ns2s_role role,
                         const uint8_t root_key[NS2S_ROOT_KEY_BYTES],
                         uint8_t alg_mask,
                         uint64_t now_ms) {
    if (hs == NULL || root_key == NULL) {
        return;
    }
    sodium_memzero(hs, sizeof(*hs));
    hs->role = role;
    hs->state = NS2S_HS_INIT;
    hs->alg_mask = alg_mask != 0 ? alg_mask
                                 : (uint8_t) (NS2S_ALG_AES256GCM | NS2S_ALG_CHACHA20POLY1305);
    hs->alg = 0;
    hs->started_ms = now_ms;
    hs->deadline_ms = now_ms + 3000ull;
    hs->last_status = NS2S_OK;
    memcpy(hs->root_key, root_key, NS2S_ROOT_KEY_BYTES);
}

void ns2s_handshake_reset(ns2s_handshake *hs) {
    if (hs != NULL) {
        sodium_memzero(hs, sizeof(*hs));
    }
}

void ns2s_handshake_destroy(ns2s_handshake *hs) {
    ns2s_handshake_reset(hs);
}

ns2s_hs_action ns2s_handshake_step(ns2s_handshake *hs,
                                   ns2s_hs_event ev,
                                   int kem_status) {
    if (hs == NULL) {
        return NS2S_HS_ACT_FAIL_CLOSE;
    }
    hs->last_event = ev;
    hs->pending_action = NS2S_HS_ACT_NONE;

    if (ev == NS2S_HS_EV_IO_ERROR || ev == NS2S_HS_EV_TIMEOUT ||
        ev == NS2S_HS_EV_PROTO_ERROR) {
        return fail(hs, NS2S_ERR_IO);
    }
    if (ev == NS2S_HS_EV_KEM_DONE && kem_status != NS2S_OK) {
        return fail(hs, kem_status);
    }

    if (hs->role == NS2S_ROLE_CLIENT) {
        switch (hs->state) {
        case NS2S_HS_INIT:
            if (ev == NS2S_HS_EV_START) {
                hs->kem_phase = NS2S_KEM_PHASE_CLIENT_HELLO;
                hs->state = NS2S_HS_KEM_CLIENT_HELLO;
                hs->pending_action = NS2S_HS_ACT_START_KEM_CLIENT_HELLO;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_KEM_CLIENT_HELLO:
            if (ev == NS2S_HS_EV_KEM_DONE) {
                hs->state = NS2S_HS_HELLO_SENT;
                hs->pending_action = NS2S_HS_ACT_SEND_HELLO;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_HELLO_SENT:
            if (ev == NS2S_HS_EV_ACK_RX) {
                hs->kem_phase = NS2S_KEM_PHASE_CLIENT_FINISH;
                hs->state = NS2S_HS_KEM_CLIENT_FINISH;
                hs->pending_action = NS2S_HS_ACT_START_KEM_CLIENT_FINISH;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_KEM_CLIENT_FINISH:
            if (ev == NS2S_HS_EV_KEM_DONE) {
                hs->state = NS2S_HS_FINISH_SENT;
                hs->pending_action = NS2S_HS_ACT_SEND_FINISH;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_FINISH_SENT:
            if (ev == NS2S_HS_EV_READY_RX) {
                if ((hs->flags & NS2S_HS_FLAG_VERIFIED) == 0) {
                    return fail(hs, NS2S_ERR_AUTH);
                }
                hs->state = NS2S_HS_ESTABLISHED;
                hs->pending_action = NS2S_HS_ACT_ESTABLISHED;
                return hs->pending_action;
            }
            break;
        default:
            break;
        }
    } else if (hs->role == NS2S_ROLE_SERVER) {
        switch (hs->state) {
        case NS2S_HS_INIT:
            if (ev == NS2S_HS_EV_HELLO_RX) {
                hs->kem_phase = NS2S_KEM_PHASE_SERVER_ACK;
                hs->state = NS2S_HS_KEM_SERVER_ACK;
                hs->pending_action = NS2S_HS_ACT_START_KEM_SERVER_ACK;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_KEM_SERVER_ACK:
            if (ev == NS2S_HS_EV_KEM_DONE) {
                hs->state = NS2S_HS_ACK_SENT;
                hs->pending_action = NS2S_HS_ACT_SEND_ACK;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_ACK_SENT:
            if (ev == NS2S_HS_EV_FINISH_RX) {
                hs->kem_phase = NS2S_KEM_PHASE_SERVER_FINISH;
                hs->state = NS2S_HS_KEM_SERVER_FINISH;
                hs->pending_action = NS2S_HS_ACT_START_KEM_SERVER_FINISH;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_KEM_SERVER_FINISH:
            if (ev == NS2S_HS_EV_KEM_DONE) {
                /*
                 * finish 的 HMAC 必须已经被 ns2s_hs_verify_finish() 校验通过。
                 * 漏调 verify 就走到这里 → 直接 FAIL_CLOSE，绝不发 ready。
                 */
                if ((hs->flags & NS2S_HS_FLAG_VERIFIED) == 0) {
                    return fail(hs, NS2S_ERR_AUTH);
                }
                hs->state = NS2S_HS_READY_SENT;
                hs->pending_action = NS2S_HS_ACT_SEND_READY;
                return hs->pending_action;
            }
            break;
        case NS2S_HS_READY_SENT:
            if (ev == NS2S_HS_EV_READY_SENT) {
                hs->state = NS2S_HS_ESTABLISHED;
                hs->pending_action = NS2S_HS_ACT_ESTABLISHED;
                return hs->pending_action;
            }
            break;
        default:
            break;
        }
    }

    return fail(hs, NS2S_ERR_STATE);
}

int ns2s_hs_check_deadline(ns2s_handshake *hs, uint64_t now_ms) {
    if (hs == NULL) {
        return NS2S_ERR_INVALID;
    }
    if (hs->state == NS2S_HS_ESTABLISHED || hs->state == NS2S_HS_FAILED) {
        return NS2S_OK;
    }
    /* deadline_ms == 0 表示调用方没有设置超时（保持向后兼容）。 */
    if (hs->deadline_ms != 0 && now_ms > hs->deadline_ms) {
        (void) fail(hs, NS2S_ERR_STATE);
        return NS2S_ERR_STATE;
    }
    return NS2S_OK;
}

const char *ns2s_hs_state_name(ns2s_hs_state s) {
    switch (s) {
    case NS2S_HS_INIT: return "INIT";
    case NS2S_HS_KEM_CLIENT_HELLO: return "KEM_CLIENT_HELLO";
    case NS2S_HS_HELLO_SENT: return "HELLO_SENT";
    case NS2S_HS_KEM_CLIENT_FINISH: return "KEM_CLIENT_FINISH";
    case NS2S_HS_FINISH_SENT: return "FINISH_SENT";
    case NS2S_HS_READY_RX: return "READY_RX";
    case NS2S_HS_KEM_SERVER_ACK: return "KEM_SERVER_ACK";
    case NS2S_HS_ACK_SENT: return "ACK_SENT";
    case NS2S_HS_KEM_SERVER_FINISH: return "KEM_SERVER_FINISH";
    case NS2S_HS_READY_SENT: return "READY_SENT";
    case NS2S_HS_ESTABLISHED: return "ESTABLISHED";
    case NS2S_HS_FAILED: return "FAILED";
    default: return "?";
    }
}

const char *ns2s_hs_action_name(ns2s_hs_action a) {
    switch (a) {
    case NS2S_HS_ACT_NONE: return "NONE";
    case NS2S_HS_ACT_START_KEM_CLIENT_HELLO: return "START_KEM_CLIENT_HELLO";
    case NS2S_HS_ACT_SEND_HELLO: return "SEND_HELLO";
    case NS2S_HS_ACT_START_KEM_SERVER_ACK: return "START_KEM_SERVER_ACK";
    case NS2S_HS_ACT_SEND_ACK: return "SEND_ACK";
    case NS2S_HS_ACT_START_KEM_CLIENT_FINISH: return "START_KEM_CLIENT_FINISH";
    case NS2S_HS_ACT_SEND_FINISH: return "SEND_FINISH";
    case NS2S_HS_ACT_START_KEM_SERVER_FINISH: return "START_KEM_SERVER_FINISH";
    case NS2S_HS_ACT_SEND_READY: return "SEND_READY";
    case NS2S_HS_ACT_ESTABLISHED: return "ESTABLISHED";
    case NS2S_HS_ACT_FAIL_CLOSE: return "FAIL_CLOSE";
    default: return "?";
    }
}

int ns2s_kem_job_from_handshake(ns2s_kem_job *job,
                                const ns2s_handshake *hs,
                                ns2s_kem_phase phase) {
    if (job == NULL || hs == NULL) {
        return NS2S_ERR_INVALID;
    }
    sodium_memzero(job, sizeof(*job));
    job->phase = phase;
    job->epoch = hs->kem_epoch;
    job->completion_fd = -1;
    memcpy(job->root_key, hs->root_key, NS2S_ROOT_KEY_BYTES);
    switch (phase) {
    case NS2S_KEM_PHASE_CLIENT_HELLO:
        job->op = NS2S_KEM_OP_KEYPAIR;
        return NS2S_OK;
    case NS2S_KEM_PHASE_SERVER_ACK:
        job->op = NS2S_KEM_OP_KEYPAIR;
        memcpy(job->peer_pk, hs->tx.client_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->client_pk, hs->tx.client_pk, NS2S_XWING_PK_BYTES);
        return NS2S_OK;
    case NS2S_KEM_PHASE_CLIENT_FINISH:
        job->op = NS2S_KEM_OP_DEC;
        job->derive_keys = 1;
        memcpy(job->sk, hs->client_sk, NS2S_XWING_SK_BYTES);
        memcpy(job->peer_pk, hs->tx.server_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->peer_ct, hs->tx.server_ct, NS2S_XWING_CT_BYTES);
        memcpy(job->own_pk, hs->tx.client_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->client_pk, hs->tx.client_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->server_pk, hs->tx.server_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->server_ct, hs->tx.server_ct, NS2S_XWING_CT_BYTES);
        return NS2S_OK;
    case NS2S_KEM_PHASE_SERVER_FINISH:
        job->op = NS2S_KEM_OP_DEC;
        job->derive_keys = 1;
        memcpy(job->sk, hs->server_sk, NS2S_XWING_SK_BYTES);
        memcpy(job->peer_ct, hs->tx.client_ct, NS2S_XWING_CT_BYTES);
        memcpy(job->own_pk, hs->tx.server_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->client_pk, hs->tx.client_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->server_pk, hs->tx.server_pk, NS2S_XWING_PK_BYTES);
        memcpy(job->client_ct, hs->tx.client_ct, NS2S_XWING_CT_BYTES);
        memcpy(job->server_ct, hs->tx.server_ct, NS2S_XWING_CT_BYTES);
        memcpy(job->ss, hs->ss_server, NS2S_XWING_SS_BYTES);
        return NS2S_OK;
    default:
        return NS2S_ERR_STATE;
    }
}

static int derive_finish_keys(ns2s_kem_job *job) {
    uint8_t ikm[2u * NS2S_XWING_SS_BYTES];
    uint8_t salt[NS2S_HS_SALT_BYTES];
    uint8_t combined[NS2S_ROOT_BYTES];
    memcpy(ikm, job->ss, NS2S_XWING_SS_BYTES);
    memcpy(ikm + NS2S_XWING_SS_BYTES, job->ss_peer, NS2S_XWING_SS_BYTES);

    size_t off = 0;
    memcpy(salt + off, job->client_pk, NS2S_XWING_PK_BYTES); off += NS2S_XWING_PK_BYTES;
    memcpy(salt + off, job->server_pk, NS2S_XWING_PK_BYTES); off += NS2S_XWING_PK_BYTES;
    memcpy(salt + off, job->client_ct, NS2S_XWING_CT_BYTES); off += NS2S_XWING_CT_BYTES;
    memcpy(salt + off, job->server_ct, NS2S_XWING_CT_BYTES); off += NS2S_XWING_CT_BYTES;

    int rc = ns2s_hkdf_sha512(ikm, sizeof(ikm), salt, off,
                              "neura-s2s-v1/kem-combine", strlen("neura-s2s-v1/kem-combine"),
                              combined, sizeof(combined));
    if (rc == NS2S_OK) {
        rc = ns2s_hkdf_sha512(combined, sizeof(combined),
                              job->root_key, sizeof(job->root_key),
                              "neura-s2s-v1/init-root", strlen("neura-s2s-v1/init-root"),
                              job->rk0, sizeof(job->rk0));
    }
    if (rc == NS2S_OK) {
        rc = ns2s_hkdf_sha512(job->rk0, sizeof(job->rk0), NULL, 0,
                              "neura-s2s-v1/c2s", strlen("neura-s2s-v1/c2s"),
                              job->c2s_key, sizeof(job->c2s_key));
    }
    if (rc == NS2S_OK) {
        rc = ns2s_hkdf_sha512(job->rk0, sizeof(job->rk0), NULL, 0,
                              "neura-s2s-v1/s2c", strlen("neura-s2s-v1/s2c"),
                              job->s2c_key, sizeof(job->s2c_key));
    }
    sodium_memzero(ikm, sizeof(ikm));
    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(combined, sizeof(combined));
    return rc;
}

static int derive_ratchet_keys(ns2s_kem_job *job, int with_confirm) {
    uint8_t new_root[NS2S_ROOT_BYTES];
    int rc = ns2s_hkdf_sha512(job->ss, NS2S_XWING_SS_BYTES,
                              job->old_root, sizeof(job->old_root),
                              "neura-s2s-v1/ratchet", strlen("neura-s2s-v1/ratchet"),
                              new_root, sizeof(new_root));
    if (rc == NS2S_OK) {
        rc = ns2s_hkdf_sha512(new_root, sizeof(new_root), NULL, 0,
                              "neura-s2s-v1/c2s", strlen("neura-s2s-v1/c2s"),
                              job->c2s_key, sizeof(job->c2s_key));
    }
    if (rc == NS2S_OK) {
        rc = ns2s_hkdf_sha512(new_root, sizeof(new_root), NULL, 0,
                              "neura-s2s-v1/s2c", strlen("neura-s2s-v1/s2c"),
                              job->s2c_key, sizeof(job->s2c_key));
    }
    if (rc == NS2S_OK) {
        memcpy(job->rk0, new_root, sizeof(new_root));
        if (with_confirm) {
            uint8_t idbuf[4];
            idbuf[0] = (uint8_t) (job->ratchet_id >> 24);
            idbuf[1] = (uint8_t) (job->ratchet_id >> 16);
            idbuf[2] = (uint8_t) (job->ratchet_id >> 8);
            idbuf[3] = (uint8_t) job->ratchet_id;
            ns2s_hmac_sha512 h;
            ns2s_hmac_sha512_init(&h, new_root, sizeof(new_root));
            ns2s_hmac_sha512_update(&h, (const uint8_t *) "neura-s2s-v1/ratchet-confirm",
                                    strlen("neura-s2s-v1/ratchet-confirm"));
            ns2s_hmac_sha512_update(&h, idbuf, sizeof(idbuf));
            rc = ns2s_hmac_sha512_final(&h, job->ratchet_mac);
            sodium_memzero(&h, sizeof(h));
        }
    }
    sodium_memzero(new_root, sizeof(new_root));
    return rc;
}

void ns2s_kem_job_execute(ns2s_kem_job *job) {
    if (job == NULL) {
        return;
    }
    int rc = NS2S_ERR_STATE;
    switch (job->phase) {
    case NS2S_KEM_PHASE_CLIENT_HELLO:
        rc = ns2s_xwing_keypair(job->pk, job->sk);
        break;
    case NS2S_KEM_PHASE_SERVER_ACK:
        rc = ns2s_xwing_keypair(job->pk, job->sk);
        if (rc == NS2S_OK) {
            rc = ns2s_xwing_enc(job->ct, job->ss, job->peer_pk);
        }
        break;
    case NS2S_KEM_PHASE_CLIENT_FINISH:
        rc = ns2s_xwing_dec(job->ss, job->peer_ct, job->sk);
        if (rc == NS2S_OK) {
            rc = ns2s_xwing_enc(job->ct, job->ss_peer, job->peer_pk);
            if (rc == NS2S_OK) {
                memcpy(job->client_ct, job->ct, NS2S_XWING_CT_BYTES);
            }
        }
        break;
    case NS2S_KEM_PHASE_SERVER_FINISH:
        rc = ns2s_xwing_dec(job->ss_peer, job->peer_ct, job->sk);
        break;
    case NS2S_KEM_PHASE_RATCHET_OFFER:
        rc = ns2s_xwing_keypair(job->pk, job->sk);
        break;
    case NS2S_KEM_PHASE_RATCHET_ENC:
        rc = ns2s_xwing_enc(job->ct, job->ss, job->peer_pk);
        if (rc == NS2S_OK) {
            rc = derive_ratchet_keys(job, 1);
        }
        break;
    case NS2S_KEM_PHASE_RATCHET_DEC:
        rc = ns2s_xwing_dec(job->ss, job->peer_ct, job->sk);
        if (rc == NS2S_OK) {
            rc = derive_ratchet_keys(job, 1);
        }
        break;
    default:
        rc = NS2S_ERR_STATE;
        break;
    }
    if (rc == NS2S_OK && job->derive_keys) {
        rc = derive_finish_keys(job);
    }
    job->status = rc;
    if (rc != NS2S_OK) {
        sodium_memzero(job->sk, sizeof(job->sk));
        sodium_memzero(job->ss, sizeof(job->ss));
        sodium_memzero(job->ss_peer, sizeof(job->ss_peer));
        sodium_memzero(job->rk0, sizeof(job->rk0));
        sodium_memzero(job->c2s_key, sizeof(job->c2s_key));
        sodium_memzero(job->s2c_key, sizeof(job->s2c_key));
    } else if (job->derive_keys) {
        /* 共享秘密不再需要；派生结果保留给 Reactor。 */
        sodium_memzero(job->ss, sizeof(job->ss));
        sodium_memzero(job->ss_peer, sizeof(job->ss_peer));
        sodium_memzero(job->sk, sizeof(job->sk));
    } else if (job->phase == NS2S_KEM_PHASE_RATCHET_ENC ||
               job->phase == NS2S_KEM_PHASE_RATCHET_DEC) {
        sodium_memzero(job->ss, sizeof(job->ss));
        sodium_memzero(job->sk, sizeof(job->sk));
    }
}

int ns2s_hs_apply_kem_job(ns2s_handshake *hs, const ns2s_kem_job *job) {
    if (hs == NULL || job == NULL || job->status != NS2S_OK) {
        return NS2S_ERR_STATE;
    }
    switch (job->phase) {
    case NS2S_KEM_PHASE_CLIENT_HELLO:
        memcpy(hs->tx.client_pk, job->pk, NS2S_XWING_PK_BYTES);
        memcpy(hs->client_sk, job->sk, NS2S_XWING_SK_BYTES);
        return NS2S_OK;
    case NS2S_KEM_PHASE_SERVER_ACK:
        memcpy(hs->tx.server_pk, job->pk, NS2S_XWING_PK_BYTES);
        memcpy(hs->tx.server_ct, job->ct, NS2S_XWING_CT_BYTES);
        memcpy(hs->server_sk, job->sk, NS2S_XWING_SK_BYTES);
        memcpy(hs->ss_server, job->ss, NS2S_XWING_SS_BYTES);
        return NS2S_OK;
    case NS2S_KEM_PHASE_CLIENT_FINISH:
        memcpy(hs->tx.client_ct, job->ct, NS2S_XWING_CT_BYTES);
        memcpy(hs->ss_server, job->ss, NS2S_XWING_SS_BYTES);
        memcpy(hs->ss_client, job->ss_peer, NS2S_XWING_SS_BYTES);
        memcpy(hs->rk0, job->rk0, NS2S_ROOT_BYTES);
        memcpy(hs->c2s_key, job->c2s_key, NS2S_KEY_BYTES);
        memcpy(hs->s2c_key, job->s2c_key, NS2S_KEY_BYTES);
        return NS2S_OK;
    case NS2S_KEM_PHASE_SERVER_FINISH:
        memcpy(hs->ss_client, job->ss_peer, NS2S_XWING_SS_BYTES);
        memcpy(hs->ss_server, job->ss, NS2S_XWING_SS_BYTES);
        memcpy(hs->rk0, job->rk0, NS2S_ROOT_BYTES);
        memcpy(hs->c2s_key, job->c2s_key, NS2S_KEY_BYTES);
        memcpy(hs->s2c_key, job->s2c_key, NS2S_KEY_BYTES);
        return NS2S_OK;
    default:
        return NS2S_ERR_STATE;
    }
}

void ns2s_kem_job_destroy(ns2s_kem_job *job) {
    if (job != NULL) {
        sodium_memzero(job, sizeof(*job));
    }
}
