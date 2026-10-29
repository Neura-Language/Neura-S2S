#include "neura/s2s_secure_mem.h"
#include "neura/s2s.h"


#include <errno.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

int ns2s_secure_alloc(ns2s_secure_region *r, size_t len) {
    if (r == NULL || len == 0) {
        return NS2S_ERR_INVALID;
    }
    memset(r, 0, sizeof(*r));
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) {
        return NS2S_ERR_INVALID;
    }
    size_t page = (size_t) ps;
    size_t alloc_len = (len + page - 1u) & ~(page - 1u);
    void *p = NULL;
    if (posix_memalign(&p, page, alloc_len) != 0 || p == NULL) {
        return NS2S_ERR_NOMEM;
    }
    sodium_memzero(p, alloc_len);
    if (mlock(p, alloc_len) != 0) {
        sodium_memzero(p, alloc_len);
        free(p);
        return NS2S_ERR_LOCKED;
    }
    r->locked = 1;
#ifdef MADV_DONTDUMP
    /* madvise 要求页对齐地址；alloc_len 已按页向上取整。 */
    if (madvise(p, alloc_len, MADV_DONTDUMP) != 0) {
        sodium_memzero(p, alloc_len);
        (void) munlock(p, alloc_len);
        free(p);
        return NS2S_ERR_LOCKED;
    }
    r->no_dump = 1;
#endif
    /* libsodium 的 mlock 包装作为第二层保险（幂等）。 */
    if (sodium_mlock(p, alloc_len) != 0) {
        sodium_memzero(p, alloc_len);
        (void) munlock(p, alloc_len);
        free(p);
        return NS2S_ERR_LOCKED;
    }
    r->ptr = p;
    r->len = len;
    r->alloc_len = alloc_len;
    return NS2S_OK;
}

void ns2s_secure_free(ns2s_secure_region *r) {
    if (r == NULL || r->ptr == NULL) {
        return;
    }
    size_t n = r->alloc_len ? r->alloc_len : r->len;
    sodium_memzero(r->ptr, n);
#ifdef MADV_DONTDUMP
    if (r->no_dump) {
        (void) madvise(r->ptr, n, MADV_DODUMP);
    }
#endif
    (void) sodium_munlock(r->ptr, n);
    if (r->locked) {
        (void) munlock(r->ptr, n);
    }
    free(r->ptr);
    memset(r, 0, sizeof(*r));
}

void ns2s_secure_zero(void *p, size_t len) {
    if (p != NULL && len > 0) {
        sodium_memzero(p, len);
    }
}

int ns2s_secure_disable_core_dumps(void) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
        return NS2S_ERR_LOCKED;
    }
    return NS2S_OK;
}
