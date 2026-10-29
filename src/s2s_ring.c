#include "neura/s2s_ring.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int ns2s_ring_init(ns2s_ring *r, size_t cap) {
    if (r == NULL || cap == 0) {
        return -1;
    }
    memset(r, 0, sizeof(*r));
    r->data = (uint8_t *) malloc(cap);
    if (r->data == NULL) {
        return -1;
    }
    r->cap = cap;
    return 0;
}

void ns2s_ring_reset(ns2s_ring *r) {
    if (r == NULL) {
        return;
    }
    r->head = 0;
    r->len = 0;
}

void ns2s_ring_free(ns2s_ring *r) {
    if (r == NULL) {
        return;
    }
    free(r->data);
    memset(r, 0, sizeof(*r));
}

size_t ns2s_ring_readable(const ns2s_ring *r) {
    return r != NULL ? r->len : 0;
}

size_t ns2s_ring_writable(const ns2s_ring *r) {
    return r != NULL ? r->cap - r->len : 0;
}

size_t ns2s_ring_capacity(const ns2s_ring *r) {
    return r != NULL ? r->cap : 0;
}

uint8_t *ns2s_ring_write_ptr(ns2s_ring *r, size_t *contig) {
    if (r == NULL || r->data == NULL || r->len == r->cap) {
        if (contig != NULL) {
            *contig = 0;
        }
        return NULL;
    }
    size_t tail = (r->head + r->len) % r->cap;
    size_t n = r->cap - tail;
    if (n > r->cap - r->len) {
        n = r->cap - r->len;
    }
    if (contig != NULL) {
        *contig = n;
    }
    return r->data + tail;
}

void ns2s_ring_commit(ns2s_ring *r, size_t n) {
    if (r == NULL || n > r->cap - r->len) {
        return;
    }
    r->len += n;
}

const uint8_t *ns2s_ring_read_ptr(const ns2s_ring *r, size_t *contig) {
    if (r == NULL || r->data == NULL || r->len == 0) {
        if (contig != NULL) {
            *contig = 0;
        }
        return NULL;
    }
    size_t n = r->cap - r->head;
    if (n > r->len) {
        n = r->len;
    }
    if (contig != NULL) {
        *contig = n;
    }
    return r->data + r->head;
}

void ns2s_ring_consume(ns2s_ring *r, size_t n) {
    if (r == NULL || n > r->len) {
        return;
    }
    r->head = (r->head + n) % r->cap;
    r->len -= n;
    if (r->len == 0) {
        r->head = 0;
    }
}

int ns2s_ring_peek(const ns2s_ring *r, uint8_t *out, size_t n) {
    if (r == NULL || out == NULL || n > r->len) {
        return -1;
    }
    size_t first = r->cap - r->head;
    if (first > n) {
        first = n;
    }
    memcpy(out, r->data + r->head, first);
    if (n > first) {
        memcpy(out + first, r->data, n - first);
    }
    return (int) n;
}

ssize_t ns2s_ring_write(ns2s_ring *r, const void *src, size_t n) {
    if (r == NULL || (src == NULL && n != 0)) {
        errno = EINVAL;
        return -1;
    }
    if (n > ns2s_ring_writable(r)) {
        n = ns2s_ring_writable(r);
    }
    const uint8_t *p = (const uint8_t *) src;
    size_t done = 0;
    while (done < n) {
        size_t contig = 0;
        uint8_t *dst = ns2s_ring_write_ptr(r, &contig);
        if (dst == NULL || contig == 0) {
            break;
        }
        size_t chunk = n - done;
        if (chunk > contig) {
            chunk = contig;
        }
        memcpy(dst, p + done, chunk);
        ns2s_ring_commit(r, chunk);
        done += chunk;
    }
    return (ssize_t) done;
}

ssize_t ns2s_ring_read(ns2s_ring *r, void *dst, size_t n) {
    if (r == NULL || (dst == NULL && n != 0)) {
        errno = EINVAL;
        return -1;
    }
    if (n > r->len) {
        n = r->len;
    }
    uint8_t *p = (uint8_t *) dst;
    size_t done = 0;
    while (done < n) {
        size_t contig = 0;
        const uint8_t *src = ns2s_ring_read_ptr(r, &contig);
        if (src == NULL || contig == 0) {
            break;
        }
        size_t chunk = n - done;
        if (chunk > contig) {
            chunk = contig;
        }
        memcpy(p + done, src, chunk);
        ns2s_ring_consume(r, chunk);
        done += chunk;
    }
    return (ssize_t) done;
}

ssize_t ns2s_ring_read_fd(ns2s_ring *r, int fd) {
    if (r == NULL || fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (r->len == r->cap) {
        errno = ENOBUFS;
        return -1;
    }
    size_t tail = (r->head + r->len) % r->cap;
    size_t first = r->cap - tail;
    size_t avail = r->cap - r->len;
    if (first > avail) {
        first = avail;
    }
    struct iovec iov[2];
    iov[0].iov_base = r->data + tail;
    iov[0].iov_len = first;
    iov[1].iov_base = r->data;
    iov[1].iov_len = avail - first;
    ssize_t n = readv(fd, iov, 2);
    if (n > 0) {
        r->len += (size_t) n;
    }
    return n;
}

ssize_t ns2s_ring_write_fd(ns2s_ring *r, int fd) {
    if (r == NULL || fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (r->len == 0) {
        return 0;
    }
    size_t first = r->cap - r->head;
    if (first > r->len) {
        first = r->len;
    }
    struct iovec iov[2];
    iov[0].iov_base = r->data + r->head;
    iov[0].iov_len = first;
    iov[1].iov_base = r->data;
    iov[1].iov_len = r->len - first;
    ssize_t n = writev(fd, iov, 2);
    if (n > 0) {
        ns2s_ring_consume(r, (size_t) n);
    }
    return n;
}
