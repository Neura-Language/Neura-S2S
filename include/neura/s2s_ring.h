/* 固定容量 Ring Buffer：避免逐包 malloc 与长度字段驱动的内存放大。 */
#ifndef NEURA_S2S_RING_H
#define NEURA_S2S_RING_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;
    size_t cap;
    size_t head;
    size_t len;
} ns2s_ring;

int ns2s_ring_init(ns2s_ring *r, size_t cap);
void ns2s_ring_reset(ns2s_ring *r);
void ns2s_ring_free(ns2s_ring *r);

size_t ns2s_ring_readable(const ns2s_ring *r);
size_t ns2s_ring_writable(const ns2s_ring *r);
size_t ns2s_ring_capacity(const ns2s_ring *r);

/* 返回可写连续区间；commit 前不会改变 len。 */
uint8_t *ns2s_ring_write_ptr(ns2s_ring *r, size_t *contig);
void ns2s_ring_commit(ns2s_ring *r, size_t n);

/* 返回可读连续区间；consume 前不会改变 len。 */
const uint8_t *ns2s_ring_read_ptr(const ns2s_ring *r, size_t *contig);
void ns2s_ring_consume(ns2s_ring *r, size_t n);

/* 拷贝 n 字节到 out，但不消费。用于在 malloc/解密前检查帧头。 */
int ns2s_ring_peek(const ns2s_ring *r, uint8_t *out, size_t n);

/* 写入/读取用户缓冲区；返回实际字节数或负错误。 */
ssize_t ns2s_ring_write(ns2s_ring *r, const void *src, size_t n);
ssize_t ns2s_ring_read(ns2s_ring *r, void *dst, size_t n);

/* 非阻塞 fd 读写；返回 >=0 字节数，-1 errno（含 EAGAIN）。 */
ssize_t ns2s_ring_read_fd(ns2s_ring *r, int fd);
ssize_t ns2s_ring_write_fd(ns2s_ring *r, int fd);

#ifdef __cplusplus
}
#endif

#endif /* NEURA_S2S_RING_H */
