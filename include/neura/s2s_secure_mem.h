/*
 * 密钥内存保护：
 *   - mlock：防 Swap；
 *   - madvise(MADV_DONTDUMP)：防 Core Dump；
 *   - sodium_memzero：唯一允许的清理方式；
 *   - 释放时 munlock + MADV_DODUMP + sodium_memzero。
 */
#ifndef NEURA_S2S_SECURE_MEM_H
#define NEURA_S2S_SECURE_MEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *ptr;
    size_t len;       /* 调用方请求的逻辑长度 */
    size_t alloc_len; /* 页对齐后的实际长度（madvise 需要页对齐） */
    int locked;
    int no_dump;
} ns2s_secure_region;

/*
 * 严格模式：mlock 或 madvise 失败即返回错误并释放内存。
 * 不使用 calloc 清零作为安全保证；密钥仍必须 sodium_memzero。
 */
int ns2s_secure_alloc(ns2s_secure_region *r, size_t len);
void ns2s_secure_free(ns2s_secure_region *r);

/* sodium_memzero 包装；禁止在密钥路径使用 memset。 */
void ns2s_secure_zero(void *p, size_t len);

/* core dump 全局兜底（可选，在 main/init 调用）。 */
int ns2s_secure_disable_core_dumps(void);

#ifdef __cplusplus
}
#endif

#endif /* NEURA_S2S_SECURE_MEM_H */
