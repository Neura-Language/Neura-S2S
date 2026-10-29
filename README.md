# Neura-S2S C11 加密库（Phase 3）

纯 C11 重写的 Neura-S2S 加密层。Phase 2 + Phase 3 已完成：

- 完整 hello/ack/finish/ready 二进制编解码 + HMAC transcript + 防降级；
- X-Wing（X25519 + ML-KEM-768）混合 KEM；
- 会话 AEAD 收发 + 每帧 HKDF-SHA512 消息链棘轮，旧密钥立即 `sodium_memzero`；
- 0.3s KEM 异步重置：Session 状态机 + `ns2s_kem_job` + worker pool + eventfd 唤醒 epoll Reactor（主线程只做 epoll/状态推进，不执行 KEM）；
- mlock + `madvise(MADV_DONTDUMP)` 密钥内存保护；
- 固定容量 Ring Buffer，包长度先校验再分配；
- ASan/UBSan 下跑通完整握手、双向消息、ratchet、红队与端到端 fuzz；
- 100% 离线构建（libsodium vendored，无任何下载命令）。

## 1. 硬性约束对照

| 要求 | 实现 |
|---|---|
| 禁止手搓密码学原语 | 全部调用 libsodium 1.0.22：`crypto_kem_xwing_*`、`crypto_aead_*`、`crypto_kdf_hkdf_sha512_*`、`crypto_auth_hmacsha512_*`、`crypto_hash_sha512_*` |
| 禁止 `memset` 清密钥 | 密钥路径统一 `sodium_memzero()` / `ns2s_secure_zero()` |
| mlock | `ns2s_secure_alloc()` 使用 `posix_memalign` + `mlock`（页对齐） |
| 防 Core Dump | `madvise(MADV_DONTDUMP)` + 可选 `setrlimit(RLIMIT_CORE, 0)` |
| epoll Reactor | `src/s2s_reactor.c`，非阻塞 accept/read，eventfd 唤醒 |
| 包长度先校验再分配 | `ns2s_frame_header_decode(..., max_frame)`；Ring/`frame_buf` 在连接建立时一次分配 |
| Ring Buffer | `src/s2s_ring.c`，固定容量、支持跨环回绕、读/写/peek/consume |
| KEM 不阻塞 Reactor | `ns2s_kem_pool` worker + eventfd completion |
| ASan | Makefile 默认 `-fsanitize=address,undefined -fno-omit-frame-pointer` |

## 2. 依赖

libsodium 1.0.22 源码位于：

```text
third_party/libsodium-src/
```

已静态编译安装到：

```text
third_party/libsodium/lib/libsodium.a
third_party/libsodium/include/
```

重建依赖：

```bash
make libsodium
```

选择 1.0.22 的原因：它原生提供 `crypto_kem_xwing`（X25519 + ML-KEM-768）、
HKDF-SHA512 与 AES-GCM/ChaCha20；系统自带的 1.0.18 不具备这些接口。

## 3. 构建与测试

```bash
cd c-s2s
make clean
make -j
make test
```

默认 ASan/UBSan。当前结果：

```text
== build/test_ring ==
test_ring: OK
== build/test_handshake ==
test_handshake: OK
== build/test_redteam ==
test_redteam: OK
== build/test_e2e ==
test_e2e: OK
== build/test_ratchet ==
test_ratchet: OK
== build/test_kem_pool ==
test_kem_pool: OK
== build/test_reactor_fixes ==
test_reactor_fixes: OK（失败项：0）
== build/test_reactor_stress ==
test_reactor_stress: OK
== fuzz_e2e (100 iter) ==
fuzz_e2e: OK
```

其中 `test_e2e` 已改为**完全走真实 epoll 网络路径**：两个 Reactor 各占一个线程，
服务端 `listen(127.0.0.1:0)`，客户端非阻塞 `connect`，hello/ack/finish/ready 四步
握手与后续业务帧全部由事件循环驱动，末尾还会比对两侧的方向链密钥是否逐字节一致。

`test_handshake` 实际跑通 X-Wing 四步 KEM：

```text
client keypair
server keypair + Encaps(pk_c)      -> ss_s
client Decaps(ct_s) + Encaps(pk_s) -> ss1 / ss_c
server Decaps(ct_c)                -> ss2
assert ss_s == ss1, ss_c == ss2
```

## 4. 核心握手状态机

完整定义见 `include/neura/s2s_handshake.h`。核心结构：

```c
typedef enum {
    NS2S_HS_INIT = 0,
    NS2S_HS_KEM_CLIENT_HELLO,
    NS2S_HS_HELLO_SENT,
    NS2S_HS_KEM_CLIENT_FINISH,
    NS2S_HS_FINISH_SENT,
    NS2S_HS_READY_RX,
    NS2S_HS_KEM_SERVER_ACK,
    NS2S_HS_ACK_SENT,
    NS2S_HS_KEM_SERVER_FINISH,
    NS2S_HS_READY_SENT,
    NS2S_HS_ESTABLISHED,
    NS2S_HS_FAILED
} ns2s_hs_state;

typedef struct {
    ns2s_role role;
    ns2s_hs_state state;
    ns2s_hs_event last_event;
    ns2s_hs_action pending_action;
    ns2s_kem_phase kem_phase;
    uint32_t flags;

    uint8_t alg_mask;
    uint8_t alg;
    uint8_t hello_nonce[16];
    uint8_t ack_nonce[16];
    uint8_t finish_nonce[16];
    uint8_t ready_nonce[16];

    uint8_t root_key[32];
    uint8_t client_sk[32];
    uint8_t server_sk[32];
    uint8_t ss_client[32];
    uint8_t ss_server[32];
    uint8_t rk0[64];
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];

    ns2s_hs_transcript_keys tx;
    uint8_t transcript[64];
    uint64_t started_ms;
    uint64_t deadline_ms;
    uint64_t kem_epoch;
    int last_status;
    struct ns2s_kem_job *kem_inflight;
} ns2s_handshake;
```

KEM 任务：

```c
typedef struct ns2s_kem_job {
    ns2s_kem_op op;
    ns2s_kem_phase phase;
    uint64_t epoch;

    uint8_t pk[1216];      /* X-Wing public key */
    uint8_t sk[32];        /* X-Wing secret key */
    uint8_t ct[1120];      /* X-Wing ciphertext */
    uint8_t ss[32];
    uint8_t ss_peer[32];

    uint8_t peer_pk[1216];
    uint8_t peer_ct[1120];

    int status;
    int completion_fd;     /* eventfd：worker 写 1 唤醒 Reactor */
    struct ns2s_kem_job *next;
} ns2s_kem_job;
```

状态机动作：

```text
client: INIT --START--> KEM_CLIENT_HELLO --KEM_DONE--> HELLO_SENT
        --ACK_RX--> KEM_CLIENT_FINISH --KEM_DONE--> FINISH_SENT
        --READY_RX--> ESTABLISHED

server: INIT --HELLO_RX--> KEM_SERVER_ACK --KEM_DONE--> ACK_SENT
        --FINISH_RX--> KEM_SERVER_FINISH --KEM_DONE--> READY_SENT
        --READY_SENT--> ESTABLISHED
```

任何非法事件 → `FAIL_CLOSE`；KEM 失败 → `FAIL_CLOSE`。

## 5. 协议（与 Go 版一致的安全目标）

```text
C -> S  hello : magic|ver|alg_mask|nonce|pk_c|HMAC_RK(transcript)
S -> C  ack   : magic|ver|alg|nonce|pk_s|ct_s|HMAC_RK(transcript)
C -> S  finish: magic|ver|alg|nonce|ct_c|HMAC_SK_c2s(transcript)
S -> C  ready : magic|ver|alg|nonce|HMAC_SK_s2c(transcript)

combined = ss_s || ss_c
RK0      = HKDF-SHA512(ikm=combined, salt=RK, info="neura-s2s-v1/init-root", 64)
SK_c2s   = HKDF-SHA512(RK0, info=".../c2s", 32)
SK_s2c   = HKDF-SHA512(RK0, info=".../s2c", 32)
```

数据帧头（Phase 2 将接入 AEAD/链棘轮）：

```text
[ver 1][alg 1][dir 1][seq 4][ratchet_id 4][plaintext_len 4] = 15 bytes
AAD = 上述 15 字节
```

解析顺序强制为：

1. Ring 可读长度 ≥ 帧头；
2. `plaintext_len <= max_frame` 且无整数溢出；
3. Ring 可读长度 ≥ 头 + nonce + ciphertext + tag；
4. 复制到连接建立时预分配的 `frame_buf`；
5. 解密/回调。

解析路径**不 malloc**，也不使用线上长度作为分配上限。

## 6. 目录

```text
c-s2s/
├── Makefile
├── include/neura/
│   ├── s2s.h                 常量、帧头、session/chain 结构
│   ├── s2s_handshake.h       状态机/KEM job 结构（本轮核心输出）
│   ├── s2s_crypto.h          libsodium 封装接口
│   ├── s2s_secure_mem.h      mlock/DONTDUMP/sodium_memzero
│   ├── s2s_ring.h            固定容量 Ring Buffer
│   └── s2s_reactor.h         epoll Reactor / conn / KEM pool
├── src/
│   ├── s2s_crypto.c          libsodium 封装
│   ├── s2s_frame.c           帧头编解码 + 长度先校验
│   ├── s2s_handshake.c       FSM + KEM job 执行 + 密钥派生
│   ├── s2s_handshake_codec.c hello/ack/finish/ready 编解码
│   ├── s2s_session.c         会话 AEAD + 链棘轮 + 0.3s 重置
│   ├── s2s_reactor.c         epoll Reactor + 握手/会话胶水层
│   ├── s2s_ring.c            固定容量 Ring Buffer
│   └── s2s_secure_mem.c      mlock / DONTDUMP / memzero
├── tests/
│   ├── test_ring.c           Ring 回绕/边界
│   ├── test_handshake.c      FSM 迁移
│   ├── test_redteam.c        AEAD 篡改 / 帧长度 / 安全内存
│   ├── test_e2e.c            ★ 真实 epoll 网络路径端到端（双 Reactor）
│   ├── test_ratchet.c        0.3s KEM 重置 / 跨 epoch
│   ├── test_kem_pool.c       KEM worker pool
│   ├── test_reactor_fixes.c  安全修复回归（app_cap / conn id / finish 门控…）
│   ├── test_reactor_stress.c ★ 4 客户端并发握手 + 回显
│   └── fuzz_e2e.c            握手 + 会话随机变异
└── third_party/
    ├── libsodium-src/        libsodium 1.0.22 源码
    └── libsodium/            静态库 + headers
```

## 7. 握手 ↔ Reactor 胶水层（Phase 3）

`src/s2s_reactor.c` 现在把「握手状态机」和「业务会话」完整接线，事件驱动、无阻塞：

```text
accept/connect
   └─ ns2s_conn_init()           预认证小缓冲（8 KiB）+ secure handshake region
   └─ ns2s_handshake_init()      置 3s deadline
   └─ EPOLLIN ─► conn_hs_pump()  按 "NS2H" magic + type 定长切分握手报文
                   └─ ns2s_hs_decode_*() → ns2s_handshake_step()
                        └─ START_KEM_*  → KEM pool（worker 执行 X-Wing，eventfd 唤醒）
                        └─ SEND_*       → encode → tx ring → writev（EAGAIN 挂 EPOLLOUT）
                        └─ SERVER_FINISH 的 KEM 回来时：verify_finish() → 才允许 READY
   └─ ESTABLISHED ─► conn_establish()
                       ├─ ns2s_conn_upgrade()      预认证 8 KiB → max_frame 容量
                       ├─ ns2s_session_init()      rk0 / c2s / s2c 进 session
                       ├─ auto_ratchet = (role==SERVER)   0.3s KEM 重置由服务端发起
                       ├─ session_ready = 1
                       ├─ 擦除 handshake 里的密钥副本
                       └─ on_established(conn)    应用可以开始 ns2s_conn_send()
会话态
   └─ EPOLLIN ─► reactor_dispatch_session()  AEAD 解帧 → ctrl → on_app()
   └─ reactor_tick()  ─► ns2s_session_ratchet_tick() → KEM pool
   └─ KEM done ─► apply_ratchet_job() / conn_hs_kem_done()
```

关键保证：

| 项 | 实现 |
|---|---|
| KEM 不阻塞 epoll | 所有 X-Wing 运算在 worker pool；完成经 `eventfd` 唤醒 Reactor |
| 未配置 RootKey 不能联网 | `ns2s_reactor_listen()` / accept 都要求 `ns2s_reactor_set_root_key()`，否则 `NS2S_ERR_STATE` / 直接 close（无明文降级） |
| 握手超时 | `deadline_ms` + `NS2S_HANDSHAKE_TIMEOUT_MS`，`reactor_tick` 回收 |
| 错误隔离 | 任何错误只置 `conn->dead`，由 `reactor_sweep()` 在本批事件处理完后统一回收，绝不遍历 `events[]` 时释放连接 |
| 跨线程发送 | `ns2s_reactor_post()` 把任务投递到 Reactor 线程（session 非线程安全） |
| 连接 id | `next_conn_id` 单调递增；`reactor_find_conn()` 命中重复即返回 NULL（KEM 结果绝不投错连接） |
| 写回背压 | tx ring + EPOLLOUT；ring 满时 `ns2s_conn_send` 返回 `NS2S_ERR_LENGTH`，不静默截断 |

新增公开 API（`include/neura/s2s_reactor.h`）：

```c
int      ns2s_reactor_set_root_key(ns2s_reactor *r, const uint8_t rk[32]);
void     ns2s_reactor_set_on_established(ns2s_reactor *r, ns2s_established_cb cb);
int      ns2s_reactor_listen(ns2s_reactor *r, const char *host, uint16_t port);
uint16_t ns2s_reactor_port(const ns2s_reactor *r);
int      ns2s_reactor_connect(ns2s_reactor *r, const char *host, uint16_t port,
                              const uint8_t rk[32], uint64_t *out_id);
int      ns2s_reactor_post(ns2s_reactor *r, ns2s_task_fn fn, void *arg);
int      ns2s_conn_send(ns2s_conn *c, const uint8_t *pt, size_t len);
ns2s_session *ns2s_conn_session(ns2s_conn *c);
int      ns2s_conn_upgrade(ns2s_conn *c);
```

最小用法：

```c
static void on_est(ns2s_conn *c) { ns2s_conn_send(c, (const uint8_t *)"hi", 3); }
static void on_msg(ns2s_conn *c, const uint8_t *pt, size_t len) { /* 已解密 */ }

ns2s_reactor r;
ns2s_reactor_init(&r, 4096, 64, 2, NULL, on_msg);
ns2s_reactor_set_root_key(&r, root_key);
ns2s_reactor_set_on_established(&r, on_est);
ns2s_reactor_listen(&r, "0.0.0.0", 9443);
ns2s_reactor_run(&r);   /* 单线程事件循环 */
```

## 8. 红队测试状态

当前 `test_redteam` 已覆盖：

- AES-GCM / ChaCha20-Poly1305 密文/tag 篡改 → `NS2S_ERR_AUTH`；
- 帧头超长 `plaintext_len` → `NS2S_ERR_LENGTH`（发生任何分配之前）；
- seq/ratchet/dir 重放 → `NS2S_ERR_REPLAY` / `NS2S_ERR_INVALID`；
- HKDF 不同 epoch 派生出不同链密钥；
- `sodium_memzero` 后密钥缓冲区全零；
- mlock + MADV_DONTDUMP 分配成功，释放走 secure_free。

Phase 2/3 已完成（原待办 → 现状）：

- ✅ hello/ack/finish/ready 编解码 + HMAC transcript；
- ✅ 会话 AEAD 收发 + seq/ratchet + 0.3s KEM 重置；
- ✅ Reactor 把 `completion_fd` 映射回连接并推进 FSM（`reactor_drain_kem`）；
- ✅ 跨 epoch：`test_ratchet` 覆盖旧根/旧链不能解新帧；
- ✅ fuzz：`fuzz_e2e`（握手 + 会话 + 篡改）；
- ✅ `test_e2e` 走真实 epoll 网络路径（两个 Reactor 两线程），并断言终态方向密钥一致；
- ✅ `test_reactor_stress`：4 客户端并发握手 + 回显，验证 KEM 结果不串连接。

仍待补：目标硬件上的 handshake/frame benchmark 与 P99；libsodium 源码哈希清单。
