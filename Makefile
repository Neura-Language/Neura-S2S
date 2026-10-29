# Offline-first build.
#
# 约束：
#   1. libsodium 源码已 vendoring 在 third_party/libsodium-src；
#   2. 构建路径不包含任何下载/网络命令；
#   3. 显式清空代理变量，避免环境代理影响本地编译；
#   4. 若静态库 missing，只用本地 configure/make 重建，绝不下载。

CC := /usr/bin/gcc
AR := ar

# 清空代理，确保任何子进程都不会尝试外网。
unexport http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY
export http_proxy :=
export https_proxy :=
export HTTP_PROXY :=
export HTTPS_PROXY :=
export ALL_PROXY :=
export NO_PROXY := *
export no_proxy := *

SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer
# 加固：PIE + 全 RELRO + FORTIFY_SOURCE（Release 时把 -O1 换成 -O2 并去掉 $(SAN)）
HARDEN ?= -fPIE -D_FORTIFY_SOURCE=2
CFLAGS ?= -std=c11 -O1 -g -Wall -Wextra -Werror -Wpedantic -D_GNU_SOURCE -Iinclude -Ithird_party/libsodium/include $(HARDEN) $(SAN)
LDFLAGS ?= $(SAN) -pie -Wl,-z,relro,-z,now -Lthird_party/libsodium/lib -lsodium -lpthread -lm

BUILD := build
SRC := \
	src/s2s_ring.c \
	src/s2s_secure_mem.c \
	src/s2s_crypto.c \
	src/s2s_frame.c \
	src/s2s_session.c \
	src/s2s_handshake_codec.c \
	src/s2s_handshake.c \
	src/s2s_reactor.c

OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))
LIB := $(BUILD)/libs2s.a

TESTS := $(BUILD)/test_ring $(BUILD)/test_handshake $(BUILD)/test_redteam $(BUILD)/test_e2e \
         $(BUILD)/test_ratchet $(BUILD)/test_kem_pool $(BUILD)/test_reactor_fixes \
         $(BUILD)/test_reactor_stress
LIBSODIUM_A := third_party/libsodium/lib/libsodium.a
LIBSODIUM_SRC := third_party/libsodium-src

.PHONY: all test asan clean libsodium offline check-offline

all: check-offline $(LIB) $(TESTS)

check-offline:
	@if grep -nE '(^|[^a-zA-Z])(curl|wget)([^a-zA-Z]|$$)|git clone' \
	      src/*.c include/neura/*.h tests/*.c >/dev/null 2>&1; then \
	  echo "ERROR: network command found in source/test path" >&2; exit 1; \
	fi
	@if grep -nE '(curl|wget|git clone)' third_party/libsodium-src/autogen.sh >/dev/null 2>&1; then \
	  echo "ERROR: vendored autogen.sh still contains network commands" >&2; exit 1; \
	fi
	@echo "offline check: OK"
	@echo "offline check: OK"


offline: clean all test

libsodium: $(LIBSODIUM_A)

# 只用本地 vendored 源码重建；config.guess/config.sub 已随源码本地化。
# 如果源码缺失，直接失败，不尝试任何下载。
$(LIBSODIUM_A):
	@test -x $(LIBSODIUM_SRC)/configure || { \
	  echo "ERROR: vendored libsodium source missing at $(LIBSODIUM_SRC)" >&2; \
	  echo "       offline build cannot fetch it from the network." >&2; \
	  exit 1; \
	}
	@test -f $(LIBSODIUM_SRC)/config.guess || { \
	  echo "ERROR: $(LIBSODIUM_SRC)/config.guess missing (offline build)" >&2; \
	  exit 1; \
	}
	@test -f $(LIBSODIUM_SRC)/config.sub || { \
	  echo "ERROR: $(LIBSODIUM_SRC)/config.sub missing (offline build)" >&2; \
	  exit 1; \
	}
	cd $(LIBSODIUM_SRC) && \
	  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
	      -u all_proxy -u ALL_PROXY -u NO_PROXY -u no_proxy \
	  ./configure --prefix=$(abspath third_party/libsodium) \
	    --disable-shared --enable-static --disable-dependency-tracking && \
	  $(MAKE) -j"$$(nproc)" && $(MAKE) install

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD) libsodium
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJ) | $(BUILD)
	$(AR) rcs $@ $(OBJ)

$(BUILD)/test_%: tests/test_%.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/fuzz_e2e: tests/fuzz_e2e.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test: all $(BUILD)/fuzz_e2e
	@for t in $(TESTS); do echo "== $$t =="; ./$$t; done
	@echo "== fuzz_e2e (100 iter) =="; ./$(BUILD)/fuzz_e2e 100

asan: clean all test

clean:
	rm -rf $(BUILD)
