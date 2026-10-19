# Те же ключи, что src/netd_minimal.mak в godminer.
ARCH  ?= $(shell uname -m)
UNAME ?= $(shell uname -o)
R3       ?= ../R3-lib

ifeq ($(ARCH),armv7)
  OPTIMIZATION = -march=armv7-a -mtune=cortex-a8 -mfpu=neon -mfloat-abi=hard
else ifeq ($(ARCH),aarch64)
  OPTIMIZATION = -march=armv8-a+crypto
else ifeq ($(ARCH),x86_64)
  OPTIMIZATION = -march=native
endif
OPTIMIZATION += -ffast-math -ftree-vectorize

CC = gcc $(OPTIMIZATION)
CFLAGS  = -std=gnu11 -O3 -fPIC -DGnuPG -Isrc -I$(R3)/src -include src/gpg_build.h
LDFLAGS = -s -pthread

ifeq ($(UNAME),GNU/Linux)
CFLAGS += -D_GNU_SOURCE -U_FORTIFY_SOURCE -fno-stack-protector
CFLAGS += -D_BITS_STDIO_H
endif

LIB = $(R3)/libr3_$(ARCH).a

.PHONY: all clean cksum hmac ttl
all: gpg cksum

SRC = src/gpg_sign.c src/gpg_armor.c src/sign.c src/rsa.c src/gzip.c
# SHA-1, SHA-256 (-u sha256), SHA-384/512 и усечения из sha512.c, MD5,
# SHA3-224/256/384/512, BLAKE2s/b, Streebog-256/512, GOST R 34.11-94.
# SM3 в src/sm3.c не регистрируется: MESSAGE_DIGEST стоит под #if 0, в hmac.h нет MD_SM3.
HASH_SRC = \
	src/sha1.c \
	src/sha512.c \
	src/md5.c \
	src/shake256.c \
	src/blake2b.c \
	src/blake2s.c \
	src/stribog.c \
	src/gosthash.c

gpg: $(SRC) $(HASH_SRC) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(HASH_SRC) -Wl,-u,sha256 $(LIB) $(LDFLAGS) -lm -lz

# Список файлов — src/Makefile-cksum. Демонстрационный main в r3_args.c не становится точкой входа.
CKSUM_SRC = src/cksum.c src/crc16_clmul.c
cksum: $(CKSUM_SRC) src/r3_args.c src/crc.h
	$(CC) $(CFLAGS) -c -o src/r3_args.o src/r3_args.c -Dmain=r3_args_demo
	$(CC) $(CFLAGS) -flax-vector-conversions -o $@ $(CKSUM_SRC) src/r3_args.o $(LDFLAGS)

ttl: src/ttl_filter.c src/ttl_filter.h
	$(CC) $(CFLAGS) -DTTL_FILTER_MAIN -o $@ src/ttl_filter.c $(LDFLAGS)

clean:
	rm -f gpg cksum hmac ttl src/r3_args.o src/gosthash.o

# Отдельная цель: векторы из src/hmac.c (digest, HMAC, PBKDF2, KDF, HKDF).
# SHA-224 берётся из src/sha.c. Там же свои SHA-1 и SHA-256, поэтому
# sha1.c и -u,sha256 сюда не подключаются.
# main в gosthash.c переименован, точкой входа остаётся hmac.c.
HMAC_SRC = \
	src/sha.c \
	src/sha512.c \
	src/md5.c \
	src/shake256.c \
	src/blake2b.c \
	src/blake2s.c \
	src/stribog.c \
	$(R3)/src/r3_slist.c \
	$(R3)/src/r3_slice.c

HMAC_CFLAGS = $(filter-out -DGnuPG -include src/gpg_build.h,$(CFLAGS))

hmac: src/hmac.c $(HMAC_SRC) src/gosthash.c
	$(CC) $(HMAC_CFLAGS) -c -o src/gosthash.o src/gosthash.c -Dmain=gosthash_demo
	$(CC) $(HMAC_CFLAGS) -DTEST_HMAC -o $@ src/hmac.c $(HMAC_SRC) src/gosthash.o $(LDFLAGS)
