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

.PHONY: all clean
all: gpg

SRC = src/gpg_sign.c src/gpg_armor.c src/sign.c src/rsa.c src/gzip.c
# SHA-1, SHA-256 (-u sha256), SHA3-224/256/384/512, BLAKE2s/b, Streebog-256/512, GOST R 34.11-94.
# sha512.c (SHA-2-512) is not in the tree.
HASH_SRC = \
	src/sha1.c \
	src/shake256.c \
	src/blake2b.c \
	src/blake2s.c \
	src/stribog.c \
	src/gosthash.c

gpg: $(SRC) $(HASH_SRC) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(HASH_SRC) -Wl,-u,sha256 $(LIB) $(LDFLAGS) -lm -lz

clean:
	rm -f gpg
