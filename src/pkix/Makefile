# pkix — просмотр PEM, CMS и контейнеров PKCS. Свой код Security и libr3.
# OCSP, OpenSSL, Windows и каталог Daemon сюда не входят.
ARCH ?= $(shell uname -m)
UNAME ?= $(shell uname -o)
R3 ?= ../../../R3-lib
SEC := ..
OCSP := ../bigbrother/ocsp

ifeq ($(ARCH),armv7)
  OPTIMIZATION = -march=armv7-a -mtune=cortex-a8 -mfpu=neon -mfloat-abi=hard
else ifeq ($(ARCH),aarch64)
  OPTIMIZATION = -march=armv8-a+crypto
else ifeq ($(ARCH),x86_64)
  OPTIMIZATION = -march=native
endif
OPTIMIZATION += -ffast-math -ftree-vectorize

CC = gcc $(OPTIMIZATION)
CFLAGS = -std=gnu11 -O3 -fPIC -Wall -I. -I$(OCSP) -I$(SEC) -include $(SEC)/gpg_build.h
CFLAGS += $(shell pkg-config --cflags glib-2.0)
CFLAGS += -idirafter $(R3)/src
LDFLAGS = -s -pthread $(shell pkg-config --libs glib-2.0)

ifeq ($(UNAME),GNU/Linux)
CFLAGS += -D_GNU_SOURCE -U_FORTIFY_SOURCE -fno-stack-protector
endif

LIB = $(R3)/libr3_$(ARCH).a
OBJ = obj

OCSP_SRC = \
	$(OCSP)/main_ocsp.c \
	$(OCSP)/cert_store.c \
	$(OCSP)/der_decode.c \
	$(OCSP)/der_encode.c \
	$(OCSP)/base64.c \
	$(OCSP)/der_oids.c \
	$(OCSP)/der_crl.c \
	$(OCSP)/der_cert.c \
	$(OCSP)/der_sign.c \
	$(OCSP)/der_cms.c \
	$(OCSP)/der_pkcs1.c \
	$(OCSP)/der_pkcs5.c \
	$(OCSP)/der_pkcs8.c \
	$(OCSP)/der_pkcs10.c \
	$(OCSP)/der_pkcs12.c \

DEMO_SRC = \
	$(SEC)/cipher.c \
	$(SEC)/hmac.c \
	$(SEC)/sign.c \
	$(SEC)/rsa.c \
	$(SEC)/gost28147.c \
	$(SEC)/gosthash.c \
	$(SEC)/stribog.c \
	$(SEC)/sha1.c \
	$(SEC)/sha512.c \
	$(SEC)/sha.c

LOCAL = http_rest.c ocsp_stub.c eckey_stub.c

OCSP_OBJ = $(patsubst $(OCSP)/%.c,$(OBJ)/ocsp_%.o,$(OCSP_SRC))
DEMO_OBJ = $(patsubst $(SEC)/%.c,$(OBJ)/sec_%.o,$(DEMO_SRC))
LOCAL_OBJ = $(LOCAL:%.c=$(OBJ)/%.o)

.PHONY: all clean
all: pkix

pkix: $(OCSP_OBJ) $(DEMO_OBJ) $(LOCAL_OBJ) $(LIB)
	$(CC) -o $@ $(OCSP_OBJ) $(DEMO_OBJ) $(LOCAL_OBJ) $(shell pkg-config --libs glib-2.0) $(LIB) -lm -pthread

$(OBJ)/ocsp_%.o: $(OCSP)/%.c
	@mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/sec_%.o: $(SEC)/%.c
	@mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ $< -Dmain=pkix_demo_main

$(OBJ)/%.o: %.c
	@mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf pkix $(OBJ)
