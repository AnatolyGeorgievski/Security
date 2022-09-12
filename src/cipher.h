#ifndef CIPHER_H
#define CIPHER_H
#include <inttypes.h>
#include "segment.h"

typedef struct _Cipher Cipher;
typedef struct _Ciph Ciph;
struct _Cipher {
    int id;
    const char* name;
    const unsigned int block_len;   // размер блока
    const unsigned int ctx_size;    // длина контекста
    void (*key_exp)(void* ctx, const uint8_t* key, int klen, int ekb);
    void (*encrypt)(void* ctx);    //!< шифрование
    void (*decrypt)(void* ctx);    //!< функция дешифрации
};
struct _Ciph {
    const Cipher* cipher;
    void* ctx;// контекст
    uint8_t* iv;
//    unsigned int ekb;     // эффективный размер ключа см RC2
    void (*encrypt)(Ciph *ciph, uint8_t* dst, const uint8_t* src, int blocks);    //!< режим шифрования
    union {
        void (*decrypt)(Ciph *ciph, uint8_t* dst, const uint8_t* src, int blocks);    //!< режим дешифрации
        void (*mac)(Ciph *ciph, uint8_t* dst, const uint8_t* src, int blocks);    //!< режим дешифрации
    };
};
typedef struct _CiphAEAD AEAD_t;
struct _CiphAEAD {
	struct _Ciph;// базовый класс
	uint8_t* aad;
	uint8_t* tag;
	size_t iv_len;
	size_t aad_len;
	size_t tag_len;
};


enum _CipherId {
    CIPH_NONE=0,
    CIPH_AES,
    CIPH_GOST,
    CIPH_RC2,
    CIPH_RC5,
    CIPH_DES,
    CIPH_TDES,      // Triple DES
    CIPH_MAGMA,     // GOST R 34.12-2015
    CIPH_KUZNYECHIK,// GOST R 34.12-2015
	CIPH_CHACHA,
};
enum {
    CIPH_MODE_ECB=0,
    CIPH_MODE_CBC,
    CIPH_MODE_CFB,
    CIPH_MODE_CFB8, // 8-бит вариант функции
    CIPH_MODE_OFB,
    CIPH_MODE_CTR,
    CIPH_MODE_XEX,
    CIPH_MODE_XTS,
    CIPH_MODE_CCM,
    CIPH_MODE_GCM,
    CIPH_MODE_GCM_SIV,
	
    CIPH_MODE_CMAC,
    CIPH_MODE_MGM, // ГОСТ
    CIPH_MODE_GCTR,// режим гаммирования ГОСТ Р 34.13-2015
    CIPH_MODE_MAC_GOST,// режим иммитовставки ГОСТ Р 34.13-2015
    CIPH_MODE_IMIT,// иммитовставка по гостам
};
/*! параметры алгоритма ГОСТ, указываются в качестве аргумента ekb при разветывании ключей */
enum {
Gost28147_Test_ParamSet,
Gost28147_CryptoProParamSet_A, /* 1.2.643.2.2.31.1 */
Gost28147_CryptoProParamSet_B, /* 1.2.643.2.2.31.2 */
Gost28147_CryptoProParamSet_C, /* 1.2.643.2.2.31.3 */
Gost28147_CryptoProParamSet_D, /* 1.2.643.2.2.31.4 */
Gost28147_TC26_ParamSet_Z,     /* 1.2.643.7.1.2.5.1.1 */
Gost28147_UKR_SBOX1,           /* 1.2.840. */
GOST28147_PARAMSET_COUNT
};

enum { // зависимости от аппаратной поддержки
    CIPH_DEPENDS_NONE   = 0,
#ifdef __i386__
    CIPH_DEPENDS_SSE2   =(1<<0),
    CIPH_DEPENDS_SSE3   =(1<<1),
    CIPH_DEPENDS_SSSE3  =(1<<2),
    CIPH_DEPENDS_SSE4_1 =(1<<3),
    CIPH_DEPENDS_AVX    =(1<<4),
    CIPH_DEPENDS_AVX2   =(1<<5),

    CIPH_DEPENDS_AES    =(1<<6),
    CIPH_DEPENDS_CLMUL  =(1<<7),
    CIPH_DEPENDS_VAES   =(1<<8),
    CIPH_DEPENDS_GFNI   =(1<<9),
#endif
};
#if 0
#define CIPHER(id) \
    const Cipher id##_ SEGMENT_ATTR(Cipher) =
#else
#define CIPHER(id) \
    static const Cipher id##_cipher;\
    static void __attribute__((constructor)) id##_reg(){ cipher_register(&id##_cipher); }\
    static const Cipher id##_cipher =
#endif // 0
#define CIPH_ALIGN __attribute__((__aligned__(16)))
#define CIPH_AES_DECRYPT 0x10000

void cipher_register(const Cipher* ciph);
Ciph* cipher_select(int id, int mode);
void cipher_set_key(Ciph* ciph, uint8_t* key, int klen, int ekb);
//void cipher_set_iv (Ciph* ciph, uint8_t* iv,  int vlen);
//void cipher_set_aad(Ciph* ciph, uint8_t* aad, int vlen);
void cipher_free   (Ciph* ciph);

/*
надо определить CMAC CBC ECB CCM ITM
 */

#endif // CIPHER_H
