#ifndef SIGN_H
#define SIGN_H
#include <inttypes.h>
#include "segment.h"

typedef struct _Sign Sign;
typedef struct _SignCtx SignCtx;
struct _SignCtx {
    int id_hash_alg;//!< идентификатор алгоритма
    int id_hash_len;//!< длина
    int id_curve;
    void* params;
};
struct _Sign {
    int id;
    char* name;   // имя алгоритма
    unsigned int signature_len;    //!< размер блока
    unsigned int public_key_len;   //!< размер блока
    int (*verify)(const SignCtx *sign, const uint8_t* public_key,
                  const uint8_t* signature, const uint8_t* src, int length);
    int (*sign)  (const SignCtx *sign, const uint8_t* private_key,
                        uint8_t* signature, const uint8_t* src, int length);
};
enum {
    SIGN_NONE=0,
    SIGN_RSA,   //RSA
    SIGN_ECDSA,   //NIST
    SIGN_ECC_GOST,
    SIGN_DSA,   //NIST
    SIGN_EdDSA, // алгоритмы бывают разные.

//    SIGN_ECDSA = SIGN_ECC,
};
enum {
SIGN_ID_None=0,
SIGN_ID_md5WithRSAEncryption,
SIGN_ID_sha1WithRSAEncryption,
SIGN_ID_sha224WithRSAEncryption,
SIGN_ID_sha256WithRSAEncryption,
SIGN_ID_sha384WithRSAEncryption,
SIGN_ID_sha512WithRSAEncryption,
SIGN_ID_sha512_224WithRSAEncryption,
SIGN_ID_sha512_256WithRSAEncryption,
SIGN_ID_GostR3411_94_with_GostR3410_2001,
SIGN_ID_GostR3411_2012_with_GostR3410_2012_256,
SIGN_ID_GostR3411_2012_with_GostR3410_2012_512,
SIGN_ID_sha256_with_secp256r1,
//SIGN_ID_GostR3411_2012
};
enum { // зависимости от аппаратной поддержки
    SIGN_DEPENDS_NONE   = 0,
#ifdef __i386__
    CIPH_DEPENDS_SSE2   =(1<<0),
    CIPH_DEPENDS_SSE3   =(1<<1),
    CIPH_DEPENDS_SSSE3  =(1<<2),
    CIPH_DEPENDS_SSE4_1 =(1<<3),
    CIPH_DEPENDS_AVX    =(1<<4),
    CIPH_DEPENDS_AVX2   =(1<<5),

    CIPH_DEPENDS_AES    =(1<<6),
    CIPH_DEPENDS_CLMUL  =(1<<7),
#endif
};

#if 0
#define SIGNATURE(id) \
    const Sign id##_ SEGMENT_ATTR(SignSchemes) =
#else
#define SIGNATURE(id) \
    static const Sign id##_sign;\
    static void __attribute__((constructor)) id##_reg(){ sign_register(&id##_sign); }\
    static const Sign id##_sign =
#endif // 0

void sign_register(const Sign* sign);
const Sign* sign_select(int alg_id, int paramset_id);
static inline
void sign_unref(const Sign* sign) {}


/*! Перечисление идентификаторов кривых */
enum {
EC_SEC_P112r1=0,
EC_SEC_P128r1,
EC_SEC_P128r2,
EC_SEC_P160k1,
EC_SEC_P160r1,
EC_SEC_P160r2,
EC_SEC_P192k1,
EC_SEC_P224k1,
EC_SEC_P256k1,
//EC_SEC_P256v1,// prime256v1
EC_X962_P192v2,
EC_X962_P192v3,
EC_X962_P239v1,
EC_X962_P239v2,
EC_X962_P239v3,
EC_NIST_P192,
EC_NIST_P224,
EC_NIST_P256,
EC_NIST_P384,
EC_NIST_P521,
EC_GOST_TEST,
EC_GOST_CRYPTO_PRO_A,
EC_GOST_CRYPTO_PRO_B,
EC_GOST_CRYPTO_PRO_C,
EC_GOST_3410_12_TEST,
EC_TC26_GOST_3410_12_A,
EC_TC26_GOST_3410_12_B,
EC_TC26_GOST_3410_2012_256_A,
EC_TC26_GOST_3410_2012_512_C,
EC_WTLS9_P160,
// EC_WTLS12_P224 = EC_NIST_P224,
EC_NUMS_P256d1,
EC_NUMS_P384d1,
EC_NUMS_P512d1,
EC_NUMS_P256t1,// Twisted Edwards
EC_NUMS_P384t1,
EC_NUMS_P512t1,
EC_SM2,
EC_WEI25519,
EC_COUNT,

EC_GOST_CRYPTO_PRO_XchA = EC_GOST_CRYPTO_PRO_A,
EC_GOST_CRYPTO_PRO_XchB = EC_GOST_CRYPTO_PRO_C,
EC_TC26_GOST_3410_2012_256_B = EC_GOST_CRYPTO_PRO_A,
EC_TC26_GOST_3410_2012_256_C = EC_GOST_CRYPTO_PRO_B,
EC_TC26_GOST_3410_2012_256_D = EC_GOST_CRYPTO_PRO_C

};
#endif // SIGN_H
