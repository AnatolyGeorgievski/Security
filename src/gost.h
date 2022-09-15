#ifndef GOST_H
#define GOST_H
#include <inttypes.h>

//void gost_init  (gost_ctx *ctx, const gost_subst_block *b);
//void gost_digest(gost_ctx *ctx, uint8_t *msg, int length, uint8_t *hash);
void gost_sum   (uint8_t  *tag, uint8_t *msg, int length);
#define GOST_PASRAMSET_TEST 0
#define GOST_PASRAMSET_CRYPTO_PRO 1
// ID = 0 Test ParamSet, ID=1 CryptoPro ParamSet
//void gost_hash  (uint8_t* hash, int id, char* message, int length);

//extern const gost_subst_block GostR3411_94_TestParamSet;
//extern const gost_subst_block GostR3411_94_CryptoProParamSet;
#endif // GOST_H
