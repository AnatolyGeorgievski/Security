#ifndef RSA_H
#define RSA_H
#include "mpz.h"
#include <stdio.h>
#include <stdint.h>
typedef struct _RSA_Key RSA_Key;
typedef struct _RSA_PrivateKey RSA_PrivateKey;
struct _RSA_Key {
    int klen;
    unsigned int e;
    mpz_t n;
};
struct _RSA_PrivateKey {
    int klen;
    mpz_t p;
    mpz_t q;
    mpz_t dP;
    mpz_t dQ;
    mpz_t qInv;
};
int rsa_pkcs_sign(mpz_t sign, RSA_PrivateKey *pKey, uint8_t *msg, int mlen);
int rsa_pkcs_verify(mpz_t sign, RSA_Key *pKey, uint8_t *msg, int mlen);
int rsa_EME_pkcs_verify(uint8_t *signature, RSA_Key *pKey, uint8_t *msg, int mlen);
#endif
