/* Кривые не собраны: в дереве нет mp.h, на который смотрит ecc.h. */
#include <stdio.h>
#include <stdint.h>
struct _GNode;
typedef struct _GNode GNode;
typedef struct _ECPrivateKey ECPrivateKey_t;
typedef struct _PrivateKeyInfo PrivateKeyInfo_t;
ECPrivateKey_t *der_eckey_parse(uint8_t *data, int length)
{
    (void)data; (void)length;
    fprintf(stderr, "eckey не собран: нет mp.h\n");
    return NULL;
}
int der_eckey_verify(ECPrivateKey_t *eckey, GNode *curve_oid)
{
    (void)eckey; (void)curve_oid;
    return -1;
}
int der_eckey_gen2(PrivateKeyInfo_t *eckey, GNode *curve_oid)
{
    (void)eckey; (void)curve_oid;
    fprintf(stderr, "eckey не собран: нет mp.h\n");
    return -1;
}
int der_ec_curve(GNode *curve_oid)
{
    (void)curve_oid;
    return -1;
}
void ecc_curve_list(void)
{
    fprintf(stderr, "список кривых не собран: нет mp.h\n");
}
uint8_t *xml_detach_sig(const void *md, uint8_t *hash, const char *filename)
{
    (void)md; (void)hash; (void)filename;
    fprintf(stderr, "xml подпись не собрана\n");
    return NULL;
}
