/* GPG signature
 \see [RFC 4880] OpenPGP Message Format            November 2007
 https://datatracker.ietf.org/doc/html/rfc4880
 \see [RFC 5581] The Camellia Cipher in OpenPGP, June 2009
 \see [RFC 6637] Elliptic Curve Cryptography (ECC) in OpenPGP
 \see [RFC 7748] Elliptic Curves for Security, January 2016
 \see [RFC 8017] PKCS #1: RSA Cryptography Specifications Version 2.2, November 2016
 \see [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA), January 2017
https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html

https://habr.com/ru/article/499746/#rec186465934

$ gcc `pkg-config glib-2.0 --cflags` -o pgp gpg_sign.c \
 r3_args.c rsa.c hmac.c mpz.c mpz_asm.c sign.c sha.c sha512.c \
 -lglib-2.0
$ gcc -O3 -march=native  `pkg-config glib-2.0 --cflags` -o pgp gpg_sign.c gpg_armor.c \
	rsa.c hmac.c sign.c base64.c \
	mpz.c mpz_asm.c sha.c sha512.c -lglib-2.0 -lz
$ gcc -DGnuPG -march=native -O3 `pkg-config glib-2.0 --cflags` -o pgp \
    gpg_armor.c gpg_sign.c \
    rsa.c hmac.c sign.c base64.c \
    mpz.c mpz_asm.c sha512.c sha.c gzip.c \
    -lglib-2.0 -lintl -lz
Тестирование - создание подписи
$ gpg --detach-sign ghash.c

	https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-03.html
	https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-06

 */
#include <stdio.h>
#include <locale.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <glib.h>
//#include "r3_args.h"
#include "hmac.h"
#include "sign.h"
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
static inline uint16_t ntohs(uint16_t v){
	return __builtin_bswap16(v);
}
static inline uint16_t htons(uint16_t v){
	return __builtin_bswap16(v);
}
static inline uint32_t htonl(uint32_t v){
	return __builtin_bswap32(v);
}
static inline uint32_t ntohl(uint32_t v){
	return __builtin_bswap32(v);
}
static inline uint64_t ntohll(uint64_t v){
	return __builtin_bswap64(v);
}
#else

#endif
static void printhex(char* title, uint8_t* s, int len)
{
	printf("%s:", title);
	int i;
	for (i=0; i< len; i++){
		if ((i&0x1F)==0) printf("\n");
		printf(" %02X", s[i]);
	}
	printf("\n");
}
static void print_time(char* title, time_t* timestamp)
{
	struct tm* ts = localtime(timestamp);
	char buf[20];
	strftime(buf, 20, "%Y-%m-%d %H:%M:%S", ts);
	printf("%s: %s\n", title, buf);
}
/*! \brief Поиск записи по таблице методом "бинарного поиска" bsearch
    \return NULL, если запись в таблице отсуствует

 */
const char *name_lookup(uint8_t code, const char *const* names, size_t length)
{
	size_t l = 0, u = length;
	while (l < u) {
		register const size_t mid = (l + u)>>1;
		register int result = code - (uint8_t)names[mid][0];
		if (result < 0)
			u = mid;
		else if (result > 0)
			l = mid + 1;
		else
			return names[mid]+2;
	}
	return NULL;
}

static void print_enum(char*title, uint8_t *array, int count, const char*const* names, size_t length)
{
	printf("%s:", title);
	int i;
	for (i=0; i< count; i++){
		const char* name = name_lookup(array[i], names, length);
		printf(" %s", name?name:"???");
	}
	printf("\n");
}
static int r2_get_contents(char* filename, uint8_t** contents, size_t *length, void* error)
{
    struct stat     statbuf;
    int res = stat(filename, &statbuf);
    if (res==0) {
        uint8_t* data = malloc(statbuf.st_size);
        FILE * f = fopen(filename, "rb");
        if (f!=NULL) {
            *length = fread(data,1,statbuf.st_size, f);
            *contents = data;
            fclose(f);
        }
    }
    return res==0;
}

#include "rsa.h"
/* проверка подписи
	if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
 */
RSA_Key* rsa_public_key_new(uint8_t* pkey_modulus, int klen)
{
    //const int klen =  1024;
    RSA_Key* Key = g_slice_new(RSA_Key);
    Key->klen = (klen+7)& ~7;
    Key->n = _aligned_malloc(Key->klen>>3,16);
	memcpy(Key->n, pkey_modulus, Key->klen>>3);
	mpz_to_octets(Key->n, Key->n, Key->klen/MPZ_LIMB_BITS);
    Key->e = 0x010001;// exp;
	return Key;
}
void rsa_public_key_free(RSA_Key* Key)
{
	_aligned_free(Key->n); Key->n = NULL;
	g_slice_free(RSA_Key, Key);
}
/* генерация хеша
For binary document signatures (type 0x00), the document data is
   hashed directly.  For text document signatures (type 0x01), the
   document is canonicalized by converting line endings to <CR><LF>,
   and the resulting data is hashed.
A certification signature (type 0x10 through 0x13) hashes the User
   ID being bound to the key into the hash context after the above
   data.  A V3 certification hashes the contents of the User ID or
   attribute packet packet, without any header.  A V4 certification
   hashes the constant 0xB4 for User ID certifications or the constant
   0xD1 for User Attribute certifications, followed by a four-octet
   number giving the length of the User ID or User Attribute data, and
   then the User ID or User Attribute data.
Once the data body is hashed, then a trailer is hashed.  A V3
   signature hashes five octets of the packet body, starting from the
   signature type field.  This data is the signature type, followed by
   the four-octet signature time.  A V4 signature hashes the packet body
   starting from its first field, the version number, through the end
   of the hashed subpacket data.  Thus, the fields hashed are the
   signature version, the signature type, the public-key algorithm, the
   hash algorithm, the hashed subpacket length, and the hashed
   subpacket body.

V4 signatures also hash in a final trailer of six octets: the
   version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
   big-endian number that is the length of the hashed data from the
   Signature packet (note that this number does not include these final
   six octets).

   After all this has been hashed in a single hash context, the
   resulting hash field is used in the signature algorithm and placed
   at the end of the Signature packet
*/
static void* pgp_digest_init(const MDigest* md)
{
    void* ctx = malloc(md->ctx_size);
    md->init   (ctx);
	return ctx;
}
static void pgp_digest_update(const MDigest* md, void * ctx, uint8_t* data, unsigned int len)
{
	md->update(ctx, data, len);
}
static void pgp_digest_fini(const MDigest* md, void * ctx, uint8_t* tag, int tlen)
{
	md->final  (ctx, tag, tlen);
    free(ctx);
}
static void pgp_digest_from_file(const MDigest* md, void * ctx, char* filename)
{
	if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
		uint8_t * contents=NULL;
		size_t length;
		if(r2_get_contents(filename, &contents, &length, NULL)){
			md->update(ctx, contents, length);
			free(contents);
			printf("assuming signed data in '%s'\n", filename);
		}
	} else
		printf("'%s' -- file not found\n", filename);
}
#ifndef FALSE
#define FALSE 0
#endif

/*! \brief
	\param[OUT] length длина имени файла
 */
static char* pgp_signed_file(char* name, size_t *length){
	size_t len = strlen(name)-4;
	if (len>0 &&  strncmp(".sig",name + len,4)==0){// has suffix
		*length = len;
		return g_strndup(name, len);
	} else {
		printf("-- name: %s", name-4);
	}
	return NULL;
}
static uint8_t* pgp_new_tag(uint8_t* s, int * type, size_t *len)
{
    *type = *s++ & 0x3F;
    uint32_t body_len = *s++;
    if (body_len < 192) {
    } else
    if (body_len < 224) {
        body_len = ((body_len - 192)<<8)+(*s++)+192;
    } else
    if (body_len == 255) {
        body_len = ntohl(*(uint32_t*)s);
        s+=4;
    } else {// Partial Body Lengths
        body_len = 1uL<<(body_len & 0x1F);
    }
    *len = body_len;
    return s;
}
static uint8_t* pgp_tag(uint8_t* s, int * type, size_t *len)
{
	*type = (s[0]>>2) & 0xF;
	switch ((*s++)&3){
	case 0: 	*len = s[0]; s+=1; break;
	case 1: 	*len = ntohs(*(uint16_t*)s); s+=2; break;
	case 2: 	*len = ntohs(*(uint32_t*)s); s+=4; break;
	case 3:
	default:	*len = ~0; break;
	}
	return s;
}
// перечисления
static const char* const gpg_packet_tag_desc[]= {
"\x00 Reserved",
"\x01 Public-Key Encrypted Session Key Packet",
"\x02 Signature Packet",
"\x03 Symmetric-Key Encrypted Session Key Packet",
"\x04 One-Pass Signature Packet",
"\x05 Secret-Key Packet",
"\x06 Public-Key Packet",
"\x07 Secret-Subkey Packet",
"\x08 Compressed Data Packet",
"\x09 Symmetrically Encrypted Data Packet",
"\x0a Marker Packet",
"\x0b Literal Data Packet",
"\x0c Trust Packet",
"\x0d User ID Packet",
"\x0e Public-Subkey Packet",
"\x11 User Attribute Packet",
"\x12 Sym. Encrypted and Integrity Protected Data Packet",
"\x13 Modification Detection Code Packet",
"\x14 AEAD Encrypted Data Packet",
// "60-63 Private or Experimental",
};
static const char* const gpg_signature_type_desc[]= {
"\x00 Signature of a binary document",
"\x01 Signature of a canonical text document",
"\x02 Standalone signature",
"\x10 Generic certification of a User ID and Public-Key packet",
"\x11 Persona certification of a User ID and Public-Key packet",
"\x12 Casual certification of a User ID and Public-Key packet",
"\x13 Positive certification of a User ID and Public-Key packet",
"\x16 Attested Key Signature",
"\x18 Subkey Binding Signature",
"\x19 Primary Key Binding Signature",
"\x1F Signature directly on a key",
"\x20 Key revocation signature",
"\x28 Subkey revocation signature",
"\x30 Certification revocation signature",
"\x40 Timestamp signature",
"\x50 Third-Party Confirmation signature",
};
static const char* const gpg_subpacket_desc[]= {
[0] = "Reserved",
[1] = "Reserved",
[2] = "Signature Creation Time",
[3] = "Signature Expiration Time",
[4] = "Exportable Certification",
[5] = "Trust Signature",
[6] = "Regular Expression",
[7] = "Revocable",
[8] = "Reserved",
[9] = "Key Expiration Time",
[10] = "Placeholder for backward compatibility",
[11] = "Preferred Symmetric Algorithms",
[12] = "Revocation Key",
[13] = "Reserved",
[14] = "Reserved",
[15] = "Reserved",
[16] = "Issuer",
[17] = "Reserved",
[18] = "Reserved",
[19] = "Reserved",
[20] = "Notation Data",
[21] = "Preferred Hash Algorithms",
[22] = "Preferred Compression Algorithms",
[23] = "Key Server Preferences",
[24] = "Preferred Key Server",
[25] = "Primary User ID",
[26] = "Policy URI",
[27] = "Key Flags",
[28] = "Signer's User ID",
[29] = "Reason for Revocation",
[30] = "Features",
[31] = "Signature Target",
[32] = "Embedded Signature",
[33] = "Issuer fingerprint",
[34] = "Preferred AEAD Algorithms",
[35] = "Intended Recipient Fingerprint",
[36] = "Reserved",
[37] = "Attested Certifications",
[38] = "Key Block",
[39] = "Preferred AEAD Ciphersuites",
[40] = "Literal Data Meta Hash",
// 100 to 110 | Private or experimental
};
static const char* const gpg_cipher_algs[] = {
"\x00 Plaintext",
"\x01 IDEA",
"\x02 TDES",
"\x03 CAST5",
"\x07 AES128",
"\x08 AES192",
"\x09 AES256",
"\x0A Twofish",
};
static const char* const gpg_public_key_algs[] = {
"\x01 RSA",
"\x02 RSA Encrypt-Only",
"\x03 RSA Sign-Only",
"\x10 Elgamal (Encrypt-Only)",
"\x11 DSA",
"\x12 ECDH",
"\x13 ECDSA",
//\x14 Reserved (formerly Elgamal Encrypt or Sign)
//\x15 Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
"\x16 EdDSA",
//\x17 Reserved for AEDH
//\x18 Reserved for AEDSA

};
static const char* const gpg_key_usage[] = {
"-- certify other keys",
"-- sign data",
"-- encrypt communications",
"-- encrypt storage",
"-- secret-sharing",
"-- authentication",
};
static const char* const gpg_compression_algs[] = {
"\x00 Uncompressed",
"\x01 ZIP",
"\x02 ZLIB",
"\x03 BZip2",
};
static const char* const gpg_hash_algs[] = {
"\x01 MD5",
"\x02 SHA1",
"\x08 SHA256",
"\x09 SHA384",
"\x0A SHA512",
"\x0B SHA224",
"\x0C SHA3-256",
"\x0E SHA3-512",
};
/*! Key flags registry (first octet)
0x01 	This key may be used to certify other keys.
0x02 	This key may be used to sign data.
0x04 	This key may be used to encrypt communications.
0x08 	This key may be used to encrypt storage.
0x10 	The private component of this key may have been split by a secret-sharing mechanism.
0x20 	This key may be used for authentication.
0x80 	The private component of this key may be in the possession of more than one person.
*/
/*! \brief заголовков и выделение длины суб пакетов
	Тип субпакета выделяется как последующий октет после выделения длины
 */
static uint8_t* gpg_subpacket_header(uint8_t* s, size_t *len){
	if (s[0]<192) {
		*len = s[0]; s+=1;
	} else
	if (s[0]<255) {
		*len = ((size_t)(s[0] - 192) << 8) + s[1] + 192; s+=2;
	} else {
		*len = __builtin_bswap32(*(uint32_t*)s); s+=5;
	}
//	*type = *s++;
	return s;
}
/*! \brief разбор суб пакетов */
static void gpg_subpackets(uint8_t* subpackets, size_t length)
{
	uint8_t* s =subpackets;
	uint8_t type;
	size_t subpacket_len=0;
	do {
		s = gpg_subpacket_header(s, &subpacket_len);
		type = s[0];
		const char* title = (type<sizeof(gpg_subpacket_desc)/sizeof(const char*))? gpg_subpacket_desc[type]: "???";
		printf(" -- '%s' subpacket(%hhd), len=%d\n", title, type, (int)subpacket_len);
		switch (type){
		case 16:{// Issuer Key Id -- младшая часть от Issue Finger Print
			uint64_t issuer_key_id = ntohll(*(uint64_t*)(s+1));
			printf("\t-- issuer Key Id: %016llX\n", issuer_key_id);
		} break;
		case  2:{// Signature Creation Time
			time_t timestamp;
			timestamp = ntohl(*(uint32_t*)(s+1));
			print_time("\tCreation  ", &timestamp);
		} break;
		case  3:{// Signature Expiration Time
		} break;
		case  9:{// Key Expiration Time
			time_t timestamp;
			timestamp = ntohl(*(uint32_t*)(s+1)); // разница, надо добавлять к дате создания
			print_time("\tExpiration", &timestamp);
		} break;
		case 33:{// Issuer fingerprint
			printhex("\tFingerprint", s+1, subpacket_len-1);
		} break;
		case 11:{// Preferred Symmetric Algorithms
			print_enum("\tAlgorithms", s+1, subpacket_len-1, gpg_cipher_algs, sizeof(gpg_cipher_algs)/sizeof(gpg_cipher_algs[0]));
		} break;
		case 21:{// Preferred Hash Algorithms
			print_enum("\tAlgorithms", s+1, subpacket_len-1, gpg_hash_algs, sizeof(gpg_hash_algs)/sizeof(gpg_hash_algs[0]));
		} break;
		case 22:{// Preferred Compression Algorithms
			print_enum("\tAlgorithms", s+1, subpacket_len-1, gpg_compression_algs, sizeof(gpg_compression_algs)/sizeof(gpg_compression_algs[0]));
		} break;
		default:
			break;
		}
		s+=subpacket_len;
	} while((s-subpackets)<length);
}

struct _pgp_signature_v4 {
uint8_t version;	//	- One-octet version number (4).
uint8_t sign_type;	//   - One-octet signature type.
uint8_t pkey_alg;	//     - One-octet public-key algorithm.
uint8_t hash_alg;	//     - One-octet hash algorithm.
//     - Two-octet scalar octet count for following hashed subpacket data.
//     - Hashed subpacket data set (zero or more subpackets).
//     - Two-octet scalar octet count for the following unhashed subpacket data.
//     - Unhashed subpacket data set (zero or more subpackets).
//     - Two-octet field holding the left 16 bits of the signed hash value.
//     - One or more multiprecision integers comprising the signature.
} __attribute__((packed));
struct _pgp_signature_v3 {
uint8_t version;	//	 - One-octet version number (3).
uint8_t len5;		//     - One-octet length of following hashed material.  MUST be 5.
uint8_t sign_type;	//         - One-octet signature type.
uint32_t sign_time; 	//         - Four-octet creation time.
uint64_t key_id;	//     - Eight-octet Key ID of signer.
uint8_t pkey_alg;	//     - One-octet public-key algorithm.
uint8_t hash_alg;	//     - One-octet hash algorithm.
uint16_t hash[1];	//     - Two-octet field holding left 16 bits of signed hash value.
//     - One or more multiprecision integers comprising the signature.
} __attribute__((packed));

static const char* const pgp_type_desc[22] = {
[0] = "Reserved - a packet tag MUST NOT have this value",
[1] = "Public-Key Encrypted Session Key Packet",
[2] = "Signature Packet",
[3] = "Symmetric-Key Encrypted Session Key Packet",
[4] = "One-Pass Signature Packet",
[5] = "Secret-Key Packet",
[6] = "Public-Key Packet",
[7] = "Secret-Subkey Packet",
[8] = "Compressed Data Packet",
[9] = "Symmetrically Encrypted Data Packet",
[10] = "Marker Packet",
[11] = "Literal Data Packet",
[12] = "Trust Packet",
[13] = "User ID Packet",
[14] = "Public-Subkey Packet",
[15] = "Reserved",
[16] = "Reserved",
[17] = "User Attribute Packet",
[18] = "Sym. Encrypted and Integrity Protected Data Packet",
[19] = "Reserved (formerly Modification Detection Code Packet)",
[20] = "Reserved (formerly AEAD Encrypted Data Packet)",
[21] = "Padding Packet",
/*
22 to 39 --	Unassigned Critical Packet
40 to 59 --	Unassigned Non-Critical Packet
60 to 63 -- Private or Experimental Values*/
};
const char* description=
"Утилита проверки/формирования цифровой подписи файла";
struct _PGP_cert {
	uint8_t* user_id;// utf8 string
	uint32_t user_id_len;
/*
	union {// \todo убрать
		struct {
			uint8_t* n;// modulus
			uint32_t n_len;
			uint8_t* e;// exp
			uint32_t e_len;
		} rsa;
	} public_key;*/
	uint8_t* public_key_data;
	size_t   public_key_len;
	uint8_t* secret_key_data;
	size_t   secret_key_len;
	uint8_t* public_subkey_data;
	size_t   public_subkey_len;
	uint8_t* secret_subkey_data;
	size_t   secret_subkey_len;
	uint64_t public_key_id;
	uint8_t* public_key_fingerprint;// versionID#SHA1(public_key)
} pgp_cert = {0};

void pgp_load(char* filename, struct _PGP_cert* pgp_cert);
void pgp_parse(struct _PGP_cert* pgp_cert, char* filename, uint8_t* content, size_t length);

typedef struct _PGP_InputData PGP_InputData;
struct _PGP_InputData {
	GQuark type_id;
	struct {
		uint8_t* str;
		int len;
	} octets;

};
extern GSList* pgp_armor_dec(GSList* list, uint8_t* data, size_t length);

static struct _CLI {
    char* alg;
    char* passwd;
    char* import;
    char* output_file;
    char* keyserver;
    int check;
    int verbose;
    int verify;
    int print_md;
    int armor;
} cli = {
.alg="gost",
.passwd=NULL,
.output_file=NULL,
.keyserver = NULL,
.check = FALSE,
.verbose = FALSE,
.verify = FALSE,
.print_md = FALSE,
.armor = FALSE,
};
static GOptionEntry entries[] =
{
  { "alg",      'a', 0, G_OPTION_ARG_STRING,    &cli.alg,   "crc algorithm", "crc32" },
  { "import",   'i', 0, G_OPTION_ARG_FILENAME,  &cli.import,   "import key", "*.pgp" },
  { "verbose",  'v', 0, G_OPTION_ARG_NONE,      &cli.verbose, "Be verbose", NULL },
  { "verify",   'V', 0, G_OPTION_ARG_NONE,      &cli.verify,	"Verify signature", NULL },
  { "armor",  	  0, 0, G_OPTION_ARG_NONE,      &cli.armor,  "Radix-64 ASCII encoding", NULL },
  { "export",  	  0, 0, G_OPTION_ARG_NONE,      NULL,  "Export public keys", NULL },
  { "export-secret-keys",  	  0, 0, G_OPTION_ARG_NONE,      NULL,  "Export secret keys", NULL },
  { "keyserver", 0,0, G_OPTION_ARG_STRING, &cli.keyserver, "LDAP Keyserver", "ldaps://ldap.example.com"},
  { NULL }
};
#if defined(GnuPG)
int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");
//  GError *error = NULL;
    GOptionContext *context = g_option_context_new ("[FILE]\nPGP sign");
    g_option_context_add_main_entries (context, entries, NULL/*GETTEXT_PACKAGE*/);
//    g_option_context_set_description(context, description);
    g_option_context_set_summary(context, description);
    if (!g_option_context_parse (context, &argc, &argv, NULL/*&error*/))
    {
      //printf ("option parsing failed: %s\n", error->message);
      exit (1);
    }
//	CRC24_selftest();

	char* filename = NULL;
	if (argc>1) filename = argv[1];
//	if (filename == NULL) return 0;

	if (cli.import!=NULL) {
		printf ("import %s\n", cli.import);
		pgp_load(cli.import, &pgp_cert);
	}
	if (filename!=NULL) {
		if (cli.armor) {
			uint8_t* contents=NULL;
			size_t length=0;
			if (r2_get_contents(filename, &contents, &length, NULL)){
				printf("file %s\n", filename);
				GSList* gpg_blocks = NULL;
				gpg_blocks = pgp_armor_dec(gpg_blocks, contents, length);
				GSList* list = gpg_blocks;
				while(list) {
					PGP_InputData * idata = list->data;
					pgp_parse(&pgp_cert, filename, idata->octets.str, idata->octets.len);
					list = list->next;
				}
			}
		} else
			pgp_load(filename, 	&pgp_cert);
	}
	return 0;
}
#endif // defined GnuPG

/*! \brief Отпечаток открытого ключа v4
	\note A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	followed by the two-octet packet length, followed by the entire
	Public-Key packet starting with the version field. The Key ID is
	the low-order 64 bits of the fingerprint. */
uint8_t* pgp_v4_fingerprint(char* fingerprint, struct _PGP_cert* pgp_cert)
{
	if (pgp_cert->public_key_data==NULL) return NULL;
	const MDigest* md = digest_select(MD_SHA1);
	uint8_t hash[md->hash_len+2];
	uint8_t aad[4];
	void * ctx = pgp_digest_init(md);
	aad[0] = 0x99; *(uint16_t*)(aad+1) = htons(pgp_cert->public_key_len);
	pgp_digest_update(md, ctx, aad, 3);
	pgp_digest_update(md, ctx, pgp_cert->public_key_data, pgp_cert->public_key_len);
	pgp_digest_fini(md, ctx, hash+1, md->hash_len);
	hash[0] = 0x04;
	pgp_cert->public_key_id = ntohll(*(uint64_t*)(hash+md->hash_len-8+1));
	printhex("fingerprint", hash, md->hash_len+1);
	printf("Key ID: %016llX\n", pgp_cert->public_key_id);
	return (uint8_t*)fingerprint;
}
/*!	\brief Отпечаток открытого ключа v5
	\note A V5 fingerprint is the 256-bit SHA2-256 hash of the octet 0x9A,
	followed by the four-octet packet length, followed by the entire
	Public-Key packet starting with the version field. The Key ID is
	the high-order 64 bits of the fingerprint. */
uint8_t* pgp_v5_fingerprint(char* fingerprint, struct _PGP_cert* pgp_cert)
{
	if (pgp_cert->public_key_data==NULL) return NULL;
	const MDigest* md = digest_select(MD_SHA256);
	uint8_t hash[md->hash_len+2];
	uint8_t aad[6];
	void * ctx = pgp_digest_init(md);
	aad[0] = 0x9A; *(uint32_t*)(aad+1) = htonl(pgp_cert->public_key_len);
	pgp_digest_update(md, ctx, aad, 5);
	pgp_digest_update(md, ctx, pgp_cert->public_key_data, pgp_cert->public_key_len);
	pgp_digest_fini(md, ctx, hash+1, md->hash_len);
	hash[0] = 0x05;
	pgp_cert->public_key_id = ntohll(*(uint64_t*)(hash+1));
#if 1
	if(cli.verbose) printhex("fingerprint", hash, md->hash_len+1);
	if(cli.verbose) printf("Key ID: %016llX\n", pgp_cert->public_key_id);
#endif
	return (uint8_t*)fingerprint;
}
/*! */
uint8_t * pgp_parse_key(uint8_t * s, size_t tag_len)
{
	//int res = -1;
	if (s[0] == 0x04)
	{
		s++;// s+= tag_len
		// вынести разбор на второй этап
		time_t time_created = ntohl(*(uint32_t*)(s)); s+=4;
		uint8_t pkey_alg = *s++;
		print_time("\tCreated", &time_created);
		printf("\tKey Alg: (%hhd) %s\n", pkey_alg,
			name_lookup(pkey_alg, gpg_public_key_algs, sizeof(gpg_public_key_algs)/sizeof(gpg_public_key_algs[0])));
		if (pkey_alg==1) {// RSA
			uint16_t pkey_bitlen = ntohs(*(uint16_t*)s); s+=2;
			if(cli.verbose)printhex("RSA modulus n", s, (pkey_bitlen+7)/8);
			//pgp_cert->public_key.rsa.n = s, pgp_cert->public_key.rsa.n_len = pkey_bitlen;
			s+=(pkey_bitlen+7)/8;
			uint16_t pexp_bitlen = ntohs(*(uint16_t*)s); s+=2;
			if(cli.verbose)printhex("RSA public exp", s, (pexp_bitlen+7)/8);
			//pgp_cert->public_key.rsa.e = s, pgp_cert->public_key.rsa.e_len = pexp_bitlen;
			s+=(pexp_bitlen+7)/8;
		} else
		if (pkey_alg==22 || pkey_alg==19) {// EdDSA ECDSA
            uint16_t oid_len = *s++;
            if(cli.verbose)printhex("Curve OID", s, oid_len);
            s += oid_len;
            // MPI of an EC point representing a public key
            uint16_t mpi_len = ntohs(*(uint16_t*)s); s+=2;//*s++;
            if(cli.verbose)printhex("EC Point", s, (mpi_len+7)/8);
            s += (mpi_len+7)/8;//mpi_len;
		} else
		if (pkey_alg==18) {// ECDH \see  5.5.5.6. Algorithm-Specific Part for ECDH Keys
            // OID, MPI(point in curve-specific point format), KDFParams
            uint16_t oid_len = *s++;
            if(cli.verbose)printhex("Curve OID", s, oid_len);
            s += oid_len;
            // MPI of an EC point representing a public key
            uint16_t mpi_len = ntohs(*(uint16_t*)s); s+=2;//*s++;
            if(cli.verbose)printhex("EC Point", s, (mpi_len+7)/8);
            s += (mpi_len+7)/8;//mpi_len;
            /* A variable-length field containing KDF parameters: 0x01 hash_alg, wrap_alg
                KEK SHA256 AES128 -> 0x01 08 07*/
            /* The key wrapping method is described in [RFC3394].
                The KDF produces a symmetric key that is used as a key-encryption key (KEK)
                as specified in [RFC3394]. Refer to Section 12.5.1 for the details regarding the choice of the KEK algorithm,
                which SHOULD be one of three AES algorithms.*/
            uint16_t kdf_len = *s++;
            if(cli.verbose)printhex("KDF params", s, kdf_len);
            s += kdf_len;
		} else
			return NULL;
	//	pgp_v4_fingerprint(NULL, pgp_cert);
	} else
		return NULL;
	return s;
}
extern int rsa_EME_pkcs_verify(uint8_t* signature, RSA_Key * pKey, uint8_t* msg, int mlen);
int pgp_signature_verify(uint8_t* signature, struct _PGP_cert* pgp_cert, uint8_t* msg, int mlen)
{
	uint8_t * pkey_modulus = pgp_cert->public_key_data+8;
	uint32_t  pkey_length  = ntohs(*(uint16_t*)(pgp_cert->public_key_data+6));
	//if(cli.verbose) printhex("public key", pkey_modulus, (pkey_length+7)/8);
	RSA_Key* pKey = rsa_public_key_new(pkey_modulus, pkey_length);
	int res = rsa_EME_pkcs_verify(signature,pKey, msg, mlen);// RSA encrypted value m**e mod n.
	rsa_public_key_free(pKey);
	return res;
}
void pgp_load(char* filename, struct _PGP_cert* pgp_cert)
{
	uint8_t* contents=NULL;
	size_t length=0;

//	if (!g_file_test(filename, G_FILE_TEST_EXISTS)) return -1;
	if (r2_get_contents(filename, &contents, &length, NULL)){
		printf("file %s\n", filename);
		pgp_parse(pgp_cert, filename, contents, length);
	}
}
/*! \brief Разбор формата в бинарном виде
	\param filename имя файла используется для выделения присоединенной подписи.
	\todo отделить разбор от проверки сертификации.
	По порядку загрузки не получается проверить все подписи, некоторые подписи могут быть подгружены позже.
	Возможно следует в два захода проверять, сначала позитивную сертификацию, потом остальные подписи.
	Позитивная сертификация подписывает сама себя.
 */
void pgp_parse(struct _PGP_cert* pgp_cert, char* filename, uint8_t* contents, size_t length)
{
	uint8_t* s = contents;
    uint8_t* binary_data = NULL;
    size_t binary_len = 0;

	do {
		if(1){
			int type;
			size_t tag_len;
            if((s[0] & 0xC0)==0x80) {
                printf("-- PGP format\n");
                s = pgp_tag(s, &type, &tag_len);
            } else
            if((s[0] & 0xC0)==0xC0) {
                printf("-- GPG new format\n");
                s = pgp_new_tag(s, &type, &tag_len);
            } else {
                printf("-- tail %d\n", (s-contents)-length);
                break;
            }
			printf("type %u: '%s', length=%d\n", type,
				name_lookup(type, gpg_packet_tag_desc, sizeof(gpg_packet_tag_desc)/sizeof(gpg_packet_tag_desc[0])),
				(unsigned)tag_len);

//			if (V) printf("type %d -- '%s' length=%d\n", type, pgp_type_desc[type], tag_len);
			if (type == 2) {// Signature Packet
                uint8_t* packet = s;
				if (s[0] == 0x03) {// v3 Signature
					struct _pgp_signature_v3 *pgp_header = (struct _pgp_signature_v3 *)s;
					printf(
						"-- version %d\n"
						"-- sign type (%d)\n"
						"-- sign time (%08X)\n"
						"-- key id (%016llX)\n"
						"-- pkey alg (%d) %s\n"
						"-- hash alg (%d) %s\n",
						pgp_header->version, 	pgp_header->sign_type,
						pgp_header->sign_time, 	pgp_header->key_id,
						pgp_header->pkey_alg,
							name_lookup(pgp_header->pkey_alg, gpg_public_key_algs, sizeof(gpg_public_key_algs)/sizeof(gpg_public_key_algs[0])),
						pgp_header->hash_alg,
							name_lookup(pgp_header->hash_alg, gpg_hash_algs, sizeof(gpg_hash_algs)/sizeof(gpg_hash_algs[0]))
					);
				} else
				if (s[0] == 0x04/* || s[0]==0x05*/) {// v4 v5 Signature
					struct _pgp_signature_v4 *gpg_header = (struct _pgp_signature_v4 *)s;
					printf(
						"-- version %d\n"
						"-- sign type(%d) %s\n" // 0x00: Signature of a binary document.
						"-- pkey alg (%d) %s\n" // 1 - RSA (Encrypt or Sign)
						"-- hash alg (%d) %s\n",// 8 - SHA256
						gpg_header->version, gpg_header->sign_type,
							name_lookup(gpg_header->sign_type, gpg_signature_type_desc, sizeof(gpg_signature_type_desc)/sizeof(gpg_signature_type_desc[0])),
						gpg_header->pkey_alg,
							name_lookup(gpg_header->pkey_alg, gpg_public_key_algs, sizeof(gpg_public_key_algs)/sizeof(gpg_public_key_algs[0])),
						gpg_header->hash_alg,
							name_lookup(gpg_header->hash_alg, gpg_hash_algs, sizeof(gpg_hash_algs)/sizeof(gpg_hash_algs[0]))
					);
					s+= sizeof(struct _pgp_signature_v4);
					uint16_t hashed_len = ntohs(*(uint16_t*) s); s+=2;
					printf("-- hash subpacket len %d\n", hashed_len);
					//printhex("hash", s, hashed_len);
					gpg_subpackets(s, hashed_len);
					s+=hashed_len;
					int digest_id = MD_SHA1;
					switch (gpg_header->hash_alg) {
					default:
					case 1: digest_id = MD_MD5; break;
					case 2: digest_id = MD_SHA1; break;
					case 8: digest_id = MD_SHA256; break;
					case 9: digest_id = MD_SHA384; break;
					case 0xA: digest_id = MD_SHA512; break;
					case 0xB: digest_id = MD_SHA224; break;
//					case 0xC: digest_id = MD_SHA3_256; break;
//					case 0xE: digest_id = MD_SHA3_512; break;
					}
					const MDigest* md = digest_select(digest_id);
					uint8_t hash[md->hash_len];//
					if (md) {
						uint8_t aad[8];
						void * ctx = pgp_digest_init(md);
						switch(gpg_header->sign_type){
						case 0x00: {// Signature of a binary document.
						    if (binary_data!=NULL){
                                pgp_digest_update(md, ctx, binary_data, binary_len);
						    } else
							if (/* cli.verify && */filename!=NULL) {
                                char* binary_filename = pgp_signed_file(filename, &binary_len);
								if (binary_filename)
                                    pgp_digest_from_file(md, ctx, binary_filename);
							} else {

							}

						} break;
						case 0x01: {// 0x01: Signature of a canonical text document.

						} break;
						case 0x02: {// 0x02: Standalone signature.
						} break;

						case 0x10 ... 0x13:
                        // 0x10: Generic certification of a User ID and Public-Key packet.
                        // 0x11: Persona certification of a User ID and Public-Key packet.
                        // 0x12: Casual certification of a User ID and Public-Key packet.
                        // 0x13: Positive certification of a User ID and Public-Key packet.
						{// A certification signature (type 0x10 through 0x13))
							// Public-Key Sign
							aad[0] = 0x99; *(uint16_t*)(aad+1) = htons(pgp_cert->public_key_len);
							pgp_digest_update(md, ctx, aad, 3);
							pgp_digest_update(md, ctx, pgp_cert->public_key_data, pgp_cert->public_key_len);
							// User ID
							aad[0] = 0xB4; *(uint32_t*)(aad+1) = htonl(pgp_cert->user_id_len);
							pgp_digest_update(md, ctx, aad, 5);
							pgp_digest_update(md, ctx, pgp_cert->user_id, pgp_cert->user_id_len);
						} break;
						case 0x18:  // 0x18: Subkey Binding Signature.
						case 0x19: {// 0x19: Primary Key Binding Signature.
							// Public-Key
							aad[0] = 0x99; *(uint16_t*)(aad+1) = htons(pgp_cert->public_key_len);
							pgp_digest_update(md, ctx, aad, 3);
							pgp_digest_update(md, ctx, pgp_cert->public_key_data, pgp_cert->public_key_len);
							// Public-SubKey
							aad[0] = 0x99; *(uint16_t*)(aad+1) = htons(pgp_cert->public_subkey_len);
							pgp_digest_update(md, ctx, aad, 3);
							pgp_digest_update(md, ctx, pgp_cert->public_subkey_data, pgp_cert->public_subkey_len);
						} break;
						case 0x1F: // 0x1F: Signature directly on a key.
                            break;
						default:
							break;
						}
						uint32_t hashed_data_len = s-(uint8_t*)gpg_header;
						pgp_digest_update(md, ctx, (uint8_t*)gpg_header, hashed_data_len);
						aad[0] = 0x04; aad[1] = 0xFF; *(uint32_t*)(aad+2) = htonl(hashed_data_len);
						pgp_digest_update(md, ctx, aad, 6);
						pgp_digest_fini(md, ctx, hash, md->hash_len);
						if (cli.verbose) printhex("digest", hash, md->hash_len);
					}

					uint16_t data_len = ntohs(*(uint16_t*) s); s+=2;
					printf("-- data subpacket len %hd\n", data_len);
					//printhex("data", s, data_len);
					gpg_subpackets(s, data_len);
					s+=data_len;
					uint16_t hash_v16 = ntohs(*(uint16_t*) s); s+=2;// старшие 16 бит хеша, для проверки
					printf("-- hash octets.. %04hX ..%s\n", hash_v16, hash_v16==ntohs(*(uint16_t*)hash)?"ok":"fail");
                /*  One or more multiprecision integers comprising the signature.
                    This portion is algorithm-specific: */
                    switch (gpg_header->pkey_alg) {
                    case 0x11: // DSA
                    case 0x13: // ECDSA
                    case 0x16: // EdDSA
                    {
                        uint16_t R_len = ntohs(*(uint16_t*) s); s+=2;
                        uint8_t* R = s;
                        s += (R_len+7)/8;
                        uint16_t S_len = ntohs(*(uint16_t*) s); s+=2;
                        uint8_t* S = s;
                        s += (S_len+7)/8;
                        if (cli.verbose) {
                            printhex("R", R, (R_len+7)/8);
                            printhex("S", S, (S_len+7)/8);
                        }
                    } break;
                    case 0x01:
                    case 0x03:
                    { // RSA
                        uint16_t sign_len = ntohs(*(uint16_t*) s); s+=2;
                        uint8_t* signature = s;
                        printf("-- sign len %d\n", sign_len);
                        if (cli.verbose) printhex("sign", s, (sign_len+7)/8);
                        if (pgp_cert->public_key_data==NULL) {
                            printf("Нужен ключ проверки подписи! Без ключа не проверить.\n"
                                "# pgp --import public_key.pgp --verify FILE.sig\n"
                            );
                        } else
                        if(md!=NULL && pgp_signature_verify(signature, pgp_cert, hash, md->hash_len)){
                            printf("Сертификация пройдена!\n");
                        } else
                            printf("Сертификация НЕ пройдена!\n");
                        s += (sign_len+7)/8;
                    } break;
                    default:
                        break;
                    }
					s = packet + tag_len;
				} else {
				    //printf("Signature unknown version %X\n", s[0]);
				    s+= tag_len;
				    //break;
				}
			} else
			if (type == 4){// One-Pass Signature Packet
				if (s[0] == 0x03) {// v3 Signature
					printf(
						"-- version %d\n"
						"-- sign type(%d) %s\n"
						"-- pkey alg (%d) %s\n"
						"-- hash alg (%d) %s\n"
						"-- key id (%016llX)\n"
						"-- flags (%02X)\n",
						s[0], 	s[1],
						name_lookup(s[1], gpg_signature_type_desc, sizeof(gpg_signature_type_desc)/sizeof(gpg_signature_type_desc[0])),
                        s[3],
                        name_lookup(s[3], gpg_public_key_algs, sizeof(gpg_public_key_algs)/sizeof(gpg_public_key_algs[0])),
                        s[2],
                        name_lookup(s[2], gpg_hash_algs, sizeof(gpg_hash_algs)/sizeof(gpg_hash_algs[0])),
                        ntohll(*(uint64_t*)&s[4]), s[12]
					);
				}
                s+= 13;//tag_len;
			} else
			if (type == 5){// Secret-Key Packet
				pgp_cert->public_key_data = s;
				pgp_cert->public_key_len  = tag_len;
				uint8_t* skey = pgp_parse_key(s, tag_len);
				if(skey) {
					pgp_cert->public_key_len = skey-s;
					pgp_cert->secret_key_data= skey;
					pgp_cert->secret_key_len = tag_len - (skey-s);
				}
				s+=tag_len;
			} else
			if (type == 6){// Public-Key Packet
				pgp_cert->public_key_data = s;
				pgp_cert->public_key_len  = tag_len;
				if(cli.verbose) pgp_parse_key(s, tag_len);
				s+=tag_len;
			} else
			if (type == 7){// Secret-SubKey Packet
				pgp_cert->public_subkey_data = s;
				pgp_cert->public_subkey_len  = tag_len;
				uint8_t* skey = pgp_parse_key(s, tag_len);
				if(skey) {
					pgp_cert->public_subkey_len = skey-s;
					pgp_cert->secret_subkey_data= skey;
					pgp_cert->secret_subkey_len = tag_len - (skey-s);
				}
				s+=tag_len;
			} else
			if (type == 8){// Compressed Data Packet
			    uint8_t compression_alg = s[0];// 0=Uncompressed, 1=ZIP [RFC1951], 2=ZLIB [RFC1950],3=BZip2 [BZ2]
			    if(cli.verbose) printf("Compression: (%d)\n", compression_alg);
			    if (compression_alg==1) {//ZIP
extern int zip_decompress(uint8_t ** dst, int * dlen, uint8_t * src, int slen);
                    int unwrap_len = 0;
                    uint8_t* dst;
                    int res = zip_decompress(&dst, &unwrap_len, &s[1], length - (s+1 - contents));
                    printf("decompress %d len=%d\n", res, unwrap_len);//length - (s-contents));
                    if (res!= 1) {// Z_STREAM_END
                        printhex("data", s, length - (s-contents));
                    }
                    s = contents = dst;
                    length = unwrap_len;
                    continue;
			    }
                if ((unsigned)tag_len == ~0u) break;
			} else
			if (type == 11){// Literal Data Packet (Tag 11)
			    uint8_t tag = s[0];// b - binary
                uint8_t name_len = s[1];
                char* name = &s[2];
                printf("-- filename: %-.*s\n", (int)name_len, name);
                time_t timestamp;
                timestamp = ntohl(*(uint32_t*)(s+2+name_len));
                print_time("\tmdate: ", &timestamp);
                binary_data = s+6+name_len;// данные для подписи или сохранения
                binary_len = tag_len-(6+name_len);
                s+=tag_len;
			} else
			if (type == 13){// User ID Packet (Tag 13)
				printf("\tUser ID: %-.*s\n", (int)tag_len, s);
				pgp_cert->user_id = s;
				pgp_cert->user_id_len = tag_len;
				s+= tag_len;
			} else
			if (type == 14){// Public-Subkey Packet
				pgp_cert->public_subkey_data = s;
				pgp_cert->public_subkey_len  = tag_len;
				if(cli.verbose) pgp_parse_key(s, tag_len);
				s+=tag_len;
			} else
			{
			    printf("undefined type -- %d\n", type);
				s+= tag_len;
				break;
			}
		} else {
			printf("%s -- %02X\n", filename, s[0]);
			break;
		}
	} while ((s-contents)<length);
}
