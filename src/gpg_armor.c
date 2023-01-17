#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <locale.h>
#include <glib.h>

typedef struct _PGP_InputData PGP_InputData;
struct _PGP_InputData {
	GQuark type_id;
	struct {
		uint8_t* str;
		int len;
	} octets;

};

typedef uint32_t CRC24;
#define CRC24_CHECK 0x21cf02
#define CRC24_INIT 	0xB704CE
#define CRC24_POLY 	0x864CFB

static const CRC24 CRC24_Lookup4[16] = {
0x000000, 0x864CFB, 0x8AD50D, 0x0C99F6,
0x93E6E1, 0x15AA1A, 0x1933EC, 0x9F7F17,
0xA18139, 0x27CDC2, 0x2B5434, 0xAD18CF,
0x3267D8, 0xB42B23, 0xB8B2D5, 0x3EFE2E,
};
/* Один байт за два шага по таблице 4 бит */
static CRC24 CRC24_update_4   (CRC24 crc, uint8_t val){
	crc^= ((CRC24)val <<16);
	crc = (crc << 4) ^ CRC24_Lookup4[(crc >> 20) & 0xF ];
	crc = (crc << 4) ^ CRC24_Lookup4[(crc >> 20) & 0xF ];
	return crc&0xFFFFFFL;
}
CRC24 CRC24_block(CRC24 crc, uint8_t*data, size_t len)
{
	size_t i;
	for (i=0; i<len; i++)
		crc = CRC24_update_4(crc, data[i]);
	return crc;
}
/* 6.1.  An Implementation of the CRC-24 in "C"

      typedef long crc24;
      crc24 crc_octets(unsigned char *octets, size_t len)
      {
          crc24 crc = CRC24_INIT;
          int i;
          while (len--) {
              crc ^= (*octets++) << 16;
              for (i = 0; i < 8; i++) {
                  crc <<= 1;
                  if (crc & 0x1000000)
                      crc ^= CRC24_POLY;
              }
          }
          return crc & 0xFFFFFFL;
      }*/

int CRC24_selftest()
{
	const char test[] = "123456789";
	CRC24 crc = CRC24_INIT;
	int i;
	for(i=0; i<9; i++){
		crc = CRC24_update_4(crc, test[i]);
	}
	printf("CRC-24/OpenPGP -- self test..%s\n", (crc)==CRC24_CHECK?"ok":"fail");
	return (crc)==CRC24_CHECK;
}
#if 0 // заголовки в файлах арморед.
   "MESSAGE", // Used for signed, encrypted, or compressed files.
   "PUBLIC KEY BLOCK" // Used for armoring public keys.
   "PRIVATE KEY BLOCK", // Used for armoring private keys.
   "MESSAGE, PART X/Y", // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
   "MESSAGE, PART X", // Used for multi-part messages, where this is the Xth part of an unspecified number of parts.  Requires the MESSAGE-ID Armor Header to be used.
   "SIGNATURE"
#endif
extern uint8_t* base64_dec (uint8_t *dst, const uint8_t* src, int length);
/*! \brief Декодирование Radix-64 */
GSList* pgp_armor_dec(GSList* list, uint8_t* data, size_t length)
{
	int offset = 0;
	uint8_t* s = data;
	while (s[0]!='\0'
	  && !(s[0]=='-' && strncmp(s, "-----BEGIN PGP ", 15)==0))
		s++;
	offset = s - data;


	if (offset != length) {
	while (strncmp(s, "-----BEGIN PGP ", 15)==0)
	{
		s+=15;
		offset = s - data;
		while (s[0]!='-' && s[0]!='\0') s++;

		if (s[0]!='\0' && strncmp(s, "-----", 5)==0){
			int name_len = s - &data[offset];
			char* name = g_strndup(data+offset, name_len);
			s+=5;
			//if (s[0]=='\n') s++;
			// пропустить комментарии
			uint8_t* comment = s;
			while (s[0]!=0 && !((s[0]=='\n' && s[1]=='\n') || strncmp(s,"\r\n\r\n",4)==0)) s++;
			g_print("'%-.*s'\n", s-comment, comment);
			if(s[0]!=0) s+=2;
			offset = s - data;
			while (s[0]!=0 && !(s[0]=='\n' && (s[1]=='=')/*((s[1]=='=') || (s[1]=='\n' && s[2]=='='))*/) && s[0]!='-') s++;
			int data_len = s - &data[offset];
			uint32_t crc24=0;
			if (s[0]=='\n' && s[1]=='='){
				s+=2;
				uint8_t crc_buf[4];
				base64_dec(crc_buf, s, 4);
				crc24 = (uint32_t)crc_buf[0] << 16 | (uint32_t)crc_buf[1] << 8 | (uint32_t)crc_buf[2];
				g_print("CRC24=0x%06X\n", crc24);
			}
			while (s[0]!=0 && !(s[0]=='-' && strncmp(s, "-----END PGP ", 13)==0 && strncmp(&s[13], name, name_len)==0
				   && strncmp(&s[13+name_len], "-----", 5)==0)) s++;
			if (s[0]!= '\0'){
				uint8_t* dst = g_malloc(data_len);
				uint8_t* tail = base64_dec(dst, data+offset,data_len);
				size_t dst_length = tail - dst;

				CRC24 crc = CRC24_block(CRC24_INIT, dst, dst_length);
				if (crc==crc24){
					PGP_InputData *idata= g_slice_alloc(sizeof(PGP_InputData));
					idata->type_id = g_quark_from_string(name);
					idata->octets.str = dst;
					idata->octets.len = dst_length;
					list = g_slist_append(list, idata);
				}

				g_print("type: %s length=%d, CRC24=0x%06X ..%s\n", name, dst_length, crc, crc==crc24?"ok":"fail");
				if(0) g_print("data:\n%-.*s\n", data_len, data+offset);
				s+=13+name_len+5;
				if (s[0]=='\n') s++;
			} else {
			}
			g_free(name);
		}
	}
	}
	return list;
}
#ifdef TEST_ARMOR
int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");

	char* filename = NULL;
	if (argc>1) filename = argv[1];
	if (filename==NULL) return 1;
	GSList* list = NULL;
	char* contents;
	gsize length;
	if(g_file_get_contents(filename, &contents, &length, NULL)){
		pgp_armor_dec(list, contents, length);
	}
	return 0;
}
#endif
