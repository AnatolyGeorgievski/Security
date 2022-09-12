/*! cksum
    Вычисление CRC от файлов
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <glib.h> -- используется собственный разбор параметров
#include <locale.h>
//#include <libgen.h>
#include <sys/stat.h>
#include "r3_args.h"
#include "crc.h"
#ifndef FALSE
#define FALSE 0
#endif

struct {
    char* alg;
    char* passwd;
    char* output_file;
    int check;
    int verbose;
    int list;
} cli = {
.alg="CRC32",
.passwd=NULL,
.output_file=NULL,
.check = FALSE,
.verbose = FALSE,
.list = FALSE,
};

static GOptionEntry entries[] =
{
  { "alg",      'a', 0, G_OPTION_ARG_STRING,    &cli.alg,   "crc algorithm", "crc32" },
  { "verbose",  'v', 0, G_OPTION_ARG_NONE,      &cli.verbose, "Be verbose", NULL },
  { "list",     'L', 0, G_OPTION_ARG_NONE,      &cli.list, "Список доступных контрольных сумм", NULL },
  { NULL }
};
static int r2_get_contents(char* filename, char** contents, size_t *length, void* error)
{
    struct stat     statbuf;
    int res = stat(filename, &statbuf);
    if (res==0) {
        char* data = malloc(statbuf.st_size);
        FILE * f = fopen(filename, "rb");
        if (f!=NULL) {
            *length = fread(data,1,statbuf.st_size, f);
            *contents = data;
            fclose(f);
        }
    }
    return res==0;
}
static const CRC32 CRC32_Lookup4[16] = {
0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9,
0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61,
0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD
};

/* Один байт за два шага по таблице 4 бит */
CRC32 CRC32_update_4   (CRC32 crc, uint8_t val){
	crc^= ((uint32_t)val <<24);
	crc = (crc << 4) ^ CRC32_Lookup4[(crc >> 28) & 0xF ];
	crc = (crc << 4) ^ CRC32_Lookup4[(crc >> 28) & 0xF ];
	return crc;
}
extern CRC32 CRC32_update_N(CRC32 crc, uint8_t *data, int len);
extern CRC32 CRC32K_update_N(CRC32 crc, uint8_t *data, int len);

const char* description=
"Утилита вычисления циклических контрольных сумм";
int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");
//  GError *error = NULL;
    GOptionContext *context = g_option_context_new ("[FILE]\nPrint or check GOST 34.11-2012/SHA256 (256-bit) checksums");
    g_option_context_add_main_entries (context, entries, NULL/*GETTEXT_PACKAGE*/);
//    g_option_context_set_description(context, description);
    g_option_context_set_summary(context, description);
    if (!g_option_context_parse (context, &argc, &argv, NULL/*&error*/))
    {
      //printf ("option parsing failed: %s\n", error->message);
      exit (1);
    }
//    int crc_alg_id=CRC_32B;

	CRC32 CRC_xorin = ~0UL;
	CRC32 CRC_xorout= ~0UL;

    size_t length = 0; // размер файла
	#define BUFLEN 4096
	uint8_t buf[BUFLEN];
    int i;
    for (i=1; i<argc; i++) {
        char* filename = argv[i];

		size_t bytes_read;
		FILE *fp;
		fp = fopen (filename, "rb");
		if (fp == NULL) {
          printf("ERR %s", filename);
          return 0;
        }

		CRC32 crc = 0;//CRC_xorin;//~0UL;
			while ((bytes_read = fread (buf, 1, BUFLEN, fp)) > 0)
			{
				unsigned char *cp = buf;

				if (length + bytes_read < length){
					printf ("%s: file too long", filename);
					return 1;
				}
				length += bytes_read;
#if 0
				while (bytes_read--)
					crc = CRC32_update_4(crc, *cp++);
#else
				crc = CRC32K_update_N(crc, buf, bytes_read);
#endif
				if (feof (fp))
				break;
			}
		while (length){
			crc = CRC32_update_4(crc, length& 0xFF);
			length>>=8;
		}


		//crc = CRC32_update_N(crc, contents, length);
//	printf("Test =%0X ..%s\n", crc^~0UL, (crc^~0UL)==CRC32B_CHECK?"ok":"fail");

            //char* base = basename(filename);
		printf("%u %d %c%s\n", crc^CRC_xorout, (int)length, '*', filename);
    }
    return 0;
}
