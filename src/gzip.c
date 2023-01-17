/*! Используется для распаковки XML

    [RFC 1950] ZLIB Compressed Data Format Specification        May 1996
    [RFC 1951] DEFLATE Compressed Data Format Specification     May 1996
    [RFC 1952] GZIP File Format Specification                   May 1996

        http://www.pkware.com/documents/casestudies/APPNOTE.TXT

      local file header signature     4 bytes  (0x04034b50)
      version needed to extract       2 bytes
      general purpose bit flag        2 bytes
      compression method              2 bytes
      last mod file time              2 bytes
      last mod file date              2 bytes
      crc-32                          4 bytes
      compressed size                 4 bytes
      uncompressed size               4 bytes
      file name length                2 bytes
      extra field length              2 bytes

      file name (variable size)
      extra field (variable size)


 $ gcc -o gz.exe src/gzip.c -DTEST_GZIP -lz `pkg-config.exe --libs --cflags glib-2.0`

 */
#include <inttypes.h>
#define ZIP_METHOD_OFFSET    8
#define ZIP_CRC_OFFSET      14
#define ZIP_SIZE_OFFSET     18
#define ZIP_USIZE_OFFSET    22
#define ZIP_NAME_LEN        26
#define ZIP_EXTRA_LEN       28
#define ZIP_HEADER_SIZE     30

#define ZIP_METHOD_STORED       0
#define ZIP_METHOD_COMPRESSED   1
#define ZIP_METHOD_PACKED       2
#define ZIP_METHOD_LZHED        3
#define ZIP_METHOD_DEFLATED     8

#define ZIP_WORD(s) ((uint32_t)*(s) | (uint32_t)*(s+1)<<8 | (uint32_t)*(s+2)<<16 | (uint32_t)*(s+3)<<24)
#define ZIP_HALF(s) ((uint16_t)*(s) | (uint16_t)*(s+1)<<8)
/*
typedef struct _zip_local_header zip_local_header;
struct _zip_local_header{
    unsigned int  signature: 32;
    unsigned int  version: 16;
    unsigned int  flag: 16;
    unsigned int  method: 16;
    unsigned int  mtime: 16;
    unsigned int  mdate: 16;
    unsigned int  crc: 32;
    unsigned int  size: 32;
    unsigned int  usize: 32;
    unsigned int  name_len: 16;
    unsigned int  extra_len: 16;
} __attribute__((aligned(1),packed));
*/
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "zlib.h"
#include <glib.h>

#define CHUNK 4096
static void print_hex(uint8_t* msg, int len)
{
    int i;
    for (i=0; i<len; i++){
        printf("%02X ", (unsigned int)msg[i]);
    }
}
typedef uint32_t CRC32;
//extern CRC32 crc_from_block(CRC32 crc, unsigned char *buffer, int size);

static const CRC32 CRC32B_Lookup4[16]={
0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190,
0x6B6B51F4, 0x4DB26158, 0x5005713C, 0xEDB88320, 0xF00F9344,
0xD6D6A3E8, 0xCB61B38C, 0x9B64C2B0, 0x86D3D2D4, 0xA00AE278,
0xBDBDF21C
};

static CRC32 crc_from_block(CRC32 crc, unsigned char *buffer, int size)
{
	//crc = CRC32_init(crc);
	int count = size;
	CRC32 const * table = CRC32B_Lookup4;
	do{
		crc^= *buffer++;
		crc = (crc>>4) ^ table[crc & 0xF];
		crc = (crc>>4) ^ table[crc & 0xF];
	} while (--count);
	return crc;//CRC32_finalize(crc);
}
int zip_decompress(uint8_t ** dst, int * dlen, uint8_t * src, int slen){
    int ret, size=0;
	z_stream strm = {.zalloc=Z_NULL, .zfree=Z_NULL, .opaque=Z_NULL, .avail_in=0, .next_in=Z_NULL};
	
	ret = inflateInit2(&strm,-15);// без использования контрольных сумм
	if (ret != Z_OK) {
		printf("GZIP: inflate init error\n");
		return ret;
	}
    strm.avail_in = slen;
    strm.next_in = src;

    GSList *chunk =NULL;
	uint8_t* buf;// = NULL;
	do {
		buf =   g_malloc(CHUNK);
		chunk = g_slist_append(chunk, buf);
		strm.avail_out = CHUNK;
        strm.next_out = buf;
        ret = inflate(&strm, Z_NO_FLUSH);
        switch (ret) {
        case Z_NEED_DICT:
            ret = Z_DATA_ERROR;     /* and fall through */
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
            printf("GZIP: data error: %s\n", strm.msg);
            print_hex(src, 16);
            printf("\n");
            (void)inflateEnd(&strm);
            return ret;
        }
		size += CHUNK - strm.avail_out;
	} while(strm.avail_in != 0 && strm.avail_out == 0 && ret== Z_OK);
	*dlen = size;
	buf = g_malloc(size);
	*dst = buf;
	
    GSList *list =chunk;
	while (chunk->next){
		__builtin_memcpy(buf, chunk->data, CHUNK);
		buf+=CHUNK;
		size-=CHUNK;
		g_free(chunk->data);
		chunk = chunk->next;
	}
	__builtin_memcpy(buf, chunk->data, size);
	g_slist_free(list);
	return ret;
}

int gzip_decompress(uint8_t ** dst, int * dlen, uint8_t * src, int slen)
{
    int ret, size=0, original_size=0, pkzip=0;
    CRC32 original_crc = 0;
    z_stream strm = {.zalloc=Z_NULL, .zfree=Z_NULL, .opaque=Z_NULL, .avail_in=0, .next_in=Z_NULL};

    GSList *chunk =NULL;
    GSList *next =NULL;

    if (ZIP_WORD(src) == 0x04034b50) {
        pkzip =1;
        int size = ZIP_WORD(src+ZIP_SIZE_OFFSET);
        original_size = ZIP_WORD(src+ZIP_USIZE_OFFSET);
        //int method = ZIP_HALF(src+ZIP_METHOD_OFFSET);
        original_crc = ZIP_WORD(src+ZIP_CRC_OFFSET);
        src = src + ZIP_HEADER_SIZE + ZIP_HALF(src+ZIP_NAME_LEN) + ZIP_HALF(src+ZIP_EXTRA_LEN);
        slen= size;


        ret = inflateInit2(&strm,-15);// без использования контрольных сумм
        if (ret != Z_OK) {
            printf("GZIP: inflate init error\n");
            return ret;
        }


    } else /*if (ZIP_HALF(src) == 0x8b1f)*/ {

        ret = inflateInit2(&strm, 32+15);// 32 = автоматическое определение формата, 16-GZIP
        if (ret != Z_OK) {
            printf("GZIP: init error\n");
            return ret;
        }
       // ret = inflateGetHeader(&strm, &header);
        if (ret != Z_OK) {
            printf("GZIP: header error\n");
            return ret;
        }
    }
    strm.avail_in = slen;
    strm.next_in = src;
    uint8_t* buf = NULL;
    do {
        buf =   g_malloc(CHUNK);
        next = g_slist_append(next, buf);
        if (next->next==NULL)
            chunk = next;
        else
            next = next->next;
        strm.avail_out = CHUNK;
        strm.next_out = buf;
        ret = inflate(&strm, Z_NO_FLUSH);
        assert (ret != Z_STREAM_ERROR);// return Z_STREAM_ERROR;
        switch (ret) {
        case Z_NEED_DICT:
            ret = Z_DATA_ERROR;     /* and fall through */
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
            printf("GZIP: data error: %s\n", strm.msg);
            print_hex(src, 16);
            printf("\n");
            (void)inflateEnd(&strm);
            return ret;
        }
        size += CHUNK - strm.avail_out;//*dlen -= strm.avail_out;

    } while (strm.avail_out == 0 && ret== Z_OK);

    buf = g_realloc(chunk->data, size+1);
    *dst = buf;
    *dlen = size;
    buf[size]='\0';
    next = chunk->next;
    int offset = 0;
    while (next) {// скопировать обрезки
        size -= CHUNK;
        offset+= CHUNK;
        memcpy(&buf[offset],next->data,size>CHUNK?CHUNK:size);
        g_free(next->data);
        next = next->next;
    }
    g_slist_free(chunk);
    if (pkzip && ret==Z_STREAM_END) { // проверка целостности для формата ZIP
        if (*dlen != original_size) {
            printf("ZIP: size error 0x%08X 0x%08X\n ", *dlen, original_size);
            ret = Z_DATA_ERROR;
        } else
        {// проверить CRC
            CRC32 crc = crc_from_block(~0, buf, *dlen);

            if (~crc != original_crc) {
                ret = Z_DATA_ERROR;
                printf("ZIP: crc error 0x%08X 0x%08X\n", ~crc, original_crc);
            }
        }
    }
    (void)inflateEnd(&strm);// clean up and return
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}
int gzip_compress(uint8_t * dst, int * dlen, uint8_t * src, int slen)
{
    int ret, level = Z_DEFAULT_COMPRESSION;
//    unsigned have;
    z_stream strm;
    gz_header header = {0};
    //header.time = ;
//    unsigned char in[CHUNK];
//    unsigned char out[CHUNK];

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit2(&strm, level, Z_DEFLATED, -15, 8,  Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;
    ret = deflateSetHeader (&strm, &header);
        /* compress until end of file */
    do {
        strm.avail_in = slen;//fread(in, 1, CHUNK, source);
        //flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = src;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {

            strm.avail_out = *dlen;
            strm.next_out = dst;

            ret = deflate(&strm, Z_FINISH);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */

            *dlen -= strm.avail_out;
        } while (0);//strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (0);//flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */
    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
//    if (in[0]==0x1F && in[1]==0x8B) return 1;
}
#ifdef TEST_GZIP
typedef struct _MainOptions MainOptions;
struct _MainOptions {
    char* input_file;
    char* output_file;
    gboolean verbose;
    gboolean decompress;
};
static MainOptions options = {
    .input_file = NULL,
    .output_file = NULL,
    .verbose = FALSE,
    .decompress = FALSE
};
static GOptionEntry entries[] =
{
  { "input",    'i', 0, G_OPTION_ARG_FILENAME,  &options.input_file,    "input file name",  "*" },
  { "output",   'o', 0, G_OPTION_ARG_FILENAME,  &options.output_file,   "output file name", "*" },
  { "verbose",  'v', 0, G_OPTION_ARG_NONE,      &options.verbose,       "Be verbose",       NULL },
  { "decompress",   'd', 0, G_OPTION_ARG_NONE,      &options.decompress,        "decompression",       NULL },
  { NULL }
};
int main(int argc, char *argv[])
{
    GError * error = NULL;
    GOptionContext *context;
    context = g_option_context_new ("- command line interface");
    g_option_context_add_main_entries (context, entries, NULL/*GETTEXT_PACKAGE*/);
    if (!g_option_context_parse (context, &argc, &argv, &error))
    {
        g_print ("option parsing failed: %s\n", error->message);
        _Exit (1);
    }
    g_option_context_free (context);

if (0) {
    uint8_t str[256] = "test";
    uint8_t buf[256];
    int dlen= 256;
    gzip_compress(buf, &dlen, str, 4);
    print_hex(buf, dlen);
    int slen = dlen;
    dlen = 256;
}
    uint8_t* buf = NULL;
    int slen=0, dlen=0;
    if (options.input_file) {
        g_file_get_contents(options.input_file, (char**)&buf, &slen, &error);
        if (error) {
            g_error_free(error); error = NULL;
        }
    }
    if (options.decompress && buf!=NULL) {

        uint8_t* data = NULL;
        if(gzip_decompress(&data, &dlen, buf, slen)!=Z_OK){
            printf("Error \n");
        } else
            printf("'%-.*s'\n", dlen, data);
    }


    return 0;
}
#endif
