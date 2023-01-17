/*! \defgroup _zbase32_ Кодирование бинарных данных методом BASE64
    \brief прямое и обратное преобразование Z-BASE32

Отладка:
$ gcc -DTEST_BASE32 -o base32 zbase32.c
$ echo -n "The quick brown fox jumps over the lazy dog." | ./base32.exe | ./base32.exe -d

    \see [RFC 2045]  Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies
    \see [RFC 4648]  The Base16, Base32, and Base64 Data Encodings
    \see [RFC 6189]  ZRTP: Media Path Key Agreement for Unicast Secure RTP, April 2011
    \see OpenPGP Web Key Directory
    https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service
    \{

Длина строки не должна превышать 76 символов
 */
#include <stdint.h>
static const uint8_t  base32_table[32] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"234567";
static const uint8_t zbase32_table[32] =
    "ybndrfg8ejkmcpqxot1uwisza345h769";

static const int8_t zbase32_rtable[256] = {
    ['y'] = 0, ['b'] = 1, ['n'] = 2, ['d'] = 3, ['r'] = 4, ['f'] = 5, ['g'] = 6, ['8'] = 7,
    ['e'] = 8, ['j'] = 9, ['k'] =10, ['m'] =11, ['c'] =12, ['p'] =13, ['q'] =14, ['x'] =15,
    ['o'] =16, ['t'] =17, ['1'] =18, ['u'] =19, ['w'] =20, ['i'] =21, ['s'] =22, ['z'] =23,
    ['a'] =24, ['3'] =25, ['4'] =26, ['5'] =27, ['h'] =28, ['7'] =29, ['6'] =30, ['9'] =31,
};

/*! \brief Кодирование Base64
    \param dst - указатель на выходной буфер, длина буфера должна быть больше (length(src)*4 + 3)/3
    \param src - указатель на входной буфер. Строка должна заканчиваться нулем
 */
uint8_t* zbase32_enc(uint8_t *dst, uint8_t *src, int length)
{
    uint32_t acc=0;
    int bits=0;
    while (length--)
    {
        bits+=8;
        acc |= (*src++) << (32-bits);
        do {
            *dst++ = (uint8_t)zbase32_table[acc>>(32-5)];
            acc <<= 5, bits-=5;
        } while (bits >= 5);
    }
    if (bits>0){
        *dst++ = (uint8_t)zbase32_table[acc>>(32-5)];
    }
    *dst = 0;
    return dst;
}
/*! \brief Декодирование Base64
    \param dst - выходной буфер
    \param src - входной буфер
 */
uint8_t* zbase32_dec (uint8_t *dst, uint8_t* src, int length)
{
//    uint32_t ch;
    uint32_t acc = 0;
    int bits =0;
    while (/*(ch = *src++)!= 0 &&*/ length-- )
    {
        uint32_t ch = *src++;
        ch = zbase32_rtable[ch];
        //if (ch2 != 0)
        {
            bits+= 5;
            acc |= ch<<(32-bits);
        }
        if (bits >= 8) {
            bits -= 8;
            *dst++ = acc >> (32-8);
            acc <<= 8;
        }
    }
    return dst;
}
//!\}
#if defined(TEST_BASE32)
#include <stdio.h>
// The quick brown fox jumps over the lazy dog.
// => 'ktwgkedtqiwsg43ycj3g675qrbug66bypj4s4hdurbzzc3m1rb4go3jyptozw6jyctzsqmo'
int main (int argc, char**argv)
{
    char in[4096] __attribute__((aligned(4)));
    char out[4096+4] __attribute__((aligned(4)));
    int len;
    while (len = fread(in,1,1024*3, stdin))
    {
        uint8_t* top = (argc==1? zbase32_enc : zbase32_dec)(out, in, len);//strlen(in));
        fwrite(out,1,top - (uint8_t*)out, stdout);
//        puts(out);
    }
//    top = base64_dec(in, out, top-(uint8_t*)out);
//    puts(in);
    return 0;
}
#endif
