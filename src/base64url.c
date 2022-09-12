/*! \brief прямое и обратное преобразование base64url
[RFC 4648]  The Base16, Base32, and Base64 Data Encodings, October 2006
    5.  Base 64 Encoding with URL and Filename Safe Alphabet

    This encoding is technically identical to the previous one, except
    for the 62:nd and 63:rd alphabet character, as indicated in Table 2.

    The pad character "=" is typically percent-encoded when used in an
    URI [9], but if the data length is known implicitly, this can be
    avoided by skipping the padding; see section 3.2.

    This encoding may be referred to as "base64url".  This encoding
    should not be regarded as the same as the "base64" encoding and
    should not be referred to as only "base64".  Unless clarified
    otherwise, "base64" refers to the base 64 in the previous section.

сборка
$ gcc -DTEST_BASE64URL -o base64url.exe base64url.c
тестирование:
кодирование
$ echo -n "{\"alg\":\"HS256\"}" | ./base64url.exe
eyJhbGciOiJIUzI1NiJ9
декодирование
$ echo -n "eyJhbGciOiJIUzI1NiJ9" | ./base64url.exe -d
{"alg":"HS256"}

 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
static const uint8_t base64url_table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";
/*! \brief Кодирование Base64-url safe (base64url)
    \param dst - указатель на выходной буфер, длина буфера должна быть больше (length(src)*4 + 3)/3
    \param src - указатель на входной буфер. Строка должна заканчиваться нулем
    \return указатель на конец записи в выходном буфере.
 */
uint8_t* base64url_enc(uint8_t *dst, uint8_t *src, size_t length)
{
    uint32_t acc=0;
    int bits=0;
//    int i=0;
    while (length--)
    {
        bits+=8;
        acc |= (uint32_t)(*src++) << (32-bits);
        do {
            *dst++ = base64url_table[(acc>>(32-6))&0x3F];
            acc <<= 6, bits-=6;
        } while (bits >= 6);
    }
    if (bits) {
        *dst++ = base64url_table[(acc>>(32-6))&0x3F];
    }
    *dst = 0;
    return dst;
}
/*! \brief Декодирование Base64-url safe
    \param dst - выходной буфер
    \param src - входной буфер
 */
uint8_t* base64url_dec (uint8_t *dst, uint8_t* src, size_t length)
{
    uint32_t ch, acc = 0;
    int bits =0;
//    for (i=0; i<slen; i++)
    while ((ch = *src++)!= 0 && length--)
    {
        bits+=6;
        switch (ch)
        {
        case 'A'...'Z': acc |= (ch - ('A'+ 0))<<(32-bits); break;
        case 'a'...'z': acc |= (ch - ('a'-26))<<(32-bits); break;
        case '0'...'9': acc |= (ch + (52-'0'))<<(32-bits); break;
        case '-': acc |= 62<<(32-bits); break;
        case '_': acc |= 63<<(32-bits); break;
//        case '=': break; -- не пригодилось
        default: // не сдвигать, пропустить символ
            bits -= 6;
            break;
        }
        if (bits >= 8)
        {
            *dst++ = acc >> (32-8);
            acc <<= 8;
            bits-=8;
        }
    }
    *dst = 0;
    return dst;
}
/* не включая пробелы и переносы строк, только символы из алфавита */
static const uint32_t base64url_mask[8] = {0x0, 0x03FF2000, 0x87FFFFFE, 0x07FFFFFE};

int base64url_validate (const uint8_t* src, int len, uint8_t** tail)
{
    int i;
    for (i=0; i<len && src[0]!='\0'; i++, src++){
        if ((base64url_mask[src[0]>>5] & (1<<(src[0] & 0x1F)))==0) {
            if (tail) *tail = src;
            return false;
        }
    }
    if (tail) *tail = src;
    return true;
}

#ifdef TEST_BASE64URL
#include <stdio.h>
int main (int argc, char**argv)
{
    char in[4096];
    char out[4096];
    int len=0;
    if (len = fread(in,1,4096, stdin))
    {
        uint8_t* top = (argc==1? base64url_enc : base64url_dec)(out, in, len);
        fwrite(out,1,top - (uint8_t*)out, stdout);
    }
    return 0;
}
#endif
