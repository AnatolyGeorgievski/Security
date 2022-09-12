/*! \brief прямое и обратное преобразование BASE64
[RFC 2045]  Multipurpose Internet Mail Extensions (MIME) Part One:
            Format of Internet Message Bodies
[RFC 4648]  The Base16, Base32, and Base64 Data Encodings


Длина строки не должна превышать 76 символов
Протестировал для совместимости с -m64

https://github.com/aklomp/base64
http://0x80.pl/articles/#base64-algorithm-new

$ gcc -march=skylake-avx512 -dM -E - < /dev/null | grep "AVX"

 */
#include <stdint.h>
#include <string.h>

#ifdef __ARM_NEON
#include <arm_neon.h>

static inline
uint8x16_t enc_translate (const uint8x8x4_t tl, const uint8x8x4_t th, const uint8x16_t in)
{
    uint8x8x2_t v;
    v.val[0] = vtbl4_u8(tl, vget_low_u8(in));
    v.val[1] = vtbl4_u8(tl, vget_high_u8(in));
    v.val[0] = vtbx4_u8(v.val[0],th, vget_low_u8(in-32));
    v.val[1] = vtbx4_u8(v.val[1],th, vget_high_u8(in-32));
    return vcombine_u8(v.val[0], v.val[1]);
}
static inline
uint8x8_t enc_translate8 (const uint8x8x4_t tl, const uint8x8x4_t th, const uint8x8_t in)
{
    uint8x8_t v;
    v = vtbl4_u8(th, in^0x20);
    return vtbx4_u8(v,tl, in);
}
static const uint8_t base64_table[64];
void enc_reshuffle8(/*const uint8x8x4_t tl, const uint8x8x4_t th, */uint8_t* dst, uint8_t* src, int len)
{
	uint8x8x4_t tl = vld4_u8(base64_table+ 0);
	uint8x8x4_t th = vld4_u8(base64_table+ 32);

    int i;
    for(i=0;i<len; i++) {
        uint8x8x3_t in = vld3_u8(src); src+=24;
#if 0
        uint8x8x4_t out;
        out.val[0] = in.val[0];// [a5..a0:b5b4][b3..b0:c5..c2][c1c0:d5..d0]
        out.val[1] = in.val[1]>>2;//
        out.val[1] = vsli_n_u8(out.val[1], in.val[0], 6);// [b]
        out.val[2] = in.val[2]>>4;//
        out.val[2] = vsli_n_u8(out.val[2], in.val[1], 4);
        out.val[3] = in.val[2]<<2;

        // Clear the top two bits by shifting the output back to the right:
        out.val[0] = out.val[0]>>2;
        out.val[1] = out.val[1]>>2;
        out.val[2] = out.val[2]>>2;
        out.val[3] = out.val[3]>>2;
#else
uint8x8x4_t out;
        out.val[3] = in.val[2]<<2>>2;
        out.val[2] = vsli_n_u8(in.val[2]>>4, in.val[1],4)>>2;
        out.val[1] = vsli_n_u8(in.val[1]>>2, in.val[0],6)>>2;
        out.val[0] = in.val[0]>>2;

#endif
        out.val[0] = enc_translate8(tl, th, out.val[0]);
        out.val[1] = enc_translate8(tl, th, out.val[1]);
        out.val[2] = enc_translate8(tl, th, out.val[2]);
        out.val[3] = enc_translate8(tl, th, out.val[3]);
        vst4_u8(dst, out); dst+=32;
    }
    if (0) {
        uint8x8x3_t in;
        switch(len&7){
        case 7: in = vld3_lane_u8(src+18, in, 6);
        case 6: in = vld3_lane_u8(src+15, in, 5);
        case 5: in = vld3_lane_u8(src+12, in, 4);
        case 4: in = vld3_lane_u8(src+ 9, in, 3);
        case 3: in = vld3_lane_u8(src+ 6, in, 2);
        case 2: in = vld3_lane_u8(src+ 3, in, 1);
        case 1: in = vld3_lane_u8(src+ 0, in, 0);
        case 0:
            break;
        }
    }
//	return out;
}

void enc_reshuffle(const uint8_t * base64_table/*const uint8x8x4_t tl, const uint8x8x4_t th*/,  uint8_t * dst, const uint8_t* src, int len)
{
	uint8x8x4_t tl = vld4_u8(base64_table+ 0);
	uint8x8x4_t th = vld4_u8(base64_table+ 32);
    int i;
    for(i=0;i<len; i+=48) {
        uint8x16x3_t in = vld3q_u8(src); src+=48;
        // [a5..a0:b5b4][b3..b0:c5..c2][c1c0:d5..d0]
        uint8x16_t v0,v1,v2,v3;
        v0 = in.val[0];
        v1 = in.val[1]>>2;
        v1 = vsliq_n_u8(v1, in.val[0], 6);
        v2 = in.val[2]>>4;
        v2 = vsliq_n_u8(v2, in.val[1], 4);
        v3 = in.val[2]<<2;

        v0 = v0>>2;
        v1 = v1>>2;
        v2 = v2>>2;
        v3 = v3>>2;

        uint8x8x4_t v;
        v.val[0] = enc_translate8(tl, th, vget_low_u8(v0));
        v.val[1] = enc_translate8(tl, th, vget_low_u8(v1));
        v.val[2] = enc_translate8(tl, th, vget_low_u8(v2));
        v.val[3] = enc_translate8(tl, th, vget_low_u8(v3));
        vst4_u8(dst, v); dst+=32;
        v.val[0] = enc_translate8(tl, th, vget_high_u8(v0));
        v.val[1] = enc_translate8(tl, th, vget_high_u8(v1));
        v.val[2] = enc_translate8(tl, th, vget_high_u8(v2));
        v.val[3] = enc_translate8(tl, th, vget_high_u8(v3));
        vst4_u8(dst, v); dst+=32;
    }
	//return dst+4*16;
}
uint8_t* base64x16_enc(uint8_t* dst, uint8_t* src, int len, uint8_t* base64_table)
{
    uint8x8x4_t tl = vld4_u8(base64_table+ 0);
    uint8x8x4_t th = vld4_u8(base64_table+32);
    int i;
    for (i=0; i<len; i+=12) {
        uint32x4_t v = (uint32x4_t)vld1q_u8(src); src+=12;
        v = (v&0x003FFF) | (v&0x0FFF000)<<4;
        v = (v&0x3F003F) | (v&0xFC00FC0)<<2;
        uint8x16_t vh = (uint8x16_t)v-32;
        uint8x16_t vl = (uint8x16_t)v;
        uint8x8_t v0 = vtbl4_u8(tl, vget_low_u8(vl)) ^ vtbl4_u8(th, vget_low_u8(vh));
        uint8x8_t v1 = vtbl4_u8(tl, vget_high_u8(vl))^ vtbl4_u8(th, vget_high_u8(vh));
        vst1_u8(dst, v0); dst+=8;
        vst1_u8(dst, v1); dst+=8;
    }
}

void base64x8_enc(uint8_t* dst, uint8_t* src, int len, uint8_t* base64_table)
{
    uint8x8x4_t tl = vld4_u8(base64_table+ 0);
    uint8x8x4_t th = vld4_u8(base64_table+32);
    uint8x8x4_t r;
    int i;
    for (i=0; i<len; i+=24) {
        uint8x8_t v3;
        uint8x8x3_t v = vld3_u8(src); src+=24;
        uint8x8_t v0,v1,v2;
        v3 =  v.val[2] <<2>>2;
        v2 = vsli_n_u8(v.val[2]>>4, v.val[1], 4)>>2;
        v1 = vsli_n_u8(v.val[1]>>2, v.val[0], 6)>>2;
        v0 = (v.val[0]>>2); // [a5..a0:b5b4][b3..b0:c5..c2][c1c0:d5..d0]
        r.val[0] = vtbl4_u8(tl, v0);
        r.val[1] = vtbl4_u8(tl, v1);
        r.val[2] = vtbl4_u8(tl, v2);
        r.val[3] = vtbl4_u8(tl, v3);

        r.val[0] = vtbx4_u8(r.val[0], th, v0 ^ 32);
        r.val[1] = vtbx4_u8(r.val[1], th, v1 ^ 32);
        r.val[2] = vtbx4_u8(r.val[2], th, v2 ^ 32);
        r.val[3] = vtbx4_u8(r.val[3], th, v3 ^ 32);
        vst4_u8(dst, r); dst+=32;
    }
}

#endif // __ARM_NEON
#if 0

typedef char v16qi __attribute__((vector_size(16)));
typedef uint32_t v4su __attribute__((vector_size(16)));
uint8_t* base64x16_enc(uint8_t* dst, uint8_t* src, int len)
{
//    v16qi z = (v16qi){0};
    v16qi v0;
    int i;
    for (i=0;i<len;i+=12)
    {
        if (len-i>=12)
            __builtin_memcpy(&v0, &src[i],12);
        else {
            __builtin_memcpy(&v0, &src[i],len-i);
            v0[len-i] = '\0';
        }
        v4su v = (v4su)__builtin_shuffle(v0,(v16qi){0,1,2,3, 3,4,5,6, 6,7,8,9, 9,10,11,0});
        v = (v & 0xFFF) | (v & 0xFFF000)<<4;
        v = (v & 0x3F003F) | (v & (0x0FC00FC0))<<2;
//        v = (v & 0x3F) | (v&0xFC0)<<2 | (v&0x3F000)<<4 | (v&0xFC0000)<<6;
        if (len-i<12) {}
        v16qi m = ((v16qi)v<26);
        v16qi r = m & ((v16qi)v + 'A');
        m = ~m & ((v16qi)v<52);
        r |= m & ((v16qi)v + 'a');
        m = ~m ;
        r |= m & __builtin_shuffle((v16qi){'0','1','2','3','4','5','6','7','8','9','+','/'}, (v16qi)v-52);// замена по таблице
        if (len-i>=12){
            __builtin_memcpy(&dst[i], &r,16);
            dst+=16;
        } else {
            int len2 = ((len-i)*4 + 2)/3;
            __builtin_memcpy(&dst[i], &r,len2);
            dst+=len2;
            // делится на 3
            switch (len-i){
            case 1:
            case 4:
            case 7:
            case 10: dst[-2]='=';
            case 2:
            case 5:
            case 8:
            case 11: dst[-1]='=';
            default:
                break;
            }
            break;
        }
    }
    *dst='\0';
    return dst;
}
#endif
static const uint8_t base64_table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
/*! \brief Кодирование Base64
    \param dst - указатель на выходной буфер, длина буфера должна быть больше (length(src)*4 + 3)/3
    \param src - указатель на входной буфер. Строка должна заканчиваться нулем
    \return указатель на конец записи в выходном буфере.
 */
#if 0
uint8_t* base64x4_enc(uint8_t *dst, uint8_t *src, int length)
{
	uint8_t r0 = src[0];// [a5..a0:b5b4]
	uint8_t r1 = src[1];// [b3..b0:c5..c2]
	uint8_t r2 = src[2];// [c1c0:d5..d0]
	*dst++ = base64_table[(        r0   )>>2];
	*dst++ = base64_table[(r0<<6 | r1>>2)>>2];
	*dst++ = base64_table[(r1<<4 | r2>>4)>>2];
	*dst++ = base64_table[(r2<<2        )>>2];
	return dst;
}
#endif
#include <x86intrin.h>

#define BEXTR(x, n, len) (((x) >> (n)) & ((1 << (len))-1))
//uint8_t* base64_enc_axv512(uint8_t *dst, uint8_t *src, int length);
__attribute__((__target__("default")))
uint8_t*
base64_enc(uint8_t *dst, uint8_t *src, int length)
{
    while (length>=3)
    {// производительность один байт на такт
        uint32_t acc;
        acc = __builtin_bswap32(*(uint32_t*)src); src+=3;// [a5..a0:b5b4][b3..b0:c5..c2][c1c0:d5..d0]
        *dst++ = base64_table[BEXTR(acc,(32- 6),6)/*(acc>>(32- 6))&0x3F*/];// _bextr2_u64(acc, (0x600+32-6))
        *dst++ = base64_table[BEXTR(acc,(32-12),6)];
        *dst++ = base64_table[BEXTR(acc,(32-18),6)];
        *dst++ = base64_table[BEXTR(acc,(32-24),6)];
        length-=3;
    }
    if (length==0) {
    } else
	if (length==2) {
        uint32_t acc;
		acc = __builtin_bswap32(*(uint16_t*)src);
        *dst++ = base64_table[BEXTR(acc,(32- 6),6)];
        *dst++ = base64_table[BEXTR(acc,(32-12),6)];
        *dst++ = base64_table[BEXTR(acc,(32-18),6)];
		*dst++ = '=';
	} else {
        uint32_t acc;
		acc = __builtin_bswap32(src[0]);
        *dst++ = base64_table[BEXTR(acc,(32- 6),6)];
        *dst++ = base64_table[BEXTR(acc,(32-12),6)];
        *dst++ = '=';
        *dst++ = '=';
    }
    *dst = 0;
    return dst;
}


__attribute__((__target__("avx512vbmi,avx512vl")))
uint8_t* base64_enc_avx512(uint8_t *dst, uint8_t *src, size_t length)
{
const __m512i lookup = _mm512_loadu_si512(base64_table);
/* [a5..a0:b5b4][b3..b0:c5..c2][c1c0:d5..d0] -- расположение бит в памяти
   32-6,32-12,32-18,32-24
   64-6,64-12,64-18,64-24 - сдвиги
*/
const __m512i shifts = _mm512_set1_epi64(0x282E343A080E141AULL);
const __m512i revert = (__m512i)(__v64qi){
    -1, 2, 1, 0, -1, 5, 4, 3, -1, 8, 7, 6, -1,11,10, 9,
    -1,14,13,12, -1,17,16,15, -1,20,19,18, -1,23,22,21,
    -1,26,25,24, -1,29,28,27, -1,32,31,30, -1,35,34,33,
    -1,38,37,36, -1,41,40,39, -1,44,43,42, -1,47,46,45
    };
    while (length>=48){// 2 такта на цикл 64 байта, ускорение 32 раза!!
        __m512i v = /* _mm512_loadu_si512 (src);*/_mm512_maskz_loadu_epi8((1ULL<<48)-1, src);
        src+=48;
        v = _mm512_permutexvar_epi8 (revert, v);// переставить местами BSWAP
        v = _mm512_multishift_epi64_epi8(shifts, v);// 32-6,32-12,32-18,32-24  64-6,64-12,64-18,64-24
        v = _mm512_permutexvar_epi8(v, lookup);// игнорирует страшие 2 бита в байте.
        _mm512_storeu_si512(dst, v); dst+=64;
        length-=48;
    }
    if (length) {// 1..47
        __mmask64 mask = (1ULL<<length)-1;
        __m512i v = _mm512_maskz_loadu_epi8(mask, src); src+=length;
        v = _mm512_permutexvar_epi8 (revert, v);// переставить местами
        v = _mm512_multishift_epi64_epi8(shifts, v);// 32-6,32-12,32-18,32-24  64-6,64-12,64-18,64-24
        v = _mm512_permutexvar_epi8(v, lookup);// игнорирует страшие 2 бита в байте.
    // пересчитать маску
//1 2 3,4 5 6, 7  8
//2 3 4 6 7 8 10 11
        size_t len = (length*4+2)/3;
        mask = (1ULL<<len)-1;
        _mm512_mask_storeu_epi8(dst, mask, v); dst+=len;

        size_t rem = (length)%3;
        if (rem==1){
            *dst++ = '=';
            *dst++ = '=';
        } else if (rem==2)
            *dst++ = '=';
        *dst = 0;
    }
    return dst;
}
__attribute__((__target__("avx512vbmi,avx512vl")))
uint8_t* base64_enc_avx512_x256(uint8_t *dst, uint8_t *src, size_t length)
{
const __m256i lookup0 = _mm256_loadu_si256((void*)base64_table);
const __m256i lookup1 = _mm256_loadu_si256((void*)base64_table+32);
/* [a5..a0:b5b4][b3..b0:c5..c2][c1c0:d5..d0] -- расположение бит в памяти
   32-6,32-12,32-18,32-24
   64-6,64-12,64-18,64-24 - сдвиги
*/
const __m256i shifts = _mm256_set1_epi64x(0x282E343A080E141AULL);
const __m256i revert = (__m256i)(__v32qi){
    -1, 2, 1, 0, -1, 5, 4, 3, -1, 8, 7, 6, -1,11,10, 9,
    -1,14,13,12, -1,17,16,15, -1,20,19,18, -1,23,22,21,
    };
    while (length>=24){// 2 такта на цикл 64 байта, ускорение 32 раза!!
        __m256i v = /* _mm512_loadu_si512 (src);*/_mm256_maskz_loadu_epi8((1ULL<<24)-1, src);
        src+=24;
        v = _mm256_permutexvar_epi8 (revert, v);// переставить местами BSWAP
        v = _mm256_multishift_epi64_epi8(shifts, v);// 32-6,32-12,32-18,32-24  64-6,64-12,64-18,64-24
        v = _mm256_permutex2var_epi8(lookup0, v, lookup1);// игнорирует страшие 2 бита в байте.
        _mm256_storeu_si256((void*)dst, v); dst+=32;
        length-=24;
    }
    if (length) {// 1..23
        __mmask32 mask = (1UL<<length)-1;
        __m256i v = _mm256_maskz_loadu_epi8(mask, src); src+=length;
        v = _mm256_permutexvar_epi8 (revert, v);// переставить местами
        v = _mm256_multishift_epi64_epi8(shifts, v);// 32-6,32-12,32-18,32-24  64-6,64-12,64-18,64-24
        v = _mm256_permutex2var_epi8(lookup0,v, lookup1);// игнорирует страшие 2 бита в байте.
        size_t len = (length*4+2)/3;
        mask = (1UL<<len)-1;
        _mm256_mask_storeu_epi8(dst, mask, v); dst+=len;

        size_t rem = (length)%3;
        if (rem==1){
            *dst++ = '=';
            *dst++ = '=';
        } else if (rem==2)
            *dst++ = '=';
        *dst = 0;
    }
    return dst;
}
#if 0
/*! Следующая задача -- переформатировать каноникализация, убрать лишние символы */
__attribute__((__target__("avx512vbmi")))
int base64_validate_avx512(uint8_t* src, int len, uint8_t** tail)
{
    for (len) {
        _mm512_loadu_si512(src);// загрузили сразу много
        __mmask64 mask =
    }
}
#endif // 0
__attribute__((__target__("avx512vbmi,avx512bw,avx512vl")))
uint8_t* base64_dec_avx512(uint8_t* dst, uint8_t* src, size_t length)
{
    const  __m512i lookup0 = (__m512i)(__v64qi){0};
    const  __m512i lookup1 = (__m512i)(__v64qi){0};
    const  __m512i revert  = (__m512i)(__v64qi){
/*
         3, 2, 1,  7, 6, 5, 11,10, 9, 15,14,13, 19,18,17, 23,22,21, 27,26,25, 31,30,29,
        35,34,33, 39,38,37, 43,42,41, 47,46,45, 51,50,49, 55,54,53, 59,58,57, 63,62,61 */
         2, 1, 0,  6, 5, 4, 10, 9, 8, 14,13,12, 18,17,16, 22,21,20, 26,25,24, 30,29,28,
        34,33,32, 38,37,36, 42,41,40, 46,45,44, 50,49,48, 54,53,52, 58,57,56, 62,61,60
        };
    __mmask64 mask = (1ULL<<48)-1;
    while (length>=64) {
        __m512i v,r;
        v = _mm512_loadu_si512(src);
        r = _mm512_permutex2var_epi8(lookup0, v, lookup1);// загрузили сразу много
        if (0 && (_mm512_movepi8_mask(r|v))) {// если значение больше 64
            // обработка ошибок -- пропустить символы
            return dst;
        }
// input:  [00dddddd|00cccccc|00bbbbbb|00aaaaaa] msb-lsb
// merge:  [0000cccc|ccdddddd|0000aaaa|aabbbbbb]
// result: [00000000|aaaaaabb|bbbbcccc|ccdddddd]
        r = _mm512_maddubs_epi16(r, _mm512_set1_epi32(0x01400140));
        r = _mm512_madd_epi16(r, _mm512_set1_epi32(0x00011000));
/*

        r = _mm512_slli_epi16(r, 8) // [00cccccc|00000000|00aaaaaa|00000000]
          ^ _mm512_srli_epi16(r, 6);// [00000000|dddddd00|00000000|bbbbbb00]
        r = _mm512_slli_epi32(r,10) // [aaaaaabb|bbbb0000|00000000|00000000]
          ^ _mm512_srli_epi32(r,18);// [00000000|0000cccc|ccdddddd|0000aaaa]
*/
//        r = _mm512_shuffle_epi8(r, _mm512_set4_epi32(0x06000102,0x090A0405, 0x0C0D0E08,0xFFFFFFFF));
/*       2,  1,  0,
         6,  5,  4,
        10,  9,  8,
        14, 13, 12,
        -1, -1, -1, -1*/
        r = _mm512_permutexvar_epi8(revert, r);
        _mm512_mask_storeu_epi8 (dst, mask, r);
//        _mm512_mask_compressstoreu_epi8 (dst, mask, r);
        //_mm512_storeu_si512(dst, r);
        dst+=48;
        src+=64;
        length-=64;
    }
    if (length){

    }
    return dst;
}
__attribute__((__target__("avx512vbmi,avx512bw,avx512vl")))
uint8_t* base64_dec_avx256(uint8_t* dst, uint8_t* src, size_t length)
{
    const  __m256i lookup0 = (__m256i)(__v32qi){0};
    const  __m256i lookup1 = (__m256i)(__v32qi){0};
    const  __m256i revert  = (__m256i)(__v32qi){
         2, 1, 0,  6, 5, 4, 10, 9, 8, 14,13,12, 18,17,16, 22,21,20, 26,25,24, 30,29,28,
        };
    __mmask32 mask = (1ULL<<24)-1;
    while (length>=32) {
        __m256i v,r;
        v = _mm256_loadu_si256((void*)src);
        r = _mm256_permutex2var_epi8(lookup0, v, lookup1);// загрузили сразу много
        if (0 && (_mm256_movepi8_mask(r|v))) {// если значение больше 64
            // обработка ошибок -- пропустить символы пробелов и табуляции
            return dst;
        }
// input:  [00dddddd|00cccccc|00bbbbbb|00aaaaaa] msb-lsb
// merge:  [0000cccc|ccdddddd|0000aaaa|aabbbbbb]
// result: [00000000|aaaaaabb|bbbbcccc|ccdddddd]

        r = _mm256_maddubs_epi16(r, _mm256_set1_epi32(0x01400140));
        r = _mm256_madd_epi16(r, _mm256_set1_epi32(0x00011000));



//        r = _mm256_slli_epi16(r, 8) // [00cccccc|00000000|00aaaaaa|00000000]
//          ^ _mm256_srli_epi16(r, 6);// [00000000|dddddd00|00000000|bbbbbb00]
//        r = _mm256_slli_epi32(r,10) // [aaaaaabb|bbbb0000|00000000|00000000]
//            ^ _mm256_srli_epi32(r,18);// [00000000|0000cccc|ccdddddd|0000aaaa]

//        r = _mm512_shuffle_epi8(r, _mm512_set4_epi32(0x06000102,0x090A0405, 0x0C0D0E08,0xFFFFFFFF));
/*       2,  1,  0,
         6,  5,  4,
        10,  9,  8,
        14, 13, 12,
        -1, -1, -1, -1*/
        r = _mm256_permutexvar_epi8(revert, r);
        _mm256_mask_storeu_epi8 (dst, mask, r);
//        _mm512_mask_compressstoreu_epi8 (dst, mask, r);
        //_mm512_storeu_si512(dst, r);
        dst+=24;
        src+=32;
        length-=32;
    }
    if (length){

    }
    return dst;
}

#if 0
uint8_t* base64_enc0(uint8_t *dst, uint8_t *src, size_t length)
{
    uint32_t acc=0;
    int bits=0;
//    int i=0;
    while (length--)
    {
        bits+=8;
        acc |= (uint32_t)(*src++) << (32-bits);// [a5..a0:b5b4][b3..b0:c5..c2]
        do {
            *dst++ = base64_table[BEXTR(acc,(32-6),6)];
            acc <<= 6, bits-=6;
        } while (bits >= 6);
    }
    if (bits) {
        *dst++ = base64_table[BEXTR(acc,(32-6),6)];
        if (bits==2) *dst++ = '=';
        *dst++ = '=';
    }
    *dst = 0;
    return dst;
}
#endif // 0
/*! \brief Декодирование Base64
    \param dst - выходной буфер
    \param src - входной буфер
 */
uint8_t* base64_dec (uint8_t *dst, const uint8_t* src, int length)
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
        case '+': acc |= 62<<(32-bits); break;
        case '/': acc |= 63<<(32-bits); break;
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
static const uint32_t base64_mask[8] = {0x260, 0x03FF8801, 0x07FFFFFE, 0x07FFFFFE};

int base64_validate (uint8_t* src, int len, uint8_t** tail)
{
    while (len!=0 && src[0]!='\0'){
        if (base64_mask[src[0]>>5] & (1<<(src[0] & 0x1F))) {
            src++, len--;
            continue;
        }
        //unsigned int ch = src[0];

        switch(src[0]){
/*
        case ' ':
        case '\t':
        case '\n':
        case '\r':
            break;*/
        case '=':
            if (len==1 || src[1]=='\0') {// конец строки
                break;
            }
            if ((src[1]=='=') && (len==2 || src[2]=='\0')) {// конец строки
                src++, len--;
                break;
            }
        default:
            if (tail) *tail = src;
            return 0;
        }
        src++, len--;
    }
    if (tail) *tail = src;
    return 1;
}

#if defined(TEST_BASE64)
#include <stdio.h>
int main (int argc, char**argv)
{
    char in[4096];
    int len=0;
    if (len = fread(in,1,4096/2, stdin))
    {
		char out[4096];
        uint8_t* top;
        if (argc==1) top = base64_enc (out, in, len);
        else top = base64_enc_avx512(out, in, len);
        fwrite(out,1,top - (uint8_t*)out, stdout);
    }
//    top = base64_dec(in, out, top-(uint8_t*)out);
//    puts(in);
    return 0;
}
#endif
