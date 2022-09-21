/*! Galois GF(2^8)

$ gcc -DTEST_RS -o rs.exe reed-solomon.c
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t exp_[256] = {
    1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117, 234,
    201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238,
    193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161, 95, 190,
    97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187, 107, 214,
    177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52,
    104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102,
    204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168, 77, 154, 41, 82,
    164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198, 145, 63, 126, 252,
    229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165,
    87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81, 162, 89,
    178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72, 144, 61, 122, 244, 245,
    247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173,
    71, 142,1};
static const uint8_t log_[256] = {
    0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239,
    129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240,
    18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6, 191,
    139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143, 150, 219,
    189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250,
    133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87, 7, 112, 192,
    247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165, 153, 119, 38, 184, 180, 124,
    17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252,
    190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162, 31, 45, 67, 216, 183,
    123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246, 108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134,
    177, 187, 204, 62, 90, 203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79,
    174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175
};
#if 1
// https://github.com/YuliaKUA/Reed-Solomon
/* @brief Addition in Galua Fields
 * @param x - left operand
 * @param y - right operand
 * @return x + y */
static inline int gf_add(int x, int y) {
    return x ^ y;
}
/* @brief Substraction in Galua Fields
 * @param x - left operand
 * @param y - right operand
 * @return x - y */
static inline int gf_sub(int x, int y) {
    return x ^ y;
}
/* @brief Multiplication in Galua Fields
 * @param x - left operand
 * @param y - rifht operand
 * @return x * y */
static inline int gf_mul(int x, int y) {
    if (x == 0 || y == 0) return 0;
    return exp_[(log_[x] + log_[y])%255];
}

/* @brief Division in Galua Fields
 * @param x - dividend
 * @param y - divisor
 * @return x / y */
static inline int gf_div(int x, int y) {
    if (x == 0) return 0;
    return exp_[(log_[x] + 255 - log_[y]) % 255]; //add 255 to make sure the difference is not negative
}
/* @brief X in power Y w
 * @param x     - operand
 * @param power - power
 * @return x^power */
static inline int pow_(int x, int power) {
    int i = log_[x];
    i *= power;
    i %= 255;

    if (i < 0) i = i + 255;

    return exp_[i];
}
/* @brief Inversion in Galua Fields
 * @param x - number
 * @return inversion of x */
static inline int inverse(int x) {
    return exp_[255 - log_[x]]; /* == div(1, x); */
}
#endif // 0
/* \todo Надо написать и отладить версию для полиномиального умножения pmull_p8 Arm Neon */
#if defined(__PCLMUL__)
typedef  int64_t v2di __attribute__((__vector_size__(16)));
typedef uint64_t v2du __attribute__((__vector_size__(16)));
static inline uint64_t CL_MUL8(uint8_t a, uint8_t b) {
    v2du v = (v2du)__builtin_ia32_pclmulqdq128 ((v2di){a},(v2di){b},0);
	return v[0];
}
//#warning "__PCLMUL__ instruction enabled"
#else
// умножение без переноса - эмуляция
static inline uint64_t CL_MUL8(uint8_t a, uint8_t b) {
    uint64_t v = 0;
	while (a!=0) {// умножение без переноса
		int n = __builtin_ctz(a);
		a ^= (1<<n);
		v ^= (b<<n);
	}
	return v;
}
#endif
#if 1
static uint8_t gf_mod(uint64_t c)
{	// редуцирование Barret's константа барета =0x1C
	uint64_t t = CL_MUL8(c>>8, 0x1C)^c;
	c^= CL_MUL8(t>>8,0x1D);
	return c & 0xFF;
}
static inline uint8_t gf_mul2(uint32_t a, uint32_t b)
{
	uint64_t c = CL_MUL8(a,b);
	return gf_mod(c);
}
#endif // 0

/*
Есть такой вариант, но он плохо кодируется
if (!__builtin_add_overflow(i+1, log_[g[j]], &k)){// %255
	k--;
}
GCC выполняет оптимизацию по виду напоминает
	uint32_t q = (v*0x80808081ULL)>>(39);// сдвигает старшые 32 бита на 7
	return v - ((q<<8)-q); == v+q
*/
static inline uint8_t mod255(uint16_t v)
{
	uint32_t q = (v*0x1010102UL)>>(24);
	return q;
}

void mod255_test(){
	uint32_t v;	
	for (v=0; v<=0xFFFF; v++)
		if ((v%255) != mod255(v)) printf("fail %d\n", v);
}	
static inline uint8_t mod255_(uint32_t v)
{
	uint32_t q = (v*0x80808081ULL)>>(39);
	return v + q;// - q*255;
}
static void generator_init(uint8_t *gen, size_t length)
{
	size_t i, j;
	int g[length];

	uint8_t k;
	for(i = 0; i < length; i++) {
		g[i] = 1;
		/* Because g[0] never be zero, skipped some conditional checks. */
		for(j = i; j > 0; j--) {
			k = mod255(i+log_[g[j]]);//%255;
			g[j] = g[j - 1] ^  exp_[k];// [(log_[g[j]] + i) % 255];
		}
/*		if (!__builtin_add_overflow(i+1, log_[g[0]], &k)){// %255
			k--;
		}*/
		k = mod255(i+log_[g[0]]);//%255;
		g[0] = exp_[k];// [(log_[g[0]] + i) % 255];
	}

	if (gen) for(i = 0; i < length; i++) {
        gen[i] = log_[g[length-1-i]];
	}
#if defined(RS_TEST)
	printf("static const uint8_t gen_%d[256] = {\n\t", (int)length);
	for(i = 0; i < length; i++) {
		printf("%d, ", gen[i]);
	}
    printf("};\n");
#endif // 0
}
#if 0
static void generator_init2(uint8_t *g, size_t length)
{
	size_t i, j;
	uint8_t k;
	for(i = 0; i < length; i++) {
		g[i] = 1;
		/* Because g[0] never be zero, skipped some conditional checks. */
		for(j = i; j > 0; j--) {
			k = mod255(i+log_[g[j]]);//%255;
			g[j] = g[j - 1] ^ exp_[k];// [(log_[g[j]] + i) % 255];
		}
		k = mod255(i+log_[g[0]]);//%255;
		g[0] = exp_[k];// [(log_[g[0]] + i) % 255];
	}
}
#endif
//g = (x-1)*(x-2^(1))*..*(x-2^(red_code_len-1))
int RSECC_encode(const uint8_t *data, uint32_t data_length, uint8_t *ecc, uint32_t ecc_length)
{
    memset(ecc, 0, ecc_length);
    int i,j;
#if 0 // этот вариант списан с libqrencode
	for(i = 0; i < data_length; i++) {
		unsigned int feedback = log_[data[i] ^ ecc[0]];
		if(feedback != 0) {
			for(j = 1; j < ecc_length; j++) {
				ecc[j] ^= exp_[(unsigned int)(feedback + gen[j-1]) % 255];
			}
		}
		memmove(&ecc[0], &ecc[1], ecc_length - 1);
		if(feedback != 0) {
			ecc[ecc_length - 1] = exp_[(unsigned int)(feedback + gen[ecc_length - 1]) % 255];
		} else {
			ecc[ecc_length - 1] = 0;
		}
	}
#elif 0
// этот вариант основан на изоморфном преобразовании алгоритма [Z]->[H(z)] <=> [H(z)]->[Z]
// Аналогично преобразованию FIR фильтра в транспонированную форму.
/*
   *-----*-----*----...----*-----*-<(s+data)
   |     |     |           |
   x g0  x g1  x g2 ...    x gn
   |     |     |           |
   +-[Z]-+-[Z]-+-[Z]...[Z]-+-[Z]-+->(s+data)

   *-[Z]-*-[Z]-*-[Z]...[Z]-*-[Z]-*-<(s+data)
   |     |     |           |
   x g0  x g1  x g2 ...    x gn
   |     |     |           |
   +-----+-----+----...----+-----+->(s+data)-->

   data>--(+s)---V-->(+s)---V-->...
           ^     |    ^     |
           x e^0 |    x e^1 |
           *-[Z]-*    *-[Z]-*
 */
    uint8_t Z[ecc_length];
    memset(Z, 0, ecc_length);

   for(i=0; i< data_length; i++) {
    uint8_t s = data[i];
    for (j=0; j< ecc_length;j++){
        uint8_t k = mod255(Z[j]+j);
        s ^= exp_[k];
        Z[j] = log_[s];
    }
   }
   for(i=0; i< ecc_length; i++) {
    uint8_t s = 0;
    for (j=0; j< ecc_length;j++){
        uint8_t k = mod255(Z[j]+j);
        s ^= exp_[k];
        Z[j] = log_[s];
    }
    ecc[i] = s;
   }

#elif 0
    uint8_t g[ecc_length];
    generator_init2(g, ecc_length);
    uint8_t Z[ecc_length];
    memset(Z, 0, ecc_length);
	for(i = 0; i < data_length; i++) {
		uint16_t s = data[i];
		for(j = 0; j < ecc_length; j++) {
			//if (Z[j]!=0)
			{
				//uint8_t k = mod255(Z[j]+gen[j]);
				//s ^= exp_[k];
				s ^= CL_MUL8(Z[j],g[ecc_length -1 -j]);
			}
		}
		memmove(&Z[1], &Z[0], ecc_length - 1);
		//Z[0] = log_[s];
		Z[0] = gf_mod(s);
	}
	for(i = 0; i < ecc_length; i++) {
		uint16_t s = 0;
		for(j = 0; j < ecc_length-i; j++) {
			//if (Z[j]!=0)
			{
				//uint8_t k = mod255(Z[j]+gen[j+i]);
				// s ^= exp_[k];
				s ^= CL_MUL8(Z[j],g[ecc_length -1 -(j+i)]);
			}
		}
		ecc[i] = gf_mod(s);
	}
#elif 0
    uint8_t g[ecc_length];
    generator_init2(g, ecc_length);
    uint16_t Z[ecc_length];
    memset(Z, 0, 2*ecc_length);
	for(i = 0; i < data_length; i++) {
		uint8_t fb =  data[i] ^ gf_mod(Z[0]);
		for(j = 0; j < ecc_length-1; j++) {
			Z[j] = Z[j+1] ^ CL_MUL8(fb, g[ecc_length-1 - j]);
		}
		Z[j] = CL_MUL8(fb, g[ecc_length-1 - j]);
	}
	for(i = 0; i < ecc_length; i++) {
		ecc[i] = gf_mod(Z[i]);
	}
#else
    uint8_t gen[ecc_length];
    generator_init(gen, ecc_length);
//    uint8_t Z[ecc_length];
//    memset(Z, 0, ecc_length);
	for(i = 0; i < data_length; i++) {
		uint8_t fb = log_[data[i] ^ ecc[0]];
		if(fb != 0) {
			//fb++;
			uint8_t k;
			for(j = 0; j < ecc_length-1; j++) {
				k = mod255(fb+gen[j]);//%255; -- ecc[j] = (data+ecc[0])*g[j] ^ ecc[j+1]
				ecc[j] = ecc[j+1] ^ exp_[k];
			}
			k = mod255(fb+gen[j]);//%255;
			ecc[j] = exp_[k];
		} else {
			for(j = 0; j < ecc_length-1; j++) {// memmove
				ecc[j] = ecc[j+1];
			}
			ecc[j] = 0;
		}
		//printf ("s=%d %d\n", s, ecc[0]);
	}
#endif
	return 0;
}
#if defined(RS_TEST)
static void RSECC_initLookupTable(uint32_t poly)
{
	unsigned int i;
    uint8_t log[256];
	uint8_t b = 1;
	printf("static const uint8_t exp_[256] = {\n\t%d, ", b);
	for(i = 0; i < 0xFF; i++) {
//		alpha[i] = b;
		log[b] = i;
		if(__builtin_add_overflow(b, b, &b)){// сдвиг
			b ^= poly;
		}
		printf("%d, ", b);
	}
	log[b] = i;
	printf("};\n");
	printf("static const uint8_t log_[256] = {\n\t", b);
    log[0] = 0;
	for(i = 0; i < 256; i++) {
		printf("%d, ", log[i]%255);
	}
	printf("};\n");
}


// https://github.com/YuliaKUA/Reed-Solomon
int main(int argc, char *argv[])
{
	mod255_test();
	//if (argc<=1) return 0;
    RSECC_initLookupTable(0x11d);// полином поля 0x11d
/*!
7 	87, 229, 146, 149, 238, 102, 21
10 	251, 67, 46, 61, 118, 70, 64, 94, 32, 45
13 	74, 152, 176, 100, 86, 100, 106, 104, 130, 218, 206, 140, 78
15 	8, 183, 61, 91, 202, 37, 51, 58, 58, 237, 140, 124, 5, 99, 105
16 	120, 104, 107, 109, 102, 161, 76, 3, 91, 191, 147, 169, 182, 194, 225, 120
17 	43, 139, 206, 78, 43, 239, 123, 206, 214, 147, 24, 99, 150, 39, 243, 163, 136
18 	215, 234, 158, 94, 184, 97, 118, 170, 79, 187, 152, 148, 252, 179, 5, 98, 96, 153
20 	17, 60, 79, 50, 61, 163, 26, 187, 202, 180, 221, 225, 83, 239, 156, 164, 212, 212, 188, 190
22 	210, 171, 247, 242, 93, 230, 14, 109, 221, 53, 200, 74, 8, 172, 98, 80, 219, 134, 160, 105, 165, 231
24 	229, 121, 135, 48, 211, 117, 251, 126, 159, 180, 169, 152, 192, 226, 228, 218, 111, 0, 117, 232, 87, 96, 227, 21
26 	173, 125, 158, 2, 103, 182, 118, 17, 145, 201, 111, 28, 165, 53, 161, 21, 245, 142, 13, 102, 48, 227, 153, 145, 218, 70
28 	168, 223, 200, 104, 224, 234, 108, 180, 110, 190, 195, 147, 205, 27, 232, 201, 21, 43, 245, 87, 42, 195, 212, 119, 242, 37, 9, 123
30 	41, 173, 145, 152, 216, 31, 179, 182, 50, 48, 110, 86, 239, 96, 222, 125, 42, 173, 226, 193, 224, 130, 156, 37, 251, 216, 238, 40, 192, 180
*/
    uint8_t gen[32];
    generator_init(gen, 7);
    generator_init(gen, 10);
    generator_init(gen, 13);
    generator_init(gen, 22);
    generator_init(gen, 28);
	uint8_t msg[] = "hello world!";
	const int ecc_len=10;
	uint8_t ecc[ecc_len];
	uint8_t ecc2[ecc_len];
	RSECC_encode(msg, strlen(msg), ecc, ecc_len);
	printf("ecc [%d] = {\n\t", ecc_len);
	int i;
	for(i = 0; i < ecc_len; i++) {// Проверка 224, 102, 50, 88, 20, 4, 178, 237, 217, 123
		printf("%d, ", ecc[i]);
	}
	printf("};\n");
	// тестирование умножения
	uint32_t a, b;
	for (b=0; b<256; b++) {
		for (a=0; a<=b; a++) {
			if (gf_mul(a,b)!= gf_mul2(a,b)) printf("mul!= %d %d\n", gf_mul(a,b), gf_mul2(a,b));
		}
	}

    uint8_t msg0[]="\x01\x01";
    uint8_t msg1[]="\x01\x00";
    uint8_t msg2[]="\x1d\x01";
	RSECC_encode(msg0, 2, ecc, ecc_len);
	printf("ecc [%d] = {", ecc_len);
	for(i = 0; i < ecc_len; i++) {// Проверка 224, 102, 50, 88, 20, 4, 178, 237, 217, 123
		printf("%d, ", ecc[i]);
	}
	printf("};\n");

	RSECC_encode(msg1, 2, ecc, ecc_len);
	RSECC_encode(msg1, 1, ecc2, ecc_len);
	printf("ecc [%d] = {", ecc_len);
	for(i = 0; i < ecc_len; i++) {// Проверка 224, 102, 50, 88, 20, 4, 178, 237, 217, 123
		printf("%d, ", ecc2[i]^ecc[i]);
	}
	printf("};\n");
#if 0
    extern void show_buffer(int argc, char *argv[],uint8_t * buffer);
    show_buffer(argc,argv, data);
#endif
	return 0;
}
#endif
