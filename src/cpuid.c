/*! 
	\author Анатолий Георгиевский 
сборка:
	$gcc -DTEST_CPUID -o cpuid cpuid.c 
*/

#include <cpuid.h>
#include <stdio.h>

unsigned int cpuid_max_func=0;
unsigned int cpuid_max_extfunc=0;
unsigned int cpuid_sign=0;
unsigned int cpuid_leaf1cx=0;

static void  __attribute__((constructor)) cpuid_init()
{
    unsigned ax=0,bx,cx,dx;
//    __cpuid_count(0x0, 0, ax,bx,cx,dx);//
//    cpuid_max_func = ax;
//    cpuid_sign = dx;

    cpuid_max_func = __get_cpuid_max(0, &cpuid_sign);

    unsigned name[13];//={0};
    // 0 - строка
    __cpuid(0, ax,bx,cx,dx);// производитель процессора
    //unsigned max_std_func = ax;
    name[0] = bx;
    name[1] = dx;
    name[2] = cx;
    name[3] = 0;
//    name[3] = ax;
//    name[0] = ax;
    __cpuid(0x80000000, ax,bx,cx,dx);
    cpuid_max_extfunc = ax;

    printf("max CPUID=0x%X ext=0x%X sign=0x%X\n", cpuid_max_func, cpuid_max_extfunc, cpuid_sign);

    if (cpuid_max_extfunc >= 0x80000004) {// расширенное название процессора
        __cpuid(0x80000002, ax,bx,cx,dx);
        name[0] = ax;
        name[1] = bx;
        name[2] = cx;
        name[3] = dx;
        __cpuid(0x80000003, ax,bx,cx,dx);
        name[4] = ax;
        name[5] = bx;
        name[6] = cx;
        name[7] = dx;
        __cpuid(0x80000004, ax,bx,cx,dx);
        name[8] = ax;
        name[9] = bx;
        name[10] = cx;
        name[11] = dx;
        //name[12] = 0;
        printf("%.48s\n", (char*)name);
    } else
        printf("%s\n", (char*)name);


    __cpuid(1, ax,bx,cx,dx);
	// printf("Cache line: %d B\n", ((bx>>8)&0xFF)*8);
	// printf("Max Proc IDs: %d B\n", ((bx>>16)&0xFF)*8);
	// cache line size in bytes
    if (dx& bit_MMX)    printf(" MMX");
    if (dx& bit_SSE)    printf(" SSE");
    if (dx& bit_SSE2)   printf(" SSE2");
cpuid_leaf1cx = cx;
    if (cx& (1<< 0))    printf(" SSE3");
    if (cx& (1<< 1))    printf(" PCLMUL");
//    if (cx& (1<< 5))    printf(" LZCNT");
//    if (cx& (1<< 8))    printf(" TM2");
    if (cx& (1<< 9))    printf(" SSSE3");
    if (cx& (1<<12))    printf(" FMA");
    if (cx& (1<<13))    printf(" CMPXCHG16B");
    if (cx& (1<<19))    printf(" SSE4.1");
    if (cx& (1<<20))    printf(" SSE4.2");
    if (cx& (1<<21))    printf(" x2APIC");
    if (cx& (1<<22))    printf(" MOVBE");
    if (cx& (1<<23))    printf(" POPCNT");
    if (cx& (1<<25))    printf(" AES");
    if (cx& (1<<26))    printf(" XSAVE");
    if (cx& (1<<27))    printf(" OSXSAVE");
    if (cx& (1<<28))    printf(" AVX");
    if (cx& (1<<29))    printf(" F16C");
    if (cx& (1<<30))    printf(" RDRND");
    if (cx& (1<<31))    printf(" HYPERVISOR");

    if (dx& (1<<04))    printf(" TSC");
    if (dx& (1<<29))    printf(" TM");
    if (dx& (1<<18))   printf(" PSN");// serial number
    if (dx& (1<<28))   printf(" HTT");
    cx =0;
int cache_line_size = ((bx>>8)& 0xFF)<<3;
int cpu_family_id = (ax>>8)&0xF;
int cpu_model_id  = (ax>>4)&0xF;
	cpu_model_id |= (cpu_family_id==6 || cpu_family_id==15)? (ax>>16<<4)&0xF0: 0;
	cpu_family_id+= (cpu_family_id==15)? ((ax>>20)&0xFF):0;
int avx10 = 0;
    if (cpuid_max_func>=0x7) {
        __cpuid_count(7,0, ax,bx,cx,dx);
    /*  CPUID.(EAX=07H, ECX=0H):EBX.AVX2[bit 5]==1
        CPUID.(EAX=07H, ECX=0H):EBX.BMI1[bit 3]==1
        CPUID.(EAX=07H, ECX=0H):EBX.BMI2[bit 8]==1  */
        if (bx& (1<<2))    printf(" SGX");
        if (bx& (1<<3))    printf(" BMI1");
        if (bx& (1<<4))    printf(" HLE");
        if (bx& (1<<5))    printf(" AVX2");
        if (bx& (1<<8))    printf(" BMI2");
        if (bx& (1<<9))    printf(" ERMS");
        if (bx& (1<<11))   printf(" RTM");
        if (bx& (1<<14))   printf(" MPX");
        if (bx& (1<<16))   printf(" AVX512F");
        if (bx& (1<<17))   printf(" AVX512DQ");
        if (bx& (1<<18))   printf(" RDSEED");
        if (bx& (1<<19))   printf(" ADX");
        if (bx& (1<<20))   printf(" SMAP");
        if (bx& (1<<21))   printf(" AVX512IFMA");
        if (bx& (1<<23))   printf(" CLFLUSHOPT");
        if (bx& (1<<26))   printf(" AVX512PF");
        if (bx& (1<<27))   printf(" AVX512ER");
        if (bx& (1<<28))   printf(" AVX512CD");
        if (bx& (1<<29))   printf(" SHA");
        if (bx& (1<<30))   printf(" AVX512BW");
        if (bx& (1<<31))   printf(" AVX512VL");
		
        if (cx& (1<< 1))   printf(" AVX512_VBMI"); // bit manipulation
        if (cx& (1<< 6))   printf(" AVX512_VBMI2"); // bit manipulation
        if (cx& (1<< 8))   printf(" GFNI"); // Galois Field 2^8
        if (cx& (1<< 9))   printf(" VAES"); //
        if (cx& (1<<10))   printf(" VPCLMULQDQ"); //
        if (cx& (1<<11))   printf(" AVX512_VNNI"); //
        if (cx& (1<<12))   printf(" AVX512_BITALG"); //
        if (cx& (1<<14))   printf(" AVX512_VPOPCNTDQ"); // bit manipulation
        if (cx& (1<<27))   printf(" MOVDIRI");
        if (cx& (1<<28))   printf(" MOVDIR64B");
        if (cx& (1<<29))   printf(" ENQCMD");
        if (dx& (1<<2))    printf(" AVX512_4VNNIW");
        if (dx& (1<<3))    printf(" AVX512_4FMAPS");
        if (dx& (1<<4))    printf(" FSRM");
        if (dx& (1<<14))   printf(" SERIALIZE");
        if (dx& (1<<15))   printf(" Hybrid");
        if (dx& (1<<16))   printf(" TSXLDTRK");
		if (dx& (1<<22))   printf(" AMX-BF16");
		if (dx& (1<<23))   printf(" AVX512-FP16");
		if (dx& (1<<24))   printf(" AMX-TILE");
		if (dx& (1<<25))   printf(" AMX-INT8");
		__cpuid_count(7,1, ax,bx,cx,dx);
		if (ax& (1<<0))    printf(" SHA512");
		if (ax& (1<<1))    printf(" SM3");
		if (ax& (1<<2))    printf(" SM4");
		if (ax& (1<<3))    printf(" RAO-INT");
		if (ax& (1<<4))    printf(" AVX-VNNI");
		if (ax& (1<<5))    printf(" AVX512_BF16");
		if (ax& (1<<21))   printf(" AMX-FP16");
		if (ax& (1<<23))   printf(" AVX-IFMA");
		if (dx& (1<<4))    printf(" AVX-VNNI-INT8");
		if (dx& (1<<4))    printf(" AMX-COMPLEX");
		if (dx& (1<<10))   printf(" AVX-VNNI-INT16");
		if (dx& (1<<19))   {
			printf(" AVX10");
			avx10 = 1;
		}
    }
    /* CPUID.(EAX=80000001H):ECX.LZCNT[bit 5]==1 */
    __cpuid(0x80000001, ax,bx,cx,dx);
    if (cx& (1<< 5))    printf(" ABM"); // advansed bit manipulation
    if (cx& (1<< 6))    printf(" SSE4a");
    if (cx& (1<<21))    printf(" TBM");
    if (dx& (1<< 4))    printf(" TSC");// timestamp
    if (dx& (1<<15))    printf(" CMOV");
    if (dx& (1<<23))    printf(" MMX");
    if (dx& (1<<31))    printf(" 3DNOW");


    printf("\n");
	if (avx10) {
		__cpuid_count(0x24,0, ax,bx,cx,dx);
		printf(" AVX10 Version=%d\n", bx&0xFF);
		//__cpuid_count(0x24,1, ax,bx,cx,dx);
	}
	
    if (cpuid_max_func >= 0x6)
    {// EAX=80000006h: Extended L2 Cache Features
		__cpuid(0x80000006, ax,bx,cx,dx);
		printf("Line size: %d B, Assoc. Type: %d; Cache Size: %d KB.\n", cx & 0xff, (cx >> 12) & 0x07, (cx >> 16) & 0xffff);
		printf("Cache line size: %d B\n", cache_line_size);

	}
    if (cpuid_max_func >= 0xB) // для новых процессоров Intel, для AMD другой метод
    {
        __cpuid_count(0xB, 0, ax,bx,cx,dx); // треды
        printf("Threads per core: %d\n", bx&0xFFFF);
        __cpuid_count(0xB, 1, ax,bx,cx,dx); // ядры
        printf("Logical processors: %d\n", bx&0xFFFF);
    } else
    if (cpuid_max_func >= 0x4) {
        int i;
        for(i=0;i<1; i++)
        {
            __cpuid_count(0x4, i, ax,bx,cx,dx); // треды
            if ((ax&0xF)==0) break;
            printf("Logical processors: %d threads per core: %d\n", /*(ax>>0)&0xF, */((ax>>26)&0x3F)+1, ((ax>>14)&0xFFF)+1);
        }
    }
#ifdef TEST_CPUID
	char *cpu_model_name="";
	if(cpu_family_id==6){
		switch (cpu_model_id){
		case 0x2A: 	cpu_model_name="Sandy Bridge"; break;
		case 0x2D: 	cpu_model_name="Sandy Bridge-E (Server)"; break;
		case 0x36: 	cpu_model_name="Cedar Trail 32nm"; break;
		case 0x37: 	cpu_model_name="Bay Trail"; break;
		case 0x3A: 	cpu_model_name="Ivy Bridge"; break;
		case 0x3C: 	cpu_model_name="Haswell-S"; break;
		case 0x3E: 	cpu_model_name="Ivy Bridge-E (Server)"; break;
		case 0x3F: 	cpu_model_name="Haswell-E (Server)"; break;
		case 0x4E: 	cpu_model_name="Skylake-U/Y"; break; 	
		case 0x55: 	cpu_model_name="Skylake (Server)"; break;
		case 0x45:	
		case 0x46:	cpu_model_name="Haswell"; break;
		case 0x47:	cpu_model_name="Broadwell"; break;
		case 0x4C:	cpu_model_name="Airmont"; break;
		case 0x4F:
		case 0x56: 	cpu_model_name="Broadwell (Server)"; break;
		case 0x57: 	cpu_model_name="Knights Landing"; break;
		case 0x5C: 	cpu_model_name="Apollo Lake"; break;
		case 0x5D: 	cpu_model_name="Silvermont"; break;
		case 0x5E: 	cpu_model_name="Skylake"; break;
		case 0x5F: 	cpu_model_name="Goldmont"; break;
		case 0x66: 	cpu_model_name="Cannon Lake"; break;
		case 0x6A: 	
		case 0x6C: 	cpu_model_name="Ice Lake (Server)"; break;
		case 0x7A: 	cpu_model_name="Gemini Lake"; break;
		case 0x7E:  cpu_model_name="Ice Lake-U/Y"; break;
		case 0x7D: 	cpu_model_name="Ice Lake"; break;
		case 0x85: 	cpu_model_name="Knights Mill"; break;
		case 0x86: 	cpu_model_name="Tremont"; break;
		case 0x8A: 	cpu_model_name="Tremont Lakefield"; break;
		case 0x8C: 	cpu_model_name="Tiger Lake-U"; break;
		case 0x8D: 	cpu_model_name="Tiger Lake-H"; break;
		case 0x8E: 	cpu_model_name="Kaby Lake"; break;
		case 0x8F: 	cpu_model_name="Sapphire Rapids Server"; break;
		
		case 0x96: 	cpu_model_name="Elkhart Lake"; break;
		case 0x97: 	cpu_model_name="Alder Lake-S"; break;
		case 0x9A: 	cpu_model_name="Alder Lake"; break;
		case 0x9C: 	cpu_model_name="Jasper Lake"; break;
		case 0x9E: 	cpu_model_name="Kaby Lake"; break;
		case 0xA5: 	cpu_model_name="Comet Lake"; break;
		case 0xA7: 	cpu_model_name="Rocket Lake"; break;
		case 0xAA: 	cpu_model_name="Meteor Lake"; break;
		case 0xAD: 	cpu_model_name="Granite Rapids"; break;
		case 0xAE: 	cpu_model_name="Granite Rapids"; break;
		case 0xAF: 	cpu_model_name="Sierra Forest"; break;
		case 0xB6: 	cpu_model_name="Grand Ridge"; break;
		case 0xB7: 	cpu_model_name="Raptor Lake-S"; break;
		case 0xBA: 	cpu_model_name="Raptor Lake"; break;
		case 0xBD: 	cpu_model_name="Lunar Lake"; break;
		case 0xBF: 	cpu_model_name="Raptor Lake"; break;
		case 0xC5: 	cpu_model_name="Arrow Lake"; break;
		case 0xC6: 	cpu_model_name="Arrow Lake"; break;
		case 0xCC: 	cpu_model_name="Panther Lake"; break;
		case 0xCF: 	cpu_model_name="Emerald Rapids Server"; break;
		case 0xDD: 	cpu_model_name="Clearwater Forest"; break;
		
		default: 	cpu_model_name=""; break;
		}
	} else 
	if (cpu_family_id==0x17){
		switch (cpu_model_id){
		case 0x31: 	cpu_model_name="Rome"; break;
		default:	cpu_model_name="Zen 1/2"; break;
		}
	} else 
	if (cpu_family_id==0x19){
		switch (cpu_model_id){
		case 0x00: 	cpu_model_name="Genesis Zen3"; break;
		case 0x01: 	cpu_model_name="Milan Zen3"; break;// EPYC 7003
		case 0x21: 	cpu_model_name="Veerner Zen3"; break;
		case 0x31: 	cpu_model_name="Genoa Zen3"; break;// EPYC 9004
		case 0x61: 	cpu_model_name="Raphael Zen4"; break;
		default:	cpu_model_name="Zen 3/4"; break;
		}
	}
	if (cpu_family_id==0x1A){
		cpu_model_name="Zen 5";
	}
		
	printf("cpuid = %02X_%02X %s\n", cpu_family_id, cpu_model_id, cpu_model_name);
#endif
}
#ifdef TEST_CPUID
int main()
{
    return 0;
}
#endif
