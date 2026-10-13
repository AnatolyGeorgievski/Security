#ifndef CRC_H_INCLUDED
#define CRC_H_INCLUDED
#include <inttypes.h>

#define ADLER32_ENABLE
#undef  CRC32_ENABLE
#define CRC32B_ENABLE
#undef  CRC32K_ENABLE
#undef  CRC32C_ENABLE
#define CRC16_ENABLE
#define CRC16B_ENABLE
#define CRC16_MODBUS_ENABLE

#define CRC16_MASK 0xFFFF
#define CRC32_MASK 0xFFFFFFFF
#define POLY16	0x1021
#define POLY16B	0x1081
/* POLY16B - это не полином, это коэффициент, который получается в результате применения
 полинома 0x8408
SDLC USB MODBUS	CRC-16-IBM 0x8005 or 0xA001
FCS [16 bits] = X16 + X15 + X2 + 1

HDLC FCS Field	CRC-16-CCITT 0x1021   0x04C11DB7
FCS [16 bits] = X16 + X12 + X5 + 1
FCS [32 bits] = X32 + X26 + X23 + X22 + X16 + X12 + X11 + X10 + X8 + X7 + X5 + X4 + X2 + X + 1

*/
typedef uint16_t CRC16;
typedef uint32_t CRC32;
typedef uint64_t CRC64;
typedef uint32_t HASH32;

extern CRC16    CRC16B_update(CRC16 crc, unsigned char c);
extern CRC16	CRC16_update(CRC16 crc, unsigned char c);
//extern CRC16 CRC16_init(void);
//extern CRC16 CRC16_finalize(CRC16 crc);

extern HASH32 ADLER32_update(HASH32 adler, void *p, int len);

//extern CRC32 CRC32_init(CRC32 crc);
//extern CRC32 CRC32_finalize(CRC32 crc);
extern CRC32 CRC32_update(CRC32 CRC, unsigned char val);
extern CRC32 CRC32B_update(CRC32 CRC, unsigned char val);
extern CRC32 crc_from_block(CRC32 crc, unsigned char *buffer, int size);
#if defined CRC16_ENABLE || defined CRC16B_ENABLE
static inline
CRC16	CRC16_init(){
	return CRC16_MASK;
}
static inline
CRC16	CRC16_finalize(CRC16 crc){
	return  (~crc) & CRC16_MASK;
}
#endif
#if defined CRC32_ENABLE || defined CRC32B_ENABLE
static inline
CRC32 CRC32_init(CRC32 crc){
	return (~crc)& CRC32_MASK;
}
static inline
CRC32 CRC32_finalize(CRC32 crc){
	return (~crc) & CRC32_MASK;
}
#endif

#if 0//def CRC16_MODBUS_ENABLE
extern CRC16 CRC16M_Lookup4[16];

static inline CRC16 modbus_crc16_update_inline(CRC16 crc, unsigned char val)
{
	crc = (crc>>4) ^ CRC16M_Lookup4[(crc ^ (val   )) & 0xF];
	crc = (crc>>4) ^ CRC16M_Lookup4[(crc ^ (val>>4)) & 0xF];
	return crc;
}

CRC16 modbus_crc16_update(CRC16 crc, unsigned char val);
#endif

unsigned short ip_standard_cksum(unsigned int acc, void *data, unsigned int len);
#endif// CRC_H_INCLUDED
