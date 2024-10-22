#ifndef NET_H
#define NET_H

#include <stdint.h>
/* Преобразование порядка следования байт 
 из сетевого (network) в локальный (host) и наоборот

 \see POSIX <net.h>
 */

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
/*! \brief Преобразование network to host */
static inline uint64_t ntohll(uint64_t a){
    return __builtin_bswap64(a);// LE
}
/*! \brief Преобразование host to network */
static inline uint64_t htonll(uint64_t a){
    return __builtin_bswap64(a);// LE
}
/*! \brief Преобразование network to host */
static inline uint32_t ntohl (uint32_t a){
    return __builtin_bswap32(a);// LE
}
/*! \brief Преобразование host to network */
static inline uint32_t htonl (uint32_t a){
    return __builtin_bswap32(a);// LE
}
/*! \brief Преобразование network to host */
static inline uint16_t ntohs (uint16_t a){
    return __builtin_bswap16(a);// LE
}
/*! \brief Преобразование network to host */
static inline uint16_t htons (uint16_t a){
    return __builtin_bswap16(a);// LE
}
#else
static inline uint64_t htonll(uint64_t a){
    return (a);// BE
}
static inline uint64_t ntohll(uint64_t a){
    return (a);// BE
}
static inline uint32_t htonl (uint32_t a){
    return (a);// BE
}
static inline uint32_t ntohl (uint32_t a){
    return (a);// BE
}
static inline uint16_t htons (uint16_t a){
    return (a);// BE
}
static inline uint16_t ntohs (uint16_t a){
    return (a);// BE
}
#endif
#endif// NET_H