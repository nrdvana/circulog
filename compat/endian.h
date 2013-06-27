#ifndef CUSTOM_ENDIAN_H
#define CUSTOM_ENDIAN_H

#include <stdint.h>

inline int16_t endian_swap_16(int16_t x) {
	return (x << 8) | ((x >> 8) & 0xFF);
}

inline int32_t endian_swap_32(int32_t x) {
	x= ((x & 0xFFFF) << 16) | ((x >> 16) & 0xFFFF);
	return ((x & 0xFF00FF) << 8) | ((x >> 8) & 0xFF00FF);
}

inline int64_t endian_swap_64(int64_t x) {
	x= ((x & 0xFFFFFFFFLL) << 32) | ((x >> 32) & 0xFFFFFFFFLL);
	x= ((x & 0xFFFF0000FFFFLL) << 16) | ((x >> 16) & 0xFFFF0000FFFFLL);
	return ((x & 0xFF00FF00FF00FFLL) << 8) | ((x >> 8) & 0xFF00FF00FF00FFLL);
}

#define CUSTOM_ENDIAN_LITTLE_ENDIAN 0x41424344UL 
#define CUSTOM_ENDIAN_BIG_ENDIAN    0x44434241UL
#define CUSTOM_ENDIAN_TARGET_ENDIAN ('ABCD')

#ifdef CUSTOM_ENDIAN_TARGET_ENDIAN == CUSTOM_ENDIAN_BIG_ENDIAN
#define htobe16(x) (x)
#define htobe32(x) (x)
#define htobe64(x) (x)
#define be16toh(x) (x)
#define be32toh(x) (x)
#define be64toh(x) (x)
#define htole16(x) endian_swap_16(x)
#define htole32(x) endian_swap_32(x)
#define htole64(x) endian_swap_64(x)
#define le16toh(x) endian_swap_16(x)
#define le32toh(x) endian_swap_32(x)
#define le64toh(x) endian_swap_64(x)
#else
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#define htobe16(x) endian_swap_16(x)
#define htobe32(x) endian_swap_32(x)
#define htobe64(x) endian_swap_64(x)
#define be16toh(x) endian_swap_16(x)
#define be32toh(x) endian_swap_32(x)
#define be64toh(x) endian_swap_64(x)
#endif

#endif