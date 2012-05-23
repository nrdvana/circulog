#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <assert.h>

inline int64_t endian_swap_32(int32_t x) {
	union {
		int32_t l;
		char c[4];
	} u;
	u.l= x;
	u.c[0] ^= u.c[3];
	u.c[3] ^= u.c[0];
	u.c[0] ^= u.c[3];
	u.c[1] ^= u.c[2];
	u.c[2] ^= u.c[1];
	u.c[1] ^= u.c[2];
	return u.l;
}
inline int64_t endian_swap_64(int64_t x) {
	union {
		int64_t ll;
		char c[8];
	} u;
	u.ll= x;
	u.c[0] ^= u.c[7];
	u.c[7] ^= u.c[0];
	u.c[0] ^= u.c[7];
	u.c[1] ^= u.c[6];
	u.c[6] ^= u.c[1];
	u.c[1] ^= u.c[6];
	u.c[2] ^= u.c[5];
	u.c[5] ^= u.c[2];
	u.c[2] ^= u.c[5];
	u.c[3] ^= u.c[4];
	u.c[4] ^= u.c[3];
	u.c[3] ^= u.c[4];
	return u.ll;
}

inline int32_t endian_swap_32_2(int32_t x) {
	x= ((x & 0xFFFF) << 16) | ((x >> 16) & 0xFFFF);
	return ((x & 0xFF00FF) << 8) | ((x >> 8) & 0xFF00FF);
}

inline int64_t endian_swap_64_2(int64_t x) {
	x= ((x & 0xFFFFFFFFLL) << 32) | ((x >> 32) & 0xFFFFFFFFLL);
	x= ((x & 0xFFFF0000FFFFLL) << 16) | ((x >> 16) & 0xFFFF0000FFFFLL);
	return ((x & 0xFF00FF00FF00FFLL) << 8) | ((x >> 8) & 0xFF00FF00FF00FFLL);
}

void print_diff(char* name, int n, struct timespec *a, struct timespec *b) {
	double elapsed_s= (double)(b->tv_sec - a->tv_sec) + (b->tv_nsec - a->tv_nsec)/1000000000.0;
	printf("%-20s:\t%7.1lf ms (%7.3lf/sec)\n", name, elapsed_s*1000, n / elapsed_s);
}

int main(int argc, char **argv) {
	int i;
	struct timespec start, end;
	/*
	for (i=0; i < 1000000000; i+= 7) {
		assert(endian_swap_32(i) == endian_swap_32_2(i));
		assert(endian_swap_64(i) == endian_swap_64_2(i));
	}
	*/
	
	int n= atoi(argv[1]);
	int x= 0;
	int y= 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i= 0; i < n; i++)
		x+= endian_swap_32(i);
	clock_gettime(CLOCK_MONOTONIC, &end);
	print_diff("endian_swap_32", i, &start, &end);

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i= 0; i < n; i++)
		x+= endian_swap_32_2(i);
	clock_gettime(CLOCK_MONOTONIC, &end);
	print_diff("endian_swap_32_2", i, &start, &end);

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i= 0; i < n; i++)
		y+= endian_swap_64(i);
	clock_gettime(CLOCK_MONOTONIC, &end);
	print_diff("endian_swap_64", i, &start, &end);

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i= 0; i < n; i++)
		y+= endian_swap_64_2(i);
	clock_gettime(CLOCK_MONOTONIC, &end);
	print_diff("endian_swap_64_2", i, &start, &end);
	
	// ensure values are used, to keep things form getting optimized out
	return x ^ (int)y;
}
