#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <assert.h>
#include <endian.h>

inline int64_t endian_swap_64(int64_t x) {
	x= ((x & 0xFFFFFFFFLL) << 32) | ((x >> 32) & 0xFFFFFFFFLL);
	x= ((x & 0xFFFF0000FFFFLL) << 16) | ((x >> 16) & 0xFFFF0000FFFFLL);
	return ((x & 0xFF00FF00FF00FFLL) << 8) | ((x >> 8) & 0xFF00FF00FF00FFLL);
}

void print_diff(char* name, int n, struct timespec *a, struct timespec *b) {
	double elapsed_s= (double)(b->tv_sec - a->tv_sec) + (b->tv_nsec - a->tv_nsec)/1000000000.0;
	printf("%-20s:\t%7.1lf ms (%7.3lf/sec)\n", name, elapsed_s*1000, n / elapsed_s);
}

int main(int argc, char **argv) {
	int i, x, n=1000000000;
	int64_t y;
	struct timespec start, end;
	
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i= 0; i < n; i++)
		y+= endian_swap_64(i);
	clock_gettime(CLOCK_MONOTONIC, &end);
	print_diff("endian_swap_64", i, &start, &end);
	
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i= 0; i < n; i++)
		y+= htobe64(i);
	clock_gettime(CLOCK_MONOTONIC, &end);
	print_diff("htobe64", i, &start, &end);
	
	// ensure values are used, to keep things form getting optimized out
	return x ^ (int)y;
}
