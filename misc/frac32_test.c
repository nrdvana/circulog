#define CCL_NSEC_TO_FRAC32(nsec) (((nsec) * ((1LL<<62)/1000000000)) >> 30)
#define CCL_FRAC32_TO_NSEC(frac) ((int) (((frac) * 1000000000LL + 0x80000000) >> 32))

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>

inline int64_t abs64(int64_t x) { return x > 0? x : -x; }

int main() {
	int mismatch= 0, i, oob= 0;
	for (i=0; i<1000000000; i++) {
		int64_t frac= CCL_NSEC_TO_FRAC32(i);
		int nsec= CCL_FRAC32_TO_NSEC(frac);
		if (i != nsec) mismatch++;
		if (frac >> 32) oob++;
	}
	printf("Mismatches: %d\n"
		"Out of Bounds: %d\n"
		"last roundup: %d\n",
		mismatch, oob, CCL_FRAC32_TO_NSEC(0xFFFFFFFF));
	return mismatch > 0;
}