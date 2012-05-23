#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>

inline int64_t abs64(int64_t x) { return x > 0? x : -x; }

int main() {
	int shift= 0;
	int mismatch, roundup, rounddown, approx_roundup, approx_rounddown;
	int i, fail, lastNsec= 0;
	long long mul, add, min, max, best, best_rounddiff;
	for (shift= 45; shift <= 62; shift++) {
		mul= (1LL<<shift)/1000000000;
		min= 7629*mul;
		max= 7630*mul;
		//min= 499996000;
		//max= 500004000;
		best_rounddiff= 0x7FFFFFFF;
		while (max>min) {
			mismatch= roundup= rounddown= approx_roundup= approx_rounddown= 0;
			fail= 0;
			if (add == (min+max>>1))
				min++;
			add= (min+max)>>1;
			
			for (i=0; i<1000000000; i++) {
				long long frac= (((long long)i<<16)+499999743)/1000000000L;
				int nsec= (int)((frac * 1000000000)+0x8000 >> 16);
				if (nsec > i) roundup++;
				else if (nsec < i) rounddown++;
				
				long long frac_approx= (i*mul + add) >> (shift-16);
				int nsec_approx= (int)((frac_approx * 1000000000)+0x8000 >> 16);
				if (nsec_approx > i) approx_roundup++;
				else if (nsec_approx < i) approx_rounddown++;
				
				if (nsec != nsec_approx) ++mismatch;
				//	printf("\t%d != %d", nsec, nsec2);
				//if (lastNsec != nsec) {
				//	printf("\n%d:\n", nsec);
				//	lastNsec= nsec;
				//}
				//printf("\ti=%d", i);
				
			}
			printf("\tadd=%lld, diff=%lld, up-down=%d", add, max-min, approx_roundup-approx_rounddown);
			fflush(stdout);
			if (approx_roundup == approx_rounddown) {
				best= add;
				break;
			}
			
			if (abs64(approx_roundup - approx_rounddown) < best_rounddiff) {
				best= add;
				best_rounddiff= abs64(approx_roundup - approx_rounddown);
			}
			
			if (approx_roundup > approx_rounddown) {
				max= add;
			} else {
				min= add;
			}
		}
		printf("\nshift=%2d %10lld %13lld: %5d mismatches %9dup %9ddn | %9dup %9ddn\n",
			shift, mul, best, mismatch, roundup, rounddown, approx_roundup, approx_rounddown);
	}
}
