#! /usr/bin/env perl
use strict;
use warnings;
use Test::More;
BEGIN {
	-d 't'
		and -f 'Makefile'
		or BAIL_OUT "Please run from project build directory. (and make sure ./t and Makefile exist)";
	mkdir 'tmp';
}
use lib "t/lib";
use Test::C_Prog;

ok_c_prog( <<END , 'new' );
#include <circulog.h>
int main() {
	ccl_log_t *log= ccl_new();
	if (!log) return 2;
	return 0;
}
END

ok_c_prog( <<END , 'new + delete' );
#include <circulog.h>
int main() {
	ccl_log_t *log= ccl_new();
	if (!log) return 2;
	if (!ccl_delete(log)) return 3;
	return 0;
}
END

ok_c_prog( <<END , 'init on buffer' );
#include <circulog.h>
int main() {
	ccl_log_t log;
	if (!ccl_init(&log, sizeof(log))) return 2;
	return 0;
}
END

done_testing;