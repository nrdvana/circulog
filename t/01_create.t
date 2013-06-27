#! /usr/bin/env perl
BEGIN {
	-d 't' and chdir('t') || die "can't chdir to 't'";
	-d 'tmp' or die "Please run from project root or ./t dir. (and make sure t/tmp exists)";
}
use strict;
use warnings;
use Test::More;
use lib "lib";
use Test::C_Prog;
ok_c_prog("int main() { return 0; }", 'empty C prog') or BAIL_OUT("Unable to compile C programs");

ok_c_prog( <<END , 'new' );
#include <circulog.h>
int main() {
	ccl_log_t *log= ccl_new();
	if (log) return 0;
	return 2;
}
END

ok_c_prog( <<END , 'new + delete' );
#include <circulog.h>
int main() {
	ccl_log_t *log= ccl_new();
	ccl_delete(log);
	return 2;
}
END

ok_c_prog( <<END , 'init on buffer');
#include <circulog.h>
int main() {
	ccl_log_t log;
	return ccl_init(&log, sizeof(log))? 0 : 2;
}
END

done_testing;