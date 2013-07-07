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

unlink("tmp/testlog.ccl");
ok_c_prog( <<END , 'create from scratch' )
#include <circulog.h>
#include <stdio.h>
int main() {
	ccl_log_t *log= ccl_new();
	if (!log) return 2;
	if (!ccl_init_timestamp_params(log, 0, 32)) return 3;
	if (!ccl_init_geometry_params(log, 4096, false, 100)) return 4;
	if (!ccl_open(log, "tmp/testlog.ccl", CCL_CREATE|CCL_WRITE)) {
		char buf[1024];
		puts(ccl_err_text(log, buf, sizeof(buf)));
		return 5;
	}
	if (!ccl_delete(log)) return 6;
	return 0;
}
END
and do {
	# test binary contents of file
	my $expected_size= 4096*2; # two pages (this test should consult the system page size)
	is( -s "tmp/testlog.ccl", $expected_size, 'log size' );
	
	my $expected=
		"CircuLog" # magic
		.pack("V",0) # version
		.pack("V",0) # oldest compat version
		.pack("V",64) # header size
		.pack("V",32) # timestamp precision
		.pack("VV",0,0) # timestamp epoch
		.pack("VV",64,0) # index start
		.pack("VV",0,0) # index size
		.pack("VV",4096,0) # spool start
		.pack("VV",4096,0) # spool size
		.("\0" x (4096-64)) # alignment
		.("\0" x 4096);     # spool data
	length($expected) == $expected_size or die "Constant has wrong length";
	local $/= undef;
	open(my $fh, "<", "tmp/testlog.ccl") or die "$!";
	my $content= <$fh>;
	is( $content, $expected, 'log contents' )
		or diag blob_diff($content, $expected);
};

done_testing;