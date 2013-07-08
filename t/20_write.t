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
	if (ccl_init_timestamp_params(log, 0, 32)
		&& ccl_init_geometry_params(log, 4096, false, 100)
		&& ccl_open(log, "tmp/testlog.ccl", CCL_CREATE|CCL_WRITE)
		&& ccl_write_str(log, "Hello World", 1)
		&& ccl_delete(log))
		return 0;
	
	char buf[1024];
	puts(ccl_err_text(log, buf, sizeof(buf)));
	return 5;
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
		.pack("V",72) # header size
		.pack("V",32) # timestamp precision
		.pack("VV",0,0) # timestamp epoch
		.pack("VV",72,0) # index start
		.pack("VV",0,0) # index size
		.pack("VV",4096,0) # spool start
		.pack("VV",4096,0) # spool size
		.pack("V", 100) # max_message_size
		.pack("V", 0) # reserved
		.("\0" x (4096-72)) # alignment
		# spool data
		."\x16Hello World\0\0\0\x16" # sizecode message padding sizecode
		.pack("VV",1,0) # timestamp
		.pack("VV", 0x691C3A62, 0x1A690D3A) # checksum(address=4096,timestamp=1,messagelen=11) => 0x1A690D3A691C3A62
		.("\0" x (4096 - 4*8));
	length($expected) == $expected_size or die "Constant has wrong length";
	local $/= undef;
	open(my $fh, "<", "tmp/testlog.ccl") or die "$!";
	my $content= <$fh>;
	is( $content, $expected, 'log contents' )
		or diag blob_diff($content, $expected);
};

done_testing;