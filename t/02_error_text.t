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
use Test::C_Prog 'compile_c_prog', 'slurp', 'exitreason';

compile_c_prog( <<'END' , 'tmp/print_err' ) or BAIL_OUT;
#include "config.h"
#include <circulog_internal.h>
#include <stdio.h>
int main(int argc, char **argv) {
	ccl_log_t *log= ccl_new();
	if (argc < 2) return 1;
	if (!log) return 2;
	log->last_errno= 0;
	log->last_errmsg= argv[1];
	char buf[64];
	int count= ccl_err_text(log, buf, sizeof(buf));
	int bufferless_count= ccl_err_text(log, NULL, 0);
	printf("%s\n%d\n%d\n", buf, count, bufferless_count);
	return 0;
}
END

my @tests= (
	[ 'Testing', 'Testing' ],
	[ 'Testing $logfile', 'Testing log file' ],
	[ 'Testing $logfile: $syserr', 'Testing log file: Success' ],
);

for (@tests) {
	my ($msg, $expected)= @$_;
	subtest $msg => sub {
		my $escaped_msg= $msg;
		$escaped_msg =~ s/\$/\\\$/g;
		print $escaped_msg."\n";
		my @result= `tmp/print_err "$escaped_msg"`;
		if ($?) {
			fail "print_err failed ".exitreason($?);
		}
		else {
			pass "print_err";
			chomp(@result);
			my ($text, $strlen, $bufferless_strlen)= @result;
			is( $text, $expected, 'text' );
			is( $strlen, length($expected), 'text len' );
			is( $bufferless_strlen, length($expected), 'bufferless text len' );
		}
		done_testing;
	};
}

done_testing;