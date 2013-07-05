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

my $out= `make libcirculog 2>&1`;
if ($?) {
	diag $out;
	BAIL_OUT("failed to build libcirculog");
}

ok_c_prog("int main() { return 0; }", 'empty C prog') or BAIL_OUT("Unable to compile C programs");

done_testing;