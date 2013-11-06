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

ok_c_prog("int main() { return 0; }", 'basic_c_prog')
	or BAIL_OUT("Unable to compile C programs");


subtest check_log_struct_size => sub { 
	ok_c_prog(<<'END', 'print_sizeof_log_public');
	#include "circulog.h"
	#include <stdio.h>
	int main() { 
		printf("%d", sizeof(ccl_log_t));
		return 0;
	}
END

	ok_c_prog(<<'END', 'print_sizeof_log_private');
	#include "libcirculog.h"
	#include <stdio.h>
	int main() {
		printf("%d", sizeof(ccl_log_t));
		return 0;
	}
END

	my $sizeof_log_pub= `./print_sizeof_log_public`;
	my $sizeof_log_priv= `./print_sizeof_log_private`;
	ok( $sizeof_log_pub >= $sizeof_log_priv, 'public log struct size is adequate' );
}

done_testing;