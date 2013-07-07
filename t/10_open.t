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
use JSON::PP;

compile_c_prog( <<END , 'tmp/read_specs' ) or BAIL_OUT;
#include "config.h"
#include <circulog_internal.h>
#include <stdio.h>
int main(int argc, char **argv) {
	ccl_log_t *log= ccl_new();
	if (argc < 2) return 1;
	if (!log) return 2;
	if (!ccl_open(log, argv[1], CCL_READ)) {
		char buf[1024];
		ccl_err_text(log, buf, sizeof(buf));
		fputs(buf, stderr);
		return 3;
	}
	
	printf("{");
	
	printf("'version': %d, ", (unsigned int) log->version);
	printf("'header_size': %d, ", (unsigned int) log->header_size);
	printf("'timestamp_precision': %d, ", (unsigned int) log->timestamp_precision);
	printf("'timestamp_epoch': %d, ", (unsigned int) log->timestamp_epoch);
	printf("'index_start': %d, ", (unsigned int) log->index_start);
	printf("'index_size': %d, ", (unsigned int) log->index_size);
	printf("'spool_start': %d, ", (unsigned int) log->spool_start);
	printf("'spool_size': %d, ", (unsigned int) log->spool_size);
	printf("'max_message_size': %d", (unsigned int) log->max_message_size);
	
	printf("}");
	
	if (!ccl_delete(log)) return 4;
	return 0;
}
END

my $jsoncoder= JSON::PP->new->relaxed->allow_singlequote;
for (qw: example01 :) {
	subtest $_ => sub {
		my ($statsfile, $logfile)= ("t/10_open/$_.json", "t/10_open/$_.ccl");
		-f $statsfile or die "No such example log specs: $_";
		-f $logfile or die "No such example log: $_";
		my $specs= $jsoncoder->decode(slurp($statsfile));
		my $actual_json= `tmp/read_specs "$logfile" 2>&1`;
		if ($?) {
			fail "read_specs failed ".exitreason($?);
			diag $actual_json;
		}
		else {
			pass "read_specs";
			my $actual= $jsoncoder->decode($actual_json);
			is_deeply( $actual, $specs )
				or diag $actual_json;
		}
		done_testing;
	};
}

done_testing;