package Test::C_Prog;
use strict;
use warnings;
use Exporter 'import';
use Test::More;

our @EXPORT= ( 'ok_c_prog' );

sub ok_c_prog {
	my $c_code= shift;
	my @args=  @{shift @_} if @_ > 0 and ref $_[0] eq 'ARRAY';
	my %env=   %{shift @_} if @_ > 0 and ref $_[0] eq 'HASH';
	my $comment= shift @_  if @_ > 0 and !ref $_[0];
	
	my $fh;
	open($fh, ">", "tmp/test.c")
		and (print $fh $c_code)
		and (close $fh)
		or die "Can't write tmp/test.c\n";
	my $compile_err= `cc -o tmp/test -I .. tmp/test.c -L../build -lcirculog -lrt 2>&1`;
	if ($? != 0) {
		diag $compile_err if $compile_err =~ /\S/;
		return fail "compile failed: $comment";
	}
	my $output= `tmp/test @args 2>&1`;
	if ($? != 0) {
		diag $output;
		return fail "execution failed: $comment";
	}
	pass $comment;
}

1;