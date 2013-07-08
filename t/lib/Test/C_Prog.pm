package Test::C_Prog;
use strict;
use warnings;
use Exporter 'import';
use Test::More;
use Try::Tiny;

our @EXPORT= ( 'ok_c_prog', 'blob_diff' );
our @EXPORT_OK= ( 'slurp', 'hexdump', 'exitreason', 'compile_c_prog', 'run_test_prog' );

sub exitreason {
	my $code= shift;
	return $code == -1? "(can't execute)"
		: ($code & 127)? "(signal ".($code & 127).")"
		: "(exit value ".($code>>8).")";
}

sub slurp {
	my $fname= shift;
	open my $fh, "<", $fname or die "open($fname): $!";
	local $/= undef;
	scalar <$fh>;
}

sub compile_c_prog {
	my ($c_code, $bin_fname)= @_;
	my $fh;
	open($fh, ">", "tmp/test.c")
		and (print $fh $c_code)
		and (close $fh)
		or die "Can't write tmp/test.c\n";
	my $compile_err= `cc -o "$bin_fname" -I . -I .. tmp/test.c -L . -lcirculog -lrt 2>&1`;
	if ($? != 0) {
		diag $compile_err if $compile_err =~ /\S/;
		die "compile failed ".exitreason($?)."\n";
	}
	return 1;
}

sub run_test_prog {
	my $bin_fname= shift;
	my @args=  @{shift @_} if @_ > 0 and ref $_[0] eq 'ARRAY';
	my %env=   %{shift @_} if @_ > 0 and ref $_[0] eq 'HASH';
	my $output= `"$bin_fname" @args 2>&1`;
	if ($? != 0) {
		diag $output;
		die "execution failed ".exitreason($?)."\n";
	}
	return 1;
}

sub ok_c_prog {
	my $c_code= shift;
	my @args=  @{shift @_} if @_ > 0 and ref $_[0] eq 'ARRAY';
	my %env=   %{shift @_} if @_ > 0 and ref $_[0] eq 'HASH';
	my $comment= shift @_  if @_ > 0 and !ref $_[0];
	
	my $err= try {
		compile_c_prog($c_code, "tmp/test");
		run_test_prog("tmp/test", \@args, \%env);
		undef;
	} catch { $_ };
	if ($err) {
		chomp($err);
		fail defined $comment? "$err: $comment" : $err;
		return '';
	} else {
		defined $comment? pass $comment : pass;
		return 1;
	}
}

sub hexdump {
	my $str= shift;
	join('', map { sprintf("%02x",ord($_)) } split //, $str)
}

sub blob_diff {
	my ($actual, $expected)= @_;
	my $i= 0;
	$i++ while substr($expected, $i, 1) eq substr($actual, $i, 1);
	my $expected_ctx= substr($expected, $i, 10);
	my $actual_ctx= substr($actual, $i, 10);
	if (($expected_ctx =~ /[\x00-\x19\x7f-\xff]/) || ($actual_ctx =~ /[\x00-\x19\x7f-\xff]/)) {
		$expected_ctx= hexdump($expected_ctx);
		$actual_ctx= hexdump($actual_ctx);
	}
	return "Difference at offset $i: \"$actual_ctx\" != \"$expected_ctx\"";
}

1;