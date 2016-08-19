use strict;
use Data::Dumper;

my $save_dir = '/root/Desktop/pentest/tools/skzproxy/findings/';

open IN, "<$save_dir"."username_attacks";
my @lines = <IN>;
close IN;

my $all_lines = join " ", @lines;

my @all_hex_strings = $all_lines =~ /0000 (.*?)\n/gm;

while ( my $hstr = shift @all_hex_strings )
{
	hex_string_proc( $hstr, (shift @all_hex_strings) );
}

sub hex_string_proc
{
	my $str = shift;
	my $str2 = shift;
	
	my @bytes_user = $str =~ /\b([\da-f]{2})\b/gi;
	my @bytes_vals = $str2 =~ /\b([\da-f]{2})\b/gi;
	
	my $user_name = $bytes_user[4]." ".$bytes_user[5];
	my $balance =  $bytes_vals[6].$bytes_vals[7];
	
	
	my $cmd = "hURL --nocolor -s -i $balance";
	#my $balance_int = `$cmd`;
	print "$user_name \n";#-> $balance_int\n";
	
}	