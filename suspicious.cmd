@rem = '--*-Perl-*--
@echo off
if "%OS%" == "Windows_NT" goto WinNT
perl -x -S "%0" %1 %2 %3 %4 %5 %6 %7 %8 %9
goto endofperl
:WinNT
perl -x -S %0 %*
if NOT "%COMSPEC%" == "%SystemRoot%\system32\cmd.exe" goto endofperl
if %errorlevel% == 9009 echo You do not have Perl in your PATH.
if errorlevel 1 goto script_failed_so_exit_with_non_zero_val 2>nul
goto endofperl
@rem ';

################################################################################
#!perl -w


# Pragmas
use strict;
use Socket;

use Content::File;


################################################################################
#
MAIN:
#
################################################################################
{
	my $input_file = shift;
	my $output_file = shift;
	$output_file = "domains.suspicious" if ( ! $output_file );
	
	my $counter = 0 + 0;
	my $out_counter = 0 + 0;

	if ( ! open INFILE, "<$input_file" )
		{	print "Cannot open input file $input_file: $!\n";
			return( undef );	
		}
		
	if ( ! open OUTFILE, ">>$output_file" )
		{	print "Cannot open output file $output_file: $!\n";
			return( undef );	
		}
	while (<INFILE>)
		{
			chomp;
           			next if (!length);  #  Ignore empty lines
			next if /^#/;  #  Skip comments
			next if /^\s*(#|$)/;

			my $new_url = $_;
			next if ( ! $new_url );
	
			$counter++;
		   
			 if  ( &SuspiciousUrl( $new_url ) )
		   		{	print "$new_url\n";
					print OUTFILE "$new_url\n";
					$out_counter++;
				}
		}

	close INFILE;
	close OUTFILE;

	print "Read in $counter URLs from file $input_file\n";
	print "Wrote out $out_counter suspicious URLs to file $output_file\n";

	exit;
}


__END__

:endofperl
