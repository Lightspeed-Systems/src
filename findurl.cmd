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

use MIME::Base64;




################################################################################
#
MAIN:
#
################################################################################
{
	my $item = shift;
	my $url = shift;

	die "You must enter a file name and a URL\n" if ( ( ! $item )  ||  ( ! $url ) );

	print "Searching file $item for $url ...\n";

	&findurl( $item, $url );
   
	exit( 0 );
}




sub findurl( $$ )
{
	my $filename = shift;
	my $url = shift;

	return if ( ! $filename );

	$url = lc( $url );

	$url = quotemeta( $url );

	open INPUT, "<$filename" or die "Unable to open file $filename: $!\n";

	my $counter = 0;

	while (<INPUT>)
		{	chomp;
			next if ( ! $_ );
	   		$counter++;
			my $check_url = lc( $_ );
			
			print "found $url on line $counter - $check_url\n" if ( $check_url =~ m/$url/ );
		}

	close INPUT;

	print "$filename has $counter lines\n";

	return( $counter );
}



__END__

:endofperl
