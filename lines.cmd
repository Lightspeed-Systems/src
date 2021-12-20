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

	die "You must enter a file name or a directory name\n" if ( ! $item );

	if ( ! -d $item )
		{  &lines( $item );
		   exit( 0 );
		}


     # Process the directory
     opendir DIR, $item;

     my $file_counter = 0;
     my $total = 0 + 0;
     while ( my $file = readdir( DIR ) )
        {
             # Skip subdirectories
             next if (-d $file);

	     $total += &lines( $file );
         }

	close( DIR );

     print "Total lines for all files = $total\n";

     exit( 0 );
}




sub lines( $ )
{
	my $filename = shift;
	return if ( ! $filename );

	open( INPUT, "<$filename" ) or die( "Unable to open file $filename: $!\n" );

	my $counter = 0;

	while (<INPUT>)
	{
	   $counter++;
	}

	close INPUT;

	print "$filename has $counter lines\n";

	return( $counter );
}



__END__

:endofperl
