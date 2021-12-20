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
use Content::File;




################################################################################
#
MAIN:
#
################################################################################
{
	my $file = shift;
	die "You must specify the name of the file to write the directory list to\n" if ( ! $file );

	open( OUTPUT, ">$file" ) or die "Unable to open output file $file: $!\n";

    	# Process the directory
     	opendir DIR, ".";

     	my $file_counter = 0;
     	while ( my $file = readdir( DIR ) )
          {
             # Skip subdirectories
             next if ( $file eq '.' );
            next if ( $file eq '..' );

	     my $url = $file;
	     $url = &CleanUrl( $url );
             next if ( ! $url );

	     print OUTPUT "$url\n";
	     $file_counter++;
       }

	close( DIR );

	close( OUTPUT );

	print "Wrote $file_counter directory names to $file\n";

     exit( 0 );
}




sub lines( $ )
{
	my $filename = shift;
	return if ( ! $filename );

	open INPUT, "<$filename";

	my $counter = 0;

	while (<INPUT>)
	{
	   $counter++;
	}

	close INPUT;

	print "$filename has $counter lines\n";
}



__END__

:endofperl
