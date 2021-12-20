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





################################################################################
#
MAIN:
#
################################################################################
{
	my $item = shift;
	die "You must enter a directory name\n" if ( ! defined $item );

	my $cmd = shift;
	die "You must enter a command to execute\n" if ( ! defined $cmd );

	my $option;
	while ( $option = shift )
	  {  $cmd = $cmd . " " . $option;
	  }

	print "Execute $cmd for each file in directory $item\n";

     	# Process the directory
     	opendir DIR, $item;

     	my $file_counter = 0;
     	while ( my $file = readdir( DIR ) )
          {
             # Skip subdirectories
             next if (-d $file);

	     my $command = $cmd . " " . $file;

	     print "command = $command\n";

	     system $command;
         }

	close( DIR );

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
