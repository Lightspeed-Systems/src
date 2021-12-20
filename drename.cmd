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
use warnings;
use strict;

use Cwd;




################################################################################
#
MAIN:
#
################################################################################
{
	my $item = shift;

	die "You must enter a file name to directory rename\n" if ( ! $item );
	die "File $item not found\n" if ( ! -e $item );

	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;

	my @parts = split /\\/, $dir;

	my $last_dir = $parts[ $#parts ];

	my $new_name = "$item.$last_dir";

	print "renaming $item to $new_name ...\n";

	rename( $item, $new_name );
   
     exit( 0 );
}



__END__

:endofperl
