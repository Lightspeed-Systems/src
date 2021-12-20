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

use strict;
use warnings;


################################################################################
#!perl -w


use Win32::API;
	

print "loading NetWkstaGetInfo\n";

	my $NetWkstaGetInfo = new Win32::API( 'Netapi32.dll', 'NetWkstaGetInfo', 'PNP', 'N' );
	if ( ! $NetWkstaGetInfo )
		{	print "Update User: Unable to call NetWkstaGetInfo in Netapi32.lib\n";
			exit( 0 );
		}
	

	my $Machine = "\x00" x 256;
	my $lpBuffer = " " x 256;
	my $lpBuffer_len = 256;
	
	my $bufptr;
	
	my $ret = $NetWkstaGetInfo->Call( $Machine , 102, $bufptr );
		
	print "ret = $ret\n";
	print "bufptr = $bufptr\n";
exit;

__END__

:endofperl
