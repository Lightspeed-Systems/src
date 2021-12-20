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

use Content::File;

open( FILE, "<google.txt" );
open( OUTPUT, ">domains" );

while (<FILE>)
	{	my $line = $_;
		chomp( $line );
		next if ( ! $line );

		my ( $junk, $url, $junk2 ) = split /\"/, $line, 3;

		next if ( ! $url );

		$url = &CleanUrl( $url );
		next if ( ! $url );
		
		$url = &TrimWWW( $url );
		next if ( ! $url );

		print OUTPUT "$url\n";
	}

close FILE;
close OUTPUT;

exit;

__END__

:endofperl
