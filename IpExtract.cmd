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
use warnings;





################################################################################
#
MAIN:
#
################################################################################
{
	my $item = shift;

	die "You must enter a file name\n" if ( ! $item );

	if ( -f $item )
		{  &extract( $item );
		   exit( 0 );
		}


     print "Error finding file $item\n";

     exit( 0 );
}




sub extract( $ )
{
	my $filename = shift;
	return if ( ! $filename );

	open( INPUT, "<$filename" ) or die( "Unable to open file $filename: $!\n" );

	my $counter = 0;

	while ( my $line = <INPUT> )
	{
	   $counter++;
		next if ( ! $line );
		my ( $junk, $ip ) = split / - /, $line, 2;
		next if ( ! $ip );

		( $ip, $junk ) = split /\s/, $ip, 2;

		print "$ip\n";
	}

	close INPUT;

	print "$filename has $counter lines\n";

	return( $counter );
}



__END__

:endofperl
