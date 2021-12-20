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

use Cwd;





################################################################################
#
MAIN:
#
################################################################################
{
	my $item = shift;
	if ( ! $item ) 
		{	my $cwd = getcwd;
			$cwd =~ s#\/#\\#g;
			$cwd =~ s/\\$//;   # Trim off a trailing slash
			$item = $cwd;
		}

	print "Delete all but the first file in directory $item\n";

     	# Process the directory
     	if ( ! opendir( DIR, $item ) )
		{	die "Unable to open directory $item: $!\n";
		}

     	my $file_counter = 0;
	my $del_count = 0 + 0;
     	while ( my $file = readdir( DIR ) )
 	{
 		# Skip subdirectories
 		next if ( -d $file );
		
		if ( $file_counter )
			{	my $full_file = "$item\\$file";
				my $ok = unlink( $full_file );
				$del_count++ if ( $ok );
			}	
		$file_counter++;
	
         }

	close( DIR );

	print "Deleted $del_count files from directory $item\n";

     exit( 0 );
}



__END__

:endofperl
