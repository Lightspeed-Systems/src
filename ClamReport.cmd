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

use Content::File;




################################################################################
#
MAIN:
#
################################################################################
{
	my $clam_report = shift;

	die "You must enter a Clam report file name\n" if ( ! $clam_report );

	my $output_file = shift;

	$output_file = $clam_report if ( ! $output_file );


  	open( INPUT, "<$clam_report" ) or die( "Unable to open file $clam_report: $!\n" );

	my $counter = 0;

	my %subdir;

	while (<INPUT>)
	{	my $line = $_;
		chomp( $line );
		next if ( ! $line );

		# Ignore jokes
		next if ( $line =~ m/joke\./i );

		# Ignore corrupted
		next if ( $line =~ m/corrupted executable/i );

		# Ignore encrypted
		next if ( $line =~ m/encrypted program in archive/i );

		# Ignore unknown
		next if ( $line =~ m/an unknown virus/i );

		# Ignore unknown
		next if ( $line =~ m/could be a suspicious file/i );


		my ( $drive, $fullpath, $infection ) = split /\:/, $line, 3;

		next if ( ! $fullpath );

		my ( $dir, $file ) = &SplitFileName( $fullpath );

		next if ( ! $file );
		next if ( ! $dir );
	

		my @parts = split /\\/, $dir;

		my $important = $parts[ 3 ];

		next if ( ! $important );
		$important = lc( $important );	

		next if ( defined $subdir{ $important } );

		print "Found $important\n";
		$subdir{ $important } = 1;

	   $counter++;
	}

	my @subdir = sort keys %subdir;

	die "Unable to find any important directories\n" if ( $#subdir < 0 );

	open( OUTPUT, ">$output_file" ) or die "Unable to open file $output_file:$!\n";

	foreach ( @subdir )
		{	next if ( ! $_ );
			print OUTPUT "$_\n";
		}

	close( OUTPUT );

     exit( 0 );
}





__END__

:endofperl
