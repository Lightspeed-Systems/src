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


my $opt_infile;
my $opt_outfile;
my @urls;



################################################################################
#
MAIN:
#
################################################################################
{

	$opt_infile = shift if ( ! defined $opt_infile );
	$opt_outfile = shift if ( ! defined $opt_outfile );
	$opt_outfile = $opt_infile if ( ! defined $opt_outfile );

	if ( ! open OUTPUT, ">$opt_outfile" )
		{	print "Unable to open file $opt_outfile: $!\n";
			exit( 0 );
		}


	my $counter = &ReadFile( $opt_infile );
	exit( 0 ) if ( ! $counter );


	foreach ( @urls )
		{	next if ( ! defined $_ );
			my $domain = $_;

			my $reverse = &ReverseDomain( $domain );
			
			print OUTPUT "$reverse\n";
		}
		
		
	close OUTPUT;
		
	print "\nDone\n";

exit;

}



sub ReadFile( $ )
{
	my $filename = shift;
	return( 0 ) if ( ! $filename );

	if ( ! open INPUT, "<$filename" )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 );
		}

	my $count = 0 + 0;
	while (<INPUT>)
		{	chomp;
			next if ( ! $_ );
			push @urls, $_;
			
			$count++;
		}

	close INPUT;

	print "$filename has $count domains\n";

	return( $count );
}



################################################################################

__END__

:endofperl
