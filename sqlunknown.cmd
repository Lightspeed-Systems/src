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
use Getopt::Long;
use Content::File;
use Content::SQL;
use DBI qw(:sql_types);
use DBD::ODBC;



my $opt_dir;                                         # Directory to put stuff to
my $opt_input_file;    
my $opt_output_file = "unknown.urls";    
my $opt_help;
my $opt_version;



# Globals
my $_version = "2.0.0";
my  $dbh;             #  My database handle



################################################################################
#
MAIN:
#
################################################################################
{ 


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "d|directory=s" 	=> \$opt_dir,
        "i|input=s" 		=> \$opt_input_file,
        "o|output=s" 		=> \$opt_output_file,
        "v|version" 		=> \$opt_version,
        "h|help" 		=> \$opt_help
    );

	print ("SQLunknown\n" );

	$opt_input_file = shift if ( ! $opt_input_file );
	my $str = shift;
	$opt_output_file = $str if ( $str );

    print "Reading URLs file $opt_input_file and creating unknown URLs file $opt_output_file ... \n";

    &Usage() if ($opt_help);
    &Version() if ($opt_version);


     $dbh = &ConnectServer() or die;

     &UnknownUrls();

     $dbh->disconnect;

     print "\nDone\n";
}

exit;
################################################################################




################################################################################
# 
sub UnknownUrls()
#
#  Check each URL to see if it is known
#
################################################################################
{	open( OUTPUT, ">$opt_output_file" ) or die ( "Can not create output file $opt_output_file: $!\n" );
	open(INPUT, "<$opt_input_file" ) or die ( "Can not open input file $opt_input_file: $!\n" );

	my $counter = 0 + 0;
	my $read_counter = 0 + 0;

	while (<INPUT>)
		{	my $url = $_;
			next if ( ! $url );

			chomp( $url );
			next if ( ! $url );

			$read_counter++;

			$url = &CleanUrl( $url );
			next if ( ! $url );

			my $retcode = &LookupUnknown( $url, 0 );

			next if ( $retcode );

			print OUTPUT "$url\n";

              			$counter++;
         		}

  	close  OUTPUT;
	close INPUT;

	print "Read $read_counter URLs from $opt_input_file\n";
    	print "Created $opt_output_file with $counter unknown URLs \n";
}



################################################################################
# 
sub Usage
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

#  -u, --url=URL         specify URL instead of using file
    print <<".";
Usage: $me [OPTION(s)]
Export domains, urls, hits, and misses from the Content Database to Squidguard format

  -c, --category=name    category name if only one category to export
  -d, --directory=PATH   to change default files directory
  -h, --help             display this help and exit
  -v, --version          display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
$me $_version
.
    exit;
}



__END__

:endofperl
