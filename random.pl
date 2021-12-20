################################################################################
#!perl -w
#
# Random
# Given a list of urls, build a random list of urls from it
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Cwd;


use Content::File;


my $opt_infile;
my $opt_outfile;
my $opt_help;
my $opt_number;
my $opt_version;
my $opt_wizard;
my $opt_debug;


my @urls;
my $_version		= "1.0.0";



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
        "i|input=s"		=> \$opt_infile,
        "o|output=s"	=> \$opt_outfile,
		"w|wizard"		=> \$opt_wizard,
		"v|version"		=> \$opt_version,
		"x|xxx"			=> \$opt_debug,
        "h|help"		=> \$opt_help
    );


	&StdHeader( "random" ) if ( ! $opt_wizard );
	
	$opt_infile = shift if ( ! defined $opt_infile );
	$opt_outfile = shift if ( ! defined $opt_outfile );
	$opt_outfile = $opt_infile if ( ! defined $opt_outfile );
	
	&Usage() if ( ( ! $opt_infile )  ||  ( ! $opt_outfile ) );
	
	print "Randomizing file $opt_infile, outputing to $opt_outfile ...\n";
	
	my $counter = &ReadFile( $opt_infile );
	exit( 0 ) if ( ! $counter );


	my $found = 0 + 0;
	
	
	if ( ! open OUTPUT, ">$opt_outfile" )
		{	print "Unable to open file $opt_outfile: $!\n";
			exit( 0 );
		}


	# Get random URLs without duplicating
	while ( $counter )
		{
			my $rand = int( rand $counter );
			
			my $url = $urls[ $rand ];
			if ( defined $url )
				{	print OUTPUT "$url\n";
				}
				
			$found++;
			$counter--;
			
			splice( @urls, $rand, 1 );
		}
		
		
	close OUTPUT;
		
	print "\nDone\n";
	
	exit( 0 );
}



sub ReadFile( $ )
{
	my $filename = shift;
	return if ( ! $filename );

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

	print "$filename has $count lines\n";

	return( $count );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "random";

    bprint <<".";
Usage: $me inputfile outputfile
Randomizes the input file of URLs and to the output file.
If no output file is given then it randomizes the input.
    
  -i, --input=FILE     the input file to randomize
  -o, --output=FILE    the output file to write the random URLs to
  -h, --help           display this help and exit
  -v, --version        display version information and exit
.
    &StdFooter;

    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "random";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}


################################################################################

__END__

:endofperl
