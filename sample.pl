################################################################################
#!perl -w
#
# sample
# Given a list of urls, build a random sample list of urls from it
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
        "n|number=s"	=> \$opt_number,
        "o|output=s"	=> \$opt_outfile,
		"w|wizard"		=> \$opt_wizard,
		"v|version"		=> \$opt_version,
		"x|xxx"			=> \$opt_debug,
        "h|help"		=> \$opt_help
    );


	&StdHeader( "sample" ) if ( ! $opt_wizard );
	
	$opt_infile = shift if ( ! $opt_infile );
	$opt_outfile = shift if ( ! $opt_outfile );
	
	&Usage() if ( ( ! $opt_number )  ||  ( ! $opt_infile )  ||  ( ! $opt_outfile ) );
	
	print "Sampling file $opt_infile $opt_number times, outputing sample to $opt_outfile ...\n";
	
	if ( ! open OUTPUT, ">$opt_outfile" )
		{	print "Unable to open file $opt_outfile: $!\n";
			exit( 0 );
		}

	my $counter = &ReadFile( $opt_infile );
	my $max_number = $counter / 2;
	if ( $opt_number >$max_number )
		{	$opt_number = int( $max_number );
			print "Sample size too big for this file, using $opt_number instead\n";
		}
		
		
	exit( 0 ) if ( ! $counter );


	my $found = 0 + 0;
	my %sample_domains;
	
	
	# Get random URLs without duplicating root domains
	while ( $found < $opt_number )
		{
			my $rand = int( rand $counter );
			
			my $url = $urls[ $rand ];
			
			my $root = &RootDomain( $url );
	
			# Have I seen this domain before?
			if ( ! defined $sample_domains{ $root } )
				{	print OUTPUT "$url\n";
					$found++;
					
					$sample_domains{ $root } = 1;
				}
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
    my $me = "sample";

    bprint <<".";
Usage: $me -n number inputfile outputfile
Samples the input file of URLs and creates the number of URLs in the output file.

    
  -i, --input=FILE     the input file to sample
  -n, --number=NUM     number of random samples to get
  -o, --output=FILE    the output file to put the samples in
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
    my $me = "sample";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}


################################################################################

__END__

:endofperl
