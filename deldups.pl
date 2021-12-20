################################################################################
#!perl -w
#
# Rob McCarthy's delete duplicate URLs from a file and get it ready to import
# into the database
#
################################################################################


# Pragmas
use strict;
use Socket;

use Getopt::Long;
use URI::Heuristic;
use Content::File;
use Content::FileUtil;



# Options
my $opt_address;
my $opt_input_file;
my $opt_output_file;
my $opt_domains;
my $opt_help;
my $opt_compress;
my $opt_version;
my $opt_numeric;
my $opt_remove;
my $opt_squid;
my $opt_regex;		# If specified, include on domains that match this regex
my $opt_wizard;		# True if I shouldn't display headers or footers
my $opt_flip;		# True if the input domains are in reverse order and must be reversed
my $opt_extensions;	# If True then drop the url extension - leaving only the domain name


my $_version = "1.0.0";



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
        "a|address"		=> \$opt_address,
        "c|compress"	=> \$opt_compress,
        "d|domains"		=> \$opt_domains,
        "e|extension"	=> \$opt_extensions,
        "f|flip"		=> \$opt_flip,
        "i|input=s"		=> \$opt_input_file,
        "n|numeric"		=> \$opt_numeric,
        "r|remove"		=> \$opt_remove,
        "o|output=s"	=> \$opt_output_file,
        "s|squid"		=> \$opt_squid,
		"w|wizard"		=> \$opt_wizard,
        "v|version"		=> \$opt_version,
		"x|xregex=s"	=> \$opt_regex,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "deldups" ) if ( ! $opt_wizard );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

    $opt_input_file = shift if ( !$opt_input_file );
    $opt_output_file = shift if ( !$opt_output_file );
    $opt_output_file = $opt_input_file if ( !$opt_output_file );
	
	if ( $opt_regex )
		{	$opt_regex = quotemeta( $opt_regex );
			print "Include only urls that match the regular expression $opt_regex\n";
		}

    &UsageError("Must specify at least the input file to delete duplicate URLs from!") unless ( $opt_input_file );

    $opt_compress = 1 if ( $opt_squid );   #  If the squid option is selected, make sure that we compress

	print "Compress domains\n" if ( $opt_compress );
	print "Use Squidguard format\n" if ( $opt_squid );
	print "Remove IP address domains\n" if ( $opt_remove );
	print "Include only IP address domains\n" if ( $opt_numeric );
	print "Validate the IP addresses of domains\n" if ( $opt_address );
	print "Strip domains down to the root domain\n" if ( $opt_domains );
	print "Drop extensions - leaving only the domain name\n" if ( $opt_extensions );
	
	if ( $opt_flip )
		{	&FlipInputFile( $opt_input_file, $opt_output_file );
		}
	else
		{	&deldups( $opt_input_file, $opt_output_file, $opt_domains, $opt_address, $opt_compress, $opt_numeric, $opt_remove, $opt_squid, $opt_regex, $opt_extensions );
		}
		
	&StdFooter if ( ! $opt_wizard );
	

	exit;
}



################################################################################
# 
sub FlipInputFile( $$ )
#
################################################################################
{	my $input_file = shift;
	my $output_file = shift;
	
	print "Flipping input file $input_file ...\n";
	
	if ( ! open( INPUT, "<$input_file" ) )
		{	print "Error opening file $input_file for input: $!\n";
			exit;	
		}
	
	my @domains;
	while (my $domain = <INPUT>)
		{	chomp( $domain );
			next if ( ! defined $domain );
			
			my $reverse = &ReverseDomain( $domain );

			push @domains, $reverse;
		}
		
	close INPUT;
	
	$output_file = $input_file if ( ! defined $output_file );
	
	
	# Now write it back out to the same file
	if ( ! open( OUTPUT, ">$output_file" ) )
		{	print "Error opening file $output_file for output: $!\n";
			exit;	
		}
	
	
	print "Writing reversed domains to $output_file ...\n";
	
	my $count = 0 + 0;
	foreach ( @domains )
		{	next if ( ! defined $_ );
			print OUTPUT "$_\n";
			$count++;
		}
		
	close OUTPUT;
	
	print "Flipped $count domains\n";
	
	return( 1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "deldups";

    bprint "$me\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
Try '$me --help' for more information.
.
    &StdFooter;

    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "deldups";

    bprint <<".";
Usage: $me [OPTION(s)]  input-file output-file
Removes duplicate and sub URLs from a list of URLs
Also cleans up http:// and trailing /
Also can include IP Addresses of domains
    
  -a, --address      validate and include the IP Addresses of domains
  -c, --compress     compress URLs and domains as much as possible
  -d, --domains      include only root domains of long URLs
  -e, --extensions   drop the url extension - leaving only the domain name
  -f, --flip         flips the input file domains from reverse order
  -i, --input=FILE   list of URLs to delete duplicates from
  -n, --numeric      output only numeric domains, i.e. IP addresses
  -o, --output=FILE  output file to put the cleaned up list of URLs
  -r, --remove       remove all numeric domains, i.e. IP addresses
  -h, --help         display this help and exit
  -s, --squid        split output files into the Squidguard domains and urls
  -v, --version      display version information and exit
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
    my $me = "deldups";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}


################################################################################

__END__

:endofperl
