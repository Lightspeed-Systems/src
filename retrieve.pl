################################################################################
#!perl -w
#
# Retrieve - retrieves archived token, link, and label files
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;

use Content::File;
use Content::SQL;
use Content::Archive;


# Options
my $opt_help;
my $opt_version;
my $opt_urls_file;						# This is the file name of the list of urls of tokens files to retrieve
my $opt_dest_directory		= 'I:\\Archive';	# This is the root of the archive directory
my $opt_target_dir;						# This is the directory to put the tokens files into
my $opt_link;
my $opt_site;
my $opt_token;
my $opt_label;
my $opt_image;


my $_version = "1.0.0";
my $missing_file = "missing.urls";		# The file to write any missing domains to



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
        "a|label"			=>	\$opt_label,
        "d|destination=s"	=>	\$opt_dest_directory,
        "l|link"			=>	\$opt_link,
        "m|missing=s"		=>	\$missing_file,
        "s|site"			=>	\$opt_site,
        "i|image"			=>	\$opt_image,
		"t|token"			=>	\$opt_token,
       "v|version"			=>	\$opt_version,
        "h|help"			=>	\$opt_help
    );
	

    &StdHeader( "Retrieve" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


	# Read the command line
	$opt_urls_file = shift if ( ! $opt_urls_file );
	$opt_target_dir = shift if ( ! $opt_target_dir );
	
	
	if ( ! defined $opt_urls_file )
		{	print "You must specify a file containing the list or URLs to retrieve tokens files for.\n";
			exit( 0 );
		}
		
	if ( ! -e $opt_urls_file )
		{	print "$opt_urls_file does not exist.\n";
			exit( 0 );
		}
		
	# If nothing specified, then use the current directory as the target directory
	if ( ( ! $opt_target_dir )  ||  ( $opt_target_dir eq "." ) )
		{	$opt_target_dir = getcwd;
			$opt_target_dir =~ s#\/#\\#gm;	
		}
		

	if ( ! -d $opt_target_dir )
		{	print "Can not find target directory $opt_target_dir\n";
			exit( 0 );
		}

	if ( ! -d $opt_dest_directory )
		{	print "Can not find archive directory $opt_dest_directory\n";
			exit( 0 );
		}


	print "Retrieving from directory $opt_dest_directory ...\n";
	print "Retrieving to directory $opt_target_dir ...\n";
	

	# Process the source directory
	open( URLLIST, "<$opt_urls_file" ) or die "Unable to open file $opt_urls_file: $!\n";

	print "Loading up the list of domains to retrieve ...\n";
	my %domains;
	while ( my $url = <URLLIST> )
		{	next if ( ! defined $url );
			
			$url = &CleanUrl( $url );
			next if ( ! defined $url );
			
			my $domain = &RootDomain( $url );
			next if ( ! defined $domain );
			
			$domain = &TrimWWW( $domain );
			next if ( ! defined $domain );
			
			$domains{ $domain } = 1;
 		}

	closedir URLLIST;


	# Actually retrieve the dump files
	my @domains = sort keys %domains;

	my $dcount = $#domains + 1;
	
	print "Found $dcount unique domain names to retrieve\n";
	
	my $retrieve_options = "";
	
	$retrieve_options .= "l" if ( $opt_link );
	$retrieve_options .= "a" if ( $opt_label );
	$retrieve_options .= "s" if ( $opt_site );
	$retrieve_options .= "t" if ( $opt_token );
	$retrieve_options .= "i" if ( $opt_image );
	
	# If no option set, grab everything
	$retrieve_options = "last" if ( ! $retrieve_options );
	
	my @missing_domains = &Retrieve( $opt_dest_directory, $opt_target_dir, $retrieve_options, \@domains ) if ( $#domains > -1 );
	
	
	print "Saving missing domains to $missing_file\n";
	open( MISSING, ">$missing_file" ) or die "Unable to open file $missing_file: $!\n";
	foreach ( @missing_domains )
		{	next if ( ! defined $_ );
			my $domain = $_;
			print MISSING "$domain\n";
			print "Missing URL $domain\n";
		}
	close MISSING;
	
	&StdFooter;

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Retrieve urlslist targetdir";
    print <<".";
Usage: $me [OPTION(s)]
Retrieves archive tokens files.  Default action is to retrieve all the file
types.  File type options can be combined.
    
File type options
  -a, --label             retrieve labels files
  -l, --link              retrieve links files
  -s, --site              retrieve site files
  -t, --token             retrieve tokens files
  -i, --image             retrieve image zip files
  
 Other options 
  -d, --dest ARCHIVEDIR    directory to retrieve the token files from
                           default is $opt_dest_directory
  -m, --missing MISSING    filename to use for missing URLs
                           default is $missing_file
  -h, --help               display this help and exit
  -v, --version            display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "Retrieve";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
