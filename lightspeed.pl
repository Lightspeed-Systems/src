################################################################################
#!perl -w
#
#  Rob McCarthy's Lightspeed database query source code
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Content::File;
use Getopt::Long;
use IO::Handle;
use Cwd;
use Content::SQL;
use Win32API::Registry 0.21 qw( :ALL );
use Benchmark;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_debug = 1;	 			# If True then don't over write existing files
my $opt_existing;				# True if run from a Wizard dialog
my $opt_category;				# The Lightspeed category name that I am comparing
my $_version = "1.0.0";
my $websense_name;				# This is the name of the Websense category that I am comparing
my $lightspeed_meta;			# This is the equivalent Lightspeed Category - quotemeta



# This hash is a mapping between the Websense category number, the equivalent Lightspeed category name,
# and the Websense sub category (if it exists)
my %websense_names =
(
 "2"	=> "business",
 
 "10"	=> "society.politics\tabortion",
 "92"	=> "society.politics\tpro-choice",
 "93"	=> "society.politics\tpro-life",
 
 "65"	=> "porn\tnudity",
 "66"	=> "adult\tadult_content",
 "67"	=> "porn\tsex",
 "94"	=> "education.sex\tsex_education",
 "95"	=> "adult\tlingerie_and_swimsuit",
 
 "11"	=> "society\tadvocacy_groups",
 
 "114"	=> "audio-video\tinternet_radio_and_tv",
 "108"	=> "audio-video\tinternet_telephony",
 "115"	=> "forums.p2p\tpeer_to_peer_file_sharing",
 "113"	=> "audio-video\tpersonal_network_storage_and_backup",
 "109"	=> "audio-video\tstreaming_media",
 
 "68"	=> "finance\tfinancial_data_and_services",
 
 "90"	=> "drugs\tabused_drugs",
 "88"	=> "health\tprescribed_medications",
 "89"	=> "health\tsuppliments_and_unregulated_compounds",
 "111"	=> "drugs\tmarijuana",

 "69"	=> "society\tcultural_institutions",
 "97"	=> "education\teducational_institutions",
 "118"	=> "education\teducational_materials",
 "121"	=> "education\treference_materials",

 "12"	=> "entertainment",
 "70"	=> "audio-video\tmp3_and_audio_download_services",
 
 "13"	=> "gambling",
 
 "14"	=> "games",

 "4"	=> "government",
 "72"	=> "government\tmilitary",
 "73"	=> "society.politics\tpolitical_organizations",
 
 "27"	=> "health",
 
 "15"	=> "adult\tillegal_or_questionable",
 
 "9"	=> "computers\tinformation_technology",
 "28"	=> "search\ttranslation",
 "76"	=> "search",
 "78"	=> "forums.personals\tweb_hosting",
 "80"	=> "security.hacking\thacking",
 "138"	=> "computer\tcomputer_security",
 "75"	=> "security.proxy\tproxy_avoidance",
 
 "74"	=> "mail\tweb_based_email",
 "79"	=> "forums.chat\tweb_chat",
 
 "16"	=> "jobs\tjob_search",
 
 "25"	=> "society.politics\tmilitancy_and_extremist",
 
 "150"	=> "computers\tcontent_delivery_networks",
 "156"	=> "computers\tfile_download_servers",
 "148"	=> "computers\timage_servers",
 
 "5"	=> "news\tnews_and_media",
 "81"	=> "news\talternate_journals",
 
 "29"	=> "ads\tadvertisements",
 "96"	=> "finance\tonline_brokerage_and_trading",
 "98"	=> "forums.im\tinstant_messaging",
 "99"	=> "security.warez\tfreeware_and_software_download",
 "112"	=> "forums\tmessage_boards_and_clubs",
 "100"	=> "access-denied\tpay_to_surf",
 
 "26"	=> "violence.hate\tracism_and_hate",
 
 "82"	=> "family.religion\tnon-traditional_religions",
 "83"	=> "family.religion\ttraditional_religions",
 
 "166"	=> "security.spyware\tkeyloggers",
 "128"	=> "security.virus\tmalicious_websites",
 "164"	=> "security.phishing",
 "154"	=> "security.spyware",
 
 "17"	=> "shopping",
 "101"	=> "shopping.auctions",
 "102"	=> "real_estate",
 
 "125"	=> "society\tprofessional",
 "123"	=> "society\tservice",
 "124"	=> "society\tsocial",
 
 "7"	=> "education.lifestyles",
 "87"	=> "alcohol\talcohol_and_tobacco",
 "85"	=> "adult.lifestyles\tgay_or_lesbian_or_bisexual_interest",
 "86"	=> "forums.personals\tpersonals_and_dating",
 "84"	=> "family.food\trestaurants_and_dining",
 "103"	=> "hobby",
 "117"	=> "forums.personals",
 
 "8"	=> "general\tspecial_events",

 "18"	=> "sports",
 "107"	=> "weapons\tsport_hunting_and_gun_clubs",
 
 "19"	=> "adult\ttasteless",

 "20"	=> "travel",
 "21"	=> "automobile\tvehicles",
 "22"	=> "violence",
 "23"	=> "violence.weapons",

 "152"	=> "expired",
 "153"	=> "unknown"
);



my @input_files = ( "domains.hit" );

my $match		= "lightspeed.match";
my $match_handle;

my $miss		= "lightspeed.miss";
my $miss_handle;

my $unknown		= "lightspeed.unknown";
my $unknown_handle;

my $block		= "lightspeed.blocked";
my $block_handle;


my $dbh;			# My database handle		


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
        "c|category=s"	=> \$opt_category,
        "d|debug"		=> \$opt_debug,
		"e|existing"	=> \$opt_existing,
        "h|help"		=> \$opt_help,
        "x|xxx"			=> \$opt_debug,
    );


	print "Lightspeed query\n";
	
    &Usage() if ($opt_help);
	
	
	if ( $opt_existing )
		{	die "Existing files\n" if ( ( -e $match )  ||  ( -e $miss )  ||  ( -e $unknown )  ||  ( -e $block ) );  
		}
		
		
	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );
				
	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;		
	
	&SetLogFilename( "$dir\\lightspeed.log", $opt_debug );
	
	
	print "Opening a connection to the ODBC System DSN \'TrafficRemote\' ...\n";
	$dbh = &ConnectRemoteServer();
	
	if ( ! $dbh )
		{
print "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.
Also add the Content SQL Server as a System DSN named \'TrafficCategory\'
with default database \'Category\'.\n";

			exit( 0 );
		}
		
	&LoadCategories();
	
		
	# Open all the logging files
	open( $match_handle,	">>$match" )		or die "Unable to open file $match: $!\n";
	$match_handle->autoflush( 1 );

	open( $miss_handle,		">>$miss" )			or die "Unable to open file $miss: $!\n";
	$miss_handle->autoflush( 1 );
	
	open( $unknown_handle,	">>$unknown" )		or die "Unable to open file $unknown: $!\n";
	$unknown_handle->autoflush( 1 );
	
	open( $block_handle,	">>$block" )		or die "Unable to open file $block: $!\n";
	$block_handle->autoflush( 1 );
	
	
	# Get the Lightspeed category name
	if ( $opt_category )
		{	$websense_name = $opt_category;
		}
	else
		{	# Figure out which Websense category I am using by the directory name
			my @parts = split /\\/, $dir;
			$websense_name = $parts[ $#parts ];
			
		}
		
		
	lprint "Websense category = $websense_name\n";
	lprint "Current directory = $dir\n";
	my $lightspeed_equiv = &WebsenseToLightspeedCategory( $websense_name );
	lprint "Lightspeed equivalent category = $lightspeed_equiv\n";
	$lightspeed_meta = quotemeta( $lightspeed_equiv );


	# Keep track of how long it takes to categorize
	my $start = new Benchmark;
	
	# Categorize any files found
	foreach ( @input_files )
		{	&LightspeedCategorize( $_ );
		}
	
	# Calc the benchmark statistics
	my $finish = new Benchmark;


	
	
	close $match_handle;
	close $miss_handle;
	close $unknown_handle;
	close $block_handle;
	
	
	my $diff = timediff($finish, $start);
	my $strtime = timestr( $diff );
	$strtime =~ s/^\s*//;	# Trim off any leading spaces

	print "Benchmark = $strtime\n";

exit;
}
################################################################################



################################################################################
# 
sub LightspeedCategorize( $ )
#
#  Given a file that contains a list of urls, query the Websense server and write
#  the results out to some text files
#
################################################################################
{	my $file = shift;
	
	return( undef ) if ( ( ! -e $file )  ||  ( ! -s $file ) );
	
	open( INPUT, "<$file" ) or die "Unable to open $file: $!\n";
	
	lprint "Processing file $file ...\n";
	
	my $counter = 0 + 0;
	
	# Loop through reading the list of urls and getting the Lightspeed category
	while (<INPUT>)
		{	my $url = $_;
			chomp( $url );
			next if ( ( ! defined $url )  ||  ( $url eq "" ) );
			
			print "Checking $url ...\n";
						
			my $lightspeed_category = &LightspeedQuery( $url );
			
			$counter++;
			
			&WriteCategory( $url, $lightspeed_category );
		}

	lprint "Checked $counter URLs from file $file\n";
	
	close INPUT;
}



################################################################################
# 
sub WriteCategory( $$ )
#
#  Given a url, and it's lightspeed category, write it to the appropriate file(s)
#
################################################################################
{	my $url = shift;
	my $lightspeed_category = shift;
	
	my $catname = &CategoryName( $lightspeed_category ) if ( $lightspeed_category );
	$catname = "unknown" if ( ! $lightspeed_category );
		
	if ( ! $lightspeed_category )
		{	print "Unknown\n";
			print $unknown_handle "$url\n";
		}
	elsif ( $catname =~ m/$lightspeed_meta/ )
		{	print "Matched\n";
			print $match_handle "$url\t$lightspeed_category\t$catname\n";
		}
	else
		{	print "Missed\n";
			print $miss_handle "$url\t$lightspeed_category\t$catname\n";
			
			# Does one or the other have this blocked?  If so, there might be something seriously wrong
			my $blocked = 1 if ( "porn gambling spam adult forums drugs phishing games spyware virus weapons" =~ m/$catname/ );
			
			print $block_handle "$url\t$lightspeed_category\t$catname\n" if ( $blocked );
		}
}



################################################################################
# 
sub WebsenseToLightspeedCategory( $ )
#
#  Given a Websense category name, return the equivalent Lightspeed category name
#
################################################################################
{	my $websense_category = shift;
	
	# Remap the %websense_names hash
	my @values = values %websense_names;
	
	my %lightspeed_names;
	foreach ( @values )
		{	next if ( ! defined $_ );
			my $value = $_;
			my ( $lightspeed, $websense ) = split /\t/, $value, 2;
			
			$websense = $lightspeed if ( ( ! defined $websense )  ||  ( $websense eq "" ) );
			
			$lightspeed_names{ $websense } = $lightspeed;
		}
	
	my $lightspeed_category = $lightspeed_names{ $websense_category };
	$lightspeed_category = "unknown" if ( ! defined $lightspeed_category );
	
	return( $lightspeed_category );
}



################################################################################
# 
sub LightspeedQuery( $ )
#
#  Given a url, query a Lightspeed server for the
#  URL category.  Return undef if an error, or the Lightspeed category number if OK.
#
################################################################################
{	my $url	= shift;
	
	# Find the old category of the URL
	my $retcode = &LookupUnknown( $url, 0 );
	my $categoryNumber;
	my $source;
	
	# If I found the URL - look up it's current category
	if ( $retcode)
		{	( $categoryNumber, $source ) = &FindCategory( $url, $retcode );
		}
	else
		{	return( 0 + 0 );	# 0 is the unknown category
		}
		
	return( $categoryNumber );
}



################################################################################
# 
sub ConnectRemoteServer()
#
#  Find and connect to the remote Content database SQL Server, if possible.  
#  Return undef if not possible
#
#  This function is mainly called by the Categorize command
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\TrafficRemote", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	RegCloseKey( $key );
	
	my $dbhRemote = DBI->connect( "DBI:ODBC:TrafficRemote", "IpmContent" );
	&SqlSetCurrentDBHandles( $dbhRemote, undef );
	
	return( $dbhRemote );
}



################################################################################
#
sub TrapErrors( $$ )
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename base on the mode I'm running in
	my $filename = "LightspeedErrors.log";
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">>$filename" ) )
		{	print( "Unable to open $filename for error logging: $!\n" ); 
			return;
		}
		
	&CarpOut( $MYLOG );
   
	print( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Lightspeed";

    print <<".";
Usage: $me urllist [OPTION(s)]
Lightspeed queries a Lightspeed server to find what it\'s database thinks the
categories of a list of URLs.

  -h, --help     display this help and exit
  -v, --version  display version information and exit
  
.
   &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl

