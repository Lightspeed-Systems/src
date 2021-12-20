################################################################################
#!perl -w
#
# BlockedReview - Given a list of urls, insert them into the Statistics database
# Blocked Content for Review
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use File::Copy;
use Cwd;
use Content::File;
use Content::SQL;


# Options
my $opt_help;
my $opt_version;
my $opt_source_directory;						# This is the directory of token, link, and label files to archive
my $dbh;
my $dbhStats;
my $_version = "1.0.0";
my $url_list_filename = "categorize.urls";



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
        "s|source=s"		=>	\$opt_source_directory,
        "v|version"			=>	\$opt_version,
        "h|help"			=>	\$opt_help
    );

    &StdHeader( "BlockedContent" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


	# Read the command line
	my $tmp = shift;
	$url_list_filename = $tmp if ( $tmp );
	
	
	print "Inserting urls from $url_list_filename into Blocked for Review entries in the Statistics database ...\n";
	
	# Connect to the database
	$dbh = &ConnectServer();
	if ( ! $dbh )
		{	print "Unable to connect to the Content database\n";
			exit( 0 );	
		}
		
	&LoadCategories();
	
    $dbhStats = &ConnectStatistics();
	if ( ! $dbhStats )
		{	print "Unable to connect to the Statistics database\n";
			exit( 0 );	
		}
	
	
	open( URLLIST, "<$url_list_filename" ) or die "Unable to open file $url_list_filename: $!\n";
	
	
	# Default the time
 	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year = 1900 + $year;
	$mon = $mon + 1;
	my $time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
	
	
	my $counter = 0 + 0;
	while ( <URLLIST> )
		{	chomp;
			next if ( ! defined $_ );
			
			$counter++;
			
			my $url = $_;

			my $retcode = &LookupUnknown( $url, 0 );
			my $catnum = 0 + 0;
			my $catname;
			
			# If I found the URL - look up it's current category
			if ( $retcode)
				{	my $source;
					( $catnum, $source ) = &FindCategory( $url, $retcode );
					$catname = &CategoryName( $catnum ) if ( $catnum );
				}
			else
				{	$catname = "unknown";
				}
				
			my $url_type = &UrlType( $url );

			if ( $url_type == 1 )
				{	$url = &ReverseDomain( $url );
				}
			elsif ( $url_type == 2 )
				{	$url_type = 3;
				}
			elsif ( $url_type == 3 )
				{	$url_type = 2;
					
     				#Truncate the URL in case it's too big!
     				$url = substr($url, 0, 127);		     
				}

			my $str = "INSERT INTO ContentFilteringBlockedForReview (URL, Reason, CategoryID, ClientHost, InSystem) VALUES (\'$url\', $url_type, $catnum, \'lightspeed\', \'$time\')";

			my $sth = $dbhStats->prepare( $str );
			if ( !$sth->execute() )
               {	print "Error inserting Blocked for review entry:\n";
                    print "URL: $url, URL_TYPE:$url_type, CATNUM: $catnum, CLIENT_IP: lightspeed, TIME: $time\n";
               }

			$sth->finish();
		}

	close URLLIST;
	
	print "Inserted $counter entries into the Statistics database\n";
	
	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );
	$dbhStats->disconnect if ( $dbhStats );

	&StdFooter;

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "BlockedReview urllist";
    print <<".";
Usage: $me [OPTION(s)]

Insert into the Blocked for Review table in the statistics database a list
or URLs so that they can be easily hand checked
    
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
    my $me = "BlockedReview";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
