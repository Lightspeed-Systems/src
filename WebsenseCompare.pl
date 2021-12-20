################################################################################
#!perl -w
#
#  WebsenseCompare - Compare a Websense server's categorization with the local
#  Lightspeed IpmContentDatabase - written 9/25/2007 by Rob McCarthy
#
################################################################################



use strict;
use warnings;


use Getopt::Long;
use IO::Handle;
use IO::Socket;
use Cwd;
use Benchmark;
use Sys::Hostname;
use Net::DNS;
use Win32::Event;


use Content::File;
use Content::SQL;
use Content::SQLCompare;



my $opt_verbose;
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_debug;

my $output_file_name;
my $dbh;								# The global database handle
my $dbhStats;							#  My database handle for the statistics database
my $sthStats;
my $counter = 0 + 0;					# The count of URLs that I have queried
my $connect_errors = 0 + 0;				# The number of socket connect errors
my %query;								# A hash of outstanding queries
my %root_domain;						# A hash of the root domains that I have already queried
my %unknown_domains;
my @new_categories;						# A list of new categories found for Websense
my $total_urls = 0 + 0;					# This is the total number of URLs returned from the query


my $local_company	= "Lightspeed";		# These names are used in the Compare SQL tables
my $remote_company	= "Websense";

my $max_sockets		= 0 + 4;
my $server_ip		= "10.16.43.13";	# Todd's test machine is "10.16.3.15", nonsense server is "10.16.43.13"
my $port_no			= 15888;



my %local_category_rating =					# This hash is used to set the Category rating if it is not set in the database
(
	1	=>	'G',
	2	=>	'S',
	3	=>	'G',
	4	=>	'R',
	5	=>	'PG',
	6	=>	'G',
	7	=>	'Errors',
	8	=>	'R',
	9	=>	'G',
	10	=>	'G',
	11	=>	'R',
	12	=>	'R',
	13	=>	'G',
	14	=>	'PG',
	15	=>	'G',
	16	=>	'S',
	17	=>	'R',
	18	=>	'G',
	19	=>	'G',
	20	=>	'G',
	21	=>	'X',
	22	=>	'X',
	23	=>	'X',
	24	=>	'X',
	25	=>	'X',
	26	=>	'X',
	27	=>	'X',
	28	=>	'S',
	29	=>	'G',
	30	=>	'G',
	31	=>	'X',
	32	=>	'R',
	33	=>	'S',
	34	=>	'G',
	35	=>	'G',
	36	=>	'G',
	37	=>	'G',
	38	=>	'G',
	39	=>	'PG',
	40	=>	'G',
	41	=>	'PG',
	42	=>	'PG',
	43	=>	'G',
	44	=>	'G',
	45	=>	'G',
	46	=>	'G',
	47	=>	'G',
	48	=>	'G',
	49	=>	'PG',
	50	=>	'G',
	51	=>	'G',
	52	=>	'G',
	53	=>	'G',
	54	=>	'G',
	55	=>	'G',
	56	=>	'G',
	57	=>	'G',
	58	=>	'G',
	59	=>	'PG',
	60	=>	'G',
	61	=>	'G',
	62	=>	'S',
	63	=>	'S',
	64	=>	'S',
	65	=>	'S',
	66	=>	'R',
	67	=>	'S',
	68	=>	'G',
	69	=>	'G',
	70	=>	'R',
	71	=>	'R',
	72	=>	'S',
	73	=>	'G',
	74	=>	'G',
	75	=>	'G',
	76	=>	'G',
	77	=>	'G',
	78	=>	'G',
	79	=>	'PG',
	80	=>	'PG',
	81	=>	'G',
	82	=>	'G',
	83	=>	'G',
	84	=>	'G',
	85	=>	'G',
	86	=>	'PG',
	87	=>	'PG',
	88	=>	'PG',
	89	=>	'PG',
	90	=>	'PG',
	91	=>	'PG',
	92	=>	'PG',
	93	=>	'PG',
	94	=>	'X',
	95	=>	'G',
	96	=>	'G',
	97	=>	'PG',
	98	=>	'G',
	99	=>	'G',
	100	=>	'R',
	101	=>	'R',
	102	=>	'X',
	103	=>	'R',
	104	=>	'G',
	105	=>	'G',
	106	=>	'PG',
	107	=>	'PG',
	108	=>	'PG',
	109	=>	'X',
	110	=>	'X',
	111	=>	'X',
	112	=>	'G',
	113	=>	'R',
	114	=>	'S',
	115	=>	'G',
	116	=>	'S',
	117	=>	'R',
	118	=>	'R',
	119	=>	'G',
	120	=>	'G',
	121	=>	'PG',
	122	=>	'R',
	123	=>	'X',
	124	=>	'S',
	200	=>	'Unknown'
);



my %compare_category_rating	=			# A hash of key = compare_category_number, value = compare category rating (S, X, R, PG, G, Errors, Unknown )
(
	152	=>	'Errors',
	2	=>	'G',
	3	=>	'G',
	4	=>	'G',
	5	=>	'G',
	7	=>	'G',
	8	=>	'G',
	9	=>	'G',
	10	=>	'G',
	11	=>	'G',
	12	=>	'G',
	14	=>	'G',
	16	=>	'G',
	17	=>	'G',
	18	=>	'G',
	20	=>	'G',
	21	=>	'G',
	27	=>	'G',
	28	=>	'G',
	29	=>	'G',
	68	=>	'G',
	69	=>	'G',
	70	=>	'G',
	72	=>	'G',
	73	=>	'G',
	74	=>	'G',
	76	=>	'G',
	78	=>	'G',
	79	=>	'G',
	81	=>	'G',
	82	=>	'G',
	83	=>	'G',
	84	=>	'G',
	87	=>	'G',
	92	=>	'G',
	93	=>	'G',
	96	=>	'G',
	97	=>	'G',
	98	=>	'G',
	99	=>	'G',
	100	=>	'G',
	101	=>	'G',
	102	=>	'G',
	103	=>	'G',
	107	=>	'G',
	108	=>	'G',
	109	=>	'G',
	112	=>	'G',
	113	=>	'G',
	114	=>	'G',
	115	=>	'G',
	118	=>	'G',
	121	=>	'G',
	123	=>	'G',
	124	=>	'G',
	125	=>	'G',
	138	=>	'G',
	146	=>	'G',
	148	=>	'G',
	150	=>	'G',
	156	=>	'G',
	172	=>	'G',
	
	85	=>	'PG',
	88	=>	'PG',
	89	=>	'PG',
	94	=>	'PG',
	
	13	=>	'R',
	19	=>	'R',
	22	=>	'R',
	23	=>	'R',
	25	=>	'R',
	26	=>	'R',
	86	=>	'R',
	90	=>	'R',
	95	=>	'R',
	111	=>	'R',
	117	=>	'R',
		
	75	=>	'S',
	80	=>	'S',
	128	=>	'S',
	154	=>	'S',
	164	=>	'S',
	166	=>	'S',
	167	=>	'S',
		
	149	=>	'Unknown',
	153	=>	'Unknown',
	
	15	=>	'X',
	65	=>	'X',
	66	=>	'X',
	67	=>	'X'
);


my %compare_category_name =				# A hash of key = compare_category_number, value = compare category name
(
	2	=> "business_and_economy",
 
	10	=> "abortion",
	92	=> "abortion.pro-choice",
	93	=> "abortion.pro-life",
 
	65	=> "adult_material.nudity",
	66	=> "adult_material.adult_content",
	67	=> "adult_material.sex",
	94	=> "adult_material.sex_education",
	95	=> "adult_material.lingerie_and_swimsuit",
 
	11	=> "advocacy_groups",
 
	114	=> "bandwidth_pg.internet_radio_and_tv",
	108	=> "bandwidth_pg.internet_telephony",
	115	=> "bandwidth_pg.peer_to_peer_file_sharing",
	113	=> "bandwidth_pg.personal_network_storage_and_backup",
	109	=> "bandwidth_pg.streaming_media",
 
	68	=> "business_and_economy.financial_data_and_services",
 
	90	=> "drugs.abused_drugs",
	88	=> "drugs.prescribed_medications",
	89	=> "drugs.suppliments_and_unregulated_compounds",
	111	=> "drugs.marijuana",

	69	=> "education.cultural_institutions",
	97	=> "education.educational_institutions",
	118	=> "education.educational_materials",
	121	=> "education.reference_materials",

	12	=> "entertainment",
	70	=> "entertainment.mp3_and_audio_download_services",
 
	13	=> "gambling",
 
	14	=> "games",

	4		=> "government",
	72	=> "government.military",
	73	=> "government.political_organizations",
 
	27	=> "health",
 
	15	=> "illegal_or_questionable",
 
	9	=> "information_technology",
	28	=> "information_technology.url_translation_sites",
	76	=> "information_technology.search_engines_and_portals",
	78	=> "information_technology.web_hosting",
	80	=> "information_technology.hacking",
	138	=> "information_technology.computer_security",
	75	=> "information_technology.proxy_avoidance",
 
	74	=> "internet_communications.web_based_email",
	79	=> "internet_communications.web_chat",
 
	16	=> "job_search",
 
	25	=> "militancy_and_extremist",
 
	150	=> "miscellaneous.content_delivery_networks",
	156	=> "miscellaneous.file_download_servers",
	148	=> "miscellaneous.image_servers",
	149	=> "miscellaneous.uncategorized",
	146	=> "miscellaneous.dynamic_content",
	172	=> "miscellaneous.images",
	151	=> "miscellaneous.private_ip_addresses",
	152	=> "miscellaneous.network_errors",
	153	=> "miscellaneous.uncategorized",
 
	5	=> "news_and_media",
	81	=> "news_and_media.alternate_journals",
 
	29	=> "productivity_pg.advertisements",
	96	=> "productivity_pg.online_brokerage_and_trading",
	98	=> "productivity_pg.instant_messaging",
	99	=> "productivity_pg.freeware_and_software_download",
	112	=> "productivity_pg.message_boards_and_clubs",
	100	=> "productivity_pg.pay_to_surf",
 
	26	=> "racism_and_hate",
 
	82	=> "religion.non-traditional_religions",
	83	=> "religion.traditional_religions",
 
	167	=> "security_pg.bot_networks",
	166	=> "security_pg.keyloggers",
	128	=> "security_pg.malicious_web_sites",
	164	=> "security_pg.phishing_and_other_frauds",
	165	=> "security_pg.potentially_unwanted_software",
	154	=> "security_pg.spyware",
 
	17	=> "shopping",
	101	=> "shopping.internet_auctions",
	102	=> "shopping.real_estate",
 
	125	=> "social_organizations.professional",
	123	=> "social_organizations.service",
	124	=> "social_organizations.social",
 
	7	=> "society_and_lifestyles",
	87	=> "society_and_lifestyles.alcohol_and_tobacco",
	85	=> "society_and_lifestyles.gay_or_lesbian_or_bisexual_interest",
	86	=> "society_and_lifestyles.personals_and_dating",
	84	=> "society_and_lifestyles.restaurants_and_dining",
	103	=> "society_and_lifestyles.hobbies",
	117	=> "society_and_lifestyles.personal_web_sites",
 
	8	=> "special_events",

	18	=> "sports",
	107	=> "sports.sport_hunting_and_gun_clubs",
 
	19	=> "tasteless",

	20	=> "travel",
	21	=> "vehicles",
	22	=> "violence",
	23	=> "weapons",

	200	=> "websense.unknown",
 	195	=> "websense.no_idea",
 	196	=> "websense.no_idea_as_well",

	3	=> "unlisted_tests"
);



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
		"p|port=i"			=> \$port_no,
        "s|server=s"		=> \$server_ip,
        "v|verbose"			=> \$opt_verbose,
		"x|xdebug"			=> \$opt_debug,
		"w|wizard"			=> \$opt_wizard,
        "h|help"			=> \$opt_help
    );


    &StdHeader( "WebsenseCompare" ) if ( ! $opt_wizard );
	
    &Usage() if ( $opt_help );
	

	my $temp = shift;
	$server_ip = $temp if ( $temp );
	
	&Usage() if ( ! $server_ip );
	&Usage() if ( ! &IsIPAddress( $server_ip ) );
	
	my $old_time = shift;
	my $new_time = shift;
	
	&Usage() if ( ( $old_time )  &&  ( ! $new_time ) );
	&Usage() if ( ( $old_time )  &&  ( $new_time )  &&  ( ! $output_file_name ) );
	
	&Usage() if ( ( $old_time )  &&  ( ! &DateFormat( $old_time ) ) );
	&Usage() if ( ( $new_time )  &&  ( ! &DateFormat( $new_time ) ) );
	
	$output_file_name = shift;
	$output_file_name = "WebsenseCompare.txt" if ( ! $output_file_name );
	
	print "Websense query server IP $server_ip port $port_no\n";
	
		
    #  Open the local database
	print "Opening a connection to the local database ...\n";
    $dbh = &ConnectServer() or &FatalError("Unable to connect to the local IpmContent database\n" );

	print "Loading the local categories ...\n";
    &LoadCategories();

    #  Open the Statistics database
    $dbhStats = &ConnectStatistics() or &FatalError("Unable to connect to the local IpmStatistics database\n" );


	# Fill out any missing category ratings with 'G'
	while ( my ( $category_number, $category_name ) = each( %compare_category_name ) )
		{	next if ( ! $category_number );
			next if ( exists $compare_category_rating{ $category_number } );
			
			$compare_category_rating{ $category_number } = 'G';
		}


	&CompareSetup( $dbh, $local_company, $remote_company, \%compare_category_rating, \%compare_category_name, \%local_category_rating );
	

	# Query the Statistics database for the right time period
    my $str = "SELECT Host, Url FROM TrafficClassUrlInternalIpAddress";
	
	if ( ( $old_time )  &&  ( $new_time ) )
		{	$str = "SELECT Host, Url FROM TrafficClassUrlInternalIpAddress WHERE [Time] >= \'$old_time\' AND [Time] <= \'$new_time\'";
		}
	
	print "Statistics Query: $str\n";
	
    $sthStats = $dbhStats->prepare( $str );
	$sthStats->execute();
	

	&SqlCompare();
		
	$sthStats->finish();
	
	
	&CompareClose( $dbh );
	
	
	print "Setting the URL counts for each entry ...\n";
	while ( my ( $root, $url_count ) = each( %root_domain ) )
		{	next if ( ! $root );
			next if ( ! $url_count );
			
			&CompareUpdateUrlCount( $dbh, $root, $url_count );
		}
	
	
	$dbhStats->disconnect if ( $dbhStats );
	$dbh->disconnect if ( $dbh );
	
	
	foreach ( @new_categories )
		{	next if ( ! $_ );
			
			my $web_catnum = $_;
			
			print "Found new Websense category $web_catnum\n";
		}
	
	print "Returned $total_urls URLs from the Statistics query\n";

	print "Done.\n";

exit;

}
exit;



################################################################################
# 
sub DateFormat( $ )
#
#  Return True if the date format matches MM/DD/YYYY  
#
################################################################################
{	my $date = shift;
	return( undef ) if ( ! $date );
	
	my ( $mon, $day, $year ) = split /\//, $date, 3;
	return( undef ) if ( ! $mon );
	return( undef ) if ( ! $day );
	return( undef ) if ( ! $year );
	
	return( undef ) if ( length( $mon ) != 2 );
	return( undef ) if ( length( $day ) != 2 );
	return( undef ) if ( length( $year ) != 4 );
	
	$mon = 0 + $mon;
	return( undef ) if ( ( $mon < 1 )  ||  ( $mon > 12 ) );
	return( undef ) if ( ( $day < 1 )  ||  ( $day > 31 ) );
	return( undef ) if ( ( $year < 2007 )  ||  ( $year > 2100 ) );

	return( 1 );
}



################################################################################
# 
sub SqlCompare()
#
#  Compare the contents of the 3 main tables in the remote IpmContent database  
#  to the local IpmContent database
#
################################################################################
{
	my $str;
	my $sth;
	my $count	= 0 + 0;
	my $lookup	= 0 + 0;


	if ( ! open( OUTPUT, ">$output_file_name" ) )
		{	print "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	print "Opened file $output_file_name for output\n";
	
	
	while ( my ( $url, $remote_category ) = &CompareNext() )
		{	last if ( ! defined $url );
			next if ( ! $url );
			next if ( ! $remote_category );
			
			# If I don't have a category name and rating then make one up ...
			if ( ! defined $compare_category_name{ $remote_category } )
				{	print "Undefined name for category number $remote_category\n";
					$compare_category_name{ $remote_category } = "websense.undefined-$remote_category";
					$compare_category_rating{ $remote_category } = 'G';
					
					# Keep track of the new category ...
					push @new_categories, $remote_category;
				}
				
			$lookup++;
			
			print "URL: $url, Category: $remote_category\n" if ( $opt_verbose );
			
			# Figure out what the type is
			my $type_name = "Domains";
			$type_name = "URLs" if ( $url =~ m/\// );
			$type_name = "IP addresses" if ( &IsIPAddress( $url ) );
					
			my $type_number = 2;
			$type_number = 1 if ( $type_name eq "Domains" );
			$type_number = 3 if ( $type_name eq "IP addresses" );
			
			my $lookupType = &LookupUnknown( $url, 0 );
			if ( $lookupType )
				{	my ( $category_number, $source_number ) = &FindCategory( $url, $lookupType );
					&CompareSave( $dbh, $type_number, $url, $category_number, $remote_category );			
					&ShowLookup( $type_name, $count, $lookup );
					next;	
				}
					
					
			# Save to the compare database as local Unknown		
			&CompareSave( $dbh, $type_number, $url, 0 + 200, $remote_category );
					
			print OUTPUT "$url\n";
					
			$count++;
			
			# Keep track of the unknown domains
			my $root = &RootDomain( $url );
			$unknown_domains{ $root } = $url;
			
			&ShowCounter( $type_name, $count, $lookup );
		}
	
	close( OUTPUT );	
	
	print "Looked up and compared $lookup URLs\n";
	
	return( 1 );
}



################################################################################
# 
sub CompareNext()
#
#  Return the next URL and category number to compare.  
#  Return undef, undef if all done
#  Return a category of 0 if nothing on this line
#  Do all the parsing of the input file here
#
################################################################################
{
	return( undef, undef ) if ( $dbhStats->err );
	
	my ( $host, $url_ext ) = $sthStats->fetchrow_array();
	return( undef, undef ) if ( ! defined $host );
	$total_urls++;
	
	my ( $clean_host, $port ) = split /\:/, $host, 2;
	return( "nothing", 0 + 0 ) if ( ! $clean_host );

	# Drop any trailing /'s
	$clean_host =~ s/\/+$//;
	return( "nothing", 0 + 0 ) if ( ! $clean_host );
	
	my $url = $clean_host . $url_ext;
	my $clean_url = &CleanUrl( $url );
	return( "nothing", 0 + 0 ) if ( ! $clean_url );
	
	my $root = &RootDomain( $clean_url );
	return( "nothing", 0 + 0 ) if ( ! $root );

	# Have I already checked this root?
	if ( exists $root_domain{ $root } )
		{	my $count = $root_domain{ $root };
			$count++;
			$root_domain{ $root } = $count;

			# Is this one of the unknown domains?  If so, then keep track of the actual url
			if ( exists $unknown_domains{ $root } )
				{	print OUTPUT "$url\n";
				}
				
			return( "nothing", 0 + 0 );
		}
		
	$counter++;
	print "Checking # $counter, Root $root, URL $clean_url ...\n";

	my $socket = IO::Socket::INET->new( Proto => 'tcp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
	
	if ( ! defined $socket )
		{	my $err = $!;
			$err = "unknown" if ( ! $err );
			&lprint( "Unable to open socket: $err\n" );
			
			$connect_errors++;
			
			if ( $connect_errors > 10 )
				{	print "Got 10 connect errors in a row so quitting ...\n";
					return( undef, undef );
				}
				
			sleep( 10 );

			# Now try to open it again
			$socket = IO::Socket::INET->new( Proto => 'tcp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
			
			# If I couldn't open it the second time, try another URL
			return( "nothing", 0 + 0 ) if ( ! defined $socket );
		}
	
	$connect_errors = 0 + 0;	
	
	# Keep track that I have queried for this root
	$root_domain{ $root } = 0 + 1;

	print "Opened socket for query ...\n" if ( $opt_debug );
	
	&WebsenseQueryAsync( $socket, $clean_url, $counter );
	
	my $resp_url, 
	my $websense_category;
	my $loop_count = 0 + 0;
	while ( ( ! $resp_url )  &&  ( $loop_count < 1000 ) )
		{	( $resp_url, $websense_category ) = &WebsenseResponseAsync( $socket );
		
			$loop_count++;
			&CPUSleep();
		}
	
	if ( ! $resp_url )
		{	print "No response from Websense server, so skipping $clean_url\n";	
			return( "nothing", 0 + 0 );
		}
		
	if ( $resp_url ne $clean_url )
		{	print "Mixed up response, response URL $resp_url\n";	
			return( "nothing", 0 + 0 );
		}
		
	return( $root, $websense_category );
}



################################################################################
# 
sub CPUSleep()
#
#	A time slice is available to sleep to slow down scanning - so sleep if necessary
#
################################################################################
{
	# Sleep for a few milliseconds
	my $sleep_time = 0 + 10;
	
	my $sleep_event = Win32::Event->new();
	return if ( ! $sleep_event );
						
	$sleep_event->wait( $sleep_time );
	$sleep_event->reset;
}



################################################################################
# 
sub ShowCounter()
#
#  Show a progress counter 
#
################################################################################
{	my $type	= shift;
	my $count	= shift;
	my $lookup	= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $count ) ||  ( ! $lookup ) );
	
	my $int = 10000 * sprintf( "%d", ( $count / 10000 ) );
	
	return( undef ) if ( $int != $count );
	
	print "Type: $type - looked up $lookup total, found $count missing so far ...\n";
	
	return( 1 );
}



################################################################################
# 
sub ShowLookup()
#
#  Show a lookup progress counter 
#
################################################################################
{	my $type	= shift;
	my $count	= shift;
	my $lookup	= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $count ) ||  ( ! $lookup ) );
	
	my $int = 100000 * sprintf( "%d", ( $lookup / 100000 ) );
	
	return( undef ) if ( $int != $lookup );
	
	print "Type: $type - looked up $lookup total, found $count missing so far ...\n";
	
	return( 1 );
}



################################################################################
# 
sub WebsenseQueryAsync( $$$ )
#
#  Given a socket, a url, and an ID number, query a Websense server for the
#  URL category.  Return undef if an error, or the Websense category number if OK.
#
################################################################################
{	my $socket	= shift;
	my $url		= shift;
	my $id		= shift;
	
	$query{ $id } = $url;

	$url = "http://" . $url if ( ! ( $url =~ m/http\:\/\//i ) );
	$url = $url . "/" if ( ! ( $url =~ m/\/$/ ) );
	
	# Lookup size if the 16 bytes for the lookup request, 2 bytes for the urls length, the url, 2 bytes for the user length (always 0) and the the user (which is null)

	my $url_length = length( $url );

	my $websense_version = 0x420;	# This is the version 4 value
#	$websense_version = 0x0001;		# This is the version 1 value
	
	# This is a request header - Service Type, Reserved, internal IP, External IP, URL length, URL, UserName Length(0), Username(0)
	my $request_header = pack( "nnNNn", 1, 0, 0, 0, $url_length );

	# Lookup size if the size of the request header, plus the size of the url, plus 2 bytes for the the size of the user name
	my $lookup_size = length( $request_header ) + $url_length + 2;

	my $total_size = 12 + $lookup_size;

	# 0x420 is the WS API version, 0x83 is the URL extended lookup
	my $header = pack( "nnnnN", $total_size, $websense_version, 0x83, 0, $id );

	my $request = $header . $request_header . $url . "\x00\x00";

	if ( $opt_debug )
		{	print "Request lookup size: $lookup_size\n";
			my $len = length( $request_header );
			print "Request header size: $len\n";
			print "Request total size: $total_size\n";
			print "Request ID: $id\n";
			print "Request URL: $url\n";
			
			my $hex = &HexPrint( $header );
			print "Header (Hex): $hex\n" if ( $hex );
			
			$hex = &HexPrint( $request_header );
			print "Request Header (Hex): $hex\n" if ( $hex );
			
			$hex = &HexPrint( $request );
			print "Full Request (Hex): $hex\n" if ( $hex );
			
		}
		
	print $socket $request;

	return( undef );
}



################################################################################
# 
sub HexPrint( $ )
#
################################################################################
{	my $val = shift;
	
	return( undef ) if ( ! defined $val );
	
	my @chars = split //, $val;

	my $str;
	foreach ( @chars )
		{	my $ch = $_;
			next if ( ! defined $ch );
			
			my $hex = &StrToHex( $ch );
			next if ( ! defined $hex );
			
			$str .= " " . $hex if ( defined $str );
			$str = $hex if ( ! defined $str );
		}

	return( $str );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
# 
sub WebsenseResponseAsync( $ )
#
#  Given a socket, return the url and the websense category if a response is waiting.
#  Return undef, undef if nothing is there
#
################################################################################
{	my $socket = shift;

	# Is it ready for reading?
	my $rin ="";
	my $rout;
	vec( $rin, fileno( $socket ), 1 ) = 1;
	return( undef, undef ) if ( select( $rout=$rin, undef, undef, 0 ) == 0 );

	my $data_len;
	
	my $num_read = 0 + 0;
	while ( ! $num_read )
		{	$num_read = read( $socket, $data_len, 2 );
			return( undef, undef ) if ( ! defined $num_read );
		}
	
	print "Response read length: $num_read\n" if ( $opt_debug );
	
	my $response_len = unpack( "n", $data_len );
	print "Response length: $response_len\n" if ( $opt_debug );

	my $data;
	$num_read = read( $socket, $data, $response_len - 2 );
	
	my $response = $data_len . $data;
	
	if ( $opt_debug )
		{	my $hex = &HexPrint( $response );
			print "Response (Hex): $hex\n" if ( $hex );
		}
		
	# 0x420 is the WS API version, 0x83 is the URL extended lookup
	my $response_header  = substr( $response, 0, 12 );

	# Unpack the header
	my ( $resp_len, $version, $messageType, $bitMap, $id  ) = unpack( "nnnnN", $response_header );
	print "Response header length: $resp_len\n" if ( $opt_debug );
	print "Response ID: $id\n" if ( $opt_debug );

	my $len = $response_len - 12;
	my $response_value  = substr( $response, 12, $len );
	return( undef ) if ( ! defined $response_value );
	
	my $value_length = length( $response_value );
	print "Response value length: $value_length\n" if ( $opt_debug );
	
	return( undef ) if ( $value_length < 6 );
	
	my ( $lookupStatus, $lookupDescriptionCode, $categoryNumber ) = unpack( "nnnn", $response_value );
	print "Response lookup status: $lookupStatus\n" if ( $opt_debug );
	print "Response description code: $lookupDescriptionCode\n" if ( $opt_debug );
	print "Response Websense category number $categoryNumber\n" if ( $opt_debug );

	my $url = $query{ $id };
	
	# Delete the query from the hash
	delete $query{ $id };

	return( $url, $categoryNumber );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "WebsenseCompare";

    print <<".";
Syntax: WebsenseCompare IP [START] [END] [OUTPUT]

WebsenseCompare compares the local IpmContent database to a Websense server,
and saves any missing entries to OUTPUT.  IP is the IP address of the
Websense server to query.  START and END are the starting and ending dates 
in the format MM/DD/YYYY for the URLs to compare.  If START and/or END
is ommitted then the entire TrafficClassUrlInternalIpAddress table will
be used.  The option OUTPUT is the list of URLs that were unknown to the 
local IpmContent database.  The default name for OUTPUT is 
WebsenseCompare.txt.

  -p, --port PORT      TCP port to query Websense on, default is 15888
  -o, --output OUTPUT  output file to write the local unknown URLs to
  -h, --help           show this help
.

    exit( 1 );
}



__END__

:endofperl
