################################################################################
#!perl -w
#
#  Rob McCarthy's Websense query source code
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################


use warnings;
use strict;


use Getopt::Long;
use IO::Handle;
use IO::Socket;
use Cwd;
use Benchmark;
use Sys::Hostname;
use Net::DNS;
use Cwd;


use Content::File;
use Content::SQL;
use Content::Process;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_debug;		 			# If True then don't over write existing files
my $opt_existing;				# True if run from a Wizard dialog
my $opt_tcp = 1;				# True if I should use TCP instead of UDP
my $opt_verbose;				# True if I should use verbose messages
my $opt_name;					# If True then reset the category names in the database to match this program
my $opt_overwrite = 1;			# If True then overwrite existing entries in the database
my $opt_list;					# If True then just list the Websense category names
my $opt_log_file;				# The name of the log file to use
my $opt_ip_file;				# If true, then create a file if IP addresses
my $opt_dns_lookup;				# If True then do a DNS lookup for each domain before checking it

my $connect_errors = 0 + 0;		# The number of socket connect errors total

my $_version = "1.0.0";
my %query;						# A hash of outstanding queries
my $max_queue_size	= 0 + 100;	# The maximum depth of the UDP queue

my $max_sockets		= 0 + 4;
my @input_files		= ( "domains", "urls" );
my $server_ip		= "10.16.43.13";	# Todd's test machine is "10.16.3.15", nonsense server is "10.16.43.13"
my $port_no			= 55806;

my $unknown			= "Websense.unknown";
my $unknown_handle;

my $known			= "Websense.known";
my $known_handle;

my $block			= "Websense.blocked";
my $block_handle;

my $dbh;						# A handle to the local IpmContent database
my $source = 0 + 3;				# Source number to use for adding rows
my $opt_no_database;			# If true then don't use the database
my $my_pid;						# My process ID
my $log_directory				= 'C:\\Content\\Log';		# This is the directory to write the logs to



# This hash is a mapping between the Websense category number, the equivalent Lightspeed category name,
# and the Websense sub category (if it exists)
my %websense_names =
(
 "2"	=> "business\tbusiness_and_economy",
 
 "10"	=> "society.politics\tabortion",
 "92"	=> "society.politics\tabortion.pro-choice",
 "93"	=> "society.politics\tabortion.pro-life",
 
 "65"	=> "porn\tadult_material.nudity",
 "66"	=> "adult\tadult_material.adult_content",
 "67"	=> "porn\tadult_material.sex",
 "94"	=> "education.sex\tadult_material.sex_education",
 "95"	=> "adult\tadult_material.lingerie_and_swimsuit",
 
 "11"	=> "society\tadvocacy_groups",
 
 "114"	=> "audio-video\tbandwidth_pg.internet_radio_and_tv",
 "108"	=> "audio-video\tbandwidth_pg.internet_telephony",
 "115"	=> "forums.p2p\tbandwidth_pg.peer_to_peer_file_sharing",
 "113"	=> "audio-video\tbandwidth_pg.personal_network_storage_and_backup",
 "109"	=> "audio-video\tbandwidth_pg.streaming_media",
 
 "68"	=> "finance\tbusiness_and_economy.financial_data_and_services",
 
 "90"	=> "drugs\tdrugs.abused_drugs",
 "88"	=> "health\tdrugs.prescribed_medications",
 "89"	=> "health\tdrugs.suppliments_and_unregulated_compounds",
 "111"	=> "drugs\tdrugs.marijuana",

 "69"	=> "society\teducation.cultural_institutions",
 "97"	=> "education\teducation.educational_institutions",
 "118"	=> "education\teducation.educational_materials",
 "121"	=> "education\teducation.reference_materials",

 "12"	=> "entertainment",
 "70"	=> "entertainment.audio-video\tentertainment.mp3_and_audio_download_services",
 
 "13"	=> "gambling",
 
 "14"	=> "games",

 "4"	=> "government",
 "72"	=> "government\tgovernment.military",
 "73"	=> "society.politics\tgovernment.political_organizations",
 
 "27"	=> "family.health\thealth",
 
 "15"	=> "adult\tillegal_or_questionable",
 
 "9"	=> "computers\tinformation_technology",
 "28"	=> "search\tinformation_technology.url_translation_sites",
 "76"	=> "search\tinformation_technology.search_engines_and_portals",
 "78"	=> "forums.personals\tinformation_technology.web_hosting",
 "80"	=> "security.hacking\tinformation_technology.hacking",
 "138"	=> "computer\tinformation_technology.computer_security",
 "75"	=> "security.proxy\tinformation_technology.proxy_avoidance",
 
 "74"	=> "forums.mail\tinternet_communications.web_based_email",
 "79"	=> "forums.chat\tinternet_communications.web_chat",
 
 "16"	=> "jobs\tjob_search",
 
 "25"	=> "society.politics\tmilitancy_and_extremist",
 
 "150"	=> "computers\tmiscellaneous.content_delivery_networks",
 "156"	=> "computers\tmiscellaneous.file_download_servers",
 "148"	=> "computers\tmiscellaneous.image_servers",
 "149"	=> "general\tmiscellaneous.uncategorized",
 "146"	=> "general\tmiscellaneous.dynamic_content",
 "172"	=> "general\tmiscellaneous.images",
 "151"	=> "access-denied\tmiscellaneous.private_ip_addresses",
 "152"	=> "expired\tmiscellaneous.network_errors",
 "153"	=> "unknown\tmiscellaneous.uncategorized",
 
 "5"	=> "news\tnews_and_media",
 "81"	=> "news\tnews_and_media.alternate_journals",
 
 "29"	=> "ads\tproductivity_pg.advertisements",
 "96"	=> "finance\tproductivity_pg.online_brokerage_and_trading",
 "98"	=> "forums.im\tproductivity_pg.instant_messaging",
 "99"	=> "security.warez\tproductivity_pg.freeware_and_software_download",
 "112"	=> "forums\tproductivity_pg.message_boards_and_clubs",
 "100"	=> "access-denied\tproductivity_pg.pay_to_surf",
 
 "26"	=> "violence.hate\tracism_and_hate",
 
 "82"	=> "family.religion\treligion.non-traditional_religions",
 "83"	=> "family.religion\treligion.traditional_religions",
 
 "167"	=> "security.spyware\tsecurity_pg.bot_networks",
 "166"	=> "security.spyware\tsecurity_pg.keyloggers",
 "128"	=> "security.virus\tsecurity_pg.malicious_web_sites",
 "164"	=> "security.phishing\tsecurity_pg.phishing_and_other_frauds",
 "165"	=> "security.spyware\tsecurity_pg.potentially_unwanted_software",
 "154"	=> "security.spyware\tsecurity_pg.spyware",
 
 "17"	=> "shopping",
 "101"	=> "shopping.auctions\tshopping.internet_auctions",
 "102"	=> "real_estate\tshopping.real_estate",
 
 "125"	=> "society\tsocial_organizations.professional",
 "123"	=> "society\tsocial_organizations.service",
 "124"	=> "society\tsocial_organizations.social",
 
 "7"	=> "education.lifestyles\tsociety_and_lifestyles",
 "87"	=> "alcohol\tsociety_and_lifestyles.alcohol_and_tobacco",
 "85"	=> "adult.lifestyles\tsociety_and_lifestyles.gay_or_lesbian_or_bisexual_interest",
 "86"	=> "forums.personals\tsociety_and_lifestyles.personals_and_dating",
 "84"	=> "family.food\tsociety_and_lifestyles.restaurants_and_dining",
 "103"	=> "hobby\tsociety_and_lifestyles.hobbies",
 "117"	=> "forums.personals\tsociety_and_lifestyles.personal_web_sites",
 
 "8"	=> "general\tspecial_events",

 "18"	=> "sports",
 "107"	=> "weapons\tsports.sport_hunting_and_gun_clubs",
 
 "19"	=> "adult\ttasteless",

 "20"	=> "travel",
 "21"	=> "automobile\tvehicles",
 "22"	=> "violence",
 "23"	=> "violence.weapons\tweapons",

 "200"	=> "websense.unknown",
 "195"	=> "websense.no_idea",
 "196"	=> "websense.no_idea_as_well",
 
 "3"	=> "general\tunlisted_tests"
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
		"a|aaa"			=> \$opt_ip_file,
        "d|dns"			=> \$opt_dns_lookup,
		"e|existing"	=> \$opt_existing,
        "i|ip=s"		=> \$server_ip,
        "l|list"		=> \$opt_list,
        "n|name"		=> \$opt_name,
		"q|queue=i"		=> \$max_queue_size,
		"o|overwrite"	=> \$opt_overwrite,
		"p|port=i"		=> \$port_no,
		"s|sockets=i"	=> \$max_sockets,
		"t|tcp"			=> \$opt_tcp,
		"u|udp"			=> sub { $opt_tcp = undef; },
        "v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help,
        "x|xxx"			=> \$opt_debug
    );


	if ( $opt_ip_file )
		{	my $start_ip = shift;
			my $end_ip = shift;
			my $file = shift;
			&CreateIPFile( $start_ip, $end_ip, $file );
			exit( 0 );
		}
		
	if ( $opt_list )
		{	&WebsenseCategoryList();
			exit( 0 );
		}
		
	print "Websense query server IP $server_ip port $port_no\n";
	
    &Usage() if ($opt_help);
	
	
	# Did I get any files on the command line?  If so, then overwrite the default list
	my @temp_list;
	while ( my $file = shift )
		{	next if ( ! $file );
			push @temp_list, $file;
		}
	
	@input_files = @temp_list if ( $#temp_list > -1 );
	
	
	my $hostname = hostname;
	print "The local hostname is $hostname\n" if ( $hostname );
	
	if ( ( ! $opt_debug )  &&  ( ! $opt_no_database )  &&  ( ( ! $hostname )  ||  ( $hostname ne "nonsense" ) ) )
		{	print "This application will only run on \"nonsense\"\n";
			die;
		}
		
		
	if ( $opt_existing )
		{	die "Existing files\n" if ( ( -e $unknown )  ||  ( -e $block )  ||  ( -e $known ) );  
		}
		
		
	$my_pid = &ProcessGetCurrentProcessId();
	
	
	mkdir( $log_directory );
	$opt_log_file = "$log_directory\\Websense-$my_pid.log" if ( ! defined $opt_log_file );

	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;

	# Does the opt_logfile include a pathname?  If not, use the current directory
	if ( ! ( $opt_log_file =~ m/\\/ ) )
		{	$opt_log_file = $dir . "\\" . $opt_log_file if ( defined $dir );
		}



	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );
				
	
	&SetLogFilename( $opt_log_file, undef ) if ( ! $opt_debug );
	
	
	lprint "Using UDP protocol ...\n" if ( ! $opt_tcp );
	lprint "Using TCP protocol ...\n" if ( $opt_tcp );
	

    #  Open the database
	if ( ! $opt_no_database )
		{	$dbh = &ConnectServer() or die;
			if ( ! &SqlTableExists( "DomainIPAddress" ) )
				{	print "Database table DomainIPAddress does not exist!\n";
					
					if ( $dbh )
						{	$dbh->disconnect;
							$dbh = undef;
						}
						
					die;	
				}
				
			# Reset the category names to the right ones for Websense
			if ( $opt_name )
				{	&ResetCategoryNames();	
					$dbh->disconnect;
					exit( 0 );
				}
				
			&LoadCategories();
		}
	else	# Can't overwrite the database if I have opened the database
		{	$opt_overwrite = undef;
		}


	# Open all the logging files
	open( $unknown_handle,	">$unknown" )	or die "Unable to open file $unknown: $!\n";
	$unknown_handle->autoflush( 1 );
	
	open( $known_handle,	">$known" )		or die "Unable to open file $known: $!\n";
	$known_handle->autoflush( 1 );
	
	open( $block_handle,	">$block" )		or die "Unable to open file $block: $!\n";
	$block_handle->autoflush( 1 );
	
	
	lprint "Current directory = $dir\n";
	
	
	# Keep track of how long it takes to categorize
	my $start = new Benchmark;
	
	# Categorize any files found
	foreach ( @input_files )
		{	next if ( ! $_ );
			my $file = $_;
			
			my $full_file = "$dir\\$file";
			
			&WebsenseCategorizeUDP( $full_file ) if ( ! $opt_tcp );
			&WebsenseCategorizeTCP( $full_file ) if ( $opt_tcp );
		}
		
	# Calc the benchmark statistics
	my $finish = new Benchmark;
	

	close( $unknown_handle );
	close( $known_handle );
	close( $block_handle );
	
	
	# If the database handle has been created, disconnect it
	if ( $dbh )
		{	$dbh->disconnect;
			$dbh = undef;
		}
		

	# Write out an OK file so the the controlling task knows that everything is OK
	my $finished_log_file = "$log_directory\\Websense-$my_pid.OK";
	open( FINISHED, ">$finished_log_file" );      	   
	print FINISHED "Done\n";
	close( FINISHED );


	my $diff = timediff($finish, $start);
	my $strtime = timestr( $diff );
	$strtime =~ s/^\s*//;	# Trim off any leading spaces

	lprint "Benchmark = $strtime\n";

exit;
}
################################################################################



################################################################################
# 
sub CreateIPFile( $$$ )
#
#  Create a file of IP addresses
#
################################################################################
{	my $start_ip	= shift;
	my $end_ip		= shift;
	my $file		= shift;
	
	if ( ( ! $start_ip )  ||  ( ! $end_ip )  ||  ( ! $file ) )
		{	print "You need to enter the start IP, end IP, and file name to create\n";
			return;
		}
	
	if ( ! &IsIPAddress( $start_ip ) )
		{	print "$start_ip is not a valid IP address\n";
			return;
		}

	if ( ! &IsIPAddress( $end_ip ) )
		{	print "$end_ip is not a valid IP address\n";
			return;
		}

	if ( ! open( IPFILE, ">$file" ) )
		{	print "Can't open file $file: $!\n";
			return;
		}
		
	my $s_ip = &StringToIP( $start_ip );
	$s_ip = unpack( "N", $s_ip );
	
	my $e_ip = &StringToIP( $end_ip );
	$e_ip = unpack( "N", $e_ip );
	
	for ( my $i = $s_ip;  $i <= $e_ip;  $i++ )
		{	my $ip = pack( "N", $i );
			
			my $str_ip = &IPToString( $ip );
			
			next if ( ! &IsValidIP( $str_ip ) );

			print IPFILE "$str_ip\n";
		}
	
	close( IPFILE );	
}



################################################################################
# 
sub WebsenseCategoryList()
#
#  Write out the list of Websense Categories
#
################################################################################
{
	my @category_numbers = keys %websense_names;
	
	print "Websense Categories in Numerical Order\n\n";

	my @catnum;
	foreach ( @category_numbers )
		{	my $catnum = $_;
			next if ( ! $catnum );
			
			$catnum = 0 + $catnum;
			
			my $catstr = sprintf( "%03d", $catnum );
			push @catnum, $catstr;
		}
		
	my @sorted = sort @catnum;
	
	my %names;
	foreach ( @sorted )
		{	my $catnum = $_;
			next if ( ! $catnum );
			$catnum = 0 + $catnum;
			
			my $value = $websense_names{ $catnum };
			
			my ( $lightspeed, $websense ) = split /\t/, $value;
			$websense = $lightspeed if ( ! $websense );
			$websense = lc( $websense );
			
			print "$catnum\t$websense\n";
			
			$names{ $websense } = $catnum;
		}

	print "\n\nWebsense Categories in Alphabetical Order\n\n";

	@sorted = sort keys %names;
	foreach ( @sorted )
		{	my $websense = $_;
			next if ( ! $websense );
	
			my $catnum = $names{ $websense };
			print "$websense\t$catnum\n";
		}	
}



################################################################################
# 
sub WebsenseCategorizeUDP( $ )
#
#  Given a file that contains a list of urls, query the Websense server and write
#  the results out to some text files using the UDP protocol
#
################################################################################
{	my $file = shift;
	
	if ( ( ! -e $file )  ||  ( ! -s $file ) )
		{	lprint "Can not read file $file: $!\n";
			return( undef );	
		}
	
	open( INPUT, "<$file" ) or die "Unable to open $file: $!\n";
	
	lprint "Processing file $file ...\n";
	
	my $socket;
	my $counter = 0 + 0;
	
	
	# Make sure the socket is open
	if ( ! defined $socket )
		{	lprint "Opening UDP socket ...\n";
			$socket = IO::Socket::INET->new( Proto => 'udp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
			die "Unable to open socket: $!\n" if ( ! defined $socket );
		}
				
				
	# Loop through reading the list of urls and getting the Websense category
	my $done;
	my $queue_size;
	while ( ! $done )
		{	# Do I have room in the queue for another query?
			$queue_size = keys %query;
			
			if ( $queue_size < $max_queue_size )
				{	if ( my $line = <INPUT> )
						{	chomp( $line );
							next if ( ! $line );
							
							# Split off any category numbers, etc that are after a tab character
							my ( $url, $junk ) = split /\t/, $line, 2;
							next if ( ! $line );
							
							$url = &CleanUrl( $url );
							
							next if ( ( ! defined $url )  ||  ( $url eq "" ) );
							
							if ( $opt_dns_lookup )
								{	my ( $host, @ipaddresses ) = &URLIPAddresses( $url );
							
									&WriteIPAddresses( $host, \@ipaddresses );
									
									# Switch to the host if I found IP addresses
									$url = $host if ( $host );
								}
								
							$counter++;
							
							print "Checking # $counter, $url ...\n";
							
							&WebsenseQueryAsync( $socket, $url, $counter );
						}
					else
						{	$done = 1;
						}
				}
			
			
			while ( my ( $resp_url, $websense_category ) = &WebsenseResponseAsync( $socket ) )
				{	last if ( ! defined $websense_category );
					
					if ( $resp_url )
						{	print "Response $resp_url ...\n";
							&WriteCategory( $resp_url, $websense_category );
						}
				}
		}


	# Wait for the last queries to finish
	print "Waiting for the last queries to finish ...\n";
	$done = undef;
	
	while ( $queue_size )
		{	while ( my ( $resp_url, $websense_category ) = &WebsenseResponseAsync( $socket ) )
				{	if ( ! defined $websense_category )
						{	sleep( 1 );
							next;
						}
					
					if ( $resp_url )
						{	print "Response $resp_url ...\n";
							&WriteCategory( $resp_url, $websense_category );
						}
						
					$queue_size = keys %query;
					last if ( ! $queue_size );
				}
		}
		
				
	lprint "Shutting down socket ...\n";
	$socket->shutdown( 2 );
							
	lprint "Checked $counter URLs from file $file\n";
	
	close INPUT;
}



################################################################################
# 
sub WebsenseCategorizeTCP( $ )
#
#  Given a file that contains a list of urls, query the Websense server and write
#  the results out to some text files using the TCP protocol
#
################################################################################
{	my $file = shift;
	
	if ( ( ! -e $file )  ||  ( ! -s $file ) )
		{	lprint "Can not read file $file: $!\n";
			return( undef );	
		}
	
	
	open( INPUT, "<$file" ) or die "Unable to open $file: $!\n";
	
	lprint "Processing file $file ...\n";
	
	my $counter = 0 + 0;
	my @socket_list;
	my $socket;
	
				
	# Loop through reading the list of urls and getting the Websense category
	my $done;
	my $queue_size;
	my $socket_num = 0 + 0;
	my $dead_socket_count = 0 + 0;
	my @ip;		# This is a list of IP addresses to lookup in Websense if I am checking DNS
	
	while ( ! $done )
		{	# Do I have room in the queue for another query?
			if ( $#socket_list <= $max_sockets )
				{	my $line = pop @ip;
					
					$line = <INPUT> if ( ! $line );
					
					if ( defined $line )
						{	chomp( $line );
							next if ( ! $line );
							
							my ( $url, $junk ) = split /\t/, $line, 2;
							next if ( ! $url );
							
							$url = &CleanUrl( $url );
							
							next if ( ( ! defined $url )  ||  ( $url eq "" ) );
							
							# If I'm not overwriting the database - do I already know this url?
							if ( ! $opt_overwrite )
								{	my $retcode = &LookupUnknown( $url, 0 );
									if ( $retcode )
										{	print "Already know $url\n";
											next;
										}
								}
							
							if ( $opt_dns_lookup )	
								{	my ( $host, @ipaddresses ) = &URLIPAddresses( $url );
							
									&WriteIPAddresses( $host, \@ipaddresses );
									
									# Add the IP addresses to be lookup up if the host is not an IP address
									push @ip, @ipaddresses if ( ! &IsIPAddress( $host ) );
									
									# Switch to the host if I found IP addresses
									$url = $host if ( $host );
								}
								
							$counter++;

							$socket = IO::Socket::INET->new( Proto => 'tcp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
							
							if ( ! defined $socket )
								{	my $err = $!;
									$err = "unknown" if ( ! $err );
									&lprint( "Unable to open socket: $err\n" );
									
									$connect_errors++;
									
									if ( $connect_errors > 10 )
										{	print "Got 10 connect errors in a row ...\n";
											die;
										}
									sleep( 10 );

									# Now try to open it again
									$socket = IO::Socket::INET->new( Proto => 'tcp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
									
									# If I couldn't open it the second time, try another URL
									next if ( ! defined $socket );
								}
							
							$connect_errors = 0 + 0;	
							push @socket_list, $socket;
							
							print "Checking # $counter, $url ...\n";
							&WebsenseQueryAsync( $socket, $url, $counter );
						}
					else
						{	$done = 1;
						}
				}
			
			
			# Did any of my queries finish?
			my $work_done;
			for ( my $socket_num = 0 + 0;  $socket_num <= $#socket_list;  $socket_num++ )
				{	my $socket = $socket_list[ $socket_num ];
					
					next if ( ! $socket );
					
					my $count = 0 + 0;
					while ( my ( $resp_url, $websense_category ) = &WebsenseResponseAsync( $socket ) )
						{	last if ( ! defined $websense_category );
							
							if ( $resp_url )
								{	print "Response $resp_url ...\n";
									&WriteCategory( $resp_url, $websense_category );
									$count++;
								}
						}
						
					# Did I get a response?
					if ( $count )
						{	$socket_list[ $socket_num ] = 0 + 0;
							$socket->shutdown( 2 );	
							$socket->close;
							
							$work_done++;
						}
				}
				
				
			# Repack the socket list
			my @new_socket_list;
			
			foreach ( @socket_list )
				{	next if ( ! $_ );
					push @new_socket_list, $_;
				}
				
			@socket_list = @new_socket_list;	
			
			
			# Are my sockets dying off?
			if ( $work_done )
				{	$dead_socket_count = 0 + 0;
				}
			else
				{	$dead_socket_count++;
					sleep( 1 );
					if ( $dead_socket_count > 10 )
						{	print "Quiting because I've got too many dead sockets!\n";
							$done = 1;
						}
				}
		}


	# Wait for the last queries to finish
	my $query_count = $#socket_list + 1;
	
	print "Waiting 10 seconds for the last $query_count queries to finish ...\n" if ( $query_count );
	$done = undef;
	
	my $final_count = 0 + 0;
	for ( my $socket_num = 0 + 0;  $socket_num <= $#socket_list;  $socket_num++ )
		{	my $socket = $socket_list[ $socket_num ];			
			next if ( ! $socket );
			
			my $resp_url;
			my $websense_category;
			
			while ( ( $resp_url, $websense_category ) = &WebsenseResponseAsync( $socket ) )
				{	last if ( ! defined $websense_category );
					
					if ( $resp_url )	
						{	print "Response $resp_url ...\n";
							&WriteCategory( $resp_url, $websense_category );
						}
				}
				
			$socket_list[ $socket_num ] = 0 + 0;
			$socket->shutdown( 2 );	
			
			# Don't wait too long for an answer
			$final_count++;
			last if ( $final_count > 10 );
			sleep( 1 );
		}
		
					
							
	lprint "Checked $counter URLs from file $file\n";
	
	close INPUT;
}



################################################################################
# 
sub WriteCategory( $$ )
#
#  Given a url, and it's Websense category, write it to the appropriate file(s)
#  based on how it compares with Lightspeed
#
################################################################################
{	my $url					= shift;
	my $websense_category	= shift;
	
	lprint "URL = $url, Websense category number = $websense_category\n" if ( $opt_debug );
	
	my ( $lightspeed_equiv, $websense_name ) = &WebsenseTranslate( $websense_category );
	
	lprint "Websense: $websense_name, Lightspeed: $lightspeed_equiv\n" if ( $opt_debug );
	
	if ( ( $websense_category )  &&  ( $websense_category == 153 ) )
		{	print "$url - Unknown\n";
			print $unknown_handle "$url\n";
		}
	else
		{	# Does one or the other have this blocked?  If so, there might be something seriously wrong
			my $blocked = 1 if ( "porn gambling spam adult forums drugs phishing games spyware virus weapons" =~ m/$lightspeed_equiv/ );
			$blocked = 1 if ( "porn gambling spam adult forums drugs phishing games spyware virus weapons" =~ m/$websense_name/ );
			
			print $block_handle "$url\t$websense_category\t$websense_name\n" if ( $blocked );
			print $known_handle "$url\t$websense_category\t$websense_name\n";
			
			print "$url - $websense_name\n";
		}


	# Quit here if I'm not saving to the local IpmContent database	
	return( 1 ) if ( $opt_no_database );

	
	# Make sure that if it is an IP address that it is valid
	my ( $domain, $url_ext ) = split /\//, $url, 2;

	$domain = &TrimWWW( $domain );		# Trim off any www
	
	if ( &IsIPAddress( $domain ) )
		{   # Check the IP address to see if it is valid
			my $valid = &IsValidIP( $domain );
			if ( ! $valid )
				{	lprint "Invalid IP address $domain\n";
					next;
				}
		}


	# Add the domain		
	my $retcode = &AddNewTrans( $domain, $websense_category, 0, $source );
	$retcode = &UpdateCategory( $domain, $websense_category, $retcode, $source ) if ( $retcode );

		
	# Add the url if it is different than the domain
	if ( $url_ext )
		{	$retcode = &AddNewTrans( $url, $websense_category, 0, $source );
			$retcode = &UpdateCategory( $url, $websense_category, $retcode, $source ) if ( $retcode );
		}
				
	return( $retcode );
}



################################################################################
# 
sub WriteIPAddresses( $$ )
#
#  Given a hostname, and an array of it's IP addresses, save it to the database
#  if the database is open
#
################################################################################
{	my $host			= shift;
	my $ip_array_ref	= shift;
	
	return( undef ) if ( $opt_no_database );
	return( undef ) if ( ! $host );
	
	my @ipaddresses = @$ip_array_ref;
	
	# Clear out the old addresses, if any
	my $root = &RootDomain( $host );
	return( undef ) if ( ! $root );
	return( undef ) if ( &IsIPAddress( $root ) );
	
	my $reverse_domain = &ReverseDomain( $root );

	my $str = "DELETE DomainIPAddress WHERE DomainName = \'$reverse_domain\'";
	my $sth = $dbh->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	my $counter = 0 + 0;
	foreach ( @ipaddresses )
		{	my $ip = $_;
			
			next if ( ! $ip );
			next if ( ! &IsValidIP( $ip ) );
			
			print "Adding IP $ip for $root to database\n";
			
			$str = "INSERT DomainIPAddress ( DomainName, IPAddress ) VALUES ( \'$reverse_domain\', \'$ip\' )";
			$sth = $dbh->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
		
	return( $counter );
}



################################################################################
# 
sub ResetCategoryNames()
#
#  Make sure that the category names in the database match the hash in this program
#
################################################################################
{	print "Setting the category names to Websense values ...\n";

	my $str = "DELETE IpmContentCategory WHERE CategoryNumber > '200'";
	my $sth = $dbh->prepare( $str );
	$sth->execute();

	$str = "SELECT CategoryNumber, CategoryName FROM IpmContentCategory ORDER BY CategoryNumber";
	$sth = $dbh->prepare( $str );
	$sth->execute();

	my $top_catnum = 0 + 0;
	while ( ( ! $dbh->err )  &&  (  my ( $catnum, $catname ) = $sth->fetchrow_array() ) )
		{	&SqlSleep();
			
			$catnum = 0 + $catnum;
			
			$top_catnum = $catnum if ( $catnum > $top_catnum );
		}
		
	$sth->finish();
	
	
	#  Add any categories necessary to reach 200
	for ( my $i = $top_catnum + 1;  $i < 201;  $i++ )
		{	my $name = "websense$i";
			
			$str = "INSERT INTO IpmContentCategory ( CategoryNumber, CategoryName, CategoryDescription, Allow, RedirectURL, CategoryType )
					VALUES ( \'$i\', \'$name\', \'$name\', '1', NULL, \'NU\' )";
			$sth = $dbh->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
	
	
	# Set the category names to the websense names
	my %categories;
	while ( my( $websense_category, $data ) = each( %websense_names ) )
		{	next if ( ! $data );
			
			$websense_category = 0 + $websense_category;
			next if ( $websense_category > 200 );
			next if ( $websense_category < 1 );
			
			my ( $lightspeed_name, $websense_name ) = split /\t/, $data;
			$websense_name = $lightspeed_name if ( ! $websense_name );
			
			$categories{ $websense_category } = $websense_name;
			
			$str = "UPDATE IpmContentCategory SET CategoryName = \'$websense_name\', CategoryDescription = NULL WHERE CategoryNumber = \'$websense_category\'";
			
			$sth = $dbh->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
	
	
	# Set any unknown websense category names to a default value
	for ( my $i = 0 + 1;  $i < 201;  $i++ )
		{	next if ( exists $categories{ $i } );
			
			my $websense_name = "websense$i";
			
			$str = "UPDATE IpmContentCategory SET CategoryName = \'$websense_name\', CategoryDescription = NULL WHERE CategoryNumber = \'$i\'";
			
			$sth = $dbh->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
		
	return( 1 );
}



################################################################################
# 
sub WebsenseTranslate( $ )
#
#  Given a Websense category number, return the equivalent Lightspeed category
#  name, and the Websense sub category, or undef if Websense does not know the URL
#
################################################################################
{	my $websense_category = shift;
	
	$websense_category = 0 + $websense_category;
	
	my $name_pair = $websense_names{ "$websense_category" };
	return( "notmapped", "$websense_category" ) if ( ! defined $name_pair );
	return( undef, undef ) if ( $name_pair eq "unknown" );
	
	my ( $lightspeed_equiv, $websense_name ) = split /\t/, $name_pair;
	$websense_name = $lightspeed_equiv if ( ! defined $websense_name );
	
	return( $lightspeed_equiv, $websense_name );
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
sub URLIPAddresses( $ )
#
#  Given a URL, return the hostname and all the IP addresses in DNS for it
#
################################################################################
{	my $url = shift;

	my $host;
	my @addresses;
	
	return( undef, @addresses ) if ( ! defined $url );
	
	my ( $domain, $url_ext ) = split /\//, $url, 2;
	$host = $domain;  # Default the host name to the domain name

	return( undef, @addresses ) if ( ! $domain );
	
	
	# Is the domain an IP address itself?  If so, return the IP address as both the host name and in the addresses array
	if ( &IsIPAddress( $domain ) )
		{	push @addresses, $domain;
			return( $domain, @addresses ) ;
		}
		
		
	my $res = Net::DNS::Resolver->new;
	
	# Wait for 16 seconds for a response
	$res->tcp_timeout( 16 );
	$res->udp_timeout( 16 );
	
	print "Querying DNS for $domain ...\n";
	my $query = $res->search( $domain ); 
	
	my $www_domain = "www.$domain" if ( ! ( $domain =~ m/^www\./ ) );
	if ( ( ! $query )  &&  ( $www_domain ) )
		{	$host = $www_domain;
	
			print "Querying DNS for $www_domain ...\n";
			$query = $res->search( $www_domain );
			$host = $www_domain;
		}
	
	if ( ! $query )
		{	my $error = $res->errorstring;
			$error = "Unknown error" if ( ! $error );
			
			# Does this domain or host exist at all?
			my $nonexisiting_domain;
			$nonexisiting_domain = 1 if ( $error eq "NXDOMAIN" );
			
			$error = "nonexisting hostname or domain: $domain and $www_domain" if ( $nonexisiting_domain );				
			print "DNS Query failed: $error\n";
			
			return( undef, @addresses );
		}
		
	foreach my $rr ( $query->answer ) 
		{	next unless $rr->type eq "A";
			my $ip = $rr->address;

			# Make sure it is a good IP address
			next if ( ! &IsValidIP( $ip ) );
			
			print "Found IP address $ip for $host\n";
			
			push @addresses, $ip;
		}
	
	if ( $#addresses < 0 )
		{	print "No valid IP addresses found for $domain\n";
			return( undef, @addresses );
		}
			
	return( $host, @addresses );	
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
sub TrapErrors( $$ )
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename base on the mode I'm running in
	my $filename = "WebsenseErrors.log";
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
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
    my $me = "Websense";

    print <<".";
Usage: $me urllist [OPTION(s)]
Websense queries a Websense server to find what it\'s database thinks the
categories are of a list of URLs.

Outputs URLs in several files:

\"Websense.block\"   are the URLs that Websense thinks are in a blocked category
\"Websense.known\"   are the URLs that Websense knows
\"Websense.unknown\" are the URLs that Websense does not know at all

Options:
  -d, --dns               to do a DNS lookup before checking each URL
  -i, --ip IP_ADDR        the IP address of the Websense server
                          default is \"$server_ip\"
  -l, --list              list the Websense category names
  -n, --name              reset the category names in the database to match
  -o, --overwrite         overwrite existing entries in the database
  -p, --port PORT         the port number to query, default is $port_no						  
  -q, --queue MAX_QUEUE   the maximum number of simultaneous UDP queries
  -s, --sockets MAX_SOCK  the maximum number of TCP socket connections
  -t, --tcp               to use TCP protocol (default is TCP)
  -u, --udp               to use UDP protocol (default is TCP)  
  -h, --help              display this help and exit
  -v, --version           display version information and exit 
.
   &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl

