################################################################################
#!perl -w
#
# IpmProxyTest - test to see if IP addresses or URLs can be used as Web or SMTP proxies
#
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;


use Getopt::Long;
use Sys::Hostname;
use Time::gmtime;
use IO::Socket;
use IO::Socket::INET;
use IO::Select;
use Net::hostent;
use Fcntl qw/:flock/;
use Net::DNS;
use Cwd;


use Content::File;
use Content::SQL;
use Content::Process;


use DBI qw(:sql_types);
use DBD::ODBC;
use Benchmark;



#  Global Options
my $opt_all;									# If True, test all possible ports
my $opt_commandline;							# True if we are reading from a command line
my $opt_version;								# True if we just want to display the version
my $_version = "5.3.0";							# File version number
my $opt_benchmark;								# True if I should benchmark the speed
my %benchtime;									# Hash of benchmark times = key is the name of the benchmark, value is the time
my $opt_override = 1;							# True if I should override the database if my source number allows it
my $opt_help;									# True if we just want to display help
my $opt_debug; 									# True if I should write to a debug log file
my $opt_wizard;									# True if I shouldn't display headers and footers
my $opt_logging = 1;							# True if I should write to a regular log file
my $opt_timeout;								# Set to the timeout value, if different than the default
my $opt_source = 0 + 3;							# The source number to use on any adds or changes
my $log_filename = "IpmProxyTest.log";			# The name of the log file to use
my $opt_exclusive;								# If True - kill any other copies of IpmProxyTest running - thisoption is used by IpmRealtimeSpam
my $opt_no_database;							# True if I could not connect to the database
my $opt_verbose;								# True if I want to display everything that is going on
my $opt_range;									# Set the a range of IPs if checking that
my $opt_kill;									# Kill all the copies of IpmProxyTest.exe that are running
my $opt_logfile;								# If set, change the log file name to this
my $opt_check;									# If set, re check IP addresses to see if they really are a proxy
my $opt_mail_only;								# If True only check for smtp relay mail servers
my $opt_nonexisting;							# If True, move non existing domains from DNS into errors
my $opt_noproxy;								# If True, then do all the tests expect the proxy tests - used by IpmRealtimeSpam with proxy checking turned off



#  Global variables
my $proxy_handle;								# Handle to the proxy test file
my $proxy_file = "IpmProxyTest.urls";			# The name of the proxy test file
my $dbh;										# My database handle to the Content Database
my %checked_proxy;								# A hash of IP addresses that have been checked - 0 if not, 1 if smtp proxy, 2 if web proxy, 3 if database blocked



# Counts of how many time things have happened
my $proxy_url_count = 0 + 0;					# This is the global count of urls that I have checked
my $proxy_ip_count	= 0 + 0;					# This is the global count of ips that I have checked
my $proxy_count		= 0 + 0;					# This is the global count of the proxies that I found
my $added_domain	= 0 + 0;					# The number of domains added to the database
my $added_ip		= 0 + 0;					# The number of IP addresses added to the database
my $changed_domain	= 0 + 0;					# The number of domains changed in the database
my $changed_ip		= 0 + 0;					# The number of IP addresses changed in the database



# Various global parameters used in the different proxy tests
my $TIMEOUT_CONNECT = 10;						# The the is number of seconds to wait for a connection to complete
my $TIMEOUT_DATA	= 2;						# This is the number of seconds to wait at max for data to arrive
my $TIMOUT_DNS		= 8;						# This is the number of seconds to wait on a DNS query
my $TEST_QUEUE		= 0 + 1000;					# The maximum number or URLs and IP addresses to queue up before testing
my $IP_QUEUE		= 0 + 10;					# The maximum number of IPs to test at a single time



# Global variables used in sending a mail test
my $INPUT_THRESHOLD = 2048;
my $MAIL_SERVER		= "lti-mail01.ltinetworks.com";
my $Mail_addr		= "al\@ltinetworks.com";	# This is the email address that the test mail will come from
my $MAIL_PORT		= 25;
my $Smtp_banner		= "221 ";
my $Hostname;									# This is the hostname of the sending mail server
my $Mail_tag;
my $decoy_account	= "bob\@macsoft.com";		# This is the email address the test message is sent to



# Global variables used in sending a WWW test
my $WEB_SERVER		= "www.microsoft.com";
my $WEB_CONTENT     = quotemeta( "<title>Microsoft Corporation" );
my $WEB_PORT		= 80;



# Global control variables used in creating multiple sockets
my %connected;		# My hash of currently connected sockets
my %waiting;		# My hash of waiting sockets
my @sockets;		# My list of sockets



# The list of ports and protocols to test on each IP address
my @scan_list = (

		#
		# 80 - Web server with unsecured/misconfigured proxy function.
		#
		"80/http-connect",
		"80/http-post",
		"80/smtp-connect",

		#
		# 25 - SMTP Relay
		"25/smtp-relay",
		
		
		#
		# 3128 - Well known port for the "squid" web cache.
		#
		"3128/http-connect",
		"3128/smtp-connect",

		#
		# 8080 - Well known port for the "webcache" service.
		#
		# I'm not sure this "http-post" test is worthwhile.
		# If I don't see this catching anything, I'll likely
		# remove it at some point.
		#
		"8080/http-connect",
		"8080/http-post",
		"8080/smtp-connect",

		"8888/http-connect",

		#
		# 8081 - Well known port for the "tproxy" transparent
		# proxy service.
		#
#		"8081/http-connect",

		#
		# 1080 - Well known port for the "socks" proxy service.
		#
#		"1080/socks4",
#		"1080/smtpsocks4",
#		"1080/socks5",

		#
		# 23 - Well known port for the "telnet" service.  Also,
		# Wingate runs a proxy on this port.
		#
		# These tests can be troublesome.  If there is something
		# listening on the port, we could hang until the timeout
		# interval.  If we are running threaded it might be
		# better to have these done early.
		#
#		"23/telnet",
#		"23/cisco",
#		"23/wingate",

		#
		# 6588 - The AnalogX product sets up an HTTP-CONNECT
		# proxy here.  This is typically caught with 1080/socks4,
		# but some networks are filtering 1080.
		#
#		"6588/http-connect",

		# Listening sockets from the Sobig.a virus
#		"1180/socks4",				# Sobig.a hidden socks server
#		"1182/http-connect",		# Sobig.a hidden proxy server
#		"1185/smtp-relay",			# Sobig.a hidden smtp server
		
		
		# Listening sockets from the Sobig.e virus
#		"2280/socks4",				# Sobig.e hidden socks server
#		"2282/http-connect",		# Sobig.e hidden proxy server
#		"2285/smtp-relay",			# Sobig.e hidden smtp server
		
		# Listening sockets from the Sobig.f virus
#		"3380/socks4",				# Sobig.f hidden socks server
#		"3382/http-connect",		# Sobig.f hidden proxy server
#		"3385/smtp-relay"			# Sobig.f hidden smtp server
		);


# The list of all possible ports and protocols to test on each IP address
my @all_scan_list = (

		#
		# 80 - Web server with unsecured/misconfigured proxy function.
		#
		"80/http-connect",
		"80/http-post",
		"80/smtp-connect",

		#
		# 25 - SMTP Relay
		"25/smtp-relay",
		
		#
		# 3127 - alternate ports for the "squid" web cache.
		#
		"3124/http-connect",
		"3127/http-connect",
		
		#
		# 3128 - Well known port for the "squid" web cache.
		#
		"3128/http-connect",
		"3128/smtp-connect",

		#
		# 8080 - Well known port for the "webcache" service.
		#
		# I'm not sure this "http-post" test is worthwhile.
		# If I don't see this catching anything, I'll likely
		# remove it at some point.
		#
		"50050/http-connect",
		"8000/http-connect",
		"8080/http-connect",
		"8080/http-post",
		"8080/smtp-connect",

		"8888/http-connect",

		#
		# 8081 - Well known port for the "tproxy" transparent
		# proxy service.
		#
		"8081/http-connect",

		#
		# 1080 - Well known port for the "socks" proxy service.
		#
		"1080/socks4",
		"1080/smtpsocks4",
		"1080/socks5",

		#
		# 23 - Well known port for the "telnet" service.  Also,
		# Wingate runs a proxy on this port.
		#
		# These tests can be troublesome.  If there is something
		# listening on the port, we could hang until the timeout
		# interval.  If we are running threaded it might be
		# better to have these done early.
		#
#		"23/telnet",
#		"23/cisco",
#		"23/wingate",

		#
		# 6588 - The AnalogX product sets up an HTTP-CONNECT
		# proxy here.  This is typically caught with 1080/socks4,
		# but some networks are filtering 1080.
		#
		"6588/http-connect",

		# Listening sockets from the Sobig.a virus
		"1180/socks4",				# Sobig.a hidden socks server
		"1182/http-connect",		# Sobig.a hidden proxy server
		"1185/smtp-relay",			# Sobig.a hidden smtp server
		
		
		# Listening sockets from the Sobig.e virus
		"2280/socks4",				# Sobig.e hidden socks server
		"2282/http-connect",		# Sobig.e hidden proxy server
		"2285/smtp-relay",			# Sobig.e hidden smtp server
		
		# Listening sockets from the Sobig.f virus
		"3380/socks4",				# Sobig.f hidden socks server
		"3382/http-connect",		# Sobig.f hidden proxy server
		"3385/smtp-relay"			# Sobig.f hidden smtp server
		);


#
# Sequence to transmit a mail message via SMTP.
#
my @MAIL_SENDING_SEQUENCE = (
	{ 'send' => "HELO %HOSTNAME%\r\n",		'resp' => 250 },
	{ 'send' => "MAIL FROM:<%EMAILADDR%>\r\n",	'resp' => 250 },
	{ 'send' => "RCPT TO:<%EMAILADDR%>\r\n",	'resp' => 250 },
	{ 'send' => "DATA\r\n",				'resp' => 354 },
	{ 'send' => "%MESSAGE%",			'resp' => undef },
	{ 'send' => ".\r\n",				'resp' => 250 },
	{ 'send' => "QUIT\r\n",				'resp' => 221 },
);



#
# $MAIL_MESSAGE_TEMPLATE is the template to generate a mail message
# we can send through an open proxy.  See the generate_mail_message()
# routine for information on the %VARIABLES% that can be used.
#
my $MAIL_MESSAGE_TEMPLATE =
q[To: %TO_ADDR%
From: %FROM_ADDR%
Date: %HDR_DATE%
Message-Id: %HDR_MSSGID%
Sender: %ORIG_SENDER%
Subject: open proxy test
X-Mailer: ipmproxytest v%VERSION%
X-Proxy-Spec: %PROXY_ADDR%:%PROXY_PORT%/%PROXY_PROTOCOL% %MAIL_TAG%

This message is a test probe, passed through what appears to
be an open proxy.

Proxy parameters:

    Address:  %PROXY_ADDR%
    Port:     %PROXY_PORT%
    Type:     %PROXY_PROTOCOL%
];



################################################################################
#
MAIN:
#
################################################################################
{  

	# Am I running a command line argument?
	my @arg = @ARGV;
	my @item_list;
	my $skip;
	foreach ( @arg )
		{	my $arg = $_;
			next if ( ! $arg );
			if ( $skip )
				{	$skip = undef;
					next;
				}
			
			if ( ( $arg eq "-f" )  ||  
				 ( $arg eq "-p" )  ||
				 ( $arg eq "-r" )  ||
				 ( $arg eq "-s" )  ||
				 ( $arg eq "-t" ) )
				{	$skip = 1;
					next;
				}
			
			next if ( $arg =~ m/^-/ );
					 
			push @item_list, $arg;
		}
		
	$opt_commandline = 1 if ( $#item_list > -1 );


     # Get the other options
     Getopt::Long::Configure("bundling");

     my $options = Getopt::Long::GetOptions
       (
        "a|addlog"		=> \$opt_all,
        "b|benchmark"	=> \$opt_benchmark,
        "c|check"		=> \$opt_check,
        "d|dnserrors"	=> \$opt_nonexisting,
        "e|exclusive"	=> \$opt_exclusive,
        "f|logfile=s"	=> \$opt_logfile,
        "g|noproxy"		=> \$opt_noproxy,
        "h|help"		=> \$opt_help,
        "k|kill"		=> \$opt_kill,
        "l|logging"		=> \$opt_logging,
        "m|mailonly"	=> \$opt_mail_only,
        "n|nodatabase"	=> \$opt_no_database,
        "o|override"	=> \$opt_override,
        "p|proxy=s"		=> \$WEB_SERVER,
        "r|range=s"		=> \$opt_range,
        "s|source=s"	=> \$opt_source,
        "t|timeout=s"	=> \$opt_timeout,
        "v|verbose"		=> \$opt_verbose,
        "w|wizard"		=> \$opt_wizard,
        "x|xxx"			=> \$opt_debug
       );

	   
	if ( $opt_kill )
		{	print "Killing all copies of IpmProxyTest that are running\n";
			&ProcessKillName( "IpmProxyTest" );
			exit( 0 );
		}
		
	my $start = new Benchmark if ( $opt_benchmark );


	&TrapErrors() if ( ! $opt_debug );
	
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	
	
	$opt_source = 0 + $opt_source;
	if ( ( $opt_source < 0 )  ||  ( $opt_source > 100 ) )
		{	&oprint( "The source number should be between 1 and 100\n" );
			$opt_source = 0 + 4;
		}
		
		
	# If I'm not begine run by IpmRealtimeSpam, and there are no command line arguments, then there is
	# nothing for me to do ...
	$opt_commandline = 1 if ( $opt_range );
	if ( ( ! $opt_commandline )  &&  ( ! $opt_exclusive ) )
		{	&Usage();
			exit( 0 );
		}
		
		
	# Get a hostname
	$Hostname = hostname();
	$Hostname = "ptest.lightspeedsystems.com" if ( ! $Hostname );
	
	
	# Should I kill off other copies?  I should if I'm reading from the shared proxy file
	my $process_running = ProcessRunningName( "IpmProxyTest" );
	my $process_killed;
	if ( ( $opt_exclusive )  &&  ( $process_running ) )
		{	# Make sure only 1 copy runs at a time
			$process_killed = &ProcessKillName( "IpmProxyTest" );
		}
		
	
	# Should I write everything out to a log file?
	$opt_logging = 1 if ( $opt_debug );
	$opt_verbose = 1 if ( $opt_debug );
	
	
	if ( $opt_logging )
		{	my $filename = "IpmProxyTest.log";
			
			if ( $opt_logfile )
				{	my $dir = getcwd;
					$dir =~ s#\/#\\#gm;

					# Does the opt_logfile incluse a pathname?  If not, use the current directory
					$dir = undef if ( $opt_logfile =~ m/\\/ );
					$filename = $opt_logfile;
					$filename = $dir . "\\" . $opt_logfile if ( $dir );
				}
				
			&SetLogFilename( $filename, undef );
			$log_filename = &GetLogFilename();
		}
		
				
	&StdHeader( "IpmProxyTest" ) if ( ! $opt_wizard );
	&oprint( "Logging events to $log_filename\n" ) if ( $opt_logging ); 

	
	if ( ( $process_running )  &&  ( $process_killed ) )
		{	# Make sure only 1 copy runs at a time
			&oprint( "Killed other copies of IpmProxyTest that were running\n" ) if ( $opt_verbose ); 
		}
		
		
	# Make sure the opt timeout value is right
	if ( $opt_timeout )
		{	if ( $opt_timeout =~ m/\D/ )
				{	&oprint( "The timout value should be between 1 and 60 seconds\n" );
					exit( 0 );
				}

	
			if ( ( $opt_timeout < 1  ||  $opt_timeout > 60  ) )
				{	&oprint( "The timout value should be between 1 and 60 seconds\n" );
					exit( 0 );
				}
		
			$TIMEOUT_CONNECT = 0 + $opt_timeout;
			&oprint( "Proxy test timeout set to $TIMEOUT_CONNECT seconds\n" );
		}

	
	
	#  Show the options
	if ( $opt_verbose )
		{	&oprint( "Override the category of known URLs if they are proxies or blocked\n" ) if ( $opt_override );	
			&oprint( "Reading URLs and IP addresses from command line\n" ) if ( $opt_commandline );	
			&oprint( "Reading URLs and IP addresses from shared file $proxy_file\n" ) if ( $opt_exclusive );	
			&oprint( "Don\'t save results in the Content database\n" ) if ( $opt_no_database );	
			&oprint( "Using source number $opt_source for adds and updates to the Content database\n" );	
			&oprint( "Checking all IP addresses to make sure the database is correct\n" );	
			&oprint( "Using $WEB_SERVER as the target for the HTTP proxy test\n" );	
			&oprint( "Only check for SMTP relay servers\n" ) if ( $opt_mail_only );	
			&oprint( "Check all possible ports for proxies and relays\n" ) if ( $opt_all );	
			&oprint( "Move domains with DNS errors into the errors category\n" ) if ( $opt_nonexisting );	
		}
		
	&oprint( "Only testing IP relationships between domain names\n" ) if ( $opt_noproxy );	
		

	# Should I only scan for smtp-relay servers?
	if ( $opt_mail_only )
		{	my @new_scan_list;
			
			foreach ( @scan_list )
				{	my $scan = $_;
					next if ( ! $scan );
					
					my ( $port, $proto ) = split /\//, $scan, 2;

					next if ( $proto ne "smtp-relay" );
					
					push @new_scan_list, $scan;
				}
			
			@scan_list = @new_scan_list;
		}


	# Should I scan everything I know of?		
	@scan_list = @all_scan_list if ( $opt_all );

	
	# If nothing to scan, say so
	if ( $#scan_list < 0 )
		{	&oprint( "There is nothing in the scan list to check\n" );
			exit( 0 );	
		}
		
		
	# If verbose, show all the ports and protocols that I'm trying
	if ( $opt_verbose )
		{	&oprint( "Ports and protocols to be tested ...\n" );
			foreach ( @scan_list )
				{	my $scan = $_;
					next if ( ! $scan );
					
					my ( $port, $proto ) = split /\//, $scan, 2;

					$proto = "http-connect" if ( ! $proto );
					
					&oprint( "Port $port protocol $proto\n" );
				}
		}

		
	# Should I check the database?
	if ( ! $opt_no_database )
		{	$dbh = &ConnectServer() ;
			if ( ! $dbh )
				{	&oprint( "Unable to connect to the Content database\n" );
					$opt_no_database = 1;
				}
		}
		
	&LoadCategories() if ( ! $opt_no_database );
	if ( $opt_no_database )
		{	&oprint( "Loading the default Content categories\n" ) if ( $opt_verbose ); 
			&DefaultCategories();
		}	
 
    &debug( "Opened Content database\n" );
	
	&debug( "Ready to test IP addresses and URLs for Web and SMTP proxying ...\n\n" );
	

    if ( ! $opt_commandline )
		{	&debug( "Opening $proxy_file\n" );
			
					
			my $done;

			&oprint( "Ready to start processing ...\n" );
			
			# Set my timeout to be 8 hours
			my $proxy_age = ( 8 * 60 * 60 ) + time();	
			
			
			# Main loop - pipe read and timer processing
			while ( !$done )	
				{	my @urls = &ProxyFileRead();

					if ( $#urls < 0 )
						{	$done = 1;
						}
					else
						{	my $new_proxies = &ProxyTest( @urls );
							$proxy_count += $new_proxies;
						
						
							# Now age out any proxy checks in memory
							if ( time() > $proxy_age )
								{	%checked_proxy = ();
									$proxy_age = ( 24 * 60 * 60 ) + time();	# Set my timeout to be 24 hours
								}
						}
				}
				
		}	# end of reading from a proxy file

	elsif ( $opt_range )
		{	my ( $from_ip, $to_ip ) = split /\-/, $opt_range, 2;

			if ( ! &IsIPAddress( $from_ip ) )
				{	&oprint( "$from_ip is not a valid IP address\n" ) if ( $from_ip );
					&oprint( "You need to enter a range in the format xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx\n" ) if ( ! $from_ip );
					exit( 1 );
				}
				
			if ( ! &IsIPAddress( $to_ip ) )
				{	&oprint( "$to_ip is not a valid IP address\n" ) if ( $to_ip );
					&oprint( "You need to enter a range in the format xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx\n" ) if ( ! $to_ip );
					exit( 1 );
				}
				
			# Build up the list of IPs to send to ProxyTest	
			my $from = &StringToIP( $from_ip );
			my $from_num = unpack( "N", $from );

			my $to = &StringToIP( $to_ip );
			my $to_num = unpack( "N", $to );
			
			my $low = $from_num;
			my $high = $to_num;
			if ( $from_num > $to_num )
				{	$low = $to_num;
					$high = $from_num;
				}
			
			&oprint( "Proxy testing range $from_ip to $to_ip ...\n" );

			my @range;
			for ( my $ip = $low;  $ip <= $high;  $ip++ )
				{	
					my $packed = pack( "N", $ip );
					
					my $str_ip = &IPToString( $packed );
					
					# Make sure that this is a real Internet IP
					next if ( ! &IsValidIP( $str_ip ) );
					push @range, $str_ip;
					
					if ( $#range >= $TEST_QUEUE )
						{	&oprint( "There are too many IP address in this range to test at one time\n" );
							exit( 1 );	
						}
				}
			
			if ( $#range < 0 )
				{	&oprint( "There no valid IP addresses in this range $opt_range\n" );
					exit( 1 );
				}
				
			my $new_proxies = &ProxyTest( @range );
			$proxy_count += $new_proxies;					
		}
    else #  just read the urls from the command line or from files
		{	foreach ( @item_list )
				{	my $item = $_;
					
					next if ( ! $item );
					
					# If the item is a filename that exists, assume it is a text file of URLs to test
					if ( -e $item )
						{	&ProxyTestFile( $item );
						}
					else
						{	my @url;
							
							push @url, $item;
							my $new_proxies = &ProxyTest( @url );
							$proxy_count += $new_proxies;
						}
				}
		}


	&debug( "Normal program close\n" );
	
	
	# Close the proxy file if I opened it
	if ( ( ! $opt_commandline )  &&  ( $proxy_handle ) )
       {	close( $proxy_handle );	
			$proxy_handle = undef;
       }


	# Show the final program results
	&oprint( "Checked $proxy_url_count URLs and $proxy_ip_count IP addresses\n" );
	&oprint( "Detected $proxy_count proxies, blocked URLs, or blocked IP addresses in total\n" );
	&oprint( "Added $added_domain domains\n" ) if ( $added_domain );
	&oprint( "Added $added_domain IP addresses\n" ) if ( $added_ip );
	&oprint( "Changed $changed_domain domains\n" ) if ( $changed_domain );
	&oprint( "Changed $changed_ip IP addresses\n" ) if ( $changed_ip );
	
	
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Program analyze time" );
		}
		
		
	if ( $opt_benchmark )
		{	my @keys = sort keys( %benchtime );
			
			&oprint( "\nBenchmarks\n\n" );

			foreach ( @keys )
				{	my $key = $_;
					next if ( ! $_ );
					my $val = $benchtime{ $key };

					my $strtime = timestr( $val );

					&oprint( "$key: $strtime\n" );
				}
		}
		
		
     $dbh->disconnect if ( $dbh );

	# Set the right exit code - 1 if I found a proxy, 0 if not
	exit( 1 ) if ( $proxy_count );
	exit;
}
###################    End of MAIN  ############################################



my $MYLOG;
################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $dir = &SoftwareDirectory();
	my $filename = $dir . "\\IpmProxyTestErrors.log";

   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	print "Unable to open $filename: $!\n";
			return( undef );
		}
		
	&CarpOut( $MYLOG );
	
	&lprint( "Logging IpmProxyTest errors to $filename\n" );
	
	return( 1 );
}



################################################################################
#
sub TimedBenchmark( $$$ )
#
#  Given the start time, the finish time, and the key, save the benchmark time
#
################################################################################
{	my $start	= shift;
	my $finish	= shift;
	my $key		= shift;
	
	return if ( ! $opt_benchmark );
	
	my $diff = timediff( $finish, $start );

	my $total = $diff;
	
	if ( defined $benchtime{ $key } )
		{	my $subtotal = $benchtime{ $key };
			$total = Benchmark::timesum( $subtotal, $diff ) ;
		}
		
	$benchtime{ $key } = $total;
}



################################################################################
# 
sub ProxyTestFile( $ )
#
#  I've been given a file that contains a list of urls to check
#  Open the file, read the urls, check them, and return
#
################################################################################
{	my $filename = shift;

			
	if ( ! open( FILE, "<$filename" ) )
		{   &oprint( "Can not open $filename: $!\n" );
			return( undef );
		}
    
	    
	&debug( "Opened proxy test file $filename\n");
	
	
	# Load up the test queue, and send it into be tested
	my @test_queue;
	while ( <FILE> )
		{	next if ( ! $_ );
			
			my $url = $_;
			chomp( $url );
			
			$url = &CleanUrl( $url );
			
			next if ( ! defined $url );
			
			# Is it a valid IP address?
			next if ( ( &IsIPAddress( $url ) )  &&  ( ! &IsValidIP( $url ) ) );
			
			push @test_queue, $url;
			
			# Don't load up the test queue too big so that it is easier to compare the results
			if ( $#test_queue > $IP_QUEUE )
				{	my $new_proxies = &ProxyTest( @test_queue );
					$proxy_count += $new_proxies;
					@test_queue = ();
				}
		}
	
	
	# Get the last of the test queue done		
	if ( $#test_queue >= 0 )
		{	my $new_proxies = &ProxyTest( @test_queue );
			$proxy_count += $new_proxies;
			@test_queue = ();
		}
				
	&debug( "Closed proxy test file\n" );
	
	close FILE;
	
	return( 1 );
		
}



################################################################################
# 
sub ProxyFileRead()
#
#  Read the next URLs to check from the proxy file
#  Return the URLs to check, or an empty array if done
#  Don't read more than TEST_QUEUE number of urls at one time
#
################################################################################
{	my @urls;

	&oprint( "Waiting for URLs to check ...\n" ) if ( $opt_logging );
	
	my $software_dir = &SoftwareDirectory();
	my $full_filename = $software_dir . "\\$proxy_file";
	
	
	# Wait for the file to be created
	while ( ! -e $full_filename )
		{	sleep( 1 );
		}
	
	
	# Wait for something to be put into the file	
	my $size = 0 + 0;
	while ( ! $size )
		{	$size = -s $full_filename;
			sleep( 1 ) if ( ! $size );
		}
		
			
	if ( ! open( $proxy_handle, "<$full_filename" ) )
		{   &FatalError( "Can not open $full_filename: $!\n" ); 
		}
    
	    
	&debug( "Opened proxy file\n");
	
	&oprint( "Reading the $proxy_file ... \n" ) if ( $opt_verbose );
	
	my $queue_full;	
	while ( <$proxy_handle> )
		{	next if ( ! $_ );
			
			my $url = $_;
			chomp( $url );
			
			if ( $_ eq "quit" )
				{	close $proxy_handle;
					
					@urls = ();
					return( @urls );	
				}
				
			$url = &CleanUrl( $url );
			
			next if ( ! defined $url );
			
			# Is it a valid IP address?
			next if ( ( &IsIPAddress( $url ) )  &&  ( ! &IsValidIP( $url ) ) );
			
			push @urls, $url;
			
			$queue_full = 1 if ( $#urls >= $TEST_QUEUE );
			last if ( $queue_full );
		}
			
	&debug( "Closed proxy file\n");
	
	my $count = $#urls + 1;
	
	&oprint( "Read $count URLs\n" ) if ( $opt_verbose );
	
	close $proxy_handle;
	$proxy_handle = undef;
	
	# Delete the file if I read everything out of it
	unlink $full_filename if ( ! $queue_full );
	
	return( @urls );
		
}



################################################################################
#
sub ProxyTest( @ )
#
#  Given a list of urls, test them to see if it can proxy smtp or web traffic
#  Add the url to the database in the spam category if it can
#
#  Return the count of proxies discovered
#
################################################################################
{	my @urls = @_;
	
	my $proxies_discovered = 0 + 0;
	
	
	if ( $#urls < 0 )
		{	&oprint( "You must enter an IP address or a URL to check for proxying\n" );
			return( 0 + 0 );
		}

	my @clean_list;
	
	foreach ( @urls )
		{	next if ( ! $_ );
			
			my $original_url = $_;
			my $url = &CleanUrl( $original_url );
			
			next if ( ! defined $url );
			
			# Is it a valid IP address?
			next if ( ( &IsIPAddress( $url ) )  &&  ( ! &IsValidIP( $url ) ) );
			
			push @clean_list, $url;
		}
		
	# Did I find any clean urls at all?	
	return( 0 + 0 ) if ( $#clean_list < 0 );
	
	
	# Non-zero if it turns out that this URL is some sort of proxy or blocked
	# Get the default category to set proxies to
	my $blocked_category		= "spam";
	my $blocked_category_num	= &CategoryNumber( "spam" );
			
			
	# Figure out the IP addresses for all of these URLs
	my @addresses = ();		# This is my list of addresses to check
	my %ip_domain;			# This is a hash where the key is the IP address, the value is the domain name
	my %results;			# The is a hash containing the results, key is domain or IP address, value is is_proxy tab catnum


	foreach ( @clean_list )
		{	next if ( ! defined $_ );
			
			my $url = $_;
			my ( $domain, $url_ext ) = split /\//, $url, 2;
			
			if ( &IsIPAddress( $domain ) )	# Is it an IP address itself?
				{	next if ( ! &IsValidIP( $domain ) );	# Make sure that it is a legal IP address
					
					# Have I recently checked this address?
					if ( defined $checked_proxy{ $domain } )
						{	my $is_proxy = $checked_proxy{ $domain };
							
							my $result = &CheckedProxy( $is_proxy );
							&oprint( "$domain was just checked and is $result\n" ) if ( $opt_verbose );
							
							# Get the category number - either spam or proxy	
							my $catnum = &CategoryNumber( "spam" );
							$catnum = &CategoryNumber( "security.proxy" ) if ( $is_proxy == 2 );

							$results{ $domain } = "$is_proxy\t$catnum";
							next;
						}
						
					&oprint( "Testing IP $domain\n" ) if ( $opt_verbose );
					
					my @ip;
					push @ip, $domain;
					
					# At this point, $@ip holds the addresses that I should check
					my ( $is_proxy, $catnum );
					( $is_proxy, $catnum ) = &CheckDatabase( undef, @ip ) if ( ( ! $opt_no_database )  &&  ( ! $opt_check ) );

					# If the address isn't blocked in the database, add it to the list to check
					if ( ! $is_proxy )
						{	push @addresses, $domain;
						}
					else	# Just save the result
						{	$results{ $domain } = "$is_proxy\t$catnum";
						}
						
					next;

				}
			
				
			# If I am checking a URL see if I can get the IP addresses, and what category the URL is in now
			$proxy_url_count++;
			
			my @domain_addresses = ();	# The list of IP addresses for this domain
			
			# Have I recently checked this address?
			if ( defined $checked_proxy{ $domain } )
				{	my $is_proxy = $checked_proxy{ $domain };
					
					my $result = &CheckedProxy( $is_proxy );
					&oprint( "$domain was just checked and is $result\n" ) if ( $opt_verbose );
					
					next;
				}


			&oprint( "Testing URL $url\n" ) if ( $opt_verbose );
			
			
			# See if I can find the root domain
			my $root_domain = &RootDomain( $domain );
			
						
			# If no root domain for this URL then go onto the next url
			if ( ! defined $root_domain  )
				{	&oprint( "No root domain for URL $url\n") if ( $opt_verbose );
					next;
				}
			
			
			my @domains_checked = ();
			@domain_addresses = &URLIPAddresses( $domain );
			
			push @domains_checked, $domain;
			
			
			# If I didn't get any IP addresses, try a www on the front
			my $test_domain = "www." . $domain;
			if ( $#domain_addresses < 0 )
				{	@domain_addresses = &URLIPAddresses( $test_domain );
					&oprint( "Found IP for domain $test_domain\n" ) if ( ( $#domain_addresses >= 0 )  &&  ( $opt_verbose ) );
					
					push @domains_checked, $test_domain;
				}
			
			
			# Try checking the root domain if it is different that the original domain
			if ( ( $#domain_addresses < 0 )  &&  ( $root_domain ne $domain ) )
				{	@domain_addresses = &URLIPAddresses( $root_domain );
					
					push @domains_checked, $root_domain;
					
					# If I found one that works, use it
					if ( $#domain_addresses >= 0 )
						{	$domain = $root_domain;
							&oprint( "Found IP for root domain $root_domain\n" ) if ( $opt_verbose );
						}
				}
			
			
			# If I still didn't get any IP addresses, try a www on the front of the root domain
			$test_domain = "www." . $root_domain;
			if ( ( $#domain_addresses < 0 )  &&  ( $root_domain ne $domain ) )
				{	@domain_addresses = &URLIPAddresses( $test_domain );
					
					push @domains_checked, $test_domain;
					
					&oprint( "Found IP for domain $test_domain\n" ) if ( ( $#domain_addresses >= 0 )  &&  ( $opt_verbose ) );
				}
				
				
			# Did I find anything at all? If not, move to the errors category if it is in the database
			if ( $#domain_addresses < 0  )
				{	&oprint( "No IP for URL $url\n") if ( $opt_verbose );
					&NonExistingDomains( @domains_checked );
					next;
				}
			
			
			# Show the IP addresses I found
			&oprint( "Found IP:\n" ) if ( $opt_verbose );
			foreach ( @domain_addresses )
				{	&oprint( "$_\n" ) if ( $opt_verbose );
				}
				
				
			# At this point, $domain and @addresses hold the addresses and/or domains that I should check
			my ( $is_proxy, $catnum );
			( $is_proxy, $catnum ) = &CheckDatabase( $domain, @domain_addresses ) if ( ( ! $opt_no_database )  &&  ( ! $opt_check ) );
			

			# If I didn't figure out that they are a proxy from the database, then add the IP addresses into my list to check
			if ( ! $is_proxy )
				{	push @addresses, @domain_addresses;
				}
			else
				{	# If they are a proxy, save the results
					$results{ $domain } = "$is_proxy\t$catnum";
					foreach ( @domain_addresses )
						{	next if ( ! $_ );
							
							my $ip = $_;
							$results{ $ip } = "$is_proxy\t$catnum";
						}
				}
				
				
			# Build up the hash of related domains and IP addresses	
			foreach ( @domain_addresses )
				{	next if ( ! $_ );
					
					my $ip = $_;
					$ip_domain{ $ip } = $domain;
				}

		}	# End of foreach @clean_url
		
	
	# Keep track of how many I've checked
	$proxy_ip_count += $#addresses + 1;
	
	my %proxy_list;	# This is the list of the IP addresses that tested as proxies
	
	# Test my list of address
	%proxy_list = &ProxyTestIP( @addresses ) if ( ( $#addresses >= 0 )  &&  ( ! $opt_noproxy ) );
					

	# Go through the proxy list and update the results hash
	foreach ( keys %proxy_list )
		{	next if ( ! defined $_ );
			
			my $proxy_ip = $_;
			
			# Get the type of proxy - Web or SMTP
			my $is_proxy = $proxy_list{ $proxy_ip };
			
			next if ( ! $is_proxy );
		
			# Get the category number - either spam, shopping.spam, or proxy	
			my $catnum = &CategoryNumber( "spam" );
			$catnum = &CategoryNumber( "security.proxy" ) if ( $is_proxy == 2 );


			# Save the proxy_ip result
			$results{ $proxy_ip } = "$is_proxy\t$catnum";
			
			
			# Find the related domain, if any
			my $domain = $ip_domain{ $proxy_ip };
			
			# If there isn't a related domain, then there aren't any other related IPs either 
			next if ( ! $domain );
			
			
			# Save the domain result
			$results{ $domain } = "$is_proxy\t$catnum";
			
			# Find the related IP addresses - if one is a proxy, they all are marked as a proxy
			my @ip = keys %ip_domain;
			
			foreach ( @ip )
				{	next if ( ! $_ );
					my $ip = $_;
					
					# Is this IP related to the domain?
					next if ( $ip_domain{ $ip } ne $domain );
					
					# Save the results in the hash
					$results{ $ip } = "$is_proxy\t$catnum";
				}
		}


	# Save the the results
	foreach ( keys %results )
		{	next if ( ! $_ );
			
			my $url = $_;
			
			my $result = $results{ $url };
								
			if ( ! $result )
				{	&oprint( "Error - bad result for URL url\n" );
					next;	
				}
			
			my ( $is_proxy, $catnum ) = split /\t/, $result, 2;
			
			if ( ( ! $is_proxy )  ||  ( ! $catnum ) )
				{	&oprint( "Error - bad is proxy or catnum for URL url\n" );
					next;	
				}
			
			$is_proxy = 0 + $is_proxy;
			$catnum = 0 + $catnum;
			
			&SetDatabase( $is_proxy, $catnum, $url );
			
			# Also save the results in the in memory hash
			$checked_proxy{ $url } = 0 + 0 if ( ! $is_proxy );
			$checked_proxy{ $url } = 0 + $is_proxy if ( $is_proxy );
			
			$proxies_discovered++;
		}
	
	
	# If checking, make sure that the proxy IP addresses are right in the database
	if ( ( $opt_check )  &&  ( ! $opt_no_database ) )
		{	my @ok_ip;
			
			# Build up my list of ok IP addresses
			foreach ( @addresses )
				{	next if ( ! $_ );
					
					my $ip = $_;
					
					my $ok = 1;
					
					# Check against the results to make sure they aren't there
					foreach ( keys %results )
						{	next if ( ! $_ );
							
							$ok = undef if ( $ip eq $_ );
						}
					
					push @ok_ip, $ip if ( $ok );
				}

			foreach ( @ok_ip )
				{	next if ( ! $_ );
				
					my $good_ip = $_;
					my @good_ip;
					push @good_ip, $good_ip;
					
					my ( $is_proxy, $catnum ) = &CheckDatabase( undef, @good_ip );
					
					# Is this wrong in the database?
					if ( ( $is_proxy )  &&  ( ( $is_proxy == 1 )  ||  ( $is_proxy == 2 ) ) )
						{	&oprint( "$good_ip is miscategorized as a proxy so moving to errors now\n" );
							&MoveErrorCategory( $good_ip, $catnum );
						}
				}
		}
		
		
	return( $proxies_discovered );
}



################################################################################
#
sub SetDatabase( $$$ )
#
#  Set the database value for the domain or IP address
#
################################################################################
{	my $is_proxy	= shift;
	my $catnum		= shift;
	my $url			= shift;	# This must be either a domain name or an IP address
	

	# Am I using the database at all?
	return( undef ) if ( $opt_no_database );
	
	
	# Don't change anything if not some sort of proxy or in a blocked category - if I'm not checking
	return( undef ) if ( ( ! $is_proxy )  &&  ( ! $opt_check ) );
	
	my $errors_catnum = &CategoryNumber( "errors" );
	
	# If I'm checking, and it's not a proxy, move it to the errors category
	if ( ( ! $is_proxy )  &&  ( $opt_check ) )
		{	$catnum = &CategoryNumber( "errors" );
		}
	
	# If I don't have a catnum, just return undef
	if ( ! $catnum )
		{	&oprint( "Error: invalid category number $catnum in SetDatabase\n" );
			return( undef );
		}
		
		
	my $catname = &CategoryName( $catnum );
	
	if ( ! $catname )
		{	&oprint( "Error: invalid category $catnum in SetDatabase\n" );
			return( undef );
		}

		
	# Is the URL a domain name or an IP address?
	if ( ! &IsIPAddress( $url ) )
		{	my $retcode = 0 + 0;
			
			my $domain = $url;
			$retcode = &LookupUnknown( $domain, 0 );
			
			
            #  If I don't know this $domain at all, add it to the right category
            if ( ! $retcode )
				{	&oprint( "Adding $domain to the $catname category\n" );
					$retcode = &AddNewTrans( $domain, $catnum, 0, $opt_source );
					$added_domain++;
					
					return( 1 );
				}
				
				
			my ( $old_catnum, $source ) = &FindCategory( $domain, $retcode );
			my $old_catname = &CategoryName( $old_catnum );
			
			
			# Is it in the same category?
			if ( ( $old_catnum eq $catnum )  ||  ( $old_catname =~ m/$catname/ ) )
				{	&oprint( "$domain is already in category $old_catname\n" );
					&UpdateReviewTime( $domain, $retcode );
					
					return( 1 );	
				}
					
							
			# Is this already in a blocked category?
			if ( ( $retcode <= ( 0 + 3 ) )  &&  ( ! $opt_check ) )
				{	&oprint( "$domain is already in category $old_catname\n" );
					&UpdateReviewTime( $domain, $retcode );
				
					return( 1 );
				}
				
			
            #  If this is already in the database, and allowed, change it - if I'm overriding
            if ( $opt_override )
				{	# Is my source less than or equal to the source number in the database?
					# Or is the old category the errors category?
					if ( ( $opt_source <= $source )  ||  ( $old_catnum eq $errors_catnum ) )
						{	my $ret = &UpdateCategory( $domain, $catnum, $retcode, $opt_source );
							
							if ( ! $ret )
								{	&oprint( "Switched $domain from $old_catname to $catname\n" );
									$changed_domain++;
								}
							else
								{	&oprint( "Error $ret trying to switch $domain from $old_catname to $catname\n" );
								}
						}
					else
						{	&oprint( "$domain has source $source so not overriding from $old_catname to $catname\n" );
						}
						
					return( 1 );
				}
				
				
			# Not overriding, so show the category
			&oprint( "$domain is already in $old_catname - not overriding to $catname\n" );
			
			return( 1 );	
		}
	
	
	# At this point the url must be an IP address
	my $str_ipaddress = $url;


	# Did the IP address test as a WWW proxy or as a SMTP proxy?  If so, put the address into those categories
	if ( $is_proxy == 2 )
		{	$catnum = &CategoryNumber( "security.proxy" );
			$catname = "security.proxy";
		}
	elsif ( $is_proxy == 1 )
		{	$catnum = &CategoryNumber( "spam" );
			$catname = "spam";
		}
		

	my $retcode = 0 + 0;	
	$retcode = &LookupUnknown( $str_ipaddress, 0 );
	
	
	#  If I don't know this addresses at all, add it to the right category
	if ( ! $retcode )
		{	&oprint( "Adding $str_ipaddress to the $catname category\n" );
			$retcode = &AddNewTrans( $str_ipaddress, $catnum, 0, $opt_source );
			
			$added_ip++;
			
			return( 1 );
		}
		
		
	# Look up the rest of the info for this IP address
	my ( $old_catnum, $source ) = &FindCategory( $str_ipaddress, $retcode );
	my $old_catname = &CategoryName( $old_catnum );
		
		
	# Is it in the same category?
	if ( ( $old_catnum eq $catnum )  ||  ( $old_catname =~ m/$catname/ ) )
		{	&oprint( "$str_ipaddress is already in category $old_catname\n" );
			&UpdateReviewTime( $str_ipaddress, $retcode );

			return( 1 );	
		}
						
								
	#  At this point str_address is in the database
	if ( $opt_override )
		{	# Is my source less than or equal to the source number in the database?
			# Or is the old category the errors category?
			if ( ( $opt_source <= $source )  ||  ( $old_catnum eq $errors_catnum ) )
				{	my $ret = &UpdateCategory( $str_ipaddress, $catnum, $retcode, $opt_source );
					
					if ( ! $ret )
						{	&oprint( "Switched $str_ipaddress from $old_catname to $catname\n" );
							$changed_ip++;
						}
					else
						{	&oprint( "Error $ret trying to switch $str_ipaddress from $old_catname to $catname\n" );
						}
				}
			else
				{	&oprint( "$str_ipaddress has source $source so not overriding from $old_catname to $catname\n" );
				}
				
			return( 1 );
		}
	
			
	# Not overriding, so show the category and don't do anything
	&oprint( "$str_ipaddress is already in $old_catname - not overriding to $catname\n" );
					

	return( 1 );
}



################################################################################
#
sub ProxyTestIP( @ )
#
#  Given an unlimited list of IP addresses, test them to see if any can proxy smtp or Web
#  Return the IP addresses that are proxies in a proxy_list hash
#
#  The key to the proxy list hash is the str_ip_address, value is the proxy type
#  Return 1 if a smtp proxy, 2 if a www proxy
#
################################################################################
{	my @full_list = @_;
	
	my %full_proxy;
	
	
	my @partial_list;
	my %partial_proxy_list;
	
	
	# Go through the full list, building partial lists that are only $IP_QUEUE in size
	# and calling the ProxyTestIPSub to check the smaller list
	foreach ( @full_list )
		{	next if ( ! $_ );
			
			my $ip = $_;
			next if ( ! &IsIPAddress( $ip ) );
			
			push @partial_list, $ip;
			
			# Have I filled the queue?
			my $queue = $#partial_list + 1;
			next if ( $queue < $IP_QUEUE );
			
			%partial_proxy_list = &ProxyTestIPSub( @partial_list );
			
			foreach ( keys %partial_proxy_list )
				{	next if ( ! $_ );
					
					my $proxy_ip = $_;
					my $is_proxy = $partial_proxy_list{ $proxy_ip };
					
					$full_proxy{ $proxy_ip } = $is_proxy;
				}
			
			
			# Clear out the partial list for the next round
			@partial_list = ();
		}
	
	
	# I'm done with the full list - did I leave anything in partial list to check?
	return( %full_proxy ) if ( $#partial_list < 0 );
	
	%partial_proxy_list = &ProxyTestIPSub( @partial_list );
	
	foreach ( keys %partial_proxy_list )
		{	next if ( ! $_ );
			
			my $proxy_ip = $_;
			my $is_proxy = $partial_proxy_list{ $proxy_ip };
			
			$full_proxy{ $proxy_ip } = $is_proxy;
		}
		
	return( %full_proxy );
}



################################################################################
#
sub ProxyTestIPSub( @ )
#
#  Given a list of up to $IP_QUEUE IP addresses, test them to see if any can proxy smtp or Web
#  Return the IP addresses that are proxies in a proxy_list hash
#
#  The key to the proxy list hash is the str_ip_address, value is the proxy type
#  Return 1 if a smtp proxy, 2 if a www proxy
#
################################################################################
{	my @target_list = @_;
	
use IO::Socket::INET;
use IO::Select;


	# This is the hash of my results
	my %proxy_list;
	
	
	# Clear out my list of sockets
	@sockets	= ();
	%connected	= ();
	%waiting	= ();
	
	
	# This is my hash of key sock, value target_addr
	my %sock_addr;
	
	
	foreach ( @target_list )
		{	next if ( ! $_ );
			
			my $target_addr = $_;		
			&oprint( "Checking IP addresss $target_addr\n" );
			
			foreach ( @scan_list )
				{	next if ( ! $_ );
					
					my $scan = $_;
					
					my ( $port, $proto ) = split /\//, $scan, 2;

					$proto = "http-connect" if ( ! $proto );
					
					next if ( ! $port );
					next if ( ! $proto );
					
					my $sock = connect_socket( $target_addr, $port, $proto );

					# Go on with the next one if an error here
					next if ( ! $sock );
					
					push @sockets, $sock;
					
					$sock_addr{ $sock } = $target_addr;
				}
		}
		

	# Wait for each of the attempted connections to connect, or give up	
	&oprint( "Waiting for $TIMEOUT_CONNECT seconds for attempted connections to complete ...\n" ) if ( $opt_debug );
	sleep( $TIMEOUT_CONNECT );
	
	foreach ( @sockets )
		{	&oprint( "Top of checking connections\n" ) if ( $opt_debug );
			
			next if ( ! $_ );
			
			my $sock = $_;

			# Is this socket waiting?  If not, go on to the next sock
			next if ( ! $waiting{ $sock } );
			
			&oprint( "Checking $sock connection\n" ) if ( $opt_debug );
			
			my $select = IO::Select->new( $sock );
			
			next if ( ! $select );
			
			my $values = $waiting{ $sock };
			my ( $proxy_addr, $proxy_port, $proxy_proto ) = split /\t/, $values;
			
			# If it can write then it my be connected
			&oprint( "Checking if $sock can write\n" ) if ( $opt_debug );
			
			if ( $select->can_write( 0 + 0.001 ) )
				{	my $value = $waiting{ $sock };
					$connected{ $sock } = $value;
					
					&oprint( "Connected IP address $proxy_addr port $proxy_port\n" ) if ( $opt_verbose );
				}
			else	# Close the socket
				{	&oprint( "shutdown $sock\n" ) if ( $opt_debug );
					#$sock->shutdown( 2 );
				}
		}
	
	
	# At this point the hash "connected" has all the sockets that were able to connect in 2 seconds
	my @connected_sockets = keys %connected;
	my $connected_count = 1 + $#connected_sockets;	

	&oprint( "Connected $connected_count sockets\n" ) if ( $opt_debug );
	
	
	# If I didn't connect anything, there can't be any proxies
	if ( ! $connected_count )
		{	&oprint( "No proxies detected\n" );
			
			return( %proxy_list );
		}
	
		
	&oprint( "Testing $connected_count connected sockets ...\n" ) if ( $opt_verbose ); 
	
	foreach ( @sockets )
		{	next if ( ! $_ );
			
			my $sock = $_;
			
			# Did I complete a connection?  If not, move on
			next if ( ! $connected{ $sock } );
			
			
			# Have I already found a proxy for this address?
			my $target_addr = $sock_addr{ $sock };
			my $is_proxy = $proxy_list{ $target_addr };
			
			
			# If I have already found 1 proxy for this target_addr, close the other sockets
			if ( $is_proxy )
				{	#$sock->shutdown( 2 );
					delete $connected{ $sock };
					next;
				}
				
			
			# Is this socket actually connected?
			&oprint( "Is $sock connected?\n" ) if ( $opt_debug );
			
			if ( ! $sock->connected )
				{	my $err = $sock->sockopt( SO_ERROR );
					&oprint( "Socket error = $err\n" );
					#$sock->shutdown( 2 );
					delete $connected{ $sock };
					next;
				}
				
				
			my $values = $connected{ $sock };
			my ( $proxy_addr, $proxy_port, $proxy_proto ) = split /\t/, $values;
			
			# Switch it to blocking mode
			# $sock->blocking( 1 );
			ioctl( $sock, 0x8004667e, 0 );

			# Set the socket timeout
			$sock->timeout( $TIMEOUT_DATA );
			
			&oprint( "Testing IP address $proxy_addr port $proxy_port protocol $proxy_proto\n" ) if ( $opt_verbose );
			
			$is_proxy = run_test_function( $sock, $proxy_addr, $proxy_port, $proxy_proto );
			
			&oprint( "Proxy detected at $proxy_addr port $proxy_port protocol $proxy_proto\n" ) if ( ( $is_proxy )  &&  ( $opt_verbose ) );

			# Save the result in my hash if a proxy
			$proxy_list{ $target_addr } = $is_proxy if ( $is_proxy );
			
			#$sock->shutdown( 2 );
			delete $connected{ $sock };
		}
	
	
	# Show the results
	my @proxy_array = keys %proxy_list;
	my $proxy_count = 0 + 0;
	
	foreach ( @proxy_array )
		{	next if ( ! $_ );
			
			my $target_addr = $_;
			my $is_proxy = $proxy_list{ $target_addr };
			
			my $result = &CheckedProxy( $is_proxy );
			
			if ( $is_proxy )
				{	&oprint( "$target_addr is $result\n" );
					$proxy_count++;
				}
		}
	
	
	&oprint( "No proxies detected\n" ) if ( ! $proxy_count );
	
	return( %proxy_list );
}



sub connect_socket
{
	my ( $proxy_addr, $proxy_port, $proxy_proto ) = @_;
	
use IO::Socket::INET;
#use Errno qw( EWOULDBLOCK EINPROGRESS );
use IO::Select;

 
	
	# &oprint( "Connecting to IP address $proxy_addr port $proxy_port\n" ) if ( $opt_debug );
	
	my $sock = IO::Socket::INET->new(
		Proto		=> "tcp",
		Type		=> SOCK_STREAM
#		Blocking	=> 0
#		Timeout		=> $TIMEOUT_CONNECT
		);
	
	
	# If I didn't get a socket, show the error
	if ( ! $sock )
		{	&oprint( "Error getting a new socket: $!\n" );
			return( undef );
		}
	
	
	# Non blocking socket
	# $sock->blocking( 0 );
	win32_blocking( $sock, 0x8004667e, undef );
	
	
	my $addr = sockaddr_in( $proxy_port, scalar inet_aton( $proxy_addr ) );
		
	my $result = $sock->connect( $addr );
	
	
	# Did it connect immediately?
	if ( $result )
		{	$connected{ $sock } = "$proxy_addr\t$proxy_port\t$proxy_proto";
			return( $sock );
		}
	elsif ( ( $! == 0 + 10036 )  ||  ( $! == 0 + 10035 ) )  # It is waiting for a connection
		{	$waiting{ $sock } = "$proxy_addr\t$proxy_port\t$proxy_proto";
			return( $sock );
		}
	
		
	&oprint( "Error connecting: $!\n" ) if ( $opt_debug );
	my $errno = 0 + $!;
	&oprint( "errno = $errno\n" ) if ( $opt_debug );
	
		
	return( undef );
}



sub win32_blocking
{
	my ($self, $blocking) = @_;
	my $nonblocking = $blocking ? "0" : "1";
	ioctl($self, 0x8004667e, $nonblocking);
};



sub run_test_function
# Return 0 if not a proxy, 1 if an smtp proxy, 2 if a web proxy
{	my( $sock, $proxy_addr, $proxy_port, $proxy_proto ) = @_;
	
	my $is_proxy;
	$proxy_proto = "undefined" if ( ! $proxy_proto );
	
	if ( $proxy_proto eq "http-connect" )
		{	$is_proxy = &proxy_test_http_connect( $sock );
		}
	elsif ( $proxy_proto eq "smtp-connect" )
		{	$is_proxy = &proxy_test_http_smtp_connect( $sock );
		}
	elsif ( $proxy_proto eq "http-post" )
		{	$is_proxy = &proxy_test_http_post( $sock, $proxy_addr, $proxy_port , $proxy_proto );
		}
	elsif ( $proxy_proto eq "socks4" )
		{	$is_proxy = &proxy_test_socks4( $sock );
		}
	elsif ( $proxy_proto eq "smtpsocks4" )
		{	$is_proxy = &proxy_test_socks4( $sock );
		}
	elsif ( $proxy_proto eq "socks5" )
		{	$is_proxy = &proxy_test_socks5( $sock );
		}
	elsif ( $proxy_proto eq "wingate" )
		{	$is_proxy = &proxy_test_wingate( $sock );
		}
	elsif ( $proxy_proto eq "telnet" )
		{	$is_proxy = &proxy_test_telnet( $sock );
		}
	elsif ( $proxy_proto eq "cisco" )
		{	$is_proxy = &proxy_test_cisco( $sock );
		}
	elsif ( $proxy_proto eq "smtp-relay" )
		{	$is_proxy = &proxy_test_smtp_relay( $sock, $proxy_addr, $proxy_port, $proxy_proto );
		}
	else
		{	&oprint( "Error: subroutine run_test_function - undefined protocol = $proxy_proto\n" );
		}
		
	return( $is_proxy );
}



#####
#
# usage:	proxy_test_http_connect($sock)
# function:	Test for an open proxy using the "HTTP CONNECT" method.
# returns:	Return TRUE if open proxy detected.
#
sub proxy_test_http_connect
{
	my $sock = shift;

	return( 0 + 0 ) if ( ! wrsock($sock, "GET http://$WEB_SERVER/ HTTP/1.0\r\nAccept: */*\r\nAccept-Language: en-us\r\nPragma: no-cache\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)\r\nHost: $WEB_SERVER\r\nProxy-Connection: Keep-Alive\r\n\r\n") );
	
	my $content = rdsock($sock);
	
	return( 0 + 0 ) if ( ! $content );

	# should see the web content
	return( 0 + 2 ) if ( $content =~ /$WEB_CONTENT/ );

	return( 0 + 0 );
}



#####
#
# usage:	proxy_test_http_smtp_connect($sock)
# function:	Test for an open proxy using the "HTTP CONNECT" method.
# returns:	Return TRUE if open proxy detected.
#
sub proxy_test_http_smtp_connect
{
	my $sock = shift;

	return( 0 + 0 ) if ( ! wrsock($sock, "CONNECT http://$MAIL_SERVER:$MAIL_PORT HTTP/1.0\r\n\r\n") );
	
	$_ = rdsock($sock)
		or return( 0 + 0 );

	# should see something like: HTTP/1.0 200 Connection established
	m!^HTTP/\S+\s+(200)\s+!
		or return 0;

	# Weird ... I'm finding some servers give a 200 to the CONNECT
	# request, but then serve up a document rather than making a
	# proxy connection.  They'll fail here.
	return( 0 + 1 ) if ( found_smtp_banner($sock) );
	
	return( 0 + 0 );
}



#####
#
# usage:	proxy_test_http_post
# function:	Test for an open proxy using the "HTTP POST
# returns:	Return TRUE if open proxy detected.
#
sub proxy_test_http_post
{
	my ( $sock, $proxy_addr, $proxy_port, $proxy_proto ) = @_;
	
	my $mssg = generate_mail_message( $proxy_addr, $proxy_port, $proxy_proto );
	
	my $is_proxy = proxy_test_http_post_sub($sock, $mssg);
					
	return( $is_proxy );
}



#####
#
# usage:	proxy_test_http_post_sub($sock, $mssg)
# function:	Test for an open proxy using the "HTTP POST" method.
# returns:	Return TRUE if open proxy detected.
#
# This test is different from all the others.  It requires very ugly
# special case handling.  The problem is the entire HTTP-POST test
# (including transmitting a probe email) must be run blindly, and then
# results checked only after all the data are transmitted.
#
sub proxy_test_http_post_sub
{
	my($sock, $mssg) = @_;

	#
	# Oddities I've seen ...
	#
	# Some proxies return HTTP status, some don't.  Thus, we don't
	# look for an HTTP success code, but set an abort on an HTTP
	# fail code.
	#
	# Some proxies transmit the HTTP headers as well as the payload.
	# thus we begin with a RSET to try to flush that garbage.
	#

	my $doc = "RSET\r\n";
	my $dispmssg;
	if ($Mail_addr) {
		foreach my $seq (@MAIL_SENDING_SEQUENCE) {
			if ($seq->{'send'} eq "%MESSAGE%") {
				$doc .= $mssg;
			} else {
				$doc .= $seq->{'send'};
			}
			$dispmssg = "(smtp dialog with probe email)";
		}
	} else {
		$dispmssg = $doc = "QUIT\r\n";
	}

	#
	# Blindly transmit the entire session.
	#
	return( 0 + 0 ) if ( ! wrsock($sock, "POST http://$MAIL_SERVER:$MAIL_PORT/ HTTP/1.0\r\n") );
	return( 0 + 0 ) if ( ! wrsock($sock, "Content-Type: text/plain\r\n") );
	return( 0 + 0 ) if ( ! wrsock($sock, "Content-Length: " . length($doc) . "\r\n\r\n") );
	return( 0 + 0 ) if ( ! wrsock($sock, $doc . "\r\n", -mssg => $dispmssg) );

	#
	# Now see if we get a connection to the mail server.
	#
	return( 0 + 1 ) if ( found_smtp_banner( $sock, -abort => ['^HTTP/1.\d [45]\d\d'] ) );
	
	return( 0 + 0 );
}



#####
#
# usage:	proxy_test_socks4($sock)
# function:	Test for an unsecured SOCKS4 proxy.
# returns:	Return TRUE if open proxy detected.
#
# reference: http://www.socks.nec.com/protocol/socks4.protocol
#

my %SOCKS4_CONNECT_RESPONSES = (
	90 => "request granted",
	91 => "request rejected or failed",
	92 => "request rejected, ident required",
	93 => "request rejected, ident mismatch",
);



sub proxy_test_socks4
{

	my $sock = shift;
	my($mssg, $repcode, $repmssg);

	#
	# CONNECT request:
	#   VN		1 byte		socks version (4)
	#   CD		1 byte		command code (1 = connect)
	#   DSTPORT	2 bytes		destination port
	#   DSTIP	4 bytes		destination address
	#   USERID	variable	(not used here)
	#   NULL	1 byte
	#
	$mssg = pack("CCnA4x", 4, 1, $WEB_PORT, inet_aton($WEB_SERVER));
	return( 0 + 0 ) if ( ! wrsock($sock, $mssg) );

	#
	# CONNECT reply:
	#   VN		1 byte		version of the reply code (should be 0)
	#   CD		1 byte		command code (the result)
	#   DSTPORT	2 bytes
	#   DSTIP	4 bytes
	#
	$mssg = rdsock($sock, -nbytes => 8)
		or return( 0 + 0 );
	$repcode = (unpack("C*", $mssg))[1];
	$repmssg = $SOCKS4_CONNECT_RESPONSES{$repcode}
		|| "unknown reply code";
#	print "socks reply code = $repcode ($repmssg)\n";
	return( 0 + 0 ) unless ($repcode == 90);

	return( 0 + 2 );
}



sub proxy_test_socks4_smtp
{

	my $sock = shift;
	my($mssg, $repcode, $repmssg);

	#
	# CONNECT request:
	#   VN		1 byte		socks version (4)
	#   CD		1 byte		command code (1 = connect)
	#   DSTPORT	2 bytes		destination port
	#   DSTIP	4 bytes		destination address
	#   USERID	variable	(not used here)
	#   NULL	1 byte
	#
	$mssg = pack("CCnA4x", 4, 1, $MAIL_PORT, inet_aton( $MAIL_SERVER ) );
	return( 0 + 0 ) if ( ! wrsock($sock, $mssg) );

	#
	# CONNECT reply:
	#   VN		1 byte		version of the reply code (should be 0)
	#   CD		1 byte		command code (the result)
	#   DSTPORT	2 bytes
	#   DSTIP	4 bytes
	#
	$mssg = rdsock($sock, -nbytes => 8)
		or return( 0 + 0 );
	$repcode = (unpack("C*", $mssg))[1];
	$repmssg = $SOCKS4_CONNECT_RESPONSES{$repcode}
		|| "unknown reply code";
#	print "socks reply code = $repcode ($repmssg)\n";
	return( 0 + 0 ) unless ($repcode == 90);

	return( 0 + 1 );
}



#####
#
# usage:	proxy_test_socks5($sock)
# function:	Test for an unsecured SOCKS5 proxy.
# returns:	Return TRUE if open proxy detected.
#
# reference: http://www.socks.nec.com/rfc/rfc1928.txt
#
# WARNING!!!  This is not tested.  I haven't found access to an open SOCKS5
# server yet.  If you can test this, please let me know.
#


my %SOCKS5_METHODS = (
	0 => "no authentication required",
	1 => "GSSAPI",
	2 => "username/password",
	255 => "no acceptable methods",
);


my %SOCKS5_CONNECT_RESPONSES = (
	0 => "succeeded",
	1 => "general SOCKS server failure",
	2 => "connection not allowed by ruleset",
	3 => "Network unreachable",
	4 => "Host unreachable",
	5 => "Connection refused",
	6 => "TTL expired",
	7 => "Command not supported",
	8 => "Address type not supported",
);



sub proxy_test_socks5
{
	my $sock = shift;
	my($mssg, $repcode, $repmssg);

	#
	# METHOD SELECT message:
	#  VER		1 byte	socks version (5)
	#  NMETHODS	1 byte	number of method identifies
	#  METHODS	var	list of methods (0 = no auth)
	#
	$mssg = pack("CCC", 5, 1, 0);
	return( 0 + 0 ) if ( ! wrsock($sock, $mssg) );

	#
	# METHOD SELECT reply:
	#  VER		1 byte	socks version (5)
	#  METHOD	1 byte	method to use
	#
	$mssg = rdsock($sock, -nbytes => 2)
		or return( 0 + 0 );
	$repcode = (unpack("C*", $mssg))[1];
	$repmssg = $SOCKS5_METHODS{$repcode}
		|| "unknown or reserved method type";
#	print "socks reply code = $repcode ($repmssg)\n";
	return( 0 + 0 ) unless ($repcode == 0);

	#
	# CONNECT request:
	#   VER		1 byte		socks version (5)
	#   CMD		1 byte		command code (1 = connect)
	#   RSV		1 byte		reserved
	#   ATYP	1 byte		address type (1 = IPv4)
	#   DST.ADDR	variable	destination address
	#   DST.PORT	2 bytes		destination port
	#
	$mssg = pack("CCCCa4n", 5, 1, 0, 1, inet_aton( $MAIL_SERVER ), $MAIL_PORT );
	return( 0 + 0 ) if ( ! wrsock($sock, $mssg) );

	#
	# CONNECT reply:
	#   VER		1 byte		socks version (5)
	#   REP		1 byte		reply code
	#   RSV		1 byte		reserved
	#   ATYP	1 byte		address type (1 = IPv4)
	#   BND.ADDR	variable	server bound address
	#   BND.PORT	2 bytes		server bound port
	#
	$mssg = rdsock($sock, -nbytes => 10)
		or return( 0 + 0 );
	$repcode = (unpack("C*", $mssg))[1];
	$repmssg = $SOCKS5_CONNECT_RESPONSES{$repcode}
		|| "unknown or reserved reply code";
#	print "socks reply code = $repcode ($repmssg)\n";
	return( 0 + 0 ) unless ($repcode == 0);

	return( 0 + 1 );
}



#####
#
# usage:	proxy_test_wingate($sock)
# function:	Test for an open Wingate proxy.
# returns:	Return TRUE if open proxy detected.
#
sub proxy_test_wingate
{
	my $sock = shift;

	return( 0 + 0 ) if ( ! wrsock($sock, "$MAIL_SERVER:$MAIL_PORT\r\n") );
	$_ = rdsock($sock)
		or return( 0 + 0 );

	return( 0 + 1 ) if ( found_smtp_banner( $sock, -abort => ["^Password:"] ) );
	
	return( 0 + 0 );
}



#####
#
# usage:	proxy_test_telnet($sock)
# function:	Test for an open telnet proxy.
# returns:	Return TRUE if open proxy detected.
#
# This is something that accepts a command:  telnet <dstaddr> <dstport>
#
# Here is an example of what one of these looks like (with the
# destination address elided to protect the guilty):
#
#	$ telnet a.b.c.d
#	Trying a.b.c.d...
#	Connected to a.b.c.d.
#	Escape character is '^]'.
#	ÿûÿûsrvfwcm telnet proxy (Version 5.5) ready:
#	tn-gw-> telnet 207.200.4.66 25
#	telnet 207.200.4.66 25
#	Trying 207.200.4.66 port 25...
#	ÿüÿüÿüConnected to 207.200.4.66.
#	220 mail.soaustin.net ESMTP Postfix [NO UCE C=US L=TX]
#
sub proxy_test_telnet
{
	my $sock = shift;

	return( 0 + 0 ) if ( ! wrsock($sock, "telnet $MAIL_SERVER $MAIL_PORT\r\n") );

	return( 0 + 1 ) if ( found_smtp_banner( $sock, -abort => ["^Password:"] ) );
	
	return( 0 + 0 );
}



#####
#
# usage:	proxy_test_cisco($sock)
# function:	Test for an proxy thru an unsecured Cisco router.
# returns:	Return TRUE if open proxy detected.
#
# The idea is you use the factory default login to access the router, and
# then you can use it like a telnet proxy.
#
# Here is a sample session:
#
#
#	[chip@mint chip]$ telnet a.b.c.d
#	Trying a.b.c.d...
#	Connected to a.b.c.d.
#	Escape character is '^]'.
#	
#	
#	User Access Verification
#	
#	Password: (bad password)
#	Password: (another bad password)
#	Password: (yet another bad password)
#	% Bad passwords
#	Connection closed by foreign host.
#
sub proxy_test_cisco
{
	my $sock = shift;

	rdsock_for_message($sock, -match => "^User Access Verification")
		or return( 0 + 0 );

	#
	# There should be a "Password:" prompt here, but we won't see
	# it until the newline is terminated.
	#
	return( 0 + 0 ) if ( ! wrsock($sock, "cisco\r\n") );
	
	rdsock_for_message($sock, -match => "^Password:")
		or return( 0 + 0 );

	#
	# If the password worked, it's just a standard telnet proxy test.
	#
	return( proxy_test_telnet($sock) );
}



#####
#
# usage:	proxy_test_smtp_relay( $sock, $proxy_addr, $proxy_port, $proxy_proto)
#
# Test to see if I can make an SMTP relay connection through the socket
#
#
sub proxy_test_smtp_relay
{
	my $sock		= shift;
	my $proxy_addr	= shift;
	my $proxy_port	= shift;
	my $proxy_proto = shift;
	
	
	# Send HELO command
	return( 0 + 0 ) if ( ! wrsock($sock, "HELO $Hostname\r\n") );
	my $content = rdsock($sock);
	my $reply_code = &ReplyCode( $content );
	return( 0 + 0 ) if ( ( $reply_code < 200 )  ||  ( $reply_code > 299 ) );
	
	
	# Send MAIL command
	return( 0 + 0 ) if ( ! wrsock($sock, "MAIL FROM: <$Mail_addr>\r\n") );
	$content = rdsock($sock);	
	$reply_code = &ReplyCode( $content );
	return( 0 + 0 ) if ( ( $reply_code < 200 )  ||  ( $reply_code > 299 ) );
		
	
	# Send RCPT TO command
	return( 0 + 0 ) if ( ! wrsock($sock, "RCPT TO: <$decoy_account>\r\n") );
	$content = rdsock($sock);
	$reply_code = &ReplyCode( $content );
	return( 0 + 0 ) if ( ( $reply_code < 200 )  ||  ( $reply_code > 299 ) );	


	# Send DATA command
	return( 0 + 0 ) if ( ! wrsock( $sock, "DATA\r\n" ) );
	$content = rdsock($sock);
	$reply_code = &ReplyCode( $content );
	return( 0 + 0 ) if ( $reply_code != 354 );

	
	# Send the message data
	my $msg = &generate_mail_message( $proxy_addr, $proxy_port, $proxy_proto );
	
	return( 0 + 0 ) if ( ! wrsock( $sock, $msg ) );
	return( 0 + 0 ) if ( ! wrsock( $sock, ".\r\n" ) );
	$content = rdsock($sock);
	$reply_code = &ReplyCode( $content );
	return( 0 + 0 ) if ( ( $reply_code < 200 )  ||  ( $reply_code > 299 ) );
	

	# Send QUIT command
	return( 0 + 0 ) if ( ! wrsock( $sock, "QUIT\r\n" ) );
	$content = rdsock($sock);
	$reply_code = &ReplyCode( $content );
	
	# If I got a good return code here, it is a smtp relay server
	return( 0 + 1 ) if ( ( $reply_code >= 200 )  &&  ( $reply_code <= 299 ) );
	
	# If I got to here, it is not a smtp relay server
	return( 0 + 0 );
}



################################################################################
# 
sub ReplyCode( $ )
#
#  Given a response from a SMTP server, peel off the reply code
#  The reply code is always 3 digits numeric
#
################################################################################
{	my $content = shift;
	
	return( 0 + 0 ) if ( ! defined $content );
	
	$content =~ s/^\s//g;
	return( 0 + 0 ) if ( ! defined $content );
	
	my ( $reply_code, $junk ) = split /\s/, $content, 2;
	return( 0 + 0 ) if ( ! defined $reply_code );
	( $reply_code, $junk ) = split /\-/, $reply_code, 2;
	return( 0 + 0 ) if ( ! defined $reply_code );
	
	# Has to be 3 digits long
	return( 0 + 0 ) if ( length( $reply_code ) != 3 );
	
	# Has to be numeric digits
	return( 0 + 0 ) if ( $reply_code =~ m/\D/ );
	
	$reply_code = 0 + 0 if ( ! $reply_code );
	$reply_code = 0 + $reply_code;

	&oprint( "SMTP reply code = $reply_code\n" ) if ( $opt_debug );
	return( $reply_code );
}



#####
#
# usage:	found_smtp_banner($sock, [options ...])
#		options passed to rdsock_for_message()
# function:	Look for the SMTP greeting banner from a mail server.
# returns:	TRUE if we can obtain an SMTP greeting banner.
#
# Actually, can be used to look for anything given the -match option.
#
sub found_smtp_banner
{
	my($sock, @args) = @_;
	# example:  220 mail.soaustin.net ESMTP Postfix [NO UCE C=US L=TX]
	return rdsock_for_message($sock, -match => "$Smtp_banner", @args);
}



#####
#
# usage:	generate_mail_message($proxy_addr, $proxy_port, $proxy_proto)
# function:	Generate an email message to use as a test probe.
# returns:	Email message, with complete headers and body.
#
sub generate_mail_message
{
	my ( $proxy_addr, $proxy_port, $proxy_proto ) = @_;
	use vars qw(%ENV);

	my $arpa_date = arpa_date();
	my $mssgid = sprintf("<ipmproxytest-%d-%d\@%s>", time(), $$, $Hostname);

	#
	# Fixup SMTP sending sequence.
	#
	foreach my $seq (@MAIL_SENDING_SEQUENCE) {
		$seq->{'send'} =~ s/%HOSTNAME%/$Hostname/ if ( $Hostname );
		$seq->{'send'} =~ s/%EMAILADDR%/$Mail_addr/ if ( $Mail_addr );
	}

	$_ = $MAIL_MESSAGE_TEMPLATE;

	s/%VERSION%/$_version/g;

	s/%PROXY_ADDR%/$proxy_addr/g;
	s/%PROXY_PORT%/$proxy_port/g;
	s/%PROXY_PROTOCOL%/$proxy_proto/g;

	if (defined($Mail_tag)) {
		s/%MAIL_TAG%/$Mail_tag/g;
	} else {
		s/\s*%MAIL_TAG%//g;
	}

	s/%TO_ADDR%/$decoy_account/g if ( $decoy_account );
	s/%FROM_ADDR%/$Mail_addr/g if ( $Mail_addr );
	s/%HDR_DATE%/$arpa_date/g;
	s/%HDR_MSSGID%/$mssgid/g;

	s/%ORIG_SENDER%/$Mail_addr/g;
	s/%ORIG_HOST%/$Hostname/g;

	s/\n/\r\n/g;
	return $_;
}



#####
#
# usage:	transmit_mail_message($sock, $mssg)
# function:	Transmit an email message via SMTP.
# returns:	TRUE if the message is successfully transmitted.
#
sub transmit_mail_message
{
	my($sock, $mssg) = @_;

	foreach my $seq (@MAIL_SENDING_SEQUENCE) {
		if ($seq->{'send'} eq "%MESSAGE%") {
			return( undef ) if ( ! wrsock($sock, $mssg, -mssg => "(email message)") );
		} else {
			my $resp = smtp_command($sock, $seq->{'send'});
			if ($seq->{'resp'} && $seq->{'resp'} != $resp) {
				return 0;
			}
		}
	}

	return 1;
}



#####
#
# usage:	smtp_command($sock, $command)
# function:	Transmit an SMTP command.
# returns:	The numeric SMTP response code, or 0 on error.
#
sub smtp_command
{
	my($sock, $command) = @_;
	my $rc = 0;
	my $cont = '-';

	return( 0 ) if ( ! wrsock($sock, $command) );
	
	while (1) {
		$_ = rdsock($sock)
			or return 0;
		my($rc, $cont) = /^(\d\d\d)([- ])/
			or return 0;
		return $rc
			if ($cont eq " ");
	}
}



#####
#
# usage:	arpa_date([$secs_since_epoch])
# function:	Format a date for use in an RFC-2822 email message header.
# returns:	Date, as a string.
#
sub arpa_date
{
	my $gm = gmtime(shift || time());
	my @Day_name = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");
	my @Month_name = (
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec");

	sprintf("%-3s, %02d %-3s %4d %02d:%02d:%02d GMT",
		$Day_name[$gm->wday],
		$gm->mday, $Month_name[$gm->mon], 1900+$gm->year,
		$gm->hour, $gm->min, $gm->sec);

}



#####
#
# usage:	wrsock($sock, $data, [options ...])
#		options:
#		    -mssg => "message to display"
#		    -timeout => secs
# function:	Transmit data across socket, with timeout.
# returns:	TRUE if successful, undef if not
#
# Displays $data before sending it.
# A diagnostic message is printed if the write fails.
#
sub wrsock
{
	my $sock = shift;
	my $data = shift;
	my %args = @_;
	my $mssg = $args{-mssg} || $data;
	my $timeout = $args{-timeout} || $TIMEOUT_DATA;

	&oprint( "wrsock\n" ) if ( $opt_debug );
	
	if ( ! defined $data )
		{	&lprint( "Undefined data in wrsock\n" );
			return( undef );	
		}
		
	my $pmsg = printable_mssg($mssg);
	
	&oprint( ">>> $pmsg\n" ) if ( $opt_debug );

	my $select = IO::Select->new( $sock );
			
	if ( ! $select )
		{	&lprint( "Unable to create select object in wrsock\n" );
			return( -1 );	
		}
			
	if ( $select->can_write( $timeout ) )
		{	my $rc = syswrite( $sock, $data, length( $data ) );
			
			if ( $rc )
				{	&oprint( "wrsock ended ok\n" ) if ( $opt_debug );
					return( $rc );
				}
				
			&oprint( ">>> ERROR: error writing socket: $!\n" ) if ( $opt_debug );
			return( undef );
		}
		
	&oprint( "Error: Timeout writing socket\n" );
	
	return( undef );
}



#####
#
# usage:	rdsock_for_message($sock, [options ...])
#		options:
#		  -match => pattern
#		  -abort => [pattern, ...]
#		  -limit = nbytes
# function:	Look for the indicated match pattern.
# returns:	TRUE if we can obtain the pattern.
#
sub rdsock_for_message
{
	my($sock, %args) = @_;
	my $matchpat = $args{-match}
		or die "$0: must specify \"-match\" for rdsock_for_message()\n";
	my $abortlist = $args{-abort};
	my $limit = $INPUT_THRESHOLD;
	my $amount_read = 0;

	while (1) {
		$_ = rdsock($sock)
			or return 0;
		/$matchpat/
			and return 1;
		if ($abortlist) {
			foreach my $pat (@$abortlist) {
				/$pat/
					and return 0;
			}
		}
		$amount_read += length($_);
		if ($limit && $amount_read > $limit) {
			&oprint( "<<< WARNING: input threshold exceeded - bailing out\n" ) if ( $opt_debug );
			return 0;
		}
	}
	return 0;
}



#####
#
# usage:	rdsock($sock, [options ...])
#		options:
#		  -timeout => secs
#		  -bytes => n (default is to read a line)
# function:	Retrieve data from socket, with timeout.
# returns:	Value retrieved.
#
# Displays data retrieved.
# Returns undefined on timeout, end of input, or read failure.
#
sub rdsock
{
	my $sock = shift;
	my %args = @_;
	my $timeout = $args{-timeout} || $TIMEOUT_DATA;
	my $nb = $args{-nbytes};

	my $data;

	my $select = IO::Select->new( $sock );
	
	&oprint( "rdsock timeout $timeout\n" ) if ( $opt_debug );
	
	if ( ! $select )
		{	&lprint( "Unable to create select object in rdsock\n" );
			return( -1 );	
		}
	
	&debug( "rdsock select\n" );		
	if ( ! $select->can_read( $timeout ) )
		{	&oprint( "Timeout error in rdsock\n" ) if ( $opt_debug );
			return( undef );
		}


	if ( defined( $nb ) ) 
		{	&debug( "rdsock nd = $nb\n" );
			
			my $total_bytes = 0 + 0;
			my $count		= 0 + 0;
			
			while ( ( $total_bytes < $nb )  &&  ( $count < $timeout ) )
				{	my $remaining = $nb - $total_bytes;
					
					my $nbytes = sysread( $sock, $data, $remaining, $total_bytes );
					$total_bytes += $nbytes if ( $nbytes );
					
					# Sleep for 1 second if I still have data to read
					if ( $total_bytes < $nb )
						{	sleep( 1 );
							$count++;
						}
				}
		} 
	else 
		{	&debug( "rdsock getline\n" );
			
			my $linefeed;
			my $total_bytes = 0 + 0;
			my $count		= 0 + 0;
			my $max_len		= 0 + $INPUT_THRESHOLD;
			
			# Read until I have at least one linefeed or max_len
			while ( ( ! $linefeed )  &&  ( $count < $timeout ) )
				{	my $nbytes = sysread( $sock, $data, ( $max_len - $total_bytes ), $total_bytes );
					$total_bytes += $nbytes if ( $nbytes );
					
					$linefeed = 1 if ( ( $data )  &&  ( $data =~ m/\n/ ) );
					
					# Sleep for 1 second if I still have data to read
					if ( ( ! $linefeed )  &&  ( ! $nbytes ) )
						{	sleep( 1 );
							$count++;
						}
				}
		}

	&debug( "rdsock finished read\n" );
	
	if ( ( $data )  &&  ( $opt_debug ) )
		{	my $pmsg = printable_mssg( $data );
			&oprint( "<<< $pmsg\n" );
		}

	&oprint( "rdsock end\n" ) if ( $opt_debug );
	
	return $data;
}



#####
#
# usage:	printable_mssg($data)
# function:	Generate a printable string from an arbitrary data string.
# returns:	Printable string.
#
# If the data is printable text data, then it is returned with trailing
# newlines elided.
#
# If the data includes unprintable content, then it is displayed as a
# list of byte values.
#
sub printable_mssg
{
	$_ = shift;

	if (/^[[:print:][:space:]]*$/) {
		s/\r/\\r/g;
		s/\n/\\n/g;
		return $_
	}
	my @x = unpack("C*", $_);
	return "binary message: " . join(" ", map(sprintf("%d", $_), @x));
}



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     lprint( @_ );
}



################################################################################
#
sub oprint( @ )
#
#  Print a line of text to STDOUT in normal or HTML format, depending on the CGI enviroment
#  And also print it to the log file
#
################################################################################
{		
	bprint( @_ );	
	&PrintLogFile( @_ ) if ( $opt_logging );
}



################################################################################
#
sub CheckDatabase( $@ )
#
#  Given a domain and a list of IP addresses, check them to see if any one of them
#  is currently blocked in the database.  Return the is_proxy value and the category
#  number.
#
#  Return 0 if ok, 1 if a smtp proxy, 2 if a www proxy, 3 is blocked in the database
#
################################################################################
{	my $domain = shift;	# May be undef
	my @addresses = @_;
	
	return( 0 + 0 ) if ( $opt_no_database );
	
	my $is_proxy = 0 + 0;
	my $catnum = 0 + 0;
	my $source;
	
	if ( defined $domain )
		{	( $catnum, $source ) = &CheckDatabaseDomain( $domain );
			$is_proxy = &CheckCategory( $catnum ) if ( $catnum );
		}
	
	if ( $is_proxy )	
		{	my $catname = &CategoryName( $catnum );
			$catname = "unknown" if ( ! $catname );
			&oprint( "From database $domain is in category $catname\n" );
			return( $is_proxy, $catnum );
		}

	foreach ( @addresses )
		{	next if ( ! defined $_ );
			
			my $str_ipaddress = $_;
			
			( $catnum, $source ) = &CheckDatabaseIPAddress( $str_ipaddress );
			$is_proxy = &CheckCategory( $catnum ) if ( $catnum );
			
			if ( $is_proxy )	
				{	my $catname = &CategoryName( $catnum );
					$catname = "unknown" if ( ! $catname );
					&oprint( "From database $str_ipaddress is in category $catname\n" );
					return( $is_proxy, $catnum );
				}
		}
		
	return( $is_proxy, $catnum );
}



################################################################################
#
sub CheckDatabaseIPAddress( $ )
#
#  Return the category and sourcenumber of a known IP address, or undef if unknown
#
################################################################################
{   my $ip_addr = shift;  # The IP address in text format
	
	my $ipaddress = StringToIP( $ip_addr );

	$dbh = &SqlErrorCheckHandle( $dbh );
    my $sth = $dbh->prepare( "SELECT IpAddress, CategoryNumber, SourceNumber FROM IpmContentIpAddress WHERE IpAddress = ?" );
    $sth->bind_param( 1, $ipaddress,  DBI::SQL_BINARY );
    $sth->execute();
	
    my ( $ipAddress, $categoryNumber, $sourceNumber ) = $sth->fetchrow_array();
	
	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	$categoryNumber = 0 + $categoryNumber if ( $categoryNumber );
	$sourceNumber = 0 + $sourceNumber if ( $sourceNumber );
	
	return( $categoryNumber, $sourceNumber );
}
	  
	  

################################################################################
#
sub CheckDatabaseDomain( $ )
#
#  Return the category and sourcenumber of a known domain, or undef if unknown
#
################################################################################
{   my $domain = shift;
	
	my $retcode = &LookupUnknown( $domain, 0 );
			
	return( 0 + 0, 0 + 0 ) if ( ! $retcode );
	
	my ( $catnum, $source )  = &FindCategory( $domain, $retcode );
	
	return( $catnum, $source );
}
	  
	  

################################################################################
#
sub CheckCategory( $ )
#
#  Given a category number, return the is_proxy value
#  Return 0 if ok, 1 if a smtp proxy, 2 if a www proxy, 3 if blocked in the database
#
################################################################################
{   my $catnum = shift;
	
	return( 0 + 0 ) if ( ! $catnum );
	
	my $is_proxy = 0 + 0;
	$is_proxy = 0 + 3 if ( &BlockedCategoryNumber( $catnum ) );
	
	my $catname = &CategoryName( $catnum );
	return( 0 + 0 ) if ( ! $catname );
	
	$is_proxy = 0 + 1 if ( &SpamBlockedCategoryName( $catname ) );
	$is_proxy = 0 + 2 if ( $catname =~ m/proxy/ );
	
	return( $is_proxy );
}
	  
	  

################################################################################
#
sub ChangeDatabaseIPAddress( $ )
#
#  Change to category of an IP address to spam
#
################################################################################
{   my $ip_addr = shift;  # The IP address in text format
	
	my $spam = &CategoryNumber( "spam" );
	return( undef ) if ( ! $spam );
	
	my $ipaddress = StringToIP( $ip_addr );

	$dbh = &SqlErrorCheckHandle( $dbh );
    my $sth = $dbh->prepare( "UPDATE IpmContentIpAddress SET CategoryNumber = $spam, TransactionTime = getutcdate() WHERE IpAddress = ?" );
    $sth->bind_param( 1, $ipaddress,  DBI::SQL_BINARY );
    $sth->execute();
		
	&SqlErrorHandler( $dbh );
	$sth->finish();
		
	return( 1 );
}
	  
	  

################################################################################
#
sub AddDatabaseIPAddress( $ )
#
#  Add to category spam an IP address
#
################################################################################
{   my $ip_addr = shift;  # The IP address in text format
	
	my $spam = &CategoryNumber( "spam" );
	return( undef ) if ( ! $spam );
	
	my $retcode = &AddNewTrans( $ip_addr, $spam, 0, $opt_source );
		
	return( $retcode );
}
	  
	  

################################################################################
# 
sub URLIPAddresses( $ )
#
#  Given a URL, return all the IP addresses in DNS for it
#
################################################################################
{	my $url = shift;
	
	my @addresses;
	
	return( @addresses ) if ( ! $url );
	
	my ( $domain, $url_ext ) = split /\//, $url, 2;

	return( @addresses ) if ( ! $domain );
	
	# Is the domain an IP address itself?
	return( @addresses ) if ( &IsIPAddress( $domain ) );
	
use Net::DNS;
	my $res = Net::DNS::Resolver->new;
	$res->tcp_timeout( $TIMOUT_DNS );
	$res->udp_timeout( $TIMOUT_DNS );
	
	&oprint( "Querying DNS for $domain ...\n" );
	
	my $query = $res->search( $domain ); 
	if ( ! $query )
		{	my $error = $res->errorstring;
			$error = "Unknown error" if ( ! $error );
			
			# Does this domain or host exist at all?
			my $nonexisiting_domain;
			$nonexisiting_domain = 1 if ( $error eq "NXDOMAIN" );
			
			$error = "nonexisting hostname or domain" if ( $nonexisiting_domain );				
			&oprint( "DNS Query failed: $error\n" );
				
			return( @addresses );
		}
		
	foreach my $rr ( $query->answer ) 
		{	next unless $rr->type eq "A";
			my $ip = $rr->address;

			# Make sure it is a good IP address
			next if ( ! &IsValidIP( $ip ) );
			push @addresses, $ip;
		}

	my $count = $#addresses + 1;
	&oprint( "DNS found IP address $addresses[ 0 ]\n" ) if ( $count == 1 );
	&oprint( "DNS found IP addresses @addresses\n" ) if ( $count > 1 );
	&oprint( "DNS did not found any IP addresses\n" ) if ( ! $count );

		
	return( @addresses );
}



################################################################################
#
sub NonExistingDomains( @ )
#
#  We just did a DNS query on these domains, and it came up non existing, so move
#  them to the errors category if it is in the database
#
################################################################################
{	my @domains	= @_;

	# Should I even be doing this?	
	return( undef ) if ( ! $opt_nonexisting );
	
	# Am I using the database at all?
	return( undef ) if ( $opt_no_database );
	
	
	# Move it to the errors category
	my $catnum = &CategoryNumber( "errors" );
	
	
	# Go through each of the domains
	foreach ( @domains )
		{	next if ( ! $_ );
			
			my $domain = $_;
			
			my $retcode = &LookupUnknown( $domain, 0 );
					
					
			#  If I don't know this $domain at all, just go on to the next
			next if ( ! $retcode );
			
			
			my ( $old_catnum, $source ) = &FindCategory( $domain, $retcode );
			my $old_catname = &CategoryName( $old_catnum );
					
					
			# Is it already in errors?
			if ( $old_catnum eq $catnum )
				{	&oprint( "$domain is already in category errors\n" );
					next;	
				}
					
					
			# Put it into the errors category				
			my $ret = &UpdateCategory( $domain, $catnum, $retcode, $opt_source );
			
			if ( ! $ret )
				{	&oprint( "Switched $domain from $old_catname to errors\n" );
					$changed_domain++;
				}
			else
				{	&oprint( "Error $ret trying to switch $domain from $old_catname to errors\n" );
				}
		}

	return( 1 );
}



################################################################################
#
sub CheckedProxy( $ )
#
#  Given the proxy status, return the definition of that status
#
################################################################################
{   my $proxy_status = shift;  # The IP address in text format
	
	my $result = "in a blocked category" ;
	$result = "not a proxy" if ( ! $proxy_status );
	
	return( $result ) if ( ! $proxy_status );
	
	$result = "a SMTP proxy" if ( $proxy_status == 1 );
	$result = "a WWW proxy" if ( $proxy_status == 2 );
		
	return( $result );
}
	  
	  

################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmProxyTest";

    bprint <<".";
Usage: $me [urlfile]

This utlity checks URLs and IP addresses to see if they are Web proxies, SMTP
proxies, or SMTP relay servers.  If any proxies are found the content database
will be updated.

This utility also checks IP addresses of unknown domains to see if the IP
address is from a known proxy, relay server, or spammer.  If so, the domain
will be added to the content database in the appropriate category.

You can either enter URLs and IP addresses on the command line, or you can
enter a file name that contains URLs and IP addresses to check.

Command line options:

  -a, --allports       check all possble ports, incluging Sobig ports
  -c, --check          check all IPs and change database if not a proxy
  -d, --dnserrors      move domains with DNS errors into the errors category
  -f, --logfile fname  to change the default logfile to fname
  -g, --noproxy        to check DNS but no proxy port tests
  -k, --kill           kill any copies of IpmProxyTest.exe that are running
  -l, --logging        log every action to IpmProxyTest.log
  -m, --mailonly       only check for smtp relay mail servers - no WWW proxies
  -n, --nodatabase     don\'t use the Content database
  -o, --override       override a known unblocked URL category if a proxy
  -p, --proxy target   to change the default target for the HTTP proxy test
  -r, --range          to enter a range of IPs, ie 192.168.0.1-192.168.0.255
  -s, --source         source number to use for database adds - default is 4
  -t, --timeout sec    set the checking timeout in seconds
  -v, --verbose        display everything that is going on
  -h, --help           display this help and exit
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
    my $me = "IpmProxyTest";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
