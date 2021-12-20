################################################################################
#!perl -w
#
# Rob McCarthy's Ipm Monitor source code
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use warnings;
use strict;


use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::ConnCache;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32;
use Win32::API;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;
use Net::SMTP::Multipart;
use Sys::Hostname;
use Cwd;


use Content::File;
use Content::SQL;
use Content::Mail;
use Content::Monitor;
use Content::MonitorCommand;
use Content::Process;
use Content::ScanUtil;

use Content::SAImport;


# Command line options
my $opt_help;
my $opt_debug;		# True if debugging
my $opt_version;	# Trus if I should display the version number
my $opt_logging;	# True if I should be logging details
my $opt_wizard;		# True if I should't display headers and footers
my $opt_kill;		# True if all I need to do is kill the other IpmMonitors that are running
my $opt_verbose;	# True if I need to print verbose messages



# Globals
my $_version = "2.0.0";
my $dbh;
my $dbhStats;				# My database handle for the statistics database
my $sql_errmsg;				# The last SQL error message
my @list;					# The list of things to monitor
my $service_started;		# True if I have reported that the service has started
my $last_server_check_time = time;	# The last time I checked the servers that I'm supposed to monitor			
my $monitor_event_name	= "IPM_MONITOR";		# The event name of the signal to the other IpmMonitor programs to die
my $monitor_event;			# The event object that I am watching
my $next_command;			# The next command to execute
my $next_command_item;		# The item number of the next command
my $last_command_result;	# If defined, this contains the result of the last command executed
my %license_key_hostname;	# A hash of key = license_key, value = descriptive hostname
my %license_key_heartbeat;	# A hash of key = license_key, value = heartbeat time in minutes - 0 is don't monitor
my $ua;						# The user agent for reuse
my $cache;					# The connection cache for reuse
my $sql_agent = "SqlAgent.exe";	# This is the name of the Sql Agent program when it is running

my $last_saexport_download; # The last time I (checked for) downloaded the SA export files
my $last_sacritical_export; # The last time I exported local changes and/or downloaded the critical SA export

# Contact info - read from registry and flipped to the monitoring serverby a URL
my $contact_name;
my $contact_org;
my $contact_phone;
my $contact_email;



# True if the database table exists
my $monitored_servers_table;		
my $monitored_server_items_table;		
my $monitored_alerts_table;
my $monitored_alerts_priority_table;
my $security_agent_service_actions;



# Reporting options - times are in minutes
my $default_monitor_server		= "monitor.lightspeedsystems.com";
my $monitor_server				= $default_monitor_server;
my $heartbeat_time				= 0 + 20;
my $report_time					= 0 + 10;
my $stale_time					= 4 * 60;
my $license_key					= "0000-1111-2222-3333-4444";
my $site_code					= "Unknown";
my $serial_number				= "Unknown";
my $hostname					= "hostname";
my $comment;							# The comment field is where I put clues about the local machine
my $enable_remote_monitoring	= 1;
my $enable_local_monitoring		= 1;
my $default_alert_email_list;			# This is the default email address to send if nothing is configured



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
        "k|kill"	=> \$opt_kill,
        "l|logging" => \$opt_logging,
        "v|verbose" => \$opt_verbose,
        "w|wizard"	=> \$opt_wizard,
        "x|xdebug"	=> \$opt_debug,
        "h|help"	=> \$opt_help
    );


    &StdHeader( "IpmMonitor" ) if ( ! $opt_wizard );


    &Usage() if ( $opt_help );
    &Version() if ($opt_version);
	
# Debugging different Monitor Commands
#my $ret = &CommandSerialNumber( "serialnumber: 1234-567-89abcd" );
#print "Monitor return = $ret\n";
#die;


	# Give myself debug privileges
	&ProcessSetDebugPrivilege();
	

	# Make sure that I'm the only IpmMonitor program running
	my $ok = &KillOtherMonitors();
	exit( 0 ) if ( $opt_kill );	# If that is all I'm supposed to do then just quit
	

	# Make sure full logging is enabled if debugging
	$opt_logging = 1 if ( $opt_debug );
	&SetLogFilename( "IpmMonitor.log", $opt_logging );
	&lprint( "Set logging file to IpmMonitor.log\n" );
		
	
	# Get rid of any old error log files
	unlink( glob( "*errors.log" ) );

	
	# Catch any errors 
	&TrapErrors() if ( ! $opt_debug );


	# Wait for all the services to start
	&lprint( "Waiting for all the services to start ...\n" );
	sleep( 60 );
	
	
    #  Open the databases
	&OpenDatabases();


	# Get the properties out of the registry
	&GetProperties();


	# Show who I am ...
	&lprint( "Host name: $hostname\n" );
	&lprint( "License: $license_key\n" );
	&lprint( "Site Code: $site_code\n" );
	&lprint( "Serial Number: $serial_number\n" );
	
	my $license_status = &MonitorTTCLicenseStatus();
	&lprint( "License status: $license_status\n" ) if ( $license_status );

	&lprint( "Monitoring Server: $monitor_server\n" ) if ( $monitor_server );
	&lprint( "No Monitoring Server\n" ) if ( ! $monitor_server );

	

	my $sql_version = &SqlVersion();
	$sql_version = "MSDE" if ( ! defined $sql_version );
	&lprint( "SQL Version: $sql_version\n" );
	
	# SQL 2005 has a different sql agent program
	$sql_agent = "SqlAgent.exe";
	$sql_agent = "SqlAgent90.exe" if ( $sql_version =~ m/SQL Server 2005/i );
	&lprint( "SQL Agent Program: $sql_agent\n" );
	

	# Initialize any monitoring stuff
	&Initialize();


	# Loop around monitoring everything
	&MonitorLoop();
	
	
	#  Clean up everything and quit
	&CloseDatabases();


   &StdFooter if ( ! $opt_wizard );

exit;
}
################################################################################



################################################################################
# 
sub OpenDatabases()
#
#  Open up the connections to the SQL databases
#
################################################################################
{
	&lprint( "Opening up connections to the SQL databases\n" );
	
	# Set the error handler to don't terminate the program if there is an error
	&SqlErrorTerminate( undef );
	
	$dbhStats->disconnect if ( $dbhStats );
	$dbhStats = undef;
	$dbh->disconnect if ( $dbh );
	$dbh = undef;
	
	$dbh = &ConnectServer();
	&lprint( "Unable to connect to Content database\n" ) if ( ! $dbh );
	&lprint( "Connected to Content database\n" ) if ( $dbh );
	
    $dbhStats = &ConnectStatistics();
	&lprint( "Unable to connect to Statistics database\n" ) if ( ! $dbhStats );
	&lprint( "Connected to Statistics database\n" ) if ( $dbhStats );
	
	# Get the list of tables that are installed in the databases
	$monitored_servers_table			= &SqlTableExists( "MonitoredServers" );
	$monitored_server_items_table		= &SqlTableExists( "MonitoredServerItems" );
	$monitored_alerts_table				= &SqlStatTableExists( "MonitoredAlerts" );
	$monitored_alerts_priority_table	= &SqlTableExists( "MonitoredServerPriority" );
	$security_agent_service_actions		= &SqlStatTableExists( "saServiceActions" );

	&MonitorSqlInitialize( $dbh, $dbhStats, $security_agent_service_actions );
	
	return( 1 );
}



################################################################################
# 
sub CloseDatabases()
#
#  Close the connections to the SQL databases
#
################################################################################
{
	$dbhStats->disconnect if ( $dbhStats );
	$dbhStats = undef;
	$dbh->disconnect if ( $dbh );
	$dbh = undef;
	
	return( 1 );
}



################################################################################
#
sub CheckDatabases()
#
#  Check to make sure the database connections are still going
#  Return True if they are ok, undef if not and an error message
#
################################################################################
{	
	&lprint( "CheckDatabases: Checking connections to the databases ...\n" );

	# Did one of the databases have an error?
	my $msg;
	my $err;
	
	# Check to make sure this handle hasn't been reconnected recently
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
			
	# Do I have a connection to the Statistics database?
	if ( ! $dbhStats )
		{	$dbhStats = &ConnectStatistics();
			
			if ( ! $dbhStats )
				{	&lprint( "CheckDatabases: Unable to connect to the Statistics SQL database\n" );
					$msg = "CheckDatabases: Unable to connect to the Statistics SQL database\n";
				}
		}
		
		
	# If I do have a connection - try to see if my tables are installed.  This will force an error if there is one	
	if ( $dbhStats )	
		{	$monitored_alerts_table		= &SqlStatTableExists( "MonitoredAlerts" );
			$security_agent_service_actions	= &SqlStatTableExists( "saServiceActions" );
			$dbhStats = &SqlErrorCheckHandle( $dbhStats );
		}
	
	
	# Do I have an error with the Statistics database?	
	$err = $dbhStats->err if ( $dbhStats );
	if ( $err )
		{	my $errstr = $dbhStats->errstr;
			&lprint( "CheckDatabases: Statistics SQL database error: $errstr\n" );
			$msg = "CheckDatabases: Statistics SQL database error: $errstr\n" if ( ! $msg );
			$msg = $msg . "\nCheckDatabases: Statistics SQL database error: $errstr\n" if ( $msg );
			
			$dbhStats->disconnect;
			$dbhStats = undef;

			&lprint( "CheckDatabases: Trying to reconnect to the Statistics database\n" );
			$dbhStats = &ConnectStatistics();
			
			if ( ! $dbhStats )
				{	&lprint( "CheckDatabases: Unable to reconnect to the Statistics SQL database\n" );
					$msg = "CheckDatabases: Unable to reconnect to the Statistics SQL database\n" if ( ! $msg );
					$msg = $msg . "\nCheckDatabases: Unable to reconnect to the Statistics SQL database\n" if ( $msg );
				}
		}
	
	
	
	# Check to make sure this handle hasn't been reconnected recently
	$dbh = &SqlErrorCheckHandle( $dbh );
	
	# Do I have a connection to the Content database?
	if ( ! $dbh )
		{	$dbh = &ConnectServer();
			
			if ( ! $dbh )
				{	&lprint( "CheckDatabases: Unable to connect to the Content SQL database\n" );
					$msg = "CheckDatabases: Unable to connect to the Content SQL database\n" if ( ! $msg );
					$msg = $msg . "\nCheckDatabases: Unable to connect to the Content SQL database\n" if ( $msg );
				}
		}
		
		
	# If I do have a connection - try to see if my tables are installed.  This will force an error if there is one	
	if ( $dbh )	
		{	$monitored_servers_table			= &SqlTableExists( "MonitoredServers" );
			$monitored_server_items_table		= &SqlTableExists( "MonitoredServerItems" );
			$monitored_alerts_priority_table	= &SqlTableExists( "MonitoredServerPriority" );
			$dbh = &SqlErrorCheckHandle( $dbh );
		}
	
	
	# Do I have an error with the Content database?	
	$err = undef;
	$err = $dbh->err if ( $dbh );
	if ( $err )
		{	my $errstr = $dbh->errstr;
			&lprint( "Content SQL database error: $errstr\n" );

			$msg = "CheckDatabases: Content SQL database error: $errstr\n" if ( ! $msg );
			$msg = $msg . "\nCheckDatabases: Content SQL database error: $errstr\n" if ( $msg );

			$dbh->disconnect;
			$dbh = undef;

			&lprint( "CheckDatabases: Trying to reconnect to the Content database\n" );
			$dbh = &ConnectServer();
			
			if ( ! $dbh )
				{	&lprint( "CheckDatabases: Unable to reconnect to the Content SQL database\n" );
					$msg = "CheckDatabases: Unable to reconnect to the Content SQL database\n" if ( ! $msg );
					$msg = $msg . "\nCheckDatabases: Unable to reconnect to the Content SQL database\n" if ( $msg );
				}
		}
	
		
	&lprint( "CheckDatabases: Connected to the Statistics SQL database OK\n" ) if ( $dbhStats );
	&lprint( "CheckDatabases: Connected to the Content SQL database OK\n" ) if ( $dbh );
	
	
	# Get the list of tables that are installed in the databases
	$monitored_servers_table			= undef;
	$monitored_server_items_table		= undef;
	$monitored_alerts_table				= undef;
	$monitored_alerts_priority_table	= undef;
	$security_agent_service_actions		= undef;
	
	
	# Recheck the tables just to make sure everything is OK
	if ( $dbh )
		{	$monitored_servers_table			= &SqlTableExists( "MonitoredServers" );
			$monitored_server_items_table		= &SqlTableExists( "MonitoredServerItems" );
			$monitored_alerts_priority_table	= &SqlTableExists( "MonitoredServerPriority" );
			$dbh = &SqlErrorCheckHandle( $dbh );
		}
		
		
	if ( $dbhStats )
		{	$monitored_alerts_table			= &SqlStatTableExists( "MonitoredAlerts" );
			$security_agent_service_actions	= &SqlStatTableExists( "saServiceActions" );
			$dbhStats = &SqlErrorCheckHandle( $dbhStats );
		}
		
		
	&MonitorSqlInitialize( $dbh, $dbhStats, $security_agent_service_actions );

		
	# Return what happened	
	return( 1, undef ) if ( ! $msg );
	return( undef, $msg );	
}




################################################################################
# 
sub KillOtherMonitors()
#
#  Make sure that I'm the only IpmMonitor program running
#
################################################################################
{	
	my $others;
	$others = &IsOtherMonitors();
	print "Signalled the other IpmMonitor program to end gracefully ...\n" if ( $others );
	print "No other IpmMonitor programs are running by this user\n" if ( ! $others );

		
	# Wait for up to 1 minute
	my $waited_seconds = 0 + 0;
	while ( ( $others )  &&  ( $waited_seconds < ( 1 * 60 ) ) )
		{				
			$others = &IsOtherMonitors();
			
			# If I can still open the event, wait for a second, signal the kill, and try again
			if ( $others )
				{	sleep( 1 );
					$waited_seconds++;		
				}
		}
	
	
	# At this point I've been nice - now I'm getting mean
	my $my_pid = &ProcessGetCurrentProcessId();

	my %processes = &ProcessHash();
	
	# Figure out if there are any IpmMonitor processes running besides myself
	my @process_names	= values %processes;
	my @process_pids	= keys %processes;
	
	my @kill_pids;
	
	my $index = 0 - 1;
	foreach ( @process_names )
		{	$index++;
			
			next if ( ! $_ );
			
			my $name = lc( $_ );
			
			# Is this an IpmMonitor process?
			next if ( ! ( $name =~ m/ipmmonitor\.exe/ ) );
			
			my $this_pid = $process_pids[ $index ];
			
			next if ( $this_pid eq $my_pid );
	
			push @kill_pids, $this_pid;				 
		}


	print "Found IpmMonitor processes being run by other users, so killing them now ...\n" if ( $kill_pids[ 0 ] );
	
	# If I found any, kill them
	foreach ( @kill_pids )
		{	next if ( ! $_ );
			my $kill_pid = $_;
			print "Killing process $kill_pid\n";
			ProcessTerminate( $kill_pid );
		}
		

	# At this point we are all set to go ...
	$monitor_event = Win32::Event->new( 1, 0, $monitor_event_name );
	if ( ! $monitor_event )
		{	print "Unable to stop other IpmMonitor programs from running\n";
			return( undef );
		}
		
	return( 1 );
}



################################################################################
# 
sub IsOtherMonitors()
#
#  Return True if another IpmMonitor program is running
#  Signal the other guy to die
#
################################################################################
{
	Win32::SetLastError( 0 + 0 );
	my $existing_event = Win32::Event->open( $monitor_event_name );
	my $WinError = Win32::GetLastError();
	
	$existing_event->set if ( $existing_event );
	
	return( 1 ) if ( ( $existing_event )  ||  ( $WinError == 5 ) );
	
	return( undef );
}



################################################################################
# 
sub Initialize()
#
#  Setup the initial conditions for monitoring
#
################################################################################
{	
	&MonitorEventlogInitialize();
	&MonitorProcessHash();
	&MonitorProcessHashSave();
	&ClearSpool();
	
	return( 1 );
}



################################################################################
# 
sub ClearSpool( $ )
#
#  Clear the spool directory of any old monitoring alerts
#
################################################################################
{	my $options = shift;
	
	my $spool_dir = &SpoolDirectory();
	
	return( 1 ) if ( ! opendir( DIRHANDLE, $spool_dir ) );

	my $counter = 0 + 0;
	
	for my $item ( readdir( DIRHANDLE ) )
		{	next if ( ! $item );
			next if ( $item eq "." );
			next if ( $item eq ".." );

			next if ( ! ( $item =~ m/MonitorAlert/ ) );
			
			my $full_path = $spool_dir . "\\$item";
			
			my $ok = unlink( $full_path );
			next if ( ! $ok );
			
			$counter++;
		}
		
	closedir( DIRHANDLE );
	
	&lprint( "Deleted $counter old alert messages from the spool directory\n" );
	
	return( 1 );
}



################################################################################
# 
sub MonitorLoop()
#
#  Loop around monitoring everything
#
################################################################################
{
	my $done;

	lprint( "Getting monitor list\n" );
	
	@list = &GetMonitorList( $monitor_server );
		
	while ( ! $done )
		{	&lprint( "\n\nTop of Monitor Loop ...\n" );
			my $start_time = time;
			
			# Show who I am ...
			&lprint( "Host name: $hostname\n" );
			&lprint( "License: $license_key\n" );
			&lprint( "Site Code: $site_code\n" );
			&lprint( "Serial Number: $serial_number\n" );
			&lprint( "Monitoring Server: $monitor_server\n" ) if ( $monitor_server );
			&lprint( "No Monitoring Server\n" ) if ( ! $monitor_server );


			# Try to make sure that both databases are open and working ok
			my ( $ok, $msg ) = &CheckDatabases();
			
			
			# Check to see if I have any alert priorities to check
			PriorityLoad();
			
			
			lprint( "Checking for new reporting options\n" );
			&GetProperties();
			@list = &GetMonitorList( $monitor_server );
				
			
			# Look for the SA export files on the SA servers.
			# Only do this every 30 minutes.
			if ( ! defined $last_saexport_download || (time - $last_saexport_download > 60 * 30) )
				{	my $download_ok = &SAExportDownloadFiles();
					$last_saexport_download = time;
					
					if ( !$download_ok )
						{	# Force a monitor alert on this event
							my @export_results = ();
							
							push @export_results, -500;
							push @export_results, "Failed to properly download SA export files from Lightspeed Systems.";
							
							&ReportList( @export_results );
						}
				}
			
			# Try exporting out local (changes
			# Only do this every 60 minutes.
			if ( ! defined $last_sacritical_export || (time - $last_sacritical_export > 60 * 60) )
				{	&SAExport();
					$last_sacritical_export = time;
				}

			
			# Is there anything to check?
			my @results;
			if ( defined $list[ 0 ] )	
				{	lprint( "Checking monitor list\n" );
					@results = &CheckList( @list );
				}
				
				
			# Is there anything to report?
			if ( defined $results[ 0 ] )
				{	lprint( "Reporting the results\n" );
					&ReportList( @results );
				}
			

			# Is there a command that I should run?
			if ( ( $next_command )  &&  ( defined $next_command_item )  &&  ( &ClearMonitorCommand( $next_command_item ) ) )
				{	$last_command_result = &CommandExecute( $next_command, $hostname, $monitor_server );
					
					# Open the database back up if I restarted SQL
					&OpenDatabases() if ( lc( $next_command ) eq "restartsql" );

					@results = ();
					push @results, $next_command_item;
					push @results, $last_command_result;
					
					lprint( "Reporting the command results: Command: $next_command_item, Result: $last_command_result\n" );
					&ReportList( @results );

					$next_command		= undef;
					$next_command_item	= undef;
					@results = ();
				}
				
				
			# Check to see if there are alerts from servers that I'm monitoring that need to be emailed
			# from the local SQL database
			&EmailMonitoredServers();
			
			
			# Calculate how long to sleep
			my $elapsed_time = time - $start_time;
			my $secs_to_sleep = ( 60 * $report_time ) - $elapsed_time;
			
			# Sleep for a minimum of 1 minute
			$secs_to_sleep = 0 + 60 if ( $secs_to_sleep < 60 );
			
			my $minutes_to_sleep = $secs_to_sleep / 60;
			$minutes_to_sleep = &Round( $minutes_to_sleep );
			
			
			# Close the databases before sleeping ...
			&CloseDatabases();
			
			lprint( "Waiting $minutes_to_sleep minutes before checking again\n" );
			
			# Wait for a timeout, or a kill event
			my $milli_secs_to_sleep = 1000 * $secs_to_sleep;
			my $ret = $monitor_event->wait( $milli_secs_to_sleep );
			
			if ( ( ! $ret )  ||  ( $ret == -1 ) )
				{	#&lprint( "No kill events have been received\n" );
				}
			else
				{	&lprint( "Ending now because another copy of the IpmMonitor program has been started\n" );
					return( 1 );		
				}
				
				
			# Open back up the databases
			&OpenDatabases();
		}
	
	return( 0 );
}



################################################################################
# 
sub GetMonitorList()
#
#  Ask the monitor server for a list of what I should check
#  Also get my local monitoring properties
#  Merge the 2 lists into one combined list to monitor
#
################################################################################
{	my $server = shift;
	
	
	# This is the list of things that I'm supposed to monitor
	my @list = ();
	
	
	# Add to my list the remote monitoring options if they are enabled
	if ( ( $enable_remote_monitoring )	&&  ( $server ) )
		{	# Build up my default monitoring list
			
			@list = (  -2, "Service", undef,
					   -1, "CheckServers", undef,
						1, "Process", "IpmManagerServer.exe",
						2, "Process", "IpmService.exe",
						3, "Process", "sqlservr.exe",
						4, "Process", $sql_agent,
						5, "Process", "Inetinfo.exe",
						6, "Process", "IpmSMTPRelay.exe",
						7, "Eventlog", "System Error",
						8, "Eventlog", "Application Error",
						9, "Eventlog", "Reports Error",
						10, "Eventlog", "Lightspeed Error",
						11, "Eventlog", "Lightspeed Warning",
						12, "Appendlog", "IpmRealtimeSpamErrors.log",
						13, "Appendlog", "IpmCategorizeErrors.log",
						14, "Appendlog", "IpmSpamForwardErrors.log",
						15, "Appendlog", "SpamReviewErrors.log",			 
						16, "Appendlog", "IpmMonitorErrors.log",
						17, "Appendlog", "SqlReloadErrors.log",
						18, "Appendlog", "SqlOptimizeErrors.log",
						19, "Appendlog", "IpmProxyTestErrors.log",
						20, "Appendlog", "IpmIndexErrors.log",
						21, "Appendlog", "IpmArchiveErrors.log",
						22, "Appendlog", "IpmRetrieveErrors.log",
						23, "Appendlog", "IpmArchiveBackupErrors.log",
						24, "Appendlog", "SuspiciousQueryErrors.log",
						25, "Appendlog", "POP3ConnecterErrors.log",
						26, "SQL", "Content",
						27, "SQL", "Statistics",
						28, "IIS", undef,
						29, "Spam", "Realtime Checker Timeout",
						30, "ScheduledTask", "TTC Update Banned Processes",
						31, "NoScheduledTask", "TTC Categorize URLs Locally",
						32, "NoScheduledTask", "TTC Update Content Database",
						33, "NoScheduledTask", "TTC Update Software",
						34, "DatabaseUpdate", undef,
						35, "CheckLicense", undef,
						36, "CheckComputerCount", undef
					);
	
	
			my @download_list = &DownloadAlertList();
			
			# If I got a list from my monitoring server, use it
			@list = @download_list if ( defined $download_list[ 0 ] );
		}	# end if if enable_remote_monitoring
		
	
	if ( $enable_local_monitoring )
		{	# Get the list that is configured locally	
			my @local_list = &GetLocalMonitorList();

			# Merge the two lists 
			my %unique_key;
			
			# First go through the main list building up the unique key hash
			my $counter = 0 + 0;
			while ( defined $list[ $counter ] )
				{	my $item = $list[ $counter ];
					$counter++;
					
					my $type = $list[ $counter ];
					
					$counter++;
					
					my $options = $list[ $counter ];
					$counter++;
					
					$options = "None" if ( ! $options );
					
					my $key = lc ( $type . $options );
					
					$unique_key{ $key } = 0 + 0;
				}
				

			# Now add the local monitoring list that is unique to the main list
			$counter = 0 + 0;
			while ( defined $local_list[ $counter ] )
				{	my $item = $local_list[ $counter ];
					$counter++;
					
					my $type = $local_list[ $counter ];
					
					$counter++;
					
					my $options = $local_list[ $counter ];
					$counter++;
					
					$options = "None" if ( ! $options );
					
					my $key = lc ( $type . $options );
					
					
					# If the unique doesn't exist, then it is a new monitoring type, so add it
					if ( ! defined $unique_key{ $key } )
						{	$unique_key{ $key } = 0 + 1;
						
							push @list, $item;	
							push @list, $type;	
							push @list, $options;	
						}
				}
		}	# End of the local monitoring list

	
	# Add the check servers and service to the list	if it isn't there
	my $check_servers;
	my $service;
	my $license_check;
	my $item;
	my $counter = 0 + 0;
	my $last_item = 0 + 0;
	my $check_computer_count;
	
	while ( defined $list[ $counter ] )
		{	$item = $list[ $counter ];
			
			$last_item = $item if ( $item > $last_item );
			
			$counter++;
			
			my $type = $list[ $counter ];
			my $lctype = lc( $type );
			
			# Is there a check servers command?
			$check_servers = 1 if ( $lctype eq "checkservers" );
			
			# Is there a service command?
			$service = 1 if ( ( $lctype eq "service" )  ||  ( $lctype eq "system" ) );
			
			# Is there a license check command?
			$license_check = 1 if ( $lctype eq "checklicense" );
			
			# Is there a check computer count command?
			$check_computer_count = 1 if ( $lctype eq "checkcomputercount" );

			$counter++;
			
			my $options = $list[ $counter ];
			$counter++;
	
		}


	# If I didn't find a checklicense task, add it
	if ( ! $license_check )
		{	$last_item++;
			$item = $last_item;
			
			push @list, $item;
			push @list, "CheckLicense";
			push @list, undef;
		}
		
		
	# If I didn't find a check computer count task, add it
	if ( ! $check_computer_count )
		{	$item = 0 - 3;
			
			push @list, $item;
			push @list, "CheckComputerCount";
			push @list, undef;
		}
		
		
	# If I didn't find a check servers task, add it
	if ( ! $check_servers )
		{	$item = 0 - 2;
			
			push @list, $item;
			push @list, "CheckServers";
			push @list, undef;
		}
		
		
	# If I didn't find a service task, add it
	if ( ! $service )
		{	$item = 0 - 1;
			
			push @list, $item;
			push @list, "Service";
			push @list, undef;
		}
		
		
	# Display my combined monitor list
	if ( defined $list[ 0 ] )
		{	lprint( "Current monitor list:\n" );
			my $counter = 0 + 0;
			while ( defined $list[ $counter ] )
				{	my $item = $list[ $counter ];
					$counter++;
					
					my $type = $list[ $counter ];
					my $lctype = lc( $type );
					
					$counter++;
					
					my $options = $list[ $counter ];
					$counter++;
					
					$options = "None" if ( ! $options );
					
					lprint( "Item $item, Type: $type, Options: $options\n" );
				}
		}
	else
		{	lprint( "Nothing configured to monitor locally or remotely\n" );
		}


	return( @list );
}



################################################################################
# 
sub GetLocalMonitorList()
#
#  Pull out of the local SQL database the list of stuff that I'm supposed to monitor
#  locally.  Return the list, empty if nothing to monitor
#
################################################################################
{	my @local_list;
	
	# Make sure the database and the table exists
	return( @local_list ) if ( ! $dbh );
	return( @local_list ) if ( ! $monitored_server_items_table );
	
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "select [ItemNumber], [Type], [Options], [Warning] from MonitoredServerItems where LicenseKey = \'localhost\'" );
	$sth->execute();

	my %license_keys;
	my $count = 0 + 0;
	while ( ( ! $dbh->err )  &&  (  my ( $item_number, $type, $options, $warning ) = $sth->fetchrow_array() ) )
		{	next if ( ! $type );
			
			my $item = 0 - $item_number;
			
			# Set the options to null if they are none
			$options = undef if ( lc( $options ) eq "none" );
			
			# Add the warning tag to the options if it is just a warning
			$options .= ":warning" if ( ( $options )  &&  ( $warning ) );
			$options = ":warning" if ( ( ! $options )  &&  ( $warning ) );
			
			push @local_list, $item;
			push @local_list, $type;
			push @local_list, $options;
			
			$count++;
		}
		

	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	
	&lprint( "Loaded $count local monitoring types\n" ) if ( $count );
	&lprint( "No local monitoring types configured\n" ) if ( ! $count );
	
	return( @local_list );
}



my %stale;	# A hash of types and options, and how long they are stale for
my %stale_results;	# A hash of the stale results 
my %stale_warning;	# A hash of the stale results that are warnings only
################################################################################
# 
sub CheckList()
#
#  Check each item on my list, returning the results
#
################################################################################
{	my @list = @_;

	my @results = ();
	if ( ( ! $enable_local_monitoring )  &&  ( ! $enable_remote_monitoring ) )
		{	lprint( "Monitoring is not enabled locally or remotely\n" );
			return( @results );
		}
		
	if ( ! defined $list[ 0 ] )
		{	lprint( "Nothing is configured to monitor locally or remotely\n" );
			return( @results );
		}
		
	my $counter = 0 + 0;
	my $system_item = 0 + 0;
	
	&MonitorProcessHash();
	&MonitorNetworkAdaptersHash();
	
	while ( defined $list[ $counter ] )
		{	my $item = $list[ $counter ];
			$counter++;
			
			my $type = $list[ $counter ];
			my $lctype = lc( $type );
			
			$counter++;
			
			my $options = $list[ $counter ];
			$counter++;

			my $result = "OK";
			
			next if ( ! $type );
			
			
			# Is this a warning only?
			# If so, keep track that it is a warning only, and clean up the options
			my $warning_only = 1 if ( ( $options )  &&  ( $options =~ m/:warning$/ ) );
			if ( $warning_only )
				{	$options =~ s/\:warning//;
				}
			
						
			if ( ( $lctype eq "system" )  ||  ( $lctype eq "service" ) )
				{	$system_item = $item;
					$result = undef;	# Wait until later to report for this item type
				}
			elsif ( $lctype eq "process" )
				{	# Fixup any monitoring of the SQL 2005 agent process
					if ( ( $options )  &&  ( $options =~ m/sqlagent\.exe/i ) )
						{	$options = $sql_agent;
						}
					$result = &MonitorProcess( $options );
				}
			elsif ( $lctype eq "disk" )
				{	$result = &MonitorDisk( $options );
				}
			elsif ( $lctype eq "cpu" )
				{	$result = &MonitorCpu( $options );
				}
			elsif ( $lctype eq "memory" )
				{	$result = &MonitorMemory( $options );
				}
			elsif ( $lctype eq "ip" )
				{	$result = &MonitorIp( $options );
				}
			elsif ( $lctype eq "eventlog" )
				{	$result = &MonitorEventlog( $options );
				}
			elsif ( $lctype eq "spool" )
				{	$result = &MonitorSpool( $options );
				}
			elsif ( $lctype eq "appendlog" )
				{	$result = &MonitorAppendlog( $options );
				}
			elsif ( $lctype eq "sql" )
				{	$result = &MonitorSql( $options );
				}
			elsif ( $lctype eq "http" )
				{	$result = &MonitorHttp( $options );
				}
			elsif ( $lctype eq "iis" )
				{	$result = &MonitorIIS( $options );
				}
			elsif ( $lctype eq "spam" )
				{	$result = &MonitorSpam( $options );
				}
			elsif ( $lctype eq "smtp" )
				{	$result = &MonitorSmtp( $options );
				}
			elsif ( $lctype eq "virus" )
				{	$result = &MonitorVirus( $options );
				}
			elsif ( $lctype eq "network" )
				{	$result = &MonitorNetwork( $options );
				}
			elsif ( $lctype eq "configuration" )
				{	$result = &MonitorConfiguration( $options );
				}
			elsif ( $lctype eq "checkservers" )
				{	$result = &CheckServers( $options );
				}
			elsif ( $lctype eq "checklicense" )
				{	$result = &MonitorCheckTTCLicense( $options );
				}
			elsif ( $lctype eq "checkcomputercount" )
				{	$result = &MonitorCheckComputerCount( $serial_number, $options );
					delete $stale{ "$item . $lctype" };	# Make sure that this result doesn't go stale
				}
			elsif ( $lctype eq "scheduledtask" )
				{	$result = &MonitorScheduledTask( $options );
				}
			elsif ( $lctype eq "noscheduledtask" )
				{	$result = &MonitorNoScheduledTask( $options );
				}
			elsif ( $lctype eq "databaseupdate" )
				{	$result = &MonitorDatabaseUpdates( $options );
				}
			elsif ( $lctype eq "command" )
				{	$result = &Command( $options, $item );
				}
			else
				{	$options = "None" if ( ! $options );
					$result = "Unsupported Type: $type Options: $options";
				}
			
			next if ( ! $result );
			
			
			$result = "OK" if ( ! $result );
			
			my $ok = 1;
			$ok = undef if ( lc( $result )  ne  "ok" );
			
			
			# Check for staleness - first build the stale key
			my $key = $item . $lctype;
			$key = $item . $lctype . $options if ( $options );
			
			
			# If I got a error result, add on warning only if that is all I'm supposed to do
			if ( ( ! $ok )  &&  ( $warning_only ) )
				{	$result .= " Warning Only" ;
					$stale_warning{ $key } = 1;
				}
			
			
			# Was there a not OK result?			
			if ( ! $ok )
				{	# Do I already know about this problem, and so it's stale?
					my $stale_item_time;
					$stale_item_time = $stale{ $key } if ( defined $stale{ $key } );
					
					my $current_time = time;
					
					
					# Figure out if the stale is still active
					# I have seen this result before, or has the stale time elapsed?
					my $stale_still_active;
					if ( $stale_item_time )
						{	my $elapsed_time_min = ( $current_time - $stale_item_time ) / 60;

							if ( ( $elapsed_time_min > $stale_time )  ||
								 ( $result ne $stale_results{ $key } ) )
								{	delete $stale{ $key };
								}
							else
								{	$stale_still_active = 1;
								}
						}
					
					
					# If there hasn't been a change, report that
					if ( $stale_still_active )
						{	$result = "No change";
						}
					else	# Keep track of the time and the result
						{	$stale{ $key }			= $current_time;
							$stale_results{ $key }	= $result;
						}
						
						
					# Save the results
					push @results, $item;	
					push @results, $result;
				}
				
			# Was this errored, and now it is ok?
			elsif ( defined $stale{ $key } )
				{	delete $stale{ $key };
					delete $stale_results{ $key };
					
					# Signal that it is ok if it was just a warning
					if ( defined $stale_warning{ $key } )
						{	push @results, $item;
							push @results, "OK";
						}
					else # If it was an error, signal that it is ok now
						{	push @results, $item;
							push @results, "OK Now";
						}
						
					delete $stale_warning{ $key };	
				}
		}
	
	
	# Save the new process hash for the next check loop
	&MonitorProcessHashSave();
	
		
	# Set the service item results value
	# If no results are being reported everything must be ok
	if ( ! defined $results[ 0 ] )
		{	push @results, $system_item;	
			push @results, "OK";
		}
	else	# There must have been problems
		{	push @results, $system_item;	
			push @results, "Reported alerts";
		}
	
	
	# Add a result that the service just started if it just did
	if ( ! $service_started )
		{	push @results, $system_item;	
			push @results, "IpmMonitor started";
			$service_started = 1;
		}
	
	return( @results );
}



################################################################################
# 
sub CheckServers( $ )
#
#  Check the servers that I'm supposed to monitor to see that I've gotten
#  something from them during the last server check time
#
################################################################################
{	my $options = shift;
	my $result = "OK";


	# If the tables don't exist, just return OK
	return( "OK" ) if ( ! $dbh );
	return( "OK" ) if ( ! $monitored_servers_table );


	# First get the list of servers from the global hash
	my @license_keys = keys %license_key_hostname;
		
		
	# If there aren't any servers to monitor, return OK here
	return( "OK" ) if ( $#license_keys < 0 );	
	
	
	# Now go through to see if those servers have reported to me within the heartbeat time
    #  Figure out heartbeat time in the correct format
	my $time_sec = time - ( $heartbeat_time * 60 );
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $time_sec );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d.000", $year, $mon, $mday, $hour, $min, $sec );
	
	
	$dbh = &SqlErrorCheckHandle( $dbh );
    my $str = "select LicenseKey, LastLogTime, LastResult from MonitoredServers WHERE LastLogTime < \'$datestr\'";
    my $sth = $dbh->prepare( $str );
    $sth->execute();
	
	
	# Get the rows from SQL
	my %license_results;	# Build up a hash of the results
	while ( ( ! $dbh->err )  &&  (  my ( $m_license_key, $last_log_time, $last_result ) = $sth->fetchrow_array() ) )
		{	next if ( ! $m_license_key );
			
			# Ignore any results that I put in there myself
			next if ( $last_result =~ m/No data from host name/ );
			
			my $m_hostname = "Unknown";
			$m_hostname = $license_key_hostname{ $m_license_key } if ( defined $license_key_hostname{ $m_license_key } );
			
			my $msg = "No data from host name: $m_hostname, license key $m_license_key, serial number $serial_number for over $heartbeat_time minutes";
						
			$license_results{ $m_license_key } = $msg;
		}
	
	&SqlErrorHandler( $dbh );
    $sth->finish();
	
	
	# At this point the license_results hash contains the new last result to put into the monitored servers table
	my @keys = sort keys %license_results;
	
	
	# Build up my result, and update the MonitoredServers table
	$result = undef;
	foreach ( @keys )
		{	next if ( ! $_ );
			my $m_license_key = $_;
			
			my $msg = $license_results{ $m_license_key };			
			$msg = &CleanValue( $msg );
			$m_license_key = &CleanValue( $m_license_key );
			
			$dbh = &SqlErrorCheckHandle( $dbh );
			my $str = "UPDATE MonitoredServers SET LastResult = \'$msg\' WHERE LicenseKey = \'$m_license_key\'";
			my $sth = $dbh->prepare( $str );
			$sth->execute();
			
			&SqlErrorHandler( $dbh );
			$sth->finish();
			

			$result .= "\n" . $msg if ( $result );
			$result = $msg if ( ! $result );
		}
	
	
	return( "OK" ) if ( ! $result );
	return( $result );
}




################################################################################
# 
sub Command( $$ )
#
#  Schedule a command
#
################################################################################
{	my $options			= shift;
	my $command_item	= shift;
	
	# Return OK if there is nothing to do
	return( "OK" ) if ( ! $options );
	
	my $result;
	
	$next_command		= undef;
	$next_command_item	= undef;
		
	my $command_check_result = &CommandCheck( $options );
	
	if ( $command_check_result eq "OK" )
		{	$result = "Command $options is scheduled";
			
			$next_command		= $options;
			$next_command_item	= $command_item;
		}
	else
		{	$result = "Unknown command $options";
		}

	
	# Now go through the current list and reset the command option to blank so that
	# I don't repeat the command
	my $counter = 0 + 0;
	
	while ( defined $list[ $counter ] )
		{	my $item = $list[ $counter ];
			$counter++;
			
			my $type = $list[ $counter ];
			my $lctype = lc( $type );
			
			$counter++;
			
			my $options = $list[ $counter ];
			
			# Is this item my command option?  If so, clear the option so that I don't run it twice
			$list[ $counter ] = undef if ( ( $item eq $command_item )  &&  ( $lctype eq "command" ) );
			
			$counter++;
		}
		
	return( $result );	
}



################################################################################
# 
sub EmailMonitoredServers()
#
#  Go through the Statistics MonitoredAlerts table to see if there are some
#  alerts that I need to mail off to somebody from the other servers that
#  I'm monitoring
#
################################################################################
{	return( "OK" ) if ( ! $dbh );
	return( "OK" ) if ( ! $monitored_servers_table );
	return( "OK" ) if ( ! $monitored_alerts_table );
	
	my $emails_sent = 0 + 0;  # This is the count of emails that I actually tried to send
	
	# Now go through the Monitored Alerts to get any alerts that we should send emails for
	my $last_time = &GetEmailLastTime();
	
	
	# Get all the alerts that have been entered since the last time I checked
	# Only keep the alerts for servers that I'm monitoring from here
	# Keep all the results in the hash %license_results
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $str = "select [LicenseKey], [HostName], [Time], [Type], [Options], [Result] from MonitoredAlerts WHERE [Time] > \'$last_time\' ORDER BY [Time]";
    my $sth = $dbhStats->prepare( $str );
    $sth->execute();
	
	my %license_results;
	my %license_errors;		# Hash key is m_license_key, value if True if reporting errors
	my %license_priority;	# Hash is the m_license_key, value if the list of priority email addresses
	my @delete_list;
	
	my $alert_count = 0 + 0;
	while ( ( ! $dbhStats->err )  &&  (  my ( $m_license_key, $m_hostname, $time, $type, $options, $result ) = $sth->fetchrow_array() ) )
		{	next if ( ! $m_license_key );
			next if ( ! $result );
			
			$type = "none" if ( ! $type );
			
			# Keep track of the most current time
			$last_time = $time;
			
			# Is this for one of the servers that I'm monitoring?
			next if ( ! defined $license_key_hostname{ $m_license_key } );
						
			# Have I set the Alert Priority to ignore?
			my ( $report, $priority_list ) = &PriorityAlert( $m_license_key, $m_hostname, $type, $options, $result );

			# Should I mark this for deletion?
			if ( ! $report )
				{	push @delete_list, "$m_license_key\t$m_hostname\t$type\t$options\t$time";
					next;
				}
			
			# Keep the priority list added up
			if ( $priority_list )
				{	my $complete_priority_list = $license_priority{ $m_license_key };
					
					$complete_priority_list = $complete_priority_list . ";" . $priority_list if ( $complete_priority_list );
					$complete_priority_list = $priority_list if ( ! $complete_priority_list );
					
					$license_priority{ $m_license_key } = $complete_priority_list;
				}
			
				
			my $lc_result = lc( $result );
					
			# Figure out what results I want to email ...
			next if ( $lc_result =~ m/ok$/ );
			next if ( $lc_result =~ m/warning only$/ );
			next if ( $lc_result =~ m/reported alerts$/ );
			next if ( ( lc( $type ) eq "system" )  &&  ( $lc_result =~ m/ok now$/ ) );
			next if ( ( lc( $type ) eq "service" )  &&  ( $lc_result =~ m/ok now$/ ) );
			next if ( lc( $type ) eq "checkcomputercount" );
			
			
			# Keep track of error reporting
			$license_errors{ $m_license_key } = 1 if ( ! ( $lc_result =~ m/ok now$/ ) );
			
			# Add the result to the other results
			my $results = $license_results{ $m_license_key };
			
			$license_results{ $m_license_key } .= "\n" . $result if ( $results );
			$license_results{ $m_license_key } = $result if ( ! $results );
			
			$alert_count++;
		}
	
	
	&SqlErrorHandler( $dbhStats );
    $sth->finish();
	
	
	# Save the newest time I got for the new go around
	&SetEmailLastTime( $last_time );
	
	
	# Delete any alerts that need to be dumped
	foreach ( @delete_list )
		{	next if ( ! $_ );
			my $line = $_;
			my ( $m_license_key, $m_hostname, $type, $options, $m_time ) = split /\t/, $line, 5;
			
			&PriorityDeleteAlert( $m_license_key, $m_hostname, $type, $options, $m_time );
		}
	
		
	# Do I have anything that I need to send to somebody?
	my @hostnames = values %license_key_hostname;
	
	if ( $#hostnames < 0 )
		{	lprint( "No remote servers configured to monitor\n" );
			return( undef );
		}
	
	if ( ! $alert_count )
		{	lprint( "No remote monitoring alerts to email\n" );
			return( undef );
		}


	# At this point the license_results contains the results that I want to email
	# license_key_hostname contains the hostnames from SQL
	# license_alerts contains the alert_email_list
	# license_priority contains the alert priority email list
	# license_errors is True if I'm reporting errors
	my @keys = sort keys %license_results;
	
	foreach ( @keys )
		{	next if ( ! $_ );
			my $m_license_key = $_;
			
			my $results = $license_results{ $m_license_key };
			my $m_hostname = $license_key_hostname{ $m_license_key };
			
			my $errors;
			$errors = 1 if ( defined $license_errors{ $m_license_key } );
			

			# If the IpmMonitor program is running on the main monitor server then don't spit back to the customer the email alerts
			my $qdefault_monitor_server = quotemeta( $default_monitor_server );
			my $report_email = &GetEmailAlertList( $m_license_key ) if ( ! ( $hostname =~ m/$qdefault_monitor_server/i ) );
			
			# Also check the alternate name of the main monitor server
			$report_email = undef if ( $hostname =~ m/monitor\.lscom\.net/i );

			
			# Add in the priority list
			my $complete_priority_list = $license_priority{ $m_license_key };
			if ( $complete_priority_list )
				{	$report_email = $report_email . ";" . $complete_priority_list if ( $report_email );
					$report_email = $complete_priority_list if ( ! $report_email );
				}
				
			$report_email = &GetAdditionalEmailList( $report_email, $results );
			
			# If there is no one to send an alert to, skip it
			next if ( ! $report_email );
			
			$results = &CleanResults( $results );
			next if ( ! $results );
			
			# Send off the email
			lprint( "Sending monitoring results to $report_email for license key $m_license_key\n" );
			&EmailAlerts( $report_email, $m_license_key, $m_hostname, $results, $errors, $hostname );
			
			$emails_sent++;
		}
	
	
	# If I sent some emails - is IpmSMTPRelay running?  If not, then launch it to send until empty only mode
	if ( $emails_sent )
		{	my $result = &MonitorProcess( "IpmSMTPRelay.exe" );
			
			if ( ( ! $result )  ||  ( $result ne "OK" ) )
				{	my $old_cwd = getcwd;
					$old_cwd =~ s#\/#\\#gm;
					
					my $software_dir = &SoftwareDirectory();
					chdir( $software_dir );
					
					my $cmd = "IpmSMTPRelay -e";
					system $cmd;
					
					chdir( $old_cwd );
				}
		}
	
	return( 1 );
}



################################################################################
# 
sub SetEmailLastTime( $ )
#
#  Save the last time that I checked the MonitoredAlerts table to entries that I should email
#
################################################################################
{   my $newest_time = shift;
    my $key;

	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_WRITE, $key );
	return( undef ) if ( ! $ok );
	
	$ok = RegSetValueEx( $key, "Last Monitored Alert Time", 0,  REG_SZ, $newest_time );
	RegCloseKey( $key );
	
	return( $ok );
}



################################################################################
# 
sub GetEmailLastTime()
#
#  Get the last time that I checked the MonitoredAlerts table to entries that I should email
#
################################################################################
{	my $key;
	my $type;
	my $data;

	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

	$ok = RegQueryValueEx( $key, "Last Monitored Alert Time", [], $type, $data, [] ) if ( $ok );

	my $newest_time = '2003-06-01 12:00:00.000';

	$newest_time = $data if ( $ok );
	 
	RegCloseKey( $key );
	
	return( $newest_time );
}



################################################################################
# 
sub ReportList()
#
#  Report my results from monitoring the local server
#
################################################################################
{	my @results = @_;

	my $ok = 1;
	
	my $counter = 0 + 0;
	
	# Show the results on the screen
	# And add all the results up for any email messages
	my $results;
	my $errors;		# True if reporting errors
	my $complete_priority_list;
	
	while ( defined $results[ $counter ] )
		{	my $item = $results[ $counter ];
			$counter++;
			
			my $result = $results[ $counter ];
			chomp( $result );
			my $lc_result = lc( $result );
			
			$counter++;
			
			my ( $type, $options ) = &GetItem( $item );
			
			$options = "None" if ( ! $options );
			$type = "Service" if ( ! $type );
			
			lprint( "Type: $type, Options: $options, Result: $result\n" );
			
			# If it is a no change result, don't report it
			next if ( $lc_result eq "no change" );
			
			# Have I set the Alert Priority to ignore?
			my ( $report, $priority_list ) = &PriorityAlert( $license_key, $hostname, $type, $options, $result );
			next if ( ! $report );
			
			
			# Keep the priority list added up
			if ( $priority_list )
				{	$complete_priority_list = $complete_priority_list . ";" . $priority_list if ( $complete_priority_list );
					$complete_priority_list = $priority_list if ( ! $complete_priority_list );
				}
			
				
			# Report what happened to my monitor server, and into the statistics database
			&ReportAlerts( $monitor_server, $license_key, $hostname, $item, $type, $options, $result ) if ( $monitor_server );
			&SqlAlerts( $monitor_server, $license_key, $hostname, $item, $type, $options, $result );
			
			
			# Figure out what results I want to email
			next if ( $lc_result eq "ok" );
			next if ( $lc_result =~ m/warning only$/ );
			next if ( $lc_result eq "reported alerts" );
			next if ( ( lc( $type ) eq "system" )  &&  ( $lc_result eq "ok now" ) );
			next if ( ( lc( $type ) eq "service" )  &&  ( $lc_result eq "ok now" ) );
			next if ( lc( $type ) eq "checkcomputercount" );
			
			
			# Is this some sort of error?
			$errors = 1 if ( $lc_result ne "ok now" );
			
			$results .= "\nType: $type\nOptions: $options\nResults: $result\n" if ( $results );
			$results = "Type: $type\nOptions: $options\nResults: $result\n" if ( ! $results );
		}
	
	
	$results = &CleanResults( $results );


	# If I have any results left, email them
	if ( $results )
		{	my $report_email = &GetEmailAlertList( "localhost" );
			
			# Add in the priority list
			if ( $complete_priority_list )
				{	$report_email = $report_email . ";" . $complete_priority_list if ( $report_email );
					$report_email = $complete_priority_list if ( ! $report_email );
				}
				
			$report_email = &GetAdditionalEmailList( $report_email, $results );
			
			if ( $report_email )
				{	&lprint( "Sending monitoring results to $report_email for localhost\n" );
					&EmailAlerts( $report_email, $license_key, $hostname, $results, $errors, $hostname );
				}
		}
		
	return( $ok );
}



################################################################################
# 
sub SqlAlerts( $$$$$$$ )
#
#  Report my results into the Statistics Database table
#
################################################################################
{	my $monitor_server	= shift;
	my $m_license_key	= shift;
	my $m_hostname		= shift;
	my $item			= shift;
	my $type			= shift;
	my $options			= shift;
	my $result			= shift;
	
	
	return( undef ) if ( ! $dbh );
	
	# Just return here if the tables doesn't exist
	return( undef ) if ( ! $monitored_alerts_table );
	
	# Just return here if there isn't a result
	return( undef ) if ( ! $result );
	
	
	# Make sure the values aren't too long to fit and are formatted ok
	$m_license_key	= "none" if ( ! $m_license_key );
	$m_license_key	= &CleanValue( $m_license_key );

	$m_hostname		= "none" if ( ! $m_hostname );
	$m_hostname		= &CleanValue( $m_hostname );
	
	# Get the current time in the correct format for SQL
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d.000", $year, $mon, $mday, $hour, $min, $sec );
	$datestr	= &CleanValue( $datestr );
	
	$item			= 0 + 0 if ( ! $item );
	$item			= 0 + $item;
	$item			= 0 - $item if ( $item < 0 );	# Flip a local item to positive again before inserting

	$type			= "None" if ( ! $type );
	$type			= &CleanValue( $type );

	$options		= "None" if ( ! $options );
	$options		= &CleanValue( $options );
	
	$result			= "none" if ( ! $result );
	$result			= substr( $result, 0, 500 );
	$result			= &CleanValue( $result );
	
	my $str = "INSERT INTO MonitoredAlerts ( [LicenseKey], [HostName], [Time], [ItemNumber], [Type], [Options], [Result] ) 
				VALUES ( \'$m_license_key\', \'$m_hostname\', \'$datestr\', \'$item\', \'$type\', \'$options\', \'$result\' )";

	# Execute the insert
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
	my $sth = $dbhStats->prepare( $str );
	$sth->execute();
	
	&SqlErrorHandler( $dbhStats );
	$sth->finish();

	return( 1 );
}



################################################################################
# 
sub GetEmailAlertList( $ )
#
#  Given a license key, return the email alert list that I need to send alerts to
#  Return undef if there is nobody to send to
#
################################################################################
{	my $m_license_key = shift;
	
	return( undef ) if ( ! $dbh );
	return( undef ) if ( ! $monitored_servers_table );
	
	
	# Get the server that I'm monitoring from SQL that has this LicenseKey
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "select LicenseKey, AlertEmailList, RemoteEmailList from MonitoredServers where LicenseKey = \'$m_license_key\'" );
	$sth->execute();
	
	
	my $alert_email_list;
	my $monitor_count = 0 + 0;
	while ( ( ! $dbh->err )  &&  (  my ( $database_license_key, $database_alert_email_list, $database_remote_email_list ) = $sth->fetchrow_array() ) )
		{	next if ( ! $database_license_key );
			
			$alert_email_list = $database_alert_email_list;
			
			# Should I add the remote list to the alert list?
			# I should if this is a remotely monitored server, and not the localhost
			if ( $m_license_key ne "localhost" )
				{	# The alert list is the remote list if the regular lart list doesn't exist
					$alert_email_list = $database_remote_email_list if ( $database_remote_email_list );
					
					# If both lists exist, combine them
					$alert_email_list = $database_alert_email_list .";" . $database_remote_email_list if ( ( $database_alert_email_list )  &&  ( $database_remote_email_list ) );
				}
				
			$monitor_count++;
		}

	&SqlErrorHandler( $dbh );
	$sth->finish();


	# If I'm checking for localhost, and there is nothing, default to nothing
	return( undef ) if ( ( $m_license_key eq "localhost" )  &&  ( ! $monitor_count ) );

	return( $alert_email_list );
}



################################################################################
# 
sub GetAdditionalEmailList( $$ )
#
#  Given a the current email list, and the results, see if there are any others
#  I should send the email to
#
################################################################################
{	my $report_email	= shift;
	my $results			= shift;
	
	return( $report_email ) if ( ! $results );
	
	
	# Should I just ignore this result?
#	return( $report_email ) if ( $results =~ m/Source: Websense/ );
#	return( $report_email ) if ( $results =~ m/Source: Alert Manager Event Interface/ );
#	return( $report_email ) if ( $results =~ m/Source: SweepNT/ );
#	return( $report_email ) if ( $results =~ m/Source: Symantec AntiVirus/ );
#	return( $report_email ) if ( $results =~ m/Source: Norton AntiVirus/ );
#	return( $report_email ) if ( $results =~ m/VirusScan Enterprise/ );
#	return( $report_email ) if ( $results =~ m/DBD::ODBC::st execute failed/ );
#	return( $report_email ) if ( $results =~ m/Description: Service stopped via service control manager/ );
#	return( $report_email ) if ( $results =~ m/Description: Unable to get Windows Socket overlapped result/ );
#	return( $report_email ) if ( $results =~ m/OK Now/ );

	
	# Build my lists of different groups of email addresses
	my @management	= ( "rob\@lightspeedsystems.com", "robjones\@lightspeedsystems.com" );
	my @web			= ( "ryan\@lightspeedsystems.com", "carson\@lightspeedsystems.com", "robjones\@lightspeedsystems.com" );
	my @service		= ( "nick\@lightspeedsystems.com", "brock\@lightspeedsystems.com", "kevin\@lightspeedsystems.com" );
	my @perl		= ( "rob\@lightspeedsystems.com" );
	my @sql			= ( "wing\@lightspeedsystems.com", "robjones\@lightspeedsystems.com" );
	my @sa			= ( "rob\@lightspeedsystems.com", "nick\@lightspeedsystems.com", "brock\@lightspeedsystems.com", "kevin\@lightspeedsystems.com" );
	
	
	my @to;
	
	
	# Figure out if the result is something one of the programmers should look at
	# push @to, @perl		if ( $results =~ m/Appendlog/ );
	#push @to, @web		if ( $results =~ m/Type: Reports Error/ );
	#push @to, @sa		if ( $results =~ m/License: Security Agent/ );
	#push @to, @service	if ( $results =~ m/IpMagic/ );
	#push @to, @sql		if ( ( $results =~ m/MSSQL/ )  &&  ( ! ( $results =~ m/Appendlog/ ) ) );

	# Add the management list if anything was found
	# push @to, @management if ( $to[ 0 ] );
	
	
	# Add in the original list
	my @original_to;
	@original_to = split /\;/, $report_email if ( $report_email );
	
	push @to, @original_to if ( $original_to[ 0 ] );
	
	
	# Are there any email addresses at all?
	return( undef ) if ( ! $to[ 0 ] );
	
	
	# Build up the list of the recipents
	# @to contains it in list form
	# Put the cleaned up list into @clean_to
	my @clean_to;
	
	foreach ( @to )
		{	my $to = &CleanEmail( $_ );
			next if ( ! $to );
			
			# Is it already in the email to list?
			next if &ItemList( $to, @clean_to );
			
			push @clean_to, $to;
		}
	
	
	# Are there any email addresses at all?
	return( undef ) if ( ! $clean_to[ 0 ] );
	
	
	# Now put the cleaned up list into the separated by colons format
	$report_email = undef;
	foreach ( @clean_to )
		{	next if ( ! $_ );
			my $to = $_;
			
			$report_email = $report_email . ";" . $to if ( $report_email );
			$report_email = $to if ( ! $report_email );
		}
	
	return( $report_email );
}



################################################################################
# 
sub GetContactInfo( $ )
#
#  Given a license key, return the contact info
#  Return undef if there is no info, or if it is for the localhost
#
################################################################################
{	my $m_license_key = shift;
	
	return( undef ) if ( ! $dbh );
	return( undef ) if ( $m_license_key eq "localhost" );
	return( undef ) if ( ! $monitored_servers_table );
	
	
	# Get the list of servers that I'm monitoring from SQL
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "select LicenseKey, ContactName, ContactPhone from MonitoredServers where LicenseKey = \'$m_license_key\'" );
	$sth->execute();
	
	
	my $contact;
	my ( $license_key, $contact_name, $contact_phone );
	while ( ( ! $dbh->err )  &&  ( ( $license_key, $contact_name, $contact_phone ) = $sth->fetchrow_array() ) )
		{	next if ( ! $license_key );
		}

	&SqlErrorHandler( $dbh );
	$sth->finish();

	$contact = "Contact Name: $contact_name\n" if ( $contact_name );
	$contact = "Contact Name: $contact_name\nContact Phone: $contact_phone\n" if ( ( $contact_name )  &&  ( $contact_phone ) );
	
	return( $contact );
}



################################################################################
# 
sub EmailAlerts( $$$$$$ )
#
#  Send an alert message to an email list
#
################################################################################
{	my $email_to		= shift;
	my $m_license_key	= shift;
	my $m_hostname		= shift;
	my $results			= shift;
	my $errors			= shift;	# True if I'm report some errors, undef if just an "ok now"
	my $m_monitor_server= shift;
	
	
	# Make sure that I'm actually emailing something useful
	return( undef ) if ( ! $email_to );
	return( undef ) if ( ! $m_license_key );
	return( undef ) if ( ! $results );
	
	$m_hostname = "unknown" if ( ! $m_hostname );
	
	my $filename	= "MonitorAlert";
	my $from		= "support\@lightspeedsystems.com";
	
	my @to;
	
	# Build up the list of the recipents
	# @to contains it in list form, $clean_email_to in string form
	my @to_list = split /\;/, $email_to;
	my $clean_email_to;
	foreach ( @to_list )
		{	my $to = &CleanEmail( $_ );
			next if ( ! $to );
			
			# Is it already in the email to list?
			next if &ItemList( $to, @to );
			
			push @to, $to;
			$clean_email_to = "\;$to" if ( $clean_email_to );
			$clean_email_to = $to if ( ! $clean_email_to );							  
		}
	
	if ( ! $to[ 0 ] )
		{	lprint( "No valid email addresses to mail alerts to\n" );
			return( 1 );
		}
		
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d", $year, $mon, $mday, $hour, $min, $sec );
	my $filestr = sprintf( "%04d%02d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );

	# Create arbitrary additional file part.
	my ( $i, $n, @chrs );
	$b = "";
	foreach $n (48..57,65..90,97..122) { $chrs[$i++] = chr($n);}
	foreach $n (0..9) {$b .= $chrs[rand($i)];}
	
	$b = lc( $b );

	$filename .= $filestr;
	$filename .= $to[ 0 ];
	$filename .= "-" . $b . ".txt";


	# Figure out the situation	
	my @lines = split /\n/, $results;
	my $situation = "OK Now";
	$situation = "Error" if ( $errors );
	$situation = "Errors" if ( ( $errors )  &&  ( $#lines > 4 ) );
	
	# If it's a short result - make that the situation
	$situation = $results if ( length( $results ) < 30 );
	$situation =~ s/\n/ /g;
	

# This is the text template for my message
my $email_template = "content-class: urn:content-classes:message
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary=\"----_=_NextPart_001_01C4A962.ACDD12E7\"
X-MimeOLE: Produced By Microsoft Exchange V6.0.6556.0
Subject: Lightspeed Alert - Hostname: IpmHOSTNAME - IpmSITUATION
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
Thread-Topic: Lightspeed Alert - Host name: IpmHOSTNAME - IpmSITUATION
Thread-Index: AcSpYqzJxNR96OTMQrezUuw8lGvFNg==
From: \"IpmSENDER\" <IpmSENDER>
To: <IpmRECIPIENT>

This is a multi-part message in MIME format.

------_=_NextPart_001_01C4A962.ACDD12E7
Content-Type: text/plain;
	charset=\"us-ascii\"
Content-Transfer-Encoding: quoted-printable

This is a Lightspeed Systems Monitoring Service Alert.

=20

Local Time: IpmTIME

Host name: IpmHOSTNAME

Monitored by: IpmMONITOR

Current Status: IpmSITUATION

License: IpmLICENSE

Results:

=20

=20

IpmTEXTCONTENT
=20

=20

=20

IpmTEXTCONTACT
=20

=20

=20

Lightspeed Monitoring alerts can come from a remote monitoring server or
from the server itself.

To remove your email address from this mailing list please contact the
administrator of the monitoring server.

To contact Lightspeed Systems for help please email
support\@lightspeedsystems.com

=20

=20

=20

=20


------_=_NextPart_001_01C4A962.ACDD12E7
Content-Type: text/html;
	charset=\"us-ascii\"
Content-Transfer-Encoding: quoted-printable

<html>

<head>
<META HTTP-EQUIV=3D\"Content-Type\" CONTENT=3D\"text/html; =
charset=3Dus-ascii\">


<meta name=3DGenerator content=3D\"Microsoft Word 10 (filtered)\">

<style>
<!--
 /* Style Definitions */
 p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0in;
	margin-bottom:.0001pt;
	font-size:12.0pt;
	font-family:\"Times New Roman\";}
a:link, span.MsoHyperlink
	{color:blue;
	text-decoration:underline;}
a:visited, span.MsoHyperlinkFollowed
	{color:purple;
	text-decoration:underline;}
span.EmailStyle17
	{font-family:Arial;
	color:windowtext;}
\@page Section1
	{size:8.5in 11.0in;
	margin:1.0in 1.25in 1.0in 1.25in;}
div.Section1
	{page:Section1;}
-->
</style>

</head>

<body lang=3DEN-US link=3Dblue vlink=3Dpurple>

<div class=3DSection1>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>This is a Lightspeed Systems Monitoring Service =
Alert.</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>&nbsp;</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>Local Time:&nbsp;IpmTIME</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>Host name:&nbsp;IpmHOSTNAME</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>Monitored by:&nbsp;IpmMONITOR</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>Current Status:&nbsp;IpmSITUATION</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>License:&nbsp;IpmLICENSE</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>Results:</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>&nbsp;</span></font></p>

IpmHTMLCONTENT
IpmHTMLCONTACT
<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>&nbsp;</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>Lightspeed Monitoring alerts can come from a remote
monitoring server or from the server itself.</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>To remove your email address from this mailing list =
please
contact the administrator of the monitoring server.</span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>To contact Lightspeed Systems for help please email =
<a
href=3D\"mailto:support\@lightspeedsystems.com\">support\@lightspeedsystems.c=
om</a></span></font></p>

<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial'>&nbsp;</span></font></p>

<p class=3DMsoNormal><font size=3D3 face=3D\"Times New Roman\"><span =
style=3D'font-size:
12.0pt'>&nbsp;</span></font></p>

<p class=3DMsoNormal><font size=3D3 face=3D\"Times New Roman\"><span =
style=3D'font-size:
12.0pt'>&nbsp;</span></font></p>

<p class=3DMsoNormal><font size=3D3 face=3D\"Times New Roman\"><span =
style=3D'font-size:
12.0pt'>&nbsp;</span></font></p>

</div>

</body>

</html>

------_=_NextPart_001_01C4A962.ACDD12E7--
.
";

	# Take the template and subsite the Ipm strings for my actual content
	my $msg = $email_template;

	$msg =~ s/IpmHOSTNAME/$m_hostname/g;	
	$msg =~ s/IpmTIME/$datestr/g;
	$msg =~ s/IpmRECIPIENT/$clean_email_to/g;
	$msg =~ s/IpmSENDER/$from/g;
	$msg =~ s/IpmSITUATION/$situation/g;
	$msg =~ s/IpmLICENSE/$m_license_key/g;
	$msg =~ s/IpmMONITOR/$m_monitor_server/g;


	# Build up the text and HTML description
	my $text;
	my $html;
	
my $html_line_template = "\n<p class=3DMsoNormal><font size=3D2 face=3DArial><span =
style=3D'font-size:10.0pt;
font-family:Arial\'>IpmLINE</span></font></p>\n";


	foreach ( @lines )
		{	my $line = $_;
			chomp( $line );
			
			my $text_line;
			
			# Is it a blank line?
			$text_line = "\n\n"  if ( ! $line );
			$text_line = "$line\n\n"  if ( $line );
			
			$text .= $text_line if ( $text );
			$text = $text_line if ( ! $text );
			
			my $html_line = $html_line_template;
			
			# Put a mostly blank line in
			$html_line =~ s/IpmLINE/----/ if ( ! $line );
			$html_line =~ s/IpmLINE/$line/ if ( $line );

			$html .= $html_line if ( $html );
			$html = $html_line if ( ! $html );
		}
	
	
	$msg =~ s/IpmTEXTCONTENT/$text/g;
	$msg =~ s/IpmHTMLCONTENT/$html/g;


	# Put the contact info in
	my $contact = &GetContactInfo( $m_license_key );
	
	$text = undef;
	$html = undef;
	
	@lines = ();
	@lines = split /\n/, $contact if ( $contact );
	
	foreach ( @lines )
		{	my $line = $_;
			chomp( $line );
			
			my $text_line;
			
			# Is it a blank line?
			$text_line = "\n\n"  if ( ! $line );
			$text_line = "$line\n\n"  if ( $line );
			
			$text .= $text_line if ( $text );
			$text = $text_line if ( ! $text );
			
			my $html_line = $html_line_template;
			
			# Put a mostly blank line in
			$html_line =~ s/IpmLINE/----/ if ( ! $line );
			$html_line =~ s/IpmLINE/$line/ if ( $line );

			$html .= $html_line if ( $html );
			$html = $html_line if ( ! $html );
		}
	
	$text = " " if ( ! $text );
	$html = " " if ( ! $html );
	
	$msg =~ s/IpmTEXTCONTACT/$text/g;
	$msg =~ s/IpmHTMLCONTACT/$html/g;
	
	
	&lprint( "Emailing alert to @to ($filename)\n" );
	
	my ( $ok, $errmsg ) = &SMTPMessageFile( $filename, $from, $msg, undef, undef, @to );
	&lprint( "Error emailing alert: $errmsg\n" ) if ( ! $ok );
	
	return( 1 );
}



################################################################################
#
sub GetItem( $ )
#
#  Given an item, return the type and options
#
################################################################################
{	my $search_item = shift;
	
	my $counter = 0 + 0;
	while ( defined $list[ $counter ] )
		{	my $item = $list[ $counter ];
			$counter++;
			
			my $type = $list[ $counter ];
			$counter++;
			
			my $options = $list[ $counter ];
			$counter++;
			
			return( $type, $options ) if ( $item eq $search_item );
		}

	return( undef, undef );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename;
	my $dir = &SoftwareDirectory();

	$filename = $dir . "\\IpmMonitorErrors.log";
	
	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or &lprint( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	&lprint( "Set error logging set to $filename\n" ); 
}



################################################################################
# 
sub GetProperties()
#
#  Get the current properties for the IpmMonitor service
#  Return True if I could get all the properties, undef if I couldn't get them all
#
################################################################################
{	my $key;
	my $type;
	my $data;
	
	
	# Reload the license_key_hostname hash, and get a decent default hostname
	&LicenseKeyHostname();
	
	# Default the license key to the hostname for version 5.0 & 5.1
	$license_key = $hostname;
	
	# See if debug logging is turned on in the registry
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );
	return( undef ) if ( !$ok );
	
	$ok = RegQueryValueEx( $key, "Logging", [], $type, $data, [] );
	$opt_logging = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );
	RegCloseKey( $key );
	

	# See if any monitoring properties are set in the registry
	$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\Local Monitoring Settings", 0, KEY_READ, $key );
	if ( $ok )
		{	$data = undef;
			$ok = RegQueryValueEx( $key, "Enable Local Monitoring", [], $type, $data, [] );
			$enable_local_monitoring = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );
			$enable_local_monitoring = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
			
			$ok = RegQueryValueEx( $key, "Enable Remote Monitoring", [], $type, $data, [] );
			$enable_remote_monitoring = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );
			$enable_remote_monitoring = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
			
			$data = undef;
			$ok = RegQueryValueEx( $key, "Monitoring Server", [], $type, $data, [] );
			$monitor_server = $data if ( ( $ok )  &&  ( $data ) );
			$monitor_server = undef if ( ( $ok )  &&  ( ! $data ) );
			$monitor_server = undef if ( ! $enable_remote_monitoring );
			$monitor_server = $default_monitor_server if ( ( $enable_remote_monitoring )  &&  ( ! $monitor_server ) );
																    
			RegCloseKey( $key );
		}
	
	&lprint( "Local monitoring is enabled\n" ) if ( $enable_local_monitoring );
	&lprint( "Remote monitoring is enabled\n" ) if ( $enable_remote_monitoring  );
			
	&GetLicenseInfo();

	# See if any contact info is set in the registry
	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\Monitoring Alerts", 0, KEY_READ, $key );
	if ( $ok )
		{	$ok = &RegQueryValueEx( $key, "Name", [], $type, $data, [] );
			$contact_name = undef;
			$contact_name = $data if ( ( $ok )  &&  ( $data )  &&  ( $data ne "" ) );
			
			$ok = &RegQueryValueEx( $key, "Organization", [], $type, $data, [] );
			$contact_org = undef;
			$contact_org = $data if ( ( $ok )  &&  ( $data )  &&  ( $data ne "" ) );
			
			$ok = &RegQueryValueEx( $key, "Phone", [], $type, $data, [] );
			$contact_phone = undef;
			$contact_phone = $data if ( ( $ok )  &&  ( $data )  &&  ( $data ne "" ) );
			
			$ok = &RegQueryValueEx( $key, "Email Address", [], $type, $data, [] );
			$contact_email = undef;
			$contact_email = $data if ( ( $ok )  &&  ( $data )  &&  ( $data ne "" ) );
																    
			&RegCloseKey( $key );
		}

	
	return( 1 );
}



################################################################################
# 
sub GetLicenseInfo()
#
#  Read out of the registry the License info
#
################################################################################
{	my $key;
	my $type;
	my $data;
	
	# See if my license key is in the registry
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\Total Traffic Control", 0, KEY_READ, $key );
	return( undef ) if ( !$ok );
	
	$ok = &RegQueryValueEx( $key, "LicenseKey", [], $type, $data, [] );
	$license_key = $data if ( ( $data )  &&  ( $ok ) );
	
	$ok = &RegQueryValueEx( $key, "SiteCode", [], $type, $data, [] );
	$site_code = $data if ( ( $data )  &&  ( $ok ) );

	$ok = &RegQueryValueEx( $key, "SerialNumber", [], $type, $data, [] );
	$serial_number = $data if ( ( $data )  &&  ( $ok ) );

	&RegCloseKey( $key );
}



my $reg_hostname;	# This hostname that I've stored into the registry
################################################################################
# 
sub LicenseKeyHostname()
#
#  Build a global hash of the license keys and hostnames from the MonitoredServers
#  SQL table - and figure out a good hostname name to use for the localhost
#  Save the localhost hostname into the registry
#
################################################################################
{
use Socket;
use Sys::Hostname;
	
	# Get a good hostname to use for the local host
	my $host = hostname();
	my ( $domain, $desc, $manu, $model, $owner, $status, $system_type, $name ) = &GetDomainName();
	$domain = "workgroup" if ( ! $domain );
	my $packed_ip = ( gethostbyname( $host ) )[ 4 ];
	my $myipaddress = inet_ntoa( $packed_ip ) if ( defined $packed_ip );
	$myipaddress = "0.0.0.0" if ( ! defined $packed_ip );

	# Default a reasonable hostname for version 5.0 and 5.1 servers 
	my $fqdn = "\($host.$domain\)";
	$hostname = $host . " - $myipaddress - " . $fqdn;
	
	
	# See if we can figure stuff out about the local machine - put everything into the comment field
	$comment = "Host: $host, Domain: $domain, IP Address: $myipaddress";
	$comment .= ", Site Code: $site_code" if ( $site_code );
	$comment .= ", Descripion: $desc" if ( $desc );
	$comment .= ", Manufacturer: $manu" if ( $manu );
	$comment .= ", Model: $model" if ( $model );
	$comment .= ", Owner: $owner" if ( $owner );
	$comment .= ", Status: $status" if ( $status );
	$comment .= ", System Type: $system_type" if ( $system_type );
	$comment .= ", Name: $name" if ( $name );
	
	my $processor = &GetProcessorInfo();
	$comment .= ", $processor" if ( $processor );
	
	# Initialize the hash
	%license_key_hostname = ();
	
	
	# Don't go any farther if I can't connect to the database
	return( undef ) if ( ! $dbh );
	
	my ( $m_license_key, $server_name, $heartbeat );
			
	# Default the server name to the host name
	$server_name = $host;
	
	
	# If I have a monitored servers table, load it up with all the values		
	if ( $monitored_servers_table )
		{	# First get the list of servers from SQL
			$dbh = &SqlErrorCheckHandle( $dbh );
			my $sth = $dbh->prepare( "select LicenseKey, ServerName, HeartbeatTime from MonitoredServers" );
			$sth->execute();

			my $count = 0 + 0;
			while ( ( ! $dbh->err )  &&  ( ( $m_license_key, $server_name, $heartbeat ) = $sth->fetchrow_array() ) )
				{	next if ( ! $m_license_key );
					
					
					# localhost is a special case
					if ( lc( $m_license_key ) eq "localhost" )
						{	$hostname = $server_name . " " . $fqdn if ( $server_name );
						}
					elsif ( $server_name )	
						{	$license_key_hostname{ $m_license_key } = $server_name;
						}
					else
						{	$license_key_hostname{ $m_license_key } = "blank";
						}
					
					$heartbeat = 0 + 0 if ( ! $heartbeat );
					$license_key_heartbeat{ $m_license_key } = $heartbeat;
					
					$count++;
				}

			&SqlErrorHandler( $dbh );
			$sth->finish();
		}


	# Make sure the hostname is not longer than 50 characters
	if ( length( $hostname ) > 50 )
		{	my $server_name_len = 0 + 0;
			$server_name_len = length( $server_name ) if ( $server_name );
			
			my $len = 48 - $server_name_len - length( $fqdn );
			
			if ( ( $server_name )  &&  ( $len > 0 ) )
				{	my $sub = substr( $server_name, 0, $len );
					$hostname = $sub . " " . $fqdn;
				}
				
			# if it is still longer, then trunc the fqdn
			if ( length( $hostname ) > 50 )
				{	$hostname = substr( $fqdn, 0, 48 );
				}
		}
	
	
	# Now save the hostname back into the registry if I need to
	#  Has it changed?
	return( 1 ) if ( ( $reg_hostname )  &&  ( $hostname eq $reg_hostname ) );
	
	my $key;
	
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\Total Traffic Control", 0, KEY_WRITE, $key );

	# If not OK, attempt to create the main keys...
	if ( ! $ok )
		{	# Make sure the main Lightspeed Systems key is created
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );

			# Now create my key
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\Total Traffic Control", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );
			
			if ( ! $ok )
				{	my $regErr = regLastError();
					lprint "Unable to create Total Traffic Control key: $regErr\n";
					return( undef );
				}
		}

	$ok = RegSetValueEx( $key, "Hostname", 0,  REG_SZ, $hostname );
	$reg_hostname = $hostname;
	
	RegCloseKey( $key );
	
	return( 1 );
}
		


################################################################################
# 
sub GetDomainName()
#
#	Return the currently computer domain name
#
################################################################################
{	
use Win32::OLE qw( in );
	my $domain;
	my $desc;
	my $manu;
	my $model;
	my $owner;
	my $status;
	my $system_type;
	my $name;
	
	my $Class = "Win32_ComputerSystem";
	my $Machine = ".";
	my $WMIServices = Win32::OLE->GetObject( "winmgmts:{impersonationLevel=impersonate,(security)}//$Machine" );
	foreach my $CS ( in( $WMIServices->InstancesOf( $Class ) ) )
		{	$domain			= $CS->{Domain};
			$desc			= $CS->{Description};
			$manu			= $CS->{Manufacturer };
			$model			= $CS->{Model};
			$owner			= $CS->{PrimaryOwnerName};
			$status			= $CS->{Status};
			$system_type	= $CS->{SystemType};
			$name			= $CS->{Name};
		}
		
	return( $domain, $desc, $manu, $model, $owner, $status, $system_type, $name );	
}



################################################################################
# 
sub ReportAlerts( $$$$$$$ )
#
#	Report to my monitor server any alerts
#
################################################################################
{	my $monitor_server	= shift;
	my $m_license_key	= shift;
	my $m_hostname		= shift;
	my $item			= shift;
	my $type			= shift;
	my $options			= shift;
	my $result			= shift;

	if ( ! $monitor_server )
		{	lprint( "No monitoring server configured to report alerts to\n" );
			return( undef );
		}
		
	# lprint( "Reporting alert to monitoring server: $monitor_server\n" );

	
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}

	my $url;
	
	$url = "http:\/\/MONITORSERVER\/content\/MonitoringAlertsAdd.aspx\?LicenseKey=IpmLICENSEKEY&HostName=IpmHOSTNAME&ItemNumber=IpmITEMNUMBER&Type=IpmTYPE&Options=IpmOPTIONS&Result=IpmRESULT";
		
	$url =~ s/MONITORSERVER/$monitor_server/;
	
	$m_license_key = "none" if ( ! $m_license_key );
	my $url_license_key = &UrlFormat( $m_license_key );
	$url =~ s/IpmLICENSEKEY/$url_license_key/ if ( defined $url_license_key );
	$url =~ s/IpmLICENSEKEY// if ( ! defined $url_license_key );
	
	
	$m_hostname	= "none" if ( ! $m_hostname );
	my $url_hostname = &UrlFormat( $m_hostname );
	$url =~ s/IpmHOSTNAME/$url_hostname/ if ( $url_hostname );
	$url =~ s/IpmHOSTNAME// if ( ! $url_hostname );
	
	$item = 0 if ( ! defined $item );
	$item = 0 + $item;
	$item = 0 - $item if ( $item < 0 );	# Flip local item numbers back to positive

	my $url_item = &UrlFormat( $item );

	$url =~ s/IpmITEMNUMBER/$url_item/ if ( defined $url_item );
	$url =~ s/IpmITEMNUMBER// if ( ! defined $url_item );
	
	
	$type = "none" if ( ! $type );
	my $url_type = &UrlFormat( $type );
	$url =~ s/IpmTYPE/$url_type/ if ( defined $url_type );
	$url =~ s/IpmTYPE// if ( ! defined $url_type );
	
	
	$options = "None" if ( ! $options );
	my $url_options = &UrlFormat( $options );
	$url =~ s/IpmOPTIONS/$url_options/ if ( defined $url_options );
	$url =~ s/IpmOPTIONS// if ( ! defined $url_options );
	
	
	# Make sure the result isn't too long to fit and it is formatted correctly
	$result	= "none" if ( ! $result );
	$result = substr( $result, 0, 500 );
	$result = &UrlFormat( $result );
	$url =~ s/IpmRESULT/$result/ if ( $result );
	$url =~ s/IpmRESULT// if ( ! $result );
	

	$| = 1;

	if ( ! $ua )
		{	$ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000 );
			$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

			my $proxy_server = &ScanUtilIEProxy( $monitor_server );
			$ua->proxy( [ 'http' ], $proxy_server ) if ( $proxy_server );
	
			$ua->conn_cache( $cache );
		}
		
	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			lprint( "$monitor_server request error reporting monitor alert: ", $error, "\n" );
			
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;

	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	lprint( "$monitor_server request error - redirected to Lightspeed Systems Access Denied\n" );
			return( undef );
		} 


	if ( $content =~ m/OK/ )
		{	return( 0 + 1 );
		}

	
	# At this point I don't know what this means
	#lprint "Response error: $content\n";
	
	return( undef );
}



my @download_list;
################################################################################
# 
sub DownloadAlertList()
#
#	Check our monitoring server to get a list of the stuff I'm supposed to monitor
#   Return the list, or an empty list if I'm supposed to use the default list
#
################################################################################
{	my @new_download_list;


	# If I don't have a monitor server configured, return an empty list
	if ( ! $monitor_server )
		{	@download_list = ();
			return( @download_list );
		}

	# If I don't have a license key, return an empty list
	if ( ! $license_key )
		{	@download_list = ();
			return( @download_list );
		}
		
	# Get my local email alert list	
	my $local_email_alert_list = &GetEmailAlertList( "localhost" );
	
	$| = 1;
	
	my $url = "http:\/\/MONITORSERVER\/content\/MonitoringServerProperties.aspx?LicenseKey=IpmLICENSEKEY&RemoteEmail=IpmREMOTEEMAIL&Hostname=IpmHOSTNAME&Comment=IpmCOMMENT&ContactName=IpmCONTACTNAME&ContactOrg=IpmCONTACTORG&ContactPhone=IpmCONTACTPHONE&ContactEmail=IpmCONTACTEMAIL";
	
	$url =~ s/MONITORSERVER/$monitor_server/;
	
	my $url_license_key = &UrlFormat( $license_key );
	$url =~ s/IpmLICENSEKEY/$url_license_key/;

	my $url_email_alert = &UrlFormat( $local_email_alert_list );
	$url =~ s/IpmREMOTEEMAIL/$url_email_alert/ if ( $url_email_alert );
	$url =~ s/IpmREMOTEEMAIL// if ( ! $url_email_alert );

	my $url_hostname = &UrlFormat( $hostname );
	$url =~ s/IpmHOSTNAME/$url_hostname/ if ( $url_hostname );
	$url =~ s/IpmHOSTNAME// if ( ! $url_hostname );

	my $url_comment = &UrlFormat( $comment );
	$url =~ s/IpmCOMMENT/$url_comment/ if ( $url_comment );
	$url =~ s/IpmCOMMENT// if ( ! $url_comment );

	my $url_contact_name = &UrlFormat( $contact_name );
	$url =~ s/IpmCONTACTNAME/$url_contact_name/ if ( $url_contact_name );
	$url =~ s/IpmCONTACTNAME// if ( ! $url_contact_name );

	my $url_contact_org = &UrlFormat( $contact_org );
	$url =~ s/IpmCONTACTORG/$url_contact_org/ if ( $url_contact_org );
	$url =~ s/IpmCONTACTORG// if ( ! $url_contact_org );

	my $url_contact_phone = &UrlFormat( $contact_phone );
	$url =~ s/IpmCONTACTPHONE/$url_contact_phone/ if ( $url_contact_phone );
	$url =~ s/IpmCONTACTPHONE// if ( ! $url_contact_phone );

	my $url_contact_email = &UrlFormat( $contact_email );
	$url =~ s/IpmCONTACTEMAIL/$url_contact_email/ if ( $url_contact_email );
	$url =~ s/IpmCONTACTEMAIL// if ( ! $url_contact_email );


	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 10000000 );
	$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

	my $proxy_server = &ScanUtilIEProxy( $monitor_server );
	$ua->proxy( [ 'http' ], $proxy_server ) if ( $proxy_server );
	
	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			lprint( "Unable to download monitored server properties from $monitor_server: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( @download_list );
		}

	my $content = $response->content;

	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&lprint( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( @download_list );
		} 

	
	my @lines = split /\n/, $content;

	# Did I get any data?
	if ( $#lines < ( 0 + 0 ) )
		{	lprint( "No response from $monitor_server - will try later\n" );	
			return( @download_list );
		} 
	
	
	# Was I told to use the defaults?  The content would be just a couple of lines
	if ( ( $#lines < 4 )  &&  ( $content =~ m/Default/ ) )
		{	lprint( "Use default monitor properties from $monitor_server\n" );
			@download_list = ();
			return( @download_list );
		} 
	
	my ( $item_number, $item_license_key, $type, $options, $warning );
	
	foreach( @lines )
		{	my $line = $_;
			chomp( $line );

			# Clean up the line
			$line =~ s/^\t.//;
			$line =~ s/^\s*//;
			$line =~ s/\s*$//;
			
			
			if ( $line =~ m/\<ItemNumber\>/ )
				{	$item_number = $line;
					$item_number =~ s/\<ItemNumber\>//;
					$item_number =~ s/\<\/ItemNumber\>//;
					$item_number = &UnUrlFormat( $item_number );
					$item_number = 0 + $item_number;
				}

				
			if ( $line =~ m/\<LicenseKey\>/ )
				{	$item_license_key = $line;
					$item_license_key =~ s/\<LicenseKey\>//;
					$item_license_key =~ s/\<\/LicenseKey\>//;
					$item_license_key = &UnUrlFormat( $item_license_key );
				}

				
			if ( $line =~ m/\<Type\>/ )
				{	$type = $line;
					$type =~ s/\<Type\>//;
					$type =~ s/\<\/Type\>//;
					$type = &UnUrlFormat( $type );
				}

				
			if ( $line =~ m/\<Options\>/ )
				{	$options = $line;
					$options =~ s/\<Options\>//;
					$options =~ s/\<\/Options\>//;
					$options = &UnUrlFormat( $options );
				}

				
			if ( $line =~ m/\<Warning\>/ )
				{	$warning = $line;
					$warning =~ s/\<Warning\>//;
					$warning =~ s/\<\/Warning\>//;
				}

				
			if ( $line =~ m/\<\/Items\>/ )
				{	next if ( ( ! defined $item_number )  ||  ( ! $item_license_key )  ||  ( ! $type ) );

					# Add the warning to the options if it is enabled
					if ( ( $warning )  &&  ( lc( $warning ) eq "true" ) )
						{	$options .= ":warning" if ( $options );
							$options = ":warning" if ( !$options );
						}
						
					push @new_download_list, $item_number;
					push @new_download_list, $type;
					push @new_download_list, $options;

					# Reset everything for the next record								
					$item_number		= undef;
					$item_license_key	= undef;
					$type				= undef;
					$options			= undef;
					$warning			= undef;
				}
		}	# end of foreach @lines
		
		
	# If I got to here, I must have downloaded a new list, so save in in my global variable
	@download_list = @new_download_list;
	
	my $count = ( $#download_list + 1 ) / 3;
	
	if ( $count < 1 )
		{	lprint( "Downloaded no monitor properties from $monitor_server, so using default properties\n" );
			return( @download_list );
		}
		
	&lprint( "Downloaded $count monitoring types from $monitor_server\n" );

	return( @download_list );
}



################################################################################
# 
sub ClearMonitorCommand( $ )
#
#	Given a command item number, clear it right before I execute the command
#   Return True if ready to go, undef if an error
#
################################################################################
{	my $item = shift;

	# If I don't have a monitor server configured, return undef
	return( undef ) if ( ! $monitor_server );
	return( undef ) if ( ! $item );
	
	$| = 1;
	
	my $url = "http:\/\/MONITORSERVER\/content\/ClearMonitorCommand.aspx?ItemNumber=IpmITEMNUMBER";
	
	$url =~ s/MONITORSERVER/$monitor_server/;
	
	my $url_item = &UrlFormat( $item );
	$url =~ s/IpmITEMNUMBER/$item/;

	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 1000000 );
	$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

	my $proxy_server = &ScanUtilIEProxy( $monitor_server );
	$ua->proxy( [ 'http' ], $proxy_server ) if ( $proxy_server );
	
	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			lprint( "Unable to clear monitor command from $monitor_server: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef);
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&lprint( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		} 

	
	my @lines = split /\n/, $content;

	# Did I get any data?
	if ( $#lines < ( 0 + 0 ) )
		{	lprint( "Unable to clear monitor command - no response from $monitor_server - will try later\n" );	
			return( undef );
		} 
	
	
	# Was I told to use the defaults?
	if ( $content =~ m/OK/ )
		{	lprint( "Cleared command from $monitor_server prior to execution\n" );
			return( 1 );
		} 
	

	# Some sort of unknown response
	lprint( "Unknown response from $monitor_server when trying to clear the command\n" );
		   
	return( undef );
}



################################################################################
# 
sub ItemList( $@ )
#
# Return True if the item is found in the list, undef if not
#
################################################################################
{	my $item = shift;
	my @list = @_;
	
	return( undef ) if ( ! defined $item );
	
	foreach ( @list )
		{	next if ( ! defined $_ );
			
			return( 1 ) if ( $item eq $_ );
		}
		
	return( undef );
}



################################################################################
sub Round( $ )	 # Round off to 2 decimal places
################################################################################
{	my $val = shift;
	
	$val =~ s/\,/\./g;	# Get rid of commas
	my $rnd = $val;
	$rnd = sprintf( "%.2f", $rnd );
	$rnd =~ s/\,/\./g;	# Get rid of commas
	$rnd = 0 + $rnd;
	
	return( $rnd );
}



################################################################################
################################################################################
##########################   Priority Functions   ##############################
################################################################################
################################################################################



my @priority;
################################################################################
# 
sub PriorityLoad()
#
#  Load into memory any MonitoredServerPriority rows.  Process the rows if 
#  anything has changed.
#
################################################################################
{	
	return( 1 ) if ( ! $monitored_alerts_priority_table );
	
	&lprint( "Loading monitoring alert priorities\n" );
	
	$dbh = &SqlErrorCheckHandle( $dbh );
    my $str = "select [PriorityType], [LicenseKey], [HostName], [Type], [Options], [Results], [EmailList] from MonitoredServerPriority ORDER BY ID";
    my $sth = $dbh->prepare( $str );
    $sth->execute();
	
	
	my $priority_count = 0 + 0;
	my @new_priority = ();
	while ( ( ! $dbh->err )  &&  (  my ( $priority_type, $m_license_key, $m_hostname, $m_type, $m_options, $m_result, $email_list ) = $sth->fetchrow_array() ) )
		{	$m_license_key	= &CleanSpaces( $m_license_key );
			$m_hostname		= &CleanSpaces( $m_hostname );
			$m_type			= &CleanSpaces( $m_type );
			$m_options		= &CleanSpaces( $m_options );
			$m_result		= &CleanSpaces( $m_result );
			
			$m_license_key	= "na" if ( ! $m_license_key );
			$m_hostname		= "na" if ( ! $m_hostname );
			$m_type			= "na" if ( ! $m_type );
			$m_options		= "na" if ( ! $m_options );
			$m_result		= "na" if ( ! $m_result );
			$email_list		= "na" if ( ! $email_list );
			
			$m_license_key	= quotemeta( lc( $m_license_key ) );
			$m_hostname		= quotemeta( lc( $m_hostname ) );
			$m_type			= quotemeta( lc( $m_type ) );
			$m_options		= quotemeta( lc( $m_options ) );
			$m_result		= quotemeta( lc( $m_result ) );
			
			# Make sure that the priority type is upper case for comparisons
			$priority_type = uc( $priority_type );
			
			my $line = "$priority_type\t$m_license_key\t$m_hostname\t$m_type\t$m_options\t$m_result\t$email_list";
			
			push @new_priority, $line;
			
			$priority_count++;
		}
	
	&SqlErrorHandler( $dbh );
    $sth->finish();


	&lprint( "Loaded $priority_count alert priorities\n" ) if ( $opt_debug );
	
	# Did the priorities change?  If so, purge everything
	if ( @new_priority ne @priority )
		{	@priority = @new_priority;
			&PriorityPurgeAlerts();
		}
	
	return( 1 );
}



################################################################################
# 
sub PriorityAlert( $$$$$ )
#
#  Check to see if an alert matches any priories.  Return True and the email 
#  list if if does, undef and undef if it is set to ignore, and True and undef
#  if there isn't any priority setting for this at all
#
################################################################################
{	my $license_key = shift;
	my $hostname	= shift;
	my $type		= shift;
	my $options		= shift;
	my $result		= shift;

	
	return( 1, undef ) if ( ! $monitored_alerts_priority_table );
	return( 1, undef ) if ( ! $priority[ 0 ] );


	# Compare lowercase
	$license_key	= lc( $license_key  )	if ( $license_key );
	$hostname		= lc( $hostname  )		if ( $hostname );
	$type			= lc( $type  )			if ( $type );
	$options		= lc( $options  )		if ( $options );
	$result			= lc( $result  )		if ( $result );

	my $notify_email_list;
	
	foreach ( @priority )
		{	next if ( ! $_ );
			my $line = $_;
			my ( $priority_type, $m_license_key, $m_hostname, $m_type, $m_options, $m_result, $email_list ) = split /\t/, $line, 7;
			
			$m_license_key	= undef if ( $m_license_key eq "na" );
			$m_hostname		= undef if ( $m_hostname eq "na" );
			$m_type			= undef if ( $m_type eq "na" );
			$m_options		= undef if ( $m_options eq "na" );
			$m_result		= undef if ( $m_result eq "na" );
			
			my $match;
			
			# Is this a license key compare?
			if ( ( $m_license_key )  &&  ( $license_key ) )
				{	$match = 1 if ( $license_key =~ m/$m_license_key/i );
					
					if ( $priority_type eq 'I' )
						{	&lprint( "Found an ignore match for license key $license_key\n" ) if ( $opt_verbose );
						}
					else
						{	&lprint( "Found an alert match for license key $license_key\n" ) if ( $opt_verbose );
						}
				}
				
			# Is this a hostname compare?
			if ( ( $m_hostname )  &&  ( $hostname ) )
				{	$match = 1 if ( $hostname =~ m/$m_hostname/i );
					
					if ( $priority_type eq 'I' )
						{	&lprint( "Found an ignore match for hostname $hostname\n" ) if ( $opt_verbose );
						}
					else
						{	&lprint( "Found an alert match for hostname $hostname\n" ) if ( $opt_verbose );
						}
				}
				
			# Is this a type compare?
			if ( ( $m_type )  &&  ( $type ) )
				{	$match = 1 if ( $type =~ m/$m_type/i );
					
					if ( $priority_type eq 'I' )
						{	&lprint( "Found an ignore match for type $type\n" ) if ( $opt_verbose );
						}
					else
						{	&lprint( "Found an alert match for type $type\n" ) if ( $opt_verbose );
						}
				}
				
			# Is this a options compare?
			if ( ( $m_options )  &&  ( $options ) )
				{	$match = 1 if ( $options =~ m/$m_options/i );
					
					if ( $priority_type eq 'I' )
						{	&lprint( "Found an ignore match for option $options\n" ) if ( $opt_verbose );
						}
					else
						{	&lprint( "Found an alert match for option $options\n" ) if ( $opt_verbose );
						}
				}
				
			# Is this a result compare?
			if ( ( $m_result )  &&  ( $result ) )
				{	$match = 1 if ( $result =~ m/$m_result/i );
					if ( $priority_type eq 'I' )
						{	&lprint( "Found an ignore match for result $m_result\n" ) if ( $opt_verbose );
						}
					else
						{	&lprint( "Found an alert match for result $m_result\n" ) if ( $opt_verbose );
						}
				}
				
			next if ( ! $match );
			
			# OK - I've got a match - now what?
			
			# Should I ignore this alert?
			if ( $priority_type eq "I" )	# "I" is ignore
				{	return( undef, undef );
				}
				
			# Should I notify on this alert?
			if ( $priority_type ne "N" )	# "N" is notify
				{	&lprint( "Matched alert has an invalid priority type of $priority_type\n" );
					return( undef, undef );
				}
			
			# I guess I should notify the email list - so does it have an email list?
			next if ( $email_list eq "na" );
			
			# At this point it matches something that I want to notify about
			$notify_email_list = $email_list;
		}
	
	# Did I find an email list to notify?	
	if ( defined $notify_email_list )
		{	&lprint( "Found a high priority alert of type $type for $notify_email_list\n" );

			return( 1, $notify_email_list );	
		}
	return( undef, undef );
}



################################################################################
# 
sub PriorityDeleteAlert( $$$$$ )
#
#  Delete any alert that matches these options.
#
################################################################################
{	my $license_key = shift;
	my $hostname	= shift;
	my $type		= shift;
	my $options		= shift;
	my $time		= shift;
	
	return( 1 ) if ( ! $monitored_alerts_priority_table );
	
	# Build the where statement
	my $where;
	
	$license_key = &CleanValue( $license_key ) if ( defined $license_key );
	
	$where = "[LicenseKey] = '$license_key'" if ( defined $license_key );
	
	if ( defined $hostname )
		{	$hostname = &CleanValue( $hostname );
			
			$where = $where . " AND [HostName] = '$hostname'" if ( $where );
			$where = "[HostName] = '$hostname'" if ( ! $where );
		}
	
	if ( defined $type )
		{	$type = &CleanValue( $type );
			
			$where = $where . " AND [Type] = '$type'" if ( $where );
			$where = "[Type] = '$type'" if ( ! $where );
		}
	
	if ( defined $options )
		{	$options = &CleanValue( $options );
			$options =~ s/:warning//;
			
			$where = $where . " AND [Options] = '$options'" if ( $where );
			$where = "[Options] = '$options'" if ( ! $where );
		}
	
	if ( defined $time )
		{	$time = &CleanValue( $time );
			
			$where = $where . " AND [Time] = '$time'" if ( $where );
			$where = "[Time] = '$time'" if ( ! $where );
		}
	
	return( 1 ) if ( ! $where );
	
	
    my $str = "DELETE MonitoredAlerts WHERE $where";

	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $sth = $dbhStats->prepare( $str );
    $sth->execute();
	
	if ( $dbhStats->err )
		{	&lprint( "SQL Error - statement: $str\n" );
		}
		
	&SqlErrorHandler( $dbhStats );
	$sth->finish();
	

	return( 1 );
}



################################################################################
# 
sub PriorityPurgeAlerts()
#
#  Execute every ignore priority alert to clean out the monitored alerts table
#
################################################################################
{	return( 1 ) if ( ! $dbh );
	return( 1 ) if ( ! $monitored_servers_table );
	return( 1 ) if ( ! $monitored_alerts_table );
	return( 1 ) if ( ! $monitored_alerts_priority_table );
	return( 1 ) if ( ! $priority[ 0 ] );
	
	&lprint( "Purging ignored priority alerts\n" );

	foreach ( @priority )
		{	next if ( ! $_ );
			my $line = $_;
			my ( $priority_type, $m_license_key, $m_hostname, $m_type, $m_options, $m_result, $email_list ) = split /\t/, $line, 7;

			next if ( $priority_type ne "I" );
			
			
			$m_license_key	= undef if ( $m_license_key eq "na" );
			$m_hostname		= undef if ( $m_hostname eq "na" );
			$m_type			= undef if ( $m_type eq "na" );
			$m_options		= undef if ( $m_options eq "na" );
			$m_result		= undef if ( $m_result eq "na" );


			# Build the where statement
			my $where;
			if ( $m_license_key )
				{	$m_license_key = &CleanMeta( $m_license_key );
					
					$where = "[LicenseKey] LIKE \'\%$license_key\%\'";
				}
				
			if ( $m_hostname )
				{	$m_hostname = &CleanMeta( $m_hostname );
					
					$where = $where . " AND [HostName] LIKE \'\%$m_hostname\%\'" if ( $where );
					$where = "[HostName] LIKE \'\%$m_hostname\%\'" if ( ! $where );
				}
			
			if ( $m_type )
				{	$m_type = &CleanMeta( $m_type );
					
					$where = $where . " AND [Type] LIKE \'\%$m_type\%\'" if ( $where );
					$where = "[Type] LIKE \'\%$m_type\%\'" if ( ! $where );
				}
			
			if ( $m_options )
				{	$m_options = &CleanMeta( $m_options );
					$m_options =~ s/:warning//;
					
					$where = $where . " AND [Options] LIKE \'\%$m_options\%\'" if ( $where );
					$where = "[Options] LIKE \'\%$m_options\%\'" if ( ! $where );
				}
			
			if ( $m_result )
				{	$m_result = &CleanMeta( $m_result );
					
					$where = $where . " AND [Result] LIKE \'\%$m_result\%\'" if ( $where );
					$where = "[Result] LIKE \'\%$m_result\%\'" if ( ! $where );
				}
			
			next if ( ! $where );
			
			
			my $str = "DELETE MonitoredAlerts WHERE $where";

			$dbhStats = &SqlErrorCheckHandle( $dbhStats );
			my $sth = $dbhStats->prepare( $str );
			$sth->execute();
			
			&SqlErrorHandler( $dbhStats );
			$sth->finish();
		}
		
		
	return( 1 );
}



sub CleanMeta( $ )
{	my $val = shift;
	return( undef ) if ( ! $val );
	
	$val =~ s/\\//g;
	$val =~ s/\%//g;
	
	$val = &CleanValue( $val );
	return( $val );
}



sub CleanSpaces( $ )
{	my $val = shift;
	return( undef ) if ( ! $val );
	
	$val =~ s/^\s+//g;
	$val =~ s/\s+$//g;
	
	return( $val );
}



################################################################################
# 
sub CleanValue( $ )
#
#  Given a value, make sure it is good to insert into SQL
#
################################################################################
{	my $val = shift;
	
	$val = 'NULL' if ( ! defined $val );
	
	$val = &CleanSpaces( $val );
	
	# Substitute double single quotes for a single quote	
	$val =~ s/'/''/g;
	
	return( $val );
}



my $critical_host;
################################################################################
# 
sub CheckCriticalUpdates()
#
#  Check the opendb servers to see if there is a new critical update waiting
#  for the SecurityAgent
#
#  Return True if OK, undef if not
#
################################################################################
{	
	my $critical_host = hostname() if ( ! $critical_host );

	# Don't do anything on an opendb server
	return( undef ) if ( ! $critical_host );
	return( undef ) if ( $critical_host =~ m/^opendb/i );
	
	# Make sure the directories exist
	my $software_dir = &SoftwareDirectory();
	return( undef ) if ( ! -d $software_dir );
	
	my $content_dir = $software_dir . "\\Website\\Content";
	return( undef ) if ( ! -d $content_dir );


	&lprint( "Checking for any new Security Agent critical updates ...\n" );
	

	my $url = "http:\/\/TTCSERVER\/Content/GetFileInfo\.aspx?filename=IpmFILENAME";
		
			
	$url =~ s/TTCSERVER/opendb\.lightspeedsystems\.com/;
	$url =~ s/IpmFILENAME/SAExport\-0\.htm/;


	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}

	$| = 1;

	if ( ! $ua )
		{	$ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000 );
			$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

			my $proxy_server = &ScanUtilIEProxy( "opendb.lightspeedsystems.com" );
			$ua->proxy( [ 'http' ], $proxy_server ) if ( $proxy_server );
	
			$ua->conn_cache( $cache );
		}
		

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			&lprint( "Error getting response from opendb.lightspeedsystems.com: $error\n" );
			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&lprint( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		} 

	
	my @lines = split /\n/, $content;
	$content = undef;
	
	my $version_string;
	foreach ( @lines )
		{	my $line = $_;
			next if ( ! $line );
			chomp( $line );
			
			next if ( ! $line );
			
			$version_string = $line;
			last;
		}

	# If I can't get a version string, return error
	return( undef ) if ( ! $version_string );	
	
	# Is the file not found?
	if ( $version_string =~ m/file not found/i )
		{	&lprint( "No Security Agent critical updates are available\n" );
			return( 1 );
		}
	
	# Does the aspx page not exist?
	return( undef ) if ( $version_string =~ m/server error in/i );
	
	# At this point $version_string contains the version of the file 
	my ( $junk, $file_size ) = split /File Size\: /, $version_string, 2;
	return( undef ) if ( ! defined $file_size );
	chomp( $file_size );
	return( undef ) if ( ! $file_size );
	
	$file_size =~ s/^\s+//;
	$file_size =~ s/\s+$// if ( $file_size );
	return( undef ) if ( ! $file_size );
	$file_size = 0 + $file_size;
	return( undef ) if ( ! $file_size );
	
	my $local_file = $content_dir . "\\SAExport-0.htm";
	my $local_tmp = $content_dir . "\\SAExport-0.tmp";
	my $local_old = $content_dir . "\\SAExport-0.old";
	my $local_size = -s $local_file;


	# If the sizes are the same then I don't have to do anything
	if ( ( $local_size )  &&  ( $local_size == $file_size ) )
		{	&lprint( "No change to the current Security Agent critical update\n" );
			return( 1 );
		}
	
	
	&lprint( "Downloading the new Security Agent critical update ...\n" );
	
	$url = "http:\/\/TTCSERVER\/Content\/SAExport-0.htm";
	$url =~ s/TTCSERVER/opendb\.lightspeedsystems\.com/;
	
 	$| = 1;

	$response = LWP::Simple::getstore( $url, $local_tmp );

	my $ok = is_success( $response );

    if ( ! $ok )
        {   my $error = HTTP::Status::status_message( $response );
		    &lprint( "Error trying to download the new critical Security Agent update: $error\n" );
	        return( undef );  #  Return that an error happened
        }

	# Delete the old file, and rename the new file
	unlink( $local_old );
	rename( $local_file, $local_old );
	unlink( $local_old );
	
	$ok = rename( $local_tmp, $local_file );
	if ( ! $ok )
		{	my $err = $!;
			&lprint( "Error renaming $local_tmp to $local_file: $err\n" );
			return( undef );
		}
		
	&lprint( "Downloaded the new Security Agent critical updates OK\n" );
	
	return( 1 );
}



################################################################################
################################################################################
############################# Utility Functions ################################
################################################################################
################################################################################
################################################################################



################################################################################
# 
sub CleanResults( $ )
#
#  Given a result string, clean it up before sending an alert
#  Return the clean result, or undef if nothing is left
#
################################################################################
{	my $result = shift;
	
	return( "" ) if ( ! defined $result );
	
	# Only show printable characters
	$result =~ s/[^A-Z,a-z,0-9,\.\-\=\!\#\%\~\_\$\^\&\,\(\)\@\[\]\s\\\:\/\'\"]//gm;
	
	# Remove any blank lines
	$result =~ s/\n+/\n/g if ( $result );
	
	# Get rid of leading and trailing whitespace
	$result =~ s/^\s+// if ( $result );
	$result =~ s/\s+$// if ( $result );
	
	# Add a trailing carriage return
	$result .= "\n" if ( $result );
	
	return( $result );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmMonitor";

    bprint <<".";
Usage: IpmMonitor
Monitors IPM tasks, reporting errors to the monitoring server

  -k, --kill             kill any copies of the IpmMonitor that are running
  -h, --help             display this help and exit
  -l, --logging          do more extensive logging of events
  -v, --verbose          display verbose messages
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
    my $me = "IpmMonitor";

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
