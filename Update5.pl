################################################################################
#!perl -w
#
# Rob McCarthy's Update scan engine, Virus signatures, and Banned Processes
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;


my $version = "5.03.02";	# Current version number - should match sapackage.txt in the current scan package
my $testing_only = undef;	# True if I'm doing internal testing, undef if release version


use Getopt::Long;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use Win32;
use Win32::API;
use Win32::OLE;
use Win32::Event;
use Win32::Process;
use Win32API::File qw( :ALL );
use Win32API::Registry 0.21 qw( :ALL );
use Fcntl qw(:DEFAULT :flock);
use Content::File;
use Content::ScanUtil;
use Content::ScanFile;
use Content::Disinfect;
use Content::Policy;
use Content::Update;
use Content::UpdateLog;
use Content::UpdateEvent;
use Content::FileIntegrity;
use Content::Registry;
use Content::QueryOS;
use Content::SAMonitor;
use Content::Process;
use File::Copy;
use Cwd;



# Options
my $opt_version;						# Display version # and exit
my $opt_help;							# Display help and exit
my $opt_reload;							# True if I should reload all the tables from the TTC Server
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_debug;							# True if debugging - main difference is the URLs used
my $opt_install;						# True if I'm installing a new scan package from the command line
my $opt_uninstall;						# True if I'm uninstalling everything
my $opt_signal;							# True if I just want to signal the security agent service to reload
my $opt_all;							# True if I should scan all the drives right now, no matter what the time
my $opt_noshell;						# True if I should unload the shell extension
my $opt_shell;							# True if I should load the shell extension
my $opt_registry_changes = 1;			# True if I should create or append to the registry change file
my $opt_force_update;					# True if I should update everything now, no matter what the time
my $opt_override;						# If set, set the update source to this value and exit
my $opt_ldap;							# True if I just need to recheck ldap user, OU, and group information



# Globals
my %category;							# The category hash containing all the category properties, index is the category number, value are all the properties, tab delimited
my %category_blocked;					# The hash of the categories, index is category number, value is 0 if allowed, 1 if blocked
my $start_date = "1\/1\/2000";			# The start date for XML if I have to reload a table
my $default_ttc_server = "securityagent.lightspeedsystems.com";
my $errors_filename;					# "$dir\\UpdateErrors\.log";
my $working_dir;						# The software working directory - normally c:\Program Files\Lightspeed Systems\SecurityAgent
my $agent_report_file;					# The name of the security agent report file, if it exists
my $error_category = 0 + 7;				# hard coded errors category



# Security Agent Properties from the registry that are also loaded into memory
# Most of these properties can be set by the TTC server
my $ttc_server;							# This the ttc server that I should get updates from
my $use_lightspeed;						# True if I should use the Lightspeed default ttc server
my $backup1;							# Backup server 1
my $backup2;							# Backup server 2
my $update_interval;					# The time interval of doing updates

# Who has set the properties
my $server_properties;					# True if the Security Agent properties can only be set by the server
my $manual_properties;					# True if the properties were set manually - must be set to 0 if server_properties is True

# Virus and permissions options
my $block_virus;						# True if I should block viruses
my $block_virus_action;					# What to do if a virus is detected
my $scan_system;						# True if I am supposed to periodically scan the entire system
my $scan_interval;						# How often to scan the entire PC for viruses - Everyday, Sunday - Saturday
my $scan_time;							# What time of the day to scan - default 6 PM or 18
my $block_spyware;						# True if I should tell the scan program to delete spyware
my $scan_content;						# True if I should scan files by content
my $block_all_unknown;					# True if all unknown programs should be blocked from running

# Reporting options
my $report_events;						# True if I should report events (like discovered viruses) back to may update server
my $remote_monitoring;					# True if remote monitoring is allowed
my $only_protected_connections;			# Currently unused

# Enabled options
my $enable_shell;						# True if the shell extension should be enabled
my $enable_manager;						# True if the Security Agent Manager should display an icon in the systray
my $enable_alerts;						# True if alert messages are enabled

# LDAP properties
my $novell_ldap_server;					# The LDAP server to use to lookup OU and group membership if Novell
my $novell_ldap_root;					# The LDAP server root to use for the lookup if Novell
my $uid_attribute;						# The LDAP UID attribute - cn for Novell LDAP
my $group_attribute;					# The LDAP group attribute - groupMembership for Novell LDAP
my $protocol_version;					# The LDAP protocol version - either "2" or "3" - "3" for Novell LDAP



# Unknown program permissions
my $use_file_integrity;					# True if I should use file integrity to discover unknown programs
my $known_permissions = 0 + 0;			# The default permissions for known programs
my $unknown_permissions = 0x00fffffe;	# The default permissions for unknown programs



# These are various update times
my $signature_update;		# This is the last time I got a virus signature update
my $banned_update;			# This is the last time I got a banned process update
my $engine_update;			# This is the last time I got a new scan engine update
my $last_scan;				# This is the last time I fully scanned the PC - in system seconds
my $category_update;		# This is the last time I got a category update
my $last_purge;				# This is the last time I purged the file integrity database - in system seconds
my $integrity_update;		# This is the last time I got a file integrity update
my $registry_update;		# This is the last time I got a registry control update



# Permissions bit values
my $unknown_bit						= 0 + 0x00000001;
my $no_talk_on_network_bit			= 0 + 0x00000002;
my $no_write_process_memory_bit		= 0 + 0x00000004;
my $no_modify_registry_bit			= 0 + 0x00000008;
my $no_listen_on_network_bit		= 0 + 0x00000010;
my $no_modify_process_disk_bit		= 0 + 0x00000020;
my $no_create_process_bit			= 0 + 0x00000040;
my $no_full_security_bit			= 0 + 0x00000080;
my $local_use_default_perm_bit		= 0 + 0x40000000;	# If this bit is set, use the default permissions for known programs
my $local_unused_bit				= 0 + 0x80000000;	# If this bit is turned on, then file is not active on the local computer
my $network_use_default_perm_bit	= 0 + 0x40000000;	# If this bit is set, use the default permissions for known programs
my $network_unused_bit				= 0 + 0x80000000;	# If this bit is turned on, then file is not active on the local computer



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
		"a|all"			=> \$opt_all,
		"c|change"		=> \$opt_registry_changes,
		"e|explorer"	=> \$opt_shell,
		"f|force"		=> \$opt_force_update,
		"i|install"		=> \$opt_install,
		"l|ldap"		=> \$opt_ldap,
		"n|noexplorer"	=> \$opt_noshell,
		"o|override=s"	=> \$opt_override,
		"r|reload"		=> \$opt_reload,
		"s|signal"		=> \$opt_signal,
		"u|uninstall"	=> \$opt_uninstall,
		"v|version"		=> \$opt_version,
		"w|wizard"		=> \$opt_wizard,
		"h|help"		=> \$opt_help,
		"x|xxxdebug"	=> \$opt_debug
    );


	# Did I get an agent report file?
	$agent_report_file = shift;


	# Should I signal the SecurityAgent sevice that something has changed
	if ( $opt_signal )
		{	my $ok = &SignalService();
			if ( $ok )
				{	print "Signaled the Security Agent service to reload properties\n";
				}
			else
				{	print "The Security Agent service is not running\n";
				}
				
			exit( 0 );
		}
		

    &StdHeader( "Security Agent Update Utility" ) if ( ! $opt_wizard );
    &StdHeader( "Version: $version" ) if ( ! $opt_wizard );

	print "Debugging turned on\n" if ( $opt_debug );
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	

	$working_dir = &ScanWorkingDirectory();


	# Do I just need to check LDAP information?
	if ( $opt_ldap )
		{	print "Checking user information ...\n";
			my ( $username, $computer_name, $computer_domain, $ou, $comment ) = &UpdateGetUserName();
			my $network = &UpdateGetNetwork();
			print "Network Type: $network\n" if ( $network );
			print "User name: $username\n" if ( $username );
			print "Computer name: $computer_name\n" if ( $computer_name );
			print "Organization Unit: $ou\n" if ( $ou );
			
			if ( $username )
				{	my @groups = &UpdateGetUserGroups( $username, $computer_name );
					foreach ( @groups )
						{	print "Group: $_\n" if ( $_ );
						}
						
					print "Unable to discover any groups\n" if ( ! $groups[ 0 ] );	
				}
				
			exit( 0 );
		}
		

	# Am I uninstalling everything?
	if ( $opt_uninstall )
		{	&UninstallSoftware();
			exit( 0 );
		}
	
	
	# Am I over riding the TTC Server?
	if ( $opt_override )
		{	&OverrideTTCServer( $opt_override );
			exit( 0 );
		}
		
		
	# Do I need to uninstall the shell extension?
	if ( $opt_noshell )
		{	my $enabled = &ShellEnabled();
			
			# Turn off the registry value for "Enable Shell"
			&SetShellEnabled( undef );
			
			if ( ! $enabled )
				{	print "The Security Agent shell extension is already not loaded.\n";
					exit( 0 );
				}
				
				
			print "Unloading the Security Agent shell extension ...\n";
			chdir( $working_dir );
			if ( -e "SecurityAgentShellExt.dll" )
				{	system "regsvr32 \/u \/s securityagentshellext.dll";
					&RestartExplorer();
				}
			else	
				{	print "Can not find SecurityAgentShellExt.dll";
				}
				
			exit( 0 );
		}			
	
	
	# Do I need to install the shell extension?
	if ( $opt_shell )
		{	my $enabled = &ShellEnabled();
			
			# Turn on the registry value for "Enable Shell"
			&SetShellEnabled( 1 );
			if ( $enabled )
				{	print "The Security Agent shell extension is already loaded.\n";
					exit( 0 );
				}
		
			
			print "Loading the Security Agent shell extension ...\n";
			chdir( $working_dir );
			if ( -e "SecurityAgentShellExt.dll" )
				{	system "regsvr32 \/s securityagentshellext.dll";
					&RestartExplorer();
				}
			else
				{	print "Can not find SecurityAgentShellExt.dll";
				}
				
			exit( 0 );
		}			
	
	
	if ( &IsUpdateRunning() )
		{	print "The is another copy of the Security Agent Update utility already running ...\n";
			exit( 0 );
		}
		
		
	# Create a new event to stop other copies of this program from running at the same time
	my $ok = &UpdateRunning();
	if ( ! $ok )
		{	print "There is another copy of Update already running by someone else ...\n";
			exit( 0 );
		}

	
	&TrapErrors() if ( ! $opt_debug );
	
	
	# Open up the security log
	my $security_log = &SecurityOpenLogFile( $working_dir );		
	&SecurityLogEvent( "Security Agent Update version $version\n" );
	
	
	# Am I installing a scan package from the command line?
	if ( $opt_install )
		{	&SecurityLogEvent( "Installing a new scan engine package from the command line\n" );
			
			my $dir = &ScanWorkingDirectory();
			my $full_filename = "scan.htm";
			$full_filename = $dir . "\\scan.htm" if ( $dir );
			
			if ( ! -e $full_filename )
				{	&SecurityLogEvent( "Scan engine package $full_filename does not exist\n" );
				}
			else
				{	&InstallScanEngine( $dir, $full_filename );
				}
				
			exit( 0 );
		}
		
		
	# Show any option selected
	&SecurityLogEvent( "Start security scan now\n" ) if ( $opt_all );
	&SecurityLogEvent( "Reload all the local databases\n" ) if ( $opt_reload );
	&SecurityLogEvent( "Force a full update now\n" ) if ( $opt_force_update );
	
	
	my ( $os, $osversion, $servicepack, $memory, $serial_number, $registered, $organization ) =
				&QueryOS();	
				
	&SecurityLogEvent( "OS: $os\n" ) if ( $os );
	&SecurityLogEvent( "OS Version: $osversion\n" ) if ( $osversion );
	&SecurityLogEvent( "OS Service Pack: $servicepack\n" ) if ( $servicepack );
	#&SecurityLogEvent( "Total virtual memory: $memory\n" ) if ( $memory );
	
	&CleanUpFiles( $working_dir, undef );
	
	
	# Make sure that the file integrity file at least contains my programs
	&UpdateSecurityAgentFileIntegrity();
	

	# Get the main TTC server and the update properties
	( $ttc_server, $signature_update,
	 $banned_update, $engine_update,
	 $last_scan, $category_update,
	 $last_purge, $manual_properties,
	 $integrity_update, $registry_update,
	 $use_lightspeed ) = &GetTTCServer( $default_ttc_server );


	# Get the additional properties from the registry
	&LoadProperties();	


	
	# If I couldn't find a responding ttc server, just log that
	my $update_ok;
	
	if ( ! $ttc_server )
		{	&SecurityLogEvent( "Unable to find any update sources right now, will try again later ...\n" );
		}
	else
		{	&SecurityLogEvent( "Using $ttc_server as the update source\n" );
			
			# Tell the TTC server about myself
			my ( $username, $computer_name, $computer_domain, $ou, $comment ) = &UpdateGetUserName();
			&SecurityLogEvent( "Reporting to $ttc_server that the Security Agent exists\n" );
			my $network = &UpdateGetNetwork();
			&SecurityLogEvent( "Network Type: $network\n" ) if ( $network );
			&SecurityLogEvent( "User name: $username\n" ) if ( $username );
			&SecurityLogEvent( "Computer name: $computer_name\n" ) if ( $computer_name );
			&SecurityLogEvent( "Organization Unit: $ou\n" ) if ( $ou );
			&ReportSecurityAgent( $ttc_server, $computer_name, $comment, $os );
			
			# At this point I've got a responding TTC Server, so get all the updates
			# This may not return - especially if there was a new update program downloaded
			# If it doesn't return it will close the security log
			$update_ok = &UpdateEverything( $opt_force_update );
		}
	
		
	# Make sure that Win XP Service Pack 2 has the right registry settings for my program to use
	&UpdateXPSP2() if ( ( $servicepack ) &&  ( $servicepack =~ m/Service Pack 2/ )  &&  ( $report_events ) );


	# Make sure that simple file sharing is turned off
	&UpdateSimpleFileSharing();
	
	&ScanSystem();
	
	
	# Tell the ttc server about the scan results - if I can
	# Don't send a report to the default ttc server if it is the one being used ...
	my $lc_ttc_server;
	$lc_ttc_server = lc( $ttc_server ) if ( $ttc_server );
	my $lc_default = lc( $default_ttc_server );


	# Should I report what happened?
	&UpdateResults() if ( ( $ttc_server )  &&  ( $lc_ttc_server ne $lc_default )  &&  ( $report_events ) );	
	
	
	# Report any monitored alerts
	&SAMonitor( $ttc_server );
	
	&DeleteReportFiles() if ( ! $report_events );
	
	
	# Save my settings back into the registry
	&SaveTTCUpdates() if ( $ttc_server );
	
	
	&MergeLogs();	# Merge all the logs into the security log	
	
	# Done with all the updating stuff, so put the time into the log
	my $time = localtime( time() );	
	&SecurityLogEvent( "\nSecurity log closed: $time\n" );
	
	
	&SecurityCloseLogFile();
	
	&AddHistoryLog( $working_dir, $security_log );
	
	
	# If everything updated ok, put it into the registry
	if ( ( $update_ok )  &&  ( $ttc_server ) )
		{	my $key;
			my $type;
			my $data;
	
			my $is_ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
			$year += 1900;
			$mon++;
			my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
			
			if ( $is_ok )
				{	RegSetValueEx( $key, "Last Complete Update", 0,  REG_SZ, $datestr );
					RegCloseKey( $key );
				}
		}
	
	exit( 0 );
}



################################################################################
#
sub OverrideTTCServer( $ )
#
#  Override the TTC Server in the registry with a new server name
#
################################################################################
{	my $override_ttc_server = shift;
			
	#  See if the key already exists
	my $key;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );

	# If not OK, create the main keys and return the default values
	if ( ! $ok )
		{	my $regErr = regLastError();
			print "Unable to open main Security Agent key: $regErr\n";
			
			# Make sure the main Lightspeed Systems key is created
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );

			# Now create my key
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );
			
			if ( ! $ok )
				{	my $regErr = regLastError();
					print "Unable to create main Security Agent key: $regErr\n";
					return( undef );
				}
		}
	
	my $type;
	my $data;	
	$ok = RegQueryValueEx( $key, "TTC Server", [], $type, $data, [] );
	
	my $multi_sz = $override_ttc_server;
	
	# Tack on 2 extra x00 on the end to make it a multi sz	
	$multi_sz = $multi_sz . "\x00\x00" if ( $multi_sz );
	
	$data = " " if ( ! $data );
	if ( $multi_sz ne $data )
		{	print "Overriding the existing update source with $override_ttc_server\n";
			RegSetValueEx( $key, "TTC Server", 0,  REG_MULTI_SZ, $multi_sz );
		}
	else
		{	print "The existing update source is already set to $override_ttc_server\n";
		}
		

	# Make sure the use lightspeed key is set to no
	$data = "\x00\x00\x00\x00";
	RegSetValueEx( $key, "Use Lightspeed", 0,  REG_DWORD, $data );

	RegCloseKey( $key );
	
	return( 1 );
}



################################################################################
#
sub SaveTTCUpdates()
#
#  Save the TTC server, and all of the update times
#
################################################################################
{	&SecurityLogEvent( "Saving current settings\n" );
	
	my $ret = &SetTTCServer( $ttc_server, $signature_update, 
				  $banned_update, $engine_update, 
				  $last_scan, $category_update, 
				  $last_purge, $integrity_update, 
				  $registry_update, $use_lightspeed );
	
	return( $ret );
}



################################################################################
#
sub AddHistoryLog( $$ )
#
#  In the given directory, merge the history log with the new log file
#
################################################################################
{	my $dir		= shift;
	my $logname = shift;
	
	# Return undef if the logfile doesn't exist
	return( undef ) if ( ! $logname );
	return( undef ) if ( ! -e $logname );
	
	my $history_log = $dir . "\\history.log";
	
	my $size = -s $history_log;
	
	my $mode = ">>";	# Default is append mode
	$mode = ">" if ( ( $size  )  &&  ( $size > ( 0 + 1000000 ) ) );	# If the size is larger than a meg, rewrite the file
	
	open HISTORY, "$mode$history_log" or return( undef );
	
	if ( ! open LOG, "<$logname" )
		{	close HISTORY;
			return( undef );	
		}
	
	print HISTORY "\n\n";
	
	while (<LOG>)
		{	print HISTORY "$_";
		}
		
	close LOG;
	close HISTORY;
	

	return( 1 );
}



################################################################################
#
sub MergeLogs()
#
#  Merge together the update, scan, and error logs
#
################################################################################
{
	# Merge the UpdateErrors log into the security log
	# If I can open the file, merge it into the security log
	if ( ( $errors_filename )  &&  ( -e $errors_filename )  &&  ( open( FILE, "<$errors_filename" ) ) )	
		{	&SecurityLogEvent( "Update Errors:\n" );
			
			my $count = 0 + 0;
			while (<FILE>)
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					
					&SecurityLogEvent( "$line\n" );
					$count++;
				}
				
			&SecurityLogEvent( "No update errors\n" ) if ( ! $count );
			close FILE;
		}
		
		
	# Merge the scan log into the security log - only stick in viruses discovered
	my $scan_log_file_name = "$working_dir\\scan.log";
	if ( open( FILE, "<$scan_log_file_name" ) )	# If I can open the file, merge it into the security log
		{	&SecurityLogEvent( "\n" );
			
			my @virus_found;
			
			while (<FILE>)
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					next if ( ! ( $line =~ m/Infection/ ) );
					
					push @virus_found, $line;		 
				}
			
			 if ( $#virus_found )	
				{	&SecurityLogEvent( "No viruses found by last scan.\n" );
				}
			else
				{	&SecurityLogEvent( "\nThe last scan found the following viruses ...\n" );
					foreach ( @virus_found )
						{	next if ( ! $_ );
							&SecurityLogEvent( "$_\n" );
						}
					&SecurityLogEvent( "\n" );	
				}
				
			close FILE;
		}
	else
		{	&SecurityLogEvent( "Error opening $scan_log_file_name: $!\n" ) if ( -e $scan_log_file_name );
		}
		
	
	# Merge the ScanErrors log into the security log
	# If I can open the file, merge it into the security log
	my $scan_errors_filename = "$working_dir\\ScanErrors\.log";
	if ( ( -e $scan_errors_filename )  &&  ( open( FILE, "<$scan_errors_filename" ) ) )	
		{	&SecurityLogEvent( "Scan Errors:\n" );
			
			my $count = 0 + 0;
			while (<FILE>)
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					
					&SecurityLogEvent( "$line\n" );
					$count++;
				}
				
			&SecurityLogEvent( "No scan errors\n" ) if ( ! $count );
			close FILE;
		}

	return( 1 );
}



################################################################################
#
sub UpdateEverything( $ )
#
#  Update everything on the system - return true if everything updated ok,
#  undef if it didn't
#
################################################################################
{	my $force_update_now = shift;	# True if I should update now, no matter what the time
	
	my $update_ok;			# The return code from this function
	
	my $changed;			# True if I've changed something that the Security Agent service should know about
	my $categories_changed;	# True if I've just changed the categories
	
	
	if ( $opt_reload )
		{	&SecurityLogEvent( "Reloading all the database tables from $ttc_server ...\n" );
			$signature_update	= $start_date;
			$banned_update		= $start_date;
			$category_update	= $start_date;
			$integrity_update	= $start_date;
			$registry_update	= $start_date;
			
			$changed = 1;
		}
	else	# Is it time to run the update everything now ...
		{	my $update_now;	# Set this to true if it is time to update now
			
			$update_interval = &OneOf( $update_interval, "Day", "Hour", "Week" );
			
		 	my $key;
			my $type;
			my $data;
	
			my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );
			my $last_update;
			
			if ( $ok )
				{	$data = undef;
					$ok = RegQueryValueEx( $key, "Last Complete Update", [], $type, $data, [] );
					RegCloseKey( $key );
					$update_now = 1 if ( ! $ok );
					$last_update = $data;
				}
			else
				{	$update_now = 1;
				}
				
				
			$update_now = 1 if ( $force_update_now );
			$update_now = 1 if ( $update_interval eq "Hour" );
			
			
			$update_now = &ExpiredTime( $update_interval, $last_update ) if ( ! $update_now );
			
			
			# Return undef, indicating that not everything updated ok
			if ( ! $update_now )
				{	&SecurityLogEvent( "The last complete update was $last_update.\n" ) if ( $last_update );
					my $lc_update_interval = lc( $update_interval );
					&SecurityLogEvent( "Set to check for updates once a $lc_update_interval.\n" );
					&SecurityLogEvent( "Not yet time to check for the next updates.\n" );
					
					
					# Check to see if the Policy Apply changes anything
					$changed = &PolicyApply();
					
					# Signal the SecurityAgent sevice that something has changed
					if ( $changed )
						{	my $ok = &SignalService();
							&SecurityLogEvent( "Signaled the Security Agent service to reload properties\n" ) if ( $ok );
							&SecurityLogEvent( "The Security Agent service is not running\n" ) if ( ! $ok );
						}
					
					return( undef );
				}
		}


	# Set this to true, and if anything screws up, set it to undef
	$update_ok = 1;
	
	
	# If I got to here, then it is time to update everything
	
	
	# If manual properties are set, is the server trying to overwrite them?
	&DownloadServerProperties( $ttc_server ) if ( $manual_properties );
	
	
	if ( ! $manual_properties )
		{	my $ok;	
			$ok = &DownloadProperties( $ttc_server );
			
			if ( $ok )
				{	&SecurityLogEvent( "Updated Security Agent properties from $ttc_server\n" );
					&SaveProperties();	# Save the new properties into the registry
					$changed = 1;
				}
			elsif ( defined $ok )
				{	&SecurityLogEvent( "Security Agent properties from $ttc_server have not changed\n" );
				}
		}
	
	
	# Show who is setting the security agent properties
	if ( $manual_properties )
		{	&SecurityLogEvent( "Security Agent Properties: Set by a local user\n" );
			&SecurityLogEvent( "Properties can not be changed from $ttc_server.\n" );
		}
		
	if ( $server_properties )
		{	&SecurityLogEvent( "Security Agent Properties: Set from $ttc_server.\n" );
			&SecurityLogEvent( "Properties can not be changed by a local user.\n" );
		}
		
		
	if ( ( ! $server_properties )  &&  ( ! $manual_properties ) )
		{	&SecurityLogEvent( "Security Agent properties: Set from $ttc_server\n" );
			&SecurityLogEvent( "Properties can be changed by both a local user and from $ttc_server.\n" );
		}
		
		
	# Rename is True if I need to install a new update program
	my $renamer;
	my $last_update;
	( $last_update, $renamer ) = &DownloadScanEngine( $ttc_server, $engine_update );
	if ( ( $last_update )  &&  ( $last_update ne $engine_update ) )
		{	$engine_update = $last_update;
			
			&SaveTTCUpdates();
		}
					
		
	# Do I need to replace the current Update.exe program with a new one?
	# If so, I should do that right away in case it adds important new functionality
	if ( $renamer )
		{	&SecurityLogEvent( "Installing new Update utility\n" );
	
	
			# Signal the SecurityAgent sevice that something has changed
			&SignalService() if ( $changed );
		
		
			# If everything works right this function will not return
			# If it does return then there was an error
			# It will cose the security log if it should
			&RenameUpdate( $working_dir );
		}
	

	# Set this flag if I should signal the service that something changed
	my $signal_service;
	
	
	# Check for changes to the categories
	$category_update = $start_date if ( ! &ScanLoadCategories() );
	( $changed, $last_update ) = &DownloadCategories( $ttc_server, $category_update );
	if ( $changed )
		{	$category_update = $last_update;
			$categories_changed = 1;
			$signal_service = 1;
			
			&SaveTTCUpdates();
		}
	
	$update_ok = undef if ( ! $last_update );	
	$changed = undef;
	
	
	# I need to get the virus signatures if the categories have changed as well as when the virus
	# signatures themselves have changed.	
	( $changed, $last_update ) = &DownloadVirusSignatures( $ttc_server, $signature_update, $categories_changed );
	if ( $changed )
		{	$signature_update = $last_update;
			$signal_service = 1;
			
			&SaveTTCUpdates();
		}
		
	$update_ok = undef if ( ! $last_update );	
	$changed = undef;
	
	
	# check for changes to the banned processes	
	( $changed, $last_update ) = &DownloadBannedProcesses( $ttc_server, $banned_update, $categories_changed );
	if ( $changed )
		{	$banned_update = $last_update;
			$signal_service = 1;
			
			&SaveTTCUpdates();
		}
			
	$update_ok = undef if ( ! $last_update );
	$changed = undef;
	
		
	( $changed, $last_update ) = &DownloadFileIntegrity( $ttc_server, $integrity_update, $categories_changed );
	if ( $changed )
		{	$integrity_update = $last_update;
			$signal_service = 1;
			
			&SaveTTCUpdates();
		}
		
	$update_ok = undef if ( ! $last_update );	
	$changed = undef;
	
		
	( $changed, $last_update ) = &DownloadRegistryControl( $ttc_server, $registry_update, $categories_changed );
	if ( $changed )
		{	$registry_update = $last_update;
			$signal_service = 1;
			
			&SaveTTCUpdates();
		}
		
	$update_ok = undef if ( ! $last_update );			
		

	# Download the disinfect scripts - they don't matter as far as the service is concerned,
	# so don't signal the service if the disinfect scripts are the only thing changed
	( $changed, $last_update ) = &DownloadDisinfectScripts( $ttc_server );


	# Get the changes to the policy tables
	( $changed, $last_update ) = &DownloadPolicy( $ttc_server );
	( $changed, $last_update ) = &DownloadPolicyDefinition( $ttc_server );
	( $changed, $last_update ) = &DownloadRequiredSoftware( $ttc_server );
	
	
	# If everything came down ok, get the required policy version that I should be running
	# I can do this because I've gotten everything from the TTC server ok
	&DownloadActivePolicy( $ttc_server ) if ( $update_ok );
	
	
	# Check to see if the Policy Apply changes anything
	$changed = &PolicyApply();
	$signal_service = 1 if ( $changed );
	
	
	# Signal the SecurityAgent sevice that something has changed
	if ( $signal_service )
		{	my $ok = &SignalService();
			&SecurityLogEvent( "Signaled the Security Agent service to reload properties\n" ) if ( $ok );
			&SecurityLogEvent( "The Security Agent service is not running\n" ) if ( ! $ok );
		}
		
		
	# Return the update ok variable
	return( $update_ok );	
}



################################################################################
#
sub ExpiredTime( $$$ )
#
#  Given the update interval and the datestr of the last update, return
#  true if it is time to update everything, undef if not
#
################################################################################
{	my $update_interval = shift;	# This will be either day or week
	my $last_update		= shift;
	
	return( 1 ) if ( ! $last_update );
	
	my $old_time;
	$old_time = time() - ( 24 * 60 * 60 ) if ( $update_interval eq "Day" );
	$old_time = time() - ( 7 * 24 * 60 * 60 ) if ( $update_interval ne "Day" );
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );
	$year += 1900;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );

	return( 1 ) if ( $datestr gt $last_update );
	
	return( undef );
}



################################################################################
#
sub ScanSystem()
#
#  Scan everything on the system
#
################################################################################
{
	# Check the registry
	my ($ok, $msg ) = &RegistryControl( $working_dir, $opt_registry_changes );
	if ( ! defined $ok )
		{	&SecurityLogEvent( "Error running registry control: $msg\n" );
			return( undef, $msg );
		}
	else
		{	&SecurityLogEvent( "$msg\n" ) if ( $msg );
			
			# &SecurityLogEvent( "Registry control actions:\n" );
			
			# Merge the registry actions log into the security log
			my $registry_log_file_name = &RegistryControlActionsFilename();
			if ( open( FILE, "<$registry_log_file_name" ) )	# If I can open the file, merge it into the security log
				{	my $count = 0 + 0;
					while (<FILE>)
						{	my $line = $_;
							chomp( $line );
							next if ( ! $line );
							
							&SecurityLogEvent( "$line\n" );
							$count++;
						}
						
					close FILE;
					
					&SecurityLogEvent( "No new registry control actions\n" ) if ( ! $count );
				}
			else
				{	&SecurityLogEvent( "Error opening $registry_log_file_name: $!\n" ) if ( -e $registry_log_file_name );
				}
		}
	
	
	# Check for a hacked hosts file	
	&CheckHostsFile();
	
	
	# RunScanEngine returns undef if it didn't do anything, the time if it did
	my ( $last_update, $last_purge_started ) = &RunScanEngine( $last_scan, $last_purge, $opt_all );
	
	if ( ( $last_update )  &&  ( $last_update ne $last_scan ) )
		{	$last_scan  = $last_update;
			$last_purge = $last_purge_started;
		
			# Save the last scan date and last purge date back into the registry
			&SaveTTCUpdates();
		}
	
	
	return( 1 );	# Return ok
}



################################################################################
#
sub CheckHostsFile()
#
#  Check to see if the hosts fle has been hacked
#
################################################################################
{
	my $system_dir = &ScanSystemDirectory();
	
	my $hosts = $system_dir . "\\system32\\drivers\\etc\\hosts";
	
	return( 1 ) if ( ! -e $hosts );
	
	my $contents;
	
	open HOSTS, "<$hosts" or return( 1 );
	
	while ( <HOSTS> )
		{	$contents .= lc( $_ ) if ( $_ );
		}
			
	close HOSTS;
	
	my $problem;

	# Is there entries in the hosts file that look weird?
	$problem = 1 if ( $contents =~ m/bank/ );
	$problem = 1 if ( $contents =~ m/paypal/ );
	$problem = 1 if ( $contents =~ m/ebay/ );
	$problem = 1 if ( $contents =~ m/wellsfargo/ );
	$problem = 1 if ( $contents =~ m/citi/ );
	$problem = 1 if ( $contents =~ m/bofa/ );
	$problem = 1 if ( $contents =~ m/bankofamerica/ );
	$problem = 1 if ( $contents =~ m/wellfleet/ );
	$problem = 1 if ( $contents =~ m/finance/ );
	$problem = 1 if ( $contents =~ m/mortgage/ );
	
	
	if ( $problem )
		{	&SecurityLogEvent( "Your hosts file $hosts may have been hacked - please check it immediately!\n" );
			return( undef );
		}
		
	return( 1 );
}



################################################################################
#
sub UpdateResults()
#
#  Tell the TTC Server the results of my scan, and what the security agent service has reported
#  Return True if updated ok, undef if problems
#
################################################################################
{	
	# If I don't have a TTC Server I can't do anything
	return( undef ) if ( ! $ttc_server );
	
	
	# Report any registry control events
	my $file = &RegistryControlActionsFilename();
	if ( -e $file )
		{	&ReportRegistryControl( $ttc_server, $file );
		}
	
	$file = &RegistryControlChangesFilename();
	if ( -e $file )
		{	&ReportRegistryControl( $ttc_server, $file );
		}
	
	
	# Figure out if I have already reported this stuff by getting the last time I finished a scan
	# plus the last time I reported a scan
	my $key;
	my $type;
	my $data;
	
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	

	# Get the last scan time I reported
	my $last_scan_reported = 0 + 0;
	$ok = RegQueryValueEx( $key, "Last Scan Reported", [], $type, $data, [] );
	$last_scan_reported = $data if ( ( $ok )  &&  ( $data ) );
	$last_scan_reported = 0 + $last_scan_reported;


	# Get the last scan time I finished - this is set by the scan program
	my $last_scan_finished = 0 + 0;
	$ok = RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, [] );
	$last_scan_finished = $data if ( ( $ok )  &&  ( $data ) );
	$last_scan_finished = 0 + $last_scan_finished;

	RegCloseKey( $key );
	
	
	# If I haven't reported the last scan that finished, do so now ...
	if ( ( $ok )  &&  ( $last_scan_finished )  &&  ( $last_scan_finished ne $last_scan_reported ) )
		{	# Report any viruses that the scan program found
			&ReportScannedViruses( $ttc_server );
			
			
			# Check the TTC Server to see if it now knows some file IDs
			# Check to see if any of the unknown executables are now known
			my ( $discovered_count, @dangerous ) = &CheckUnknownFiles( $ttc_server, $working_dir, $opt_debug );


			# If I did figure out some of the unknown files, let the Security Agent service know about it
			if ( $discovered_count > 0 )
				{	&SecurityLogEvent( "Updated $discovered_count unknown executables as now known\n" ) if ( $discovered_count > 0 );

					# Signal the Security Agent service
					&SignalService();
				}
			
			# Since I've reported my unknown file to the TTC server, get rid of the unknown log
			my $unknown_log = $working_dir . "\\Unknown.log";
			if ( -e $unknown_log )
				{	$ok = unlink $unknown_log;
					&SecurityLogEvent( "Error deleting file $unknown_log: $!\n" ) if ( ! $ok );
				}
	
			# Save that I did this it back into the registry
			$last_scan_reported = $last_scan_finished;
			$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );	
			RegSetValueEx( $key, "Last Scan Reported", 0,  REG_SZ, $last_scan_reported ) if ( ( $last_scan_reported )  &&  ( $ok ) );

			RegCloseKey( $key ) if ( $ok );
		}	# end if if last_scan_reported ne $last_scan
	

	# Report any detected viruses, blocked unknown programs, etc ...
	if ( ( $agent_report_file )  &&  ( -e $agent_report_file ) )
		{	&ReportServiceActions( $ttc_server, $agent_report_file );
		}
	
	
	# See if there are any old reports from the security agent service in the tmp directory
	my $tmp_dir = &ScanTmpDirectory();
	return( 1 ) if ( ! opendir( DIRHANDLE, $tmp_dir ) );

	for my $item ( readdir( DIRHANDLE ) )
		{	# Is it the file current open by the service?
			next if ( ! $item );
			next if ( $item =~ m/Actions\.txt/ );
		
			my $lc_item = lc( $item );
			next if ( ! ( $lc_item =~ m/\.txt$/ ) );	# The file has to end in .txt
			next if ( ! ( $lc_item =~ m/^actions/ ) );	# The file has to start with actions
			
			my $full_path = $tmp_dir . "\\$item";

			next if ( ! -f $full_path );	# Is it a regular file?
			next if ( ! -T $full_path );	# Is it a text file?
			next if ( ! -w $full_path );	# Can I write to it? as a test for if I can delete it


			&ReportServiceActions( $ttc_server, $full_path );
		}
		
	closedir( DIRHANDLE );
	
	
	# Report the policy complience events
	&ReportPolicyComplience( $ttc_server );
	
	
	# Return ok
	return( 1 );	
}



################################################################################
#
sub ReportPolicyComplience( $$ )
#
#  Report back to the ttc_server any policy complience issues
#
################################################################################
{	my $ttc_server			= shift;
	
	my $file = $working_dir . "\\PolicyComplience.log";
	return( undef ) if ( ! -e $file );
	
	if ( ! open FILE, "<$file" )
		{	&SecurityLogEvent( "Unable to open policy complience log file $file: $!\n" );
			return( undef );
		}
		
	my $event_count = 0 + 0;
	my $ok = 1;
	
	while (<FILE>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			my ( $datestr, $username, $computer, $domain, $ou, $policy, $policy_type, $description ) = split /\t/, $line;
			
			next if ( ! $datestr );
			next if ( ! $username );
			next if ( ! $policy );
			next if ( ! $description );
			
			$domain		= undef if ( $domain	eq "N/A" );
			$computer	= undef if ( $computer	eq "N/A" );
			$ou			= undef if ( $ou		eq "N/A" );
						
			$ok = &ReportPolicyEvent( $ttc_server, $datestr, $username, $computer, $domain, $ou, $policy, $policy_type, $description );
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
		}
	
	close FILE;
	
	if ( $ok )
		{	$ok = unlink $file;
			&SecurityLogEvent( "Error deleting file $file: $!\n" ) if ( ! $ok );
		}
		
	&SecurityLogEvent( "Reported $event_count policy events back to $ttc_server\n" ) if ( $event_count > 0 );
	
	return( 1 );
}



################################################################################
#
sub ReportServiceActions( $$ )
#
#  Report back to the ttc_server any actions performed by the Security Agent Service
#
################################################################################
{	my $ttc_server			= shift;
	my $agent_report_file	= shift;
	

	if ( ! open FILE, "<$agent_report_file" )
		{	&SecurityLogEvent( "Unable to open security event file $agent_report_file: $!\n" );
			return( undef );
		}
	
	&SecurityLogEvent( "Reporting service actions from file $agent_report_file\n" );	

	my $event_count = 0 + 0;
	my $ok = 1;
	my $last_file;
	
	while (<FILE>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			my ( $date, $time, $file, $action, $virus ) = split /\t/, $line;
			
			next if ( ! $date );
			next if ( ! $time );
			next if ( ! $file );
			next if ( ! $action );
			
			# Don't flood the reporting with the same file name
			next if ( ( $last_file )  &&  ( $last_file eq $file ) );
			$last_file = $file;
			
			my $datestr = "$date $time";
			
			# Does the action say Virus blocked?  Then the action has the virus name stuck in it
			if ( $action =~ m/Virus blocked \(/ )
				{	$virus = $action;
					$virus =~ s/Virus blocked \(//;
					$virus =~ s/\)$//;
				}
				
			&SecurityLogEvent( "Security event: $datestr $virus\: $action\: $file\n" ) if ( $virus );
			&SecurityLogEvent( "Security event: $datestr $action\: $file\n" ) if ( ! $virus );
			
			$ok = &ReportSecurityEvent( $ttc_server, $datestr, $file, $virus, $action, undef, $opt_debug );
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
		}
	
	close FILE;
	
	if ( $ok )
		{	$ok = unlink $agent_report_file;
			&SecurityLogEvent( "Error deleting file $agent_report_file: $!\n" ) if ( ! $ok );
		}
		
	&SecurityLogEvent( "Reported $event_count security service actions back to $ttc_server\n" ) if ( $event_count > 0 );
	
	return( 1 );
}



################################################################################
#
sub ReportScannedViruses( $ )
#
#  Report back to the ttc_server any viruses found by the scan program
#
################################################################################
{	my $ttc_server = shift;
	
	return( undef ) if ( ! $ttc_server );
	
	my $file = $working_dir . "\\Virus.log";
	return( undef ) if ( ! -e $file );
	
	if ( ! open FILE, "<$file" )
		{	&SecurityLogEvent( "Unable to open virus log file $file: $!\n" );
			return( undef );
		}
		
	
	# At this point I have an opened virus.log file - now go through it looking for detected viruses	
	my $event_count = 0 + 0;
	
	
	# Put the current time into the correct format for the web page
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $last_scan );
	$year += 1900;
	$mon++;
	my $datestr = sprintf( "%02d\/%02d\/%04d %02d\:%02d\:%02d", $mon, $mday, $year, $hour, $min, $sec );
	
	
	# Go through each line of the file, looking for found viruses
	my $ok = 1;
	
	while (<FILE>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			# If the line in the virus log has the word Infection, then it is an infection
			next if ( ! ( $line =~ m/Infection/ ) );
		
			my ( $file, $junk, $virus, $action ) = split /\: /, $line;
			
			next if ( ! $virus );
			next if ( ! $file );

			$action = "Report only" if ( ! $action );			
			
			$ok = &ReportSecurityEvent( $ttc_server, $datestr, $file, $virus, $action, "Scan", $opt_debug );
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
		}
	
	close FILE;
						
	# Did I send all the viruses back to TTC ok?
	if ( $ok )
		{	$ok = unlink $file;
			&SecurityLogEvent( "Error deleting file $file: $!\n" ) if ( ! $ok );
		}
		
	&SecurityLogEvent( "Reported $event_count viruses detected by the scan program back to $ttc_server\n" ) if ( $event_count );
		
	return( $ok );
}



################################################################################
#
sub ReportRegistryControl( $$ )
#
#  Report back to the ttc_server any actions performed by Registry Control
#
################################################################################
{	my $ttc_server			= shift;
	my $agent_report_file	= shift;
	

	if ( ! open FILE, "<$agent_report_file" )
		{	&SecurityLogEvent( "Unable to open registry control file $agent_report_file: $!\n" );
			return( undef );
		}
		
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $last_scan );
	$year += 1900;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
		
		
	my $event_count = 0 + 0;
	my $ok = 1;
	
	while (<FILE>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			my $key;
			my $valname;
			my $valtype;
			my $oldvalue;
			my $newvalue;
			my $time = $datestr;
			my $action;
			my $clientip;
			
			
			my ( $desc, $val ) = split /: /, $line, 2;
			
			if ( $desc eq "Changed Key" )
				{	$action = "Changed Key";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$valtype = &GetValue( $line, "Type" );
					$line = <FILE>;
					$oldvalue = &GetValue( $line, "Old Value" );
					$line = <FILE>;
					$newvalue = &GetValue( $line, "New Value" );
				}
			elsif ( $desc eq "Deleted Key" )
				{	$action = "Deleted Key";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$valtype = &GetValue( $line, "Type" );
					$line = <FILE>;
					$oldvalue = &GetValue( $line, "Value" );
				}
			elsif ( $desc eq "Added Key" )
				{	$action = "Added Key";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$valtype = &GetValue( $line, "Type" );
					$line = <FILE>;
					$newvalue = &GetValue( $line, "Value" );
					
				}
			elsif ( $desc eq "Control Set" )
				{	$action = "Control Set";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$newvalue = &GetValue( $line, "Value" );					
				}
			elsif ( $desc eq "Control Delete" )
				{	$action = "Control Delete";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$oldvalue = &GetValue( $line, "Value" );					
				}
			else
				{	&SecurityLogEvent( "Unknown registry event: $line\n" );
					next;
				}
			
			$ok = &ReportRegistryEvent( $ttc_server, $key, $valname, $valtype, $oldvalue, $newvalue, $time, $action );
			
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
		}
	
	close FILE;
	
	
	# Did I send all the registry events back to TTC ok?
	if ( $ok )
		{	$ok = unlink $agent_report_file;
			&SecurityLogEvent( "Error deleting file $agent_report_file: $!\n" ) if ( ! $ok );
		}
		
		
	&SecurityLogEvent( "Reported $event_count registry actions back to $ttc_server\n" ) if ( $event_count > 0 );
	
	return( 1 );
}



################################################################################
#
sub GetValue( $$ )
#
#  Given a line, return the value extracted out
#
################################################################################
{	my $line = shift;
	my $name = shift;
	
	chomp( $line );
	return( undef ) if ( ! $line );
	
	
	my ( $lc_name, $value ) = split /\:/, $line, 2;
	
	$lc_name = lc( $name );
	
	if ( $lc_name ne lc( $name ) )
		{	&SecurityLogEvent( "Bad parameter in registry file: $line\n" );
			return( undef );	
		}
			
	return( $value );
}



################################################################################
#
sub DeleteReportFiles()
#
#  If I'm not reporting events, I need to delete the event report files so
#  that the disk doesn't fill up with them
#
################################################################################
{
	my $file = &RegistryControlActionsFilename();
	unlink $file if ( -e $file );
	
	
	# Is there an agent report file?
	if ( ( $agent_report_file )  &&  ( -e $agent_report_file ) )
		{	unlink $agent_report_file;
		}
	
	
	# See if there are any old reports from the security agent service in the tmp directory
	my $tmp_dir = &ScanTmpDirectory();
	return( 1 ) if ( ! opendir( DIRHANDLE, $tmp_dir ) );

	for my $item ( readdir( DIRHANDLE ) )
		{	# Is it the file current open by the service?
			next if ( ! $item );
			next if ( $item =~ m/Actions\.txt/ );
		
			my $lc_item = lc( $item );
			next if ( ! ( $lc_item =~ m/\.txt$/ ) );	# The file has to end in .txt
			next if ( ! ( $lc_item =~ m/^actions/ ) );	# The file has to start with actions
			
			my $full_path = $tmp_dir . "\\$item";

			next if ( ! -f $full_path );	# Is it a regular file?
			next if ( ! -T $full_path );	# Is it a text file?
			next if ( ! -w $full_path );	# Can I write to it? as a test for if I can delete it


			unlink $full_path;
		}
		
	closedir( DIRHANDLE );
	
	return( 1 );
}



################################################################################
#
sub UninstallSoftware()
#
#  Stop all the services, remove the device driver, remove all the directories
#
################################################################################
{
	print "Uninstalling SecurityAgent software ...\n";
	
	system( "net stop \"Security Agent Service\"" );
	
	my $working_dir = &ScanWorkingDirectory();
	my $system_dir = &ScanSystemDirectory();
	my $tmp_dir = &ScanTmpDirectory();
	my $quarantine = &ScanQuarantineDirectory();

	if ( ! -e $working_dir )
		{	print "Unable to find working directory: $working_dir\n";
			return( undef );
		}
		
	chdir( $working_dir );
	
	
	# Do I need to uninstall the shell extension?
	if ( ( -e "SecurityAgentShellExt.dll" )  &&  ( &ShellEnabled() ) )
		{	system "regsvr32 \/u \/s securityagentshellext.dll";
			&RestartExplorer();
		}
						
	
	# Signal the manager to die
	&KillManager();
	
	# Kill any of our processes that are running
	&ProcessKillName( "Scan" );
	&ProcessKillName( "SecurityAgentManager" );
		
	
	#  Delete all the Security Agent registry keys
	my $key;
	my $type;
	my $data;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems", 0, KEY_READ, $key );
	$ok = RegDeleteKey( $key, "SecurityAgent" ) if ( $ok );
	RegCloseKey( $key );


	&CleanUpFiles( $working_dir, undef );


	# Delete all the log files and data files
	my @delete_list;	
	push @delete_list, "$working_dir\\scan.log";
	push @delete_list, "$working_dir\\ScanErrors.log";
	push @delete_list, "$working_dir\\Security.log";
	push @delete_list, "$working_dir\\Unknown.log";
	push @delete_list, "$working_dir\\UpdateErrors.log";
	push @delete_list, "$working_dir\\History.log";
	push @delete_list, "$working_dir\\Category.dat";
	push @delete_list, "$working_dir\\Disinfect.dat";
	push @delete_list, "$working_dir\\BannedProcess.dat";
	push @delete_list, "$working_dir\\RegistryControl.dat";
	push @delete_list, "$working_dir\\RegistryMonitor.dat";
	push @delete_list, "$working_dir\\RegistryChanges.log";
	push @delete_list, "$working_dir\\RegistryActions.log";
	push @delete_list, "$working_dir\\RegistryHistory.log";
	push @delete_list, "$working_dir\\Policy.dat";
	push @delete_list, "$working_dir\\PolicyDefinition.dat";
	push @delete_list, "$working_dir\\PolicyComplience.log";
	push @delete_list, "$working_dir\\RequiredSoftware.dat";
	push @delete_list, "$working_dir\\sapackage.txt";
	push @delete_list, "$working_dir\\status.zip";
	push @delete_list, "$working_dir\\Autorun.log";
	push @delete_list, "$working_dir\\Registry.log";
	push @delete_list, "$working_dir\\Process.log";
	push @delete_list, "$working_dir\\Virus.log";
	push @delete_list, "$working_dir\\IpmSecurityAgentManager.chm";
	push @delete_list, "$working_dir\\msvcr71.dll";
	
	push @delete_list, "$working_dir\\arrow.gif";
	push @delete_list, "$working_dir\\bg.gif";
	push @delete_list, "$working_dir\\policy_blocked_banner.gif";
	push @delete_list, "$working_dir\\RequiredSoftware.html";
	
	push @delete_list, "$system_dir\\FileIntegrity";
	push @delete_list, "$system_dir\\VirusSignatures";
	push @delete_list, "$system_dir\\AllowSignatures";
	push @delete_list, "$system_dir\\CustomSignatures";

	
	foreach ( @delete_list )
		{	next if ( ! $_ );
			unlink( $_ );
		}
		

	my $cmd = "rmdir \"$tmp_dir\" \/s \/q";
	system( $cmd );
	
	$cmd = "rmdir \"$quarantine\" \/s \/q";
	system( $cmd );

	
	print "Done.\n";
}



################################################################################
#
sub CheckShellExtension()
#
#  Check to make sure that the enable_shell registry entry matches what is registered
#  with explorer - if not, make it so
#
#  Return True if it is enable, undef if not
#
################################################################################
{	my $explorer_enable = &ShellEnabled();
	
	
	# Does my property already match with is actually going on?
	# Is it supposed to not be enabled?
	return( undef ) if ( ( ! $explorer_enable )  &&  ( ! $enable_shell ) );
	
	
	# Is it supposed to be enabled?
	return( 1 ) if ( ( $explorer_enable )  &&  ( $enable_shell ) );
	
	
	# OK - at this point the shell extension is wrong - so fix it
	chdir( $working_dir );
	
	if ( ! -e "SecurityAgentShellExt.dll" )
		{	&SecurityLogEvent( "Can not find SecurityAgentShellExt.dll\n" );
			return( undef );
		}
		
	if ( $enable_shell )	
		{	&SecurityLogEvent( "Loading the Security Agent shell extension ...\n" );
			system "regsvr32 \/s securityagentshellext.dll";
		}
	else
		{	&SecurityLogEvent( "Unloadeding the Security Agent shell extension ...\n" );
			system "regsvr32 \/u \/s securityagentshellext.dll";
		}

	return( $enable_shell );
}



################################################################################
#
sub ShellEnabled()
#
#  Return True if the shell extension is registed with Explorer
#
################################################################################
{	my $explorer_shell_enabled;
	
	# See if the shell extension is registered with the property pages
	my $key;
	my $ok = RegOpenKeyEx( HKEY_CLASSES_ROOT, "*\\shellex\\PropertySheetHandlers\\{C374FD5E-0CB4-4CCE-B4FB-8F5BFB3F4454}", 0, KEY_READ, $key );
	RegCloseKey( $key ) if ( $ok );
	
	$explorer_shell_enabled = 1 if ( $ok );
	
	return( $explorer_shell_enabled );
}



################################################################################
#
sub SetShellEnabled( $ )
#
#  Set the the shell extension enabled status.
#  Don't do anything if the key doesn't exist
#
################################################################################
{	my $enable_shell = shift;
	
	my $key;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );	
	return( undef ) if ( ! $ok );

	my $data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_shell );
	RegSetValueEx( $key, "Enable Shell", 0,  REG_DWORD, $data );

	RegCloseKey( $key ) if ( $ok );
	
	return( $enable_shell );
}



################################################################################
#
sub RestartExplorer()
#
#  I have changed the shell extension, so now I need to restart explorer
#  This is called by a command line, or on the uninstall, so the current
#  user is the logged on user, so this should work
#
################################################################################
{
	&ProcessKillName( "explorer" );
	
	# Make sure that explorer comes back
	my $count = 0 + 0;
	my $running;
	
	# Wait up to 6 seconds for it to start running
	while ( ( $count < 6 )  &&  ( ! $running ) )
		{	sleep( 1 );
			$running = &ProcessRunningName( "explorer" );
			$count++;
		}
	
	if ( ! $running )
		{	my $explorer_process;
			my $system_root = $ENV{ SystemRoot };

			my $fullpath = $system_root . "\\explorer.exe";
			my $ok = Win32::Process::Create( $explorer_process, $fullpath, "explorer", 0, NORMAL_PRIORITY_CLASS, "." );	
			
			if ( ! $ok )
				{	my $str = Win32::FormatMessage( Win32::GetLastError() );
					print "Error relaunching $fullpath = $str\n";
				}
		}
		
	return( 1 );
}



################################################################################
#
sub DownloadProperties( $$ )
#
#  Download the Security Agent properties
#  Return True if downloaded the properties and they changed, 
#  0 if they didn't change, or undef if an error
#
################################################################################
{	my $ttc_server	= shift;
	my $last_update = shift;
	
	my $done;
	my $counter;
	
	my $url = "http:\/\/TTCSERVER\/content\/SecurityAgentProperties.aspx";
	
	$url =~ s/TTCSERVER/$ttc_server/;
			
	$| = 1;

	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 10000000 );
	$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			&SecurityLogEvent( "Unable to get Security Agent properties from $ttc_server: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		} 
		

	my @lines = split /\n/, $content;
	
	# Keep count of how many lines of data I've received
	if ( $#lines < ( 0 + 0 ) )
		{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
			return( undef );
		} 
			

	$content = undef;
	
	
	my $new_backup1						= $backup1;	
	my $new_backup2						= $backup2;	
	
	my $new_update_interval				= $update_interval;	
	
	my $new_scan_system					= undef;
	$new_scan_system					= "1" if ( $scan_system );
	
	my $new_block_virus					= undef;	
	$new_block_virus					= "1" if ( $block_virus );	
	
	my $new_block_virus_action			= $block_virus_action;	
	
	my $new_scan_content				= undef;
	$new_scan_content					= "1" if ( $scan_content );

	my $new_block_spyware				= undef;
	$new_block_spyware					= "1" if ( $block_spyware );
	
	my $new_server_properties			= undef;
	$new_server_properties				= "1" if ( $server_properties );
	
	my $new_block_all_unknown			= undef;
	$new_block_all_unknown				= "1" if ( $block_all_unknown );
	
	my $new_scan_interval				= $scan_interval;	
	my $new_scan_time					= $scan_time;	
	
	my $new_use_file_integrity			= undef;	
	$new_use_file_integrity				= "1" if ( $use_file_integrity );	

	my $new_report_events				= undef;		
	$new_report_events					= "1" if ( $report_events );
	
	my $new_remote_monitoring			= undef;		
	$new_remote_monitoring				= "1" if ( $remote_monitoring );
	
	my $new_only_protected				= undef;		
	$new_only_protected					= "1" if ( $only_protected_connections );
	
	my $new_enable_shell				= undef;		
	$new_enable_shell					= "1" if ( $enable_shell );
	
	my $new_enable_alerts				= undef;		
	$new_enable_alerts					= "1" if ( $enable_alerts );
	
	my $new_enable_manager				= undef;		
	$new_enable_manager					= "1" if ( $enable_manager );
	
		
	my $new_known_permissions			= $known_permissions;
	my $new_unknown_permissions			= $unknown_permissions;
	

	# LDAP parameters
	my $new_novell_ldap_server			= $novell_ldap_server;
	my $new_novell_ldap_root			= $novell_ldap_root;
	my $new_uid_attribute				= $uid_attribute;
	my $new_group_attribute				= $group_attribute;
	my $new_protocol_version			= $protocol_version;
	
	
	my $url_scan_time = "$scan_time am";
	my $pm = $scan_time - 12;
	$url_scan_time = "$pm pm" if ( $scan_time > 12 );
	my $url_scan_content = "FileExtension";
	$url_scan_content = "Content" if ( $scan_content );
	
	
	foreach( @lines )
		{	my $line = $_;
			chomp( $line );
			
			# Clean up the line
			$line =~ s/^\t.//;
			$line =~ s/^\s*//;
			$line =~ s/\s*$//;
			
			next if ( ! $line );


			$new_backup1					= &ValueExtract( $line, "Backup1", $new_backup1 );			
			$new_backup2					= &ValueExtract( $line, "Backup2", $new_backup2 );	
			
			$new_update_interval			= &ValueExtract( $line, "UpdateInterval", $new_update_interval );

			$new_scan_system				= &ValueExtract( $line, "ScanEntirePCforViruses", $new_scan_system );
			
			$new_block_virus				= &ValueExtract( $line, "BlockVirus", $new_block_virus );			
			$new_block_virus_action			= &ValueExtract( $line, "BlockVirusAction", $new_block_virus_action );
			
			$new_block_spyware				= &ValueExtract( $line, "RemoveSpyware", $new_block_spyware );
			
			$new_server_properties			= &ValueExtract( $line, "ServerProperties", $new_server_properties );
			
			$new_block_all_unknown			= &ValueExtract( $line, "BlockAllUnknown", $new_block_all_unknown );
			
			$new_scan_interval				= &ValueExtract( $line, "ScanDayofWeek", $new_scan_interval );			
			$url_scan_time					= &ValueExtract( $line, "ScanTimeofDay", $url_scan_time );	
			
			$url_scan_content				= &ValueExtract( $line, "ScanFilesBy", $url_scan_content );			
			
			$new_use_file_integrity			= &ValueExtract( $line, "UseFileIntegrity", $new_use_file_integrity );			

			$new_report_events				= &ValueExtract( $line, "ReportSecurityEvents", $new_report_events );			

			$new_only_protected				= &ValueExtract( $line, "AllowProtectedPCsOnly", $new_only_protected );
			
			$new_enable_shell				= &ValueExtract( $line, "ShowProgramPermissionsWithFileProperties", $new_enable_shell );
			
			$new_enable_manager				= &ValueExtract( $line, "ShowSystemTrayIcon", $new_enable_manager );
			
			$new_enable_alerts				= &ValueExtract( $line, "EnableAlerts", $new_enable_alerts );

			$new_known_permissions			= &ValueExtract( $line, "KnownProgramPermissions", $new_known_permissions );			
			$new_unknown_permissions		= &ValueExtract( $line, "UnknownProgramPermissions", $new_unknown_permissions );				

			$new_novell_ldap_server			= &ValueExtract( $line, "LDAPServer", $new_novell_ldap_server );				
			$new_novell_ldap_root			= &ValueExtract( $line, "LDAPRoot", $new_novell_ldap_root );				
			$new_uid_attribute				= &ValueExtract( $line, "LDAPUIDAttribute", $new_uid_attribute );				
			$new_group_attribute			= &ValueExtract( $line, "LDAPGroupAttribute", $new_group_attribute );				
			$new_protocol_version			= &ValueExtract( $line, "LDAPProtocolVersion", $new_protocol_version );				
		}
	

	my $changed = 0 + 0;
	
			
	$changed = 1 if ( &ChangedValue( $backup1, $new_backup1 ) );
	$changed = 1 if ( &ChangedValue( $backup2, $new_backup2 ) );
	
	$changed = 1 if ( &ChangedValue( $update_interval, $new_update_interval ) );
	
	$new_block_virus = &BinaryValue( $new_block_virus );
	$changed = 1 if ( &ChangedValue( $block_virus, $new_block_virus ) );
	
	$changed = 1 if ( &ChangedValue( $block_virus_action, $new_block_virus_action ) );
	
	$new_block_spyware = &BinaryValue( $new_block_spyware );
	$changed = 1 if ( &ChangedValue( $block_spyware, $new_block_spyware ) );
	
	$new_server_properties = &BinaryValue( $new_server_properties );
	$changed = 1 if ( &ChangedValue( $server_properties, $new_server_properties ) );
	
	$new_block_all_unknown = &BinaryValue( $new_block_all_unknown );
	$changed = 1 if ( &ChangedValue( $block_all_unknown, $new_block_all_unknown ) );
	
	$new_scan_system = &BinaryValue( $new_scan_system );
	$changed = 1 if ( &ChangedValue( $scan_system, $new_scan_system ) );
	
	$changed = 1 if ( &ChangedValue( $scan_interval, $new_scan_interval ) );
	
	my ( $hour, $meridian ) = split /\s/, $url_scan_time;
	$new_scan_time = 0 + $hour;
	$new_scan_time = 12 + $hour if ( ( $meridian )  &&  ( $meridian eq "pm" ) );


	$changed = 1 if ( &ChangedValue( $scan_time, $new_scan_time ) );
	
	$new_scan_content = undef;
	$new_scan_content = 0 + 1 if ( ( $url_scan_content )  &&  ( $url_scan_content ne "FileExtension" ) );
	$changed = 1 if ( &ChangedValue( $scan_content, $new_scan_content ) );
								  
	$new_use_file_integrity = &BinaryValue( $new_use_file_integrity );
	$changed = 1 if ( &ChangedValue( $use_file_integrity, $new_use_file_integrity ) );
	
	$new_report_events = &BinaryValue( $new_report_events );
	$changed = 1 if ( &ChangedValue( $report_events, $new_report_events ) );
	
	$new_remote_monitoring = &BinaryValue( $new_remote_monitoring );
	$changed = 1 if ( &ChangedValue( $remote_monitoring, $new_remote_monitoring ) );

	$new_only_protected = &BinaryValue( $new_only_protected );
	$changed = 1 if ( &ChangedValue( $only_protected_connections, $new_only_protected ) );

	$new_enable_shell = &BinaryValue( $new_enable_shell );
	$changed = 1 if ( &ChangedValue( $enable_shell, $new_enable_shell ) );

	$new_enable_alerts = &BinaryValue( $new_enable_alerts );
	$changed = 1 if ( &ChangedValue( $enable_alerts, $new_enable_alerts ) );

	$new_enable_manager = &BinaryValue( $new_enable_manager );
	$changed = 1 if ( &ChangedValue( $enable_manager, $new_enable_manager ) );
	
	$changed = 1 if ( &ChangedValue( $known_permissions, $new_known_permissions ) );
	$changed = 1 if ( &ChangedValue( $unknown_permissions, $new_unknown_permissions ) );
	
	$changed = 1 if ( &ChangedValue( $novell_ldap_server, $new_novell_ldap_server ) );
	$changed = 1 if ( &ChangedValue( $novell_ldap_root, $new_novell_ldap_root ) );
	$changed = 1 if ( &ChangedValue( $uid_attribute, $new_uid_attribute ) );
	$changed = 1 if ( &ChangedValue( $group_attribute, $new_group_attribute ) );
	$changed = 1 if ( &ChangedValue( $protocol_version, $new_protocol_version ) );
		
	$backup1					= $new_backup1;	
	$backup2					= $new_backup2;	
	
	$update_interval			= $new_update_interval;	
	
	$block_virus				= $new_block_virus;	
	$block_virus_action			= $new_block_virus_action;	
	
	$block_spyware				= $new_block_spyware;
	
	$server_properties			= $new_server_properties;
	
	# Make sure the manual properties are turned off if the server properties are turned on
	if ( ( $server_properties )  &&  ( $manual_properties ) )	
		{	$changed = 1;
			$manual_properties = undef;	
		}
		
	$block_all_unknown			= $new_block_all_unknown;
	
	$scan_system				= $new_scan_system;
	
	$scan_interval				= $new_scan_interval;	
	$scan_time					= $new_scan_time;	
	
	$scan_content				= $new_scan_content;
	
	$use_file_integrity			= $new_use_file_integrity;	
	

	# Can I actually turn on file integrity yet?
	# I can't if I haven't done the initial scan yet
	if ( $use_file_integrity )
		{	my $key;
			my $data;
			my $type;
			my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );

			$ok = RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, [] ) if ( $ok );
			
			$use_file_integrity = undef if ( ! $ok );
			$use_file_integrity = undef if ( ( $ok )  &&  ( ! $data ) );
			
			RegCloseKey( $key );
		}
	

	$report_events				= $new_report_events;
	
	$remote_monitoring			= $new_remote_monitoring;
	
	$only_protected_connections = $new_only_protected;
	
	$enable_shell				= $new_enable_shell;
	
	# Make sure the shell extension is set the right way with explorer
	&CheckShellExtension();
	
	$enable_alerts				= $new_enable_alerts;
	
	$enable_manager				= $new_enable_manager;
	
	$known_permissions			= $new_known_permissions;
	$unknown_permissions		= $new_unknown_permissions;

	$novell_ldap_server			= $new_novell_ldap_server;
	$novell_ldap_root			= $new_novell_ldap_root;
	$uid_attribute				= $new_uid_attribute;
	$group_attribute			= $new_group_attribute;
	$protocol_version			= $new_protocol_version;
	
	
	$ttc_server	= $default_ttc_server if ( ! $ttc_server );
	
	# Make sure the Security Agent Manager is set to run the right way	
	&CheckAutorunManager();
	
	return( $changed );
}




################################################################################
#
sub DownloadServerProperties( $$ )
#
#  Download the Security Agent Server properties - this is called if manual properties are enabled
#  Return True if server properties are enabled, which should turn off manual properties
#
################################################################################
{	my $ttc_server	= shift;
	my $last_update = shift;
	
	my $done;
	my $counter;
	
	&SecurityLogEvent( "Checking $ttc_server to see if server properties are set\n" );
	
	my $url = "http:\/\/TTCSERVER\/content\/SecurityAgentProperties.aspx";
	
	$url =~ s/TTCSERVER/$ttc_server/;
			
	$| = 1;

	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 10000000 );
	$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			&SecurityLogEvent( "Unable to get Security Agent properties from $ttc_server: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		} 
		

	my @lines = split /\n/, $content;
	
	# Keep count of how many lines of data I've received
	if ( $#lines < ( 0 + 0 ) )
		{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
			return( undef );
		} 
			

	$content = undef;
	
		
	my $new_server_properties	= undef;
	$new_server_properties		= "1" if ( $server_properties );
		
	
	foreach( @lines )
		{	my $line = $_;
			chomp( $line );
			
			# Clean up the line
			$line =~ s/^\t.//;
			$line =~ s/^\s*//;
			$line =~ s/\s*$//;
			
			next if ( ! $line );

			$new_server_properties	= &ValueExtract( $line, "ServerProperties", $new_server_properties );
			
		}
	
	
	my $changed;
	
	$new_server_properties = &BinaryValue( $new_server_properties );
	$changed = 1 if ( &ChangedValue( $server_properties, $new_server_properties ) );
		
	$server_properties = $new_server_properties;
	
	
	# Make sure the manual properties are turned off if the server properties are turned on
	if ( ( $server_properties )  &&  ( $manual_properties ) )	
		{	$manual_properties = undef;	
			$changed = 1;
		}
	
	
	# Save the new properties into the registry	
	&SaveProperties() if ( $changed );	
	
	
	# Make sure the shell extension is set the right way with explorer
	&CheckShellExtension();

	
	# Make sure the Security Agent Manager is set to run the right way	
	&CheckAutorunManager();
	
	return( $server_properties );
}




################################################################################
#
sub CheckAutorunManager()
#
#  Make sure the the autorun key is set to the right thing
#
################################################################################
{
	# Make sure the Security Agent Manager is enabled or disabled correctly
	# I need to make sure that the autorun entry is correct for the Security Agent Manager
	my $autokey;
	my $auto_ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, $autokey );


	# If I can't open the autorun, just return here
	if ( ! $auto_ok )
		{	&SecurityLogEvent( "Unable to open the autorun key\n" );
			return( undef );
		}
		
	my $running = &ProcessRunningName( "SecurityAgentManager" );
	
	my $type;
	my $data;
	my $ok = RegQueryValueEx( $autokey, "SecurityAgentManager", [], $type, $data, [] );
	my $fullpath = "$working_dir\\SecurityAgentManager.exe"; 


	# Is the registry already set to the correct full path?
	my $set;
	$set = 1 if ( ( $ok )  &&  ( $data )  &&  ( $data eq $fullpath ) );


	# Make sure the auto run key matches the registry entry
	if ( ( ! $enable_manager )  &&  ( $ok ) )
		{	# I should delete the value whatever it is
			RegDeleteValue( $autokey, "SecurityAgentManager" );
			&SecurityLogEvent( "Deleted the Security Agent Manager from auto running\n" );
		}
		
	if ( ( $enable_manager )  &&  ( ! $set ) )	# Make sure that is is set to autorun
		{	RegSetValueEx( $autokey, "SecurityAgentManager", 0,  REG_SZ, $fullpath );
			&SecurityLogEvent( "Set the Security Agent Manager to autorun\n" );
		}
		
	RegCloseKey( $autokey );	


	# Kill the manager if I have to ...
	if ( ( $running )  &&  ( ! $enable_manager ) )
		{	&SecurityLogEvent( "Signaling the Security Agent Manager to quit ...\n" );	
			
			# Signal the manager to die
			&KillManager();		
		}
		
	return( 1 );
}



################################################################################
#
sub BinaryValue( $ )
#
#  Given a "0" or "1", return undef or 0 + 1
#
################################################################################
{	my $val = shift;
	
	return( undef ) if ( ! $val );

	return( undef ) if ( $val eq "0" );
	
	return( undef ) if ( $val eq 0 );
	
	return( 0 + 1 );
}



################################################################################
#
sub ValueExtract( $$$ )
#
#  Pull a value out from a Url response
#
################################################################################
{	my $line	= shift;
	my $name	= shift;
	my $value	= shift;
	
	my $lc_line = lc( $line );
	my $lc_name = lc( $name ) . "\:";
	
	my $pos = index( $lc_line, $lc_name );
	return( $value ) if ( $pos < 0 );		# Just return the default value if the name isn't in the line
	
	my $start_pos = $pos + length( $lc_name );
	
	my $end_pos = index( $lc_line, ";", $start_pos );
		
	return( $value ) if ( $end_pos < 0 );
	return( undef ) if ( $end_pos == $start_pos );
	return( $value ) if ( $end_pos <= $start_pos );
	
	my $len = $end_pos - $start_pos;
	
	my $str = substr( $line, $start_pos, $len );
		
	return( undef ) if ( ! $str );
	
	$value = $str;
	$value = ( 0 + 1 ) if ( $str eq "1" );
	$value = ( 0 + 0 ) if ( $str eq "0" );

	# Is it a hex value?  Remember, this is in big-endian, so I have to switch to little endian
	if ( $value =~ m/^0x/ )
		{	$value = HexPermissionsToDWORD( $value );
		}
		
	return( $value );
}



################################################################################
#
sub ChangedValue( $$ )
#
#  Given 2 values, return 0 if they are the same, 1 if they are not
#
################################################################################
{	my $val1	= shift;
	my $val2	= shift;

	return( 0 ) if ( ( ! $val1 )  &&  ( ! $val2 ) );
	return( 1 ) if ( ( $val1 )  &&  ( ! $val2 ) );
	return( 1 ) if ( ( ! $val1 )  &&  ( $val2 ) );

	return( 1 ) if ( $val1 ne $val2 );
	
	return( 0 );
}




################################################################################
#
sub LoadProperties()
#
#  Load the additional properties from the registry - use defaults if not specified
#  Save the additional properties back into the registry if I have to use defaults
#
################################################################################
{	my $key;
	my $type;
	my $data;


	# Set the default values
	$backup1					= undef;
	$backup2					= undef;
	
	$update_interval			= "Day";
	$block_virus				= 0 + 1;
	$block_virus_action			= "Nothing";
	
	$block_spyware				= 0 + 1;
	
	$server_properties			= undef;
	
	$block_all_unknown			= undef;
	
	$scan_system				= 0 + 1;
	
	$scan_interval				= "Friday";
	$scan_time					= 0 + 18;
	
	$scan_content				= undef;
	
	$use_file_integrity			= undef;
	
	$report_events				= 0 + 1;

	$remote_monitoring			= 0 + 1;
	
	$only_protected_connections = undef;
	
	# For the default value use what the shell extension is currently set to
	$enable_shell				= &ShellEnabled();
	
	$enable_alerts				= 0 + 1;
	
	$enable_manager				= 0 + 1;
	
	$known_permissions			= 0 + 0;
	$unknown_permissions		= 0x00fffffe - 0x00000200;  # The unknown bit off, and the inherit bit off

	$novell_ldap_server			= undef;
	$novell_ldap_root			= undef;
	$uid_attribute				= "cn";
	$group_attribute			= "groupMembership";
	$protocol_version			= "3";
	

	my $save_properties;
	
	
	#  See if the key already exists
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );
	if ( ! $ok )
		{	&SaveProperties();	# Save the default properties if the key wasn't there
			return( undef );
		}
	
	
	# Load all the values in the registry
	$ok = RegQueryValueEx( $key, "Backup1", [], $type, $data, [] );
	if ( $ok )
		{	$backup1 = $data if ( $data );
			$backup1 = undef if ( ( $backup1 )  &&  ( $data eq "" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	$ok = RegQueryValueEx( $key, "Backup2", [], $type, $data, [] );
	if ( $ok )
		{	$backup2 = $data if ( $data );
			$backup2 = undef if ( ( $backup2 )  &&  ( $data eq "" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Update Interval", [], $type, $data, [] );
	if ( $ok )
		{	$update_interval = $data if ( $data );
			$update_interval = "Day" if ( ( $update_interval )  &&  ( $update_interval eq "" ) );
			$update_interval = &OneOf( $update_interval, "Day", "Hour", "Week" );
			$save_properties = 1 if ( ( ! $data )  ||  ( $update_interval ne $data ) );
		}
	$save_properties = 1 if ( ! $ok );

	
	$ok = RegQueryValueEx( $key, "Block Virus", [], $type, $data, [] );
	if ( $ok )
		{	$block_virus = undef;
			$block_virus = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );


	$ok = RegQueryValueEx( $key, "Block Virus Action", [], $type, $data, [] );
	if ( $ok )
		{	$block_virus_action = $data if ( $data );
			$block_virus_action = "Nothing" if ( ( $block_virus_action )  &&  ( $block_virus_action eq "" ) );
			$block_virus_action = &OneOf( $block_virus_action, "Nothing", "Delete", "Quarantine", "Disable" );
			$save_properties = 1 if ( ( ! $data )  ||  ( $block_virus_action ne $data ) );
		}
	$save_properties = 1 if ( ! $ok );


	$ok = RegQueryValueEx( $key, "Scan System", [], $type, $data, [] );
	if ( $ok )
		{	$scan_system = 0 + 1;
			$scan_system = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Scan Interval", [], $type, $data, [] );
	if ( $ok )
		{	$scan_interval = $data if ( $data );
			$scan_interval = "Friday" if ( ( $scan_interval )  &&  ( $data eq "" ) );
			$scan_interval = &OneOf( $scan_interval, "Friday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Everyday", "Saturday" );
			$save_properties = 1 if ( ( ! $data )  ||  ( $scan_interval ne $data ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Scan Time", [], $type, $data, [] );
	if ( $ok )
		{	$scan_time = 0 + 18;
			$scan_time = unpack "L", $data if ( $data );
			$scan_time = 0 + 18 if ( ( $scan_time < ( 0 + 0 ) )  &&  ( $scan_time > ( 0 + 23 ) ) );
			$save_properties = 1 if ( ! $data );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Scan Method", [], $type, $data, [] );
	if ( $ok )
		{	$scan_content = undef;
			$scan_content = 0 + 1 if ( ( $data )  &&  ( $data eq "Content" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$data = undef;
	$ok = RegQueryValueEx( $key, "Block Spyware", [], $type, $data, [] );
	if ( $ok )
		{	$block_spyware = undef;
			$block_spyware = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$data = undef;
	$ok = RegQueryValueEx( $key, "Server Properties", [], $type, $data, [] );
	if ( $ok )
		{	$server_properties = undef;
			$server_properties = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	# Make sure the manual properties are turned off if the server properties are turned on
	if ( ( $server_properties )  &&  ( $manual_properties ) )	
		{	$save_properties = 1;
			$manual_properties = undef;	
		}
	
	
	$data = undef;
	$ok = RegQueryValueEx( $key, "Block All Unknown", [], $type, $data, [] );
	if ( $ok )
		{	$block_all_unknown = undef;
			$block_all_unknown = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Use File Integrity", [], $type, $data, [] );
	if ( $ok )
		{	$use_file_integrity = undef;
			$use_file_integrity = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Report Events", [], $type, $data, [] );
	if ( $ok )
		{	$report_events = undef;
			$report_events = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Remote Monitoring", [], $type, $data, [] );
	if ( $ok )
		{	$remote_monitoring = undef;
			$remote_monitoring = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	
	$ok = RegQueryValueEx( $key, "Only Protected Connections", [], $type, $data, [] );
	if ( $ok )
		{	$only_protected_connections = undef;
			$only_protected_connections = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );

	
	$ok = RegQueryValueEx( $key, "Enable Shell", [], $type, $data, [] );
	if ( $ok )
		{	$enable_shell = undef;
			$enable_shell = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );
	
	# Make sure the shell extension is set the right way with explorer
	&CheckShellExtension();


	$ok = RegQueryValueEx( $key, "Enable Alerts", [], $type, $data, [] );
	if ( $ok )
		{	$enable_alerts = undef;
			$enable_alerts = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );

	$ok = RegQueryValueEx( $key, "Novell LDAP Server", [], $type, $data, [] );
	if ( $ok )
		{	$novell_ldap_server = $data;
			$novell_ldap_server = undef if ( $novell_ldap_server eq "" );
		}
	$save_properties = 1 if ( ! $ok );	


	$ok = RegQueryValueEx( $key, "Novell LDAP Base DN", [], $type, $data, [] );
	if ( $ok )
		{	$novell_ldap_root = $data;
			$novell_ldap_root = undef if ( $novell_ldap_root eq "" );
		}
	$save_properties = 1 if ( ! $ok );

	
	$ok = RegQueryValueEx( $key, "Novell LDAP UID Attribute", [], $type, $data, [] );
	if ( $ok )
		{	$uid_attribute = $data;
			$uid_attribute = undef if ( $uid_attribute eq "" );
		}
	$save_properties = 1 if ( ! $ok );

	
	$ok = RegQueryValueEx( $key, "Novell LDAP Group Attribute", [], $type, $data, [] );
	if ( $ok )
		{	$group_attribute = $data;
			$group_attribute = undef if ( $group_attribute eq "" );
		}
	$save_properties = 1 if ( ! $ok );

	
	$ok = RegQueryValueEx( $key, "Novell LDAP Protocol Version", [], $type, $data, [] );
	if ( $ok )
		{	$protocol_version = $data;
			$protocol_version = 0 + 3 if ( $protocol_version eq "" );
			
			# There are only 2 possible values for this - 2 or 3
			$protocol_version = 0 + 3 if ( ( $protocol_version ne 2 )  &&  ( $protocol_version ne 3 ) );
		}
	$save_properties = 1 if ( ! $ok );

	
	$ok = RegQueryValueEx( $key, "Enable Manager", [], $type, $data, [] );
	if ( $ok )
		{	$enable_manager = undef;
			$enable_manager = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ! $ok );	
	
	
	# I need to make sure that the autorun entry is correct for the Security Agent Manager
	$data = undef;
	$ok = RegQueryValueEx( $key, "Enable Manager", [], $type, $data, [] );
	if ( ( $ok )  &&  ( defined $data ) )
		{	$enable_manager = 0 + 1;
			$enable_manager = undef if ( $data  eq "\x00\x00\x00\x00" );
		}
		
	RegCloseKey( $key );
	
	CheckAutorunManager();
	
	( $known_permissions, $unknown_permissions ) = &LoadNetworkPermissions( $working_dir );
	
	&SaveProperties() if ( $save_properties );

	return( undef );
}



################################################################################
#
sub OneOf()
#
#  Given a variable value, make sure that it is one of the possible values
#  The current value is the first parameter, the default value is the second parameter
#  and all of the possible values are the next parameters
#  Make the comparisions case insensitive
#
################################################################################
{	my $current		= shift;
	my $lc_current	= lc( $current );
	my $default;
	my $ret;
	
	while ( my $val = shift )
		{	$default = $val if ( ! $default );
			
			my $lc_val = lc( $val );
			$ret = $val if ( $lc_val eq $lc_current );
		}
	
	$ret = $default if ( ! $ret );
	
	return( $ret );
}



################################################################################
#
sub SaveProperties()
#
#  Save the additional properties into the registry
#
################################################################################
{	my $key;
	my $type;
	my $data;
	
	
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );

	# If it's not ok, then I need to create the key
	if ( ! $ok )
		{	my $regErr = regLastError();
			&SecurityLogEvent( "Unable to open main Security Agent key: $regErr\n" );
			
			# Make sure the main Lightspeed Systems key is created
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );

			# Now create my key
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );
			
			if ( ! $ok )
				{	my $regErr = regLastError();
					&SecurityLogEvent( "Unable to create main Security Agent key: $regErr\n" );
					return( undef );
				}
		}


	$backup1 = "" if ( ! $backup1 );
	RegSetValueEx( $key, "Backup1", 0,  REG_SZ, $backup1 );
	$backup2 = "" if ( ! $backup2 );
	RegSetValueEx( $key, "Backup2", 0,  REG_SZ, $backup2 );
	
	$update_interval = "Day" if ( ! $update_interval );
	$update_interval = &OneOf( $update_interval, "Day", "Hour", "Week" );
	RegSetValueEx( $key, "Update Interval", 0,  REG_SZ, $update_interval );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_virus );
	RegSetValueEx( $key, "Block Virus", 0,  REG_DWORD, $data );
	
	$block_virus_action = "Nothing" if ( ! $block_virus_action );
	$block_virus_action = &OneOf( $block_virus_action, "Nothing", "Delete", "Quarantine", "Disable" );
	RegSetValueEx( $key, "Block Virus Action", 0,  REG_SZ, $block_virus_action );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $scan_system );
	RegSetValueEx( $key, "Scan Interval", 0,  REG_DWORD, $data );
	
	$scan_interval = "Friday" if ( ! $scan_interval );
	$scan_interval = &OneOf( $scan_interval, "Friday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Everyday", "Saturday" );
	RegSetValueEx( $key, "Scan Interval", 0,  REG_SZ, $scan_interval );
	
	$scan_time = 0 + 0 if ( ! $scan_time );
	$scan_time = 0 + $scan_time;
	$data = pack "L", $scan_time if ( $scan_time );
	RegSetValueEx( $key, "Scan Time", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $scan_system );
	RegSetValueEx( $key, "Scan System", 0,  REG_DWORD, $data );
	
	$data = "Extension";
	$data = "Content" if ( $scan_content );
	RegSetValueEx( $key, "Scan Method", 0,  REG_SZ, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_spyware );
	RegSetValueEx( $key, "Block Spyware", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $server_properties );
	RegSetValueEx( $key, "Server Properties", 0,  REG_DWORD, $data );

	# If the server properties are set, make sure that the manual properties are turned off
	if ( $server_properties )
		{	$data = "\x00\x00\x00\x00";
			RegSetValueEx( $key, "Manual Properties", 0,  REG_DWORD, $data );
			$manual_properties = undef;
		}

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_all_unknown );
	RegSetValueEx( $key, "Block All Unknown", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $report_events );
	RegSetValueEx( $key, "Report Events", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $remote_monitoring );
	RegSetValueEx( $key, "Remote Monitoring", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $only_protected_connections );
	RegSetValueEx( $key, "Only Protected Connections", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_shell );
	RegSetValueEx( $key, "Enable Shell", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_alerts );
	RegSetValueEx( $key, "Enable Alerts", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_manager );
	RegSetValueEx( $key, "Enable Manager", 0,  REG_DWORD, $data );

	$data = $novell_ldap_server;
	$data = "" if ( ! $novell_ldap_server );
	RegSetValueEx( $key, "Novell LDAP Server", 0,  REG_SZ, $data );

	$data = $novell_ldap_root;
	$data = "" if ( ! $novell_ldap_root );
	RegSetValueEx( $key, "Novell LDAP Base DN", 0,  REG_SZ, $data );

	$data = $uid_attribute;
	$data = "" if ( ! $uid_attribute );
	RegSetValueEx( $key, "Novell LDAP UID Attribute", 0,  REG_SZ, $data );

	$data = $group_attribute;
	$data = "" if ( ! $group_attribute );
	RegSetValueEx( $key, "Novell LDAP Group Attribute", 0,  REG_SZ, $data );

	$data = $protocol_version;
	$data = "" if ( ! $protocol_version );
	RegSetValueEx( $key, "Novell LDAP Protocol Version", 0,  REG_SZ, $data );


	RegSetValueEx( $key, "Software Version", 0,  REG_SZ, $version );
	
	
	# Make sure that we don't turn on File Integrity checking if the Last Scan Finished hasn't happened	
	$ok = RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, [] );
	my $last_scan_finished = undef;
	if ( ( $ok )  &&  ( defined $data ) )
		{	$last_scan_finished = $data;
		}


	# If no last scan finished, don't turn on file integrity
	$use_file_integrity = undef if ( ! $last_scan_finished );
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $use_file_integrity );
	RegSetValueEx( $key, "Use File Integrity", 0,  REG_DWORD, $data );
	

	RegCloseKey( $key );
		
	&SaveNetworkPermissions( $working_dir, $known_permissions, $unknown_permissions );
	
	return( 1 );
}



################################################################################
#
sub ScanLoadCategories()
#
#  Load the categories off disk
#
################################################################################
{
	# Set the defaults
	my $catnum = 0 + 63;
	$category_blocked{ $catnum } = 1;
	
	
	my $file = &ScanCategoryFile();
	&ScanNoReadOnly( $file );	
	
	if ( ! open FILE, "<$file" )
		{	&SecurityLogEvent( "Unable to open categories $file: $!\n" );
			return( undef );	
		}
	
		
	%category_blocked = ();
	
	my $counter = 0 + 0;	
	while (<FILE>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			my ( $category_name, $category_number, $allow, $time, $description ) = split /\t/, $line;
			
			# If the allow field isn't true or false, then I need to reload the whole table
			return( 0 ) if ( ! $allow );
			return( 0 ) if ( ( $allow ne "true" )  &&  ( $allow ne "false" ) );
			
			next if ( ! $category_number );
			
			$category_number = 0 + $category_number;
			
			$counter++;
			
			my $val = ( 0 + 0 );
			$val = ( 0 + 1 ) if ( $allow eq "false" );
			
			$category_number = 0 + $category_number;
			$category_blocked{ $category_number } = $val;
			
			$category{ $category_number } = $line;
		}
		
	close FILE;
	
	return( $counter );
}



################################################################################
#
sub ScanSaveCategories()
#
#  Save the categories to disk
#
################################################################################
{	my $file = &ScanCategoryFile();
	
	&ScanNoReadOnly( $file );
	
	if ( ! open FILE, ">$file" )
		{	&SecurityLogEvent( "Unable to open categories $file: $!\n" );
			return( undef );	
		}
		
	my @values = sort values %category;
	
	foreach ( @values )
		{	next if ( ! $_ );
			
			my $values = $_;
			
			print FILE "$values\n";
		}
		
	close FILE;
	
	return( 1 );
}



################################################################################
#
sub DownloadCategories( $$ )
#
#  Download the categories if they have changed.
#  Return undef if an error, True if data changed and the last updated date if the categories did change
#
################################################################################
{	my $ttc_server	= shift;
	my $last_update = shift;
	my $changed;
	
	my $done;
	my $counter;
	my $cleared;
	
	my $file = &ScanCategoryFile();
	$last_update = $start_date if ( ! -e $file );
	
	$cleared = 1 if ( $last_update eq $start_date );
	
	
	my $transaction_time = $last_update;

	
	# Loop through this
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	if ( $cleared )
				{	%category = ();
					%category_blocked = ();
				}
				
				
			my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=IpmContentCategory&LastUpdate=UPDATETIME&Page=1";
			
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;

			$| = 1;

			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download content categories from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;
			$content = undef;
			
			my ( $category_number, $category_name, $category_description, $allow );
			$counter = 0 + 0;
			
			# Flag it as done
			$done = 1;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				} 
			
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );
					
					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<CategoryName\>/ )
						{	$category_name = $line;
							$category_name =~ s/\<CategoryName\>//;
							$category_name =~ s/\<\/CategoryName\>//;
							$category_name =~ s/\t/ /g;
							$category_name = lc( $category_name );
						}
						
					if ( $line =~ m/\<CategoryDescription\>/ )
						{	$category_description = $line;
							$category_description =~ s/\<CategoryDescription\>//;
							$category_description =~ s/\<\/CategoryDescription\>//;
							$category_description =~ s/\t/ /g;
						}
						
					if ( $line =~ m/\<Allow\>/ )
						{	$allow = $line;
							$allow =~ s/\<Allow\>//;
							$allow =~ s/\<\/Allow\>//;
							$allow = lc( $allow ) if ( $allow );
							$allow =~ s/\t/ /g;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
							$transaction_time =~ s/\t/ /g;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	next if ( ( ! $category_number )  ||  ( ! $category_name )  ||  ( ! $allow )  ||  ( ! $transaction_time ) );
							$category_description = "<blank>" if ( ! $category_description );
							
							my $val = ( 0 + 0 );
							$val = ( 0 + 1 ) if ( $allow eq "false" );
							
							my $old_val;
							$old_val = $category_blocked{ $category_number } if ( defined $category_blocked{ $category_number } );
							
							# Did the category actually change?
							if ( ! defined $old_val )
								{	$counter++;
								}
							elsif ( $val ne $old_val )
								{	$counter++;
								}
								
							$category_blocked{ $category_number } = $val;
							
							my $values = "$category_name\t$category_number\t$allow\t$transaction_time\t$category_description";
							$category{ $category_number } = $values;
							
							$category_name			= undef;
							$category_number		= undef;
							$allow					= undef;
							$category_description	= undef;
						}
				}
			
		}	# end of ! $done loop
	
	
	if ( ( $counter )  ||  ( $cleared ) )
		{	my $ok = &ScanSaveCategories();	
			&SecurityLogEvent( "Saved the category changes\n" ) if ( $ok );
			$changed = 1;
		}
		
		
	&SecurityLogEvent( "Downloaded $counter new categories from $ttc_server\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "No changes to the categories\n" ) if ( ! $changed );

	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadVirusSignatures( $$$ )
#
#  Download the virus signatures if they have changed.
#  Return the last updated date if the signatures did change
#  Return undef if an error
#
################################################################################
{	my $ttc_server			= shift;
	my $last_update			= shift;
	my $categories_changed	= shift;
	my $changed;
	
	my $counter = 0 + 0;
	my $updated = 0 + 0;
	my $removed = 0 + 0;
	
	my $transaction_time = $last_update;
	
	
	# If the categories have changed I need to rewrite the virus file no matter what
	$changed = 1 if ( $categories_changed );
	
	
	my %virus_list;
	%virus_list = &ScanReadSignatures( undef );	
	my @virus_array = keys %virus_list;
			
	my $virus_count = 1 + $#virus_array;
			
	&SecurityLogEvent( "Loaded $virus_count virus signatures\n" ) if ( $virus_count );
	
	
	# If I couldn't read any virus signatures, reload everything		
	if ( ! $virus_count )
		{	&SecurityLogEvent( "Unable to load any virus signatures from disk\n" );
			&SecurityLogEvent( "Downloading complete virus signature file from $ttc_server\n" );
			$last_update = $start_date;
		}
	
	
	$| = 1;

	my $done;
	my $page = 0 + 0;
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=VirusSignatures&LastUpdate=UPDATETIME&Page=1";
	
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;

			$page++;
			my $pagestr = "Page=$page";
			$url =~ s/Page=1/$pagestr/;
			
			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download virus signatures from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;
			$content = undef;
			
			my ( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $test );
			
			my $chunk_counter = 0 + 0;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;			
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				} 
			
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );
					
					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					

					if ( $line =~ m/\<VirusName\>/ )
						{	$virus_name = $line;
							$virus_name =~ s/\<VirusName\>//;
							$virus_name =~ s/\<\/VirusName\>//;
							$virus_name = &UnUrlFormat( $virus_name );
							$virus_name = &CleanVirusName( $virus_name );
						}

					if ( $line =~ m/\<VirusType\>/ )
						{	$virus_type = $line;
							$virus_type =~ s/\<VirusType\>//;
							$virus_type =~ s/\<\/VirusType\>//;
						}
						
					if ( $line =~ m/\<AppSig\>/ )
						{	$appsig = $line;
							$appsig =~ s/\<AppSig\>//;
							$appsig =~ s/\<\/AppSig\>//;
						}
						
					if ( $line =~ m/\<SigStart\>/ )
						{	$sigstart = $line;
							$sigstart =~ s/\<SigStart\>//;
							$sigstart =~ s/\<\/SigStart\>//;
							$sigstart = 0 + $sigstart;
						}
						
					if ( $line =~ m/\<SigEnd\>/ )
						{	$sigend = $line;
							$sigend =~ s/\<SigEnd\>//;
							$sigend =~ s/\<\/SigEnd\>//;
							$sigend = 0 + $sigend;
						}
						
					if ( $line =~ m/\<Signature\>/ )
						{	$signature = $line;
							$signature =~ s/\<Signature\>//;
							$signature =~ s/\<\/Signature\>//;							
						}
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<Test\>/ )
						{	$test = $line;
							$test =~ s/\<Test\>//;
							$test =~ s/\<\/Test\>//;
							
							# This should be either "true" or "false"
							$test = lc( $test );
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	$chunk_counter++;

							next if ( ( ! $virus_name )  ||  ( ! $virus_type )  ||  ( ! $appsig )  ||  ( ! $sigend )  ||  ( ! $signature ) );

							# Clean up the signature
							chomp( $signature );
							$signature = lc( $signature );
							$signature =~ s/^\s//g;
							$signature =~ s/\s$//g;
			
							# make sure the delete is either 1 or 0
							my $delete = "0";
							$delete = "1" if ( ( $test )  &&  ( $test eq "true" ) );
											  
							# Is the signature a clean one, with no regular expressions?
							next if ( ! $signature );
							next if ( $signature =~ m/[^\da-f]/ );

		
							# Is this an error?  If so, remove it from the hash
							if ( $category_number == $error_category )
								{	if ( defined $virus_list{ $virus_name } )
										{	$changed = 1;
											$removed++;
											delete $virus_list{ $virus_name };
										}
								}
							else
								{	my $line = "$virus_name\t$virus_type\t$appsig\t$sigstart\t$sigend\t$signature\t$category_number\t$delete";

									if ( ! ( defined $virus_list{ $virus_name } ) )
										{	$changed = 1;
											$counter++;
										}
										
									# Did anything actually change?	
									elsif ( $line ne $virus_list{ $virus_name } )
										{	$changed = 1;
											$updated++; 
										}
										
									$virus_list{ $virus_name } = $line;
								}


							# Reset everything for the next record								
							$virus_name = undef;
							$virus_type = undef;
							$appsig		= undef;
							$sigstart	= undef;
							$sigend		= undef;
							$signature	= undef;
							$test		= undef;
						}
				}	# end of foreach @lines
				
			$done = 1 if ( $chunk_counter < 2500 );
		}	# End of not done	

	

	# Did anything change?
	if ( $changed )
		{	my ( $total, $msg ) = &ScanWriteSignatures( %virus_list );
			
			if ( $total )
				{	&SecurityLogEvent( "Currently have $total active virus signatures\n" );
				}
			else
				{	&SecurityLogEvent( "$msg\n" ) if ( $msg );
				}
		}	# end of anything changing
		
		
	&SecurityLogEvent( "Downloaded $counter new virus signatures\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Downloaded $updated updated virus signatures\n" ) if ( $updated > 0 );
	&SecurityLogEvent( "Removed $removed virus signatures\n" ) if ( $removed > 0);
	&SecurityLogEvent( "No changes to the virus signatures\n" ) if ( ! $changed );
		
	
	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadFileIntegrity( $$$ )
#
#  Download the fileintegrity permissions if they have changed.
#  Return the last updated date if the signatures did change
#  Return undef if an error
#
################################################################################
{	my $ttc_server			= shift;
	my $last_update			= shift;
	my $categories_changed	= shift;
	my $changed;
	
	my $counter = 0 + 0;
	my $removed = 0 + 0;
	my $cleared;
	
	
	my $transaction_time = $last_update;
	
	
	# If the categories have changed I need to reload everything
	$last_update = $start_date if ( $categories_changed );
	
	
	# Load the file integrity hash - if I get an error just keep on going as if I have a start date
	my ( $loaded_fileIDs, $msg ) = &LoadFileIntegrity( $opt_debug );
	
	
	my ( $total, $active ) = &FileIntegrityDatabaseSize();
	&SecurityLogEvent( "Currently have $total total and $active active file IDs\n" ) if ( ( $total )  &&  ( $opt_debug ) );
	
	
	if ( ! defined $loaded_fileIDs )
		{	&SecurityLogEvent( "Error loading the file integrity database: $msg\n" );
			$last_update = $start_date;
		}
	elsif ( $loaded_fileIDs < ( 0 + 100 ) )
		{	&SecurityLogEvent( "File integrity database is damaged, so reloading it now ...\n" );
			$last_update = $start_date;
		}
	else
		{	# Backup the file integrity hash before modifying it
			&BackupFileIntegrity();
		}
		
	
	# If I'm reloading everything, make sure I rewrite the file on disk
	$cleared = 1 if ( $last_update eq $start_date );
		
		
	$| = 1;

	my $done;
	my $page = 0 + 0;
	my $data_lines = 0 + 0;
	
	while ( ! $done )
		{	my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=ApplicationProcessesSA&LastUpdate=UPDATETIME&Page=1";

			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;
	
			$page++;
			my $pagestr = "Page=$page";
			$url =~ s/Page=1/$pagestr/;

# print "url = $url\n";
			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");

#print "here\n";

			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download file integrity from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;
					
					&RestoreFileIntegrity();
					
					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					
					&RestoreFileIntegrity();
					
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;
			$content = undef;
			
			my ( $hex_fileID, $category_number, $hex_permissions );
			
			my $chunk_counter = 0 + 0;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;		
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					&RestoreFileIntegrity();
					return( undef, undef );
				} 

			foreach( @lines )
				{	my $line = $_;
					chomp( $line );

					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					
					if ( $line =~ m/\<FileID\>/ )
						{	$hex_fileID = $line;
							$hex_fileID =~ s/\<FileID\>//;
							$hex_fileID =~ s/\<\/FileID\>//;
						}

					if ( $line =~ m/\<ProgramPermissions\>/ )
						{	$hex_permissions = $line;
							$hex_permissions =~ s/\<ProgramPermissions\>//;
							$hex_permissions =~ s/\<\/ProgramPermissions\>//;
						}
												
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	$chunk_counter++;

							next if ( ( ! $hex_fileID )  ||  ( ! $hex_permissions ) );

							my $file_id			= &HexToStr( $hex_fileID );			
							my $permissions		= &HexToStr( $hex_permissions );

							my $permissions_num = unpack "N", $permissions;
							$permissions_num	= 0 + $permissions_num;

							my $len = length( $file_id );
							
							# Is this an error?
							if ( $category_number == $error_category )
								{	$removed++ if ( &DeleteFileID( $file_id ) );
								}
							elsif ( $len == ( 0 + 28 ) )
								{	$counter++ if ( &AddFileID( $file_id, $category_number, $permissions_num, undef ) );
								}
							else
								{	&SecurityLogEvent( "Received invalid File ID = $hex_fileID\n" )
								}
										
							$hex_fileID			= undef;
							$hex_permissions	= undef;			
							$category_number	= undef;			
						}
				}	# end of foreach @lines

#print "chunk_counter = $chunk_counter\n";

			$done = 1 if ( $chunk_counter < 2500 );
		}	# End of not done	


	# Make sure that the file integrity file at least contains my programs
	my $changed_files = &UpdateSecurityAgentFileIntegrity();


	# Did anything change?
	$changed = undef;
	if ( &ChangedFileIntegrity() )
		{	my ( $ok, $msg ) = &SaveFileIntegrity( $working_dir, undef );
			
			
			if ( ! defined $ok )
				{	&SecurityLogEvent( "Error saving the file integrity data: $msg\n" );
					&SecurityLogEvent( "Restoring original file integrity database\n" );
					&RestoreFileIntegrity();
					
					return( undef, undef );
				}
			elsif ( $msg )
				{	&SecurityLogEvent( "Error saving the file integrity data: $msg\n" );
				}
				
				
			$changed = 1;	
			&SecurityLogEvent( "Saved the file integrity file database changes\n" );
			
			
			# If I cleared out the file integrity hash, then I need to purge unused entries on the next scan
			if ( $cleared )
				{	$last_purge = 0 + 0;
					
					# Save it back into the registry
					&SaveTTCUpdates();
				}	
		}	# end of anything changing
		
		
	&SecurityLogEvent( "Downloaded $counter new file integrity file IDs and permissions\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Removed $removed old file integrity file IDs and permissions\n" ) if ( $removed > 0 );
	&SecurityLogEvent( "No changes to the file integrity database\n" ) if ( ! $changed );
	
	if ( $opt_debug )
		{	( $total, $active ) = &FileIntegrityDatabaseSize();
			&SecurityLogEvent( "Now have $total total and $active active file IDs\n" );
		}
		
		
	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadRegistryControl( $$$ )
#
#  Download the registry control table
#  Return the last updated date if the table changed
#  Return undef if an error
#
################################################################################
{	my $ttc_server			= shift;
	my $last_update			= shift;
	my $categories_changed	= shift;
	my $changed;
	

	my $counter = 0 + 0;
	my $removed = 0 + 0;
	my $cleared;
	
	my $transaction_time = $last_update;
	
	
	# If the categories have changed I need to reload everything
	$last_update = $start_date if ( $categories_changed );
	
	
	my ( $ok, $msg ) = &LoadRegistryControl( $working_dir );
	if ( ! defined $ok )
		{	# &SecurityLogEvent( "Error loading the registry control database: $msg\n" );
			$last_update = $start_date;	# Reload everything
		}
	
	
	# If I'm reloading everything, clear the old data out
	if ( $last_update eq $start_date )	
		{	&ClearRegistryControl();
			$cleared = 1;
		}
		
		
	$| = 1;

	my $done;
	my $page = 0 + 0;
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=RegistryControl&LastUpdate=UPDATETIME&Page=1";
	
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;
	
			$page++;
			my $pagestr = "Page=$page";
			$url =~ s/Page=1/$pagestr/;

			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download registry control from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;
			$content = undef;
			
			my ( $key, $valName, $valType, $valData, $protected, $monitored, $set, $delete, $policy_name, $category_number )
			= ( undef, undef, undef, undef, undef, undef, undef, undef, "N/A", undef );
			
			$protected	= "false";
			$monitored	= "false";
			$set		= "false";
			$delete		= "false";

			my $chunk_counter = 0 + 0;

			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;		
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				} 
			
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );

					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					

					if ( $line =~ m/\<Key\>/ )
						{	$key = $line;
							$key =~ s/\<Key\>//;
							$key =~ s/\<\/Key\>//;
						}

					if ( $line =~ m/\<ValName\>/ )
						{	$valName = $line;
							$valName =~ s/\<ValName\>//;
							$valName =~ s/\<\/ValName\>//;
						}
						
					if ( $line =~ m/\<ValType\>/ )
						{	$valType = $line;
							$valType =~ s/\<ValType\>//;
							$valType =~ s/\<\/ValType\>//;
						}
						
					if ( $line =~ m/\<ValData\>/ )
						{	$valData = $line;
							$valData =~ s/\<ValData\>//;
							$valData =~ s/\<\/ValData\>//;
						}
						
					if ( $line =~ m/\<Protected\>/ )
						{	$protected = $line;
							$protected =~ s/\<Protected\>//;
							$protected =~ s/\<\/Protected\>//;
						}
						
					if ( $line =~ m/\<Monitored\>/ )
						{	$monitored = $line;
							$monitored =~ s/\<Monitored\>//;
							$monitored =~ s/\<\/Monitored\>//;
						}
						
					if ( $line =~ m/\<Set\>/ )
						{	$set = $line;
							$set =~ s/\<Set\>//;
							$set =~ s/\<\/Set\>//;							
						}
						
					if ( $line =~ m/\<Delete\>/ )
						{	$delete = $line;
							$delete =~ s/\<Delete\>//;
							$delete =~ s/\<\/Delete\>//;							
						}
						
					if ( $line =~ m/\<PolicyName\>/ )
						{	$policy_name = $line;
							$policy_name =~ s/\<PolicyName\>//;
							$policy_name =~ s/\<\/PolicyName\>//;							
						}
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	$chunk_counter++;

							next if ( ( ! $key )  ||  ( ! $category_number ) );
							
							my $pmode = "0";
							$pmode = "1" if ( $protected eq "true" );
							
							my $mmode = "0";
							$mmode = "1" if ( $monitored eq "true" );
							
							my $smode = "0";
							$smode = "1" if ( $set eq "true" );
							
							my $dmode = "0";
							$dmode = "1" if ( $delete eq "true" );
							
							# Make a mode of the 4 attributes together
							my $mode = $pmode . $mmode . $smode . $dmode;
							
							if ( $category_number == $error_category )
								{	$removed++ if ( &DeleteRegistryControl( $key, $mode ) );
								}
							else
								{	$counter++ if ( &AddRegistryControl( $key, $mode, $valName, $valType, $valData, $category_number, $policy_name ) );
								}
							
							$key				= undef;
							$mode				= undef;
							$valName			= undef;
							$valType			= undef;
							$valData			= undef;
							$policy_name		= "N/A";
							$category_number	= undef;
						}
				}	# end of foreach @lines
				
			$done = 1 if ( $chunk_counter < 2500 );
		}	# End of not done	


	# Did anything change?
	if ( ( $counter )  ||  ( $removed )  ||  ( $cleared ) )
		{	my ( $ok, $msg ) = &SaveRegistryControl( $working_dir );
			
			if ( ! defined $ok )
				{	&SecurityLogEvent( "Error saving registry control: $msg\n" );
					return( undef, undef );
				}
			
			$changed = 1;	
			&SecurityLogEvent( "Saved the registry control changes\n" );	
		}	# end of anything changing
		
		
	&SecurityLogEvent( "Downloaded $counter new registry controls\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Removed $removed old registry controls\n" ) if ( $removed > 0 );
	&SecurityLogEvent( "No changes to the registry control\n" ) if ( ! $changed );
		
	
	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadBannedProcesses( $$$ )
#
#  Download the banned processes if they have changed.
#  Return the last updated date if they did change
#
################################################################################
{	my $ttc_server			= shift;
	my $last_update			= shift;
	my $categories_changed	= shift;
	my $changed;
	
	my $done;
	my $counter = 0 + 0;
	my $cleared;
	my $removed = 0 + 0;
	my $added	= 0 + 0;
	
	
	my $transaction_time = $last_update;
	

	my %banned_process = &PolicyBannedProcessLoad();
	my @banned = keys %banned_process;
	
	$last_update = $start_date if ( ! $banned[ 0 ] );
	
	
	# Loop through this
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	# Am I reloading everything?
			if ( $last_update eq $start_date )
				{	%banned_process = ();
					$cleared = 1 if ( $banned[ 0 ] );
				}
				
				
			my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=BannedProcesses&LastUpdate=UPDATETIME&Page=1";
			
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;
									
			$| = 1;

			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download banned processes from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;
			$content = undef;
			
			my ( $process, $category_number );
			
			$counter = 0 + 0;
			
			# Flag it as done
			$done = 1;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;		
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				}
			
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );
					
					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					

					if ( $line =~ m/\<Process\>/ )
						{	$process = $line;
							$process =~ s/\<Process\>//;
							$process =~ s/\<\/Process\>//;
							
							$process = lc( $process );
						}
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	next if ( ! $process );
							next if ( ! $category_number );							
											 
							# Is this an error?
							if ( $category_number == $error_category )
								{	 if ( defined $banned_process{ $process } )
										{	delete $banned_process{ $process };
											$removed++;
											$changed = 1;
										}
								}
							# Am I added a new banned process?
							elsif ( ! defined $banned_process{ $process } )
								{	$banned_process{ $process } = $category_number;
									$added++;
									$changed = 1;
								}
							# Am I changing an existing banned process category? 	
							elsif ( $category_number ne $banned_process{ $process } )	
								{	$banned_process{ $process } = $category_number;
									$counter++;
									$changed = 1;
								}
								
							$process			= undef;	
							$category_number	= undef;	
						}
				}
	
			
			# Do I need to reload all the banned processes?
			# I do if the last transaction time is different that the last_update
			# and the last update isn't the start time
			if ( ( $transaction_time ne $last_update )  &&  ( $last_update ne $start_date ) )
				{	$done = undef;
					$last_update = $start_date;
					$cleared = 1;
				}
		}	# end of ! $done loop
	
	
	
	if ( $changed )
		{	my ( $ok, $msg ) = &PolicyBannedProcessSave( %banned_process );
			
			return( undef, undef ) if ( ! $ok );
						
			if ( $ok )			
				{	&SecurityLogEvent( "Saved the banned process changes\n" );
				}
			else
				{	&SecurityLogEvent( "Error saving banned process table: $msg\n" )
				}
		}
		
		
	&SecurityLogEvent( "Downloaded $added new banned processes\n" ) if ( $added > 0 );
	&SecurityLogEvent( "Downloaded $counter changed banned processes\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Downloaded $removed removed banned processes\n" ) if ( $removed > 0 );
	&SecurityLogEvent( "No changes to the banned processes\n" ) if ( ! $changed );
	
	
	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadDisinfectScripts( $ )
#
#  Download the disinfect scripts
#  Return the last updated date if they did change
#
################################################################################
{	my $ttc_server	= shift;
	
	my $last_update	= &GetUpdateTime( "Disinfect Update" );

	my $changed;
	
	my $done;
	my $counter = 0 + 0;
	my $cleared;
	my $removed = 0 + 0;
	my $added	= 0 + 0;
	
	
	my $transaction_time = $last_update;
		
	my %disinfect = &DisinfectLoadScripts();	# This is a hash of the disinfect scripts
	my @virus_names = sort keys %disinfect;
		
	$last_update = $start_date if ( $#virus_names < ( 0 + 0 ) );
	
	
	# Loop through this
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	# Am I reloading everything?
			if ( $last_update eq $start_date )
				{	%disinfect = ();
					$cleared = 1 if ( $#virus_names > ( 0 + 0 ) );
				}
				
				
			my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=DisinfectScripts&LastUpdate=UPDATETIME&Page=1";
			
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;
									
			$| = 1;

			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download disinfect scripts from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;

			$content = undef;
			
			my ( $virus_name, $description, $script, $category_number );
			
			$counter = 0 + 0;
			
			# Flag it as done
			$done = 1;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;		
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				}
			
			my $script_started;
			
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					
					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					next if ( ! $line );

					
					if ( $line =~ m/\<VirusName\>/ )
						{	$virus_name = $line;
							$virus_name =~ s/\<VirusName\>//;
							$virus_name =~ s/\<\/VirusName\>//;
						}
						
					if ( $line =~ m/\<Description\>/ )
						{	$description = $line;
							$description =~ s/\<Description\>//;
							$description =~ s/\<\/Description\>//;
						}
						
						
					# Scripts can be multi line	
					if ( $line =~ m/\<Script\>/ )
						{	$script = "$line\n";
							$script_started = 1;
							$script_started = undef if ( $script =~ m/\<\/Script\>/ );
							$script =~ s/\<Script\>//;
							$script =~ s/\<\/Script\>//;
							
						}
					elsif ( $line =~ m/\<\/Script\>/ )
						{	$script_started = undef;
						}
					elsif ( $script_started )
						{	$script .= "$line\n" if ( $script_started );
						}
						
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	next if ( ! $virus_name );
							next if ( ! $script );

							my $key = lc( $virus_name );
							# Is this an error?
							if ( $category_number == $error_category )
								{	 if ( defined $disinfect{ $key } )
										{	delete $disinfect{ $key };
											$removed++;
											$changed = 1;
										}
								}
							# Is it a completely new script?	
							elsif ( ! defined $disinfect{ $key } )
								{	$disinfect{ $key } = $script;
									$added++;
									$changed = 1;
								}
							# I must be changing an existing script	
							else	
								{	my $old_script = $disinfect{ $key };
									if ( $old_script ne $script )
										{	$disinfect{ $key } = $script;
											$counter++;
											$changed = 1;
										}
								}
								
							$virus_name			= undef;	
							$description		= undef;	
							$script				= undef;	
							$category_number	= undef;	
						}
				}
		}	# end of ! $done loop
	
	
	if ( $changed )
		{	my ( $ok, $msg ) = &DisinfectSaveScripts( %disinfect );
			
			if ( ! $ok )
				{	&SecurityLogEvent( "unable to save disinfect scripts: $msg\n" ) if ( $msg );
					return( undef, undef );
				}
				
			&SecurityLogEvent( "Saved the disinfect script changes\n" );
			&SetUpdateTime( "Disinfect Update", $transaction_time );
		}
		
		
	&SecurityLogEvent( "Downloaded $added new disinfect scripts\n" ) if ( $added > 0 );
	&SecurityLogEvent( "Downloaded $counter changed disinfect scripts\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Downloaded $removed removed disinfect scripts\n" ) if ( $removed > 0 );
	&SecurityLogEvent( "No changes to the disinfect scripts\n" ) if ( ! $changed );
	
	
	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadPolicy( $ )
#
#  Download the sub policy table
#  Return the last updated date if they did change
#
################################################################################
{	my $ttc_server	= shift;
	
	my $last_update	= &GetUpdateTime( "Policy Update" );

	my $changed;
	
	my $done;
	my $counter = 0 + 0;
	my $cleared;
	my $removed = 0 + 0;
	my $added	= 0 + 0;
	
	
	my $transaction_time = $last_update;
		
	my %policy = &PolicyLoad();
	my @policies = keys %policy;
	
	$last_update = $start_date if ( ! $policies[ 0 ] );
	
	
	# Loop through this
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	# Am I reloading everything?
			if ( $last_update eq $start_date )
				{	%policy = ();
					$cleared = 1 if ( $policies[ 0 ] );
				}
				
				
			my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=SubPolicy&LastUpdate=UPDATETIME&Page=1";
			
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;
									
			$| = 1;

			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download policy table from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;

			$content = undef;
			
			my ( $policy_name, $subpolicy_name, $category_number );
			
			$counter = 0 + 0;
			
			# Flag it as done
			$done = 1;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;		
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				}
				
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					
					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					next if ( ! $line );

					
					if ( $line =~ m/\<PolicyName\>/ )
						{	$policy_name = $line;
							$policy_name =~ s/\<PolicyName\>//;
							$policy_name =~ s/\<\/PolicyName\>//;
						}
						
					if ( $line =~ m/\<SubPolicyName\>/ )
						{	$subpolicy_name = $line;
							$subpolicy_name =~ s/\<SubPolicyName\>//;
							$subpolicy_name =~ s/\<\/SubPolicyName\>//;
						}
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	next if ( ! $policy_name );
							next if ( ! $subpolicy_name );
							
							
							my $key = $policy_name . "\t" . $subpolicy_name; 
							
							# Is this an error?
							if ( $category_number == $error_category )
								{	
									if ( defined $policy{ $key } )
										{	delete $policy{ $key };
											$removed++;
											$changed = 1;
										}
								}
							# Is it a completely new policy?	
							elsif ( ! defined $policy{ $key } )
								{	$policy{ $key } = $category_number;
									$added++;
									$changed = 1;
								}
							# I must be changing an existing policy
							else	
								{	my $old_category_number = $policy{ $key };
									if ( $old_category_number ne $category_number )
										{	$policy{ $key } = $category_number;
											$counter++;
											$changed = 1;
										}
								}
								
							$policy_name		= undef;	
							$subpolicy_name		= undef;	
							$category_number	= undef;	
						}
				}
		}	# end of ! $done loop
	
	
	if ( $changed )
		{	my ( $ok, $msg ) = &PolicySave( %policy );
			
			if ( $ok )			
				{	&SecurityLogEvent( "Saved the policy changes\n" );
			
					&SetUpdateTime( "Policy Update", $transaction_time );
				}
			else
				{	&SecurityLogEvent( "Error saving policy table: $msg\n" )
				}
		}
		
		
	&SecurityLogEvent( "Downloaded $added new policies\n" ) if ( $added > 0 );
	&SecurityLogEvent( "Downloaded $counter changed policies\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Downloaded $removed removed policies\n" ) if ( $removed > 0 );
	&SecurityLogEvent( "No changes to the policies\n" ) if ( ! $changed );
	
	
	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadPolicyDefinition( $ )
#
#  Download the policy definition table
#  Return the last updated date if they did change
#
################################################################################
{	my $ttc_server	= shift;
	
	my $last_update	= &GetUpdateTime( "Policy Definition Update" );

	my $changed;
	
	my $done;
	my $counter = 0 + 0;
	my $cleared;
	my $removed = 0 + 0;
	my $added	= 0 + 0;
	
	
	my $transaction_time = $last_update;
		
	my %policy_definition = &PolicyDefinitionLoad();
	my @policies = keys %policy_definition;
	
	$last_update = $start_date if ( ! $policies[ 0 ] );
	
	
	# Loop through this
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	# Am I reloading everything?
			if ( $last_update eq $start_date )
				{	%policy_definition = ();
					$cleared = 1 if ( $policies[ 0 ] );
				}
				
				
			my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=PolicyDefinitions&LastUpdate=UPDATETIME&Page=1";
			
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;
									
			$| = 1;

			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download policy definitions from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;

			$content = undef;
			
			my ( $id, $policy_name, $policy_type, $val_name, $val_type, $val_data, $category_number );
			
			$counter = 0 + 0;
			
			# Flag it as done
			$done = 1;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;		
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				}
				
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					
					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					next if ( ! $line );

					
					if ( $line =~ m/\<ID\>/ )
						{	$id = $line;
							$id =~ s/\<ID\>//;
							$id =~ s/\<\/ID\>//;
						}
						
					if ( $line =~ m/\<PolicyName\>/ )
						{	$policy_name = $line;
							$policy_name =~ s/\<PolicyName\>//;
							$policy_name =~ s/\<\/PolicyName\>//;
						}
						
					if ( $line =~ m/\<PolicyType\>/ )
						{	$policy_type = $line;
							$policy_type =~ s/\<PolicyType\>//;
							$policy_type =~ s/\<\/PolicyType\>//;
						}
						
					if ( $line =~ m/\<ValName\>/ )
						{	$val_name = $line;
							$val_name =~ s/\<ValName\>//;
							$val_name =~ s/\<\/ValName\>//;
						}
						
					if ( $line =~ m/\<ValType\>/ )
						{	$val_type = $line;
							$val_type =~ s/\<ValType\>//;
							$val_type =~ s/\<\/ValType\>//;
						}
						
					if ( $line =~ m/\<ValData\>/ )
						{	$val_data = $line;
							$val_data =~ s/\<ValData\>//;
							$val_data =~ s/\<\/ValData\>//;
						}
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	next if ( ! $id );
							next if ( ! $policy_name );
							next if ( ! $policy_type );
							next if ( ! $val_name );
							next if ( ! $val_type );
							next if ( ! $category_number );
							
							$val_data = "N/A" if ( ! $val_data );
							
							my $line = "$id\t$policy_name\t$policy_type\t$val_name\t$val_type\t$val_data\t$category_number";
							
							# Is this an error?
							if ( $category_number == $error_category )
								{	
									if ( defined $policy_definition{ $id } )
										{	delete $policy_definition{ $id };
											$removed++;
											$changed = 1;
										}
								}
							# Is it a completely new policy?	
							elsif ( ! defined $policy_definition{ $id } )
								{	$policy_definition{ $id } = $line;
									$added++;
									$changed = 1;
								}
							# I must be changing an existing policy
							else	
								{	my $old_line = $policy_definition{ $id };
									if ( $old_line ne $line )
										{	$policy_definition{ $id } = $line;
											$counter++;
											$changed = 1;
										}
								}
							
							$id					= undef;	
							$policy_name		= undef;	
							$policy_type		= undef;
							$val_name			= undef;
							$val_type			= undef;
							$val_data			= undef;
							$category_number	= undef;	
						}
				}
		}	# end of ! $done loop
	
	
	if ( $changed )
		{	my ( $ok, $msg ) = &PolicyDefinitionSave( %policy_definition );
			
			if ( $ok )			
				{	&SecurityLogEvent( "Saved the policy definition changes\n" );
			
					&SetUpdateTime( "Policy Definition Update", $transaction_time );
				}
			else
				{	&SecurityLogEvent( "Error saving policy definitions table: $msg\n" )
				}
		}
		
		
	&SecurityLogEvent( "Downloaded $added new policy definitions\n" ) if ( $added > 0 );
	&SecurityLogEvent( "Downloaded $counter changed policy definitions\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Downloaded $removed removed policy definitions\n" ) if ( $removed > 0 );
	&SecurityLogEvent( "No changes to the policy definitions\n" ) if ( ! $changed );
	

	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadRequiredSoftware( $ )
#
#  Download the required software table
#  Return the last updated date if they did change
#
################################################################################
{	my $ttc_server	= shift;
	
	my $last_update	= &GetUpdateTime( "Required Software Update" );

	my $changed;
	
	my $done;
	my $counter = 0 + 0;
	my $cleared;
	my $removed = 0 + 0;
	my $added	= 0 + 0;
	
	
	my $transaction_time = $last_update;
		
	my %required_software = &PolicyRequiredSoftwareLoad();
	my @required = keys %required_software;
	
	$last_update = $start_date if ( ! $required[ 0 ] );
	
	
	# Loop through this
	my $data_lines = 0 + 0;
	while ( ! $done )
		{	# Am I reloading everything?
			if ( $last_update eq $start_date )
				{	%required_software = ();
					$cleared = 1 if ( $required[ 0 ] );
				}
				
				
			my $url = "http:\/\/TTCSERVER\/contentupdate\/export\.aspx?Table=RequiredSoftwareVersions&LastUpdate=UPDATETIME&Page=1";
			
			my $backdate = &BackDate( $last_update );
			$url =~ s/TTCSERVER/$ttc_server/;
			$url =~ s/UPDATETIME/$backdate/;
									
			$| = 1;

			my $ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 10000000 );
			$ua->timeout( 120 );  #  Go ahead and wait for 120 seconds

			my $req = HTTP::Request->new( GET => $url );
			$req->referer("http://wizard.yellowbrick.oz");


			# Get the response
			my $response = $ua->request( $req );

			if ( $response->is_error() )
				{	my $error = $response->status_line;
					&SecurityLogEvent( "Unable to download required software versions from $ttc_server: ", $error, "\n" );
					my ( $retval, $str ) = split /\s/, $error, 2;

					return( undef, undef );  #  Return that an error happened
				}

			my $content = $response->content;
			
			if ( $content =~ m/Lightspeed Systems Content Filtering/ )
				{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
					return( undef, undef );
				} 

			
			my @lines = split /\n/, $content;

			$content = undef;
			
			# Set default values
			my  ( $app_name, $class_name, $file_name, $file_version, $file_size, $date_modified, $os_name, $os_version, $os_servicepack, $description, $required_url, $running, $reg_key, $reg_value, $category_number, $checksum ) =
				( undef, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A" );
			
			$counter = 0 + 0;
			
			# Flag it as done
			$done = 1;
			
			# Keep count of how many lines of data I've received
			$data_lines = $data_lines + $#lines;		
			if ( $data_lines < ( 0 + 0 ) )
				{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
					return( undef, undef );
				}
				
			foreach( @lines )
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					
					# Clean up the line
					$line =~ s/^\t.//;
					$line =~ s/^\s*//;
					$line =~ s/\s*$//;
					next if ( ! $line );

					
					if ( $line =~ m/\<AppName\>/ )
						{	$app_name = $line;
							$app_name =~ s/\<AppName\>//;
							$app_name =~ s/\<\/AppName\>//;
						}
						
					if ( $line =~ m/\<ClassName\>/ )
						{	$class_name = $line;
							$class_name =~ s/\<ClassName\>//;
							$class_name =~ s/\<\/ClassName\>//;
						}
						
					if ( $line =~ m/\<FileName\>/ )
						{	$file_name = $line;
							$file_name =~ s/\<FileName\>//;
							$file_name =~ s/\<\/FileName\>//;
						}
						
					if ( $line =~ m/\<FileVersion\>/ )
						{	$file_version = $line;
							$file_version =~ s/\<FileVersion\>//;
							$file_version =~ s/\<\/FileVersion\>//;
						}
						
					if ( $line =~ m/\<FileSize\>/ )
						{	$file_size = $line;
							$file_size =~ s/\<FileSize\>//;
							$file_size =~ s/\<\/FileSize\>//;
							$file_size = 0 + $file_size;
						}
						
					if ( $line =~ m/\<DateModified\>/ )
						{	$date_modified = $line;
							$date_modified =~ s/\<DateModified\>//;
							$date_modified =~ s/\<\/DateModified\>//;
						}
						
					if ( $line =~ m/\<OSName\>/ )
						{	$os_name = $line;
							$os_name =~ s/\<OSName\>//;
							$os_name =~ s/\<\/OSName\>//;
						}
						
					if ( $line =~ m/\<OSVersion\>/ )
						{	$os_version = $line;
							$os_version =~ s/\<OSVersion\>//;
							$os_version =~ s/\<\/OSVersion\>//;
						}
						
					if ( $line =~ m/\<OSServicePack\>/ )
						{	$os_servicepack = $line;
							$os_servicepack =~ s/\<OSServicePack\>//;
							$os_servicepack =~ s/\<\/OSServicePack\>//;
						}
						
					if ( $line =~ m/\<Description\>/ )
						{	$description = $line;
							$description =~ s/\<Description\>//;
							$description =~ s/\<\/Description\>//;
						}
						
					if ( $line =~ m/\<URL\>/ )
						{	$required_url = $line;
							$required_url =~ s/\<URL\>//;
							$required_url =~ s/\<\/URL\>//;
						}
						
					if ( $line =~ m/\<Running\>/ )
						{	$running = $line;
							$running =~ s/\<Running\>//;
							$running =~ s/\<\/Running\>//;
						}
						
					if ( $line =~ m/\<RegKey\>/ )
						{	$reg_key = $line;
							$reg_key =~ s/\<RegKey\>//;
							$reg_key =~ s/\<\/RegKey\>//;
						}
						
					if ( $line =~ m/\<RegValue\>/ )
						{	$reg_value = $line;
							$reg_value =~ s/\<RegValue\>//;
							$reg_value =~ s/\<\/RegValue\>//;
						}						
						
					if ( $line =~ m/\<CategoryNumber\>/ )
						{	$category_number = $line;
							$category_number =~ s/\<CategoryNumber\>//;
							$category_number =~ s/\<\/CategoryNumber\>//;
							$category_number = 0 + $category_number;
						}
						
					if ( $line =~ m/\<Checksum\>/ )
						{	$checksum = $line;
							$checksum =~ s/\<Checksum\>//;
							$checksum =~ s/\<\/Checksum\>//;
							$checksum = 0 + $checksum;
						}
						
					if ( $line =~ m/\<TransactionTime\>/ )
						{	$transaction_time = $line;
							$transaction_time =~ s/\<TransactionTime\>//;
							$transaction_time =~ s/\<\/TransactionTime\>//;
						}
						
					if ( $line =~ m/\<\/Table\>/ )
						{	next if ( ! $app_name );
														
							my $line = "$app_name\t$class_name\t$file_name\t$file_version\t$file_size\t$date_modified\t$os_name\t$os_version\t$os_servicepack\t$description\t$required_url\t$running\t$reg_key\t$reg_value\t$category_number\t$checksum";

							# Is this an error?
							if ( $category_number == $error_category )
								{	
									if ( defined $required_software{ $app_name } )
										{	delete $required_software{ $app_name };
											$removed++;
											$changed = 1;
										}
								}
							# Is it a completely new required software?	
							elsif ( ! defined $required_software{ $app_name } )
								{	$required_software{ $app_name } = $line;
									$added++;
									$changed = 1;
								}
							# I must be changing an existing required software
							else	
								{	my $old_line = $required_software{ $app_name };
									if ( $old_line ne $line )
										{	$required_software{ $app_name } = $line;
											$counter++;
											$changed = 1;
										}
								}
							
							( $app_name, $class_name, $file_name, $file_version, $file_size, $date_modified, $os_name, $os_version, $os_servicepack, $description, $required_url, $running, $reg_key, $reg_value, $category_number, $checksum ) =
							( undef, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A" );
						}
				}
		}	# end of ! $done loop
	
	
	if ( $changed )
		{	my ( $ok, $msg ) = &PolicyRequiredSoftwareSave( %required_software );
			
			if ( $ok )			
				{	&SecurityLogEvent( "Saved the required software changes\n" );
			
					&SetUpdateTime( "Required Software Update", $transaction_time );
				}
			else
				{	&SecurityLogEvent( "Error saving required software versions table: $msg\n" )
				}
		}
		
		
	&SecurityLogEvent( "Downloaded $added new required software\n" ) if ( $added > 0 );
	&SecurityLogEvent( "Downloaded $counter changed required software\n" ) if ( $counter > 0 );
	&SecurityLogEvent( "Downloaded $removed removed required software\n" ) if ( $removed > 0 );
	&SecurityLogEvent( "No changes to the required software\n" ) if ( ! $changed );
	

	return( $changed, $transaction_time );
}



################################################################################
#
sub DownloadActivePolicy( $ )
#
#  Download the policy and version that this PC should use
#  Put the values into the Policy Required registry
#  Return True if changed the required policy, undef if it stayed the same
#
################################################################################
{	my $ttc_server	= shift;
			
	my $url = "http:\/\/TTCSERVER\/Content\/PolicyLookup.aspx?UserName=IpmUSERNAME&DomainName=IpmDOMAINNAME&ComputerName=IpmCOMPUTERNAME&OU=IpmOUNAME&Groups=IpmGROUPS";
			
	$url =~ s/TTCSERVER/$ttc_server/;
	
	my ( $username, $computer_name, $computer_domain, $ou ) = &UpdateGetUserName();
	my @groups = &UpdateGetUserGroups( $username, $computer_name );
	
	# Put the groups list into a comma delimted string
	my $group_str;
	foreach ( @groups )
		{	next if ( ! $_ );
			if ( $group_str )
				{	$group_str = $group_str . "," . $_;
				}
			else
				{	$group_str = $_;
				}
		}
		
	&SecurityLogEvent( "Checking required policy\n" );
	&SecurityLogEvent( "\tUser     $username\n" )			if ( $username );
	&SecurityLogEvent( "\tComputer $computer_name\n" )		if ( $computer_name );
	&SecurityLogEvent( "\tDomain   $computer_domain\n" )	if ( $computer_domain );
	&SecurityLogEvent( "\tOU       $ou\n" )					if ( $ou );
	&SecurityLogEvent( "\tGroups   $group_str\n" )			if ( $group_str );
	
	
	$username			= &UrlFormat( $username )			if ( $username );
	$computer_name		= &UrlFormat( $computer_name )		if ( $computer_name );
	$computer_domain	= &UrlFormat( $computer_domain )	if ( $computer_domain );
	$ou					= &UrlFormat( $ou )					if ( $ou );
	$group_str			= &UrlFormat( $group_str )			if ( $group_str );
	
	
	# Fill in the fields in the URL	
	$url =~ s/IpmUSERNAME/$username/ if ( defined $username );
	$url =~ s/IpmUSERNAME// if ( ! defined $username );
	
	$url =~ s/IpmCOMPUTERNAME/$computer_name/ if ( defined $computer_name );
	$url =~ s/IpmCOMPUTERNAME// if ( ! defined $computer_name );
	
	$url =~ s/IpmDOMAINNAME/$computer_domain/ if ( defined $computer_domain );
	$url =~ s/IpmDOMAINNAME// if ( ! defined $computer_domain );

	$url =~ s/IpmOUNAME/$ou/ if ( defined $ou );
	$url =~ s/IpmOUNAME// if ( ! defined $ou );
	
	$url =~ s/IpmGROUPS/$group_str/ if ( defined $group_str );
	$url =~ s/IpmGROUPS// if ( ! defined $group_str );
	
	$| = 1;


	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 10000000 );
	$ua->timeout( 60 );  #  Go ahead and wait for 60 seconds

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			&SecurityLogEvent( "Unable to download the required policy from $ttc_server: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef, undef );
		} 

	my @lines = split /\n/, $content;


	$content = undef;
			
	# Keep count of how many lines of data I've received
	if ( $#lines < ( 0 + 0 ) )
		{	&SecurityLogEvent( "No response from $ttc_server - will try later\n" );	
			return( undef, undef );
		}
	
	
	# Read the policy name and version from the content
	my $policy_name;
	my $policy_version;
	
	
	foreach( @lines )
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			last if ( $line =~ m/Policy Not Found/ );
			
			( $policy_name, $policy_version ) = split /\:/, $line, 2;

		}	# end of foreach loop
		
		
	$policy_name = "default" if ( ! $policy_name );
	$policy_version = "n/a" if ( ! $policy_version );


	# Open the registry and get the current required policy name and version
	my $key;
	my $type;
	my $data;

	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );
	return( undef ) if ( ! $ok );
	
	my $old_policy_name;
	my $old_policy_version;
	$ok = RegQueryValueEx( $key, "Policy Required", [], $type, $data, [] );
	$old_policy_name = $data if ( ( $ok )  &&  ( $data ) );
	
	$ok = RegQueryValueEx( $key, "Policy Required Version", [], $type, $data, [] );
	$old_policy_version = $data if ( ( $ok )  &&  ( $data ) );
	
	if ( ( $old_policy_name )  &&
		 ( $old_policy_version )  &&
		 ( $policy_name eq $old_policy_name )  &&
		 ( $policy_version eq $old_policy_version ) )
		{	RegCloseKey( $key );
			&SecurityLogEvent( "Required policy: $policy_name, version: $policy_version\n" );
			return( undef );
		}
	
	
	# Put the required policy stuff back into the registry
	RegSetValueEx( $key, "Policy Required", 0,  REG_SZ, $policy_name );
	RegSetValueEx( $key, "Policy Required Version", 0,  REG_SZ, $policy_version );

	RegCloseKey( $key );
	
	&SecurityLogEvent( "New required policy: $policy_name, version: $policy_version\n" );

	return( 1 );
}



################################################################################
#
sub DownloadScanEngine( $$ )
#
#  Download the scan engine if it has changed.
#  Return the last updated date if the engine did change, and if I should run the 
#  rename command to rename the Update program
#
################################################################################
{	my $ttc_server	= shift;
	my $last_update = shift;
	my $renamer;	# Do I need to rename the Update program itself?
	
	
	# if I am a TTC Server, I need to download the scan engine directy from Lightspeed
	if ( &TTCServerMode() )
		{	$ttc_server = $default_ttc_server;
			&SecurityLogEvent( "This PC is a TTC Server itself so contacting Lightspeed Systems directly\n" );
			&SecurityLogEvent( "Checking with $ttc_server for a new security agent package\n" );
		}
	
	
	# Do I need to download the scan engine at all?
	my $url = "http:\/\/TTCSERVER\/content\/ScanLastUpdate.aspx";
	$url =~ s/TTCSERVER/$ttc_server/;
	
			
	$| = 1;

	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 100000 );
	$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			&SecurityLogEvent( "Unable to connect to $ttc_server to check for a new security agent package: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef, undef );  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&SecurityLogEvent( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef, undef );
		}

	my $current_date = $content;
	chomp( $current_date );


	# Has something changed?
	my $changed = undef;
	if ( $current_date ne $last_update )
		{	$changed = 1;
			
			# See if I can read the sapackage.txt file and get the version from that ...
			$url = "http:\/\/TTCSERVER\/content\/GetSAPackage.aspx";
			$url =~ s/TTCSERVER/$ttc_server/;

			$req = HTTP::Request->new( GET => $url );
			
			my $response = $ua->request( $req );
			my $content = $response->content;

			# Check to see if I can read a version in the response
			if ( ( ! $response->is_error() )  &&  ( $content =~ m/Version/ ) )
				{	my @lines = split /\n/, $content;
					
					my $package_version;
					
					# Pull out the package version
					foreach( @lines )
						{	next if ( ! $_ );
							my $line = $_;
							if ( $line =~ m/Version\:/ )
								{	my $junk;
									chomp( $line );
									( $junk, $package_version ) = split /Version\:/, $line, 2;
									$package_version =~ s/\s//g;
								}
						}
					
					# Compare the package version and make sure that it is newer	
					if ( ( $package_version )  &&  ( $package_version le $version ) )
						{	&SecurityLogEvent( "The SA package software is the same or older than your current software.\n" );
							&SecurityLogEvent( "Not installing download over your current software.\n" );
							&SecurityLogEvent( "Downloaded version: $package_version\n" );
							&SecurityLogEvent( "Current version: $version\n" );
							$changed = undef;  #  Nothing has changed, or it is older
						}
				}
		}


	# If it has changed, download the scan package and install it
	if ( $changed )	
		{	&SecurityLogEvent( "Downloading a newer version of the security agent from $ttc_server\n" );
			
			my $dir = &ScanWorkingDirectory();
			
			&CleanUpFiles( $dir, undef );
			
			$url = "http:\/\/TTCSERVER\/contentfiltering\/scan\.htm";
			$url =~ s/TTCSERVER/$ttc_server/;
			
			my $full_filename = $dir . "\\scan\.htm";
        	unlink( $full_filename );
 
 			$| = 1;

	        my $response = LWP::Simple::getstore( $url, $full_filename );

	        my $ok = is_success( $response );

            if ( !$ok )
                {   my $error = HTTP::Status::status_message($response);
		            &SecurityLogEvent( "Unable to download new security agent ($response): $error\n" );
	                return( undef, undef );  #  Return that an error happened
                }

			( $ok, $renamer ) = &InstallScanEngine( $dir, $full_filename );
			
			&CleanUpFiles( $dir, $renamer );
	
			return( undef, undef ) if ( ! $ok );
		}
	else
		{	&SecurityLogEvent( "No changes to the security agent\n" );
		}


	# If I got to here, then everything went ok
	return( $current_date, $renamer );
}



################################################################################
#
sub InstallScanEngine( $$ )
#
#  Given the scan.htm scan engine package, install it
#  Called by DownloadScanEngine and by command line
#  Return 2 parameter, the first is if I installed ok ( undef or True )
#  the second is if I need to run the rename program to install a new Update 
#  program ( undef or True )
#
################################################################################
{	my $dir				= shift;
	my $full_filename	= shift;	
	my $renamer;	# Do I need to rename the Update program itself?

	
	# Testing only
	return( 1, undef ) if ( $testing_only );


	my ( $err_msg, @files ) = &ScanUnzipFile( $dir, $full_filename );

	if ( $err_msg )
		{	&SecurityLogEvent( "Unable to unzip security agent package $full_filename: $err_msg\n" );
			return( undef, undef );					
		}
	
	if ( ! $files[ 0 ] )
		{	&SecurityLogEvent( "Unable to unzip security agent package $full_filename\n" );
			return( undef, undef );					
		}
	
	my $scan_error = &ScanLastUnzipError();
	if ( $scan_error )
		{	&SecurityLogEvent( "Error unzipping security agent package: $scan_error\n" );
			return( undef, undef );					
		}
	
	
	# Switch to the working directory
	my $cur_dir = getcwd();	
	chdir( $dir );

	if ( $opt_debug )
		{	&SecurityLogEvent( "Install working directory: $dir\n" );
			&SecurityLogEvent( "Install security agent package contents:\n" );
			foreach ( @files )
				{	next if ( ! $_ );
					my $file = $_;
					&SecurityLogEvent( "$file\n" );
				}
			&SecurityLogEvent( "\n" );	
		}
		
		
	# Make sure that the new programs are well know by the SecurityAgentService
	&UpdateSecurityAgentFileIntegrity( @files );
	
	
	# At this point I have all the files I unzipped into the @files array
	# Is there anything special I need to do with each one?
	
	# If there are any errors, put the error message in errors so I don't update the web server
	my $errors = undef;
	my @package_txt = ();
	
	
	# Look for the sapackage.txt file first so that is in the Security Log first ...
	my $package_version;
	
	foreach( @files )
		{	my $full_file = lc( $_ );
			
			# Is there a version package inside the scan package?
			if ( $full_file =~ m/sapackage\.txt/ )
				{	&SecurityLogEvent( "Security agent package information:\n\n" );
					
					if ( ! open PACKAGE, "<$full_file" )
						{	&SecurityLogEvent( "Unable to open $full_file: $!\n" );
						}
					else
						{	# Put each line of the package file into the security log
							while (<PACKAGE>)
								{	next if ( ! $_ );
									my $line = $_;
									
									&SecurityLogEvent( "$line" );
									
									push @package_txt, $line;
									
									if ( $line =~ m/Version\:/ )
										{	my $junk;
											chomp( $line );
											( $junk, $package_version ) = split /Version\:/, $line, 2;
											$package_version =~ s/\s//g;
										}
								}
								
							close PACKAGE;
						}
				}
		}
		
	
	# Check to make sure the package version is greater than my current version
	if ( ( ! $package_version )  ||  ( $package_version le $version ) )
		{	$package_version = "1.00.01" if ( ! $package_version );
			&SecurityLogEvent( "The downloaded software is the same or older than your current software.\n" );
			&SecurityLogEvent( "Not installing download over your current software.\n" );
			&SecurityLogEvent( "Downloaded version: $package_version\n" );
			&SecurityLogEvent( "Current version: $version\n" );
			return( 1, undef );
		}
		

	# Now go through the rest of the files, installing them one by one ...
	# If any errors at all, flag that in errors
	foreach( @files )
		{	my $full_file = lc( $_ );
			
			# Make sure I'm in the current directory
			chdir( $dir );


			# Did the scan engine actually change?
			if ( $full_file =~ m/scan\.new/ )
				{	next if ( ! &FileCompare( "scan.exe", "scan.new" ) );
					
					my $rename_ok = 1;							
					&ScanNoReadOnly( "scan.exe" );	
					if ( ! rename( "scan.exe", "scan.old" ) )
						{	$errors = "Could not rename scan.exe to scan.old: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					&ScanNoReadOnly( "scan.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "scan.new", "scan.exe" ) ) )
						{	$errors = "Could not rename scan.new to scan.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if scan.exe doesn't exist
							rename( "scan.old", "scan.exe" ) if ( ! ( -e "scan.exe" ) );
							next;
						}
						
					&SecurityLogEvent( "Updated scan engine\n" ) if ( $rename_ok );
				}
				
				
			# Did the sig design utility actually change?
			if ( $full_file =~ m/sigdesign\.new/ )
				{	next if ( ! &FileCompare( "sigdesign.exe", "sigdesign.new" ) );
					
					my $rename_ok = 1;							
					&ScanNoReadOnly( "sigdesign.exe" );	
					if ( ( -e "sigdesign.exe" )  &&  ( ! rename( "sigdesign.exe", "sigdesign.old" ) ) )
						{	$errors = "Could not rename sigdesign.exe to sigdesign.old: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					&ScanNoReadOnly( "sigdesign.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "sigdesign.new", "SigDesign.exe" ) ) )
						{	$errors = "Could not rename sigdesign.new to sigdesign.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if sigdesign.exe doesn't exist
							rename( "sigdesign.old", "sigdesign.exe" ) if ( ! ( -e "sigdesign.exe" ) );
							next;
						}
						
					&SecurityLogEvent( "Updated Signature Design utility\n" ) if ( $rename_ok );
				}
				
				
			# Did the virtest utility actually change?
			if ( $full_file =~ m/virtest\.new/ )
				{	next if ( ! &FileCompare( "virtest.exe", "virtest.new" ) );
					
					my $rename_ok = 1;							
					&ScanNoReadOnly( "virtest.exe" );	
					if ( ( -e "virtest.exe" )  &&  ( ! rename( "virtest.exe", "virtest.old" ) ) )
						{	$errors = "Could not rename virtest.exe to virtest.old: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					&ScanNoReadOnly( "virtest.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "virtest.new", "virtest.exe" ) ) )
						{	$errors = "Could not rename virtest.new to virtest.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if virtest.exe doesn't exist
							rename( "virtest.old", "virtest.exe" ) if ( ! ( -e "virtest.exe" ) );
							next;
						}
						
					&SecurityLogEvent( "Updated virus scanner active utility (virtest.exe)\n" ) if ( $rename_ok );
				}
				
				
			# Did the scan.dll actually change?
			elsif ( $full_file =~ m/scandll\.new/ )
				{	next if ( ! &FileCompare( "scan.dll", "scandll.new" ) );
					
					my $rename_ok = 1;															
					if ( -e "scan.dll" )
						{	&ScanNoReadOnly( "scan.dll" );	
							if ( ! rename( "scan.dll", "scandll.old" ) )
								{	$errors = "Could not rename scan.dll to scandll.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					&ScanNoReadOnly( "scandll.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "scandll.new", "scan.dll" ) ) )
						{	$errors = "Could not rename scandll.new to scan.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if scan.dll doesn't exist
							rename( "scandll.old", "scan.dll" ) if ( ! ( -e "scan.dll" ) );
							next;
						}
						
					&SecurityLogEvent( "Updated scan.dll\n" ) if ( $rename_ok );
				}

				
			# Did the msvcr71.dll actually change?
			elsif ( $full_file =~ m/msvcr71\.new/ )
				{	next if ( ! &FileCompare( "msvcr71.dll", "msvcr71.new" ) );
					
					my $rename_ok = 1;															
					if ( -e "msvcr71.dll" )
						{	&ScanNoReadOnly( "msvcr71.dll" );	
							if ( ! rename( "msvcr71.dll", "msvcr71.old" ) )
								{	$errors = "Could not rename msvcr71.dll to msvcr71.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					&ScanNoReadOnly( "msvcr71.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "msvcr71.new", "msvcr71.dll" ) ) )
						{	$errors = "Could not rename msvcr71.new to msvcr71.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if msvcr71.dll doesn't exist
							rename( "msvcr71.old", "msvcr71.dll" ) if ( ! ( -e "msvcr71.dll" ) );
							next;
						}
						
					&SecurityLogEvent( "Updated msvcr71.dll\n" ) if ( $rename_ok );
				}

				
			# Did the service files actually change?
			elsif ( $full_file =~ m/securityagentnew\.exe/ )
				{	next if ( ! &FileCompare( "SecurityAgent.exe", "SecurityAgentNew.exe" ) );

					system( "net stop \"Security Agent Service\"" );

					my $rename_ok = 1;
					
					if ( -e "SecurityAgent.exe" )
						{	&ScanNoReadOnly( "SecurityAgent.exe" );	
							if ( ! rename( "SecurityAgent.exe", "SecurityAgent.old" ) )
								{	$errors = "Could not SecurityAgent.exe to SecurityAgent.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}


					&ScanNoReadOnly( "SecurityAgentNew.exe" );	
					if ( ( $rename_ok )  &&  ( ! rename( "SecurityAgentNew.exe", "SecurityAgent.exe" ) ) )
						{	$errors = "Could not rename SecurityAgentNew.exe to SecurityAgent.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename the old one back if it doesn't exist
							rename( "SecurityAgent.old", "SecurityAgent.exe" ) if ( ! ( -e "SecurityAgent.exe" ) );
							
							# At this point I havn't changed anything, so just restart the service
							system( "net start \"Security Agent Service\"" );
							next;
						}
						

					if ( $rename_ok )
						{	system( "SecurityAgent.exe -i -w" );
							&SecurityLogEvent( "Updated Security Agent service and device driver\n" );
						}
						
						
					system( "net start \"Security Agent Service\"" );
				}
				
				
			# Did the update program actually change?
			elsif ( $full_file =~ m/update\.new/ )
				{	next if ( ! &FileCompare( "update\.exe", "update\.new" ) );
						
					&SecurityLogEvent( "Received new Update utility\n" );
	 				$renamer = 1;	# Because I got a new update utility, and need to call the renamer program to switch the name around
				}
				
				
			# Did the securityagentshellext.dll change?
			elsif ( $full_file =~ m/securityagentshellextnew\.dll/ )
				{	next if ( ! &FileCompare( "SecurityAgentShellExt.dll", "SecurityAgentShellExtNew.dll" ) );
						
					&SecurityLogEvent( "Received new Security Agent shell extension\n" );
					
					# If the old shell extension currently exists, rename it
					if ( -e "SecurityAgentShellExt.dll" )
						{	&ScanNoReadOnly( "SecurityAgentShellExt.dll" );	
							
							my $moved_ok = Win32API::File::MoveFile( "SecurityAgentShellExt.dll", "SecurityAgentShellExt.old" );
			
							if ( ! $moved_ok )
								{	$errors = "Could not move file SecurityAgentShellExt.dll to SecurityAgentShellExt.old: $!\n";
									&SecurityLogEvent( $errors );
								}
						}
						
					my $rename_ok = 1;
					
					&ScanNoReadOnly( "SecurityAgentShellExtNew.dll" );	
					if ( ! rename( "SecurityAgentShellExtNew.dll", "SecurityAgentShellExt.dll" ) )
						{	$errors = "Could not rename SecurityAgentShellExtNew.dll to SecurityAgentShellExt.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					
					# If I did everything OK, and the shell extension should be enabled, then enable it
					if ( ( $rename_ok )  &&  ( $enable_shell ) )
						{	system "regsvr32 \/s securityagentshellext.dll";
							&SecurityLogEvent( "Installed new Security Agent shell extension ok\n" );
						}
				}
				
				
			# Did the Security Agent Manager actually change?
			elsif ( $full_file =~ m/securityagentmanager.new/ )
				{	next if ( ! &FileCompare( "SecurityAgentManager.exe", "SecurityAgentManager.new" ) );
					
					my $running = &ProcessRunningName( "SecurityAgentManager" );
					
					# Signal the manager to die
					&KillManager();

					my $killed = &ProcessKillName( "SecurityAgentManager" );	
					&SecurityLogEvent( "Killed the old Security Agent Manager process\n" ) if ( $killed );

					my $rename_ok = 1;
					
					# If the security agent manager currently exists, rename it
					if ( -e "SecurityAgentManager.exe" )
						{	&ScanNoReadOnly( "SecurityAgentManager.exe" );	
							
							if ( ! rename( "SecurityAgentManager.exe", "SecurityAgentManager.old" ) )
								{	$errors = "Could not rename SecurityAgentManager.exe to SecurityAgentManager.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
						
					&ScanNoReadOnly( "SecurityAgentManager.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "SecurityAgentManager.new", "SecurityAgentManager.exe" ) ) )
						{	$errors = "Could not rename SecurityAgentManager.new to SecurityAgentManager.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if securityagentmanager doesn't exist
							rename( "SecurityAgentManager.old", "SecurityAgentManager.exe" ) if ( ! ( -e "SecurityAgentManager.exe" ) );
						}
					
					
					# Now try to get the new SecurityAgentManager running ...
					if ( ( $running )  &&  ( $rename_ok ) )
						{	&SecurityLogEvent( "Starting the Security Agent Manager\n" );
							my $processObj;
							if ( ! Win32::Process::Create( $processObj, "SecurityAgentManager.exe", "", 0, NORMAL_PRIORITY_CLASS, "." ) )
								{	my $str = Win32::FormatMessage( Win32::GetLastError() );
									$errors = "Error running the Security Agent Manager: $str\n";
									&SecurityLogEvent( $errors );
								}	
						}
						
					&SecurityLogEvent( "Updated Security Agent Manager\n" ) if ( $rename_ok );
				}
		}  # end of foreach @files
		
		
	# Do I need to copy the scan engine package to the web server?	
	my $ttc_server_mode = &TTCServerMode();
	
	if ( ( ! $errors )  &&  ( $ttc_server_mode ) )
		{	my $software_dir = &SoftwareDirectory();
			my $new_filename;
			
			$new_filename = $software_dir . "\\Website\\Content\\scan.htm";
			&ScanNoReadOnly( $new_filename );
			
			if ( copy( "scan.htm", $new_filename ) )
				{	&SecurityLogEvent( "Replaced the security agent package $new_filename\n" );
				}
			else
				{	&SecurityLogEvent( "Unable to copy the security agent package to $new_filename\n" );
				}
			
			$new_filename = $software_dir . "\\Website\\Content\\sapackage.txt";
			&ScanNoReadOnly( $new_filename );
			
			if ( copy( "sapackage.txt", $new_filename ) )
				{	&SecurityLogEvent( "Replaced $new_filename\n" );
				}
			else
				{	&SecurityLogEvent( "Unable to copy $new_filename\n" );
				}
		}
		
		
	# Switch back to the original directory
	chdir( $cur_dir );
					
	# Save the sapackage.txt into the registry
	&SetPackageVersion( $errors, @package_txt );

	
	&SecurityLogEvent( "Finished installing the new version of the security agent\n" );
	&SecurityLogEvent( "Not all parts of the security agent were installed ok\n" ) if ( $errors );

	return( 1, $renamer );
}



################################################################################
#
sub SetPackageVersion( $@ )
#
#  Put the package version text into the registry
#  The first argument is the last error that happened
#
################################################################################
{	my $errors = shift;
	
	my @package_txt;
	
	while ( my $line = shift )
		{	push @package_txt, $line;
		}
	
	push @package_txt, "No package version information\n" if ( ! $package_txt[ 0 ] );
	
	
	if ( $errors )
		{	push @package_txt, "Last update install error: $errors\n";
		}
	else
		{	push @package_txt, "No errors installing the update package\n";
		}
	
	
	my $multi_sz;
	my $key;
	my $type;
	my $data;
	
	
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );
	foreach ( @package_txt )
		{	next if ( ! $_ );
			chomp( $_ );
			$multi_sz = $multi_sz . $_ . "\x00" if ( $multi_sz );
			$multi_sz = $_ . "\x00" if ( ! $multi_sz );
		}
	
	
	# Tack on an extra x00 on the end	
	$multi_sz = $multi_sz . "\x00" if ( $multi_sz );

	# If an empty list, st multi_sz to an empty string
	$multi_sz = "" if ( ! $multi_sz );
	

	# Put the cleaned up list back into the registry
	RegSetValueEx( $key, "Package Version", 0,  REG_MULTI_SZ, $multi_sz );

	return( 1 );
}



################################################################################
#
sub UpdateSecurityAgentFileIntegrity()
#
#  Given a list of files, update the file integrity file so that all of the 
#  SecurityAgent files are known programs
#
################################################################################
{
	my @file_list;
	
	while ( my $file = shift )
		{	next if ( ! $file );
			push @file_list, $file;
		}
	
	
	# Add my normal programs in as well
	push @file_list, "$working_dir\\scan.exe";
	push @file_list, "$working_dir\\sigdesign.exe";
	push @file_list, "$working_dir\\virtest.exe";
	push @file_list, "$working_dir\\scan.dll";
	push @file_list, "$working_dir\\msvcr71.dll";
	push @file_list, "$working_dir\\securityagent.exe";
	push @file_list, "$working_dir\\securityagentmanager.exe";
	push @file_list, "$working_dir\\update.exe";
	push @file_list, "$working_dir\\updateext.exe";
	push @file_list, "$working_dir\\securityagentshellext.dll";
	
	my $system_dir = &ScanSystemDirectory();
	push @file_list, "$system_dir\\IpmSecurityAgent.sys";
	
	
	# Load the file integrity hash so that I can add the new programs to it
	# If I had an error, reload everything from the ttc server
	my ( $ok, $msg ) = &LoadFileIntegrity( $opt_debug );
	
	if ( ! defined $ok )
		{	&SecurityLogEvent( "Error loading the file integrity database: $msg\n" );
			$integrity_update = $start_date;
		}
		
	my $changed_count = 0 + 0;
	foreach ( @file_list )
		{	my $file = $_;
			next if ( ! $file );
			next if ( ! -e $file );
			
			$changed_count++ if ( &AddFileIntegrity( $file, 1 ) );
		}


	# If nothing changed, just return
	return( undef ) if ( ! $changed_count );
	
		
	# Save it back down
	( $ok, $msg ) = &SaveFileIntegrity( $working_dir, undef );
			
	if ( ! defined $ok )
		{	&SecurityLogEvent( "Error saving the file integrity database: $msg\n" );
			return( undef );
		}
	

	# Let the service know that something has changed
	&SignalService();
			
			
	return( 1 );	
}



################################################################################
#
sub CleanUpFiles( $$ )
#
#  Clean up all the files created when installing a new scan.htm
#
################################################################################
{	my $dir		= shift;
	my $renamer = shift;  # Don't delete the new update program if set
		
	my $cur_dir = getcwd();
	
	chdir( $dir );
	
	&ScanNoReadOnly( "scan.htm" );
	&ScanNoReadOnly( "scan.old" );
	&ScanNoReadOnly( "scan.new" );
	
	&ScanNoReadOnly( "securityagent.old" );
	&ScanNoReadOnly( "securityagentnew.exe" );
	
	&ScanNoReadOnly( "securityagentmanager.old" );
	&ScanNoReadOnly( "securityagentmanager.new" );
	
	&ScanNoReadOnly( "securityagentshellext.old" );
	&ScanNoReadOnly( "securityagentshellextnew.dll" );
	
	&ScanNoReadOnly( "update.new" );
	&ScanNoReadOnly( "update.old" );
	
	&ScanNoReadOnly( "scandll.new" );
	&ScanNoReadOnly( "scandll.old" );
	
	&ScanNoReadOnly( "SigDesign.new" );
	&ScanNoReadOnly( "SigDesign.old" );

	&ScanNoReadOnly( "virtest.new" );
	&ScanNoReadOnly( "virtest.old" );

	&ScanNoReadOnly( "msvcr71.new" );
	&ScanNoReadOnly( "msvcr71.old" );

	
	unlink "scan.htm";
	unlink "scan.old";
	unlink "scan.new";
	
	unlink "securityagent.old";
	unlink "securityagentnew.exe";
	
	unlink "securityagentmanager.new";
	unlink "securityagentmanager.old";
	
	unlink "securityagentshellextnew.dll";
	unlink "securityagentshellext.old";
	
	unlink "update.new" if ( ! $renamer );
	unlink "update.old";
			
	unlink "scandll.new";
	unlink "scandll.old";
	
	unlink "SigDesign.new";
	unlink "SigDesign.old";
	
	unlink "virtest.new";
	unlink "virtest.old";
	
	unlink "msvcr71.new";
	unlink "msvcr71.old";
	
	chdir( $cur_dir );
	
	
	return( undef );
}



################################################################################
#
sub FileCompare( $$ )
#
#  Compare 2 files.  If the sizes are different, return TRUE
#
################################################################################
{	my $file1 = shift;
	my $file2 = shift;
	
	use File::Compare 'cmp';

	# Do the files exist?
	return( 1 ) if ( !-e $file1 );
	return( 1 ) if ( !-e $file2 );
	
	# Are the file sizes different?	
	my $size1 = -s $file1;
	my $size2 = -s $file2;

	return( 1 ) if ( $size1 ne $size2 );
	
	return( 1 ) if cmp( $file1, $file2 );
	
	return( undef );
}



################################################################################
#
sub RunScanEngine( $$$ )
#
#  Run the scan engine if it is time
#  Return the current time if I did run it
#
################################################################################
{	my $last_scan_started	= shift;	# The last time I scanned - in system time (secs)
	my $last_purge_started	= shift;	# The last time I purged the file integrity file
	my $scan_now			= shift;	# If true, then scan now no matter what the time
	
	
	# Check to see if there is another copy of scan already running ...
	if ( &IsScanRunning() )
		{	&SecurityLogEvent( "The scan utility is already running\n" );
			return( undef, $last_purge_started );
		}
		
	
	$last_scan_started  = 0 if ( ! $last_scan_started );
	$last_scan_started  = 0 + $last_scan_started;
	
	$last_purge_started = 0 if ( ! $last_purge_started );
	$last_purge_started = 0 + $last_purge_started;


	# Get the last scan time I finished - this is set by the scan program
	my $key;
	my $data;
	my $type;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );

	my $last_scan_finished = 0 + 0;
	$ok = RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, [] ) if ( $ok );
	
	$last_scan_finished = $data if ( ( $ok )  &&  ( $data ) );
	$last_scan_finished = 0 + $last_scan_finished;
	
	
	# Get the registry value that set to scan the system or not - this might not exist
	my $scan_system = 1;
	$ok = RegQueryValueEx( $key, "Scan System", [], $type, $data, [] );
	
	$scan_system = undef if ( ( $ok )  &&  ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
	
	RegCloseKey( $key );
		

	# At this point I need to make a decision about if I should scan now, and
	# what scan option to use ...
	
	# Am I supposed to do system scans at all?
	# Quit if I'm not doing an initial scan, and I'm not being forced to scan
	return( undef, $last_purge_started ) if ( ( ! $scan_system )  &&  ( ! $scan_now ) );
	
	
	# If the last scan finished is later than the last scan + 1 hour, use that instead
	my $last_scan_1_hours = 0 + 0;
	$last_scan_1_hours = $last_scan_finished - ( 60 * 60 ) if ( $last_scan_finished );
	$last_scan_started = $last_scan_1_hours if ( $last_scan_1_hours > $last_scan_started );
	
	my $current_time = time();
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $current_time );
	$wday = 0 + $wday;
	
	
	# How many seconds has it been since I last scanned?
	my $diff = $current_time - $last_scan_started;
	
	# How many hours has it been?
	my $diff_hours = $diff / ( 60 * 60 );
	
	# If it is less than 23 hours later - bail out here
	return( undef, $last_purge_started ) if ( ( $diff_hours < ( 0 + 23 ) )  &&  ( ! $scan_now ) );
	

	# If it is not yet the right time of day to scan, bail out here
	my $current_hour	= 0 + $hour;
	my $scan_hour		= 0 + $scan_time;

	return( undef, $last_purge_started ) if ( ( $current_hour < $scan_hour )  &&  ( ! $scan_now ) );

	
	# Check to see if it is the right week day to scan
	if ( $scan_interval eq "Everyday" )
		{	$scan_now = 1;
		}
	elsif( ! $scan_now )
		{	$scan_now = 1 if ( ( $scan_interval eq "Sunday" )		&&  ( $wday == 0 ) );
			$scan_now = 1 if ( ( $scan_interval eq "Monday" )		&&  ( $wday == 1 ) );
			$scan_now = 1 if ( ( $scan_interval eq "Tuesday" )		&&  ( $wday == 2 ) );
			$scan_now = 1 if ( ( $scan_interval eq "Wednesday" )	&&  ( $wday == 3 ) );
			$scan_now = 1 if ( ( $scan_interval eq "Thursday" )		&&  ( $wday == 4 ) );
			$scan_now = 1 if ( ( $scan_interval eq "Friday" )		&&  ( $wday == 5 ) );
			$scan_now = 1 if ( ( $scan_interval eq "Saturday" )		&&  ( $wday == 6 ) );
		}
		
		
	# Has it gone longer than 8 days?  I must have missed a day completely, or it's the initial scan
	$scan_now = 1 if ( $diff_hours > ( 0 + 192 ) );
					  
					  
	# Is it time to scan?
	return( undef, $last_purge_started ) if ( ! $scan_now );
	
	
	# Ok - at this point I've decided to scan.  What options should I use?	
		
	my $dir = &ScanWorkingDirectory();

	my $full_filename = $dir . "\\scan.exe";
	
	
	# Purge the file integrity file once a year after first purging it
	my $max_purge_time = 365 * 24 * 60 * 60;
	my $purge_diff = $current_time - $last_purge_started;
	
	
	# Build up the command line argument to the scan utility
	my $cmd = "scan -a -e";	# Scan all the local fixed drives
	
	
	# Should I purge the file integrity file now?
	$cmd = "scan -a -e -p" if ( $purge_diff > $max_purge_time );
		
		
	# If I've never run before, add the unknown files found as locally added,
	# and mark unused entries in the file integrity database
	$cmd = "scan -a -e -p -u" if ( ! $last_scan_finished );
	
	$cmd = $cmd . " -k" if ( $block_spyware );
	
	$last_purge_started = $current_time if ( $cmd =~ m /\-p/ );	
	
		
	my $outgoing_process;	
	$ok = Win32::Process::Create( $outgoing_process, $full_filename, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	if ( ! $ok )
			{	my $str = Win32::FormatMessage( Win32::GetLastError() );
				&SecurityLogEvent( "Unable to create outgoing process $full_filename: $str\n" );
			}	
		else
			{	&SecurityLogEvent( "Started scanning all the local drives ...\n" );
			}
			
	
	return( $current_time, $last_purge_started );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $dir = &ScanWorkingDirectory();

	$errors_filename = "$dir\\UpdateErrors\.log";

	my $MYLOG;
	open( $MYLOG, ">$errors_filename" ) or print( "Unable to open $errors_filename: $!\n" );
   
	&CarpOut( $MYLOG );
}



################################################################################
#
sub RenameUpdate( $ )
#
#  There is a new update program called Update.new
#  Rename the old update program to update.old
#  rename the new update program to update.new
#  Close the security log if I'm not going to return
#
################################################################################
{	my $dir = shift;
	
	
	# Switch to the given directory
	my $ok = chdir( $dir );
	if ( ! $ok )
		{	&SecurityLogEvent( "Error: unable to switch to the directory $dir: $!\n" );
			return;	
		}
	
	
	# Make sure everything is not readonly
	&ScanNoReadOnly( "Update\.new" );
	&ScanNoReadOnly( "Update\.exe" );
	&ScanNoReadOnly( "Update\.old" );

	
	# Make sure the UpdateExt program is there
	if ( ! -e "UpdateExt\.exe" )
		{	&SecurityLogEvent( "Error: the UpdateExt\.exe program is not in the current directory $dir\n" );
			return;	
		}
	
	
	# Make sure the new version is there
	if ( ! -e "Update\.new" )
		{	&SecurityLogEvent( "Error: the new Update\.new program is not in the current directory $dir\n" );
			return;	
		}
	
	
	# Make sure the old version is there
	if ( ! -e "Update\.exe" )
		{	&SecurityLogEvent( "Error: the old Update\.exe program is not in the current directory $dir\n" );
			return;	
		}
	
	
	# Make sure the 2 files are different
	if ( ! &FileCompare( "Update\.exe", "Update\.new" ) )
		{	&SecurityLogEvent( "The new Update\.exe program is the same as the old program, so not updating it.\n" );
		
			unlink( "Update\.old" );
			rename( "Update\.new", "Update\.old" );
			exit( 0 );
		}
		
		
	# Make sure the older version isn't still hanging around
	&ScanNoReadOnly( "Update.old" );
	
	if ( -e "Update.old" )
		{
			system "del Update.old";
			unlink "Update.old";
		}
		
	&SecurityLogEvent( "Installed new Update utility ok\n" );

	
	# Close the security log before running the UpdateExt program
	my $time = localtime( time() );	
	&SecurityLogEvent( "Closed Security Agent Log: $time\n" );
	&SecurityCloseLogFile();
	
	
	# Run the UpdateExt program with the right arguments  
	exec "UpdateExt.exe Update.exe Update.old Update.new Update.exe";
}



################################################################################
# 
sub BackDate( $ )
#
#  Given a SQL date, back it up an hour to make sure we don't miss any changes
#
################################################################################
{	my $date = shift;

	return( $start_date ) if ( ! $date );
	return( $start_date ) if ( $date eq $start_date );
	
	my $backdate = $date;
	
	my ( $day, $time ) = split /T/, $date, 2;
	
	return( $date ) if ( ! $time );
	
	my ( $hour, $remainder ) = split /:/, $time, 2;
	
	# Cut the fractions of a second off of the remainder
	my $junk;

	( $remainder, $junk ) = split /\./, $remainder, 2;
	
	my $last_hour = $hour - 1;
	
	my $last_hour_str = sprintf "%02d", $last_hour;
	
	# Did I subract past midnight?
	if ( $last_hour > -1 )
		{	$backdate = $day . "T" . "$last_hour_str" . ":" . $remainder;
		}
	else	# If if subtracted past midnight, just set to midnight
		{	$backdate = $day . "T" . "00:00:00";
		}
		
	return( $backdate );
}



################################################################################
# 
sub UpdateXPSP2()
#
#  Make sure that Win XP Service Pack 2 has the right registry settings
#  for the security agent exe to be accessed remotely
#
################################################################################
{	my $key;

use Win32::OLE;

use constant {
	NET_FW_PROFILE_DOMAIN	=>  0,
	NET_FW_PROFILE_STANDARD =>  1,
	NET_FW_SCOPE_ALL		=>  0,
	NET_FW_IP_VERSION_ANY	=>  2,
	};


	# First check to see if the port is enabled
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\GloballyOpenPorts\\List", 0, KEY_ALL_ACCESS, $key );

	if ( ! $ok )
		{	&SecurityLogEvent( "Unable to check Microsoft firewall port settings\n" );
			return( undef );
		}
		
	# This is the value name and value data to turn on the port for us to use
	my $name	= "1305:UDP";
	my $value	= "1305:UDP:*:Enabled:Lightspeed Systems Security Agent Management";
	
	my $current_value;
	my $type;
	
	$ok = RegQueryValueEx( $key, $name, [], $type, $current_value, [] );
		
	if ( ( ! $current_value )  ||  ( $current_value ne $value ) )
		{	$ok = RegSetValueEx( $key, $name, 0,  REG_SZ, $value );
			&SecurityLogEvent( "Set the Microsoft firewall to allow the Security Agent.\n" ) if ( $ok );
			&SecurityLogEvent( "Unable to set Microsoft firewall to allow the Security Agent.\n" ) if ( ! $ok );
		}
	else
		{	&SecurityLogEvent( "The Microsoft firewall port list is set to allow the Security Agent.\n" );
		}
		
	RegCloseKey( $key );


	# Now check to see if our application is added
	$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\AuthorizedApplications\\List", 0, KEY_ALL_ACCESS, $key );

	if ( ! $ok )
		{	&SecurityLogEvent( "Unable to check Microsoft firewall application settings\n" );
			return( undef );
		}
		
	# Figure out the full path of the securityagent.exe service
	my $dir = &ScanWorkingDirectory();
	my $fullpath = $dir . "\\SecurityAgent.exe";
	
	$ok = RegQueryValueEx( $key, $fullpath, [], $type, $current_value, [] );
	RegCloseKey( $key );
	
	if ( ( $ok )  &&  ( $current_value ) )
		{	&SecurityLogEvent( "The Microsoft firewall application list is also set to allow the Security Agent.\n" );
			return( 1 );
		}	
	

	# Add our application to the Windows firewall exceptions list
	my $fwMgr = Win32::OLE->new( "HNetCfg.FwMgr" );
	
	if ( ! $fwMgr )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "OLE error getting the current Windows firewall exception list: $err_msg.\n" );
			return( undef );
		}


	# Get the current profile for the local firewall policy.
	my $profile = $fwMgr->LocalPolicy->{CurrentProfile};
	
	if ( ! $profile )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "OLE error getting the current local firewall policy profile: $err_msg.\n" );
			return( undef );
		}


	# Get the application object
	my $app = Win32::OLE->new( "HNetCfg.FwAuthorizedApplication" );
	if ( ! $app )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "OLE error getting the FWAuthorizedApplication object: $err_msg.\n" );
			return( undef );
		}


	$app->{ProcessImageFileName}	= $fullpath;
	$app->{Name}					= "Lightspeed Security Agent";
	$app->{Scope}					= NET_FW_SCOPE_ALL;
	$app->{IpVersion}				= NET_FW_IP_VERSION_ANY;
	$app->{Enabled}					= 1;

	$profile->AuthorizedApplications->Add( $app );


	my $errornum = 0 + Win32::OLE->LastError();

	if ( $errornum )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "OLE error adding to the Windows firewall exception list: $err_msg.\n" );
			return( undef );
		}

	&SecurityLogEvent( "Successfully added the Security Agent to the firewall applications list.\n" );
	
	return( 1 );
}



################################################################################
# 
sub UpdateSimpleFileSharing()
#
#  Make sure that simple file sharing is turned off
#  for the security agent exe to be accessed remotely
#
################################################################################
{	my $key;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_ALL_ACCESS, $key );

	if ( ! $ok )
		{	&SecurityLogEvent( "Unable to check Microsoft Simple File Sharing settings\n" );
			return( undef );
		}
			
	my $current_value;
	my $value = "\x00\x00\x00\x00";
	my $type;
	
	$ok = RegQueryValueEx( $key, "forceguest", [], $type, $current_value, [] );
		
	if ( ( ! $current_value )  ||  ( $current_value ne $value ) )
		{	$ok = RegSetValueEx( $key, "forceguest", 0,  REG_DWORD, $value );
			&SecurityLogEvent( "Turned Microsoft Simple File Sharing off to allow Security Agent remote access.\n" ) if ( $ok );
			&SecurityLogEvent( "Unable to set Microsoft Simple File Sharing to allow the Security Agent remote access.\n" ) if ( ! $ok );
		}
	else
		{	#&SecurityLogEvent( "Microsoft Simple File Sharing is set to allow Security Agent remote access.\n" )
		}
		
	RegCloseKey( $key );

	return( 1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "Update";

    bprint "$_[0]\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
.
    &StdFooter;

    exit( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Update";

    bprint <<".";
This utility updates the scan engine, virus signatures, and banned processes
list.  If scheduled, or a change has occurred, will also run the scan engine
to check for viruses and vulnerabilities.


  -a, --all              update and then scan all the drives immediately
  -e, --explorer         register a new explorer shell extention
  -f, --force            force a full update right now
  -i, --install          install new scan engine from current directory
  -l, --ldap             refresh any LDAP user information
  -n, --noexplorer       unregister an old explorer shell extention
  -o, --override server  override the update source with server
  -r, --reload           reload completely all the Security Agent tables
  -s, --signal           signal the Security Agent service to get properties
  -h, --help             display this help and exit
  -u, --uninstall        uninstall the device driver and all the software
  -v, --version          display version information and exit
.
    &StdFooter;

    exit( 1 );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "Update";

    bprint <<".";
$me version: $version
.
    &StdFooter;

    exit( 1 );
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
