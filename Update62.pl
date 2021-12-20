################################################################################
#!perl -w
#
# Rob McCarthy's Update scan engine, Virus signatures, and Banned Processes
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;


my $version = '6.02.08';	# Current version number - should match sa7package.txt or sa6package.txt in the current scan package
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
use Win32API::Registry qw( :ALL );
use Fcntl qw(:DEFAULT :flock);
use File::Copy;
use Cwd;


use Content::File;
use Content::ScanUtil;
use Content::ScanFile;
use Content::Disinfect;
use Content::Policy;
use Content::FileIntegrity;
use Content::FileID;
use Content::PerlAddFileID;
use Content::Registry;
use Content::QueryOS;
use Content::SAMonitor;
use Content::Process;
use Content::Update;
use Content::UpdateLog;
use Content::UpdateEvent;
use Content::UpdateDownload;
use Content::SAImport;



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
my $start_date = "1\/1\/2000";			# The start date for XML if I have to reload a table
my $default_ttc_server = "securityagent.lightspeedsystems.com";
my $errors_filename;					# "$dir\\UpdateErrors\.log";
my $working_dir;						# The software working directory - normally c:\Program Files\Lightspeed Systems\SecurityAgent
my $agent_report_file;					# The name of the security agent report file, if it exists
my $security_agent_service_restart;		# This flag is set if I need to net stop and net start the security agent service


# Security Agent Properties from the registry that are also loaded into memory
# Most of these properties can be set by the TTC server
my $ttc_server;							# This the ttc server that I should get updates from
my $use_lightspeed;						# True if I should use the Lightspeed default ttc server
my $last_ttc_server_version;			# If set, this is the version of the last ttc server I talked to successfully
my $batch_results;						# If True, then I can send update results back to the ttc_server via a batch
my $update_interval;					# The time interval of doing updates
my $interactive_mode;					# True if interactive mode is active
my $enable_file_and_printer_sharing;	# True if I should turn on the file and printer sharing Firewall ports for the Network task Manager
my @alternate_ttc_servers;				# This is the list of alternate TTC servers that I need to announce to


# Who has set the security agent properties
my $server_properties;					# True if the Security Agent properties can only be set by the server
my $manual_properties;					# True if the properties were set manually - must be set to 0 if server_properties is True


# Virus and permissions options
my $block_virus;						# True if I should block viruses
my $block_virus_action;					# What to do if a virus is detected
my $update_virus;						# True if I should update virus signatures
my $update_time;						# If set, the time of day to do database updates
my $scan_system;						# True if I am supposed to periodically scan the entire system
my $scan_interval;						# How often to scan the entire PC for viruses - Everyday, Sunday - Saturday
my $scan_time;							# What time of the day to scan - default 6 PM or 18
my $scan_type;							# Quick or full - default is full
my $scan_job_percent;					# How much job percent to scan with
my $block_spyware;						# True if I should tell the scan program to delete spyware
my $scan_content;						# True if I should scan files by content
my $block_all_unknown;					# True if all unknown programs should be blocked from running
my $scan_exclusions;					# List of files types and directories to NOT scan
my $removable_media_permissions;		# Removable media permissions - #define RMP_READ 0x00000001 define RMP_WRITE 0x00000002 define RMP_EXECUTE 0x00000004 Reporting 0x00000010

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
my $novell_precedence;					# If True, then the Novell userid takes precedence over the Microsoft userid

# Content Filter properties
my $enable_content_filtering;			# True if desktop content filtering is enabled
my $block_unknown_urls;					# True if unknown URLs should be blocked
my $block_failed_url_lookups;			# True if failed lookups should block
my $content_filtering_servers;			# Multi string list of servers to use for Content filtering

# Unknown program permissions
my $use_file_integrity;					# True if I should use file integrity to discover unknown programs
my $known_permissions = 0 + 0;			# The default permissions for known programs
my $unknown_permissions = 0x00fffffe;	# The default permissions for unknown programs



# These are various update times
my $signature_update;					# This is the last time I got a virus signature update
my $banned_update;						# This is the last time I got a banned process update
my $engine_update;						# This is the last time I got a new scan engine update
my $last_scan;							# This is the last time I fully scanned the PC - in system seconds
my $category_update;					# This is the last time I got a category update
my $last_purge;							# This is the last time I purged the file integrity database - in system seconds
my $integrity_update;					# This is the last time I got a file integrity update
my $fileid_update;						# This is the last time I got a file ID update
my $registry_update;					# This is the last time I got a registry control update


# User Information
my $username;
my $computer_name;
my $computer_domain;
my $computer_ou;
my $user_ou;
my $comment;
my $name_type;
my $group_list;


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


# This is the list of hostnames that indicate a hacked hosts file
my @hacked_hosts = (
'lightspeed',
'bank',
'paypal',
'ebay',
'wellsfargo',
'citi',
'bofa',
'bankofamerica',
'wellfleet',
'finance',
'mortgage',
'216.130.185.143',
'200.155.4.45',
'200.201.166.200',
'200.155.100.225',
'200.155.4.45',
'200.201.166.200',
'200.155.100.225',
'3510794929',
'greg-search.com',
'mig29here.com',
'mt-download.com',
'slotch.com',
'climaxbucks.com',
'sidefind.com',
'internet-optimizer.com',
'movies-etc.com',
'abetterinternet.com',
'localnrd.com',
'offeroptimizer.com',
'trafficmp.com',
'advertising.com',
'windowws.cc',
'super-spider.com',
'couldnotfind.com',
'kaspersky',
'symantec.com',
'sophos.com',
'mcafee.com',
'symantecliveupdate.com',
'viruslist.com',
'f-secure.com',
'avp.com',
'networkassociates.com',
'ca.com',
'my-etrust.com',
'nai.com',
'trendmicro.com',
'grisoft.com',
'microsoft.com'
);


################################################################################
#
MAIN:
#
################################################################################
{

	$SIG{'INT'} = 'INT_handler';
 
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

	
	$working_dir = &ScanWorkingDirectory();

	
	# Am I uninstalling everything?
	if ( $opt_uninstall )
		{	&UninstallSoftware();
			exit( 0 );
		}
	
	
	if ( $opt_debug )
		{	# Turn on additional logging/information.
			&UpdateDebug( $opt_debug );
			print "Debugging turned on\n" ;
		};
	
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	

	# Do I just need to check LDAP information?
	if ( $opt_ldap )
		{	# Open up the security log
			my $security_log = &SecurityOpenLogFile( $working_dir );		
			&SecurityLogEvent( "Security Agent Update version $version\n" );

			&SecurityLogEvent( "Checking user information ...\n" );
			my ( $os, $osversion, $servicepack, $total_virtual_memory, $serial_number, $registered, $organization, $total_free_virtual, $total_visible, $free_physical ) =
				&QueryOS();	

			( $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $comment, $name_type ) = &UpdateGetUserName();
			my $network = &UpdateGetNetwork();
			
			&SecurityLogEvent( "Network Type: $network\n" ) if ( defined $network );
			&SecurityLogEvent( "User name: $username\n" ) if ( defined $username );
			&SecurityLogEvent( "Computer name: $computer_name\n" ) if ( defined $computer_name );
			&SecurityLogEvent( "Computer Organization Unit: $computer_ou\n" ) if ( defined $computer_ou );
			&SecurityLogEvent( "User Organization Unit: $user_ou\n" ) if ( defined $user_ou );
			&SecurityLogEvent( "Network Name Type: $name_type\n" ) if ( defined $name_type );
			
			if ( $username )
				{	my @groups = &UpdateGetUserGroups( $username, $computer_name );
					foreach ( @groups )
						{	my $group = $_;
							next if ( ! defined $group );
							&SecurityLogEvent( "Update: Group: $group\n" );
							
							$group_list .= "," . $group if ( defined $group_list );
							$group_list = $group if ( ! defined $group_list );
						}
						
					&SecurityLogEvent( "Unable to discover any groups\n" ) if ( ! $groups[ 0 ] );	
				}

			# Get the main TTC server and the update properties
			my (	$ttc_server, $signature_update,
						$banned_update, $engine_update,
						$last_scan, $category_update,
						$last_purge, $manual_properties,
						$integrity_update, $fileid_update, $registry_update,
						$use_lightspeed, $last_ttc_server_version ) = &GetTTCServer( $default_ttc_server );
	
			# Get the changes to the policy tables
			&DownloadPolicy( $ttc_server, $opt_reload );
			&DownloadPolicyDefinition( $ttc_server, $opt_reload );
		
			&DownloadActivePolicy( $ttc_server, $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $group_list );
			
			# Apply the proper policy
			&PolicyApply();
			
			# If I changed the enable content filtering flag, make sure the LSP is registered
			&SetUseLSPStatus( undef );
			
			# Download the blocked category policy
			&DownloadBlockedCategories( $ttc_server, $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $group_list, $opt_reload );


			# Now report everything that I found out
			&ReportSecurityAgent( $ttc_server, $computer_name, $computer_domain, $comment, $os, $version, $username, $group_list, $user_ou );

			foreach ( @alternate_ttc_servers )
				{	my $alternate_ttc_server = $_;
					next if ( ! defined $alternate_ttc_server );
					&ReportSecurityAgent( $alternate_ttc_server, $computer_name, $computer_domain, $comment, $os, $version, $username, $group_list, $user_ou );
				}
				
	
			# Done with all the updating stuff, so put the time into the log
			my $time = localtime( time() );	
			&SecurityLogEvent( "Security log closed: $time\n" );
			
			&SecurityCloseLogFile();
			&AddHistoryLog( $working_dir, $security_log );
					
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
	
	
	# Am I running a new version of Update for the first time?
	# If so I have have to do some work to get everthing up to date
	&UpdateFirstRun();
	
	
	# Am I installing a scan package from the command line?
	if ( $opt_install )
		{	&SecurityLogEvent( "Update: Installing a new scan engine package from the command line\n" );
			
			my $dir = &ScanWorkingDirectory();

			my $update_filename = "SA7Update.htm";
			$update_filename = "SA62Update.htm" if ( $version lt '7.00.00' );
			$update_filename = "SA6Update.htm" if ( $version lt '6.02.00' );

			my $full_filename = $update_filename;
			$full_filename = $dir . "\\$update_filename" if ( $dir );
			
			if ( ! -e $full_filename )
				{	&SecurityLogEvent( "Update: Scan engine package $full_filename does not exist\n" );
				}
			else
				{	&InstallScanEngine( $dir, $full_filename );
				}
			
			
			# Do I need to restart the service
			&RestartService() if ( $security_agent_service_restart );	
			
			exit( 0 );
		}
		
		
	# Show any option selected
	&SecurityLogEvent( "Update Option: Start security scan now\n" ) if ( $opt_all );
	&SecurityLogEvent( "Update Option: Reload all the local databases\n" ) if ( $opt_reload );
	&SecurityLogEvent( "Update Option: Force a full update now\n" ) if ( $opt_force_update );
	
	
	my ( $os, $osversion, $servicepack, $total_virtual_memory, $serial_number, $registered, $organization, $total_free_virtual, $total_visible, $free_physical ) =
				&QueryOS();	
				
	&SecurityLogEvent( "Update: OS: $os\n" ) if ( $os );
	&ReportAddAttribute( "OS: Type", $os );
	
	&SecurityLogEvent( "Update: OS Version: $osversion\n" ) if ( $osversion );
	&ReportAddAttribute( "OS: Version", $osversion );
	
	&SecurityLogEvent( "Update: OS Service Pack: $servicepack\n" ) if ( $servicepack );
	&ReportAddAttribute( "OS: Service Pack", $servicepack );
	
	
	my $memory = 0 + 0;
	$memory = sprintf( "%9d", $total_virtual_memory ) if ( defined $total_virtual_memory );
	my $format_memory = &FormatSize( 1024 * $memory );
	&SecurityLogEvent( "Update: Virtual memory:      $memory KB\n" ) if ( defined $total_virtual_memory );
	&ReportAddAttribute( "Memory: Virtual memory", $format_memory );
	

	$memory = 0 + 0;
	$memory = sprintf( "%9d", $total_free_virtual ) if ( defined $total_free_virtual );
	$format_memory = &FormatSize( 1024 * $memory );
	&SecurityLogEvent( "Update: Free virtual memory: $memory KB\n" ) if ( defined $total_free_virtual );
	&ReportAddAttribute( "Memory: Free virtual memory", $format_memory );
	
	
	# Figure out the % free virtual memory
	my $percent = 0 + 0;
	$percent = 100 * ( $total_free_virtual / $total_virtual_memory ) if ( ( defined $total_free_virtual )  &&  ( $total_virtual_memory ) );
	$percent = sprintf( "%d", $percent );
	&SecurityLogEvent( "Update: Free virtual percentage:    $percent \%\n" );
	&ReportAddAttribute( "Memory: Free virtual percent", "$percent \%" );


	$memory = 0 + 0;
	$memory = sprintf( "%9d", $total_visible ) if ( defined $total_visible );
	$format_memory = &FormatSize( 1024 * $memory );
	&SecurityLogEvent( "Update: Visible memory:      $memory KB\n" ) if ( defined $total_visible );
	&ReportAddAttribute( "Memory: Visible memory", $format_memory );


	$memory = 0 + 0;
	$memory = sprintf( "%9d", $free_physical ) if ( defined $free_physical );
	$format_memory = &FormatSize( 1024 * $memory );
	&SecurityLogEvent( "Update: Free physical memory:$memory KB\n" ) if ( defined $free_physical );
	&ReportAddAttribute( "Memory: Free physical memory", $format_memory );


	# Figure out the % free physical memory
	$percent = 0 + 0;
	$percent = 100 * ( $free_physical / $total_visible ) if ( ( defined $free_physical )  &&  ( $total_visible ) );
	$percent = sprintf( "%d", $percent );
	&SecurityLogEvent( "Update: Free physical percentage:   $percent \%\n" );
	&ReportAddAttribute( "Memory: Free physical percent", "$percent \%" );


	# Cleanup any old install files ...
	&CleanUpFiles( $working_dir, undef );


	# Make sure that Win XP Service Pack 2 has the right registry settings for my program to use
	&UpdateXPSP2() if ( ( $servicepack ) &&  ( $servicepack =~ m/Service Pack 2/ ) );

	# Do the same thing for all versions of Vista
	&UpdateXPSP2() if ( ( $os ) &&  ( $os =~ m/vista/i ) );


	# Get the main TTC server and the update properties
	( $ttc_server, $signature_update,
	 $banned_update, $engine_update,
	 $last_scan, $category_update,
	 $last_purge, $manual_properties,
	 $integrity_update, $fileid_update, $registry_update,
	 $use_lightspeed, $last_ttc_server_version ) = &GetTTCServer( $default_ttc_server );
	

	# Do I have current virus signatures?  I might not if the TTC server has changed
	# If I don't have current signatures then I better download everything
	if ( ( $ttc_server )  &&  ( ( ! $signature_update )  ||  ( $signature_update eq $start_date ) ) )
		{	&SecurityLogEvent( "Update: Reloading all the properties from $ttc_server because this is a new TTC server\n" );
			$opt_reload = 1;
		}
		
	
	# Get the additional properties from the registry
	&LoadProperties();	


	&ReportBatchOpen() if ( $report_events );
	

	# Make sure that the file integrity file at least contains my programs
	&UpdateSecurityAgentFileIntegrity();
	

	# If I couldn't find a responding ttc server, just log that
	my $update_ok;
	
	if ( ! $ttc_server )
		{	&SecurityLogEvent( "Update: Unable to find any update sources right now, will try again later ...\n" );
		}
	else
		{	&SecurityLogEvent( "Update: Using $ttc_server as the update source\n" );
			
			
			# Tell the TTC server about myself - first find out everything out about myself
			( $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $comment, $name_type ) = &UpdateGetUserName();
			
			my $network = &UpdateGetNetwork();
			&SecurityLogEvent( "Update: Network Type: $network\n" )				if ( defined $network );
			&SecurityLogEvent( "Update: User name: $username\n" )				if ( defined $username );
			&SecurityLogEvent( "Update: Computer name: $computer_name\n" )		if ( defined $computer_name );
			&SecurityLogEvent( "Update: Computer domain: $computer_domain\n" )	if ( defined $computer_domain );
			&SecurityLogEvent( "Update: User's Organization Unit: $user_ou\n" )				if ( defined $user_ou );
			&SecurityLogEvent( "Update: Computer's Organization Unit: $computer_ou\n" )		if ( defined $computer_ou );
			&SecurityLogEvent( "Update: Network Name Type: $name_type\n" )		if ( defined $name_type );
			
			if ( $username )
				{	my @groups = &UpdateGetUserGroups( $username, $computer_name );
					foreach ( @groups )
						{	my $group = $_;
							next if ( ! defined $group );
							&SecurityLogEvent( "Update: Group: $group\n" );
							
							$group_list .= "," . $group if ( defined $group_list );
							$group_list = $group if ( ! defined $group_list );
						}
						
					&SecurityLogEvent( "Update: Unable to discover any groups\n" ) if ( ! $groups[ 0 ] );	
				}

	
			# Now report everything that I found out
			&ReportSecurityAgent( $ttc_server, $computer_name, $computer_domain, $comment, $os, $version, $username, $group_list, $user_ou );

			foreach ( @alternate_ttc_servers )
				{	my $alternate_ttc_server = $_;
					next if ( ! defined $alternate_ttc_server );
					&ReportSecurityAgent( $alternate_ttc_server, $computer_name, $computer_domain, $comment, $os, $version, $username, $group_list, $user_ou );
				}
			
			
			# At this point I've got a responding TTC Server, so get all the updates
			# This may not return - especially if there was a new update program downloaded
			# If it doesn't return it will close the security log
			$update_ok = &UpdateEverything( $opt_force_update );
		}
	
		
	# Make sure that simple file sharing is turned off
	&UpdateSimpleFileSharing();
	
	
	# Make sure the LmhostsTimeout entry is set correctly to allow FQDN resolution
	&UpdateLmhostsTimeout();

	
	# Make sure that the Server service is running
	&CheckServerService() if ( $report_events );
	
	
	# Check the registry and the hosts file, and launch the scan task if it is time
	&ScanSystem();
	
	
	# Report any monitored alerts
	&SAMonitor( $ttc_server );
	
	
	# Tell the ttc server about the scan results - if I can
	# Don't send a report to the default ttc server if it is the one being used ...
	my $lc_ttc_server;
	$lc_ttc_server = lc( $ttc_server ) if ( $ttc_server );
	my $lc_default = lc( $default_ttc_server );


	# Should I report what happened?
	if ( ! defined $lc_ttc_server )
		{	&SecurityLogEvent( "Update: no active TTC server to report to.\n" );
		}
	elsif ( $lc_ttc_server eq $lc_default )
		{	&SecurityLogEvent( "Update: $lc_default does not want security events reported.\n" )
		}
	else
		{	&UpdateResults( $ttc_server, $opt_force_update );
		}
	
	
	&DeleteReportFiles() if ( ! $report_events );
	
	
	# Save my settings back into the registry
	&SaveTTCUpdates() if ( $ttc_server );
	
	
	&MergeLogs();	# Merge all the logs into the security log	
	
	
	# Done with all the updating stuff, so put the time into the log
	my $time = localtime( time() );	
	&SecurityLogEvent( "Security log closed: $time\n" );
	
	
	&SecurityCloseLogFile();
	
	&AddHistoryLog( $working_dir, $security_log );
	
	
	# If everything updated ok, put it into the registry
	if ( ( $update_ok )  &&  ( $ttc_server ) )
		{	my $key;
			my $type;
			my $data;
	
			my $is_ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
			$year += 1900;
			$mon++;
			my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
			
			if ( $is_ok )
				{	&RegSetValueEx( $key, "Last Complete Update", 0,  REG_SZ, $datestr );
					&RegCloseKey( $key );
				}
		}
	
	exit( 0 );
}



################################################################################
#
sub INT_handler( $ )
#
#  Interrupt handler
#
################################################################################
{		  
	exit( 253 ); 
}



################################################################################
#
sub RestartService()
#
#  The scan.dll has been changed.  Since version .2 this means I need to restart
#  the security agent service
#
################################################################################
{		  
	$security_agent_service_restart = undef; 
	
	if ( &ProcessRunningName( "SecurityAgent.exe" ) )
		{	print "Stopping the Security Agent service ...\n";
			system( "net stop \"Security Agent Service\"" );
		
			print "Restarting the Security Agent service ...\n";	
			system( "net start \"Security Agent Service\"" );
			
			print "done restating ...\n";
		}
}



################################################################################
#
sub SetUseBHOStatus( $ )
#
#  Given what the BHO is suppposed to be set to, actually register it or
#  unregister it, depending on what the right thing to do is 
#
#  Return True if I think I did it ok, undef it not
#
################################################################################
{	my $should_use_bho = shift;	# If True, then I should be using the BHO
	
	# First, figure out what I last did
	my $key;
	my $type;
	my $data;
	
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );

	my $bho_registered = 1;
	$ok = &RegQueryValueEx( $key, "BHO Registered", [], $type, $data, []) if ( ( $ok )  &&  ( $key ) );
	if ( ( $ok )  &&  ( $key ) )
		{	$bho_registered = undef;
			my $len = length( $data );
			$bho_registered = 0 + 1 if ( ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}

	# If the should_use_bho and the bho_registered agree, then I am done without doing anything
	if ( ( $should_use_bho )  &&  ( $bho_registered ) )
		{	&RegCloseKey( $key );
			return( 1 );
		}
		
	if ( ( ! $should_use_bho )  &&  ( ! $bho_registered ) )
		{	&RegCloseKey( $key );
			return( 1 );
		}


	# OK - at this point I need to either turn on or turn on the BHO
	# Switch to the working directory
	my $working_dir = &ScanWorkingDirectory();
	my $cur_dir = getcwd();	
	chdir( $working_dir );	
	
	# If the BHO doesn't exist, I can't do anything
	if ( ! -e "SecurityAgentBHO.dll" )
		{	&RegCloseKey( $key );
			chdir( $cur_dir );
			return( undef );
		}
		
	if ( $should_use_bho )
		{	system "regsvr32 \/s securityagentbho.dll";
		}
	else
		{	system "regsvr32 \/u \/s SecurityAgentBho.dll";
		}
		
		
	# Switch back to the original directory
	chdir( $cur_dir );
	
	
	# Set the registry value if I can
	if ( $key )
		{	$data = "\x00\x00\x00\x00";
			$data = "\x01\x00\x00\x00" if ( $should_use_bho );
			
			&RegSetValueEx( $key, "BHO Registered", 0,  REG_DWORD, $data );
			&RegCloseKey( $key );
		}
		
	return( 1 );
}



################################################################################
#
sub SetUseLSPStatus( $ )
#
#  Given what the LSP is suppposed to be set to, actually register it or
#  unregister it, depending on what the right thing to do is 
#
#  Return True if I think I did it ok, undef it not
#
################################################################################
{	my $uninstall = shift;
	my $should_use_lsp = undef;
	
	my ($key, $type, $data);
	
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );
	$ok = &RegQueryValueEx( $key, "Enable Content Filtering", [], $type, $data, []) if ( ( $ok )  &&  ( $key ) );
	if ( ( $ok )  &&  ( $key ) )
	{	my $len = length( $data );
		$$should_use_lsp = 0 + 1 if ( ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
	}
	
	
	# If I am uninstalling, just remove it.
	$should_use_lsp = undef if ( $uninstall );

	# OK - at this point I need to either turn on or turn on the BHO
	# Switch to the working directory
	my $cur_dir = getcwd();	
	my $system32_dir	= "$ENV{ SystemRoot }\\SYSTEM32";

	chdir( $system32_dir );	
	
	
	# If the LSP doesn't exist, I can't do anything
	if ( ! -e "salsp.dll" )
		{	&SecurityLogEvent(  "Update: Error - unable to find salsp.dll in directory $system32_dir\n" );
			chdir( $cur_dir );
			&RegCloseKey( $key );
			return( undef );
		}
		
		
	# First, figure out what I last did

	# Default to assume that it is not registered
	my $lsp_registered;
	my $lsp_key_exists;
	$data = undef;
	$ok = &RegQueryValueEx( $key, "LSP Registered", [], $type, $data, [] ) if ( ( $ok )  &&  ( $key ) );
	my $len = length( $data );

	# If the "LSP Registered" key doesn't exist, assume the lsp is registered, and unregister it, no matter what
	if ( $len <= 0 )
		{	&SecurityLogEvent(  "Update: Unregistering salsp.dll in directory $system32_dir\n" );
			system "regsvr32 \/u \/s salsp.dll";
			
			# Set the status flags
			$lsp_registered = undef;
			$lsp_key_exists = undef;
		}
	elsif ( ( $ok )  &&  ( $key ) )	# If the key does exist, then get the current registered status
		{	# Set the status flags
			$lsp_registered = undef;
			$lsp_registered = 0 + 1 if ( ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
			$lsp_key_exists = 1;
			
			&SecurityLogEvent(  "Update: Key exists and the LSP should be registered\n" ) if ( $lsp_registered );
			&SecurityLogEvent(  "Update: Key exists and the LSP should NOT be registered\n" ) if ( ! $lsp_registered );
		}


	# If the should_use_lsp and the lsp_registered agree, and the "LSP Registered" key exists,
	# then I am done without doing anything
	if ( ( $should_use_lsp )  &&  ( $lsp_registered )  &&  ( $lsp_key_exists ) )
		{	&RegCloseKey( $key );
			chdir( $cur_dir );
			return( 1 );
		}
		
		
	if ( ( ! $should_use_lsp )  &&  ( ! $lsp_registered )  &&  ( $lsp_key_exists ) )
		{	&RegCloseKey( $key );
			chdir( $cur_dir );
			return( 1 );
		}


	if ( $should_use_lsp )
		{	&SecurityLogEvent(  "Update: Registering salsp.dll in directory $system32_dir\n" );
			system "regsvr32 \/s salsp.dll";
		}
	else
		{	&SecurityLogEvent(  "Update: Unregistering salsp.dll in directory $system32_dir\n" );
			system "regsvr32 \/u \/s salsp.dll";
		}
		
		
	# Switch back to the original directory
	chdir( $cur_dir );
	
	
	# Set the registry value if I can
	if ( $key )
		{	$data = "\x00\x00\x00\x00";
			$data = "\x01\x00\x00\x00" if ( $should_use_lsp );
			
			&SecurityLogEvent(  "Update: Setting the LSP Registered status in the registry\n" );
			$ok = &RegSetValueEx( $key, "LSP Registered", 0,  REG_DWORD, $data );
			
			if ( ! $ok )
				{	my $reg_err = &regLastError();
					$reg_err = "Unknown error" if ( ! $reg_err );
					&SecurityLogEvent(  "Update: Error setting the LSP Registered key: $reg_err\n" );
				}
				
			&RegCloseKey( $key );
		}
		
	return( 1 );
}



################################################################################
#
sub UpdateFirstRun( $ )
#
#  Is this the first time that I've run this version of Update on this PC?
#  If so, there may be some update work that I have to do
#
################################################################################
{
	#  Get the software version from the registry
	my $key;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );
	return( undef ) if ( ! $ok );
	
	my $data;
	my $type;	
	$ok = &RegQueryValueEx( $key, "Software Version", [], $type, $data, []);
	my $len = length( $data );
	
	my $registry_version = $data if ( ( $ok )  &&  ( $len > 0 ) );
	
	
	# Is it the same version?  If so then I don't have to do anything
	if ( ( $ok )  &&  ( $registry_version )  &&  ( $version )  &&  ( $registry_version eq $version ) )
		{	&RegCloseKey( $key );
			return( 1 );
		}
		
		
	# Do all the version specific update work
	
	
	# Am I updating a 6.00.20 or earlier version?
	if ( $registry_version le '6.00.20' )
		{	# Reset the virus signature update time so that all the virus signatures get reloaded
			# I have to do this because Brock's new scan code can now handle wildcard and extended signatures
			&RegSetValueEx( $key, "Signature Update", 0,  REG_SZ, $start_date );
		}
		
	&RegCloseKey( $key );

	return( 1 );
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
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );

	# If not OK, create the main keys and return the default values
	if ( ! $ok )
		{	my $regErr = regLastError();
			print "Unable to open main Security Agent key: $regErr\n";
			
			# Make sure the main Lightspeed Systems key is created
			$ok = &RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );

			# Now create my key
			$ok = &RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );
			
			if ( ! $ok )
				{	my $regErr = regLastError();
					print "Unable to create main Security Agent key: $regErr\n";
					return( undef );
				}
		}
	
	my $type;
	my $data;	
	$ok = &RegQueryValueEx( $key, "TTC Server", [], $type, $data, []);
	
	my $multi_sz = $override_ttc_server;
	
	# Tack on 2 extra x00 on the end to make it a multi sz	
	$multi_sz = $multi_sz . "\x00\x00" if ( $multi_sz );
	
	my $len = length( $data );
	
	$data = " " if ( $len <= 0 );
	$data = " " if ( ! $data );
	if ( $multi_sz ne $data )
		{	print "Overriding the existing update source with $override_ttc_server\n";
			&RegSetValueEx( $key, "TTC Server", 0,  REG_MULTI_SZ, $multi_sz );
		}
	else
		{	print "The existing update source is already set to $override_ttc_server\n";
		}
		

	# Make sure the use lightspeed key is set to no
	$data = "\x00\x00\x00\x00";
	&RegSetValueEx( $key, "Use Lightspeed", 0,  REG_DWORD, $data );

	&RegCloseKey( $key );
	
	return( 1 );
}



################################################################################
#
sub SaveTTCUpdates()
#
#  Save the TTC server, and all of the update times
#
################################################################################
{	&SecurityLogEvent( "Update: Saving current settings ...\n" );
	
	my $ret = &SetTTCServer( $ttc_server, $signature_update, 
				  $banned_update, $engine_update, 
				  $last_scan, $category_update, 
				  $last_purge, $integrity_update, $fileid_update,
				  $registry_update, $use_lightspeed, $last_ttc_server_version );
	
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
	
	# Check that the directory exists
	return( undef ) if ( ! $dir );
	return( undef ) if ( ! -d $dir );
	
	# Return undef if the logfile doesn't exist
	return( undef ) if ( ! $logname );
	return( undef ) if ( ! -e $logname );
	
	my $history_log = $dir . "\\history.log";
	
	my $size = -s $history_log;
	
	&HistoryBackup( $dir ) if ( ( $size  )  &&  ( $size > ( 0 + 5000000 ) ) );	# If the size is larger than a 5 megs, backup the file
	
	open( HISTORY, ">>$history_log" ) or return( undef );
	
	if ( ! open( LOG, "<$logname" ) )
		{	close( HISTORY );
			return( undef );	
		}
	
	print HISTORY "\n\n";
	
	while (my $line = <LOG>)
		{	print HISTORY "$line" if ( defined $line );
		}
		
	close( LOG );
	close( HISTORY );
	

	return( 1 );
}



################################################################################
#
sub HistoryBackup( $ )
#
#  In the given directory, backup the history log
#
################################################################################
{	my $dir		= shift;
	
	# Check that the directory exists
	return( undef ) if ( ! $dir );
	return( undef ) if ( ! -d $dir );
	
	my $history_log = $dir . "\\history.log";
	return( undef ) if ( ! -f $history_log );
	
	my $history_backup = $dir . "\\history.bak";

	unlink( $history_backup );	
	my $ok = rename( $history_log, $history_backup );
	
	return( $ok );
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
	# If I can open the file, and it's not too larget, merge it into the security log
	if ( ( $errors_filename )  &&
		( -e $errors_filename )  &&
		( -s $errors_filename )  &&
		( -s $errors_filename lt 1000000 )  &&
		( open( FILE, "<$errors_filename" ) ) )	
		{	&SecurityLogEvent( "Update Errors:\n" );
			
			my $count = 0 + 0;
			while (my $line = <FILE>)
				{	chomp( $line );
					next if ( ! defined $line );
					
					&SecurityLogEvent( "$line\n" );
					$count++;
				}
				
			&SecurityLogEvent( "Update: No update errors\n" ) if ( ! $count );
			close FILE;
		}
		
		
	# Merge the scan log into the security log - only stick in viruses discovered
	my $scan_log_file_name = "$working_dir\\scan.log";
	if ( open( FILE, "<$scan_log_file_name" ) )	# If I can open the file, merge it into the security log
		{	my @virus_found;
			
			while (my $line = <FILE>)
				{	chomp( $line );
					next if ( ! defined $line );
					next if ( ! ( $line =~ m/Infection/ ) );
					
					push @virus_found, $line;		 
				}
			close FILE;
			
			 if ( $#virus_found )	
				{	&SecurityLogEvent( "Update: No viruses found by last scan.\n" );
				}
			else
				{	&SecurityLogEvent( "Update: The last scan found the following viruses ...\n" );
					foreach ( @virus_found )
						{	next if ( ! defined $_ );							
							my $line = $_;
							&SecurityLogEvent( "$line\n" );
						}
				}
				
			# Blow away the scan log now that I've reported it
			# Now I'm not blowing it away - I'll just leave it hanging around
			#unlink( $scan_log_file_name );
		}
	else
		{	&SecurityLogEvent( "Update: Error opening $scan_log_file_name: $!\n" ) if ( -e $scan_log_file_name );
		}
		
	
	# Merge the ScanErrors log into the security log
	# If I can open the file, and it's not too large, merge it into the security log
	my $scan_errors_filename = "$working_dir\\ScanErrors\.log";
	if ( ( -e $scan_errors_filename )  &&
		( -s $scan_errors_filename )  &&
		( -s $scan_errors_filename < 1000000 )  &&
		( open( FILE, "<$scan_errors_filename" ) ) )	
		{	&SecurityLogEvent( "Update: Scan Errors:\n" );
			
			my $count = 0 + 0;
			while (my $line = <FILE>)
				{	chomp( $line );
					next if ( ! defined $line );
					
					&SecurityLogEvent( "$line\n" );
					$count++;
				}
				
			&SecurityLogEvent( "Update: No scan errors\n" ) if ( ! $count );
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
	
	
	# Make sure that I have write access to all the directories I need to ...
	my $dir_err = &DirectoryAccessCheck();
	if ( ! $dir_err  )
		{	&SecurityLogEvent( "Update: Tested directory access OK\n" );
		}
	else
		{	&SecurityLogEvent( "Update: ERROR - Directory Access: $dir_err\n" );
			return( undef );
		}
		

	if ( $opt_reload )
		{	&SecurityLogEvent( "Update: Reloading all the database tables from $ttc_server ...\n" );
			$signature_update	= $start_date;
			$banned_update		= $start_date;
			$category_update	= $start_date;
			$integrity_update	= $start_date;
			$fileid_update		= $start_date;
			$registry_update	= $start_date;
			
			$changed = 1;
		}
	else	# Is it time to run the update everything now ...
		{	my $update_now;	# Set this to true if it is time to update now
			
			$update_interval = &OneOf( $update_interval, "Day", "Hour", "Week" );
			
		 	my $key;
			my $type;
			my $data;
	
			my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );
			my $last_update;
			
			if ( $ok )
				{	$data = undef;
					$ok = &RegQueryValueEx( $key, "Last Complete Update", [], $type, $data, [] );
					my $len = length( $data );
					&RegCloseKey( $key );
					$update_now = 1 if ( ! $ok );
					$update_now = 1 if ( $len <= 0 );
					$last_update = $data if ( $len > 0 );
				}
			else
				{	$update_now = 1;
				}
				
				
			$update_now = 1 if ( $force_update_now );
			$update_now = 1 if ( $update_interval eq "Hour" );
			
			
			# Expired time returns 2 if it's been a long time, 1 if it need a normal update, or undef if current
			# First make sure that the update time is rational
			$update_time = 0 + 12 if ( ( defined $update_time )  &&  ( ( $update_time < 0 )  ||  ( $update_time > 23 ) ) );
			
			my $expired = &ExpiredTime( $update_interval, $last_update, $update_time );
			
			
			# Has a really long time gone by since I last got data from $ttc_server?
			if ( ( $expired )  &&  ( $expired > 1 ) )
				{	&SecurityLogEvent( "Update: Reloading all the database tables from $ttc_server ...\n" );
					$signature_update	= $start_date;
					$banned_update		= $start_date;
					$category_update	= $start_date;
					$integrity_update	= $start_date;
					$fileid_update		= $start_date;
					$registry_update	= $start_date;
					
					$changed = 1;
					$update_now = 1;
				}
			elsif ( $expired )
				{	$update_now = 1;
				}
				
			
			# Is it the right time to update?  
			# The update time might not be set
			if ( ( $update_now )  &&  
				( ! $force_update_now )  &&  
				( $update_interval ne "Hour" )  &&  
				( ! $changed )  &&  
				( $update_time ) )
				{	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
					
					my $url_update_time = "$update_time am";
					my $pm = $update_time - 12;
					$url_update_time = "$pm pm" if ( $update_time >= 12 );
					$url_update_time = "12 am" if ( ! $update_time );	# 0 military time is 12 am
					$url_update_time = "12 pm" if ( $update_time == 12 );
					
					if ( $hour < $update_time )
						{	&SecurityLogEvent( "Update: The Update Time is set to $url_update_time and so it is too early in the day to update now\n" );
							$update_now = undef;
						}
					elsif ( $hour == $update_time )
						{	&SecurityLogEvent( "Update: The Update Time is set to $url_update_time and so it now the right time to update\n" );
						}
					else
						{	&SecurityLogEvent( "Update: The Update Time is set to $url_update_time and so it is too late in the day to update now\n" );
							$update_now = undef;
						}
				}
			
			
			# Return undef, indicating that not everything updated ok
			if ( ! $update_now )
				{	&SecurityLogEvent( "Update: The last complete update was $last_update.\n" ) if ( $last_update );
					my $lc_update_interval = lc( $update_interval );
					&SecurityLogEvent( "Update: Set to check for updates once a $lc_update_interval.\n" );
					&SecurityLogEvent( "Update: Not yet time to check for the next updates.\n" );
					
					&DownloadPolicy( $ttc_server, $opt_reload );
					&DownloadPolicyDefinition( $ttc_server, $opt_reload );
				
					# Find the correct policy to apply to this user.
					&DownloadActivePolicy( $ttc_server, $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $group_list );
					
					# Check to see if the Policy Apply changes anything
					$changed = &PolicyApply();
					
					# If I changed the enable content filtering flag, make sure the LSP is registered
					&SetUseLSPStatus( undef );
					
					# Download the blocked category policy
					$changed = 1 if ( &DownloadBlockedCategories( $ttc_server, $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $group_list, $opt_reload ) );

					# Check for critical updates
					$changed = 1 if ( &SAImportCritical( $ttc_server, $opt_reload, \$signature_update, \$banned_update, \$category_update, \$integrity_update, \$fileid_update, \$registry_update ) );
					
					# Signal the SecurityAgent sevice that something has changed
					&SignalService() if ( $changed );
					
					return( undef );
				}
		}


	# Set the expired time flag to indicate that I just ran - for whatever reason - could be opt_reload, could be force update, could be hourly update
	&SaveLastExpiredTime( time, 0 + 0 );


	# Set this to true, and if anything screws up, set it to undef
	$update_ok = 1;
	
	
	# If I got to here, then it is time to update everything
	&SecurityLogEvent( "Update: Updating the Security Agent using server $ttc_server\n" );
	
	
	# If manual properties are set, is the server trying to overwrite them?
	&DownloadServerProperties( $ttc_server ) if ( $manual_properties );
	
	
	if ( ! $manual_properties )
		{	my $ok;	
			$ok = &DownloadProperties( $ttc_server );
			
			if ( $ok )
				{	&SecurityLogEvent( "Update: Updated Security Agent properties from $ttc_server\n" );
					&SaveProperties();	# Save the new properties into the registry
					$changed = 1;
				}
		}
	
	
	# Show who is setting the security agent properties
	if ( $manual_properties )
		{	&SecurityLogEvent( "Update: Security Agent Property Control: Set by a local user\n" );
			&SecurityLogEvent( "Update: Security Agent properties can not be changed from server $ttc_server.\n" );
			&ReportAddAttribute( "Security Agent Properties: Properties Control", "Set only by a local user" );
		}
		
	if ( $server_properties )
		{	&SecurityLogEvent( "Update: Security Agent Property Control: Set from server $ttc_server.\n" );
			&SecurityLogEvent( "Update: Security Agent properties can not be changed by a local user.\n" );
			&ReportAddAttribute( "Security Agent Properties: Properties Control", "Set only from server $ttc_server" );
		}
		
	if ( ( ! $server_properties )  &&  ( ! $manual_properties ) )
		{	&SecurityLogEvent( "Update: Security Agent Property Control: Set by either server $ttc_server or local user\n" );
			&SecurityLogEvent( "Update: Security Agent properties can be changed by both a local user and from server $ttc_server.\n" );
			&ReportAddAttribute( "Security Agent Properties: Properties Control", "Can be set by either server $ttc_server or a local user" );
		}
		
		
	# Rename is True if I need to install a new update program
	my $renamer;
	my $last_update;
	( $last_update, $renamer ) = &DownloadScanEngine( $ttc_server, $engine_update );
	if ( ( $last_update )  &&  ( $last_update ne $engine_update ) )
		{	$engine_update = $last_update;
			
			&SaveTTCUpdates();
			
			# Do I need to restart the service
			&RestartService() if ( $security_agent_service_restart );	
		}
					
		
	# Do I need to replace the current Update.exe program with a new one?
	# If so, I should do that right away in case it adds important new functionality
	if ( $renamer )
		{	&SecurityLogEvent( "Update: Installing new Update utility\n" );
	
	
			# Signal the SecurityAgent sevice that something has changed
			&SignalService() if ( $changed );
		
		
			# If everything works right this function will not return
			# If it does return then there was an error
			# It will cose the security log if it should
			&RenameUpdate( $working_dir );
		}
	

	# Set this flag if I should signal the service that something changed
	my $signal_service;
	
	
	# Check to make sure that the VirusSignatures and FileIntegrity files exist - if not, try to do an SAImport
	my $file = &ScanSignatureFile();
	$signature_update = $start_date if ( ( ! -e $file )  ||  ( ! -s $file ) );
	
	# This file may exist - but be too small to matter
	$file = &FileIntegrityFilename();
	$integrity_update = $start_date if ( ( ! -e $file )  ||  ( -s $file < 10000 ) );


	# Make sure the file ID and file ID index files exist if the server version supports it
	my $fileid_needs_update;
	if ( ( $last_ttc_server_version )  &&  ( $last_ttc_server_version ge "6.02.00" ) )
		{	$file = &FileIDFilename();
			$fileid_update = $start_date if ( ( ! -e $file )  ||  ( ! -s $file ) );
			
			$file = &FileIDNameFilename();
			$fileid_update = $start_date if ( ( ! -e $file )  ||  ( ! -s $file ) );
			
			$file = &FileIDIndexFilename();
			$fileid_update = $start_date if ( ( ! -e $file )  ||  ( ! -s $file ) );
			
			$fileid_needs_update = 1 if ( $fileid_update eq $start_date );
		}
		
		
	# If I need to move down completely one of the big tables I better go full speed
	if ( ( $signature_update eq $start_date )  ||  
		( $integrity_update eq $start_date )   ||
		( $fileid_needs_update ) )
		{	&SecurityLogEvent( "Update: Moving full tables so setting the download to run at full speed ...\n" );
			&UpdateDownSleepMilliseconds( 0 + 0 );
		}


	# If I am reloading any of the big tables see if the server has a compressed copy of the Security Agent data
	# Also get compressed data if only updating once a day or once a week
	if ( ( $signature_update eq $start_date )  ||  
		( $integrity_update eq $start_date )   ||
		( $fileid_needs_update )  ||
		( $update_interval ne "Hour" ) )
		{	if ( $update_virus )
				{	my $changed = &SAImport( $ttc_server, $opt_reload, \$signature_update, \$banned_update, \$category_update, \$integrity_update, \$fileid_update, \$registry_update );
					$signal_service = 1 if ( $changed );
			
					&SaveTTCUpdates();

					&DownloadPolicy( $ttc_server, $opt_reload );
					&DownloadPolicyDefinition( $ttc_server, $opt_reload );
				}
		}


	# At this point I've gotten any big changes, so don't get the incremental changes unless I have to
	# So, should I do an incremental update?  This can run slowly if lots of Security Agents are querying the
	# same TTC server - so do this sparingly
	if ( ( $update_interval eq "Hour" )  ||
		( $force_update_now )  ||
		( $opt_reload ) )
		{	&SecurityLogEvent( "Update: Checking server $ttc_server for any recent changes ...\n" );
	
	
			# Check for changes to the categories
			my %category_blocked = &ScanBlockedCategories();
			my @categories = keys %category_blocked;
			
			# Reload everything if no categories loaded
			$category_update = $start_date if ( $#categories lt 1 );
			( $changed, $last_update ) = &DownloadCategories( $ttc_server, $category_update, undef, undef );
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
			if ( $update_virus )
				{	( $changed, $last_update ) = &DownloadVirusSignatures( $ttc_server, $signature_update, $categories_changed, undef, undef );
					$signature_update = $last_update if ( defined $last_update );	
				}
				
			if ( $changed )
				{	$signal_service = 1 if ( $block_virus );	# Only signal the service if it is using virus signatures
					
					&SaveTTCUpdates();
				}
				
			$update_ok = undef if ( ! $last_update );	
			$changed = undef;
			
			
			# check for changes to the banned processes	
			( $changed, $last_update ) = &DownloadBannedProcesses( $ttc_server, $banned_update, $categories_changed, undef, undef );
			$banned_update = $last_update if ( defined $last_update );
			
			if ( $changed )
				{	$signal_service = 1;
					
					&SaveTTCUpdates();
				}
					
			$update_ok = undef if ( ! $last_update );
			$changed = undef;
			
			
			if ( $update_virus )	
				{	( $changed, $last_update ) = &DownloadFileIntegrity( $ttc_server, $integrity_update, $categories_changed, undef, undef );
					$integrity_update = $last_update if ( defined $last_update );
				}
				
			if ( $changed )
				{	$signal_service = 1;
					
					&SaveTTCUpdates();
				}
			
				
			$update_ok = undef if ( ! $last_update );	
			$changed = undef;
			

			# This download type was added in verion 6.0.22	
			if ( $update_virus )
				{	( $changed, $last_update ) = &DownloadFileID( $ttc_server, $fileid_update, $categories_changed, undef, undef );
					$fileid_update = $last_update if ( defined $last_update );
				}
				
			if ( $changed )
				{	$signal_service = 1;
					
					&SaveTTCUpdates();
				}
			
				
			$update_ok = undef if ( ! $last_update );	
			$changed = undef;
			
				
			( $changed, $last_update ) = &DownloadRegistryControl( $ttc_server, $registry_update, $categories_changed, undef, undef );
			$registry_update = $last_update if ( defined $last_update );
			
			if ( $changed )
				{	
					$signal_service = 1;
					
					&SaveTTCUpdates();
				}
				
			$update_ok = undef if ( ! $last_update );			
				

			# Download the disinfect scripts - they don't matter as far as the service is concerned,
			# so don't signal the service if the disinfect scripts are the only thing changed
			( $changed, $last_update ) = &DownloadDisinfectScripts( $ttc_server, $opt_reload, undef, undef );


			# Get the changes to the policy tables
			( $changed, $last_update ) = &DownloadPolicy( $ttc_server, $opt_reload );
			( $changed, $last_update ) = &DownloadPolicyDefinition( $ttc_server, $opt_reload );
			( $changed, $last_update ) = &DownloadRequiredSoftware( $ttc_server, $opt_reload );
		}  # End of incremental changes
		

	# If everything came down ok, get the required policy version that I should be running
	# I can do this because I've gotten everything from the TTC server ok
	&DownloadActivePolicy( $ttc_server, $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $group_list ) if ( $update_ok );
	
	
	# Check to see if the Policy Apply changes anything
	$changed = &PolicyApply();
	$signal_service = 1 if ( $changed );
	
	
	# If I changed the enable content filtering flag, make sure the LSP is registered
	&SetUseLSPStatus( undef );


	# Download the blocked category policy
	$changed = 1 if ( &DownloadBlockedCategories( $ttc_server, $username, $computer_name, $computer_domain, $computer_ou, $user_ou, $group_list, $opt_reload ) );
	$signal_service = 1 if ( $changed );


	# Make sure that the file integrity file at least contains my programs
	$changed = 1 if ( &UpdateSecurityAgentFileIntegrity() );
	$signal_service = 1 if ( $changed );
	

	# Check for critical updates
	$changed = 1 if ( &SAImportCritical( $ttc_server, $opt_reload, \$signature_update, \$banned_update, \$category_update, \$integrity_update, \$fileid_update, \$registry_update ) );
	$signal_service = 1 if ( $changed );


	# Signal the SecurityAgent sevice that something has changed
	&SignalService() if ( $signal_service );
		
		
	# Return the update ok variable
	return( $update_ok );	
}



################################################################################
#
sub DirectoryAccessCheck()
#
#  Make sure that I have directory write access to all the directories I need
#  Return an error message if I have a problem, undef if no problems
#
################################################################################
{
	my $working_dir		= &ScanWorkingDirectory();
	my $system_dir		= &ScanSystemDirectory();
	my $tmp_dir			= &ScanTmpDirectory();
	my $scan_temp_dir	= &ScanTempDirectory();
	my $quarantine		= &ScanQuarantineDirectory();
	my $log_dir			= &ScanLogDirectory();

	my $err = &DirectoryWriteCheck( $working_dir );
	return( $err ) if ( $err );
	
	$err = &DirectoryWriteCheck( $system_dir );
	return( $err ) if ( $err );
	
	$err = &DirectoryWriteCheck( $tmp_dir );
	return( $err ) if ( $err );
	
	$err = &DirectoryWriteCheck( $scan_temp_dir );
	return( $err ) if ( $err );
	
	$err = &DirectoryWriteCheck( $quarantine );
	return( $err ) if ( $err );
	
	$err = &DirectoryWriteCheck( $log_dir );
	return( $err ) if ( $err );

	return( $err );
}



################################################################################
#
sub DirectoryWriteCheck( $ )
#
#  Make sure that I have directory write access to all the directories I need
#  Return an error message if I have a problem, undef if no problems
#
################################################################################
{	my $dir = shift;

	return( "Undefined directory" ) if ( ! defined $dir );

	return( "Directory $dir does not exist" ) if ( ! -d $dir );
	
	my $tmp_file = $dir . "\\SADirectoryCheck.tmp";
	
	# Can I open a file for write access?
	if ( ! open( TMP, ">$tmp_file" ) )
		{	my $err = $!;
			return( "Unable to access directory $dir: $err" );
		}
	
	# Can I write to the file?
	if ( ! print( TMP "test string\n" ) )
		{	my $err = $!;
			close( TMP );
			unlink( $tmp_file );
			return( "Unable to write to directory $dir: $err" );
		}
		
	close( TMP );
	
	# Did I acually create a file with some data?
	if ( ! -s $tmp_file )
		{	unlink( $tmp_file );
			return( "Unable to create files in directory $dir" );
		}

	# Can I now read the file?
	if ( ! open( TMP, "<$tmp_file" ) )
		{	my $err = $!;
			unlink( $tmp_file );
			return( "Unable to read from directory $dir: $!" );
		}
		
	close( TMP );
	
	unlink( $tmp_file );
	
	return( undef );
}



################################################################################
#
sub ExpiredTime( $$$ )
#
#  Given the update interval and the datestr of the last update, return
#  1 if it is time to update everything, 2 if it's been a really long time
#  since I updated, or undef if I'm pretty current
#
################################################################################
{	my $update_interval = shift;	# This will be either Day or Week
	my $last_update		= shift;
	my $update_time		= shift;	# If set, this is the hour of the day to do an update
	
	return( 0 + 2 ) if ( ! $last_update );
	
	
	my ( $last_expired, $random_wait ) = &GetLastExpiredTime();
	my $current_expired = time;
	&SaveLastExpiredTime( $current_expired, $random_wait );
	
	
	# If the expired time has never been run, just return a 2 showing it's been a really long time
	if ( ( ! $last_expired )  ||  ( ! $current_expired ) )
		{	return( 0 + 2 );
		}
		
	
	# If it has been a long time since the ExpiredTime function has been called, then that is a good 
	# indication that this PC has been turned off for a while - like overnight or over the week end
	# If it has been turned off, then reset the random wait time
	my $last_secs = $current_expired - $last_expired;
	my $last_hours = $last_secs / ( 60 * 60 );
	
	if ( $last_hours < ( 0 + 0.5 ) )	# Has it been less than 1/2 hours?
		{	# Then don't do anything
		}
	elsif ( $last_hours < ( 0 + 1.5 ) )	# Has it been been 1/2 and 1 1/2 hours?
		{	# Then count down the random wait time
			$random_wait = $random_wait - 1;
			$random_wait = 0 + 0 if ( $random_wait < 0 );
			&SaveLastExpiredTime( $current_expired, $random_wait );
		}
	else	# Has it been longer than 1 1/2 hours?  If so, then this PC was probably turned off, so reset the random wait
		{	# Pick a random number of hours been 0 and 6 to wait 
			my $rand = rand( 7 );
			$rand = sprintf( "%d", $rand );
			$random_wait = 0 + $rand;
			&SaveLastExpiredTime( $current_expired, $random_wait );
		}
		
		
	# Figure out the current time
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $current_expired );
	$year += 1900;
	$mon++;
	
	
	my $old_time;
	if ( $update_interval eq "Day" )	# I am doing a daily update
		{	$old_time = $current_expired - ( 24 * 60 * 60 );
		}
	else	# I must be doing a weekly update
		{	$old_time = $current_expired - ( 7 * 24 * 60 * 60 );
		}
		
	
	# I'm defining a long time as 2 weeks or more
	my $long_time = $current_expired - ( 2 * 7 * 24 * 60 * 60 );
	
	( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );
	$year += 1900;
	$mon++;
	
	my $old_time_str = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
		
	( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $long_time );
	$year += 1900;
	$mon++;

	my $long_time_str = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
	
	
	# If it has been a really long time, go ahead and update no matter what	
	if ( $long_time_str gt $last_update )
		{	&SaveLastExpiredTime( $current_expired, 0 + 0 );
			return( 0 + 2 );	
		}
	
	
	# Is this an hourly update?  If so, return right here
	return( 0 + 1 ) if ( $update_interval eq "Hour" );


	# Is this a daily update and is it the hour of the update time?  If so I should update right now - no sense waiting for a random time
	return( 0 + 1 ) if ( ( $update_time )  &&  ( $update_interval eq "Day" )  &&  ( $update_time == $hour ) );
	
	
	# Should I be waiting a random time?  I do this if I think the PC was turned off for a least a couple of hours
	return( undef ) if ( $random_wait );
	
	
	return( 0 + 1 ) if ( $old_time_str gt $last_update );
	
	return( undef );
}



################################################################################
#
sub GetLastExpiredTime()
#
#  Return the system time in seconds when the ExpiredTime function has been run,
#  and any random hours to wait
#  Return undef if it has never been run
#
################################################################################
{
	my $key;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );

	return( undef, undef ) if ( ! $ok );
	
	my $type;
	my $data;
	my $last_expired_time;
	my $random_wait = 0 + 0;
	
	$ok = &RegQueryValueEx( $key, "Last Update Expired Time", [], $type, $data, []) if ( ( $ok )  &&  ( $key ) );
	my $len = length( $data );
	if ( ( $ok )  &&  ( $key ) &&  ( $len > 0 ) )
		{	$last_expired_time = 0 + $data if ( $data );
		}

	$ok = &RegQueryValueEx( $key, "Last Update Random Hours", [], $type, $data, []) if ( ( $ok )  &&  ( $key ) );
	$len = length( $data );
	if ( ( $ok )  &&  ( $key )  &&  ( $len > 0 ) )
		{	$random_wait = 0 + $data if ( $data );
		}
		
	&RegCloseKey( $key );

	return( $last_expired_time, $random_wait );
}



################################################################################
#
sub SaveLastExpiredTime( $$ )
#
#  Set the system time in seconds when the ExpiredTime function was run
#  Return undef if a problem, True if OK
#
################################################################################
{	my $last_expired_time	= shift;
	my $random_wait			= shift;
	
	return( undef ) if ( ! $last_expired_time );
	
	my $key;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );

	return( undef ) if ( ! $ok );
			
	&RegSetValueEx( $key, "Last Update Expired Time", 0, REG_SZ, $last_expired_time );
	&RegSetValueEx( $key, "Last Update Random Hours", 0, REG_SZ, $random_wait );
	
	&RegCloseKey( $key );
	
	return( 1 );
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
		{	&SecurityLogEvent( "Update: Error running registry control: $msg\n" );
			return( undef, $msg );
		}
	else
		{	&SecurityLogEvent( "Update: $msg\n" ) if ( $msg );
			
			# &SecurityLogEvent( "Registry control actions:\n" );
			
			# Merge the registry actions log into the security log
			my $registry_log_file_name = &RegistryControlActionsFilename();
			if ( open( FILE, "<$registry_log_file_name" ) )	# If I can open the file, merge it into the security log
				{	my $count = 0 + 0;
					while (my $line = <FILE>)
						{	chomp( $line );
							next if ( ! $line );
							
							&SecurityLogEvent( "$line\n" );
							$count++;
						}
						
					close FILE;
					
					&SecurityLogEvent( "Update: No new registry control actions\n" ) if ( ! $count );
				}
			else
				{	&SecurityLogEvent( "Update: Error opening $registry_log_file_name: $!\n" ) if ( -e $registry_log_file_name );
				}
		}
	
	
	# Check for a hacked hosts file	
	&SecurityLogEvent( "Update: Checking for hacked hosts file ...\n" );
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
	my $system_root = $ENV{ SystemRoot };
	
	return( undef ) if ( ! $system_root );
	
	my $hosts = $system_root . "\\system32\\drivers\\etc\\hosts";
	
	return( 1 ) if ( ! -e $hosts );
	
	my $contents;
	
	open HOSTS, "<$hosts" or return( 1 );
	
	while ( my $line = <HOSTS> )
		{	$contents .= lc( $line ) if ( defined $line );
		}
			
	close HOSTS;
	
	my $problem;

	# Is there entries in the hosts file that look weird?
	foreach ( @hacked_hosts )
		{	next if ( ! $_ );
			my $host = $_;
			
			my $qhost = quotemeta( $host );
			$problem = 1 if ( $contents =~ m/$qhost/ );
		}
		
	if ( $problem )
		{	&SecurityLogEvent( "Update: Your hosts file $hosts may have been hacked - please check it immediately!\n" );
			return( undef );
		}
		
	return( 1 );
}



################################################################################
#
sub UpdateResults( $$ )
#
#  Tell the TTC Server the results of my scan, and what the security agent service has reported
#  Return True if updated ok, undef if problems
#
################################################################################
{	my $ttc_server			= shift;
	my $force_update_now	= shift;
	
	
	return( undef ) if ( ! defined $ttc_server );
	
	
	# If I'm not set to update reports, show that and return
	if ( ! $report_events )
		{	&SecurityLogEvent( "Update: Reporting Events: this PC has not checked \'Report security events to the update source\', so no events will be reported.\n" );
			&ReportBatchUnlink() if ( ! $opt_debug );
			return( undef );
		}
	
	
	# Can I send my updates back to this ttc_server using a batch results update?	
	$batch_results = 1 if ( $last_ttc_server_version );
	&SecurityLogEvent( "Update: UpdateResults: Batch reporting supported\n" ) if ( $batch_results );
	&SecurityLogEvent( "Update: UpdateResults: Batch reporting NOT supported\n" ) if ( ! $batch_results );
	
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year += 1900;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
	&ReportAddAttribute( "Security Agent Properties: Last Update Time", $datestr );
	
	
	# Report any registry control events
	&SecurityLogEvent( "Update: Reporting Events: Registry Control Events\n" );
	
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
	
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	

	# Get the last scan time I reported
	my $last_scan_reported = 0 + 0;
	$ok = &RegQueryValueEx( $key, "Last Scan Reported", [], $type, $data, []);
	my $len = length( $data );
	
	$last_scan_reported = $data if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data ) );
	$last_scan_reported = 0 + $last_scan_reported;


	# Get the last scan time I finished - this is set by the scan program
	my $last_scan_finished = 0 + 0;
	$ok = &RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, []);
	$len = length( $data );
	$last_scan_finished = $data if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data ) );
	$last_scan_finished = 0 + $last_scan_finished;

	if ( $last_scan_finished )
		{	( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $last_scan_finished );
			$year += 1900;
			$mon++;
			$datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
			&ReportAddAttribute( "Security Agent Properties: Last Scan Finished", $datestr );
		}
		
	&RegCloseKey( $key );
	

	# Report any additional security agent properties that Brock wants to see
	&ReportAddAttribute( "Security Agent Properties: TTC Server", $ttc_server );
	&ReportAddAttribute( "Security Agent Properties: Version", $version );
	&ReportAddAttribute( "Security Agent Properties: Block All Unknown", $block_all_unknown );
	&ReportAddAttribute( "Security Agent Properties: Block Failed URL Lookups", $block_failed_url_lookups );
	&ReportAddAttribute( "Security Agent Properties: Block Spyware", $block_spyware );
	&ReportAddAttribute( "Security Agent Properties: Block Unknown URLs", $block_unknown_urls );
	&ReportAddAttribute( "Security Agent Properties: Block Virus", $block_virus );
	&ReportAddAttribute( "Security Agent Properties: Block Virus Action", $block_virus_action );
	&ReportAddAttribute( "Security Agent Properties: Update Virus", $update_virus );
	&ReportAddAttribute( "Security Agent Properties: Last Virus Update", $signature_update );
	&ReportAddAttribute( "Security Agent Properties: Last File Integrity Update", $integrity_update );
	&ReportAddAttribute( "Security Agent Properties: Last File ID Update", $fileid_update );
	&ReportAddAttribute( "Security Agent Properties: Use File Integrity", $use_file_integrity );


	&SecurityLogEvent( "Update: Reporting Events: Virus Scan Events ...\n" );
	
	# If I haven't reported the last scan that finished, do so now ...
	if ( ( $ok )  &&  ( $last_scan_finished )  &&  ( $last_scan_finished ne $last_scan_reported ) )
		{	# Report any viruses that the scan program found
			&ReportScannedViruses( $ttc_server );
			

# This section has been superceded			
			# Check the TTC Server to see if it now knows some file IDs
			# Check to see if any of the unknown executables are now known
#			my ( $discovered_count, @dangerous ) = &CheckUnknownFiles( $ttc_server, $working_dir, $opt_debug );


			# If I did figure out some of the unknown files, let the Security Agent service know about it
#			if ( $discovered_count > 0 )
#				{	&SecurityLogEvent( "Update: Updated $discovered_count unknown executables as now known\n" ) if ( $discovered_count > 0 );

					# Signal the Security Agent service
#					&SignalService();
#				}
			
			# Since I've reported my unknown file to the TTC server, get rid of the unknown log
#			my $unknown_log = $working_dir . "\\Unknown.log";
#			if ( -e $unknown_log )
#				{	$ok = unlink $unknown_log;
#					&SecurityLogEvent( "Update: Error deleting file $unknown_log: $!\n" ) if ( ! $ok );
#				}
# end of superceded section	
	
			# Save that I did this it back into the registry
			$last_scan_reported = $last_scan_finished;
			$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );	
			&RegSetValueEx( $key, "Last Scan Reported", 0, REG_SZ, $last_scan_reported ) if ( ( $last_scan_reported )  &&  ( $ok ) );

			&RegCloseKey( $key ) if ( $ok );
		}	# end if if last_scan_reported ne $last_scan
	

	&SecurityLogEvent( "Update: Reporting Events: Current SA Service Action Events ...\n" );
	
	# Report any detected viruses, blocked unknown programs, etc ...
	if ( ( $agent_report_file )  &&  ( -e $agent_report_file ) )
		{	&ReportServiceActions( $ttc_server, $agent_report_file );
		}
	
	
	# See if there are any old reports from the security agent service in the tmp directory
	&SecurityLogEvent( "Update: Reporting Events: Old SA Service Action Events ...\n" );
	
	
	# If I can open the tmp directory, see if there are any old events to report
	my $tmp_dir = &ScanTmpDirectory();
	if ( opendir( DIRHANDLE, $tmp_dir ) )
		{	for my $item ( readdir( DIRHANDLE ) )
				{	next if ( ! $item );
					
					my $lc_item = lc( $item );
					
					# Ignore the file "actions.txt" itself - this is the current file that the service is adding to
					next if ( $lc_item eq "actions.txt" );
				
					next if ( ! ( $lc_item =~ m/\.txt$/ ) );	# The file has to end in .txt
					next if ( ! ( $lc_item =~ m/^actions/ ) );	# The file has to start with actions
					
					my $full_path = $tmp_dir . "\\$item";

					# Is it a zero length file?
					if ( ! -s $full_path )
						{	unlink( $full_path );
							next;	
						}
						
					next if ( ! -f $full_path );	# Is it a regular file?
					next if ( ! -T $full_path );	# Is it a text file?
					next if ( ! -w $full_path );	# Can I write to it? as a test for if I can delete it


					&ReportServiceActions( $ttc_server, $full_path );
				}
				
			closedir( DIRHANDLE );
		}
	
	
	# Report the policy complience events
	&SecurityLogEvent( "Update: Reporting Events: Policy Complience Events ...\n" );
	
	&ReportPolicyComplience( $ttc_server );
	
	
	# If I'm batching stuff up, then I need to actually send it into the ttc_server now ...
	if ( $batch_results )
		{	my $last_attribute_report;
			my $report_attributes;
			$report_attributes = 1 if ( $force_update_now );
			
		 	my $key;
			my $type;
			my $data;
	
			my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );
			
			if ( $ok )
				{	$data = undef;
					&RegQueryValueEx( $key, "Last System Information Report", [], $type, $data, []);
					my $len = length( $data );
					
					$report_attributes = 1 if ( ! $ok );
					$last_attribute_report = $data if ( ( $ok )  &&  ( $len > 0 ) );
				}
			else
				{	$report_attributes = 1;
				}


			# Has a day gone by since I last reported?
			# Expired time returns 2 if it's been a long time, 1 if it need a normal update, or undef if current
			$report_attributes = &ExpiredTime( "Day", $last_attribute_report, $update_time ) if ( ! $report_attributes );

			
			# Report the attributes if I haven't reported today ...
			&ReportAttributes() if ( $report_attributes );


			if ( ( $ok )  &&  ( $report_attributes ) )
				{	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
					$year += 1900;
					$mon++;
					$last_attribute_report = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
					
					&RegSetValueEx( $key, "Last System Information Report", 0,  REG_SZ, $last_attribute_report );
				}
				
	
			&RegCloseKey( $key ) if ( $ok );
			
			# Now send whatever events I have batch recorded
			$ok = &ReportBatchSend( $ttc_server ) ;
		}
	
	&ReportBatchUnlink() if ( ! $opt_debug );
	
	# Return ok
	return( $ok );	
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
		{	&SecurityLogEvent( "Update: Unable to open policy compliance log file $file: $!\n" );
			return( undef );
		}
		
	my $event_count = 0 + 0;
	my $ok = 1;
	
	while (my $line = <FILE>)
		{	chomp( $line );
			next if ( ! defined $line );
			
			my ( $datestr, $username, $computer, $domain, $ou, $policy, $policy_type, $description ) = split /\t/, $line;
			
			next if ( ! $datestr );
			next if ( ! $username );
			next if ( ! $policy );
			next if ( ! $description );
			
			$domain		= undef if ( $domain	eq "N/A" );
			$computer	= undef if ( $computer	eq "N/A" );
			$ou			= undef if ( $ou		eq "N/A" );
			
			if ( $batch_results )
				{	$ok = &ReportBatch( "PolicyComplience", $datestr, $username, $computer, $domain, $ou, $policy, $policy_type, $description );
				}
			else
				{	$ok = &ReportPolicyEvent( $ttc_server, $datestr, $username, $computer, $domain, $ou, $policy, $policy_type, $description );
				}
			
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
		}
	
	close FILE;
	
	if ( $ok )
		{	$ok = unlink $file;
			&SecurityLogEvent( "Update: Error deleting file $file: $!\n" ) if ( ! $ok );
		}
		
	&SecurityLogEvent( "Update: Reported $event_count policy events back to $ttc_server\n" ) if ( $event_count > 0 );
	
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
		{	&SecurityLogEvent( "Update: Unable to open security event file $agent_report_file: $!\n" );
			return( undef );
		}
	
	&SecurityLogEvent( "Update: Reporting service actions from file $agent_report_file\n" );	

	my $event_count = 0 + 0;
	my $ok = 1;
	my $last_unique;
	
	while (my $line = <FILE>)
		{	chomp( $line );
			next if ( ! defined $line );
			
			my ( $date, $time, $file, $action, $username, $option1, $option2, $option3 ) = split /\t/, $line;
			
			next if ( ! defined $date );
			next if ( ! defined $time );
			next if ( ! defined $file );
			next if ( ! defined $action );
			
			my $removable_media;	# Flag to indicate if it is a removable media action
			my $virus		= "";
			my $file_id		= "";
			$username	= "" if ( ! defined $username );
			
			# Does the action say Virus blocked?  Then the action has the virus name stuck in it, so clean it up
			if ( $action =~ m/Virus blocked/i )
				{	$virus = $action;
					$virus =~ s/^Virus blocked \(//;
					$virus =~ s/\)$//;
					$action = "Virus blocked";
					
					$file_id = $option2 if ( defined $option2 );
					$file_id = $option1 if ( ( defined $option1 )  &&  ( $file_id eq "" ) );
				}
			
			# Does the action say "Unknown DLL blocked" or "Unknown DLL"?  Then I should report the .dll and not the .exe
			elsif ( $action =~ m/Unknown DLL/i )
				{	$file_id = $option2 if ( defined $option2 );
					$file = $option1 if ( defined $option1 );
				}
			
			# Does the action say "Unknown process"?
			elsif ( $action =~ m/Unknown process/i )
				{	$file_id = $option2 if ( defined $option2 );
					$file_id = $option1 if ( ( defined $option1 )  &&  ( $file_id eq "" ) );
				}
			
			# Does the action say "Create process blocked"?
			elsif ( $action =~ m/Create process blocked/i )
				{	$file_id = $option2 if ( defined $option2 );
					$file_id = $option1 if ( ( defined $option1 )  &&  ( $file_id eq "" ) );
				}
			
			# Does the action say "removable media"?
			elsif ( $action =~ m/removable media/i )
				{	$removable_media = 1;
					$file_id = $option2 if ( defined $option2 );
					$file_id = $option1 if ( ( defined $option1 )  &&  ( $file_id eq "" ) );
				}
			
			# Or is it some entirely new service action that I don't know the format
			else
				{	# Well, I'm going to guess that the file ID is one of the option fields
					$file_id = $option3 if ( defined $option3 );
					$file_id = $option2 if ( ( defined $option2 )  &&  ( $file_id eq "" ) );
					$file_id = $option1 if ( ( defined $option1 )  &&  ( $file_id eq "" ) );
				}
			
			
			# Clean up the file ID	
			$file_id = "" if ( ! defined $file_id );
			$file_id = "" if ( $file_id =~ m/^0+$/ );		# A file ID of all 0's means blank
			$file_id = "" if ( length( $file_id ) != 56 );	# make sure the file ID is the right length
			
			$username = "" if ( ! defined $username );
			
			my $unique = $file . $virus . $action . $username . $file_id;
			
			# Don't flood the reporting with the same file name
			next if ( ( defined $last_unique )  &&  ( $last_unique eq $unique ) );
			
			$last_unique = $unique;
			
			my $datestr = "$date $time";


			&SecurityLogEvent( "Update: Security event: $datestr $virus\: $action\: $file\n" ) if ( $virus );
			&SecurityLogEvent( "Update: Security event: $datestr $action\: $file\n" ) if ( ! $virus );
			
			if ( $batch_results )
				{	if ( $removable_media )
						{	$ok = &ReportBatch( "RemovableMedia", $datestr, $username, $file, $option1, $action );							
						}
					else
						{	$ok = &ReportBatch( "ServiceActions", $datestr, $file, $action, $username, $file_id, $virus );
						}
				}
			else
				{	$ok = &ReportSecurityEvent( $ttc_server, $datestr, $file, $virus, $action, $username, $opt_debug );
				}
				
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
			
			
			# If the action is an unknown program or dll, then tell the server about the file IDs, etc
			my $lc_action = lc( $action );
			
			next if ( ! ( $lc_action =~ m/unknown/ ) );
			
			my ( $ret, $category_num, $network_permissions ) = &FileIntegrityReportUnknown( $ttc_server, $file );
		}
	
	close FILE;


	if ( $ok )
		{	$ok = unlink $agent_report_file;
			&SecurityLogEvent( "Update: Error deleting file $agent_report_file: $!\n" ) if ( ! $ok );
		}
		
	&SecurityLogEvent( "Update: Reported $event_count security service actions back to $ttc_server\n" ) if ( $event_count > 0 );
	
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
		{	&SecurityLogEvent( "Update: Unable to open virus log file $file: $!\n" );
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
	
	while (my $line = <FILE>)
		{	chomp( $line );
			next if ( ! defined $line );
			
			# If the line in the virus log has the word Infection, then it is an infection
			next if ( ! ( $line =~ m/Infection/ ) );
		
			my ( $file, $junk, $virus, $action ) = split /\: /, $line;
			
			next if ( ! defined $virus );
			next if ( ! defined $file );

			$action = "Report only" if ( ! defined $action );			
			
			if ( $batch_results )
				{	# Just ignore this in batch mode - I am already reporting this via the ScanAppProcess.dat file
					# $ok = &ReportBatch( "ScannedVirus", $datestr, $file, $virus, $action, "Scan" );
					$ok = 1;
				}
			else
				{	$ok = &ReportSecurityEvent( $ttc_server, $datestr, $file, $virus, $action, "Scan", $opt_debug );
				}
				
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
		}
	
	close FILE;
						
	# Did I send all the viruses back to TTC ok?
	if ( $ok )
		{	$ok = unlink( $file );
			&SecurityLogEvent( "Update: Error deleting file $file: $!\n" ) if ( ! $ok );
		}
		
	&SecurityLogEvent( "Update: Reported $event_count viruses detected by the scan program back to $ttc_server\n" ) if ( $event_count );
		
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
		{	&SecurityLogEvent( "Update: Unable to open registry control file $agent_report_file: $!\n" );
			return( undef );
		}
		
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $last_scan );
	$year += 1900;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
		
		
	my $event_count = 0 + 0;
	my $ok = 1;
	
	while (my $line = <FILE>)
		{	chomp( $line );
			next if ( ! defined $line );
			
			my $key;
			my $valname;
			my $valtype;
			my $oldvalue;
			my $newvalue;
			my $time = $datestr;
			my $action;
			my $clientip;
			
			
			my ( $desc, $val ) = split /:/, $line, 2;
			$val =~ s/^\s+// if ( defined $val );	# Get rid of leading spaces
			
			if ( $desc =~ m/Changed Key/i )
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
			elsif ( $desc =~ m/Deleted Key/i )
				{	$action = "Deleted Key";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$valtype = &GetValue( $line, "Type" );
					$line = <FILE>;
					$oldvalue = &GetValue( $line, "Value" );
				}
			elsif ( $desc =~ m/Added Key/i )
				{	$action = "Added Key";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$valtype = &GetValue( $line, "Type" );
					$line = <FILE>;
					$newvalue = &GetValue( $line, "Value" );
					
				}
			elsif ( $desc =~ m/Control Set/i )
				{	$action = "Control Set";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$newvalue = &GetValue( $line, "Value" );					
				}
			elsif ( $desc =~ m/Control Delete/i )
				{	$action = "Control Delete";
					$key = $val;
					$line = <FILE>;
					$valname = &GetValue( $line, "Name" );
					$line = <FILE>;
					$oldvalue = &GetValue( $line, "Value" );					
				}
			else
				{	&SecurityLogEvent( "Update: Unknown registry event: desc = $desc, value = $line\n" );
					next;
				}
			
			if ( $batch_results )
				{	$ok = &ReportBatch( "RegistryEvent", $key, $valname, $valtype, $oldvalue, $newvalue, $time, $action );
				}
			else
				{	$ok = &ReportRegistryEvent( $ttc_server, $key, $valname, $valtype, $oldvalue, $newvalue, $time, $action );
				}
				
			$event_count++ if ( $ok );
			
			last if ( ! $ok );
		}
	
	close FILE;
	
	
	# Did I send all the registry events back to TTC ok?
	if ( $ok )
		{	$ok = unlink $agent_report_file;
			&SecurityLogEvent( "Update: Error deleting file $agent_report_file: $!\n" ) if ( ! $ok );
		}
		
		
	&SecurityLogEvent( "Update: Reported $event_count registry actions back to $ttc_server\n" ) if ( $event_count > 0 );
	
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
		{	&SecurityLogEvent( "Update: Bad parameter in registry file: $line\n" );
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
			my $lc_item = lc( $item );
			
			
			# Don't delete the current actions.txt file
			next if ( $lc_item =~ m/actions\.txt/ );
		
			
			next if ( ! ( $lc_item =~ m/\.txt$/ ) );	# The file has to end in .txt
			next if ( ! ( $lc_item =~ m/^actions/ ) );	# The file has to start with actions
			
			
			my $full_path = $tmp_dir . "\\$item";

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
	
	if ( &ProcessRunningName( "SecurityAgent.exe" ) )
		{	print "Stopping the Security Agent service ...\n";
			system( "net stop \"Security Agent Service\"" );
		}
	
	
	# Get all the directories that I might have created
	my $working_dir		= &ScanWorkingDirectory();
	my $system_dir		= &ScanSystemDirectory();
	my $tmp_dir			= &ScanTmpDirectory();
	my $scan_temp_dir	= &ScanTempDirectory();
	my $quarantine		= &ScanQuarantineDirectory();
	my $system32_dir	= &ScanSystemDirectory();
	my $log_dir			= &ScanLogDirectory();


	if ( ! -e $working_dir )
		{	print "Unable to find the working directory: $working_dir\n";
			return( undef );
		}
		
	
	if ( ! -e $system32_dir )
		{	print "Unable to find the SYSTEM32 directory: $system32_dir\n";
			return( undef );
		}
		
	
	# Do I need to uninstall the shell extension?
	if ( ( -e "SecurityAgentShellExt.dll" )  &&  ( &ShellEnabled() ) )
		{	print "Uninstalling the shell extension ...\n";
			chdir( $working_dir );
			
			system "regsvr32 \/u \/s securityagentshellext.dll";
			
			# Todd says to not restart explorer here
			# &RestartExplorer();
		}
						
	
	# Do I need to uninstall the BHO?
	&SetUseBHOStatus( undef );
						
	
	# Do I need to uninstall the LSP?
	&SetUseLSPStatus( 1 );
						

	# Signal the manager to die
	&KillManager();
	
	
	# Kill any of our processes that are running
	&ProcessKillName( "Scan.exe" );
	&ProcessKillName( "satray.exe" );
	&ProcessKillName( "sascan.exe" );
	&ProcessKillName( "saexplorer.exe" );
	&ProcessKillName( "sadash.exe" );
	&ProcessKillName( "saalert.exe" );
		
	
	#  Delete all the Security Agent registry keys
	my $key;
	my $type;
	my $data;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems", 0, KEY_ALL_ACCESS, $key );
	if ( $ok )
	{	&RegDeleteKey( $key, "SecurityAgent\\Last Document Activity Times" );
		&RegDeleteKey( $key, "SecurityAgent\\Current User" );
		&RegDeleteKey( $key, "SecurityAgent" );
		&RegCloseKey( $key );
	}


	&CleanUpFiles( $working_dir, undef );

	&ReportBatchUnlink();
	
	# Delete all the log files and data files
	my @delete_list;	
	push @delete_list, "$working_dir\\scan.log";
	push @delete_list, "$working_dir\\scan2.log";
	push @delete_list, "$working_dir\\scan.new";
	push @delete_list, "$working_dir\\sascan.exe";
	push @delete_list, "$working_dir\\saexplorer.exe";
	push @delete_list, "$working_dir\\ScanErrors.log";
	push @delete_list, "$working_dir\\ScanAppProcess.dat";
	push @delete_list, "$working_dir\\Security.log";
	push @delete_list, "$working_dir\\Unknown.log";
	push @delete_list, "$working_dir\\UpdateErrors.log";
	push @delete_list, "$working_dir\\UpdateEvents.dat";
	push @delete_list, "$working_dir\\UpdateID.dat";
	push @delete_list, "$working_dir\\History.log";
	push @delete_list, "$working_dir\\History.bak";
	push @delete_list, "$working_dir\\Category.dat";
	push @delete_list, "$working_dir\\Disinfect.dat";
	push @delete_list, "$working_dir\\BannedProcess.dat";
	push @delete_list, "$working_dir\\RegistryControl.dat";
	push @delete_list, "$working_dir\\RegistryMonitor.dat";
	push @delete_list, "$working_dir\\RegistryChanges.log";
	push @delete_list, "$working_dir\\RegistryActions.log";
	push @delete_list, "$working_dir\\RegistryHistory.log";
	push @delete_list, "$working_dir\\Quarantine.log";
	push @delete_list, "$working_dir\\Policy.dat";
	push @delete_list, "$working_dir\\PolicyDefinition.dat";
	push @delete_list, "$working_dir\\PolicyComplience.log";
	push @delete_list, "$working_dir\\RequiredSoftware.dat";
	push @delete_list, "$working_dir\\UpdateTimes.dat";
	push @delete_list, "$working_dir\\sa6package.txt";
	push @delete_list, "$working_dir\\sa62package.txt";
	push @delete_list, "$working_dir\\sa7package.txt";
	push @delete_list, "$working_dir\\status.zip";
	push @delete_list, "$working_dir\\Autorun.log";
	push @delete_list, "$working_dir\\Registry.log";
	push @delete_list, "$working_dir\\Process.log";
	push @delete_list, "$working_dir\\Virus.log";
	push @delete_list, "$working_dir\\SAHelp.chm";
	push @delete_list, "$working_dir\\SAExport.htm";
	push @delete_list, "$working_dir\\msvcr71.dll";
	push @delete_list, "$working_dir\\SecurityAgentShellExt.dll";
	push @delete_list, "$working_dir\\SecurityAgentBHO.dll";
	push @delete_list, "$working_dir\\SigDesign.exe";
	push @delete_list, "$working_dir\\VirusSignatures.old";
	push @delete_list, "$working_dir\\VirusSignatures";
	push @delete_list, "$working_dir\\FileIntegrity";
	
	push @delete_list, "$working_dir\\arrow.gif";
	push @delete_list, "$working_dir\\bg.gif";
	push @delete_list, "$working_dir\\policy_blocked_banner.gif";
	push @delete_list, "$working_dir\\RequiredSoftware.html";
	push @delete_list, "$working_dir\\salsp.new";
	
	push @delete_list, "$working_dir\\SA7Update.htm";
	push @delete_list, "$working_dir\\SA62Update.htm";
	push @delete_list, "$working_dir\\SA6Update.htm";
	
	push @delete_list, "$working_dir\\SA7Update.new";
	push @delete_list, "$working_dir\\SA62Update.new";
	push @delete_list, "$working_dir\\SA6Update.new";
	
	push @delete_list, "$working_dir\\SA7Update.old";
	push @delete_list, "$working_dir\\SA62Update.old";
	push @delete_list, "$working_dir\\SA6Update.old";
	
	push @delete_list, "$system_dir\\FileIntegrity";
	push @delete_list, "$system_dir\\FileIntegrity.bad";
	push @delete_list, "$system_dir\\FileIntegrity.bak1";
	push @delete_list, "$system_dir\\FileIntegrity.bak2";
	push @delete_list, "$system_dir\\FileIntegrity.bak3";
	push @delete_list, "$system_dir\\VirusSignatures";
	push @delete_list, "$system_dir\\VirusSignatures.nx";
	push @delete_list, "$system_dir\\AllowSignatures";
	push @delete_list, "$system_dir\\CustomSignatures";

	push @delete_list, "$system_dir\\FileID.dat";
	push @delete_list, "$system_dir\\FileID.def";
	push @delete_list, "$system_dir\\FileID.idx";
	push @delete_list, "$system_dir\\FileID.idl";
	push @delete_list, "$system_dir\\FileID.dat.bak";
	push @delete_list, "$system_dir\\FileID.def.bak";
	push @delete_list, "$system_dir\\FileID.idx.bak";
	push @delete_list, "$system_dir\\FileID.idl.bak";
	push @delete_list, "$system_dir\\FileID.dat.bak1";
	push @delete_list, "$system_dir\\FileID.def.bak1";
	push @delete_list, "$system_dir\\FileID.idx.bak1";
	push @delete_list, "$system_dir\\FileID.idl.bak1";
	push @delete_list, "$system_dir\\IpmSecurityAgent.sys";
	
	push @delete_list, "$system32_dir\\salsp.dll";
	push @delete_list, "$system32_dir\\salsp.old";

	push @delete_list, "$system32_dir\\sporder.dll";
	push @delete_list, "$working_dir\\sporder.dll";	# This could be in both places
	push @delete_list, "$system32_dir\\sporder.old";
	
	push @delete_list, "$working_dir\\scanclient.dll";
	push @delete_list, "$working_dir\\scanclient.old";
	push @delete_list, "$working_dir\\scanclient.new";
	

	print "Deleting working files ...\n";
	foreach ( @delete_list )
		{	next if ( ! defined $_ );
			my $file = $_;
			unlink( $file );
		}
		

	if ( -d $tmp_dir )
		{	print "Removing tmp directory $tmp_dir ...\n";
			my $cmd = "rmdir \"$tmp_dir\" \/s \/q";
			system( $cmd );
			print "Removed tmp directory\n" if ( ! -d $tmp_dir );
			print "Unable to remove tmp directory\n" if ( -d $tmp_dir );
		}
		
	if ( -d $scan_temp_dir )
		{	print "Removing ScanTemp directory $scan_temp_dir ...\n";
			my $cmd = "rmdir \"$scan_temp_dir\" \/s \/q";
			system( $cmd );
			print "Removed ScanTemp directory\n" if ( ! -d $scan_temp_dir );
			print "Unable to remove ScanTemp directory\n" if ( -d $scan_temp_dir );
		}
		
	if ( -d $quarantine )
		{	print "Removing quarantine directory $quarantine ...\n";
			my $cmd = "rmdir \"$quarantine\" \/s \/q";
			system( $cmd );
			print "Removed quarantine directory\n" if ( ! -d $quarantine );
			print "Unable to remove quarantine directory\n" if ( -d $quarantine );
		}
	
	if ( -d $log_dir )
		{	print "Removing log directory $log_dir ...\n";
			my $cmd = "rmdir \"$log_dir\" \/s \/q";
			system( $cmd );
			print "Removed log directory\n" if ( ! -d $log_dir );
			print "Unable to remove log directory\n" if ( -d $log_dir );
		}
		
	
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
		{	&SecurityLogEvent( "Update: Can not find SecurityAgentShellExt.dll\n" );
			return( undef );
		}
		
	if ( $enable_shell )	
		{	&SecurityLogEvent( "Update: Loading the Security Agent shell extension ...\n" );
			system "regsvr32 \/s securityagentshellext.dll";
		}
	else
		{	&SecurityLogEvent( "Update: Unloadeding the Security Agent shell extension ...\n" );
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
	my $ok = &RegOpenKeyEx( HKEY_CLASSES_ROOT, "*\\shellex\\PropertySheetHandlers\\{C374FD5E-0CB4-4CCE-B4FB-8F5BFB3F4454}", 0, KEY_READ, $key );
	&RegCloseKey( $key ) if ( $ok );
	
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
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );	
	return( undef ) if ( ! $ok );

	my $data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_shell );
	&RegSetValueEx( $key, "Enable Shell", 0,  REG_DWORD, $data );

	&RegCloseKey( $key ) if ( $ok );
	
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
			my $ok = Win32::Process::Create( $explorer_process, $fullpath, "explorer", 0, NORMAL_PRIORITY_CLASS, $system_root );	
			
			if ( ! $ok )
				{	my $str = Win32::FormatMessage( Win32::GetLastError() );
					print "Error relaunching $fullpath = $str\n";
				}
		}
		
	return( 1 );
}



################################################################################
#
sub DownloadProperties( $ )
#
#  Download the Security Agent properties
#  Return True if downloaded the properties and they changed, 
#  0 if they didn't change, or undef if an error
#
################################################################################
{	my $ttc_server	= shift;
	
	my $done;
	my $counter;
	
	&SecurityLogEvent( "Update: Downloading Security Agent properties from server $ttc_server ...\n" );
	
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
			&SecurityLogEvent( "Update: Unable to get Security Agent properties from $ttc_server: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&SecurityLogEvent( "Update: Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		} 
		

	my @lines = split /\n/, $content;

	# Keep count of how many lines of data I've received
	if ( $#lines < ( 0 + 0 ) )
		{	&SecurityLogEvent( "Update: No response from $ttc_server - will try later\n" );	
			return( undef );
		} 
			

	$content = undef;
	
	
	# This is a comma delimited list
	my $ttc_servers_list = &UpdateGetTTCServersList();
	my $new_ttc_servers_list			= $ttc_servers_list;

	my $new_update_interval				= $update_interval;	
	my $new_interactive_mode			= $interactive_mode;
	
	my $new_scan_system					= undef;
	$new_scan_system					= "1" if ( $scan_system );
	
	my $new_block_virus					= undef;	
	$new_block_virus					= "1" if ( $block_virus );	
	
	my $new_block_virus_action			= $block_virus_action;	
		
	my $new_scan_content				= undef;
	$new_scan_content					= "1" if ( $scan_content );
	my $url_scan_content = "FileExtension";
	$url_scan_content = "ContentAndFileExtension" if ( $scan_content );

	my $new_block_spyware				= undef;
	$new_block_spyware					= "1" if ( $block_spyware );
	
	# This is a comma delimited list
	my $new_scan_exclusions				= $scan_exclusions;

	my $new_removable_media_permissions = $removable_media_permissions;
	
	my $new_server_properties			= undef;
	$new_server_properties				= "1" if ( $server_properties );
	
	my $new_block_all_unknown			= undef;
	$new_block_all_unknown				= "1" if ( $block_all_unknown );
	
	my $new_scan_interval				= $scan_interval;	
	my $new_scan_time					= $scan_time;	
	my $new_scan_type					= $scan_type;	
	my $new_scan_job_percent			= $scan_job_percent;
	
	my $new_update_time					= $update_time;
	
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
	
	
	my $new_known_permissions			= $known_permissions ;
	my $new_unknown_permissions			= $unknown_permissions;
	

	# LDAP parameters
	my $new_novell_ldap_root			= $novell_ldap_root;
	my $new_novell_ldap_root2			= undef;

	my $new_novell_ldap_server			= $novell_ldap_server;
	my $new_uid_attribute				= $uid_attribute;
	my $new_group_attribute				= $group_attribute;
	my $new_protocol_version			= $protocol_version;
	my $new_novell_precedence			= $novell_precedence;
	
	
	# Content filtering parameters
	my $new_enable_content_filtering	= undef;
	$new_enable_content_filtering		= "1" if ( $enable_content_filtering );
	
	my $new_block_unknown_urls			= undef;
	$new_block_unknown_urls				= "1" if ( $block_unknown_urls );
	
	my $new_block_failed_url_lookups	= undef;
	$new_block_failed_url_lookups		= "1" if ( $block_failed_url_lookups );
	
	# This is a comma delimited list
	my $new_content_filtering_servers	= $content_filtering_servers;
	
	
	my $url_scan_time = "$scan_time am";
	my $pm = $scan_time - 12;
	$url_scan_time = "$pm pm" if ( $scan_time >= 12 );
	$url_scan_time = "12 am" if ( ! $scan_time );	# 0 military time is 12 am
	$url_scan_time = "12 pm" if ( $scan_time == 12 );
	
	
	my $url_update_time;
	if ( $update_time )
		{	$url_update_time = "$update_time am";
			my $pm = $update_time - 12;
			$url_update_time = "$pm pm" if ( $update_time >= 12 );
			$url_update_time = "12 am" if ( ! $update_time );	# 0 military time is 12 am
			$url_update_time = "12 pm" if ( $update_time == 12 );
		}
	
		
	foreach( @lines )
		{	my $line = $_;
			chomp( $line );
			
			# Clean up the line
			$line =~ s/^\t.//;
			$line =~ s/^\s*//;
			$line =~ s/\s*$//;
			
			next if ( ! defined $line );


			$new_update_interval			= &ValueExtract( $line, "UpdateInterval", $new_update_interval );

			$new_interactive_mode			= &ValueExtract( $line, "InteractiveMode", $new_interactive_mode );
			
			$new_scan_system				= &ValueExtract( $line, "ScanEntirePCforViruses", $new_scan_system );
			
			$new_block_virus				= &ValueExtract( $line, "BlockVirus", $new_block_virus );			
			$new_block_virus_action			= &ValueExtract( $line, "BlockVirusAction", $new_block_virus_action );
			
			$new_block_spyware				= &ValueExtract( $line, "RemoveSpyware", $new_block_spyware );
			
			$new_server_properties			= &ValueExtract( $line, "ServerProperties", $new_server_properties );
			
			$new_block_all_unknown			= &ValueExtract( $line, "BlockAllUnknown", $new_block_all_unknown );
			
			$new_scan_interval				= &ValueExtract( $line, "ScanDayofWeek", $new_scan_interval );			
			$url_scan_time					= &ValueExtract( $line, "ScanTimeofDay", $url_scan_time );	
			$new_scan_type					= &ValueExtract( $line, "ScanType", $new_scan_type );	
			
			$url_scan_content				= &ValueExtract( $line, "ScanFilesBy", $url_scan_content );			
			
			$url_update_time				= &ValueExtract( $line, "UpdateTimeofDay", $url_scan_time );	

			$new_use_file_integrity			= &ValueExtract( $line, "UseFileIntegrity", $new_use_file_integrity );			

			$new_report_events				= &ValueExtract( $line, "ReportSecurityEvents", $new_report_events );			

			$new_only_protected				= &ValueExtract( $line, "AllowProtectedPCsOnly", $new_only_protected );
			
			$new_enable_shell				= &ValueExtract( $line, "ShowProgramPermissionsWithFileProperties", $new_enable_shell );
			
			$new_enable_manager				= &ValueExtract( $line, "ShowSystemTrayIcon", $new_enable_manager );
			
			$new_enable_alerts				= &ValueExtract( $line, "EnableAlerts", $new_enable_alerts );

			$new_known_permissions			= &ValueExtract( $line, "KnownProgramPermissions", $new_known_permissions );			
			$new_unknown_permissions		= &ValueExtract( $line, "UnknownProgramPermissions", $new_unknown_permissions );				

			$new_removable_media_permissions = &ValueExtract( $line, "RemovableMediaPermissions", 0 + 7 );	# Default this to everything allowed if RemovableMediaPermissions are not in the line
																	
			# Check for both values for the root DN
			$new_novell_ldap_root			= &ValueExtract( $line, "LDAPRoot", $new_novell_ldap_root );				
			$new_novell_ldap_root2			= &ValueExtract( $line, "LDAPBaseDN", $new_novell_ldap_root2 );				
			
			$new_novell_ldap_server			= &ValueExtract( $line, "LDAPServer", $new_novell_ldap_server );				
			$new_uid_attribute				= &ValueExtract( $line, "LDAPUIDAttribute", $new_uid_attribute );				
			$new_group_attribute			= &ValueExtract( $line, "LDAPGroupAttribute", $new_group_attribute );				
			$new_protocol_version			= &ValueExtract( $line, "LDAPProtocolVersion", $new_protocol_version );	
			$new_novell_precedence			= &ValueExtract( $line, "NovellPrecedence", $new_novell_precedence );	

			# Content filtering parameters
			$new_enable_content_filtering	= &ValueExtract( $line, "EnableContentFiltering", $new_enable_content_filtering );	
			$new_block_unknown_urls			= &ValueExtract( $line, "BlockUnknownURLs", $new_block_unknown_urls );	
			$new_block_failed_url_lookups	= &ValueExtract( $line, "BlockFailedURLLookups", $new_block_failed_url_lookups );	
			$new_content_filtering_servers	= &ValueExtract( $line, "ContentFilteringServers", $new_content_filtering_servers );				

			$new_scan_exclusions			= &ValueExtract( $line, "ScanExclusions", $new_scan_exclusions );				

			$new_ttc_servers_list			= &ValueExtract( $line, "TTCServersList", $new_ttc_servers_list );				

			$new_scan_job_percent			= &ValueExtract( $line, "ScanJobPercent", $new_scan_job_percent );				
		}
	

	$new_novell_ldap_root = $new_novell_ldap_root2 if ($new_novell_ldap_root2);

	my $changed = 0 + 0;
	
			
	$changed = 1 if ( &ChangedValue( $update_interval, $new_update_interval, "Update Interval" ) );
	
	$new_interactive_mode = &BinaryValue( $new_interactive_mode );
	$changed = 1 if ( &ChangedValue( $interactive_mode, $new_interactive_mode, "Interactive Mode" ) );

	$new_block_virus = &BinaryValue( $new_block_virus );
	$changed = 1 if ( &ChangedValue( $block_virus, $new_block_virus, "Enable Active Threat Scanning" ) );
	
	$changed = 1 if ( &ChangedValue( $block_virus_action, $new_block_virus_action, "Block Virus Action" ) );
	
	$new_block_spyware = &BinaryValue( $new_block_spyware );
	$changed = 1 if ( &ChangedValue( $block_spyware, $new_block_spyware, "Block Spyware" ) );
	
	$new_server_properties = &BinaryValue( $new_server_properties );
	my $property_control_changed;
	$property_control_changed = 1 if ( &ChangedValue( $server_properties, $new_server_properties, "Security Agent Property Control" ) );
	
	
	# Show who is now in charge of the Security Agent properties
	if ( $property_control_changed )
		{	&SecurityLogEvent( "Update: Security Agent Property Control has been changed by $ttc_server.\n" );
			
			if ( $manual_properties )
				{	&SecurityLogEvent( "Update: Security Agent Property Control: Set by a local user\n" );
					&SecurityLogEvent( "Update: Security Agent properties can not be changed from server $ttc_server.\n" );
				}
				
			if ( $server_properties )
				{	&SecurityLogEvent( "Update: Security Agent Property Control: Set from server $ttc_server.\n" );
					&SecurityLogEvent( "Update: Security Agent properties can not be changed by a local user.\n" );
				}
				
				
			if ( ( ! $server_properties )  &&  ( ! $manual_properties ) )
				{	&SecurityLogEvent( "Update: Security Agent Property Control: Set by either server $ttc_server or local user\n" );
					&SecurityLogEvent( "Update: Security Agent properties can be changed by both a local user and from server $ttc_server.\n" );
				}
				
			$changed = 1;
		}
	
	
	$new_block_all_unknown = &BinaryValue( $new_block_all_unknown );
	$changed = 1 if ( &ChangedValue( $block_all_unknown, $new_block_all_unknown, "Block All Unknown Programs" ) );
	
	$new_scan_system = &BinaryValue( $new_scan_system );
	$changed = 1 if ( &ChangedValue( $scan_system, $new_scan_system, "Scan System For Viruses" ) );
	
	$changed = 1 if ( &ChangedValue( $scan_interval, $new_scan_interval, "Scan Interval" ) );
	
	my ( $hour, $meridian ) = split /\s/, $url_scan_time;
	$hour = 0 + $hour;
	$new_scan_time = 0 + $hour;
	$new_scan_time = 12 + $hour if ( ( $meridian )  &&  ( $meridian eq "pm" )  &&  ( $hour < 12 ) );
	$new_scan_time = 0 + 0 if ( ( $meridian )  &&  ( $meridian eq "am" )  &&  ( $hour == 12 ) );

	# Check for crazy values for the scan time
	$new_scan_time = 0 + 12 if ( $new_scan_time >= 24 );
	$new_scan_time = 0 + 0 if ( $new_scan_time < 0 );

	$changed = 1 if ( &ChangedValue( $scan_time, $new_scan_time ) );
	
	
	# Make sure the scan type is either "quick" or "full"
	$new_scan_type = lc( $new_scan_type ) if ( $new_scan_type );
	$new_scan_type = "quick" if ( ! $new_scan_type );
	$new_scan_type = "quick" if ( ( $new_scan_type ne "quick" )  &&  ( $new_scan_type ne "full" ) );
	$changed = 1 if ( &ChangedValue( $scan_type, $new_scan_type ) );
	
	$changed = 1 if ( &ChangedValue( $scan_job_percent, $new_scan_job_percent ) );
	
	$new_scan_content = undef;
	$new_scan_content = "1" if ( ( $url_scan_content )  &&  ( $url_scan_content ne "FileExtension" ) );
	$changed = 1 if ( &ChangedValue( $scan_content, $new_scan_content, "Scan By Content" ) );

	$changed = 1 if ( &ChangedValue( $scan_exclusions, $new_scan_exclusions, "Scan Exclusions" ) );
	
	
	if ( $url_update_time )
		{	( $hour, $meridian ) = split /\s/, $url_update_time;
			$hour = 0 + $hour;
			$new_update_time = 0 + $hour;
			$new_update_time = 12 + $hour if ( ( $meridian )  &&  ( $meridian eq "pm" )  &&  ( $hour < 12 ) );
			$new_update_time = 0 + 0 if ( ( $meridian )  &&  ( $meridian eq "am" )  &&  ( $hour == 12 ) );

			# Check for crazy values for the update time
			$new_update_time = 0 + 12 if ( $new_update_time >= 24 );
			$new_update_time = 0 + 0 if ( $new_update_time < 0 );

			$changed = 1 if ( &ChangedValue( $update_time, $new_update_time ) );
		}
	else
		{	$update_time = undef;
		}


	$changed = 1 if ( &ChangedValue( $ttc_servers_list, $new_ttc_servers_list, "TTC Servers List" ) );
	
	$changed = 1 if ( &ChangedValue( $removable_media_permissions, $new_removable_media_permissions, "Removable Media Permissions" ) );
								  
	$new_report_events = &BinaryValue( $new_report_events );
	$changed = 1 if ( &ChangedValue( $report_events, $new_report_events, "Report Events" ) );
	
	$new_remote_monitoring = &BinaryValue( $new_remote_monitoring );
	$changed = 1 if ( &ChangedValue( $remote_monitoring, $new_remote_monitoring ) );

	$new_only_protected = &BinaryValue( $new_only_protected );
	$changed = 1 if ( &ChangedValue( $only_protected_connections, $new_only_protected, "Allow Remote Monitoring" ) );

	$new_enable_shell = &BinaryValue( $new_enable_shell );
	$changed = 1 if ( &ChangedValue( $enable_shell, $new_enable_shell, "Enable Shell Extension" ) );

	$new_enable_alerts = &BinaryValue( $new_enable_alerts );
	$changed = 1 if ( &ChangedValue( $enable_alerts, $new_enable_alerts, "Enable Alerts" ) );

	$new_enable_manager = &BinaryValue( $new_enable_manager );
	$changed = 1 if ( &ChangedValue( $enable_manager, $new_enable_manager, "Enable Security Agent Dashboard" ) );

	$new_known_permissions = 0 + $new_known_permissions;
	$changed = 1 if ( &ChangedValue( $known_permissions, $new_known_permissions, "Known Program Permissions" ) );

	$new_unknown_permissions = 0 + $new_unknown_permissions;
	$changed = 1 if ( &ChangedValue( $unknown_permissions, $new_unknown_permissions, "Unknown Program Permissions" ) );

	$changed = 1 if ( &ChangedValue( $novell_ldap_server, $new_novell_ldap_server, "Novell/LDAP Server" ) );
	$changed = 1 if ( &ChangedValue( $novell_ldap_root, $new_novell_ldap_root, "Novell/LDAP Root" ) );
	$changed = 1 if ( &ChangedValue( $uid_attribute, $new_uid_attribute, "Novell/LDAP UID Attribute" ) );
	$changed = 1 if ( &ChangedValue( $group_attribute, $new_group_attribute, "Novell/LDAP Group Attribute" ) );
	$changed = 1 if ( &ChangedValue( $protocol_version, $new_protocol_version, "Novell/LDAP Protocol Version" ) );

	$new_novell_precedence = &BinaryValue( $new_novell_precedence );
	$changed = 1 if ( &ChangedValue( $novell_precedence, $new_novell_precedence, "Novell Precedence" ) );


	# Content filtering parameters		
	$new_enable_content_filtering = &BinaryValue( $new_enable_content_filtering );
	$changed = 1 if ( &ChangedValue( $enable_content_filtering, $new_enable_content_filtering, "Enable Content Filtering" ) );
	
	$new_block_unknown_urls = &BinaryValue( $new_block_unknown_urls );
	$changed = 1 if ( &ChangedValue( $block_unknown_urls, $new_block_unknown_urls, "Block Unknown URLs" ) );
	
	$new_block_failed_url_lookups = &BinaryValue( $new_block_failed_url_lookups );
	$changed = 1 if ( &ChangedValue( $block_failed_url_lookups, $new_block_failed_url_lookups, "Block Failed URL Lookups" ) );
	
	$changed = 1 if ( &ChangedValue( $content_filtering_servers, $new_content_filtering_servers, "Content Filtering Servers" ) );

		
	$update_interval			= $new_update_interval;	
	$interactive_mode			= $new_interactive_mode;
	
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
	$scan_type					= $new_scan_type;	
	$scan_job_percent			= $new_scan_job_percent;
	
	$scan_content				= $new_scan_content;
	$scan_exclusions			= $new_scan_exclusions;
	
	$update_time				= $new_update_time;
	
	# Should I update the TTC servers list in the registry?
	if ( $new_ttc_servers_list )
		{	&UpdateSetTTCServersList( $ttc_servers_list ) if ( ( ! $ttc_servers_list )  ||  ( $new_ttc_servers_list ne $ttc_servers_list ) );
		}
		
	$ttc_servers_list			= $new_ttc_servers_list;
	
	$removable_media_permissions = $new_removable_media_permissions;
	
	
	# Did I change the use file integrity value?
	$new_use_file_integrity = &BinaryValue( $new_use_file_integrity );
	my $file_integrity_changed;
	$file_integrity_changed = 1 if ( &ChangedValue( $use_file_integrity, $new_use_file_integrity, "Enable Program Permissions" ) );
	
	if ( $file_integrity_changed )
		{	&SecurityLogEvent( "Update: Server $ttc_server has requested that program permissions be enabled\n" ) if ( $new_use_file_integrity );
			$changed = 1;
		}
		

	# Can I actually turn on file integrity yet?
	# I can't if I haven't done the initial scan yet
	if ( ( ! $use_file_integrity )  &&  ( $new_use_file_integrity ) )
		{	my $key;
			my $data;
			my $type;
			my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );

			$ok = &RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, []) if ( $ok );
			my $len = length( $data );
			
			$use_file_integrity = $new_use_file_integrity;
			$use_file_integrity = undef if ( ! $ok );
			$use_file_integrity = undef if ( ( $ok )  &&  ( ! $len ) );
			
			&RegCloseKey( $key );
			
			if ( ! $use_file_integrity )
				{	&SecurityLogEvent( "Update: $ttc_server has requested that program permissions be enabled, but the local\n" );
					&SecurityLogEvent( "PC can not enable permissions until the first full virus scan has finished.\n" );
				}
			else
				{	&SecurityLogEvent( "Update: A full virus scan has finished, so enabling program permissions now.\n" );
				}
		}
	else
		{	$use_file_integrity	= $new_use_file_integrity;
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
	$novell_precedence			= $new_novell_precedence;
	
	# Content filtering parameters		
	$enable_content_filtering	= $new_enable_content_filtering;
	$block_unknown_urls			= $new_block_unknown_urls;
	$block_failed_url_lookups	= $new_block_failed_url_lookups;
	$content_filtering_servers	= $new_content_filtering_servers;
	
	
	$ttc_server	= $default_ttc_server if ( ! $ttc_server );
		
	# If I changed the enable content filtering flag, make sure the LSP is registered
	&SetUseLSPStatus( undef );
	
	# Make sure the Security Agent Manager is set to run the right way	
	&CheckAutorunManager();
	
	&SecurityLogEvent( "Update: No Security Agent properties from server $ttc_server have changed\n" ) if ( ! $changed );
	
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
	
	&SecurityLogEvent( "Update: Checking $ttc_server to see if server properties are set\n" );
	
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
			&SecurityLogEvent( "Update: Unable to get Security Agent properties from $ttc_server: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&SecurityLogEvent( "Update: Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		} 
		

	my @lines = split /\n/, $content;
	
	# Keep count of how many lines of data I've received
	if ( $#lines < ( 0 + 0 ) )
		{	&SecurityLogEvent( "Update: No response from $ttc_server - will try later\n" );	
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
	$changed = 1 if ( &ChangedValue( $server_properties, $new_server_properties, "Security Agent Property Control: Server Only" ) );
		
	$server_properties = $new_server_properties;
	
	
	# Make sure the manual properties are turned off if the server properties are turned on
	if ( ( $server_properties )  &&  ( $manual_properties ) )	
		{	$manual_properties = undef;	
			$changed = 1;
		}
	
	
	# Show who is now in charge of the Security Agent properties
	if ( $changed )
		{	&SecurityLogEvent( "Update: Security Agent Property Control has been changed by $ttc_server.\n" );
			
			if ( $manual_properties )
				{	&SecurityLogEvent( "Update: Security Agent Property Control: Set by a local user\n" );
					&SecurityLogEvent( "Update: Security Agent properties can not be changed from server $ttc_server.\n" );
				}
				
			if ( $server_properties )
				{	&SecurityLogEvent( "Update: Security Agent Property Control: Set from server $ttc_server.\n" );
					&SecurityLogEvent( "Update: Security Agent properties can not be changed by a local user.\n" );
				}
				
				
			if ( ( ! $server_properties )  &&  ( ! $manual_properties ) )
				{	&SecurityLogEvent( "Update: Security Agent Property Control: Set by either server $ttc_server or local user\n" );
					&SecurityLogEvent( "Update: Security Agent properties can be changed by both a local user and from server $ttc_server.\n" );
				}
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
#  Make sure the the autorun keys are set to the right thing
#
################################################################################
{
	# Make sure the Security Agent Manager is enabled or disabled correctly
	# I need to make sure that the autorun entry is correct for the Security Agent Manager
	my $autokey;
	my $auto_ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, $autokey );


	# If I can't open the autorun, just return here
	if ( ! $auto_ok )
		{	&SecurityLogEvent( "Update: Unable to open the autorun key\n" );
			return( undef );
		}
		
	my $running = &ProcessRunningName( "satray" );
	
	$working_dir = &ScanWorkingDirectory();
	
	my $type;
	my $data;
	my $ok = &RegQueryValueEx( $autokey, "SecurityAgentTray", [], $type, $data, []);
	my $len = length( $data );
	my $fullpath = "$working_dir\\satray.exe"; 


	# Is the registry already set to the correct full path?
	my $set;
	$set = 1 if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data eq $fullpath ) );


	# Delete the old key - used in version 5.0
	&RegDeleteValue( $autokey, "SecurityAgentManager" );


	# Make sure the auto run key matches the registry entry
	if ( ( ! $enable_manager )  &&  ( $ok ) )
		{	# I should delete the value whatever it is
			&RegDeleteValue( $autokey, "SecurityAgentTray" );
			&SecurityLogEvent( "Update: Deleted the Security Agent Tray from auto running\n" );
		}
		
	if ( ( $enable_manager )  &&  ( ! $set ) )	# Make sure that is is set to autorun
		{	&RegSetValueEx( $autokey, "SecurityAgentTray", 0,  REG_SZ, $fullpath );
			&SecurityLogEvent( "Update: Set the Security Agent Tray to autorun\n" );
		}
		
	RegCloseKey( $autokey );	


	# Kill the manager if I have to ...
	if ( ( $running )  &&  ( ! $enable_manager ) )
		{	&SecurityLogEvent( "Update: Signaling the Security Agent Tray application to quit ...\n" );	
			
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
		
	return( undef ) if ( ! defined $str );
	
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
sub ChangedValue( $$$ )
#
#  Given 2 values, return 0 if they are the same, 1 if they are not
#  If the property is given, report any changes
#
################################################################################
{	my $val1		= shift;
	my $val2		= shift;
	my $property	= shift;	# This is the name of the property that I am changing
	my $changed;

	return( 0 + 0 ) if ( ( ! $val1 )  &&  ( ! $val2 ) );
	$changed = 1 if ( ( $val1 )  &&  ( ! $val2 ) );
	$changed = 1 if ( ( ! $val1 )  &&  ( $val2 ) );

	$changed = 1 if ( ( $val1 )  &&  ( $val2 )  &&  ( $val1 ne $val2 ) );
	
	if ( ( $changed )  &&  ( $property ) )
		{	&SecurityLogEvent( "Update: The server has changed property \"$property\" to NULL\n" ) if ( ! defined $val2 );
			&SecurityLogEvent( "Update: The server has changed property \"$property\" to \"$val2\"\n" ) if ( defined $val2 );
		}
		
	return( $changed );
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

	&SecurityLogEvent( "Update: Loading properties from the local registry ...\n" );
	
	# Set the default values
	$update_interval			= "Day";
	$interactive_mode			= 0 + 1;
	
	$block_virus				= 0 + 1;
	$block_virus_action			= "ReportOnly";
	
	$update_virus				= 0 + 1;
	
	$block_spyware				= 0 + 1;
	
	$server_properties			= undef;
	
	$block_all_unknown			= undef;
	
	$scan_system				= 0 + 1;
	
	$scan_interval				= "Friday";
	$scan_time					= 0 + 18;
	$scan_type					= "quick";
	$scan_job_percent			= 0 + 25;
	
	$scan_content				= undef;
	
	$scan_exclusions			= undef;
	
	$update_time				= undef;
	
	$removable_media_permissions = 0 + 7;	# Default to allow everything, report nothing
	
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
	$novell_precedence			= undef;
	
	# Content filtering parameters
	$enable_content_filtering	= undef;
	$block_unknown_urls			= undef;
	$block_failed_url_lookups	= undef;
	$content_filtering_servers	= undef;

	my $save_properties;
	
	#  See if the key already exists
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );
	if ( ! $ok )
		{	&SaveProperties();	# Save the default properties if the key wasn't there
			return( undef );
		}
	
	# Superceded values
	$ok = &RegDeleteValue( $key, "Backup1" );
	$ok = &RegDeleteValue( $key, "Backup2" );
	$ok = &RegDeleteValue( $key, "BHO Registered" );
	
	
	$ok = &RegQueryValueEx( $key, "Update Interval", [], $type, $data, []);
	my $len = length( $data );
	
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$update_interval = $data if ( $data );
			$update_interval = "Day" if ( ( $update_interval )  &&  ( $update_interval eq "" ) );
			$update_interval = &OneOf( $update_interval, "Day", "Hour", "Week" );
			$save_properties = 1 if ( ( ! $data )  ||  ( $update_interval ne $data ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );

	
	$ok = &RegQueryValueEx( $key, "Interactive Mode", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$interactive_mode = 0 + 0;
			$interactive_mode = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	

	$ok = &RegQueryValueEx( $key, "Block Virus", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$block_virus = undef;	
			$block_virus = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );


	$ok = &RegQueryValueEx( $key, "Block Virus Action", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$block_virus_action = $data if ( $data );
			$block_virus_action = "ReportOnly" if ( ( $block_virus_action )  &&  ( $block_virus_action eq "" ) );
			$block_virus_action = "ReportOnly" if ( ( $block_virus_action )  &&  ( $block_virus_action eq "Nothing" ) );
			$block_virus_action = &OneOf( $block_virus_action, "ReportOnly", "Delete", "Quarantine", "Disable" );
			$save_properties = 1 if ( ( ! $data )  ||  ( $block_virus_action ne $data ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );


	$ok = &RegQueryValueEx( $key, "Update Virus", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$update_virus = undef;	
			$update_virus = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		

	$ok = &RegQueryValueEx( $key, "Scan System", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$scan_system = 0 + 1;
			$scan_system = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		
	
	$ok = &RegQueryValueEx( $key, "Scan Interval", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$scan_interval = $data if ( $data );
			$scan_interval = "Friday" if ( ( $scan_interval )  &&  ( $data eq "" ) );
			$scan_interval = &OneOf( $scan_interval, "Friday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Everyday", "Saturday", "Daily" );
			$save_properties = 1 if ( ( ! $data )  ||  ( $scan_interval ne $data ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Scan Time", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$scan_time = 0 + 18;
			$scan_time = unpack( "L", $data ) if ( $data );
			$scan_time = 0 + 18 if ( ( $scan_time < ( 0 + 0 ) )  &&  ( $scan_time > ( 0 + 23 ) ) );
			$save_properties = 1 if ( ! $data );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Scan Type", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$scan_type = "quick";
			$scan_type = "full" if ( ( $data )  &&  ( $data =~ m/full/i ) );
			$save_properties = 1 if ( ! $data );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Scan Job Percent", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$scan_job_percent = 0 + 25;
			$scan_job_percent = unpack( "L", $data ) if ( $data );
			$scan_job_percent = 0 + 25 if ( ( $scan_job_percent < 5 )  ||  ( $scan_job_percent > 100 ) );
			$save_properties = 1 if ( ! $data );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Scan Method", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$scan_content = undef;
			$scan_content = 0 + 1 if ( ( $data )  &&  ( $data eq "Content" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Update Time", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$update_time = 0 + 12;
			$update_time = unpack( "L", $data ) if ( $data );
			$update_time = 0 + 12 if ( ( $update_time < ( 0 + 0 ) )  &&  ( $update_time > ( 0 + 23 ) ) );
		}
	else
		{	$update_time = undef;
		}
	

	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Spyware", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$block_spyware = undef;
			$block_spyware = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Server Properties", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$server_properties = undef;
			$server_properties = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	# Make sure the manual properties are turned off if the server properties are turned on
	if ( ( $server_properties )  &&  ( $manual_properties ) )	
		{	$save_properties = 1;
			$manual_properties = undef;	
		}
	
	
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block All Unknown", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$block_all_unknown = undef;
			$block_all_unknown = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Use File Integrity", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$use_file_integrity = undef;
			$use_file_integrity = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Report Events", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$report_events = undef;
			$report_events = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Remote Monitoring", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$remote_monitoring = undef;
			$remote_monitoring = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	$ok = &RegQueryValueEx( $key, "Only Protected Connections", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$only_protected_connections = undef;
			$only_protected_connections = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );

	
	$ok = &RegQueryValueEx( $key, "Enable Shell", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$enable_shell = undef;
			$enable_shell = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );

	
	# Make sure the shell extension is set the right way with explorer
	&CheckShellExtension();


	$ok = &RegQueryValueEx( $key, "Enable Alerts", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	$enable_alerts = undef;
			$enable_alerts = 0 + 1 if ( ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );


	$data = "";
	$ok = &RegQueryValueEx( $key, "Novell LDAP Server", [], $type, $data, []);
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	my $len = length( $data );
			$novell_ldap_server = undef;
			$novell_ldap_server = $data if ( $len > 0 );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );


	$data = "";
	$ok = &RegQueryValueEx( $key, "Novell LDAP Base DN", [], $type, $data, []);
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	my $len = length( $data );
			$novell_ldap_root = undef;
			$novell_ldap_root = $data if ( $len > 0 );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );


	$data = "";
	$ok = &RegQueryValueEx( $key, "Novell LDAP UID Attribute", [], $type, $data, []);
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	my $len = length( $data );
			$uid_attribute = undef;
			$uid_attribute = $data if ( $len > 0 );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );

	
	$data = "";
	$ok = &RegQueryValueEx( $key, "Novell LDAP Group Attribute", [], $type, $data, []);
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	my $len = length( $data );
			$group_attribute = undef;
			$group_attribute = $data if ( $len > 0 );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );


	$data = "";
	$ok = &RegQueryValueEx( $key, "Novell LDAP Protocol Version", [], $type, $data, []);
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	my $len = length( $data );
			$protocol_version = 0 + 3;
			$protocol_version = $data if ( $len > 0 );
			
			# There are only 2 possible values for this - 2 or 3
			$protocol_version = 0 + 3 if ( ( $protocol_version ne 2 )  &&  ( $protocol_version ne 3 ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );


	$data = "";	
	$ok = &RegQueryValueEx( $key, "Novell Precedence", [], $type, $data, []);
	if ( ( $ok )  &&  ( $len > 0 ) )
		{	my $len = length( $data );
			$novell_precedence = undef;
			$novell_precedence = 1 if ( ( $len > 0 )  &&  ( $data eq "\x01\x00\x00\x00" ) );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );

	
	# I need to make sure that the autorun entry is correct for the Security Agent Manager
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Enable Manager", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	$enable_manager = 0 + 1;
			$enable_manager = undef if ( $data  eq "\x00\x00\x00\x00" );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		

	# Content filtering parameters
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Enable Content Filtering", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	$enable_content_filtering = 0 + 1;
			$enable_content_filtering = undef if ( $data  eq "\x00\x00\x00\x00" );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		
	
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Unknown URLs", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	$block_unknown_urls = 0 + 1;
			$block_unknown_urls = undef if ( $data  eq "\x00\x00\x00\x00" );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		
		
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Failed URL Lookups", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	$block_failed_url_lookups = 0 + 1;
			$block_failed_url_lookups = undef if ( $data  eq "\x00\x00\x00\x00" );
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		
		
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Content Filtering Servers", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	$content_filtering_servers = undef;
			
			# Convert a Multi SZ to a comma delimited list
			if ( $data )
				{	$content_filtering_servers = $data;
					$content_filtering_servers =~ s/\x00+$//g;
					$content_filtering_servers =~ s/\x00/\,/g;
				}
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		
		
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Scan Exclusions", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	$scan_exclusions = undef;
			
			my $len = length( $data );
			# Convert a Multi SZ to a comma delimited list
			if ( ( $len > 0 )  &&  ( $data ) )
				{	$scan_exclusions = $data;
					$scan_exclusions =~ s/\x00+$//g;
					$scan_exclusions =~ s/\x00/\,/g;
				}
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
		
	
	$data = undef;
	@alternate_ttc_servers = ();
	$ok = &RegQueryValueEx( $key, "Alternate TTC Servers", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	my @temp = split /\x00/, $data;
			
			foreach ( @temp )
				{	my $alternate_ttc_server = $_;
					next if ( ! defined $alternate_ttc_server );
					next if ( ! length( $alternate_ttc_server ) );
					
					push @alternate_ttc_servers, $alternate_ttc_server;
				}
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Removable Media Permissions", [], $type, $data, []);
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	my $val = unpack( "L", $data );
			$removable_media_permissions = 0 + $val;
		}
	$save_properties = 1 if ( ( ! $ok )  ||  ( $len <= 0 ) );
	
	
	# Do I need to reset the RemovableMediaPermissions to the default to fix an unfortunate error?
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Removable Media Reset", [], $type, $data, []);
	$len = length( $data );
	if ( ( ! $ok )  ||  ( $len <= 0 )  ||  ( ! defined $data ) )
		{	$removable_media_permissions = 0 + 7;	# Default this to allow everything and log nothing
			$save_properties = 1;
		}
		
	
	# Check to make sure the registry software version matches the Update program's version
	$data = undef;	
	$ok = &RegQueryValueEx( $key, "Software Version", [], $type, $data, []);
	$len = length( $data );
	if ( ( ! $ok )  ||  ( $len <= 0 )  ||  ( ! defined $data )  ||  ( $data ne $version ) )
		{	$save_properties = 1;
		}
		
	
	&RegCloseKey( $key );


	&CheckAutorunManager();


	( $known_permissions, $unknown_permissions ) = &LoadNetworkPermissions();

	&SecurityLogEvent( "Update: Finished loading properties from the local registry\n" );


	# If I changed the enable content filtering flag, make sure the LSP is registered
	&SetUseLSPStatus( undef );
	
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
	my $lc_current	= lc( $current ) if ( defined $current );
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
	
	&SecurityLogEvent( "Update: Saving properties to the local registry ...\n" );
	
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_ALL_ACCESS, $key );

	# If it's not ok, then I need to create the key
	if ( ! $ok )
		{	my $regErr = regLastError();
			&SecurityLogEvent( "Update Save Properties: Unable to open main Security Agent key: $regErr\n" );
			
			# Make sure the main Lightspeed Systems key is created
			$ok = &RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );

			# Now create my key
			$ok = &RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );
			
			if ( ! $ok )
				{	my $regErr = regLastError();
					&SecurityLogEvent( "Update Save Properties: Unable to create main Security Agent key: $regErr\n" );
					return( undef );
				}
		}


	$update_interval = "Day" if ( ! defined $update_interval );
	$update_interval = &OneOf( $update_interval, "Day", "Hour", "Week" );
	&RegSetValueEx( $key, "Update Interval", 0,  REG_SZ, $update_interval );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $interactive_mode );
	&RegSetValueEx( $key, "Interactive Mode", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_virus );
	&RegSetValueEx( $key, "Block Virus", 0,  REG_DWORD, $data );

	$block_virus_action = "ReportOnly" if ( ! $block_virus_action );
	$block_virus_action = &OneOf( $block_virus_action, "ReportOnly", "Delete", "Quarantine", "Disable" );
	&RegSetValueEx( $key, "Block Virus Action", 0,  REG_SZ, $block_virus_action );
	
	# Superceded registry value
	&RegDeleteValue( $key, "Use BHO" );
	
	$scan_interval = "Friday" if ( ! defined $scan_interval );
	$scan_interval = &OneOf( $scan_interval, "Friday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Everyday", "Saturday", "Daily" );
	&RegSetValueEx( $key, "Scan Interval", 0,  REG_SZ, $scan_interval );
	
	$scan_time = 0 + 0 if ( ! $scan_time );
	$scan_time = 0 + $scan_time;
	$data = pack( "L", $scan_time );
	&RegSetValueEx( $key, "Scan Time", 0,  REG_DWORD, $data );
	
	$data = "quick";
	$data = "full" if ( $scan_type =~ m/full/i );
	&RegSetValueEx( $key, "Scan Type", 0,  REG_SZ, $data );

	$scan_job_percent = 0 + 25 if ( ! $scan_job_percent );
	$scan_job_percent = 0 + $scan_job_percent;
	$data = pack( "L", $scan_job_percent );
	&RegSetValueEx( $key, "Scan Job Percent", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $scan_system );
	&RegSetValueEx( $key, "Scan System", 0,  REG_DWORD, $data );
	
	$data = "Extension";
	$data = "Content" if ( $scan_content );
	&RegSetValueEx( $key, "Scan Method", 0,  REG_SZ, $data );

	if ( $update_time )	
		{	$update_time = 0 + 0 if ( ! $update_time );
			$update_time = 0 + $update_time;
			$data = pack( "L", $update_time );
			&RegSetValueEx( $key, "Update Time", 0,  REG_DWORD, $data );
		}
	else
		{	&RegDeleteValue( $key, "Update Time" );
		}
		
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_spyware );
	&RegSetValueEx( $key, "Block Spyware", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $server_properties );
	&RegSetValueEx( $key, "Server Properties", 0,  REG_DWORD, $data );

	# If the server properties are set, make sure that the manual properties are turned off
	if ( $server_properties )
		{	$data = "\x00\x00\x00\x00";
			&RegSetValueEx( $key, "Manual Properties", 0,  REG_DWORD, $data );
			$manual_properties = undef;
		}

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_all_unknown );
	&RegSetValueEx( $key, "Block All Unknown", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $report_events );
	&RegSetValueEx( $key, "Report Events", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $remote_monitoring );
	&RegSetValueEx( $key, "Remote Monitoring", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $only_protected_connections );
	&RegSetValueEx( $key, "Only Protected Connections", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_shell );
	&RegSetValueEx( $key, "Enable Shell", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_alerts );
	&RegSetValueEx( $key, "Enable Alerts", 0,  REG_DWORD, $data );
	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_manager );
	&RegSetValueEx( $key, "Enable Manager", 0,  REG_DWORD, $data );

	$data = $novell_ldap_server;
	$data = "" if ( ! defined $novell_ldap_server );
	&RegSetValueEx( $key, "Novell LDAP Server", 0,  REG_SZ, $data );

	$data = $novell_ldap_root;
	$data = "" if ( ! defined $novell_ldap_root );
	&RegSetValueEx( $key, "Novell LDAP Base DN", 0,  REG_SZ, $data );

	$data = $uid_attribute;
	$data = "" if ( ! defined $uid_attribute );
	&RegSetValueEx( $key, "Novell LDAP UID Attribute", 0,  REG_SZ, $data );

	$data = $group_attribute;
	$data = "" if ( ! defined $group_attribute );
	&RegSetValueEx( $key, "Novell LDAP Group Attribute", 0,  REG_SZ, $data );

	$data = $protocol_version;
	$data = "" if ( ! defined $protocol_version );
	&RegSetValueEx( $key, "Novell LDAP Protocol Version", 0,  REG_SZ, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $novell_precedence );
	&RegSetValueEx( $key, "Novell Precedence", 0,  REG_DWORD, $data );

	&RegSetValueEx( $key, "Software Version", 0,  REG_SZ, $version );


	# Content filtering parameters	
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $enable_content_filtering );
	&RegSetValueEx( $key, "Enable Content Filtering", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_unknown_urls );
	&RegSetValueEx( $key, "Block Unknown URLs", 0,  REG_DWORD, $data );

	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $block_failed_url_lookups );
	&RegSetValueEx( $key, "Block Failed URL Lookups", 0,  REG_DWORD, $data );


	# Convert a comma delimited list to a multi sz
	$data = "";
	if ( $content_filtering_servers )
		{	$data = $content_filtering_servers;
			$data =~ s/\,/\x00/g;
			$data .= "\x00\x00";
		}
		
	&RegSetValueEx( $key, "Content Filtering Servers", 0,  REG_MULTI_SZ, $data );


	# Convert a comma delimited list to a multi sz
	$data = "";
	if ( $scan_exclusions )
		{	$data = $scan_exclusions;
			$data =~ s/\,/\x00/g;
			$data .= "\x00\x00";
		}
		
	&RegSetValueEx( $key, "Scan Exclusions", 0,  REG_MULTI_SZ, $data );

	
	# Make sure that we don't turn on File Integrity checking if the Last Scan Finished hasn't happened	
	$ok = &RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, []);
	my $len = length( $data );
	my $last_scan_finished = undef;
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) )
		{	$last_scan_finished = $data;
		}


	# If no last scan finished, don't turn on file integrity
	$use_file_integrity = undef if ( ! $last_scan_finished );
	$data = "\x00\x00\x00\x00";
	$data = "\x01\x00\x00\x00" if ( $use_file_integrity );
	&RegSetValueEx( $key, "Use File Integrity", 0,  REG_DWORD, $data );
	

	# Default this to everything allowed if removable_media_permissions is not defined
	$data = "\x07\x00\x00\x00";
	if ( defined $removable_media_permissions )
		{	$data = pack( "L", $removable_media_permissions );
		}
		
	&RegSetValueEx( $key, "Removable Media Permissions", 0,  REG_DWORD, $data );
	
	$data = "\x01\x00\x00\x00";
	&RegSetValueEx( $key, "Removable Media Reset", 0,  REG_DWORD, $data );
	

	&RegCloseKey( $key );

	&SaveNetworkPermissions( $working_dir, $known_permissions, $unknown_permissions );
	
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
	my $local_ttc_server = $ttc_server;
	
	
	if ( &TTCServerMode() )
		{	$local_ttc_server = $default_ttc_server;
			&SecurityLogEvent( "Update: This PC is a TTC Server itself so contacting Lightspeed Systems directly\n" );
			&SecurityLogEvent( "Update: Checking with $local_ttc_server for a new security agent package\n" );
		}
	
	
	# Do I need to download the scan engine at all?
	my $update_filename = "SA7Update.htm";
	$update_filename = "SA62Update.htm" if ( $version lt '7.00.00' );
	$update_filename = "SA6Update.htm" if ( $version lt '6.02.00' );
			
	my $url = "http:\/\/TTCSERVER\/content\/GetFileInfo.aspx?FileName=$update_filename";
	$url =~ s/TTCSERVER/$local_ttc_server/;
	
			
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
			&SecurityLogEvent( "Update: Unable to connect to $local_ttc_server to check for a new security agent package: ", $error, "\n" );
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
			
			&SecurityLogEvent( "Update: Checking $ttc_server for the update package version ...\n" );
			
			# See if I can read the sa7package.txt file or the sa6package.txt file and get the version from that ...
			$url = "http:\/\/TTCSERVER\/content\/SA7Package.txt";
			$url = "http:\/\/TTCSERVER\/content\/SA62Package.txt" if ( $version lt '7.00.00' );
			$url = "http:\/\/TTCSERVER\/content\/SA6Package.txt" if ( $version lt '6.02.00' );
			
			$url =~ s/TTCSERVER/$local_ttc_server/;

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
						{	&SecurityLogEvent( "Update: The SA package software on $ttc_server is the same or older than your current software.\n" );
							&SecurityLogEvent( "Update: Not installing SA package over your current software.\n" );
							&SecurityLogEvent( "Update: SA package version on $ttc_server: $package_version\n" );
							&SecurityLogEvent( "Update: Your current version: $version\n" );
							$changed = undef;  #  Nothing has changed, or it is older
						}
					else
						{	&SecurityLogEvent( "Update: A newer Security Agent version $package_version is available on $ttc_server\n" );
						}
				}
			else
				{	&SecurityLogEvent( "Update: Unable to get the update package version, will check for it next time\n" );
					$changed = undef;
				}
		}


	# If it has changed, download the scan package and install it
	if ( $changed )	
		{	my $dir = &ScanWorkingDirectory();
			
			&CleanUpFiles( $dir, undef );
			
			&SecurityLogEvent( "Update: Downloading a newer version of the security agent from $local_ttc_server\n" );
			
			my $update_filename = "SA7Update.htm";
			$update_filename = "SA62Update.htm" if ( $version lt '7.00.00' );
			$update_filename = "SA6Update.htm" if ( $version lt '6.02.00' );

			$url = "http:\/\/TTCSERVER\/contentfiltering\/$update_filename";
			$url =~ s/TTCSERVER/$local_ttc_server/;
			
			my $full_filename = $dir . "\\$update_filename";
        	unlink( $full_filename );
 
 			$| = 1;

	        my $response = LWP::Simple::getstore( $url, $full_filename );

	        my $ok = is_success( $response );

            if ( !$ok )
                {   my $error = HTTP::Status::status_message( $response );
		            &SecurityLogEvent( "Update: Unable to download new security agent ($response): $error\n" );
	                return( undef, undef );  #  Return that an error happened
                }

			&SecurityLogEvent( "Update: Downloaded OK from $local_ttc_server\n" );
			
			( $ok, $renamer ) = &InstallScanEngine( $dir, $full_filename );
			
			&CleanUpFiles( $dir, $renamer );
	
			return( undef, undef ) if ( ! $ok );
		}
	else
		{	&SecurityLogEvent( "Update: No changes to the security agent\n" );
		}


	# If I got to here, then everything went ok
	return( $current_date, $renamer );
}



################################################################################
#
sub InstallScanEngine( $$ )
#
#  Given the SAUpdate scan engine package, install it
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
		{	&SecurityLogEvent( "Update: Unable to unzip security agent package $full_filename: $err_msg\n" );
			return( undef, undef );					
		}
	
	if ( ! $files[ 0 ] )
		{	&SecurityLogEvent( "Update: Unable to unzip security agent package $full_filename\n" );
			return( undef, undef );					
		}
	
	my $scan_error = &ScanLastUnzipError();
	if ( $scan_error )
		{	&SecurityLogEvent( "Update: Error unzipping security agent package: $scan_error\n" );
			return( undef, undef );					
		}
	
	
	# Switch to the working directory
	my $cur_dir = getcwd();	
	chdir( $dir );

	if ( $opt_debug )
		{	&SecurityLogEvent( "Update: Install working directory: $dir\n" );
			&SecurityLogEvent( "Update: Install security agent package contents:\n" );
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
	
	
	# Look for the sa7package.txt file or the sa6package.txt file first so that is in the Security Log first ...
	my $package_version;
	
	foreach( @files )
		{	my $full_file = lc( $_ );
			
			# Is there a version package inside the scan package?
			if ( ( $full_file =~ m/sa7package\.txt/i )  ||  
				( $full_file =~ m/sa6package\.txt/i )  ||  
				( $full_file =~ m/sa62package\.txt/i ) ) 
				{	&SecurityLogEvent( "Update: Security agent package information:\n" );
					
					if ( ! open PACKAGE, "<$full_file" )
						{	&SecurityLogEvent( "Update: Unable to open $full_file: $!\n" );
						}
					else
						{	# Put each line of the package file into the security log
							while (my $line = <PACKAGE>)
								{	next if ( ! defined $line );
									
									&SecurityLogEvent( "Update Package: $line" );
									
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
	if ( ( ! $opt_debug )  &&  ( ( ! $package_version )  ||  ( $package_version le $version ) ) )
		{	$package_version = "1.00.01" if ( ! $package_version );
			&SecurityLogEvent( "Update: The downloaded software is the same or older than your current software.\n" );
			&SecurityLogEvent( "Update: Not installing download over your current software.\n" );
			&SecurityLogEvent( "Update: Downloaded version: $package_version\n" );
			&SecurityLogEvent( "Update: Current version: $version\n" );
			return( 1, undef );
		}
		

	# Now go through the rest of the files, installing them one by one ...
	# If any errors at all, flag that in errors
	foreach( @files )
		{	my $full_file = lc( $_ );
			
			# Make sure I'm in the current directory
			chdir( $dir );


			# Did the Security Agent SAScan actually change?
			if ( $full_file =~ m/sascan.new/i )
				{	next if ( ! &FileCompare( "sascan.exe", "sascan.new" ) );
					
					my $running = &ProcessRunningName( "sascan" );
					
					my $killed = &ProcessKillName( "sascan" ) if ( $running );	
					&SecurityLogEvent( "Update: Killed the old Security Agent SAScan process\n" ) if ( $killed );
					
					my $rename_ok = 1;
					
					# If the sascan currently exists, rename it
					if ( -e "sascan.exe" )
						{	&ScanNoReadOnly( "sascan.exe" );	
							
							if ( ! rename( "sascan.exe", "sascan.old" ) )
								{	$errors = "Update: Could not rename sascan.exe to sascan.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					
					# Now rename the sascan.new to sascan.exe	
					&ScanNoReadOnly( "sascan.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "sascan.new", "SAScan.exe" ) ) )
						{	$errors = "Update: Could not rename sascan.new to SAScan.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if sascan doesn't exist
							rename( "sascan.old", "sascan.exe" ) if ( ! ( -e "sascan.exe" ) );
						}					
						
					&SecurityLogEvent( "Update: Updated the Security Agent SAScan OK\n" ) if ( $rename_ok );
				}


			# Did the Security Agent SaExplorer actually change?
			if ( $full_file =~ m/saexplorer.new/i )
				{	next if ( ! &FileCompare( "saexplorer.exe", "saexplorer.new" ) );
					
					my $running = &ProcessRunningName( "saexplorer" );
					
					my $killed = &ProcessKillName( "saexplorer" ) if ( $running );	
					&SecurityLogEvent( "Update: Killed the old Security Agent SAExplorer process\n" ) if ( $killed );
					
					my $rename_ok = 1;
					
					# If the saexplorer currently exists, rename it
					if ( -e "saexplorer.exe" )
						{	&ScanNoReadOnly( "saexplorer.exe" );	
							
							if ( ! rename( "saexplorer.exe", "saexplorer.old" ) )
								{	$errors = "Update: Could not rename saexplorer.exe to saexplorer.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					
					# Now rename the saexplorer.new to saexplorer.exe	
					&ScanNoReadOnly( "saexplorer.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "saexplorer.new", "SaExplorer.exe" ) ) )
						{	$errors = "Update: Could not rename saexplorer.new to saexplorer.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if saexplorer doesn't exist
							rename( "saexplorer.old", "saexplorer.exe" ) if ( ! ( -e "saexplorer.exe" ) );
						}					
						
					&SecurityLogEvent( "Update: Updated the Security Agent SaExplorer OK\n" ) if ( $rename_ok );
				}


			# Did the scan engine actually change?
			if ( $full_file =~ m/scan\.new/i )
				{	next if ( ! &FileCompare( "scan.exe", "scan.new" ) );
					
					my $rename_ok = 1;							
					&ScanNoReadOnly( "scan.exe" );	
					if ( ! rename( "scan.exe", "scan.old" ) )
						{	$errors = "Update: Could not rename scan.exe to scan.old: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					&ScanNoReadOnly( "scan.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "scan.new", "scan.exe" ) ) )
						{	$errors = "Update: Could not rename scan.new to scan.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if scan.exe doesn't exist
							rename( "scan.old", "scan.exe" ) if ( ! ( -e "scan.exe" ) );
							next;
						}
						
					&SecurityLogEvent( "Update: Updated scan engine\n" ) if ( $rename_ok );
				}
				
				
			# Did the sig design utility actually change?
			if ( $full_file =~ m/sigdesign\.new/i )
				{	next if ( ! &FileCompare( "sigdesign.exe", "sigdesign.new" ) );
					
					my $rename_ok = 1;							
					&ScanNoReadOnly( "sigdesign.exe" );	
					if ( ( -e "sigdesign.exe" )  &&  ( ! rename( "sigdesign.exe", "sigdesign.old" ) ) )
						{	$errors = "Update: Could not rename sigdesign.exe to sigdesign.old: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					&ScanNoReadOnly( "sigdesign.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "sigdesign.new", "SigDesign.exe" ) ) )
						{	$errors = "Update: Could not rename sigdesign.new to sigdesign.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if sigdesign.exe doesn't exist
							rename( "sigdesign.old", "sigdesign.exe" ) if ( ! ( -e "sigdesign.exe" ) );
							next;
						}
						
					&SecurityLogEvent( "Update: Updated Signature Design utility\n" ) if ( $rename_ok );
				}
				
				
			# Did the virtest utility actually change?
			if ( $full_file =~ m/virtest\.new/i )
				{	next if ( ! &FileCompare( "virtest.exe", "virtest.new" ) );
					
					my $rename_ok = 1;							
					&ScanNoReadOnly( "virtest.exe" );	
					if ( ( -e "virtest.exe" )  &&  ( ! rename( "virtest.exe", "virtest.old" ) ) )
						{	$errors = "Update: Could not rename virtest.exe to virtest.old: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					&ScanNoReadOnly( "virtest.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "virtest.new", "virtest.exe" ) ) )
						{	$errors = "Update: Could not rename virtest.new to virtest.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if virtest.exe doesn't exist
							rename( "virtest.old", "virtest.exe" ) if ( ! ( -e "virtest.exe" ) );
							next;
						}
						
					&SecurityLogEvent( "Update: Updated virus scanner active utility (virtest.exe)\n" ) if ( $rename_ok );
				}
				
				
			# Did the scan.dll actually change?
			elsif ( $full_file =~ m/scandll\.new/i )
				{	next if ( ! &FileCompare( "scan.dll", "scandll.new" ) );
					
					my $rename_ok = 1;															
					if ( -e "scan.dll" )
						{	&ScanNoReadOnly( "scan.dll" );	
							if ( ! rename( "scan.dll", "scandll.old" ) )
								{	$errors = "Update: Could not rename scan.dll to scandll.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					&ScanNoReadOnly( "scandll.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "scandll.new", "scan.dll" ) ) )
						{	$errors = "Update: Could not rename scandll.new to scan.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if scan.dll doesn't exist
							rename( "scandll.old", "scan.dll" ) if ( ! ( -e "scan.dll" ) );
							next;
						}
						
					&SecurityLogEvent( "Update: Updated scan.dll\n" ) if ( $rename_ok );
					
					# Flag that I need to restart the service
					$security_agent_service_restart = 1;
				}

				
			# Did the msvcr71.dll actually change?
			elsif ( $full_file =~ m/msvcr71\.new/i )
				{	next if ( ! &FileCompare( "msvcr71.dll", "msvcr71.new" ) );
					
					my $rename_ok = 1;															
					if ( -e "msvcr71.dll" )
						{	&ScanNoReadOnly( "msvcr71.dll" );	
							if ( ! rename( "msvcr71.dll", "msvcr71.old" ) )
								{	$errors = "Update: Could not rename msvcr71.dll to msvcr71.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					&ScanNoReadOnly( "msvcr71.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "msvcr71.new", "msvcr71.dll" ) ) )
						{	$errors = "Update: Could not rename msvcr71.new to msvcr71.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if msvcr71.dll doesn't exist
							rename( "msvcr71.old", "msvcr71.dll" ) if ( ! ( -e "msvcr71.dll" ) );
							next;
						}
						
					&SecurityLogEvent( "Update: Updated msvcr71.dll\n" ) if ( $rename_ok );
				}

				
			# Did the service files actually change?
			elsif ( $full_file =~ m/securityagentnew\.exe/i )
				{	next if ( ! &FileCompare( "SecurityAgent.exe", "SecurityAgentNew.exe" ) );

					system( "net stop \"Security Agent Service\"" );

					my $rename_ok = 1;
					
					if ( -e "SecurityAgent.exe" )
						{	&ScanNoReadOnly( "SecurityAgent.exe" );	
							if ( ! rename( "SecurityAgent.exe", "SecurityAgent.old" ) )
								{	$errors = "Update: Could not SecurityAgent.exe to SecurityAgent.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}


					&ScanNoReadOnly( "SecurityAgentNew.exe" );	
					if ( ( $rename_ok )  &&  ( ! rename( "SecurityAgentNew.exe", "SecurityAgent.exe" ) ) )
						{	$errors = "Update: Could not rename SecurityAgentNew.exe to SecurityAgent.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename the old one back if it doesn't exist
							rename( "SecurityAgent.old", "SecurityAgent.exe" ) if ( ! ( -e "SecurityAgent.exe" ) );
							
							# At this point I havn't changed anything, so just restart the service
							system( "net start \"Security Agent Service\"" );
							next;
						}
						

					if ( $rename_ok )
						{	system( "SecurityAgent.exe -i -w" );
							&SecurityLogEvent( "Update: Updated Security Agent service and device driver\n" );
						}
						
					
					# Flag that I don't need to do this again
					$security_agent_service_restart = undef;	
					system( "net start \"Security Agent Service\"" );
				}
				
				
			# Did the update program actually change?
			elsif ( $full_file =~ m/update\.new/i )
				{	next if ( ! &FileCompare( "update\.exe", "update\.new" ) );
						
					&SecurityLogEvent( "Update: Received new Update utility\n" );
	 				$renamer = 1;	# Because I got a new update utility, and need to call the renamer program to switch the name around
				}
				
				
			# Did the securityagentshellext.dll change?
			elsif ( $full_file =~ m/securityagentshellextnew\.dll/i )
				{	next if ( ! &FileCompare( "SecurityAgentShellExt.dll", "SecurityAgentShellExtNew.dll" ) );
						
					&SecurityLogEvent( "Update: Received new Security Agent shell extension\n" );
					
					# If the old shell extension currently exists, rename it
					if ( -e "SecurityAgentShellExt.dll" )
						{	&ScanNoReadOnly( "SecurityAgentShellExt.dll" );	
							
							my $moved_ok = Win32API::File::MoveFile( "SecurityAgentShellExt.dll", "SecurityAgentShellExt.old" );
			
							if ( ! $moved_ok )
								{	$errors = "Update: Could not move file SecurityAgentShellExt.dll to SecurityAgentShellExt.old: $!\n";
									&SecurityLogEvent( $errors );
								}
						}
						
					my $rename_ok = 1;
					
					&ScanNoReadOnly( "SecurityAgentShellExtNew.dll" );	
					if ( ! rename( "SecurityAgentShellExtNew.dll", "SecurityAgentShellExt.dll" ) )
						{	$errors = "Update: Could not rename SecurityAgentShellExtNew.dll to SecurityAgentShellExt.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
						}
					
					
					# If I did everything OK, and the shell extension should be enabled, then enable it
					if ( ( $rename_ok )  &&  ( $enable_shell ) )
						{	system "regsvr32 \/s securityagentshellext.dll";
							&SecurityLogEvent( "Update: Installed new Security Agent shell extension OK\n" );
						}
				}
				
				
			# Did the Security Agent Tray actually change?
			elsif ( $full_file =~ m/satray.new/i )
				{	next if ( ! &FileCompare( "SATray.exe", "SATray.new" ) );
					
					my $running = &ProcessRunningName( "satray" );
					
					# Signal the satray to die
					&KillManager();

					my $killed = &ProcessKillName( "satray" );	
					&SecurityLogEvent( "Update: Killed the old Security Agent Tray process\n" ) if ( $killed );

					my $rename_ok = 1;
					
					# If the satray currently exists, rename it
					if ( -e "satray.exe" )
						{	&ScanNoReadOnly( "satray.exe" );	
							
							if ( ! rename( "satray.exe", "satray.old" ) )
								{	$errors = "Update: Could not rename satray.exe to satray.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
						
					&ScanNoReadOnly( "satray.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "satray.new", "SATray.exe" ) ) )
						{	$errors = "Update: Could not rename satray.new to satray.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							$rename_ok = undef;
							
							# Try to rename back if satray doesn't exist
							rename( "satray.old", "satray.exe" ) if ( ! ( -e "satray.exe" ) );
						}
											
					&SecurityLogEvent( "Update: Updated the Security Agent Tray task OK\n" ) if ( $rename_ok );
				}
				
				
			# Did the Security Agent Alert actually change?
			elsif ( $full_file =~ m/saalert.new/i )
				{	next if ( ! &FileCompare( "saalert.exe", "saalert.new" ) );
					
					my $running = &ProcessRunningName( "saalert" );
					
					my $rename_ok = 1;
					
					# If the saalert currently exists, rename it
					if ( -e "saalert.exe" )
						{	&ScanNoReadOnly( "saalert.exe" );	
							
							if ( ! rename( "saalert.exe", "saalert.old" ) )
								{	$errors = "Update: Could not rename saalert.exe to saalert.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
						
					&ScanNoReadOnly( "saalert.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "saalert.new", "SAAlert.exe" ) ) )
						{	$errors = "Update: Could not rename saalert.new to SAAlert.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if saalert doesn't exist
							rename( "saalert.old", "saalert.exe" ) if ( ! ( -e "saalert.exe" ) );
							
							$rename_ok = undef;
						}
					
					
					my $killed = &ProcessKillName( "saalert" );	
					&SecurityLogEvent( "Update: Killed the old Security Agent Alert process\n" ) if ( $killed );
						
					&SecurityLogEvent( "Update: Updated the Security Agent Alert task OK\n" ) if ( $rename_ok );
				}
				
				
			# Did the Security Agent Dashboard actually change?
			elsif ( $full_file =~ m/sadash.new/i )
				{	next if ( ! &FileCompare( "sadash.exe", "sadash.new" ) );
					
					my $running = &ProcessRunningName( "sadash" );
					
					my $killed = &ProcessKillName( "sadash" ) if ( $running );	
					&SecurityLogEvent( "Update: Killed the old Security Agent Dashboard process\n" ) if ( $killed );
					
					my $rename_ok = 1;
					
					# If the sadash currently exists, rename it
					if ( -e "sadash.exe" )
						{	&ScanNoReadOnly( "sadash.exe" );	
							
							if ( ! rename( "sadash.exe", "sadash.old" ) )
								{	$errors = "Update: Could not rename sadash.exe to sadash.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					
					# Now rename the sadash.new to sadash.exe	
					&ScanNoReadOnly( "sadash.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "sadash.new", "SADash.exe" ) ) )
						{	$errors = "Update: Could not rename sadash.new to SADash.exe: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if sadash doesn't exist
							rename( "sadash.old", "sadash.exe" ) if ( ! ( -e "sadash.exe" ) );
						}
					
					
					# Now try to install the new SADashHtml.dll file
					# Rename the old SADashHtml.dll to SADashHtml.old
					if ( -e "sadashhtml.dll" )
						{	&ScanNoReadOnly( "sadashhtml.dll" );	
							
							if ( ! rename( "sadashhtml.dll", "sadashhtml.old" ) )
								{	$errors = "Update: Could not rename SADashHtml.dll to SADashHtml.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
					
					# Now rename the new SADashHtml.new to SADashHtml.dll	
					&ScanNoReadOnly( "sadashhtml.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "sadashhtml.new", "SADashHtml.dll" ) ) )
						{	$errors = "Update: Could not rename SADashHtml.new to SADashHtml.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if sadash doesn't exist
							rename( "sadashhtml.old", "SADashHtml.dll" ) if ( ! ( -e "SADashHtml.dll" ) );
						}
					
						
					&SecurityLogEvent( "Update: Updated the Security Agent Dashboard OK\n" ) if ( $rename_ok );
				}
				
			# Did the Security Agent LSP actually change?
			elsif ( $full_file =~ m/salsp.new/i )
				{	# First, if the old BHO is around, unregister it and delete it
					if ( -e "SecurityAgentBHO.dll" )
						{	# Unregister the BHO if I need to
							&SetUseBHOStatus( undef );
							
							unlink( "SecurityAgentBHO.dll" );
						}

					my $system32_dir = "$ENV{ SystemRoot }\\SYSTEM32";

					# Skip doing anything if the file really hasn't changed
					next if ( ! &FileCompare( "$system32_dir\\salsp.dll", "salsp.new" ) );
					
					my $rename_ok = 1;
					
					
					# Turn off any readonly bits on the Windows file system	
					&ScanNoReadOnly( "salsp.new" );	
					
					
					# Now copy the sporder.dll to the system32 directory if it doesn't exist
					if ( ! -e "$system32_dir\\sporder.dll" )
						{	# Turn off any readonly bits on the Windows file system	
							&ScanNoReadOnly( "sporder.dll" );	
							
							if ( ! copy( "sporder.dll", "$system32_dir\\sporder.dll" ) )
								{	$errors = "Update: Could not copy sporder.dll to $system32_dir\\sporder.dll: $!\n";
									&SecurityLogEvent( $errors );
									$rename_ok = undef;	# Don't even try to register the new dll
								}
							else
								{	&SecurityLogEvent( "Update: Updated the SpOrder.dll OK\n" );
								}
						}
						
						
					# Does an old salsp.dll version exist at all?  If so, rename the old version
					if ( ( $rename_ok )  &&  ( -e "$system32_dir\\salsp.dll" ) )
						{	unlink( "$system32_dir\\salsp.old" );	# Delete any old file if it exists
							
							if ( ! rename( "$system32_dir\\salsp.dll", "$system32_dir\\salsp.old" ) )
								{	$errors = "Update: Could not rename $system32_dir\\salsp.dll to $system32_dir\\salsp.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
					
					
					# Now copy the salsp.new to salsp.dll	
					if ( ( $rename_ok )  &&  ( ! copy( "salsp.new", "$system32_dir\\salsp.dll" ) ) )
						{	$errors = "Update: Could not copy salsp.new to $system32_dir\\salsp.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back the old if salsp.dll doesn't exist
							rename( "$system32_dir\\salsp.old", "$system32_dir\\salsp.dll" ) if ( ! ( -e "$system32_dir\\salsp.dll" ) );
						}
					
					
					# If I changed the enable content filtering flag, make sure the LSP is registered
					&SetUseLSPStatus( undef );
	
					
					&SecurityLogEvent( "Update: Updated the Security Agent LSP OK\n" ) if ( $rename_ok );
					&SecurityLogEvent( "Update: Errors updating the Security Agent LSP\n" ) if ( ! $rename_ok );
				}
				
			# Did we include the SpOrder.dll?
			elsif ( $full_file =~ m/sporder.dll/i )
				{
					my $system32_dir = "$ENV{ SystemRoot }\\SYSTEM32";

					next if ( ! &FileCompare( "$system32_dir\\sporder.dll", "sporder.dll" ) );
					
					# Turn off any readonly bits on the Windows file system	
					&ScanNoReadOnly( "sporder.dll" );	
					
					# Rename the old sporder.dll if it exists
					if ( ( -e "$system32_dir\\sporder.dll" )  &&  ( ! rename( "$system32_dir\\sporder.dll", "$system32_dir\\sporder.old" ) ) )
						{	$errors = "Update: Could not rename $system32_dir\\sporder.dll to $system32_dir\\sporder.old: $!\n";
							&SecurityLogEvent( $errors );
						}
						
					# Now copy the sporder.dll to the system32 directory	
					my $copy_ok = 1;
					if ( ! copy( "sporder.dll", "$system32_dir\\sporder.dll" ) )
						{	$errors = "Update: Could not copy sporder.dll to $system32_dir\\sporder.dll: $!\n";
							&SecurityLogEvent( $errors );
							$copy_ok = undef;
						}
						
					&SecurityLogEvent( "Update: Updated the SpOrder.dll OK\n" ) if ( $copy_ok );
				}

			# Did we include the scanclient.dll, and has it changed?
			elsif ( $full_file =~ m/scanclient.new/i )
				{	next if ( ! &FileCompare( "scanclient.dll", "scanclient.new" ) );
					
					my $rename_ok = 1;
					
					# If the scanclient.dll currently exists, rename it
					if ( -e "scanclient.dll" )
						{	&ScanNoReadOnly( "scanclient.dll" );	
							
							if ( ! rename( "scanclient.dll", "scanclient.old" ) )
								{	$errors = "Update: Could not rename scanclient.dll to scanclient.old: $!\n";
									&SecurityLogEvent( $errors );
									
									$rename_ok = undef;
								}
						}
						
						
					&ScanNoReadOnly( "scanclient.new" );	
					if ( ( $rename_ok )  &&  ( ! rename( "scanclient.new", "scanclient.dll" ) ) )
						{	$errors = "Update: Could not rename scanclient.new to scanclient.dll: $!\n";
							&SecurityLogEvent( $errors );
							
							# Try to rename back if scanclient doesn't exist
							rename( "scanclient.old", "scanclient.dll" ) if ( ! ( -e "scanclient.dll" ) );
							
							$rename_ok = undef;
						}
					
					&SecurityLogEvent( "Update: Updated the ScanClient.dll OK\n" ) if ( $rename_ok );
				}

		}  # end of foreach @files
		
		
	# Do I need to copy the scan engine package to the web server?	
	my $ttc_server_mode = &TTCServerMode();
	
	if ( ( ! $errors )  &&  ( $ttc_server_mode ) )
		{	my $software_dir = &SoftwareDirectory();
			my $new_filename;
			
			my $update_filename = "SA7Update.htm";
			$update_filename = "SA62Update.htm" if ( $version lt '7.00.00' );
			$update_filename = "SA6Update.htm" if ( $version lt '6.02.00' );

			$new_filename = $software_dir . "\\Website\\Content\\$update_filename";
			&ScanNoReadOnly( $new_filename );
			
			if ( copy( $update_filename, $new_filename ) )
				{	&SecurityLogEvent( "Update: Replaced the security agent package $new_filename\n" );
				}
			else
				{	&SecurityLogEvent( "Update: Unable to copy the security agent package to $new_filename\n" );
				}
			
			# Use the right package name depending on the version number
			my $package_name = "sa7package.txt";
			$package_name = "sa62package.txt" if ( $version lt '7.00.00' );
			$package_name = "sa6package.txt" if ( $version lt '6.02.00' );
			
			$new_filename = $software_dir . "\\Website\\Content\\$package_name";
			&ScanNoReadOnly( $new_filename );
			
			if ( copy( $package_name, $new_filename ) )
				{	&SecurityLogEvent( "Update: Replaced $new_filename\n" );
				}
			else
				{	&SecurityLogEvent( "Update: Unable to copy $new_filename\n" );
				}
		}
		
		
	# Switch back to the original directory
	chdir( $cur_dir );
					
	# Save the package.txt into the registry
	&SetPackageVersion( $errors, @package_txt );

	
	&SecurityLogEvent( "Update: Finished installing the new version of the security agent\n" );
	&SecurityLogEvent( "Update: Not all parts of the security agent were installed ok\n" ) if ( $errors );

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
	
	
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_WRITE, $key );
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
	&RegSetValueEx( $key, "Package Version", 0,  REG_MULTI_SZ, $multi_sz );

	return( 1 );
}



################################################################################
#
sub UpdateSecurityAgentFileIntegrity()
#
#  Given a list of files, update the file integrity file so that all of the 
#  SecurityAgent files are known programs
#
#  Return True if I need to signal the Security Agent service
#
################################################################################
{
	&SecurityLogEvent( "Update: Verifying the Security Agent programs are known good in the local database ...\n" );
	
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
	
	# New files in version 6.0
	push @file_list, "$working_dir\\saalert.exe";
	push @file_list, "$working_dir\\sadash.exe";
	push @file_list, "$working_dir\\sascan.exe";
	push @file_list, "$working_dir\\saexplorer.exe";
	push @file_list, "$working_dir\\sadashhtml.dll";
	push @file_list, "$working_dir\\satray.exe";
	push @file_list, "$working_dir\\scanclient.dll";
	
	push @file_list, "$working_dir\\update.exe";
	push @file_list, "$working_dir\\updateext.exe";
	push @file_list, "$working_dir\\securityagentshellext.dll";
	push @file_list, "$working_dir\\securityagentbho.dll";
	
	my $system_dir = &ScanSystemDirectory();
	
	# Also new driver for 6.0
	push @file_list, "$system_dir\\IpmSecurityAgent1.sys";
	push @file_list, "$system_dir\\IpmSecurityAgent2.sys";
	
	
	# Load the file integrity hash so that I can add the new programs to it
	# If I had an error, reload everything from the ttc server
	my ( $ok, $msg ) = &LoadFileIntegrity( $opt_debug, undef );
	
	if ( ! defined $ok )
		{	&SecurityLogEvent( "Update: Error loading the file integrity database: $msg\n" );
			$integrity_update = $start_date;
		}
		
	my $changed_count = 0 + 0;
	foreach ( @file_list )
		{	my $file = $_;
			next if ( ! defined $file );
			next if ( ! -e $file );

			if ( &AddFileIntegrity( $file, 1 ) )
				{	&SecurityLogEvent( "Update: Added $file into the file integrity database\n" );
					$changed_count++;	
				}
		}


	# Make sure that all the Perl dll's are known
	if ( my $dll_count = &PerlAddFileID() )
		{	&SecurityLogEvent( "Update: Added $dll_count .DLLs into the file integrity database\n" );
			$changed_count += $dll_count;	
		}


	# Make sure the special Windows update programs have the inherit permissions
	my $system_root = $ENV{ SystemRoot };
	my @inherit_files = ();
	push @inherit_files, "$system_root\\system32\\wuauclt.exe";
	push @inherit_files, "$system_root\\system32\\wuauclt1.exe";
	push @inherit_files, "$system_root\\system32\\msiexec.exe";

	foreach ( @inherit_files )
		{	my $file = $_;

			next if ( ! $file );
			next if ( ! -e $file );
			
			my $file_id = &ApplicationFileID( $file );
			next if ( ! $file_id );
			
			my ( $category_num, $network_permissions, $local_permissions ) = &GetPermissions( $file_id );
			
			# Should I change it?
			if ( ( $category_num != 6 )  ||
				 ( $network_permissions != 0xc0000200 )  ||
				 ( $local_permissions != 0 ) )
				{	&SetPermissions( $file_id, 6, 0xc0000200, 0 );
					$changed_count++;	
				}
		}
		

	# Save it back down if it changed
	if ( $changed_count )
		{	( $ok, $msg ) = &SaveFileIntegrity( $working_dir, undef, undef );
			
			if ( ! defined $ok )
				{	&SecurityLogEvent( "Update: Error saving the file integrity database: $msg\n" );
				}
		}
			
	# Drop all the memory used
	&UnloadFileIntegrity();
	
	return( $changed_count );	
}



################################################################################
#
sub CleanUpFiles( $$ )
#
#  Clean up all the files created when installing a new SAUpdate
#
################################################################################
{	my $dir		= shift;	# This should be the working dir
	my $renamer = shift;	# Don't delete the new update program if set
	
	&SecurityLogEvent( "Update: Cleaning up old install and event files ...\n" );
	
	my $cur_dir = getcwd();
	
	chdir( $dir );
	
	
	# Get rid of any UpdateEvent*.zip files
	if ( !opendir( WDIRHANDLE, $dir ) )
		{	&SecurityLogEvent( "Error opening directory $dir: $!\n" );
		}
	else
		{	for my $item ( readdir( WDIRHANDLE ) ) 
				{	next if ( ! defined $item );
					unlink( $item ) if ( ( $item =~ m/^UpdateEvent/ )  &&  ( $item =~ m/\.zip$/ ) );
				}
	
			closedir( WDIRHANDLE );
		}
		

	# SA 6.0 version
	&ScanNoReadOnly( "sa7update.htm" );
	&ScanNoReadOnly( "sa62update.htm" );
	&ScanNoReadOnly( "sa6update.htm" );

	&ScanNoReadOnly( "saexport.htm" );
	
	&ScanNoReadOnly( "scan.old" );
	&ScanNoReadOnly( "scan.new" );
	
	&ScanNoReadOnly( "satray.old" );
	&ScanNoReadOnly( "satray.new" );

	&ScanNoReadOnly( "saalert.old" );
	&ScanNoReadOnly( "saalert.new" );
	
	&ScanNoReadOnly( "sadash.old" );
	&ScanNoReadOnly( "sadash.new" );
	
	&ScanNoReadOnly( "sascan.old" );
	&ScanNoReadOnly( "sascan.new" );
	
	&ScanNoReadOnly( "saexplorer.old" );
	&ScanNoReadOnly( "saexplorer.new" );
	
	&ScanNoReadOnly( "sadashhtml.old" );
	&ScanNoReadOnly( "sadashhtml.new" );
	
	&ScanNoReadOnly( "scanclient.old" );
	&ScanNoReadOnly( "scanclient.new" );

	
	# Same names as 5.0
	&ScanNoReadOnly( "securityagent.old" );
	&ScanNoReadOnly( "securityagentnew.exe" );
	
	&ScanNoReadOnly( "securityagentshellext.old" );
	&ScanNoReadOnly( "securityagentshellextnew.dll" );
	
	&ScanNoReadOnly( "securityagentbho.old" );
	&ScanNoReadOnly( "securityagentbhonew.dll" );
	
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


	# Clean up any old IpmSecurityAgent driver
	my $system_dir = &ScanSystemDirectory();
	
	if ( -e "$system_dir\\IpmSecurityAgent.sys" )
		{	&ScanNoReadOnly( "$system_dir\\IpmSecurityAgent.sys" );
			rename( "$system_dir\\IpmSecurityAgent.sys", "$system_dir\\IpmSecurityAgent.sys.old" ); 
		}
	
	unlink( "$system_dir\\IpmSecurityAgent.sys.old" );
	
	# These virus signature files are no longer needed
	unlink( "$system_dir\\VirusSignatures.nx" );
	unlink( "$system_dir\\AllowSignatures" );
	unlink( "$system_dir\\VirusSignatures.tmp" );
	unlink( "$system_dir\\FileID.idl" );
	unlink( "$system_dir\\FileID.idl.bak" );
	unlink( "$system_dir\\FileID.idl.bak1" );
	
	unlink "sa7update.htm";
	unlink "sa7update.old";
	unlink "sa7update.new";
	
	unlink "sa62update.htm";
	unlink "sa62update.old";
	unlink "sa62update.new";

	unlink "sa6update.htm";
	unlink "sa6update.old";
	unlink "sa6update.new";

	unlink "saexport.htm";
	
	# Delete any incremental update files
	for ( my $i = 0 + 1;  $i <= 50;  $i++ )
		{	my $update_file = "SAExport-$i.htm";
			unlink( $update_file );
			my $update_zip = "SAExport-$i.zip";
			unlink( $update_zip );
		}
	
	# Delete any leftover XML files
	unlink "category.xml";
	unlink "virussignatures.xml";
	unlink "bannedprocess.xml";
	unlink "fileintegrity.xml";
	unlink "fileid.xml";
	unlink "registrycontrol.xml";
	unlink "disinfect.xml";
	unlink "policy.xml";
	unlink "policydefinition.xml";
	unlink "requiredsoftware.xml";
	
	unlink "securityagent.old";
	unlink "securityagentnew.exe";
	
	# SA 6.4 - no longer need this
	unlink "salsp.dll" if ( $version gt '6.04.00' );
	
	# SA 6.0 files
	unlink "satray.new";
	unlink "satray.old";
	
	unlink "saalert.new";
	unlink "saalert.old";
	
	unlink "sadash.new";
	unlink "sadash.old";
	
	unlink "scanclient.new";
	unlink "scanclient.old";
	
	# Handle the case where the SaScan.exe doesn't get updated properly...	
	rename( "sascan.new", "SaScan.exe" ) if ( ( -e "sascan.new" )  &&  ( ! -e "sascan.exe" ) );

	unlink "sascan.new";
	unlink "sascan.old";
	
	# Handle the case where the SaExplorer.exe doesn't get updated properly...	
	rename( "saexplorer.new", "SaExplorer.exe" ) if ( ( -e "saexplorer.new" )  &&  ( ! -e "saexplorer.exe" ) );

	unlink "saexplorer.new";
	unlink "saexplorer.old";
	
	unlink "sadashhtml.new";
	unlink "sadashhtml.old";


	unlink "securityagentshellextnew.dll";
	unlink "securityagentshellext.old";
	
	unlink "securityagentbhonew.dll";
	unlink "securityagentbho.old";
	
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
	
	&SecurityLogEvent( "Update: Checking to see if it is time to run the background virus scan ...\n" );
	
	# Check to see if there is another copy of scan already running ...
	if ( &IsScanRunning() )
		{	&SecurityLogEvent( "Update: The background virus scan is already running so will try again later\n" );
			return( undef, $last_purge_started );
		}
		
	&SecurityLogEvent( "Update: Start security scan now command line option has been set\n" ) if ( $scan_now );
	
	$last_scan_started  = 0 if ( ! $last_scan_started );
	$last_scan_started  = 0 + $last_scan_started;
	
	$last_purge_started = 0 if ( ! $last_purge_started );
	$last_purge_started = 0 + $last_purge_started;


	# Load Properties (they may have been set by a policy)
	&LoadProperties();


	# Get the last scan time I finished - this is set by the scan program
	my $key;
	my $data;
	my $type;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );

	my $last_scan_finished = 0 + 0;
	$ok = &RegQueryValueEx( $key, "Last Scan Finished", [], $type, $data, []) if ( $ok );
	my $len = length( $data );
	$last_scan_finished = $data if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data ) );
	$last_scan_finished = 0 + $last_scan_finished;
	
	
	# Get the registry value that set to scan the system or not - this might not exist
	my $scan_system = 1;
	$ok = &RegQueryValueEx( $key, "Scan System", [], $type, $data, []);
	$len = length( $data );
	$scan_system = undef if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
	
	
	# Should Lightspeed analyze unknown program info?
	my $lightspeed_analyze_unknown = 1;
	$ok = &RegQueryValueEx( $key, "Lightspeed Analyze Unknown", [], $type, $data, []);
	$len = length( $data );
	$lightspeed_analyze_unknown = undef if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
	
	
	&RegCloseKey( $key );
		

	# At this point I need to make a decision about if I should scan now, and
	# what scan option to use ...
	
	# Am I supposed to do system scans at all?
	# Quit if I'm not doing an initial scan, and I'm not being forced to scan
	if ( ( ! $scan_system )  &&  ( ! $scan_now ) )
		{	&SecurityLogEvent( "Update: Not scanning now because the \"Scan System\" parameter is turned off\n" );
			return( undef, $last_purge_started );	
		}
	
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
	
	# If it is less than 12 hours later - bail out here
	if ( ( $diff_hours < ( 0 + 12 ) )  &&  ( ! $scan_now ) )
		{	# Round it off
			$diff_hours = sprintf( "%d", $diff_hours );
			&SecurityLogEvent( "Update: Not scanning now because the last scan was only $diff_hours hours ago\n" );
			return( undef, $last_purge_started );	
		}
	

	# If it is not yet the right time of day to scan, bail out here
	my $current_hour	= 0 + $hour;
	
	# Make sure the scan time is not some insane number - it should be between 0 to 23 inclusive
	$scan_time = 0 + 18 if ( ( ! defined $scan_time )  ||  ( $scan_time < 0 )  ||  ( $scan_time > 23 ) );
	my $scan_hour		= 0 + $scan_time;

	if ( ( $current_hour < $scan_hour )  &&  ( ! $scan_now ) )
		{	# Format the time so that it prints pretty
			my $current		= sprintf( "%02d:%02d", $hour, $min );
			my $scan_start	= sprintf( "%02d:00", $scan_hour );
			&SecurityLogEvent( "Update: Not scanning now because the current time is $current and it is before the scan start time of $scan_start\n" );
			return( undef, $last_purge_started );	
		}

	
	if ( ( $current_hour > $scan_hour )  &&  ( ! $scan_now ) )
		{	# Format the time so that it prints pretty
			my $current		= sprintf( "%02d:%02d", $hour, $min );
			my $scan_start	= sprintf( "%02d:00", $scan_hour );
			&SecurityLogEvent( "Update: Not scanning now because the current time is $current and it is past the scan start time of $scan_start\n" );
			return( undef, $last_purge_started );	
		}

	
	# Check to see if it is the right week day to scan
	# First make sure the scan interval is not something insane
	$scan_interval = "Friday" if ( ! defined $scan_interval );
	$scan_interval = &OneOf( $scan_interval, "Friday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Everyday", "Saturday", "Daily" );

	if ( ( ! $scan_now )  &&  ( $scan_interval =~ m/Everyday/i ) )
		{	$scan_now = 1;
			&SecurityLogEvent( "Update: The scan interval is set to $scan_interval\n" );
		}
	elsif ( ( ! $scan_now )  &&  ( $scan_interval =~ m/Daily/i ) )
		{	$scan_now = 1;
			&SecurityLogEvent( "Update: The scan interval is set to $scan_interval\n" );
		}
	elsif( ! $scan_now )
		{	$scan_now = 1 if ( ( $scan_interval =~ m/Sunday/i )		&&  ( $wday == 0 ) );
			$scan_now = 1 if ( ( $scan_interval =~ m/Monday/i )		&&  ( $wday == 1 ) );
			$scan_now = 1 if ( ( $scan_interval =~ m/Tuesday/i )	&&  ( $wday == 2 ) );
			$scan_now = 1 if ( ( $scan_interval =~ m/Wednesday/i )	&&  ( $wday == 3 ) );
			$scan_now = 1 if ( ( $scan_interval =~ m/Thursday/i )	&&  ( $wday == 4 ) );
			$scan_now = 1 if ( ( $scan_interval =~ m/Friday/i )		&&  ( $wday == 5 ) );
			$scan_now = 1 if ( ( $scan_interval =~ m/Saturday/i )	&&  ( $wday == 6 ) );
			
			&SecurityLogEvent( "Update: Not scanning now because the scan interval is set to $scan_interval\n" ) if ( ! $scan_now );
		}
		
		
	# Is it time to scan?
	return( undef, $last_purge_started ) if ( ! $scan_now );
	
	# Ok - at this point I've decided to scan.  What options should I use?	
		
	my $dir = &ScanWorkingDirectory();

	my $full_filename = $dir . "\\scan.exe";
	
	
	# Purge the file integrity file once a year after first purging it
	my $max_purge_time = 365 * 24 * 60 * 60;
	my $purge_diff = $current_time - $last_purge_started;
	
	
	# Build up the command line argument to the scan utility
	my $cmd;
	if ( ( $scan_type )  &&  ( $scan_type eq "quick" ) )
		{	$cmd = "scan -q -e";
		}
	else
		{	$cmd = "scan -a -e";	# Scan all the local fixed drives

			# Should I purge the file integrity file now?  I can only do this if I have the -a switch on
			$cmd = $cmd . " -p" if ( $purge_diff > $max_purge_time );
		}
	
	
	if ( ! $last_scan_finished )
		{	&SecurityLogEvent( "Update: This is the first scan so doing a one time full scan and adding all the unknown programs into the FileIntegrity database ...\n" );
			$cmd = "scan -a -e -u";	
		}
	
	&SecurityLogEvent( "Update: Scanning now with command line: $cmd\n" );


	$last_purge_started = $current_time if ( $cmd =~ m /\-p/ );	
	
		
	my $outgoing_process;	
	$ok = Win32::Process::Create( $outgoing_process, $full_filename, $cmd, 0, IDLE_PRIORITY_CLASS, $dir );
	if ( ! $ok )
			{	my $str = Win32::FormatMessage( Win32::GetLastError() );
				&SecurityLogEvent( "Update: Unable to create outgoing process $full_filename: $str\n" );
			}	
		else
			{	&SecurityLogEvent( "Update: Started scanning disks ...\n" );
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
		{	&SecurityLogEvent( "Update Error: Unable to switch to the directory $dir: $!\n" );
			return;	
		}
	
	
	# Make sure everything is not readonly
	&ScanNoReadOnly( "Update\.new" );
	&ScanNoReadOnly( "Update\.exe" );
	&ScanNoReadOnly( "Update\.old" );

	
	# Make sure the UpdateExt program is there
	if ( ! -e "UpdateExt\.exe" )
		{	&SecurityLogEvent( "Update Error: the UpdateExt\.exe program is not in the current directory $dir\n" );
			return;	
		}
	
	
	# Make sure the new version is there
	if ( ! -e "Update\.new" )
		{	&SecurityLogEvent( "Update Error: the new Update\.new program is not in the current directory $dir\n" );
			return;	
		}
	
	
	# Make sure the old version is there
	if ( ! -e "Update\.exe" )
		{	&SecurityLogEvent( "Update Error: the old Update\.exe program is not in the current directory $dir\n" );
			return;	
		}
	
	
	# Make sure the 2 files are different
	if ( ! &FileCompare( "Update\.exe", "Update\.new" ) )
		{	&SecurityLogEvent( "Update: The new Update.exe program is the same as the old program, so not changing it.\n" );
		
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
		
	&SecurityLogEvent( "Update: Installed new Update utility ok\n" );

	
	# Close the security log before running the UpdateExt program
	my $time = localtime( time() );	
	&SecurityLogEvent( "Update: Closed Security Agent Log: $time\n" );
	&SecurityCloseLogFile();
	
	
	# Run the UpdateExt program with the right arguments  
	exec "UpdateExt.exe Update.exe Update.old Update.new Update.exe";
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
	NET_FW_IP_PROTOCOL_TCP	=>  6,
	NET_FW_IP_PROTOCOL_UDP =>  17
	};


	&SecurityLogEvent( "Update: Checking to see if the Security Agent ports 1305 UDP & TCP are added to the Windows firewall exceptions list.\n" );

	#  See if the key already exists
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List\\1305:TCP", 0, KEY_READ, $key );
	my $tcp_exists = 1 if ( $ok );
	&RegCloseKey( $key ) if ( $ok );

	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List\\1305:UDP", 0, KEY_READ, $key );
	my $udp_exists = 1 if ( $ok );
	&RegCloseKey( $key ) if ( $ok );

	
	if ( ( $tcp_exists )  &&  ( $udp_exists ) )
		{	&SecurityLogEvent( "Update: Security Agent ports 1305 UDP & TCP are already added to the Windows firewall exceptions list.\n" );
			return( 1 );
		}
		
		
	# Figure out the full path of the securityagent.exe service
	my $dir = &ScanWorkingDirectory();
	my $fullpath = $dir . "\\SecurityAgent.exe";
	

	# Add our ports (TCP/UDP 1305) to the Windows firewall exceptions list
	my $fwMgr = Win32::OLE->new( "HNetCfg.FwMgr" );
	
	if ( ! $fwMgr )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "Update: The Windows firewall service is not running.\n" );
			return( undef );
		}


	# Make sure that I can find the local policy
	my $local_policy = $fwMgr->LocalPolicy;
	if ( ! $local_policy )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "Update Error: OLE error getting the firewall local policy: $err_msg.\n" );
			return( undef );
		}
		
		
	# Get the current profile for the local firewall policy.
	my $profile = $fwMgr->LocalPolicy->{CurrentProfile};
	
	if ( ! $profile )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "Update: The Windows firewall service is not running.\n" );
			return( undef );
		}


	# Add the TCP port into the Windows Firewall port exceptions list.
	my $port = Win32::OLE->new( "HNetCfg.FwOpenPort" );
	if ( ! $port )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "Update Error: OLE error getting the FwOpenPort object: $err_msg.\n" );
			return( undef );
		}


	$port->{Port} 		= 1305;
	$port->{Name}		= "Lightspeed Security Agent (TCP)";
	$port->{Enabled}	= 1;
	$port->{Protocol}	= NET_FW_IP_PROTOCOL_TCP;

	$profile->GloballyOpenPorts->Add( $port );

	my $errornum = 0 + Win32::OLE->LastError();

	if ( $errornum )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "Update Error: OLE error adding TCP Port to the Windows firewall exceptions list: $err_msg.\n" );
			return( undef );
		}


	# Add the UDP port into the Windows Firewall port exceptions list.
	$port = Win32::OLE->new( "HNetCfg.FwOpenPort" );
	if ( ! $port )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "Update Error: OLE error getting the FwOpenPort object: $err_msg.\n" );
			return( undef );
		}


	$port->{Port} 		= 1305;
	$port->{Name}		= "Lightspeed Security Agent (UDP)";
	$port->{Enabled}	= 1;
	$port->{Protocol}	= NET_FW_IP_PROTOCOL_UDP;

	$profile->GloballyOpenPorts->Add( $port );

	$errornum = 0 + Win32::OLE->LastError();

	if ( $errornum )
		{	my $err_msg = Win32::OLE->LastError();
			$err_msg = "Unknown" if ( ! $err_msg );
			&SecurityLogEvent( "Update Error: OLE error adding UDP Port to the Windows firewall exceptions list: $err_msg.\n" );
			return( undef );
		}


	&SecurityLogEvent( "Update: Successfully added the Security Agent ports to the Windows firewall exceptions list.\n" );
	
	return( 1 );
}



################################################################################
# 
sub CheckServerService()
#
#  Check to make sure the Server service (lanmanserver) is running
#  It it isn't, start it ...
#
################################################################################
{
use Win32::OLE qw( in );

	&SecurityLogEvent( "Update: Making sure that the \"Server\" service is running ...\n" );
	
	my $Machine = ".";
	my $WMIServices = Win32::OLE->GetObject( "winmgmts:{impersonationLevel=impersonate,(security)}//$Machine" );

	return( 1 ) if ( ! defined $WMIServices );

	my $Class = "Win32_Service";
	my $service_list = $WMIServices->InstancesOf( $Class );


	# This is the status of each share
	foreach my $item ( in( $service_list ) ) 
		{	my $name	= $item->{Name};
			next if ( ! defined $name );
			
			# Looking for the lanmanserver service
			if ( lc( $name ) eq "lanmanserver" )
				{	my $desc	= $item->{Description};
			
					my $started = $item->{Started};

					last if ( $started );
					
					&SecurityLogEvent( "Update: Asking WMI to start the \"Server\" service ...\n" );
					$item->StartService();
					
					last;
				}
		}
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
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_ALL_ACCESS, $key );

	&SecurityLogEvent( "Update: Checking Microsoft Simple File Sharing settings ...\n" );
	
	if ( ! $ok )
		{	&SecurityLogEvent( "Update: Unable to check Microsoft Simple File Sharing settings\n" );
			return( undef );
		}
			
	my $current_value;
	my $value = "\x00\x00\x00\x00";
	my $type;
	
	$ok = &RegQueryValueEx( $key, "forceguest", [], $type, $current_value, []);
	my $len = length( $current_value );
	
	if ( ( $len <= 0 )  ||  ( ! $current_value )  ||  ( $current_value ne $value ) )
		{	$ok = &RegSetValueEx( $key, "forceguest", 0,  REG_DWORD, $value );
			&SecurityLogEvent( "Update: Turned Microsoft Simple File Sharing off to allow Security Agent remote access.\n" ) if ( $ok );
			&SecurityLogEvent( "Update: Unable to set Microsoft Simple File Sharing to allow the Security Agent remote access.\n" ) if ( ! $ok );
		}
	else
		{	#&SecurityLogEvent( "Microsoft Simple File Sharing is set to allow Security Agent remote access.\n" )
		}
		
	&RegCloseKey( $key );

	return( 1 );
}



################################################################################
# 
sub UpdateLmhostsTimeout()
#
#  Make sure that LmhostsTimeout is set correctly so the FQDN resolution works correctly
#
################################################################################
{	my $key;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters", 0, KEY_ALL_ACCESS, $key );

	&SecurityLogEvent( "Update: Checking Microsoft Lmhosts timeout settings ...\n" );
	
	if ( ! $ok )
		{	&SecurityLogEvent( "Update: Unable to check Microsoft Lmhosts timeout settings\n" );
			return( undef );
		}
	
	my $min_timeout = 15 * 1000;	# This timeout is in milliseconds - default it to a minimum of 15 seconds		
	my $current_dword;
	my $current_value = 0 + 0;
	my $type;
	
	$ok = &RegQueryValueEx( $key, "LmhostsTimeout", [], $type, $current_dword, []);
	my $len = length( $current_dword );
	
	$current_value = unpack( "L", $current_dword ) if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $current_dword ) );
	
	if ( ( defined $current_value )  &&  ( defined $min_timeout )  &&  ( $current_value < $min_timeout ) )
		{	$current_dword = pack( "L", $min_timeout );
			$ok = &RegSetValueEx( $key, "LmhostsTimeout", 0,  REG_DWORD, $current_dword );
			&SecurityLogEvent( "Update: Set Microsoft Lmhosts timeout to $min_timeout milliseconds.\n" ) if ( $ok );
			&SecurityLogEvent( "Update: Unable to set Microsoft Lmhosts timeout.\n" ) if ( ! $ok );
		}
	else
		{	#&SecurityLogEvent( "Microsoft Simple File Sharing is set to allow Security Agent remote access.\n" )
		}
		
	&RegCloseKey( $key );

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
  -n, --noexplorer       unregister the explorer shell extention
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
