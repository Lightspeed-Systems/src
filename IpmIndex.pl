################################################################################
#!perl -w
#
# Rob McCarthy's IpmIndex source code
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Fcntl qw(:DEFAULT :flock);
use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;
use Win32::EventLog;
use Win32::File;
use Archive::Zip qw( :ERROR_CODES );
use Win32::Process;
use Cwd;


use Pack::PackUtil;
use Content::File;
use Content::SQL;
use Content::Index;
use Content::Process;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging;				# True if I should log to the file IpmCache.log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_wizard;					# True if run from a Wizard dialog
my $_version = "1.0.0";
my %properties;



my $index_unique_event_name	= "IpmIndexUniqueEvent";
my $unique_event;


my $dbh;             			# My database handle to the Content Database
my $dbhStat;             		# My database handle to the Statistics Database
my $archive_path;				# The path to the Mail Archive



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
        "d|debug"	=> \$opt_debug,
        "l|logging" => \$opt_logging,
        "v|version" => \$opt_version,
        "h|help"	=> \$opt_help,
        "w|wizard"	=> \$opt_wizard,
        "x|xxx"		=> \$opt_debug,
    );

	
    &StdHeader( "IpmIndex" ) if ( ! $opt_wizard );
	
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	
	# Give myself debug privileges
	&ProcessSetDebugPrivilege();

	# Make sure that I'm the only IpmIndex program running
	my $ok = &KillOtherIpmIndex();
	
	
	# Kill any IpmArchive processes that are running
# Don't kill these - they might be reindexing
#	&ProcessKillName( "IpmArchive.exe" );
	
	# Kill any IpmArchiveBackup processes that are running
	&ProcessKillName( "IpmArchiveBackup.exe" );
	
	# Kill any POP3Connecter processes that are running
	&ProcessKillName( "POP3Connecter.exe" );
	
	&debug( "Debugging messages turned on\n" );
	
	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
		
	&SetLogFilename( 'IpmIndex.log', $opt_debug );
	
			
	# Get the properties out of the current configuration
	&GetProperties();

		
	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	my $dir = &SoftwareDirectory();
	my $index_dir = $dir . "\\Mail Archive\\Index";
	&BuildDirectory( $index_dir );
	
	my $sa_import_dir = $dir . "\\Mail Archive\\SAImport";
	&BuildDirectory( $sa_import_dir );
	
	
    $dbh = &ConnectServer() or &FatalError( "Unable to connect to Content SQL database\n" );
    $dbhStat = &ConnectStatistics() or &FatalError( "Unable to connect to Statistics SQL database\n" );

	$ok = &PackUtilGetProperties( \%properties, 1 );
	my $archive_internal = $properties{ "Archive Internal Mail" };
	my $archive_incoming = $properties{ "Archive Incoming Mail" };
	my $archive_outgoing = $properties{ "Archive Outgoing Mail" };

	my $index_email;
	$index_email = 1 if ( ( $archive_internal )  &&  ( $archive_internal eq "\x01\x00\x00\x00" ) );
	$index_email = 1 if ( ( $archive_incoming )  &&  ( $archive_incoming eq "\x01\x00\x00\x00" ) );
	$index_email = 1 if ( ( $archive_outgoing )  &&  ( $archive_outgoing eq "\x01\x00\x00\x00" ) );

	# If I'm not going to call IpmArchive at this point, are there some Backup documents on this server?
	if ( ( ! $index_email )  &&  ( &ArchiveBackupFiles() ) )
		{	$index_email = 1;
		}


	&POP3Cleanup();


	&lprint( "Ready to call IpmArchive to index email and instant messaging ...\n" ) if ( $index_email );	

	
	# Are any email backup servers defined?
	my $email_backup;
	my @backup = ( "Backup Server 1", "Backup Server 2", "Backup Server 3", "Backup Server 4", "Backup Server 5" );
	foreach ( @backup )
		{	my $server = $_;
			my $server_name = $properties{ $server };
			$email_backup = 1 if ( ( $server_name )  &&  ( length( $server_name ) > 1 ) );
		}
	
	$email_backup = undef if ( ! $index_email );
	
	
	&lprint( "Waiting for SQL server to come up to speed ..." );
	sleep( 120 );
	
	&lprint( "Ready to call IpmArchiveBackup to backup email and instant messaging ...\n" ) if ( $email_backup );	
	
	
	# Loop forever waiting for something to happen
	&lprint( "Ready to process Security Agent events ...\n" );	
	my $ret;
	my $done;
	
	my $wait_time = 0 + 5;	# This is the number of minutes to wait until looping again
    while ( ! $done )    
		{	my $work;
			
			$ok = &PackUtilGetProperties( \%properties, 1 );
			
			my $pop1 = $properties{ "POP3 Server 1" };
			my $pop2 = $properties{ "POP3 Server 2" };
			my $pop3 = $properties{ "POP3 Server 3" };

			&ProcessPOP3()		if ( ( $pop1 )  ||  ( $pop2 )  ||  ( $pop3 ) );
			
			&ProcessArchive()	if ( $index_email );
			&ProcessBackup()	if ( $email_backup );
			
			$work = &ProcessSAImport( $sa_import_dir );
			
			chdir( $cwd );	
			
			$done = 1 if ( $opt_debug );
			
			if ( ( ! $work )  &&  ( ! $done ) )
				{	&lprint( "Waiting $wait_time minutes for events to process ...\n" );
					sleep( 60 * $wait_time );
				}
		}
	
	&lprint( "Ending the IpmIndex process\n" );
	
	chdir( $cwd );
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
# 
sub ArchiveBackupFiles( $ )
#
#  Return True if there are backup email files to be archived
#
################################################################################
{	my $queue_dir = $properties{ "Queue Directory" };
	
	return( undef ) if ( ! $queue_dir );
	
	my $queue_backup_dir = "$queue_dir\\Backup";

	return( undef ) if ( ! -d  $queue_backup_dir );
	
	return( undef ) if ( ! opendir( BACKUP_DIR, $queue_backup_dir ) );
	
	my $exists;
	while ( my $file = readdir( BACKUP_DIR ) )
		{	my $full_file = "$queue_backup_dir\\$file";
			
			# Ignore directories
			next if ( -d $full_file );
			
			$exists = 1;
			last;
		}
		
	closedir( BACKUP_DIR );
	
	return( $exists );
}



################################################################################
# 
sub POP3Cleanup()
#
#  Cleanup any POP3 tmp files left in the software directory
#
################################################################################
{	my $software_dir = &SoftwareDirectory();
	
	return( undef ) if ( ! $software_dir );
	return( undef ) if ( ! -d $software_dir );
	
	&lprint( "Checking for old temporary POP3Connecter files ...\n" );

    # Process the directory
    opendir( DIR, $software_dir );

	my $file_counter = 0 + 0;
	
    while ( my $file = readdir( DIR ) )
        {	next if ( ! $file );
			
			my $full_filename = "$software_dir\\$file";
			
            # Skip anything that isn't a normal file
            next if ( ! -f $full_filename );

			next if ( ! ( $file =~ m/^pop3connecter/i ) );
			
			next if ( ! ( $file =~ m/\.dat$/i ) );
			
			unlink( $full_filename );
			
			$file_counter++;
        }

	closedir( DIR );
	
	&lprint( "Deleted $file_counter temporary POP3Connecter files\n" ) if ( $file_counter );
	
	return( 1 );
}



################################################################################
# 
sub ProcessPOP3()
#
#  Run the POP3Connecter program to archive any email
#
################################################################################
{		
	my $software_dir = &SoftwareDirectory();

	my $full_filename = $software_dir . "\\POP3Connecter.exe";
	
	# Does the program exist?
	if ( ! -f $full_filename )
		{	&lprint( "$full_filename does not exist\n" );
			return( undef );
		}  
		   
		   
	# Set up in the right directory
	my $old_cwd = getcwd;
	$old_cwd =~ s#\/#\\#gm;
	
	chdir( $software_dir );
	
	
	for ( my $i = 1;  $i <= 3;  $i++ )
		{	my $server_property = "POP3 Server $i";
			my $server = $properties{ $server_property };
			
			my $username_property = "POP3 Username $i";
			my $username = $properties{ $username_property };
			
			my $password_property = "POP3 Password $i";
			my $password = $properties{ $password_property };
			
			my $ssl_property = "Use SSL $i";
			my $use_ssl = $properties{ $ssl_property };
			$use_ssl = undef if ( ( $use_ssl )  &&  ( $use_ssl eq "0" ) );

			next if ( ! $server );
			next if ( ! $username );
			next if ( ! $password );
			
			&CreatePOP3Connecter( $full_filename, $server, $username, $password, $use_ssl );
		}
		
	chdir( $old_cwd );
	
	return( 1 );
}



################################################################################
# 
sub CreatePOP3Connecter( $$$$$ )
#
#  Create a POP3 Connecter process if one is not already running for the given server
#
################################################################################
{	my $full_filename	= shift;
	my $server			= shift;
	my $username		= shift;
	my $password		= shift;
	my $use_ssl			= shift;
	
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $server );
	return( undef ) if ( ! $username );
	return( undef ) if ( ! $password );


	# Check to see if it is already running and connected to this server
	my %processes = &ProcessHash();
	my $software_dir = &SoftwareDirectory();

	while ( my ( $pid, $process_name ) = each( %processes ) )
		{
			next if ( ! $pid );
			next if ( ! $process_name );
			next if ( ! ( $process_name =~ m/pop3connecter/i ) );
			
			# Open the POP3Connecter dat file for this process and see what server it is running
			my $pop3dat_file = "$software_dir\\Pop3Connecter-$pid.dat";
			next if ( ! open( POP3DAT, "<$pop3dat_file" ) );
			
			my $line = <POP3DAT>;
			chomp( $line );

			my ( $working_server, $working_username ) = split /\t/, $line, 2 if ( $line );
			
			close( POP3DAT );
			
			next if ( ! $working_server );
			next if ( ! $working_username );
			
			if ( ( $working_server eq $server )  &&  ( $working_username eq $username ) )
				{	&lprint( "The POP3Connecter is already connected to server $server and username $username\n" );
					return( 0 + 0 );
				}
		}


	# OK - at this point I know I need to run the POP3Connecter, and it isn't already connected to this server
	&lprint( "Creating a POP3Connecter task to connect to server $server and username $username ...\n" );
	&lprint( "Full path: $full_filename\n" );
	&lprint( "Using SSL to connect ...\n" ) if ( $use_ssl );
	
	
	my $cmd = "POP3Connecter.exe $server $username $password" if ( defined $password );
	$cmd = "POP3Connecter.exe $server $username" if ( ! defined $password );
	
	$cmd .= " -a" if ( $use_ssl );
	
	
	&lprint( "Command line: $cmd\n" );
	

	my $outgoing_process;	
	my $ok = Win32::Process::Create( $outgoing_process, $full_filename, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	if ( ! $ok )
		{	my $str = Win32::FormatMessage( Win32::GetLastError() );
			&lprint( "Unable to create outgoing process $full_filename: $str, command line $cmd\n" );
			
			return( undef );
			
		}

	&lprint( "Created POP3Connecter task ok\n" );
	
	return( 1 );
}



################################################################################
# 
sub ProcessArchive()
#
#  Run the IpmArchive program to archive any email
#
################################################################################
{	# Is the IpmArchive program already running?
	return( undef ) if ( &ProcessRunningName( "IpmArchive.exe" ) );
	
	my $software_dir = &SoftwareDirectory();

	my $full_filename = $software_dir . "\\IpmArchive.exe";
	
	# Does the program exist?
	if ( ! -f $full_filename )
		{	&lprint( "$full_filename does not exist\n" );
			return( undef );
		}  
		   
		   
	my $cmd = "IpmArchive.exe";
	
	# Set up in the right directory
	my $old_cwd = getcwd;
	$old_cwd =~ s#\/#\\#gm;
	
	chdir( $software_dir );
		
	my $outgoing_process;	
	my $ok = Win32::Process::Create( $outgoing_process, $full_filename, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	if ( ! $ok )
		{	my $str = Win32::FormatMessage( Win32::GetLastError() );
			&lprint( "Unable to create outgoing process $full_filename: $str\n" );
			chdir( $old_cwd );
			
			return( undef );
			
		}
		
	chdir( $old_cwd );
	return( 1 );
}



################################################################################
# 
sub ProcessBackup()
#
#  Run the IpmArchiveBackup program to backup any email
#
################################################################################
{	# Is the IpmArchiveBackup program already running?
	return( undef ) if ( &ProcessRunningName( "IpmArchiveBackup.exe" ) );
	
	my $software_dir = &SoftwareDirectory();

	my $full_filename = $software_dir . "\\IpmArchiveBackup.exe";
	
	# Does the program exist?
	if ( ! -f $full_filename )
		{	&lprint( "$full_filename does not exist\n" );
			return( undef );
		}  
		   
		   
	my $cmd = "IpmArchiveBackup.exe";
	
	# Set up in the right directory
	my $old_cwd = getcwd;
	$old_cwd =~ s#\/#\\#gm;
	
	chdir( $software_dir );
		
	my $outgoing_process;	
	my $ok = Win32::Process::Create( $outgoing_process, $full_filename, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	if ( ! $ok )
		{	my $str = Win32::FormatMessage( Win32::GetLastError() );
			&lprint( "Unable to create outgoing process $full_filename: $str\n" );
			chdir( $old_cwd );
			
			return( undef );
			
		}
		
	chdir( $old_cwd );
	return( 1 );
}



################################################################################
# 
sub KillOtherIpmIndex()
#
#  Make sure that I'm the only IpmIndex program running
#
################################################################################
{	
	# At this point I've been nice - now I'm getting mean
	my $my_pid = &ProcessGetCurrentProcessId();

	my %processes = &ProcessHash();
	
	# Figure out if there are any IpmIndex processes running besides myself
	my @process_names	= values %processes;
	my @process_pids	= keys %processes;
	
	my @kill_pids;
	
	my $index = 0 - 1;
	foreach ( @process_names )
		{	$index++;
			
			next if ( ! $_ );
			
			my $name = lc( $_ );
			
			# Is this an IpmIndex process?
			next if ( ! ( $name =~ m/ipmindex\.exe/ ) );
			
			my $this_pid = $process_pids[ $index ];
			
			next if ( $this_pid eq $my_pid );
	
			push @kill_pids, $this_pid;				 
		}


	print "Found IpmIndex processes running, so killing them now ...\n" if ( $kill_pids[ 0 ] );
	
	
	# If I found any, kill them
	foreach ( @kill_pids )
		{	next if ( ! $_ );
			my $kill_pid = $_;
			print "Killing process $kill_pid\n";
			ProcessTerminate( $kill_pid );
		}
		

	# At this point we are all set to go ...
	$unique_event = Win32::Event->new( 1, 0, $index_unique_event_name );
	if ( ! $unique_event )
		{	print "Unable to stop other IpmIndex programs from running\n";
			return( undef );
		}
		
	return( 1 );
}



################################################################################
# 
sub ProcessSAImport( $ )
#
#  Go through the SAImport directory, processing any UpdateEvent files stored there
#  Return True if I did some work, undef if not
#
################################################################################
{	my $sa_import_dir = shift;
	
	my $work = 0 + 0;
	
	chdir( $sa_import_dir );
	
    # Process the directory
    opendir( DIR, $sa_import_dir );

	my $file_counter = 0 + 0;
	
    while ( my $file = readdir(DIR) )
        {
            # Skip subdirectories
            next if ( -d $file );
            $file_counter++;
  			
			$work++ if ( &ProcessSAImportFile( $sa_import_dir, $file ) );
        }

	closedir( DIR );
	
	return( $work );
}



################################################################################
# 
sub ProcessSAImportFile( $$ )
#
#  Given a single UpdateEvent files, process it
#  Return True if I did some work, undef if not
#
################################################################################
{	my $import_dir	= shift;
	my $import_file = shift;
	
	my $full_filename = "$import_dir\\$import_file";
	
	my $work = 0 + 0;

	# If the file doesn't end in .zip, then it isn't my file
	if ( ! ( $import_file =~ m/\.zip$/i ) )
		{	unlink( $full_filename );
			return( 1 );
		}
		
		
	my $zip = Archive::Zip->new( $full_filename );
	
	# If I can't read the zip file, delete it and return	
	if ( ! $zip )
		{	lprint "Unable to read zip file $full_filename\n";
			unlink( $full_filename );
			return( 1 );
		}
			
	my @members = $zip->memberNames();
	
	my @files;
	my $update_id_found;		# Set this to True if I found the required UpdateID.dat file
	
	foreach ( @members )
		{	my $member = $_;
			
			# Clean up the name and extract out just the filename to use
			my $mem = $member;
			$mem =~ s#\/#\\#g;

			my ( $original_dir, $original_file ) = &SplitFileName( $mem );

			# Flag that I found the UpdateID.dat file
			$update_id_found = 1 if ( $original_file =~ /UpdateID\.dat/i );
			
			# Get the filename extracted
			my @parts = split /\\/, $mem;
			
			my $error_code = $zip->extractMemberWithoutPaths( $member, $original_file );
			
			if ( $error_code != AZ_OK )
				{	lprint "Unzip error: extracting $original_file: $error_code\n";
				}
			else
				{	push @files, $original_file;
				}
		}

	unlink ( $full_filename ) if ( ! $opt_debug );
			
	
	# Read the UpdateID.dat file
	my %update_id;
	
	if ( $update_id_found )
		{	if ( open( UPDATE_ID, "<$import_dir\\UpdateID.dat" ) )
				{	while (my $line = <UPDATE_ID>)
						{	next if ( ! defined $line );
							
							chomp( $line );
							
							my ( $attribute, $value ) = split /\:/, $line, 2;
							
							next if ( ! defined $attribute );
							next if ( ! defined $value );
							
							# Get rid of leading whitespace in the value
							$value =~ s/^\s+//;
							
							$update_id{ $attribute } = $value;
						}
					
					close( UPDATE_ID );
				}
			else
				{	lprint "Unable to open UpdateID.dat: $!\n";
					$update_id_found = undef;
				}
		}


	# Did I find valid Update.dat info?
	$update_id{ "Computer Domain" } = "WORKGROUP" if ( ! defined $update_id{ "Computer Domain" } );

	$update_id_found = undef if ( ! defined $update_id{ "Computer Name" } );
	$update_id_found = undef if ( ! defined $update_id{ "Client IP" } );


	if ( ! $update_id_found )
		{	lprint "Could not read valid Update ID info from file $import_file\n";
			$update_id_found = undef;
		}
		
	
	my $computer_domain;
	my $computer_name;
	my $client_ip;
	my $sa_version;
	my $id;


	# If I found the UpdateID file ok, then set the values I need to get the computer ID value
	if ( $update_id_found )
		{	$computer_domain	= $update_id{ "Computer Domain" };
			$computer_name		= $update_id{ "Computer Name" };
			$client_ip			= $update_id{ "Client IP" };
			$sa_version			= $update_id{ "Security Agent Version" };
			
			# Figure out the computer id - create it if I have to
			$id = &SetComputerNameID( $computer_domain, $computer_name, $client_ip, $sa_version );
	
			if ( ! defined $id )
				{	lprint "Could not get the computer name id for $computer_domain\\$computer_name\n";
					$update_id_found = undef;
				}
		}
		

	# If I didn't get a valid update ID file, or I had some other problem, delete all the created files and return
	if ( ! $update_id_found )
		{	unlink ( $full_filename ) if ( ! $opt_debug );
			
			foreach ( @files )
				{	next if ( ! defined $_ );
					my $original_file = $_;
										
					if ( -e $original_file )
						{	unlink ( "$import_dir\\$original_file" ) if ( ! $opt_debug );
						}
				}
				
			return( 1 );
		}
		
		
	lprint "Processing Update events from $computer_domain\\$computer_name - $client_ip ...\n";

	
	foreach ( @files )
		{	next if ( ! defined $_ );
			my $original_file = $_;
					
			my $full_path = "$import_dir\\$original_file";
			
			lprint "Processing file $full_path ...\n";
			
			if ( -e $original_file )
				{	if ( $original_file =~ m/UpdateEvents\.dat/i )
						{	&ProcessSAImportUpdateEvents( $import_dir, $original_file, $id );
						}
					elsif ( $original_file =~ m/ScanAppProcess\.dat/i )
						{	&ProcessSAImportScanAppProcess( $import_dir, $original_file, $id );
						}
					elsif ( $original_file =~ m/UpdateID\.dat/i )
						{	# Don't do anything - just let it get deleted
						}
						
					unlink ( $full_path ) if ( ! $opt_debug );	
				}	
		}
	
	return( $work );
}



################################################################################
# 
sub ProcessSAImportUpdateEvents( $$$ )
#
#  Given the directory and filename and computer ID, insert the Update Events
#  into the Statistics database.  Return True if updated OK, undef if not
#
################################################################################
{	my $import_dir	= shift;
	my $import_file = shift;
	my $id			= shift;
	
	my $full_filename = "$import_dir\\$import_file";
	
	if ( ! open( EVENTS, "<$full_filename" ) )
		{	my $err = $!;
			lprint "Error opening $full_filename: $err\n";
			return( undef );
		}


	# These are the hashes and arrays holding the different UpdateEvents read out of the file
	my %system_info;
	my @event_log;
	my @policy_complience;
	my @service_actions;
	my @registry_event;
	my @removable_media;
	my @system_files;
	my @document_activity;

	
	my $event_type;	# This keeps track of the current event type that I am processing though
	
	while (my $line = <EVENTS>)
		{	chomp( $line );
			next if ( ! defined $line );
			
			
			# Am I setting or clearing an event type?
			if ( $line =~ m/<SystemInformation>/ )
				{	$event_type = "SystemInformation";
					%system_info = ();
					next;
				}
			elsif ( $line =~ m/<\/SystemInformation>/ )
				{	$event_type = undef;
					next;
				}
			
			if ( $line =~ m/<EventLog>/ )
				{	$event_type = "EventLog";
					next;
				}
			elsif ( $line =~ m/<\/EventLog>/ )
				{	$event_type = undef;
					next;
				}
								
			if ( $line =~ m/<PolicyComplience>/ )
				{	$event_type = "PolicyComplience";
					next;
				}
			elsif ( $line =~ m/<\/PolicyComplience>/ )
				{	$event_type = undef;
					next;
				}
				
			if ( $line =~ m/<ServiceActions>/ )
				{	$event_type = "ServiceActions";
					next;
				}
			elsif ( $line =~ m/<\/ServiceActions>/ )
				{	$event_type = undef;
					next;
				}
				
			if ( $line =~ m/<RegistryEvent>/ )
				{	$event_type = "RegistryEvent";
					next;
				}
			elsif ( $line =~ m/<\/RegistryEvent>/ )
				{	$event_type = undef;
					next;
				}
								
			if ( $line =~ m/<RemovableMedia>/ )
				{	$event_type = "RemovableMedia";
					next;
				}
			elsif ( $line =~ m/<\/RemovableMedia>/ )
				{	$event_type = undef;
					next;
				}
								
			if ( $line =~ m/<SystemFiles>/ )
				{	$event_type = "SystemFiles";
					next;
				}
			elsif ( $line =~ m/<\/SystemFiles>/ )
				{	$event_type = undef;
					next;
				}
								
				
			if ( $line =~ m/<DocumentActivity>/ )
				{	$event_type = "DocumentActivity";
					next;
				}
			elsif ( $line =~ m/<\/DocumentActivity>/ )
				{	$event_type = undef;
					next;
				}
								
				
			# At this point, if I don't have an event type, then I don't known what to do ...	
			if ( ! $event_type )
				{	lprint "Unclassified Update Event: $line\n";
					next;
				}
				
			
			# Now handle each update event type
			if ( $event_type eq "SystemInformation" )
				{	my ( $attribute, $value ) = split /\t/, $line, 2;
					
					if ( ( ! defined $attribute )  ||  ( ! defined $value ) )
						{	lprint "Error: bad attribute/value pair in SystemInformation\n"
						}
					else
						{	$system_info{ $attribute } = $value;
						}
				}
			elsif ( $event_type eq "EventLog" )
				{	push @event_log, $line;
				}
			elsif ( $event_type eq "PolicyComplience" )
				{	push @policy_complience, $line;
				}
			elsif ( $event_type eq "ServiceActions" )
				{	push @service_actions, $line;
				}
			elsif ( $event_type eq "RegistryEvent" )
				{	push @registry_event, $line;
				}
			elsif ( $event_type eq "RemovableMedia" )
				{	push @removable_media, $line;
				}
			elsif ( $event_type eq "SystemFiles" )
				{	push @system_files, $line;
				}
			elsif ( $event_type eq "DocumentActivity" )
				{	push @document_activity, $line;
				}
			else
				{	lprint "Unhandled Update Event type: $event_type\n";
				}
		}
		
	close EVENTS;
	

	# After reading all of the update events, add each one into the database
	&IndexInsertSysteminformation( $id, \%system_info );
	&IndexInsertEventLog( $id, \@event_log );
	&IndexInsertPolicyCompilence( $id, \@policy_complience );
	&IndexInsertServiceActions( $id, \@service_actions );
	&IndexInsertRegistryEvent( $id, \@registry_event );
	&IndexInsertRemovableMedia( $id, \@removable_media );
	&IndexInsertSystemFiles( $id, \@system_files );
	&IndexInsertDocumentActivity( $id, \@document_activity );
	
	
	return( 1 );
}



################################################################################
# 
sub ProcessSAImportScanAppProcess( $$$ )
#
#  Given the directory and filename and computer ID, insert the ScanAppProcess.dat
#  into the Statistics database.  Return True if updated OK, undef if not
#
################################################################################
{	my $import_dir	= shift;
	my $import_file = shift;
	my $id			= shift;
	
	my $full_filename = "$import_dir\\$import_file";
	
	if ( ! open( SCAN, "<$full_filename" ) )
		{	my $err = $!;
			lprint "Error opening $full_filename: $err\n";
			return( undef );
		}
	
	my %scan_results;
	
	while (my $line = <SCAN>)
		{	chomp( $line );
			next if ( ! defined $line );
		
			my ( $hex_file_id, $data ) = split /\t/, $line, 2;
			
			# Does the data look ok?
			next if ( ! defined $hex_file_id );
			next if ( length( $hex_file_id ) != 56 );
			next if ( ! defined $data );
			
			$scan_results{ $hex_file_id } = $data;
		}
		
	&IndexInsertScanResults( $id, \%scan_results );
	
	close SCAN;
	
	return( 1 );
}



################################################################################
# 
sub SetComputerNameID( $$$$ )
#
#  Get the computer ID for the given domain and computer name.  If it doesn't
#  exist then create.  Return the ID, or undef if I couldn't create it
#
################################################################################
{	my $computer_domain = shift;
	my $computer_name	= shift;
	my $client_ip		= shift;
	my $sa_version		= shift;
	
	return( undef ) if ( ! defined $computer_domain );
	return( undef ) if ( ! defined $computer_name );
	$sa_version = "Unknown" if ( ! defined 	$sa_version );

	my ( $id, $database_client_ip, $database_sa_version ) = &GetComputerNameID( $computer_domain, $computer_name );

	# Did I get an ID with everything matching?
	return( $id ) if ( ( defined $id )  &&  ( $database_client_ip eq $client_ip )  &&  ( $database_sa_version eq $sa_version ) );
	
	# OK - I either have to insert a new record, or update an old record
	my $ipaddress = &StringToIP( $client_ip );
	$ipaddress = 0 + 0 if ( ! $ipaddress );
	
	my $qcomputer_name = &IndexInsertSqlValue( $computer_name, 64 );
	my $qsa_version = &IndexInsertSqlValue( $sa_version, 32 );
	
	# Do I need to insert a new record?
	if ( ! defined $id )
		{	
			my $str = "INSERT INTO saComputerNames ( [Domain], Computer, IpAddress, AgentVersion ) VALUES 
			( \'$computer_domain\', \'$qcomputer_name\', ?, \'$qsa_version\' )";

			$dbhStat = &SqlErrorCheckHandle( $dbhStat );
			my $sth = $dbhStat->prepare( $str );
			$sth->bind_param( 1, $ipaddress,  DBI::SQL_BINARY );
			
			$sth->execute();

			&SqlErrorHandler( $dbhStat );
			$sth->finish();

			( $id, $database_client_ip, $database_sa_version ) = &GetComputerNameID( $computer_domain, $computer_name );
			
			if ( ! defined $id )
				{	lprint "Error: unable to insert computer name $computer_domain\\$computer_name into the database\n";
					lprint "SQL Statement: $str\n";
				}
		}
		
	# I just need to update an existing record	
	else	
		{	my $str = "UPDATE saComputerNames SET IpAddress = ?, AgentVersion = \'$qsa_version\', UpdateTime = getdate() WHERE ID = \'$id\'";

			$dbhStat = &SqlErrorCheckHandle( $dbhStat );
			my $sth = $dbhStat->prepare( $str );
			$sth->bind_param( 1, $ipaddress,  DBI::SQL_BINARY );
			
			$sth->execute();

			&SqlErrorHandler( $dbhStat );
			$sth->finish();
		}


	return( $id );
}



################################################################################
# 
sub GetComputerNameID( $$ )
#
#  Get the Computer ID given the computer domain and computer name.
#  Return undef if it doesn't exist, the ID, Client IP, and SA version if it does
#
################################################################################
{	my $computer_domain = shift;
	my $computer_name	= shift;
	
	return( undef ) if ( ! defined $computer_domain );
	return( undef ) if ( ! defined $computer_name );
	
	my $qcomputer_name = &IndexInsertSqlValue( $computer_name, 64 );
	my $str = "SELECT ID, IpAddress, AgentVersion FROM saComputerNames WHERE [Domain] = \'$computer_domain\' AND Computer = \'$qcomputer_name\'";

	$dbhStat = &SqlErrorCheckHandle( $dbhStat );
	my $sth = $dbhStat->prepare( $str );
	$sth->execute();

	my ( $id, $ipaddress, $sa_version ) = $sth->fetchrow_array();

	&SqlErrorHandler( $dbhStat );
	$sth->finish();

	my $str_ipaddress = &IPToString( $ipaddress ) if ( defined $ipaddress );
	$str_ipaddress = "0.0.0.0" if ( ! defined $str_ipaddress );
	
	return( $id, $str_ipaddress, $sa_version );
}



################################################################################
# 
sub GetProperties()
#
#  Get the current properties from the Spam Blocker Object that affect
#  the IpmSpamForward
#
################################################################################
{	my $key;
	my $type;
	my $data;


	# Should I turn on extended logging?
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

	return if ( !$ok );
	$ok = &RegQueryValueEx( $key, "Logging", [], $type, $data, [] );
	$opt_logging = 1 if ( ( length( $data ) > 0 )  &&  ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );

	&RegCloseKey( $key );
		
		
	#  First get the current config number
	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations", 0, KEY_READ, $key );

	return if ( !$ok );
	$ok = &RegQueryValueEx( $key, "Current", [], $type, $data, [] );
	
	&RegCloseKey( $key );

	return if ( ! $ok );   
	return if ( ! length( $data ) );   
	return if ( length( $data ) < 0 );   
	
	my $current = &HexToInt( $data );

	my $current_key = sprintf( "%05u", $current );

	my $subkey;
	my $counter;
	
	#  Next go through the current config looking for a Spam Mail Blocker object
	for ( my $i = 1;  $i < 100;  $i++ )
		{	$counter = sprintf( "%05u", $i );

			$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter";

			$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
			next if ( !$ok );  

			$ok = &RegQueryValueEx( $key, "ProgID", [], $type, $data, [] );  # Blank is the (Default) value

			&RegCloseKey( $key );
			
			next if ( ! length( $data ) );
			next if ( length( $data ) < 0 );
			
			next if ( ! $data );

			last if ( $data =~ m/SpamMailBlockerSvc/ );         
		}

	return if ( ! $data =~ m/SpamMailBlockerSvc/ ); 


	# At this point I've got a spam blocker object in this config
	$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter\\Dynamic Properties";

	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
	return if ( !$ok );  


	$data = undef;
	$archive_path = undef;
    $ok = &RegQueryValueEx( $key, "Archive Path", [], $type, $data, [] );  # C:\Program Files\Lightspeed Systems\Traffic\Mail Archive
	$archive_path = $data if ( ( $ok )  &&  ( length( $data ) > 0 )  &&  ( $data ) );
	$archive_path =~ s/\x00//g if ( $archive_path );
	
			
	&RegCloseKey( $key );
			

	return;
}



################################################################################
# 
sub BuildDirectory( $ )
#
# Given a directory, do the best job possible in building it
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! $dir );
	
	# Does the directory already exist?
	return( 1 ) if ( -e $dir );
	
	my $ok = 1;
	
	my @parts = split /\\/, $dir;
	
	my $parent;
	
	# Is this an UNC kind of path?
	$parent = "\\" if ( $dir =~ m/^\\\\/ );
	
	foreach ( @parts )
		{	next if ( ! $_ );
			my $part = $_;
			
			$parent = $parent . "\\" . $part if ( $parent );
			
			$parent = $part if ( ! $parent );
			
			next if ( -e $parent );
			
			$ok = undef if ( ! mkdir( $parent ) );
		}
		
	$ok = ( -e $dir );
	
	return( $ok );
}



################################################################################
# 
sub HexToInt( $ )
#
#  Convert a registry hex value to a decimal value
#
################################################################################
{  my $hexstring = shift;

   my $dec = unpack( "CH", $hexstring );
 
   return( $dec );
}



################################################################################
#
sub debug( @ )
#
#  Print a line of text to STDOUT in normal or HTML format, depending on the CGI enviroment
#  And also print it to the log file
#
################################################################################
{
     return if ( ! $opt_debug );

     bprint( @_ );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = &SoftwareDirectory() . "\\IpmIndexErrors.log";
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
    my $me = "IpmIndex";

    print <<".";
Usage: $me [OPTION(s)]
IpmIndex indexes email and instant messaging for faster retrieval.  It also
inputs batch events from Security Agents into the Statistics database.

  -l, --logging  log incoming and outgoing messages
  -h, --help     display this help and exit
  -v, --version  display version information and exit
  
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
    my $me = "IpmIndex";

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

