################################################################################
#!perl -w
#
# Rob McCarthy's Virus Scanner source code
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;


my $_version = '8.01.03';


use Cwd;
use Getopt::Long();
use Benchmark;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);


use Win32;
use Win32::File;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;


use Content::File;

use Content::ScanLog;
use Content::Scanable;
use Content::ScanUtil;
use Content::ScanFile;
use Content::ScanStatus;
use Content::ScanRegistry;
use Content::ScanReport;
use Content::ScanQuarantine;

use Content::Disinfect;
use Content::DisinfectCommand;
use Content::DisinfectPoly;

use Content::FileIntegrity;
use Content::FileID;
use Content::UpdateEvent;
use Content::Process;
use Content::QueryOS;



my $opt_help;						# True if I should just show the help file
my $opt_version;					# True if I should just show the program version number
my $opt_debug;						# True if I am debugging - show extra messages and no debug file
my $opt_dir;						# The current directory that I was run from
my $opt_subdir;						# True if I should not scan subdirectories
my $opt_benchmark = 1;				# True if I should benchmark the speed
my $opt_wizard;						# True if I shouldn't display headers or footers
my $opt_test;						# True if I should load test signatures only
my $opt_all;						# True if all drives should be scanned
my $opt_zip;						# True if I should unpack zip files
my $opt_disinfect;					# True if I should try to disinfect bad files
my $opt_quiet = 1;					# True if I should be quiet
my $opt_verbose;					# The opposite of $opt_quiet
my $opt_purge;						# True if I should mark unused entries in the file integrity
my $opt_compress;					# True if I should compress unused entries in the file integrity
my $opt_good;						# True if I should tell the TTC Server that my unknown files are good
my $opt_unknown;					# True if I should add all the unknown files into the file integrity list without checking a TTC Server
my $opt_file;						# Set to the file name to return the file permissions attributes of
my $opt_no_mail;					# True if I want to build a status.zip file, but I don't want to mail it
my $opt_job;						# Percent of maximum cpu job time - 0 to 100 - effects how much time spent sleeping 
my $lightspeed_analyze_unknown;		# True if I should report unknown program info back to Lightspeed for analysis
my $lightspeed_analyze_virus;		# True if I should report virus info back to Lightspeed for analysis
my $opt_content;					# True if I should scan on content, ignoring file integrity
my $opt_no_integrity;				# True if I should not do file integrity checks
my $opt_scan_registry;				# True if the command line scan registry has been choosen
my $opt_block_spyware;				# True if I should delete spyware automatically 
my $opt_exclusive;					# True if I should run scan exclusively 
my $opt_status;						# True if I should create a status.zip file of the system status
my $opt_prompt;						# True if I should prompt before running
my $opt_network;					# True if I should scan network drives
my $opt_virus_archive;				# True if I should archive off virus infected files in Lightspeed format to drive I:
my $virus_directory = "Q:\\Virus Archive";	# This is the directory to archive virus infect files in Lightspeed format
my $alt_virus_directory = "W:\\Virus Archive";	# This is the alternate directory to archive virus infect files in Lightspeed format
my $opt_track_unknown;				# If true, then keep track of unknown programs found in working_dir\\ScanAppProcess.dat
my $opt_report_file;				# If set, log all the discovered viruses here
my $opt_quarantine_check;			# If set, check the scan quarantine
my $opt_quick;						# If set then do a quick system scan
my $opt_restart;					# If set the continue scanning from the last stopping point
my $skip_directory;					# If set, this is the last directory I started to scan
my $skip_directory_time;			# This is the last time I saved a skip directory
my $virus_logfile;					# If set, this is the name of the logfile to write the virus file list to
my $opt_appprocess;					# If set, keep track of all the applications and email them back to Lightspeed
my $opt_scan_local;					# If set, then dump all the locally discovered file IDs from the FileIntegrity file
my $opt_cloud;						# If set then use the global cloud repository for replacing any polymorphic virus infected files



# Global variables
my $block_virus			= 1;
my $block_virus_action	= "ReportOnly";
my $working_dir;					# My working directory
my $known_good = 0 + 0;				# The count of files that I told my ttc server that are good
my $ttc_server;						# The TTC server to use if report stuff back - read from the registry
my $tmp_dir;						# The temporary directory to use


# % CPU variables
my $factor;							# The factor to divide the actual job time by to come up with the sleep time - a factor of 1 is 50% CPU time
my $sleep_event;					# The event used to time sleeping
my $t0;								# The start benchmark time for CPUSleep


# Global statistics
my $objects		= 0 + 0;
my $total_files = 0 + 0;
my @infected_files;					# The list of infected files found
my @infection;						# The infection the file has
my @infected_file_id;				# The file IDs of the infected files
my @infected_contained;				# The list of infected files inside of zip files, uuencoded, base64 encoded, etc
my @unknown_files;					# The list of unknown files found
my @error_files;					# The list of error files found
my @error_files_ret;				# The return code of the scan error
my @network_unknown_files;			# The list of network unknown files found
my @ignore_directories;				# This is the list of directories to ignore when scanning


# My hash of local file_ids if purging the database
my %local_file_id;


# These are different virus names that actually aren't a problem - so if they are detected they can be ignored
my @ignore_virus_names = 
(	"Encrypted.Zip",
	"Encrypted.Rar",
	"Suspect.Zip",
	"Oversized.Zip",
	"Suspicious encrypted program",
	"Virus.Txt.Eicar.Test.File",
	"Virus.W32.Eicar.Test.File",
	"Virus.EICAR.Test",
	"Eicar.Test.Signature",
	"W32.Virus.Eicar.Test.File",
	"Virus.MD5.Eicar.Test.File",
	"Virus.HTM.Eicar.Test.File",
	"ClamAV.Test.File"
);



################################################################################
#
MAIN:
#
################################################################################
{

	# Should I load into Disinfect script processing?
	foreach( @ARGV )
		{	if ( $_ =~ m/^\-\-disinfect/i )
				{	my $ret = &DisinfectOptions( $_version );
					exit( 0 );
				}
		}
	

 	$SIG{'INT'} = 'INT_handler';

	# Get the options
	my $options = Getopt::Long::GetOptions
       (
		"0|app=s"		=> \$opt_appprocess,
		"a|all"			=> \$opt_all,
		"b|benchmark"	=> \$opt_benchmark,
		"c|content"		=> \$opt_content,
		"cloud"			=> \$opt_cloud,
		"d|disinfect"	=> \$opt_disinfect,
		"e|exclusive"	=> \$opt_exclusive,
		"3"				=> sub { $opt_content = 0 + 0x01 + 0x02; },
		"f|file=s"		=> \$opt_file,
		"g|good"		=> \$opt_good,
        "h|help"		=> \$opt_help,
        "i|integrity"	=> \$opt_no_integrity,
 		"j|job=s"		=> \$opt_job,
 		"k|killspyware"	=> \$opt_block_spyware,
 		"l|logfile=s"	=> \$opt_report_file,
		"m|mail"		=> \$opt_no_mail,
		"n|nosubdir"	=> \$opt_subdir,
		"o|network"		=> \$opt_network,
		"p|purge"		=> sub { $opt_purge = 1;  $opt_compress = 1; },
		"q|quick"		=> \$opt_quick,
		"r|registry"	=> \$opt_scan_registry,
		"s|scanlocal"	=> \$opt_scan_local,
		"t|tmp=s"		=> \$tmp_dir,
		"u|unknown"		=> \$opt_unknown,
		"v|verbose"		=> sub { $opt_quiet = undef; },
		"w|wizard"		=> \$opt_wizard,
		"x|xxx"			=> \$opt_debug,
		"y|yyy"			=> \$opt_virus_archive,
 		"z|zip"			=> \$opt_zip
     );


	$opt_verbose = 1 if ( ! $opt_quiet );
	$opt_verbose = 1 if ( $opt_debug );
	$opt_restart = 1 if ( $opt_exclusive );
	$opt_content = 0 + 1 if ( ( ! $opt_content )  &&  ( $opt_unknown ) );
	
	
	print( "Lightspeed Virus, Vulnerability & File Integrity Scanner\n" ) if ( ! $opt_wizard );
	print "Version: $_version\n" if ( ! defined $opt_wizard );


	# Before going into 64 bit mode - locate the scan.dll to use
	&ScanDllLocation( undef, undef );

	# Setup to handle Win 64 bit operations if running under one of those OSes
	&OueryOSWin64Bit();


	$tmp_dir = &ScanTmpDirectory() if ( ! defined $tmp_dir );
	

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	

	if ( ( $opt_virus_archive )  &&  ( ! -d $virus_directory ) )
		{	$virus_directory = $alt_virus_directory if ( -d $alt_virus_directory );
		}
		
	if ( ( $opt_virus_archive )  &&  ( ! -d $virus_directory ) )
		{	lprint "Virus archive directory $virus_directory does not exist!\n";
			exit( 0 );
		}
		
		
	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	$opt_dir = $cwd if ( !$opt_dir );
	
	$working_dir = &ScanWorkingDirectory();
	
	my $quarantine_dir = &ScanQuarantineDirectory();
	
	# Set the name of the virus logfile - default is working_dir\Virus.log
	$virus_logfile = $working_dir . "\\Virus.log" if ( ! defined $opt_report_file );
	$virus_logfile = $opt_report_file if ( defined $opt_report_file );
	
	
	# Am I just returning the permissions of a file?
	if ( $opt_file )
		{	&FilePermissions( $opt_file );
			exit( 0 );	
		}
	
	
	# Send I send a status zip to the help desk?
	if ( ( $opt_status )  ||  ( $opt_no_mail ) )
		{	print "Creating and mailing system status.zip file ...\n" if ( ! $opt_no_mail );
			print "Creating system status logs and status.zip file ...\n" if ( $opt_no_mail );
			my $count = &ScanLoadSignatures( $working_dir, $tmp_dir, 1, $opt_debug, $opt_virus_archive, $opt_verbose );
			
			if ( ! $count )
				{	&StatusError( "Unable to load virus signatures\n" );
					exit( 1 );
				}
				
			my ( $ok, $msg ) = &LoadFileIntegrity( $opt_debug );
			
			my $mail;
			$mail = 1 if ( ! $opt_no_mail );
			my $ret = &ScanStatus( $mail );
			
			&ScanUnloadSignatures();
			
			exit( $ret );	
		}

	
	# Should I dump all the locally discovered file IDs in the FileIntegrity file and signal the service
	if ( $opt_scan_local )
		{	print "Removing all the locally discovered files from the file integrity database ...\n";
			
			my ( $ok, $msg ) = &LoadFileIntegrity( $opt_debug );
			
			if ( ! $ok )
				{	print "Error loading the File Integrity database: $msg\n";
					exit( 1 );
				}
				
			my $deleted_count = &DeleteLocalFileIDs();
			
			if ( $deleted_count )
				{	my ( $count, $msg ) = &SaveFileIntegrity( undef, undef, undef );
			
					if ( ! defined $count )
						{	print "Error saving the file integrity database: $msg\n";
						}
					else
						{	&SignalService();
						}
				}
			
			print "\nDone\n";
			
			exit( 0 );	
		}


	# Set the options for opt_all & opt_network
	$opt_all = 1 if ( $opt_network );
	
	my $second_copy;
	
	if ( &IsScanRunning() )
		{	print "\nThere is another copy of the scan utility already running ...\n\n";
			$second_copy = 1;
		}
		
	# Create a new event to stop other copies of this program from running at the same time
	my $ok = &ScanRunning();
	if ( ( ! $ok )  &&  ( ! $second_copy ) )
		{	print "\nThere is another copy of the scan utility already running by someone else ...\n\n";
			$second_copy = 1;
		}

	exit( 1 ) if ( ( $second_copy )  &&  ( $opt_exclusive ) );
	

	&TrapErrors() if ( ! $opt_debug );


	my $scan_log_file;

	if ( ! $second_copy )
		{	$scan_log_file = &ScanSetLog( "scan.log", $opt_debug );
		}
	else
		{	$scan_log_file = &ScanSetLog( "scan2.log", $opt_debug );
		}
		
	print "Logging set to $scan_log_file\n" if ( $scan_log_file );
	print "Can not open log file.\n" if ( ! $scan_log_file );
	
			
	my $software_version = &LoadProperties();
	&SoftwareUpdate( $software_version, $working_dir );
	
	
	# This is my list of stuff to scan - if nothing in it then scan the current directory
	my @scan_list;
	
	
	# Am I doing a quick scan?
	if ( $opt_quick )
		{	$opt_all			= undef;
			$opt_network		= undef;
			$opt_unknown		= 1;
			$opt_content		= undef;
			$opt_file			= undef;
			$opt_no_mail		= undef;
			$opt_virus_archive	= undef;
			$opt_scan_registry	= 1;
			&ScanLogEvent( "Doing a quick initial system scan only\n" );
			
			my $system_root = $ENV{ SystemRoot };
			$system_root = "C:\\Windows" if ( ! $system_root );
			
			my $system_drive = $ENV{ SystemDrive };
			$system_root = "C:" if ( ! $system_drive );
			
			# Set the list of directories to scan
			push @scan_list, $system_root;
			push @scan_list, "$system_drive\\Program Files\\Common Files";
			push @scan_list, "$system_drive\\Program Files\\Internet Explorer";
			push @scan_list, "$system_drive\\Program Files\\Microsoft Office";
			
			# Set the list of directories to ignore
			push @ignore_directories, "$system_root\\\$hf_mig\$";
			push @ignore_directories, "$system_root\\\$ntuninstall";
			push @ignore_directories, "$system_root\\assembly";
			push @ignore_directories, "$system_root\\cursors";
			push @ignore_directories, "$system_root\\downloaded installations";
			push @ignore_directories, "$system_root\\fonts";
			push @ignore_directories, "$system_root\\help";
			push @ignore_directories, "$system_root\\ime";
			push @ignore_directories, "$system_root\\inf";
			push @ignore_directories, "$system_root\\installer";
			push @ignore_directories, "$system_root\\pchealth";
			push @ignore_directories, "$system_root\\temp";
			
			# Try to use the ScanClient.dll interface since we are only scanning local drives
			&ScanDllLocation( 1, undef );
		}
		
		
	if ( $opt_all )
		{	$opt_job = 0 + 25 if ( ! defined $opt_job );
			$opt_quarantine_check = 1;
			$opt_track_unknown = 1;	# Keep track of unknown and virus files if I am doing a scan all
			
			# Try to use the ScanClient.dll interface since we are only scanning local drives
			&ScanDllLocation( 1, undef );
		}


	$opt_job = 0 + $opt_job if ( defined $opt_job );
	if ( ( $opt_job )  &&  ( ( $opt_job < 5 )  ||  ( $opt_job > 100 ) ) )
		{	print "Maximum CPU job percent must be from 5 to 100\%\n";
			exit( 1 );
		}
	
	
	# Calculate how much time to sleep between scans if $opt_job is set
	# If opt_job is 100 then run at full speed with no sleeps
	if ( ( $opt_job )  &&  ( $opt_job == 100 ) )
		{	$factor = 0 + 0;
		}
	elsif ( ( $opt_job )  &&  ( $opt_job < 100 )  &&  ( $opt_job > 1 ) )	# Run at less that full speed
		{	$factor = 0 + 1;
			my $divisor = $opt_job / ( 100 - $opt_job );
			$factor = 1000 / $divisor;
			
			# Round the factor off
			$factor = 0 + sprintf( "%d", $factor );
		}
	else	# If nothing is set then also run at full speed
		{	$factor = 0 + 0;
		}


	# Should I force disinfection?
	if ( $opt_disinfect )
		{	$block_virus = 1;
			$block_virus_action = "disinfect";
		}


	# Show all the options selected	
	&ScanLogEvent( "Verbose mode\n" ) if ( $opt_verbose );
	&ScanLogEvent( "Scanning all local fixed drives\n" ) if ( $opt_all );
	&ScanLogEvent( "Scanning all network drives\n" ) if ( $opt_network );
	&ScanLogEvent( "Scanning files by file extension only\n" ) if ( ! $opt_content );
	&ScanLogEvent( "Scanning registry\n" ) if ( $opt_scan_registry );
	
	if ( ( $opt_good )  &&  ( $ttc_server ) )
		{	&ScanLogEvent( "Report unknown files as known good back to $ttc_server\n" );
		}
	elsif ( ( $opt_good )  &&  ( ! $ttc_server ) )
		{	&ScanLogEvent( "There is no TTC Server configured in the registry\n" );
			exit( 1 );
		}
		
	my $action = $block_virus_action;
	if ( lc( $block_virus_action )  eq "reportonly" )
		{	$action = "Report only";
		}
		
	&ScanLogEvent( "Anti-virus action: $action\n" ) if ( $block_virus );
	&ScanLogEvent( "Report only if a virus is discovered\n" ) if ( ! $block_virus );
	&ScanLogEvent( "Automatically delete spyware files\n" ) if ( $opt_block_spyware );
	&ScanLogEvent( "No file integrity checking\n" ) if ( $opt_no_integrity );
	&ScanLogEvent( "Mark unused entries in the file integrity database\n" ) if ( $opt_purge );
	&ScanLogEvent( "Compress unused entries in the file integrity database\n" ) if ( $opt_compress );
	&ScanLogEvent( "Send virus infected program data back to Lightspeed for analysis\n" ) if ( $lightspeed_analyze_virus );
	&ScanLogEvent( "Writing unknown program data to file $working_dir\\ScanAppProcess.dat\n" ) if ( $opt_track_unknown );
	&ScanLogEvent( "Send unknown program data back to Lightspeed for analysis\n" ) if ( $lightspeed_analyze_unknown );
	&ScanLogEvent( "Not scanning subdirectories\n" ) if ( $opt_subdir );
	&ScanLogEvent( "Send application information back to Lightspeed for analysis\n" ) if ( $opt_appprocess );
		
	if ( ( $opt_purge )  &&  ( ! $opt_all) )
		{	&ScanLogEvent( "Can not purge unused entries in the file integrity database without scanning all local drives\n" );
			exit( 1 );	
		}

	&ScanLogEvent( "Add all currently unknown files into the file integrity database\n" ) if ( $opt_unknown );
	&ScanLogEvent( "Show scanning benchmarks\n" ) if ( $opt_benchmark );
	&ScanLogEvent( "Use a maximum of $opt_job\% available CPU job time for scanning\n" ) if ( $opt_job );

	if ( $opt_content )
		{	&ScanLogEvent( "Scanning all files by content, ignoring file extensions and file integrity\n" );
			&ScanLogEvent( "Also ignoring the File ID database\n" ) if ( $opt_content & 0x02 );
			&ScanLogEvent( "Note: scanning by content is very extensive - but very slow\n" );
		}

	&ScanLogEvent( "Unpacking and scanning .cab, .msi, .rar, .bz, .gz, and .zip archives\n" ) if ( $opt_zip );
	&ScanLogEvent( "Quarantining viruses in Lightspeed archive format to $virus_directory\n" ) if ( $opt_virus_archive );
	&ScanLogEvent( "Continue scanning from stopping point if interrupted\n" ) if ( $opt_restart );


	# If I'm using a report file, make sure I can open and use it
	if ( defined $opt_report_file )
		{	if ( ! open( VIRUS, ">$opt_report_file"	) )
				{	my $err = $!;
					&ScanLogEvent( "Error opening virus report file $opt_report_file: $err\n" );
					exit( -1 );
				}
				
			close( VIRUS );
			
			&ScanLogEvent( "Logging discovered virues to report file: $opt_report_file\n" );
		}
		
		
	
	# Read the remaining arguments as files or directories to scan
	while ( my $temp = shift )
		{	if ( $temp eq "\." )
				{	push @scan_list, $cwd;
				}
			else	
				{	# If there are no black slashes, assume it needs the current directory added to it
					$temp = $cwd . "\\" . $temp if ( ! ( $temp =~ m/\\/ ) );
					$temp =~ s#\/#\\#gm;
					push @scan_list, $temp;
				}
		}
	

	# If scanning all the local drives, get them and build the scan list from that
	if ( ( $opt_all )  &&  ( ! $opt_network ) )
		{	my @drives = &get_drives();
			
			@scan_list = ();
			
			foreach ( @drives )
				{	my $letter = $_;
					push @scan_list, "$letter:\\";
					
					&ScanLogEvent( "Scanning drive $letter:\\\n" );
				}				
		}
		
		
	# If scanning all the local and network drives, get them and build the scan list from that
	if ( $opt_network )
		{	my @drives = &get_network_drives();
			
			@scan_list = ();
			
			foreach ( @drives )
				{	my $letter = $_;
					push @scan_list, "$letter:\\" if ( length( $letter ) eq 1 );	# It is a local drive letter
					push @scan_list, "$letter\\" if ( length( $letter ) gt 1 );		# It is a UNC
				}	
		}
		
		
	# If no arguments, scan the current directory and all subdirectories	
	if ( ( ! $scan_list[ 0 ] )  &&  ( ! $opt_scan_registry ) )
		{	push @scan_list, $cwd;
			
			# If the cwd is on a local drive, try to use the ScanClient.dll
			if ( ( $cwd )  &&  ( $cwd =~ m/^.\:/ ) )
				{	my $local;
					
					my @drives = &get_drives();

					# Get the drive letter of the cwd
					my $drive_letter = uc( substr( $cwd, 0, 1 ) );

					foreach( @drives )
						{	$local = 1 if ( $drive_letter eq uc( $_ ) );
						}
						
					# Try to use the ScanClient.dll interface since we are only scanning local drives
					&ScanDllLocation( 1, undef ) if ( $local );
				}
		}

	
	# Set up the ignore list	
	&ScanableIgnore( $opt_debug, $tmp_dir, $quarantine_dir, "$working_dir\\ScanTemp", @ignore_directories );
	
	
	# Make sure the ignore list doesn't include the directories I'm supposed to scan
	&ScanableInclude( @scan_list );
	
	
	# My global flag is $opt_no_integrity, which is kind of backward from what you would think	
	my $use_file_integrity = 1;
	$use_file_integrity = undef if ( $opt_no_integrity );
	
	&CleanTmpDirectory( $tmp_dir ) if ( ! $second_copy );
	
	# Clean out the unknown processes file if it is there from the last scan
	unlink( "$working_dir\\ScanAppProcess.dat" );


	&ScanLogEvent(  "Loading the virus signatures ...\n" );
	

	my $count = &ScanLoadSignatures( $working_dir, $tmp_dir, 1, $opt_debug, $opt_virus_archive, $opt_verbose );
	
	
	if ( ! $count )
		{	&ScanLogEvent( "Unable to load virus signatures\n" );
			&StdFooter();
			exit( 1 );
		}
		

	if ( $opt_quarantine_check )
		{	&OueryOSWin64BitFile();
			&ScanQuarantineCheck();
			&OueryOSWin32BitFile();
		}
		
		
	# Put a blank line down	
	&ScanLogEvent( "\n" );
	
	
	# Prime the pump for sleeping if I need to		
	if ( $factor )
		{	my $sleep_name = sprintf( "ScanCPUTimer %d", time );	# Build a unique sleep event name
			$sleep_event = Win32::Event->new( 1, 1, $sleep_name );
			$sleep_event->set if ( $sleep_event );
		}
	
				
	# Keep track of how long it takes to scan
	&ScanLogEvent( "Scan started\n" );
	my $start = new Benchmark;

	&OueryOSWin64BitFile();

	# Should I scan the running processes?
	&ScanProcess( $block_virus, $opt_verbose, \@unknown_files ) if ( ( $opt_scan_registry )  ||  ( $opt_all ) );

	# Should I scan the registry?
	&ScanRegistry( $block_virus, $opt_verbose, \@unknown_files ) if ( ( $opt_scan_registry )  ||  ( $opt_all ) );


	# Am I restarting an older scan?
	if ( ( $opt_restart )  &&  ( $skip_directory = &GetSkipDirectory() ) )
		{	&ScanLogEvent(  "Continuing scanning from the directory $skip_directory ...\n" );
		}
	else
		{	unlink( $virus_logfile ) if ( defined $virus_logfile );
			&SetSkipDirectory( undef );
		}
		

	foreach ( @scan_list )
		{	my $item = $_;
			
			&OueryOSWin64BitFile();
			
			next if ( $item =~ m/^\.$/ );	# Skip dot files
			next if ( $item =~ m/^\.\.$/ );	# Skip dot files
					
			if ( -d $item )
				{	&ScanLogEvent(  "Scanning $item and subdirectories ...\n" ) if ( ! $opt_subdir );
					&ScanLogEvent(  "Scanning $item ...\n" ) if ( $opt_subdir );
	
					&ScanDir( $item );
				}
			elsif ( -e $item )
				{	$item = &FileFullPath( $item );
					
					# Can this file be scanned?
					my $scanable = &Scanable( $item, $opt_content );
					
					# Was there an error trying to find out if it is scanable?
					my $downadup;
					if ( ! defined $scanable )
						{	my $err = $!;
							$err = "Undefined" if ( ! $err );
							&ScanLogEvent( "Error opening $item: $err\n" );
							
							# Could this be the Downadup bastard?
							my $size = -s $item;
							$downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );
						}
				
					elsif ( ! $scanable )
						{	&ScanLogEvent( "$item is OK\n" ) if ( $opt_verbose );
							next if ( ! $factor );
							
							&CPUSleep();
							next;
						}
					
					# If doing a quick scan, only scan executable programs
					if ( ( $scanable )  &&  ( $scanable != 1 )  &&  ( $opt_quick ) )
						{	next;
						}
					
					&ScanLogEvent( "Scanning file $item ...\n" );
					
					my ( $ret, $file_id ) = &ScanMessageFile( $item, $scanable );
					$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );
										
					if ( $ret )
						{	if ( $ret =~ m/Unknown executable/i )
								{	push @unknown_files, $item;
									&ScanLogEvent( "$item is $ret\n" ) if ( $opt_verbose );
								}
							elsif ( $ret =~ m/Scan error/i )
								{	push @error_files, $item;
									push @error_files_ret, $ret;
									&ScanLogEvent( "$item is $ret\n" );
								}
							else
								{	&ScanLogEvent( "$item is $ret\n" );
									&ScanEventLogVirus( "File $item is $ret" );
									
									push @infected_files, $item;
									push @infection, $ret;
									push @infected_file_id, $file_id if ( defined $file_id );
									push @infected_file_id, "" if ( ! defined $file_id );
									
									my ( $infected_file, $infected_virus, $infected_category ) = &ScanVirusContained();
									push @infected_contained, $infected_file if ( $opt_virus_archive );
								}
						}
					elsif ( $opt_verbose )
						{	&ScanLogEvent( "$item is OK\n" );
						}
				}
			else
				{	&ScanLogEvent( "$item not found\n" );
				}
		}
	
	# Calc the benchmark statistics
	my $finish = new Benchmark;

	my $diff = timediff($finish, $start);
	my $strtime = timestr( $diff );
	$strtime =~ s/^\s*//;	# Trim off any leading spaces
	
	
	my $infected;
	( $objects, $infected ) = &ScanStatistics();
			
			
	&ScanLogEvent( "Scan finished\n" );
	&SetSkipDirectory( undef );
	
	
	# Close the file ID index if I opened it		
	&FileIDIndexClose();
	
	
	&ScanLogEvent( "\n" );
	&ScanLogEvent( "Scan results:\n" );
	
	
	# Log anything that I found ...	
	my $unknown_count = $#unknown_files + 1;
	
	if ( $unknown_files[ 0 ] )
		{	&ScanLogEvent( "Found $unknown_count unknown programs\n" );
			for ( my $i = 0;  $unknown_files[ $i ];  $i++ )
				{	&ScanLogEvent( "$unknown_files[ $i ]: Unknown program\n" ) if ( $opt_verbose );
				}
				
			#&AddUnknownFiles( $working_dir, $opt_all, @unknown_files );
		}
	else
		{	&ScanLogEvent( "No unknown programs found\n" ) if ( !$opt_no_integrity );
		}
				
				
	my $network_unknown_count = $#network_unknown_files + 1;
	if ( $network_unknown_files[ 0 ] )
		{	if ( $opt_verbose )
				{	for ( my $i = 0;  $network_unknown_files[ $i ];  $i++ )
						{	&ScanLogEvent( "$network_unknown_files[ $i ]: Local permissions only\n" );
						}
				}
				
			&ScanLogEvent( "Found $network_unknown_count local permissions only programs\n" );	
			#&AddUnknownFiles( $working_dir, $opt_all, @network_unknown_files );
		}
	else
		{	&ScanLogEvent( "No local permissions only programs found\n" ) if ( !$opt_no_integrity );
		}
				
				
	if ( $opt_good )
		{	&ScanLogEvent( "Reported $known_good programs as known good back to $ttc_server\n" );
		}

	if ( $error_files[ 0 ] )
		{	for ( my $i = 0;  $error_files[ $i ];  $i++ )
				{	&ScanLogEvent( "$error_files[ $i ]: $error_files_ret[ $i ]\n" );
				}				
		}
	else
		{	&ScanLogEvent( "No scan errors\n" );
		}
				

	# Write the virus infected file list to the virus log file
	&SetVirusInfected();
	my $total_virus_count = 0 + 0;

	# If I found some viruses print out the log file
	if ( ( defined $virus_logfile )  &&  ( -s $virus_logfile ) )
		{	&ScanLogEvent( "\n" );
			&ScanLogEvent( "Virus infected or spyware files:\n" );
			
			# Print out the virus logfile
			open( VIRUS, "<$virus_logfile" ) or $virus_logfile = undef;
			
			while ( my $line = <VIRUS> )
				{	&ScanLogEvent( $line );
					$total_virus_count++;
				}
				
			close( VIRUS ) if ( defined $virus_logfile );	
		}
	else
		{	unlink( $virus_logfile ) if ( defined $virus_logfile );
		}
		
		
		
	if ( ! $total_virus_count )
		{	&ScanLogEvent( "No viruses or spyware programs found\n" );
		}
	else
		{	&ScanLogEvent( "Found $total_virus_count virus infected or spyware programs\n" );
		}
	
	
	if ( $opt_benchmark )		
		{	&ScanLogEvent( "\n" );
			&ScanLogEvent( "Scan benchmarks:\n" );
			&ScanLogEvent( "Files Scanned:     $total_files\n" );
			&ScanLogEvent( "Infected Files:    $total_virus_count\n" );
			&ScanLogEvent( "Unknown Programs:  $unknown_count\n" );
			&ScanLogEvent( "Local Permissions: $network_unknown_count\n" );
			&ScanLogEvent( "Scan Time:         $strtime\n" );
			
			my ( $secs, $junk ) = split /\s/, $strtime, 2;
			$secs = 0 + $secs;
			my $min = $secs / 60;
			$min = sprintf( "%d", $min);
			my $hours = $min / 60;
			$hours = sprintf( "%d", $hours );
			
			$min = $min - ( 60 * $hours );
			$secs = $secs - ( 60 * $min ) - ( 3600 * $hours );
			
			if ( $hours == 0 )
				{	$hours = "";
				}
			elsif ( $hours == 1 )
				{	$hours = "1 hour ";
				}
			else
				{	$hours = "$hours hours ";
				}
				
			if ( $min == 0 )
				{	$min = "";
				}
			elsif ( $min == 1 )
				{	$min = "1 minute ";
				}
			else
				{	$min = "$min minutes ";
				}
				
			if ( $secs == 0 )
				{	$secs = "0 seconds";
				}
			elsif ( $secs == 1 )
				{	$secs = "1 second";
				}
			else
				{	$secs = "$secs seconds";
				}
				
			&ScanLogEvent( "                  $hours$min$secs\n" );
			
			&ScanLogEvent( "\n" );
		}
	
		
	# Should I modify the file integrity file?	
	if ( ( $opt_purge )  ||  ( $opt_unknown ) || ( $#infected_file_id >= 0 ) )
		{	my ( $ok, $msg ) = &ReLoadFileIntegrity();
			&ScanLogEvent(  "Error reloading the file integrity database: $msg\n" ) if ( ! $ok );	
			
			# Do I need to set the unused bit?
			# Don't do this anymore because new file IDs get add with this bit set right in the first place
			# &UnusedFileIntegrity() if ( $opt_purge );
			
			&AddUnknowns() if ( $opt_unknown );
			
			# If I'm purging the unused file IDs, go through the list now
			if ( $opt_purge )
				{	while ( my ( $file_id, $value ) = each( %local_file_id ) )
						{	next if ( ! defined $file_id );
							&FileIDUsedLocal( $file_id, 1 );
						}
				}
			
		  # Delete any infected file_id from the FileIntegrity file.
		  &DeleteInfectedFileIntegrity();
		  
			# Save the file integrity file if it has changed
			my $changed;
			if ( ( &ChangedFileIntegrity() )  ||  ( $opt_purge ) )
				{	my $count;
					( $count, $msg ) = &SaveFileIntegrity( $working_dir, $opt_compress, undef );
					
					if ( ! defined $count )
						{	&ScanLogEvent( "Error saving the file integrity database: $msg\n" );
						}
						
					$changed = 1;	
				}


			my ( $total, $active ) = &FileIntegrityDatabaseSize();

			&ScanLogEvent( "Currently have $total total and $active active file IDs\n" ) if ( $total );
							
			if ( $changed )				
				{	$ok = &SignalService();
				}
		}
		
		
	&SaveLastScanFinished( $total_virus_count, $unknown_count, $strtime, $objects );
	
	
	# Should I report the virus or unknown program info back to Lightspeed?
	&ScanReportAnalyzeUnknown( $working_dir, "ScanAppProcess.dat", $opt_appprocess ) if ( ( $lightspeed_analyze_virus )  ||  ( $lightspeed_analyze_unknown ) ||  ( $opt_appprocess ) );
	
	&ScanLogEvent( "WARNING: A system reboot is required to finish cleaning up the disinfected viruses\n" ) if ( &DisinfectRebootRequired() );
	
	&ScanCloseLogFile();
	&AddHistoryLog( $working_dir, $scan_log_file );
	
	&StdFooter();
	
	&OueryOSWin32BitFile();
	
	# Clean up the scan.dll
	&ScanUnloadSignatures();

	# Exit with a 1 if a virus found
	exit( 1 ) if ( $total_virus_count );
	
	# Exit with a 0 if nothing found
	exit( 0 );
}
###################    End of MAIN  ################################################




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
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $dir = &ScanWorkingDirectory();

	my $scan_errors_filename = "$dir\\ScanErrors.log";
		
	my $MYLOG;
   
	open( $MYLOG, ">$scan_errors_filename" ) or print( "Unable to open $scan_errors_filename: $!\n" );
   
	&CarpOut( $MYLOG ) if ( $MYLOG );
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
	
	my $scan_history_log = $dir . "\\ScanHistory.log";
	
	my $size = -s $scan_history_log;
	
	&HistoryBackup( $dir ) if ( ( $size  )  &&  ( $size > ( 0 + 2000000 ) ) );	# If the size is larger than a 2 megs, backup the file
	
	open( HISTORY, ">>$scan_history_log" ) or return( undef );
	
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
	
	my $history_log = $dir . "\\ScanHistory.log";
	return( undef ) if ( ! -f $history_log );
	
	my $history_backup = $dir . "\\ScanHistory.bak";

	unlink( $history_backup );	
	my $ok = rename( $history_log, $history_backup );
	
	return( $ok );
}



################################################################################
# 
sub CleanTmpDirectory( $ )
#
#  Clean out any old files in the tmp directory
#
################################################################################
{	my $tmp_dir = shift;
	
	return( undef ) if ( ! $tmp_dir );
	return( undef ) if ( ! -d $tmp_dir );
	
	# Clean out the tmp directory
	if ( opendir( DIR, $tmp_dir ) )
		{	ScanLogEvent( "Cleaning out the tmp directory: $tmp_dir ...\n" ) if ( $opt_verbose );

			while ( my $file = readdir( DIR ) )
				{	next if ( ! $file );
					next if ( $file =~ m/^actions/i );
					
					my $fullfile = "$tmp_dir\\$file";
					# Skip subdirectories
					next if ( -d $fullfile );
					
					unlink( $fullfile );
				}
				
			closedir( DIR );
			
			return( 1 );
		}
		
	return( 0 );
}



################################################################################
#
sub LightspeedVirusArchive( $$ )
#
#  Archive a virus infected file in Lightspeed format
#  Return True if archived ok, undef if not
#
################################################################################
{	my $virus_file = shift;
	my $virus_name = shift;

	if ( ! -e $virus_file )
		{	&ScanLogEvent( "virus file $virus_file does not exist\n" );			
			return( undef );
		}
			
	my $short_file = $virus_name;
	
	$short_file = "unnamed" if ( ! defined $short_file );
	$short_file =~ s/blocked program//;
	$short_file =~ s/Infected//;
	$short_file =~ s/infected//;
	$short_file =~ s/by//;
	$short_file =~ s/\s+//gm;
	$short_file =~ s/\\/\./gm;
	$short_file =~ s#\/#\.#gm;
	
	$short_file = &CleanFileName( $short_file );
	
	my $file_id = &ApplicationFileID( $virus_file );
	return( undef ) if ( ! defined $file_id );
	
	my $hex_file_id = &StrToHex( $file_id );

	# Clean off any inconvenient file extensions of the directory
	my $short_dir = $short_file;
	$short_dir =~ s/\.exe$//;
	$short_dir =~ s/\.bat$//;
	$short_dir =~ s/\.htm$//;
	
	
	# See if I can figure out if it is a VBS, W32, Linux, etc type of virus
	my $virus_type = &VirusTypeName( $virus_name );
	
	
	my $final_dir = $virus_directory . "\\$short_dir";
	$final_dir = $virus_directory . "\\$virus_type\\$short_dir" if ( defined $virus_type );
	
	&MakeDirectory( $final_dir );
	
    my ( $src_dir, $src_filename ) = &SplitFileName( $virus_file );

	my $final_filename = $final_dir . "\\$src_filename";
	
	# Add an underscore to the end of the file name if it doesn't already exist
	$final_filename = $final_filename . "_" if ( ! ( $final_filename =~ m/\_$/ ) );
	
	
	&ScanLogEvent( "Archiving from: $virus_file\n" );
	&ScanLogEvent( "Archiving to: $final_filename\n" );
	

	# Does the final filename already exist?  If so, is this a new version?
	my $ok = 1;
	my $copy_it = 1;
	
	
	# Am I copying to the same file name?
	my $lc_final_filename = lc( $final_filename );
	my $lc_virus_file = lc( $virus_file );
	
	
	$copy_it = undef if ( $lc_final_filename eq $lc_virus_file );
	
	if ( ( -e $final_filename )  &&  ( $copy_it ) )
		{	
			my $existing_file_id = &ApplicationFileID( $final_filename );
			if ( ! defined $existing_file_id )
				{	$copy_it = 1;
				}
			elsif  ( $existing_file_id eq $file_id )
				{	#print "File already exists: $final_filename\n";
					$copy_it = undef;
				}
			else
				{	&ScanLogEvent( "New version: $final_filename\n" );
					
					my $existing_hex_file_id = &StrToHex( $existing_file_id );
					
					my $version_dir = $final_dir . "\\$existing_hex_file_id";
					&MakeDirectory( $version_dir );
					
					my ( $fdir, $fshortname ) = &SplitFileName( $final_filename );
					
					my $version_file = $version_dir . "\\$fshortname";
					
					# Copy it if it doesn't already exist
					$ok = copy( $final_filename, $version_file ) if ( ! -e $version_file );

					if ( ! $ok )
						{	&ScanLogEvent( "File copy error: $!\n" );
							&ScanLogEvent( "Source file: $final_filename\n" );
							&ScanLogEvent( "Destination file: $version_file\n" );
						}
					else
						{	unlink( $final_filename );
						}
						
					$copy_it = 1;
				}
		}
		

	if ( ( $ok )  &&  ( $copy_it ) )
		{	$ok = copy( $virus_file, $final_filename );
	
			if ( ! $ok )
				{	&ScanLogEvent( "File copy error: $!\n" );
					&ScanLogEvent( "Source file: $virus_file\n" );
					&ScanLogEvent( "Destination file: $final_filename\n" );
				}
		}


	# Should I also copy the file to the Downloaded Spyware directory?
	if ( ( $ok )  &&  ( $src_dir =~ m/i\:\\download\\/i ) )
		{	my $target_dir = $src_dir;
			$target_dir =~ s/download/Downloaded Spyware/;
					
			&MakeDirectory( $target_dir );
			
			my $target_file = "$target_dir\\$src_filename";
			
			&ScanLogEvent( "Also archiving to: $target_file\n" );
			$ok = copy( $virus_file, $target_file );
		}
		
				
	# Finally, delete the original virus file	
	if ( $ok )
		{	my $delete_ok = unlink( $virus_file );
			&ScanLogEvent( "Error deleting virus file $virus_file: $!\n" ) if ( ! $delete_ok );
		}

		
	return( $ok );
}



################################################################################
#
sub FilePermissions( $ )
#
#  Print out the file permissions for the given file
#
################################################################################
{	my $file = shift;
	
	# Is this actually a file ID?
	my $file_id;
	my $hex_md5;
	
	if ( length( $file ) == 56 )
		{	$file_id = &HexToStr( $file );
			$file_id = undef if ( ( $file_id )  &&  ( length( $file_id ) != 28 ) );
		}
		
	if ( ( ! $file_id )  &&  ( ! -e $file ) )
		{	print "$file does not exist\n";
			return( undef );
		}
		
	if ( ! $file_id )
		{	print "\nFile permissions for file $file\n";
			my $size = -s $file;
			print "File size: $size bytes\n";
			$file_id = &ApplicationFileID( $file );
			$hex_md5 = &DisinfectCommandHexMD5File( $file );
		}
	else
		{	print "\nFile permissions for file ID $file\n";
		}
		
	
	my ( $ok, $msg ) = &LoadFileIntegrity( $opt_debug );
	
	if ( ! $ok )
		{	print "Error loading the file integrity database: $msg\n";	
			return( undef );
		}


	my $category_number;
	my $network_permissions;
	my $local_permissions;

	my $default_known_network_permissions;
	my $default_known_local_permissions;
	
	my $default_unknown_network_permissions;
	my $default_unknown_local_permissions;
	
	( $ok, $file_id, $category_number, $network_permissions, $local_permissions ) = &CheckFileIntegrity( $file, 1 );

	( $category_number, $network_permissions, $local_permissions ) = &GetPermissions( $file_id );
	$ok = undef if ( ! $category_number );

	( $category_number, $default_unknown_network_permissions, $default_unknown_local_permissions ) = &GetDefaultUnknownPermissions();
	( $category_number, $default_known_network_permissions, $default_known_local_permissions ) = &GetDefaultKnownPermissions();
		
	if ( ! $ok )
		{	print "$file is an unknown file so using the default unknown permissions\n";
			( $category_number, $network_permissions, $local_permissions ) = &GetDefaultUnknownPermissions();
		}
	elsif ( ! $file_id )
		{	print "$file is not executable\n";
			return( undef );
		}
	else
		{	print "$file is a known program\n";
		}
		
	my $hex_file_id = lc( &StrToHex( $file_id ) );
	my $hex_pretty = substr( $hex_file_id, 0, 8 ) . " " . substr( $hex_file_id, 8, 8 ) . " " . substr( $hex_file_id, 16 );
	
	print "File ID (raw) = $hex_pretty\n";	
	print "MD5 Hash = $hex_md5\n" if ( defined $hex_md5 );

	print "Category: $category_number\n";
	
	printf "\nActual Network Permissions:\t0x%08x\n", $network_permissions;
	printf "Actual Local Permissions:\t0x%08x\n\n", $local_permissions;
		
	&DecodeNetworkPermissions( $network_permissions );
	print "\n\n";
	&DecodeLocalPermissions( $local_permissions );

	# Does this fileID exist in the fileID.dat file?
	my ( $app_name, $virus_category, $permissions_num ) = &FileIDAppName( $file_id );
	
	if ( ! defined $app_name )
		{	print "\n\nThis file is not in the server's ApplicationsProcesses table\n";
			return( 0 );
		}
	
	print "\n\nServer's ApplicationProcesses table values:\n";
	print "File ID name: $app_name\n";
	print "File ID category: $virus_category\n";
	print "File ID permissions: $permissions_num\n";
	
	return( 1 );
}



################################################################################
#
sub SaveLastScanFinished( $$$$ )
#
#  Save the time that the last scan totally finished into the registry so the Update program can use it
#  Also save the count of viruses found
#
################################################################################
{	my $virus_count		= shift;
	my $unknown_count	= shift;
	my $strtime			= shift;
	my $objects			= shift;
	
	my $key;
	my $type;
	my $data;
	

	my $access = &OueryOSRegistryAccess( KEY_WRITE );
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, $access, $key );

	return( undef ) if ( ! $ok );

	# Make sure that I am not being redirected under a 64 bit Windows OS
	&OueryOSWin64BitRegistry( $key );

	# Get the current time
	my $last_scan_finished = time();
	
	
	# Put the current time into the correct format for Brock
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $last_scan_finished );
	$year += 1900;
	$mon++;
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d", $year, $mon, $mday, $hour, $min, $sec );
	
	$ok = &RegSetValueEx( $key, "Last Scan Finished Date", 0,  REG_SZ, $datestr );
	
	
	# Save the time that I finished a complete scan
	if ( ( $opt_exclusive ) && ( $opt_all ) )
		{	$ok = &RegSetValueEx( $key, "Last Scan Finished", 0,  REG_SZ, $last_scan_finished );
			$ok = &RegSetValueEx( $key, "Last Full Scan Finished Date", 0,  REG_SZ, $datestr );
		}


	# Pack the threat count into a dword
	my $dword = pack( "V", 0 + $virus_count );
	$ok = &RegSetValueEx( $key, "Last Scan Threats", 0,  REG_DWORD, $dword );


	# Pack the unknown count into a dword
	$dword = pack( "V", 0 + $unknown_count );
	$ok = &RegSetValueEx( $key, "Last Scan Unknowns", 0,  REG_DWORD, $dword );
	

	# Pack the object count into a dword
	$dword = pack( "V", 0 + $objects );
	$ok = &RegSetValueEx( $key, "Last Scan Files", 0,  REG_DWORD, $dword );
	

	# Format the strtime into the format Brock wants ...
	my ( $seconds, $junk ) = split /\s/, $strtime, 2;
	if ( $seconds )
		{	$seconds = 0 + $seconds;
		}
	else
		{	$seconds = 0 + 0;
		}


	my $hours	= &Integer( $seconds / 3600 );
	my $minutes = &Integer( ( $seconds - ( 3600 * $hours ) ) / 60 );
	my $secs	= $seconds - ( 60 * $minutes ) - ( 3600 * $hours );
	
	my $elapsed_time = sprintf( "%02d:%02d:%02d", $hours, $minutes, $secs );
	
	$ok = &RegSetValueEx( $key, "Last Scan Elapsed Time", 0,  REG_SZ, $elapsed_time );

	&RegCloseKey( $key );
	
	
	return( $ok );
}



################################################################################
#
sub Integer( $ )
#
#  Return the Integer value of a real value
#
################################################################################
{	my $real = shift;
	
	return( 0 + 0 ) if ( ! $real );
	my $int = sprintf( "%d", $real );
	$int = 0 + $int;
	
	return( $int );
}



################################################################################
#
sub LoadProperties()
#
#  Load the additional properties from the registry - use defaults if not specified
#
################################################################################
{	my $key;
	my $type;
	my $data;


	# Set the default values
	$block_virus				= 0 + 1;
	$block_virus_action			= "ReportOnly";	
	
	
	#  See if the key exists
	my $access = &OueryOSRegistryAccess( KEY_READ );
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, $access, $key );
	
	return( undef ) if ( ! $ok );

	# Make sure that I am not being redirected under a 64 bit Windows OS
	&OueryOSWin64BitRegistry( $key );

	$ok = &RegQueryValueEx( $key, "Block Virus", [], $type, $data, [] );
	$block_virus = 0 + 0 if ( $ok );
	my $len = length( $data );
	$block_virus = 0 + 1 if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );


	$ok = &RegQueryValueEx( $key, "Block Virus Action", [], $type, $data, [] );
	$len = length( $data );
	$block_virus_action = "";
	$block_virus_action = $data if  ( ( $ok )  &&  ( $len > 0 ) );
	$block_virus_action = "ReportOnly" if ( ( $block_virus_action )  &&  ( $block_virus_action eq "" ) );
	$block_virus_action = &OneOf( $block_virus_action, "ReportOnly", "Delete", "Quarantine", "Disable" );
	$block_virus_action = "ReportOnly" if ( ( ! $block_virus_action )  ||  ( $block_virus_action eq "Nothing" ) );
	
	
	# Default this to no
	$ok = &RegQueryValueEx( $key, "Lightspeed Analyze Unknown", [], $type, $data, [] );
	$len = length( $data );
	$lightspeed_analyze_unknown = undef;
	$lightspeed_analyze_unknown = 0 + 1 if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
	
	
	# Default this to no
	$ok = &RegQueryValueEx( $key, "Lightspeed Analyze Virus", [], $type, $data, [] );
	$len = length( $data );
	$lightspeed_analyze_virus = undef;
	$lightspeed_analyze_virus = 0 + 1 if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) );
		
		
	# Default this to undef
	$ok = &RegQueryValueEx( $key, "Scan Job Percent", [], $type, $data, [] );
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) )
		{	$opt_job = unpack( "L", $data ) if ( ! $opt_job );
		}
	
	
	# Make sure that if it is set that it is within a valid range	
	if ( ( $opt_job )  &&  ( ( $opt_job < 5 )  ||  ( $opt_job > 100 ) ) )
		{	print "Maximum scan CPU job percent must be from 5 to 100\%\n";
			$opt_job = 0 + 25;
		}
		
		
	$ttc_server = undef;
	$ok = &RegQueryValueEx( $key, "TTC Server", [], $type, $data, [] );
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data ) )
		{	# Flip a REG_MULTI_SZ into a list format
			my @ttc_servers = split /\x00/, $data;

			# Now, just use the first ttc server in the list
			if ( $ttc_servers[ 0 ] )
				{	$ttc_server = $ttc_servers[ 0 ];
				}
		}
	
	
	# Should I default to scanning by Content?
	$ok = &RegQueryValueEx( $key, "Scan Method", [], $type, $data, [] );
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data =~ m/content/i ) )
		{	$opt_content = 1 if ( ! $opt_content );	# If I am set to ignore the File Integrity and File ID databases then don't override that
		}
	
	
	# Is there a software version?
	my $software_version;
	$ok = &RegQueryValueEx( $key, "Software Version", [], $type, $data, [] );
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data ) )
		{	$software_version = $data;
		}

	
	# Is Cloud Repository enabled?
	$ok = &RegQueryValueEx( $key, "Cloud Repository", [], $type, $data, [] );
	$len = length( $data );
	if ( ( $ok )  &&  ( $len > 0 )  &&  ( $data )  &&  ( $data  ne "\x00\x00\x00\x00" ) )
		{	$opt_cloud = 1;
		}


	&RegCloseKey( $key );
	
	return( $software_version );
}



################################################################################
#
sub OneOf()
#
#  Given a variable value, make sure that it is one of the possible values
#  The default value is the first possibility
#
################################################################################
{	my $current = shift;
	my $lc_current = lc( $current );
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
sub AddUnknowns()
#
#  Add all the unknown executables into the file integrity hash
#  Return the number added
#
################################################################################
{	&ScanLogEvent( "Adding the unknown files into the local file integrity database\n" );
	
	my $count = 0 + 0;
	my $display_count = 0 + 0;
	foreach ( @unknown_files )
		{	next if ( ! $_ );
			&AddFileIntegrity( $_, 1 );
			$count++;
			$display_count++;
			
			# Show some progress if adding a lot of files
			if ( $display_count == 1000 )
				{	&ScanLogEvent( "Added $count unknown files so far ...\n" );
					$display_count = 0 + 0;
				}
				
			next if ( ! $factor );
			
			&CPUSleep();
		}
		
	&ScanLogEvent( "Added $count unknown file(s) to the local file integrity database\n" ) if ( $count );
	&ScanLogEvent( "No unknown files added to the local file integrity database\n" ) if ( ! $count );
	
	@unknown_files = ();
	
	return( $count );
}



################################################################################
#
sub DeleteInfectedFileIntegrity()
#
#  Delete all the FileIntegrity entries that exist that have 
#   been detected as viruses.
#
################################################################################
{	&ScanLogEvent( "Correcting file integrity entries\n" );
	
	# Check each infected file ID and see if it exists in the FileIntegrity DB.
	my $count = 0 + 0;
	foreach ( @infected_file_id )
		{	next if ( ! defined $_ );
			
			my $file_id = $_;
			next if ( $file_id eq "");
			
			if ( &IsLocalKnownFileID( $file_id ) )
			  {
			    my ( $delete_ok, $msg ) = &DeleteFileID( $file_id );
			    $count++ if ( $delete_ok );
			  }
		}
		
	&ScanLogEvent( "Corrected $count file integrity entries\n" ) if ( $count );
	&ScanLogEvent( "No file integrity entries to be corrected\n" ) if ( ! $count );
	
	
	return( $count );
}



################################################################################
#
sub FileFullPath( $ )
#
#  Return the full path of the file, including disk drive
#
################################################################################
{	my $file = shift;
	
	return( undef ) if ( ! $file );
	
	$file =~ s#\/#\\#g;
	
	my $full_path;

	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#g;
	$cwd =~ s/\\$//;   # Trim off a trailing slash
	
	
	# Is there no path at all in the file name?
	if ( ! ( $file =~ m/\\/ ) )
		{	$full_path = $cwd . "\\$file";
			return( $full_path );
		}
	
	
	$full_path = $file;
	
	return( $full_path );
}



################################################################################
#
sub get_drives( $ )
#
#  Return the drive letters for all of the local drives
#
################################################################################
{
use Win32::DriveInfo;

     my @drives = Win32::DriveInfo::DrivesInUse();
	 my @local_drives;
	 
	 foreach ( @drives )
		{	my $letter = $_;
			my $type = Win32::DriveInfo::DriveType( $letter );

			# Type 3 is a fixed drive
			push @local_drives, $letter if ( $type == 3 );
		}

	return( @local_drives );
}



################################################################################
#
sub get_network_drives( $ )
#
#  Return the drive letter or UNC for local and network drives
#
################################################################################
{
use Win32::DriveInfo;

     my @drives = Win32::DriveInfo::DrivesInUse();
	 my @local_drives;
	 
	 foreach ( @drives )
		{	my $letter = $_;
			my $type = Win32::DriveInfo::DriveType( $letter );

			# Type 3 is a fixed drive
			push @local_drives, $letter if ( $type == 3 );
			
			# Type 4 is a fixed drive
			push @local_drives, $letter if ( $type == 4 );
		}

	return( @local_drives );
}



################################################################################
#
sub ScanRegistry( $$$ )
#
#  Scan through the registry looking for unknown programs and viruses
#
################################################################################
{	my $block_virus			= shift;
	my $opt_verbose			= shift;
	my $unknown_files_ref	= shift;
	
use Win32::Shortcut;
	
	&ScanLogEvent( "Scanning critical registry entries ...\n" );
	
	
	# First, check the registry entries
	my ( @ret ) = &ScanRegistryAutoruns();
	
	my @key;
	my @value;
	my @file;
	
	
	# Unpack out the return from ScanRegistryAutoruns function
	foreach ( @ret )
		{	next if ( ! $_ );
			my ( $key, $val, $file ) = split /\t/, $_, 3;
			
			push @key, $key;
			push @value, $val;
			push @file, $file;
		}
	
	
	# Check each file for virus or unknown
	for ( my $count = 0 + 0;  $file[ $count ];  $count++ )
		{	
			my $file = $file[ $count ];
			my $key = $key[ $count ];
			my $val = $value[ $count ];
			
			next if ( ! defined $file );
			next if ( ! -f $file );
			
			my $ret;
			my $file_id;
			
			my $lc_key = lc( $key );
			
			
			# First, check to see if I know this is bad just from the name of the key or the file
			$ret = "DyFuCa" if ( $lc_key =~ m/dyfuca/ );
			
			# Make sure that I can access the file
			&DisinfectCommandFileAccessNormal( $file );
			
			my $scanable = &Scanable( $file, 1 );
					
			# Was there an error trying to find out if it is scanable?
			my $downadup;
			if ( ! defined $scanable )
				{	my $err = $!;
					$err = "Undefined" if ( ! $err );
					&ScanLogEvent( "Error opening $file: $err\n" );
					
					# Could this be the Downadup bastard?
					my $size = -s $file;
					$downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );
				}	
							
			( $ret, $file_id ) = &ScanFile( $file, 1, undef );
			$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );
			
			# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
			if ( $ret )
				{	foreach( @ignore_virus_names )
						{	my $ignore_name = $_;
							next if ( ! $ignore_name );
							my $qignore_name = quotemeta( $ignore_name );
							if ( $ret =~ m/$qignore_name/i )
								{	&ScanLogEvent( "$file is $ret - ignoring\n" );
									$ret = undef;
									last;
								}
						}
				}
				
			# Go the the next file if there is nothing wrong with this one 
			if ( ! defined $ret )
				{	&ScanLogEvent( "$file is OK\n" ) if ( $opt_verbose );
					next;
				}
			
			if ( $ret =~ m/Unknown executable/ )
				{	push @$unknown_files_ref, $file;
					
					my ( $reg_hive, $subkey ) = &ScanRegistrySplit( $key );
					
					next if ( ! defined $reg_hive );
					next if ( ! defined $subkey );
										
					# Are unknown program allowed to modify the registry?
					&ScanLogEvent( "Warning only: Unknown program $file is being autorun - in registry key $key\n" ) if ( ! $val );
					&ScanLogEvent( "Warning only: Unknown program $file is being autorun - in registry value $key $val\n" ) if ( $val );
				}
				
			elsif ( $ret =~ m/Scan error/ )	# Ignore scan errors - usually it is because the program isn't there
				{
				}
				
			else	# It's a virus, so delete the registry key or value
				{	my ( $reg_hive, $subkey ) = &ScanRegistrySplit( $key );
					
					next if ( ! defined $reg_hive );
					next if ( ! defined $subkey );
					
					# Should I get rid of the registry key?
					if ( ! $block_virus )
						{	&ScanLogEvent( "Warning only: $file has Virus $ret - in registry key $key\n" ) if ( ! $val );
							&ScanLogEvent( "Warning only: $file has Virus $ret - in registry key $key\\$val\n" ) if ( $val );
						}
					else	# Get rid of it
						{	# Figure out the actual registry type
							my $registry_key = "$key\\$val";
							
							my $ok = &ScanRegistryDelete( $key, $val );
							
							if ( $ok )	
								{	&ScanLogEvent( "$file has virus $ret - Setting registry value $key\\$val to blank.\n" );
								}
							else
								{	&ScanLogEvent( "$file has virus $ret - Unable to set registry value $key\\$val to blank to stop it.\n" );
								}
						}
						
					&ScanEventLogVirus( "File $file is $ret" );	
					
					push @infected_files, $file;
					push @infection, $ret;
					push @infected_file_id, $file_id if ( defined $file_id );
					push @infected_file_id, "" if ( ! defined $file_id );				
				}
		}
		

	&ScanLogEvent( "Scanning startup folders ...\n" );
	
	
	# Look at the StartUp folders for all the users
	my @startup_folders;
	
	
	my $username = $ENV{ USERNAME };
	my $homedrive = $ENV{ HOMEDRIVE };
	
	my $startup_dir = "C:\\Documents and Settings";
	$startup_dir =~ s/C:/$homedrive/ if ( $homedrive );
	
	my $start_dir = "C:\\Documents and Settings\\USERNAME\\Start Menu\\Programs\\Startup";
	my $start_menu = "C:\\Documents and Settings\\USERNAME\\Start Menu";
	
	
	if ( opendir( DIRHANDLE, $startup_dir ) )
		{	for my $file ( readdir( DIRHANDLE ) )
				{	# Is it the file current open by the service?
					next if ( ! $file );
					
					next if ( $file eq "." );
					next if ( $file eq ".." );
					
					my $dir = $start_dir;
					$dir =~ s/USERNAME/$file/;
					
					my $menu = $start_menu;
					$menu =~ s/USERNAME/$file/;
					
					push @startup_folders, $dir;
					push @startup_folders, $menu;
				}
				
			closedir( DIRHANDLE );	
		}
	else # If I can't open the startup directory, giveup
		{	return( 1 );
		}
	

	foreach ( @startup_folders )
		{	next if ( ! $_ );
			my $startup_folder = $_;
			
			$startup_folder =~ s/USERNAME/$username/ if ( $username );
			$startup_folder =~ s/C:/$homedrive/ if ( $homedrive );
			
			next if ( ! -d $startup_folder );
			
			next if ( ! opendir( DIRHANDLE, $startup_folder ) );

			for my $file ( readdir( DIRHANDLE ) )
				{	# Is it the file current open by the service?
					next if ( ! $file );
					
					next if ( $file eq "." );
					next if ( $file eq ".." );
							 
					my $fullpath = "$startup_folder\\$file";
					next if ( ! -f $fullpath );
					
					# Is it just a link?
					my $lc_path = lc( $fullpath );
					
					if ( $lc_path =~ m/\.lnk$/ )
						{
							my $link = new Win32::Shortcut();
							$link->Load( "$fullpath" );
							
							my $link_path = $link->{'Path'};
							$link->Close();

							next if ( ! -f $link_path );
							
							# Make sure that I can access the file
							&DisinfectCommandFileAccessNormal( $link_path );

							my $scanable = &Scanable( $link_path, 1 );
							my $ret;
							my $file_id;
							
							# Was there an error trying to find out if it is scanable?
							my $downadup;
							if ( ! defined $scanable )
								{	my $err = $!;
									$err = "Undefined" if ( ! $err );
									&ScanLogEvent( "Error opening $link_path: $err\n" );
									
									# Could this be the Downadup bastard?
									my $size = -s $link_path;
									$downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );
								}	
								
							( $ret, $file_id ) = &ScanFile( $link_path, 1, undef );
							$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );

							# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
							if ( $ret )
								{	foreach( @ignore_virus_names )
										{	my $ignore_name = $_;
											next if ( ! $ignore_name );
											my $qignore_name = quotemeta( $ignore_name );
											if ( $ret =~ m/$qignore_name/i )
												{	&ScanLogEvent( "$link_path is $ret - ignoring\n" );
													$ret = undef;
													last;
												}
										}
								}
								
							# Go the the next file if there is nothing wrong with this one 
							if ( ! defined $ret )
								{	&ScanLogEvent( "$link_path is OK\n" ) if ( $opt_verbose );
									next;	
								}
								
							if ( $ret =~ m/Unknown executable/ )
								{	push @$unknown_files_ref, $link_path;
									
									&ScanLogEvent( "Warning only: Unknown program in startup folder: $fullpath links to $link_path\n" );
								}
							elsif ( $ret =~ m/Scan error/ )	# Ignore scan errors - usually it is because the program isn't there
								{
								}
							else
								{	&ScanLogEvent( "Danger: Program infected with $ret in startup folder: $fullpath links to $link_path\n" );
									&ScanEventLogVirus( "File $link_path is $ret" );
									
									push @infected_files, $link_path;
									push @infection, $ret;
									push @infected_file_id, $file_id if ( defined $file_id );
									push @infected_file_id, "" if ( ! defined $file_id );				
								}
								
							next;							
						}
													
					if ( $lc_path =~ m/\.ini$/ )
						{
							open( INIFILE, "<$fullpath" ) or next;
							
							while (my $line = <INIFILE>)
								{	chomp( $line );
									next if ( ! $line );
								
									my $lcline = lc( $line );
									if ( $lcline =~ m/\.lnk=@/ )
										{	my ( $junk, $ini_prog ) = split /\.lnk=@/, $lcline, 2;
											#print "ini prog = $ini_prog\n";
										}
								}
								
							close( INIFILE );

							next;
						}
						

					# Is the file a program, or just some kind of data file?
					next if ( ! -f $fullpath );
					next if ( ! &IsProgram( $fullpath, undef ) );
					
					# Make sure that I can access the file
					&DisinfectCommandFileAccessNormal( $fullpath );

					my $scanable = &Scanable( $fullpath, 1 );
						
					my $ret;
					my $file_id;
					
					# Was there an error trying to find out if it is scanable?
					my $downadup;
					if ( ! defined $scanable )
						{	my $err = $!;
							$err = "Undefined" if ( ! $err );
							&ScanLogEvent( "Error opening $fullpath: $err\n" );
							
							# Could this be the Downadup bastard?
							my $size = -s $fullpath;
							$downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );
						}	
						
					( $ret, $file_id ) = &ScanFile( $fullpath, 1, undef );
					$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );

					# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
					if ( $ret )
						{	foreach( @ignore_virus_names )
								{	my $ignore_name = $_;
									next if ( ! $ignore_name );
									my $qignore_name = quotemeta( $ignore_name );
									if ( $ret =~ m/$qignore_name/i )
										{	&ScanLogEvent( "$fullpath is $ret - ignoring\n" );
											$ret = undef;
											last;
										}
								}
						}
						
					# Go the the next file if there is nothing wrong with this one 
					if ( ! defined $ret )
						{	&ScanLogEvent( "$fullpath is OK\n" ) if ( $opt_verbose );
							next;
						}
					
					if ( $ret =~ m/Unknown executable/ )
						{	push @$unknown_files_ref, $fullpath;
							
							&ScanLogEvent( "Warning only: Unknown program in startup folder: $fullpath\n" );
						}
					elsif ( $ret =~ m/Scan error/ )	# Ignore scan errors - usually it is because the program isn't there
						{
						}
					else
						{	&ScanLogEvent( "Danger: Program infected with $ret in startup folder: $fullpath\n" );
							&ScanEventLogVirus( "File $fullpath is $ret" );
							
							push @infected_files, $fullpath;
							push @infection, $ret;
							push @infected_file_id, $file_id if ( defined $file_id );
							push @infected_file_id, "" if ( ! defined $file_id );				
						}
				}
				
			closedir( DIRHANDLE );

		}


	&ScanLogEvent( "Scanning Svchost dlls ...\n" );

	( @ret ) = &SvcHost();

	# Unpack out the return from Svchost function
	foreach ( @ret )
		{	next if ( ! defined $_ );
			my ( $service, $file ) = split /\t/, $_, 2;
			next if ( ! defined $service );
			next if ( ! defined $file );
			next if ( ! -f $file );
			
			# Make sure that I can access the file
			&DisinfectCommandFileAccessNormal( $file );

			my $scanable = &Scanable( $file, 1 );
				
			my $ret;
			my $file_id;
			
			# Was there an error trying to find out if it is scanable?
			my $downadup;
			if ( ! defined $scanable )
				{	my $err = $!;
					$err = "Undefined" if ( ! $err );
					&ScanLogEvent( "Error opening $file: $err\n" );
					
					# Could this be the Downadup bastard?
					my $size = -s $file;
					$downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );
				}	
				
			( $ret, $file_id ) = &ScanFile( $file, 1, undef );
			$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );
			
			# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
			if ( $ret )
				{	foreach( @ignore_virus_names )
						{	my $ignore_name = $_;
							next if ( ! $ignore_name );
							my $qignore_name = quotemeta( $ignore_name );
							if ( $ret =~ m/$qignore_name/i )
								{	&ScanLogEvent( "$file is $ret - ignoring\n" );
									$ret = undef;
									last;
								}
						}
				}

			# Go the the next file if there is nothing wrong with this one 
			if ( ! defined $ret )
				{	&ScanLogEvent( "$file is OK\n" ) if ( $opt_verbose );
					next;
				}
			
			if ( $ret =~ m/Unknown executable/ )
				{	push @$unknown_files_ref, $file;
					
					&ScanLogEvent( "Warning only: Unknown dll loaded by Svchost service $service: $file\n" );
				}
			elsif ( $ret =~ m/Scan error/ )	# Ignore scan errors - usually it is because the program isn't there
				{
				}
			else
				{	&ScanLogEvent( "Danger: Dll loaded by Svchost service $service is infected with $ret: $file\n" );
					&ScanEventLogVirus( "File $file is $ret" );
					
					push @infected_files, $file;
					push @infection, $ret;
					push @infected_file_id, $file_id if ( defined $file_id );
					push @infected_file_id, "" if ( ! defined $file_id );				
				}
		}
		

	return( 1 );
}



################################################################################
#
sub ScanProcess( $$$ )
#
#  Scan through the running processes looking for unknown programs and viruses
#
################################################################################
{	my $block_virus			= shift;
	my $opt_verbose			= shift;
	my $unknown_files_ref	= shift;
	
use Win32::Shortcut;
	
	&ScanLogEvent( "Scanning running processes ...\n" );
	
    my %process_hash = &ProcessHash();
	
	my %checked_process;
	
	while ( my ( $pid, $process ) = each( %process_hash ) )
		{	next if ( ! $pid );
			next if ( ! defined $process );			
			next if ( ! -f $process );

			# Have I already scanned this?
			next if ( defined $checked_process{ lc( $process ) } );
			$checked_process{ lc( $process ) } = 1;
			
			# Make sure that I can access the file
			&DisinfectCommandFileAccessNormal( $process );

			my $scanable = &Scanable( $process, 1 );
			
			my $ret;
			my $file_id;
			
			# Was there an error trying to find out if it is scanable?
			my $downadup;
			if ( ! defined $scanable )
				{	my $err = $!;
					$err = "Undefined" if ( ! $err );
					&ScanLogEvent( "Error opening $process: $err\n" );
					
					# Could this be the Downadup bastard?
					my $size = -s $process;
					$downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );
				}	

			( $ret, $file_id ) = &ScanFile( $process, 1, undef );
			$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );
			
			# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
			if ( $ret )
				{	foreach( @ignore_virus_names )
						{	my $ignore_name = $_;
							next if ( ! $ignore_name );
							my $qignore_name = quotemeta( $ignore_name );
							if ( $ret =~ m/$qignore_name/i )
								{	&ScanLogEvent( "$process is $ret - ignoring\n" );
									$ret = undef;
									last;
								}
						}
				}
				
			# Go the the next file if there is nothing wrong with this one 
			if ( ! defined $ret )
				{	&ScanLogEvent( "$process is OK\n" ) if ( $opt_verbose );
					next;	
				}
				
			if ( $ret =~ m/Unknown executable/ )
				{	push @$unknown_files_ref, $process;
					
					&ScanLogEvent( "Warning only: Unknown program $process is currently running\n" );
				}
			elsif ( $ret =~ m/Scan error/ )	# Ignore scan errors - usually it is because the program isn't there
				{
				}
			else
				{	&ScanLogEvent( "Danger: Running program $process is virus infected with $ret\n" );
					&ScanEventLogVirus( "File $process is $ret" );
					
					push @infected_files, $process;
					push @infection, $ret;
					push @infected_file_id, $file_id if ( defined $file_id );
					push @infected_file_id, "" if ( ! defined $file_id );				
				}
		}
		
		
	&ScanLogEvent( "Scanning running process dlls ...\n" );
	
    my %process_dll = &ProcessDlls();
	
	# Figure out the unique names so that I don't scan the same thing twice
	my @process_dll_list	= values %process_dll;
	my @process_pids		= keys %process_dll;
	
	# Build up a hash of unique names and related process names
	my %unique_names;
	
	my $index = 0 - 1;
	foreach ( @process_dll_list )
		{	$index++;
			
			next if ( ! defined $_ );
			my $list = $_;
			
			# Get the names of the .dlls that this pid has loaded
			my @dll_files = split /\t/, $list;
			
			foreach ( @dll_files )
				{	my $dll_file = lc( $_ );
					
					if ( ! defined $unique_names{ $dll_file } )
						{	$unique_names{ $dll_file } = $process_pids[ $index ];
						}
					else
						{	$unique_names{ $dll_file } .= "\t" . $process_pids[ $index ];
						}
				}
		}
		

	# Now that I've got a unique list of .dll names - scan each .dll name	
	while ( my ( $dll_file, $pid_list ) = each( %unique_names ) )
		{	next if ( ! defined $dll_file );
			next if ( ! defined $pid_list );
			next if ( ! -f $dll_file );
			
			# Have I already scanned this?
			next if ( defined $checked_process{ lc( $dll_file ) } );
			$checked_process{ lc( $dll_file ) } = 1;

			# Make sure that I can access the file
			&DisinfectCommandFileAccessNormal( $dll_file );

			my $scanable = &Scanable( $dll_file, 1 );
			
			my $ret;
			my $file_id;
			
			# Was there an error trying to find out if it is scanable?
			my $downadup;
			if ( ! defined $scanable )
				{	my $err = $!;
					$err = "Undefined" if ( ! $err );
					&ScanLogEvent( "Error opening $dll_file: $err\n" );
					
					# Could this be the Downadup bastard?
					my $size = -s $dll_file;
					$downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );
				}	

			( $ret, $file_id ) = &ScanFile( $dll_file, 1, undef );
			$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );
			
			# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
			if ( $ret )
				{	foreach( @ignore_virus_names )
						{	my $ignore_name = $_;
							next if ( ! $ignore_name );
							my $qignore_name = quotemeta( $ignore_name );
							if ( $ret =~ m/$qignore_name/i )
								{	&ScanLogEvent( "$dll_file is $ret - ignoring\n" );
									$ret = undef;
									last;
								}
						}
				}
				
			# Go the the next file if there is nothing wrong with this one 
			if ( ! defined $ret )
				{	&ScanLogEvent( "$dll_file is OK\n" ) if ( $opt_verbose );
					next;	
				}
				
			if ( $ret =~ m/Unknown executable/ )
				{	push @$unknown_files_ref, $dll_file;
					
					&ScanLogEvent( "Warning only: Unknown .dll $dll_file is currently running\n" );
				}
			elsif ( $ret =~ m/Scan error/ )	# Ignore scan errors - usually it is because the program isn't there
				{
				}
			else
				{	&ScanLogEvent( "Danger: Running .dll $dll_file is virus infected with $ret\n" );
					
					# Show the list of programs running the .dll
					my @pids = split /\t/, $pid_list;
					
					foreach ( @pids )
						{	next if ( ! defined $_ );
							my $this_pid = $_;
							
							my $process_name = &ProcessPIDName( $this_pid );
							$process_name = "Unknown" if ( ! $process_name );
							
							&ScanLogEvent( "Virus infected $dll_file is loaded by $process_name\n" );
						}
						
					&ScanEventLogVirus( "File $dll_file is $ret" );	
					
					push @infected_files, $dll_file;
					push @infection, $ret;
					push @infected_file_id, $file_id if ( defined $file_id );
					push @infected_file_id, "" if ( ! defined $file_id );				
				}
		}
		
	return( 1 );	
}



################################################################################
#
sub ScanDir( $ )
#
#  Scan all the files in a given directory
#
################################################################################
{
	my $scandir = shift;

	$scandir = lc( $scandir );	
	if ( -d $scandir ) 
		{
			&ScanDirRecursive( $scandir );
		}
	else 
		{
			&ScanLogEvent( "No such directory: $scandir\n" );
			return();
		}
}



################################################################################
#
sub ScanMessageFile( $$ )
#
#  Scan a file for viruses.  If it is a Lightspeed message file, expand out
#  the attachments and scan them as well.  Delete the created files
#  Return the name of the first virus found, or undef if nothing found
#  Also return the file ID of the virus infected file
#
################################################################################
{	my $scanfile = shift;	# This is the name of the file to scan
	my $scanable = shift;	# This is what scanable type the file is


	# If it isn't scanable then don't scan it
	return( undef, undef ) if ( ! $scanable );


	if ( $opt_debug )
		{	&ScanLogEvent( "Scanable file type: $scanable\n" );
			my $desc = &ScanableDescription( $scanable );
			&ScanLogEvent( "Scanable description: $desc\n" );
		}
		
	
	# Don't scan zip files if I'm not supposed to - or msi, cab, rar, StuffIt, bz, bz2, gz
	return( undef, undef ) if ( ( $scanable == 2 )  &&  ( ! $opt_zip ) );
	return( undef, undef ) if ( ( $scanable == 7 )  &&  ( ! $opt_zip ) );
	return( undef, undef ) if ( ( $scanable == 8 )  &&  ( ! $opt_zip ) );
	return( undef, undef ) if ( ( $scanable == 9 )  &&  ( ! $opt_zip ) );
	return( undef, undef ) if ( ( $scanable == 14 )  &&  ( ! $opt_zip ) );
	return( undef, undef ) if ( ( $scanable == 15 )  &&  ( ! $opt_zip ) );


	# Can I read it?
	return( "Scan error: can not read file $scanfile", undef ) if ( ! -r $scanfile ); 

	$total_files++;


	# Scan using the content flag, and report unknown executables
	my ( $ret, $file_id ) = &ScanFile( $scanfile, $opt_content, undef );	
	
	if ( ( $opt_debug )  &&  ( $file_id ) )
		{	my $hex_file_id = &StrToHex( $file_id );
			&ScanLogEvent( "Scan return: $ret\n" ) if ( $ret );
			my $len = length( $hex_file_id );
			&ScanLogEvent( "Scan return file ID: $hex_file_id, length: $len\n" );
		}
		
	
	# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
	if ( $ret )
		{	foreach( @ignore_virus_names )
				{	my $ignore_name = $_;
					next if ( ! $ignore_name );
					my $qignore_name = quotemeta( $ignore_name );
					if ( $ret =~ m/$qignore_name/i )
						{	&ScanLogEvent( "$scanfile is $ret - ignoring\n" );
							$ret = undef;
							last;
						}
				}
		}
		

	# If the file is an SMTP message file ...
	if ( ( ! defined $ret )  &&  ( $scanable == 6 )  &&  ( $opt_content ) )
		{	my @attachments = &ScanMessageAttachments( $scanfile, $tmp_dir, $opt_debug );
			
			# Scan all the attachments looking for viruses	
			my $virus_found;
			foreach ( @attachments )
				{	next if ( ! $_ );
					
					my $file = $_;
					
					# If I've already found a virus in the attachments then just delete everything else
					if ( $virus_found )
						{	# Delete the file unless I am debugging
							unlink( $file ) if ( ! $opt_debug );
							next;
						}
						
					my ( $temp_dir, $temp_name ) = &SplitFileName( $file );
								
					my $attach_scanable = &Scanable( $file, $opt_content );
					
					# Was there an error trying to find out if it is scanable?
					if ( ! defined $attach_scanable )
						{	my $err = $!;
							$err = "Undefined" if ( ! $err );
							&ScanLogEvent( "Error opening $file: $err\n" );
							
							next;
						}
				
					if ( ! $attach_scanable )
						{	&ScanLogEvent( "$scanfile -> $temp_name is OK\n" ) if ( $opt_verbose );
							next;
						}
						
					# If doing a quick scan, only scan executable programs
					if ( ( $attach_scanable != 1 )  &&  ( $opt_quick ) )
						{	next;
						}
					
					my $attach_file_id;
					( $ret, $attach_file_id ) = &ScanFile( $file, 1, undef );	# Scan using the content flag, and report unknown executables

					
					# Should I ignore password protected zip files, Eicar test files, etc. as viruses?
					if ( $ret )
						{	foreach( @ignore_virus_names )
								{	my $ignore_name = $_;
									next if ( ! $ignore_name );
									my $qignore_name = quotemeta( $ignore_name );
									if ( $ret =~ m/$qignore_name/i )
										{	&ScanLogEvent( "$scanfile is $ret - ignoring\n" );
											$ret = undef;
											last;
										}
								}
						}


					if ( ( $ret )  &&
						( ! ( $ret =~ m/Scan error/i ) )  &&
						( ! ( $ret =~ m/Unknown executable/i ) ) )
						{	&ScanLogEvent( "$scanfile -> $temp_name is $ret\n" ) if ( $opt_verbose);
					
							$file_id = $attach_file_id;	# Set the file ID to the file ID of the infected file
							
							# Delete the attached file unless I am debugging or I am archiving
							# If I am debugging then don't delete the infected file
							if ( ( $opt_debug )  ||  ( $opt_virus_archive ) )
								{	my ( $infected_file, $infected_virus, $infected_category ) = &ScanVirusContained();
									unlink( $file ) if ( ( $infected_file )  &&  ( $file ne $infected_file ) );
								}
							else
								{	unlink( $file );
								}
								
							# Stop scanning the other files since I've found a virus
							$virus_found = 1;
						}
					else	
						{	&ScanLogEvent( "$scanfile -> $temp_name is OK\n" ) if ( $opt_verbose );
							
							# Delete the file unless I am debugging
							unlink( $file ) if ( ! $opt_debug );
						}
				}
		} 

	
	# Did I find a virus?  A return code can also be a scan error or an unknown program
	my $virus_infected = $ret;
	$virus_infected = undef if ( ( defined $ret )  &&  ( $ret eq "Unknown executable" ) );
	$virus_infected = undef if ( ( defined $ret )  &&  ( ( $ret =~ m/Scan error/ ) ) );
	$virus_infected = undef if ( ( defined $ret )  &&  ( ( $ret =~ m/Scan error/ ) ) );


	# The infected file can be different than the scanfile - especially if the scanfile is a zip archive
	my ( $infected_file, $infected_virus, $infected_category ) = &ScanVirusContained();
	&ScanLogEvent( "ScanVirusContained return: $infected_file, $infected_virus, $infected_category\n" ) if ( ( $infected_file )  &&  ( $opt_debug ) ); 
		

	# This fixes an issue in scan.dll - file ID can be all blanks if virus detected depending on the type of scan
	$file_id = &ApplicationFileID( $infected_file ) if ( ( $infected_file )  &&  ( defined $file_id )  &&  ( $file_id eq ( " " x 28 ) ) ); 


	&ScanHandleResults( $scanfile, $scanable, $virus_infected, $infected_file, $file_id, $infected_category );

	
	# Calculate and do the sleep if necessary
	&CPUSleep() if ( $factor );
		
	return( $ret, $file_id );
}



################################################################################
#
sub ScanHandleResults( $$$ $$$ )
#
#  I've just scanned a file - handle the different outcomes
#
################################################################################
{	my $scanfile			= shift;	# The name of the original file
	my $scanable			= shift;	# The scanable type of the original file
	my $virus_infected		= shift;	# What it is infected with - if anything

	my $infected_file		= shift;	# The name of the infected file
	my $file_id				= shift;	# The file ID of the original file, or the infected file if it is different
	my $infected_category	= shift;	# The category of the virus infection
	
	
	if ( ( $opt_purge )  &&  ( ! $virus_infected )  &&  ( defined $file_id )  &&  ( $scanable == 1 ) )
		{	my $digital_signed;
			
# This is commented out for now			
#			$digital_signed = &ScanFileDigitalSigned( $scanfile );
			
			# Only add the file if it isn't digitally signed
			$local_file_id{ $file_id } = 1 if ( ! $digital_signed );
			&ScanLogEvent( "$scanfile is digitally signed so not adding it to the FileIntegrity database\n" ) if ( ( $digital_signed )  &&  ( $opt_verbose ) );
		}
		
	
	# Is this virus category blocked?
	my $virus_definition;				# Default to undefined
	my $virus_scanable = $scanable;		# Default to original scanable type
	my $app_name;


	# If we found a virus, figure out the scanable type
	if ( $virus_infected )
		{	# If the infected file isn't defined, then it is the scanned file
			$infected_file = $scanfile if ( ! defined $infected_file );
			
			# Figure out what kind of scan detected the infected file
			$virus_scanable = &Scanable( $infected_file, $opt_content );	
		}

	
	# The rest of this processing only matters if it is a scanable file type
	# This includes programs, zip files, documents, etc
	return( 1 ) if ( ! $virus_scanable );

	# Also return here if I don't have a file_id
	return( 1 ) if ( ! defined $file_id );	
	

	if ( ( $virus_infected )  &&  ( $virus_infected =~ m/blocked program/i )  &&  ( $file_id ) )
		{	my $hex = &StrToHex( $file_id );
			&ScanLogEvent( "Blocked program file: $scanfile\n" );
			&ScanLogEvent( "Blocked program file ID: $hex\n" );
		}
			
	
	# Am I supposed to report every program as known good if it isn't virus infected?
	if ( ( $opt_good )  &&  ( ! $virus_infected )  &&  ( $virus_scanable == 1 ) )
		{	my $ok = &ScanReportKnownGood( $ttc_server, $file_id, $scanfile );
			$known_good++;
					
			if ( ( $opt_verbose )  &&  ( $ok ) )
				{	my $hex = &StrToHex( $file_id );
					&ScanLogEvent( "Reported unknown program $hex : $scanfile as known good to $ttc_server\n" ) if ( $ok );
				}
				
			&ScanLogEvent( "Error reporting unknown program $scanfile as known good to $ttc_server\n" ) if ( ! $ok );
		}
	

	# Should I save the file info to report it to Lightspeed and/or my TTC Server?
	# If it isn't a network known file_id, and I scanned it fully, and it is a real executable,
	# and I am supposed to report to Lightspeed, then I should report it to Lightspeed
	# If it is virus infected, then I should report it

	# Do I care if the network knows about this file?
	my $network_known;
	if ( ( $opt_track_unknown )  ||  ( $opt_verbose ) )
		{	# Make sure the FileID Index is loaded
			&FileIDIndexLoad();
			
			my ( $app_name, $category_number, $permissions_num ) = &FileIDGet( $file_id, undef, undef, undef );
			$network_known = 1 if ( defined $app_name );
			
			# If the ApplicationProcesses table knows this file ID then show it if we are in verbose mode
			if ( ( $network_known )  &&  ( $opt_verbose ) )
				{	my $hex = &StrToHex( $file_id );
					&ScanLogEvent( "File ID $hex is in the ApplicationProcesses table as AppName $app_name\n" );
				}
				
			&FileIDIndexClose();
		}
		
		
	my $report = 0 + 0;
    
	# If the ttc server doesn't know about this Win32 program file, should I report it?
	$report = 1 if ( ( $opt_track_unknown )  &&  ( ! $network_known )  &&  ( $virus_scanable == 1 ) );
    
	# We should always report virus-infected files
	$report = 1 if ( $virus_infected );
    
	# We should report if I am sending data back to Lightspeed for analysis and the network doesn't know this file
	$report = 1 if ( ( $opt_appprocess )  &&  ( ! $network_known )  &&  ( $virus_scanable == 1 ) );
	
	if ( $report )
		{	my $saScanResults = $virus_infected;

			$saScanResults = "OK" if ( ! defined $saScanResults );
			
			$saScanResults = "Local permissions only" if ( ( ! $network_known )  &&  ( ! $virus_infected ) );

			# Do I know this file ID locally?
			my $fileID_known = &IsKnownFileID( $file_id );


			$saScanResults = "Unknown executable" if ( ( ! $fileID_known )  &&  ( ! $virus_infected ) );
			
			$saScanResults = "OK - Network known executable" if ( ( $network_known )  &&  ( ! $virus_infected ) );
	        
			$infected_category = 0 + 6 if ( ! defined $infected_category );
            
			# If it isn't OK then report it back to the TTC server
			&ReportScanAppProcess( $file_id, $scanfile, $saScanResults, $infected_category ) if ( ! ( $saScanResults =~ m/^OK/i ) );
		}

	return( 1 );
}



################################################################################
# 
sub ScanVirusInfected( $$$ )
#
#  Given a file with a virus, and the action to take, handle it
#  Return what was done
#
################################################################################
{	my $file	= shift;
	my $action	= shift;
	my $virus	= shift;
	
	return( undef ) if ( ! defined $file );
	
	$action = lc( $action );
	my $lcfile = lc( $file );
	
	return( undef ) if ( ! -e $file );
	
	my $result = "Report only";
	
	if ( ( $action eq "reportonly" )  ||  ( $action eq "nothing" ) )
		{	$result = "Report only";
		}
	elsif ( ( $action eq "quarantine" )  ||  ( $action eq "disinfect" )  ||  ( $action eq "disable" ) )
		{	&ScanNoReadOnly( $file );
			
			# Run a disinfect script if it exists
			my $ok = &Disinfect( $file, $virus, $_version, $opt_verbose, $opt_cloud );

			&ScanLogEvent( "Disinfect for $virus was run successfully\n" ) if ( $ok );
			

			# Show any errors in disinfecting
			my @disinfect_errors = &DisinfectErrors();
			if ( $#disinfect_errors < 0 )
				{	&ScanLogEvent(  "No disinfect script for $virus\n" ) if ( ! $ok );
				}
			elsif ( ! $ok )
				{	&ScanLogEvent(  "Disinfect errors:\n" );
					foreach( @disinfect_errors )
						{	my $error = $_;
							next if ( ! $error );
							my ( $line_number, $formatted_cmd ) = split /\t/, $error;
							&ScanLogEvent(  "Line $line_number: $formatted_cmd\n" );
						}
				}
			
			
			# Did the disinfect script move the file?
			return( "Disinfecting for $virus moved the file $file\n" ) if ( ! -f $file );
			
			# So the disinfect script ran OK, but it didn't move the file.  Maybe it is a pending rename,
			# maybe it disnfected it successfully with Marty's stuff
			return( "Disinfect ran OK on $file" ) if ( $ok );
			
			# So at this point I didn't disinfect it - now I'll try to quarantine it
			my $dir = &ScanQuarantineDirectory();
				
			my $new_file;
			( $ok, $new_file ) = &ScanQuarantine( $virus, $file, $dir );
			
			if ( $ok )
				{	$result = "Moved infected file to $new_file";
				}
			else
				{	$result = "Unable to move infected file $file: $new_file";
				}
		}
	elsif ( $action eq "delete" )
		{	# Rename the file, then try to delete it.  That way if the delete fails, the file has been
			# somewhat disabled			
			&ScanNoReadOnly( $file );

			# Run a disinfect script if it exists
			my $ok = &Disinfect( $file, $virus, $_version, $opt_verbose, $opt_cloud );

			&ScanLogEvent( "Disinfect for $virus was run successfully\n" ) if ( $ok );
			
			
			# Show any errors in disinfecting
			my @disinfect_errors = &DisinfectErrors();
			if ( $#disinfect_errors < 0 )
				{	&ScanLogEvent(  "No disinfect script for $virus\n" ) if ( ! $ok );
				}
			elsif ( ! $ok )
				{	&ScanLogEvent(  "Disinfect errors:\n" );
					foreach( @disinfect_errors )
						{	my $error = $_;
							next if ( ! $error );
							my ( $line_number, $formatted_cmd ) = split /\t/, $error;
							&ScanLogEvent(  "Line $line_number: $formatted_cmd\n" );
						}
				}
				
			
			# Did the disinfect script move the file?
			return( "Disinfecting for $virus moved the file $file\n" ) if ( ! -f $file );

			# So the disinfect script ran OK, but it didn't move the file.  Maybe it is a pending rename,
			# maybe it disnfected it successfully with Marty's stuff
			return( "Disinfect ran OK on $file" ) if ( $ok );
			
			# So at this point it didn't disinfect it - so now I'll try to delete it
			# The best way to delete is by renaming it, and then deleting the renamed file
			my $renamed_file = $file . "_";
			
			my $renamed_ok = rename( $file, $renamed_file );
			
			$ok = undef;
			if ( $renamed_ok )
				{	$ok = unlink( $renamed_file );
				}
			else
				{	$ok = unlink( $file );
				}
			
			if ( $ok )
				{	$result = "Deleted infected file $file";
				}
			else
				{	$result = "Unable to delete infected file $file: $!";
					$result = "Renamed infected file to $renamed_file, but unable to delete: $!\n" if ( $renamed_ok );
				}
		}
	else
		{	$result = "Unknown action to take for virus or dangerous file: $action";
		}
		
		
	return( $result );	
}



################################################################################
#
sub ReportScanAppProcess( $$$$ )
#
#  Given a file ID and the full file path, save all the info to report back to 
#  my TTC server
#
################################################################################
{	my $file_id			= shift;
	my $scanfile		= shift;
	my $scan_ret		= shift;	# This is the return code from the virus scan
	my $virus_category	= shift;

	return( undef ) if ( ! defined $file_id );
	return( undef ) if ( ! defined $scanfile );
	$scan_ret = " " if ( ! defined $scan_ret );
	
	# Get what infomation I can out of the file itself
	my ( $app_name, $company, $description, $product_name ) = &GetFileInfo( $scanfile );
	return( undef ) if ( ! $app_name );

	my $hex_file_id = &StrToHex( $file_id );

	my $output_file = $working_dir . "\\ScanAppProcess.dat";
	
	if ( ! open( OUTPUT, ">>$output_file" ) )
		{	&ScanLogEvent( "Error opening file $output_file: $!\n" );
			return( undef );
		}
		
	# Default all the values that I can ...
	my $rec				= 0 + 0;			# Recommended bit
	my $dang			= 0 + 0;			# Dangerous bit
	my $current			= 0 + 0;			# CurrentVersion bit
	my $ports			= " ";
	my $opt_source_num	= 0 + 3;
	
	$app_name		= "" if ( ! defined $app_name );
	$company		= "" if ( ! defined $company );
	$description	= "" if ( ! defined $description );
	$product_name	= "" if ( ! defined $product_name );
	$virus_category	= "" if ( ! defined $virus_category );

	print OUTPUT "$hex_file_id\t$scanfile\t$app_name\t$company\t$description\t$rec\t$dang\t$current\t$ports\t$virus_category\t$opt_source_num\t$scan_ret\n"; 
	
	close OUTPUT;
	
	return( 1 );
}



################################################################################
#
sub ScanDirRecursive( $ )
#
#  Check a directory for viruses
#
################################################################################
{	my $dir_path = shift;


	# Should I ignore this directory?
	my $lc_path = lc( $dir_path );
	
	if ( &ScanableExcludedDir( $lc_path ) )
		{	&ScanLogEvent( "Scan excluded: $dir_path\n" ) if ( $opt_verbose );
			return;	
		}
		

	unless( -r $dir_path ) 
		{	&ScanLogEvent( "Permission denied at $dir_path\n" );
			return;
		}
	
	my $dir_handle;	
	if ( ! opendir( $dir_handle, $dir_path ) )
		{	&ScanLogEvent( "Error opening directory $dir_path: $!\n" ) if ( $opt_verbose );
			return;
		}
	
	
	# Am I restarting a scan?
	my $skip_files;
	if ( ( $opt_restart )  &&  ( $skip_directory ) )
		{	# If this isn't the skip to directory, then don't scan any files
			if ( lc( $skip_directory ) ne lc( $dir_path ) )
				{	$skip_files = 1;
					&ScanLogEvent( "Skipping scanning directory $dir_path ...\n" ) if ( $opt_verbose );
				}
			else	# If this is the skip to directory, then start scanning from here
				{	&ScanLogEvent( "Found $dir_path to start scanning\n" );
					$skip_directory = undef;
				}
		}
		
		
	&ScanLogEvent( "Scanning directory $dir_path\n" ) if ( ( $opt_verbose )  &&  ( ! $skip_files ) );
	
	while ( my $item = readdir( $dir_handle ) )
		{	( $item =~ /^\.+$/o ) and next;
			
			#$dir_path eq "/" and $dir_path = "";
			my $f;
			
			if ( $dir_path =~ m#\\+$# )
				{	$f = $dir_path . $item;
				}
			else
				{	$f = $dir_path . "\\" . $item;
				}
			

			# If the file is a directory, call recursively
			# If it is a ordinary file, scan it
			if ( -d $f )
				{	# Should I save a skip directory now?
					if ( $opt_restart )
						{	if ( ! defined $skip_directory )
								{	&SetSkipDirectory( $f );
									&SetVirusInfected();
								}
							else	# I must be restarting - so have I reach the directory to restart on?
								{	next if ( ! &ReachedSkipDirectory( $f, $skip_directory ) );
								}
						}
					# Write out the virus.log file periodically through the scan
					elsif ( $opt_report_file )
						{	&SetVirusInfected();
						}	

					&ScanDirRecursive( $f ) if ( ! $opt_subdir );
					next;
				}

			# Am I skipping scanning files because I am restarting after being interrupted?
			next if ( $skip_files );
			
			# Can this file be scanned?
			my $scanable = &Scanable( $f, $opt_content );

			my $ret;
			my $file_id;
			
			# Was there an error trying to find out if it is scanable?
			if ( ! defined $scanable )
				{	my $err = $!;
					$err = "Undefined" if ( ! $err );
					&ScanLogEvent( "Error opening $f: $err\n" );
					
					# Could this be the Downadup bastard?
					my $size = -s $f;
					my $downadup = 1 if ( ( $err =~ m/Permission denied/i )  &&  ( &Downadup( $size ) ) );

					( $ret, $file_id ) = &ScanFile( $f, 1, undef );
					$ret = "Downadup" if ( ( $downadup )  &&  ( ! $ret ) );
										
					next if ( ! $ret );
				}
			elsif ( ! $scanable )
				{	next if ( ! $factor );
					
					&CPUSleep();
					next;
				}
			
			# If doing a quick scan, only scan executable programs
			if ( ( ! $ret )  &&  ( $scanable != 1 )  &&  ( $opt_quick ) )
				{	next;
				}

			( $ret, $file_id ) = &ScanMessageFile( $f, $scanable ) if ( ! defined $ret );
			&ScanLogEvent( "$f is OK\n" ) if ( ( ! $ret )  &&  ( $opt_verbose ) );


			if ( $ret )
				{	if ( $ret =~ m/Unknown executable/i )
						{	push @unknown_files, $f;
							&ScanLogEvent( "$f is $ret\n" ) if ( $opt_verbose );
						}
					elsif ( $ret =~ m/Scan error/i )
						{	push @error_files, $f;
							push @error_files_ret, $ret;
							&ScanLogEvent( "$f is $ret\n" ) if ( $opt_verbose );
						}
					else
						{	&ScanLogEvent( "$f is $ret\n" );
							&ScanEventLogVirus( "File $f is $ret" );
							
							push @infected_files, $f;
							push @infection, $ret;
							push @infected_file_id, $file_id if ( defined $file_id );
							push @infected_file_id, "" if ( ! defined $file_id );
							
							if ( $opt_virus_archive )
								{	my ( $infected_file, $infected_virus, $infected_category ) = &ScanVirusContained();
									push @infected_contained, $infected_file if ( $infected_file );
								}
						}	
				}
		}
		
	closedir( $dir_handle );
	
	return;
}



################################################################################
# 
sub CPUSleep()
#
#	A time slice is available to sleep to slow down scanning - so sleep if necessary
#
################################################################################
{
	return if ( ! $factor );
	return if ( ! $sleep_event );
	
	if ( ! $t0 )
		{	# Prime the pump for the next go around
			$t0 = new Benchmark;
			return;
		}

	my $t1 = new Benchmark;
	my $td = timediff( $t1, $t0 );	
	
	# This CPU time is in seconds, the sleep time is in milliseconds
	my $cpu_time = $td->cpu_a;
	return if ( ! $cpu_time );
	
	my $sleep_time = $factor * $cpu_time;

	# If not enough time has elasped then return here
	return if ( $sleep_time < 2 );
	
	# Don't sleep for over 4 seconds at a time
	$sleep_time = ( 0 + 4000 ) if ( $sleep_time > ( 0 + 4000 ) );
		
	$sleep_event->wait( $sleep_time );
	$sleep_event->reset;
	
	# Prime the pump for the next go around
	$t0 = new Benchmark;
}



################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Return OK if the directory already exists
	return( 1 ) if ( -d $dir );
	
	my @parts = split /\\/, $dir;
	
	my $created_dir;
	foreach ( @parts )
		{	next if ( ! defined $_ );
			
			$created_dir .= "\\" . $_ if ( defined $created_dir );
			$created_dir = $_ if ( ! defined $created_dir );

			if ( ! -d $created_dir )
				{	mkdir( $created_dir );
				}
		}
		
	return( 1 );
}



################################################################################
#
sub ReachedSkipDirectory( $$ )
#
#  Given a directory, and the skip directory, have I reached it? 
#  Return True if I reached it, undef if not
#
################################################################################
{	my $dir			= shift;
	my $skip_dir	= shift;
	
	
	return( undef ) if ( ! defined $dir );
	return( 1 )		if ( ! defined $skip_dir );
	
		
	# If I have reached the skip directory then all the parts of dir should match as far as they go in skip dir
	my @dir			= split /\\/, $dir;
	my @skip_dir	= split /\\/, $skip_dir;
	
	my $match = 1;
	
	for (  my $i = 0 + 0;  $i <= $#dir;  $i++ )
		{	
			next if ( ( ! defined $dir[ $i ] )  &&  ( ! defined $skip_dir[ $i ] ) );
			
			if ( ! defined $dir[ $i ] )
				{	$match = undef;
					last;
				}
				
			if ( ! defined $skip_dir[ $i ] )
				{	$match = undef;
					last;
				}
			
			my $lc_dir = lc( $dir[ $i ] );
			my $lc_skip_dir = lc( $skip_dir[ $i ] );
			
			if ( $lc_dir ne $lc_skip_dir )
				{	$match = undef;
					last;
				}
		}

	
	if ( ( $opt_verbose )  &&  ( $match ) )
		{	# Have I reached the exact skip directory?
			if ( lc( $dir ) eq  lc( $skip_dir ) )
				{	&ScanLogEvent( "Reached the directory to restart scanning from: $skip_dir\n" );
				}
			else
				{	#  &ScanLogEvent( "Reached a parent directory of where to restart scanning from: $dir\n" );
				}
		}
		
		
	return( $match );
}



################################################################################
#
sub SetSkipDirectory( $ )
#
#  Save the directory to restart from 
#
################################################################################
{	my $skip_dir = shift;
	
	my $key;
	my $type;
	my $data;
	
	# Has enough time elasped to save a restarting directory?
	my $save_it = 1 if ( ! defined $skip_dir );
	
	$skip_directory_time = 0 + 0 if ( ! $skip_directory_time );
	my $elapsed = time - $skip_directory_time;
	
	# Has more than 5 seconds gone by?
	$save_it = 1 if ( $elapsed > ( 0 + 5 ) );
	
	return( undef ) if ( ! $save_it );
	
	# OK - I got to here, so set a stopping point
	my $access = &OueryOSRegistryAccess( KEY_WRITE );
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, $access, $key );

	return( undef ) if ( ! $ok );

	# Make sure that I am not being redirected under a 64 bit Windows OS
	&OueryOSWin64BitRegistry( $key );

	if ( ! defined $skip_dir )
		{	$ok = &RegDeleteValue( $key, "Skip Directory" );
			$skip_directory_time = undef;
		}
	else
		{	$ok = &RegSetValueEx( $key, "Skip Directory", 0,  REG_SZ, $skip_dir );
			
			# Save the time that I set this stopping point
			$skip_directory_time = time if ( $ok );
		}
		
	&RegCloseKey( $key );
		
	
	return( $ok );
}



################################################################################
#
sub SetVirusInfected()
#
#  Write the current virus infected files list to disk
#  Return the count of virus files and the count of archived files
#
################################################################################
{	
	my $virus_count		= 0 + 0;
	my $archive_count	= 0 + 0;
	
	return( $virus_count, $archive_count ) if ( $#infected_files < 0 );
	
	# Put any viruses infected file names into a special virus log so the update program can report it
	return( $virus_count, $archive_count ) if ( ! defined $virus_logfile );
	
	if ( ! open( VIRUS, ">>$virus_logfile" ) )
		{	my $err = $!;
			$err = "Unknown error" if ( ! defined $err );
			&ScanLogEvent(  "Error trying to open virus log file $virus_logfile: $err\n" );
			
			# Set the file name to undef so that I don't try doing this again
			$virus_logfile = undef;
			return( $virus_count, $archive_count );
		}
		
	for ( my $i = 0;  $infected_files[ $i ];  $i++ )
		{	my $result = "Report only";
			$result = &ScanVirusInfected( $infected_files[ $i ], $block_virus_action, $infection[ $i ] ) if ( $block_virus );
			$result = "Report only" if ( ! $result );
			print VIRUS "$infected_files[ $i ]: Infection: $infection[ $i ]: $result\n";
			
			if ( $opt_virus_archive )
				{	my $ret = &LightspeedVirusArchive( $infected_contained[ $i ], $infection[ $i ] );
					
					if ( $ret )
						{	$result = "Virus archived";
							$archive_count++;
						}
						
					# Delete the infected file (could be a zip archive or something containing the virus infected file)
					unlink( $infected_files[ $i ] );	
				}
						
			$virus_count++;
		}
				
	close( VIRUS );	
	
	# Now that I've done the virus action, and written what I've done to disk, clear out the array of viruses
	@infected_files = ();
	@infection = ();
	
	return( $virus_count, $archive_count );
}



################################################################################
#
sub GetSkipDirectory()
#
#  Get the directory to restart from 
#
################################################################################
{	my $key;
	my $type;
	my $data;
	
	my $access = &OueryOSRegistryAccess( KEY_READ );
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, $access, $key );

	return( undef ) if ( ! $ok );

	# Make sure that I am not being redirected under a 64 bit Windows OS
	&OueryOSWin64BitRegistry( $key );

	$ok = &RegQueryValueEx( $key, "Skip Directory", [], $type, $data, [] );
	
	my $skip_dir;
	my $len = length( $data );
	$skip_dir = $data if ( ( $ok )  &&  ( $len > 0 )  &&  ( defined $data ) );
		
	&RegCloseKey( $key );
	
	return( $skip_dir );
}



################################################################################
#
sub Downadup( $ )
#
#  Return True if the size is a possible Downadup virus
#
################################################################################
{	my $size = shift;
	
	return( undef ) if ( ! $size );
	
	$size = 0 + $size;
	
	# These are the file sizes from the Program database
	my @sizes = 
		( 56320,
		61320,
		62464,
		62976,
		63391,
		63488,
		86016,
		158003,
		159084,
		160603,
		161612,
		161712,
		162423,
		163032,
		164972,
		165840,
		166048,
		166555,
		173318 );

	foreach ( @sizes )
		{	my $downadup_size = $_;
			next if ( ! $downadup_size );
			$downadup_size = 0 + $downadup_size;
			
			return( 1 ) if ( $size == $downadup_size );			
		}
		
	return( undef );	
}



################################################################################
#
sub SoftwareUpdate( $$ )
#
#  Given the software version of the update.exe program - is there something I
#  need to do?
#
################################################################################
{	my $software_version	= shift;
	my $working_dir			= shift;
	
	return( undef ) if ( ! $software_version );
	
	return( undef ) if ( ! $working_dir );

	return( undef ) if ( ! -d $working_dir );

	my $new_update = "$working_dir\\Update.70102";
	my $old_update = "$working_dir\\Update.old";
	my $existing_update = "$working_dir\\Update.exe";
	
	# If the current Update.exe program is newer than 7.01.02 then I can just delete this update.70102
	if ( $software_version gt "7.01.02" )
		{	unlink( $new_update );
			return( undef );
		}
		
	# Is the version before 7.01.02?	
	return( undef ) if ( $software_version ne "7.01.02" );
	
	# At this point it looks like the active update program is version 7.01.02 - so
	# is there a replacement for it?
	return( undef ) if ( ! -f $new_update );
		
	# Is the existing Update.exe the right size?  It needs to match exactly
	my $size = -s $existing_update;
	return( undef ) if ( ! $size );
	return( undef ) if ( $size != 0 + 5027272 );
	
	
	# OK - this must be the version of Update.exe with the problem that I need to fix.
	&ScanLogEvent(  "Fixing up a problem with the 7.01.02 version of Update.exe ...\n" );
	
	if ( -f $existing_update )
		{	&ScanLogEvent(  "Renaming $existing_update to $old_update ...\n" );
			
			unlink( $old_update );
			my $ok = rename( $existing_update, $old_update );
			
			if ( ! $ok )
				{	my $err = $!;
					$err = "Unknown error" if ( ! $err );
					&ScanLogEvent(  "Error when renaming $existing_update to $old_update: $err\n" );
					
					return( undef );
				}
		}

	if ( -f $new_update )
		{	&ScanLogEvent(  "Renaming $new_update to $existing_update ...\n" );
			
			my $ok = rename( $new_update, $existing_update );
			
			if ( ! $ok )
				{	my $err = $!;
					$err = "Unknown error" if ( ! $err );
					&ScanLogEvent(  "Error when renaming $new_update to $existing_update: $err\n" );
					
					# Try to put things back if I had an error
					rename( $old_update, $existing_update );
					
					return( undef );
				}
				
			&ScanLogEvent(  "Installed the new version of Update.exe OK\n" );
		}
		

	return( 1 );
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
sub Version
#
################################################################################
{
    my $me = "Scan";

    print <<".";
scan $_version
.

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Scan";
	
    print <<".";

Usage: scan [Options] [list]

Scan a list of directories and/or files for viruses and vulnerabilities
Default is to scan the current directory and all subdirectories

Possible options are:

-a, --all                scan all local fixed drives
-b, --benchmark          report on the performance time of the scan
-c, --content            scan files based on content, ignoring file
                         extensions and file integrity
 --cloud                 Use the global cloud repository for replacing any
                         polymorphic virus infected files
-d                       disinfect virus infected files if possible,
                         even if policy is set to 'Report Only'
--disinfect OPTIONS      execute a disinfect script
                         See --disinfect --help for disinfecting options.
-f, --file  FILE         return the permissions of the given file
-3, --fileid             ignore the file ID database
-i, --integrity          do not do file integrity checks
-j, --job PERCENT        Maximum CPU job time percent, default is 50%
-k, --killspyware        automatically kill any spyware files
-l, --logfile VLOG       log all the discovered viruses to VLOG
-m, --mail               create the system status.zip, but don't mail it
-n, --nosubdir           don't scan subdirectories
-o, --network            scan all local fixed AND network drives
-p, --purge              mark unused entries in the file integrity database
-q, --quick              do a quick initial system scan
-r, --registry           scan the registry
-s, --scanlocal          remove all the locally discovered file IDs from the 
                         file integrity database.
-t, --tmp TMPDIR         tmp directory to use for unpacking files, default is:
                         $tmp_dir
-u, --unknown            add unknown files to the local file integrity list
-v, --verbose            display every file as it is scanned
-y, --yyy                quarantine viruses in Lightspeed archive format
-z, --zip                unpack and scan .cab, .msi, .rar, .bz, .gz, and .zip
-0, --app COMMENT        Send application info back to Lightspeed for analysis,
                         COMMENT is a description of the PC being analyzed
  
-h, --help               print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
