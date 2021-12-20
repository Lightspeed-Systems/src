################################################################################
#!perl -w
#
# QueueVirus - Keep a Mail-Virus machine processing along
#
################################################################################



# Pragmas
use strict;
use warnings;



use Errno qw(EAGAIN);
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use Cwd;
use Sys::Hostname;
use Win32::Process;
use Win32API::Registry 0.21 qw( :ALL );
use DBI qw(:sql_types);
use DBD::ODBC;



use Content::File;
use Content::Process;
use Content::Category;
use Content::FileIntegrity;
use Content::Mail;



# Options
my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_scan;				# If set, the just launch virus scanners using the scanlist file for the directories to scan
my $opt_email;				# If set then this QueueVirus just monitors the changes in the database, and emails updates
my $opt_incoming;			# This is the ';' separated list of directories to monitor
my $opt_verbose;			# True if verbose mode
my $opt_minutes = 0 + 20;	# The number of minutes to wait before the parent process gives up
my $opt_move;				# If True then just move any old shared directories to the backup


my $hostname = "hostname";
my $analysis_email_addresses = "rob\@lightspeedsystems.com,steve\@lightspeedsystems.com,christian\@lightspeedsystems.com,robjones\@lightspeedsystems.com";
my $further_analysis = "further analysis";					# This is the phrase that I use when a file need further analysis by Lightspeed
my $monitor_server = "monitor.lightspeedsystems.com";		# This is the TTC server at Lightspeed to flip email alerts to
my $event_name = "QueueVirus";
my $log_filename;

my $dbhProgram;				# Handle to the Program database



# Directories used by QueueVirus
my $program_source				= "F:\\Content\\bin";
my $program_dest				= "C:\\Content\\bin";
my $log_directory				= "Q:\\Virus Logs";
my $check_root					= "Q:\\Virus Check";		# This is the root directory to put all virus check results into
my $virus_errors				= "Q:\\Virus Errors";		# Used to keep the files I had errors processing
my $cwd;													# The current working directory


# This is the list of directories to watch for incoming viruses
my @incoming_virus_dir;										# Normally directories	"V:\\Virus" or "I:\\VirusUploads"


my @monitor_dir = (											# This is the list of directories that I should monitor to see if I need to wake up
				   "V:\\Virus",
				   "I:\\VirusUploads"
				  );


my $shared_dir					= "Q:\\VirusShared";
my $shared_dir_backup			= "Q:\\VirusSharedBackup";
my $scan_list					= "Q:\\VirusShared\\ScanList.txt";


my @programs = (	"VirusProcess.exe",
					"scan.exe",
					"VLogCopy.exe",
					"CheckFile.exe",
					"IpmRealtimeSpam.exe",
					"update.exe"
			   );



my @email_alert = ( "rob\@lightspeedsystems.com",
					"robjones\@lightspeedsystems.com"
				  );		# If set - this is the list of email addresses to send alerts to



my @log_files = (
"IpmRealtimeSpam.log",
"IpmRealtimeSpamErrors.log",
"IpmCategorizeErrors.log",
"Conclusions.txt",
"salist.log",
"kasplist.log",
"clamlist.log",
"VirusProcess.log",
"VirusProcessErrors.log",
"CheckFile.log",
"CheckFileErrors.log"
);


my $_version = "1.0.0";



################################################################################
#
MAIN:
#
################################################################################
{	

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (	"e|email"		=>	\$opt_email,	
		"i|incoming=s"	=>	\$opt_incoming,
		"m|move"		=>	\$opt_move,
		"s|scan"		=>	\$opt_scan,
        "v|verbose"		=>	\$opt_verbose,
        "h|help"		=>	\$opt_help,
		"x|xxx"			=>	\$opt_debug
    );


    &StdHeader( "QueueVirus" );


    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	# Make sure that the right combination of options is done
	# Only one of these three options should be set - but one must be set
	&Usage() if ( ( $opt_email )  &&  ( $opt_incoming ) );
	&Usage() if ( ( $opt_email )  &&  ( $opt_scan ) );
	&Usage() if ( ( $opt_scan )  &&  ( $opt_incoming ) );
	&Usage() if ( ( ! $opt_email )  &&  ( ! $opt_incoming )   &&  ( ! $opt_scan )  &&  ( ! $opt_move ) );
	
	
	# Figure out the hostname
	$hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );


	$cwd = getcwd();
	$cwd =~ s#\/#\\#gm;



	$log_filename = "$log_directory\\QueueVirus-$hostname.log";		# The name of the log file to use
	&CheckLogFile();
	
	&SetLogFilename( $log_filename, 1 );


	&TrapErrors() if ( ! $opt_debug );


	# Map drive Q: if it isn't already mapped
	if ( ! -d $check_root )
		{	lprint "Mapping drive Q: to \\\\fs06\\Drive-Q ...\n";
			system "net use Q: \\\\fs06\\Drive-Q /USER:LIGHTSPEED\\Rob seeker";
		}


	if ( ! -d $check_root )
		{	lprint "Unable to find the virus check results directory $check_root\n";
			&BadError( "Unable to find the virus check results directory $check_root" );
			&StdFooter();

			exit( 1 );
		}
		
	
	if ( ! -d $virus_errors )
		{	lprint "Unable to find the virus errors directory $virus_errors\n";
			&BadError( "Unable to find the virus errors directory $virus_errors" );
			&StdFooter();

			exit( 1 );
		}
		
	
	if ( ! -d $log_directory )
		{	lprint "Unable to find the log directory $log_directory\n";
			&BadError( "Unable to find the log directory $log_directory" );
			&StdFooter();
			
			exit( 1 );
		}
		
	
	if ( ! -d $shared_dir )
		{	lprint "Can not find the shared directory $shared_dir\n";
			&BadError( "Can not find the shared directory $shared_dir" );			
			&StdFooter();
			
			exit( 1 );
		}
	
	
	if ( ! -d $shared_dir_backup )
		{	lprint "Can not find the shared backup directory $shared_dir_backup\n";
			&BadError( "Can not find the shared backup directory $shared_dir_backup" );			
			&StdFooter();
			
			exit( 1 );
		}
	
	
	if ( $opt_move )
		{	&MoveShared( $shared_dir, $shared_dir_backup );
			exit( 0 );	
		}
		
		
	# If not processing emails, and not just scanning, then I am monitoring incoming directories
	# so I better make sure that I can find those directories
	if ( ( ! $opt_scan )  &&  ( ! $opt_email ) )	
		{	# Build the list of incoming directories
			@incoming_virus_dir = split /;/, $opt_incoming if ( defined $opt_incoming );


			# Did I get any directories at all?
			if ( $#incoming_virus_dir < 0 )
				{	lprint "No incoming virus directories specified to monitor\n";
								
					# Close any databases that I opened
					$dbhProgram->disconnect if ( $dbhProgram );
					$dbhProgram = undef;
					
					&BadError( "No incoming virus directories specified to monitor" );

					&StdFooter();
					
					exit( 1 );
				}
			
			
			# Make sure that I can find the directories
			foreach ( @incoming_virus_dir )
				{	my $incoming_virus_dir = $_;
					next if ( ! defined $incoming_virus_dir );
					
					if ( ! -d $incoming_virus_dir )
						{	lprint "Can not find the incoming virus directory $incoming_virus_dir\n";
								
							# Close any databases that I opened
							$dbhProgram->disconnect if ( $dbhProgram );
							$dbhProgram = undef;
							
							&BadError( "Can not find the incoming virus directory $incoming_virus_dir" );
							
							&StdFooter();
							
							exit( 1 );
						}
						
					lprint "Watching for new viruses to be analyzed in directory $incoming_virus_dir\n";	
				}
		}
		
		
	# Make sure all the required directories exist
	&CheckDirectories();

	
	lprint "Do scan processing on $hostname only ...\n" if ( $opt_scan );
	lprint "Doing virus processing on directory $opt_incoming ...\n" if ( $opt_incoming );
	lprint "Doing email processing ...\n" if ( $opt_email );
	
	
	# Get rid of the existing scan list if restarting the virus processing
	unlink( $scan_list ) if ( $opt_incoming );
	
	
	my $done;
	my $no_work = 0 + 0;
	
	
	# Get a unique name to use for an event for signalling between the parent and child process
	my $my_pid = &ProcessGetCurrentProcessId();
	$event_name .= "-PID$my_pid";
	
	
	#  Now fork off a child process
	my $pid;
	
	FORK:
		{
			if ( $pid = fork )
				{	&lprint( "Started child process pid $pid\n" ) if ( $opt_verbose ); 
					sleep 10;  # Sleep for 10 seconds to give the child time to get started 
				}

			elsif ( defined $pid )
				{	&lprint( "Child process started\n" );
					goto CONTINUE;
				}

			elsif ( $! == EAGAIN )
				{	sleep 15;
					redo FORK;
				}

			else
				{	&BadError( "Can't fork: $!\n");
				}

		}  # end of FORK


	CONTINUE:


	# From the parent process shoot off an email saying that everything is OK now
	if ( $pid )
		{	&lprint( "Shooting off an email saying that everything is OK now ...\n" );

			my $ret = &EmailLogFile( "QueueVirusEmail.txt", "QueueVirus Startup", "No error message", $log_filename );
			sleep( 2 );	# Give the mail message a little time

		}
		
		
	# The parent process should have the pid defined
	if ( $pid )
		{	&lprint( "Parent process is watching child process pid $pid ...\n" ) if ( $opt_verbose );
			
			my $event = Win32::Event->new( 1, 1, $event_name );
			$event->set;
			
			my $no_change = 0 + 0;
			while ( 1 )
				{	&lprint( "Top of parent loop\n" ) if ( $opt_verbose );
					
					# Handle the outgoing process event - this waits for 60 seconds
					my $ret = $event->wait( 60 * 1000 );
					$event->reset;
					
					if ( ( ! $ret )  ||  ( $ret == -1 ) )
						{	$no_change++;
							&lprint( "Child process has not responded for $no_change minutes\n" ) if ( $no_change > 1 );	

							last if ( $no_change >= $opt_minutes );
						}
					else
						{	&lprint( "Child process is alive\n" ) if ( $opt_verbose );
							print "Child process is alive\n" if ( ! $opt_verbose );
							
							$no_change = 0 + 0;
						}
						
					# Has the QueueVirus program changed?	
					if ( &QueueVirusChanged( undef ) )	
						{	&BadError( "The QueueVirus.exe program has changed so restarting ...\n" );	

							lprint "Ending the parent process ...\n";
							last;
						}
				}
			

			if ( $no_change >= $opt_minutes )
				{	&BadError( "At least $no_change minutes has gone by without the child QueueVirus responding\n" );	
					&lprint( "Killing the child process ...\n" );
					kill( -15, $pid );
				}
				
			&lprint( "Waiting for the child process to quit ...\n" );
			wait;
				
			lprint "\nDone\n";
			exit( 0 );
		}
		
	
		
	# This is where the child process starts doing work ...	
	sleep( 20 );  # Wait for the parent process to get going
	&lprint( "Child process has started ...\n" );

	
	# Make sure that I can connect to the Program database if I'm not just scanning
	if ( ! $opt_scan )
		{	$dbhProgram = &ConnectRemoteProgram();
			
			if ( ! $dbhProgram )
				{
lprint "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";
					&BadError( "Unable to open the Remote Program database." );
					&StdFooter();
					exit( 0 + 6 );
				}
		}

	&lprint( "Child process is waiting 30 seconds before beginning to loop ...\n" );
	sleep( 30 );  # Wait for the parent process to get going
	
	# Loop around doing whatever kind of process that I'm supposed to do
	while ( ! $done )
		{	my $loopevent = Win32::Event->open( $event_name );
			if ( ! $loopevent )
				{	&BadError( "Parent process has disappeared - exiting now\n" );
					$done = 1;
					last;
				}
								
			# Signal the inevent
			$loopevent->set if ( $loopevent );

			
			# Has the QueueVirus program changed?	
			if ( &QueueVirusChanged( undef ) )	
				{	lprint "Ending the child process ...\n";
					$done = 1;
					last;
				}
				
			# Check to make sure that the other programs are still the same
			$done = 1 if ( &ProgramsCheck() );


			if ( ( ! $opt_scan )  &&  ( ( ! $dbhProgram )  ||  ( $dbhProgram->err ) ) )
				{	my $err = $dbhProgram->errstr if ( $dbhProgram );
					$err = "Undefined handle" if ( ! defined $dbhProgram );
					
					lprint "Error with the Program database handle: $err\n";
					&BadError( "Error with the Program database handle: $err\n" );
					$done = 1;
					last;
				}
				
			my $work = 0 + 0;
			

			# Do one of the 3 different types of processing
			if ( $done )
				{	# Do nothing
				}
			elsif ( $opt_email )
				{	$work = 1 if ( &EmailProcessLoop() );
				}
			elsif ( $opt_scan )
				{	$work = 1 if ( &ScanProcessLoop( $cwd ) );
									
					# If the waiting flag file has stuff in it then I need to do some work
					$work = 1 if ( -s "$log_directory\\waiting.log" );
				}
			else
				{	# Check all the incoming virus directories
					foreach ( @incoming_virus_dir )
						{	my $incoming_virus_dir = $_;
							next if ( ! defined $incoming_virus_dir );
							next if ( ! -d $incoming_virus_dir );

							$work = 1 if ( &VirusProcessLoop( $incoming_virus_dir, $cwd ) );

							# Get rid of the waiting flag file if I have returned back to here
							unlink( "$log_directory\\waiting.log" );
						}
						
					# If there isn't any work done - are there old shared directories I can move?	
					if ( ! $work )
						{	&MoveShared( $shared_dir, $shared_dir_backup );
						}
				}

				
			chdir( $cwd );
			
			$no_work = 0 + 0 if ( $work );
			
			next if ( $work );
			
			lprint "Waiting for events ...\n";
			
			
			# If nothing has been going on then wait for a longer and longer period ...
			$no_work++;
			$no_work = 10 if ( $no_work > 10 );
			
			&CheckLogFile();
			
			
			my $inner_loop = 0 + 0;
			
			my $loop_done;
			
			# Watch over the active directories to see if I need to wake up and do something
			while ( ( ! $done )  &&  ( ! $loop_done )  &&  ( $inner_loop < $no_work ) )
				{	my @dir = @incoming_virus_dir;
					@dir = @monitor_dir if ( $opt_scan );
					
					my $loopevent = Win32::Event->open( $event_name );
					if ( ! $loopevent )
						{	&BadError( "Parent process has disappeared - exiting now\n" );
							$done = 1;
							last;
						}
						
					# Signal the inevent
					$loopevent->set if ( $loopevent );

					foreach ( @dir )
						{	my $dir = $_;
							next if ( ! defined $dir );
							next if ( ! -d $dir );
							
							$loop_done = 1 if ( &DirectoryActive( $dir ) );
							$loop_done = 1 if ( -s "$log_directory\\waiting.log" );
							
							last if ( $loop_done );	
						}
						
					last if ( $loop_done );
					
					sleep( 10 );
					$inner_loop++;
				}
		}
		

	# Close any databases that I opened
	$dbhProgram->disconnect if ( $dbhProgram );
	$dbhProgram = undef;


	lprint "Ending child process ...\n";
	
	&StdFooter();
	
    exit( 0 );
}



my %last_directory_count;
my %last_directory_filelist;
my %last_mtime;
my %last_size;
################################################################################
#
sub DirectoryActive( $ )
#
#  Return True if the directory is active - i.e. something new has been put in it
#
################################################################################
{	my $incoming_dir = shift;
	
	
	return( undef ) if ( ! defined $incoming_dir );
	return( undef ) if ( ! -d $incoming_dir );
	
	
	# Is the waiting flag file created?
	return( 1 ) if ( -s "$log_directory\\waiting.log" );
	
	
	# Did the scan_list change?
	my $changed;
	if ( -s $scan_list )
		{	# Are the date/times different in the scan list file since the last time I looped?
			my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $scan_list;	
			$mtime	= 0 + $mtime;
			$size	= 0 + $size;
			
			# Has anything changed?
			my $last_mtime = $last_mtime{ $incoming_dir };
			my $last_size = $last_size{ $incoming_dir };
			
			if ( ( $last_mtime )  &&  ( $last_size ) )
				{	$changed = 1 if ( ( $mtime != $last_mtime )  &&  ( $size != $last_size ) );
				}
			else
				{	$changed = 1;
				}
				
			$last_mtime{ $incoming_dir } = $mtime;
			$last_size{ $incoming_dir }	= $size;
		}
	else
		{	# Has anything changed?
			my $last_mtime = $last_mtime{ $incoming_dir };
			my $last_size = $last_size{ $incoming_dir };

			# Did the scan list file exist before and now it's gone?
			$changed = 1 if ( ( $last_mtime )  &&  ( $last_size ) );
			
			delete $last_mtime{ $incoming_dir };
			delete $last_size{ $incoming_dir };
		}


	# I can quit here if I've figured out that something has changed	
	return( $changed ) if ( $changed );
	
		
	# Did stuff in the directory change?  More files, or a different last file?
	my $virusdir;
	if ( ! opendir( $virusdir, $incoming_dir ) )
		{	lprint "Error opening directory $incoming_dir: $!\n" ;
			return( undef );
		}


	my $counter = 0 + 0;
	my $filelist;
	while ( my $file = readdir( $virusdir ) )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			$filelist .= "$incoming_dir\\$file" if ( defined $filelist );
			$filelist = "$incoming_dir\\$file" if ( ! defined $filelist );
			
			$counter++;
		}
	
	closedir( $virusdir );	


	# Compare what I have now to when I last checked this for this particular directory
	my $last_directory_count	= $last_directory_count{ $incoming_dir };
	my $last_directory_filelist	= $last_directory_filelist{ $incoming_dir };

	
	# Did the number of files in the directory change?
	$changed = 1 if ( ( $counter )  &&  ( ! $last_directory_count ) );
	$changed = 1 if ( ( ! $counter )  &&  ( $last_directory_count ) );
	$changed = 1 if ( ( $counter )  &&  ( $last_directory_count )  &&  ( $counter != $last_directory_count ) );

	
	# Did the last entry in the directory change?
	$changed = 1 if ( ( $filelist )  &&  ( ! $last_directory_filelist ) );
	$changed = 1 if ( ( ! $filelist )  &&  ( $last_directory_filelist ) );
	$changed = 1 if ( ( $filelist )  &&  ( $last_directory_filelist )  &&  ( $filelist ne $last_directory_filelist ) );

	
	# Keep track of what I found for the the next loop through
	$last_directory_count{ $incoming_dir }		= $counter;
	$last_directory_filelist{ $incoming_dir }	= $filelist;


	return( $changed );
}



my $scan_last_directory;
my $scan_last_mtime;
my $scan_last_size;
################################################################################
#
sub ScanProcessLoop( $ )
#
#  Read the scanlist for for the list of directories to scan, and then launch a
#  scanner with the VirusScanList batch file ...
#
#  Return True if I did some work, or undef if I didn't do anything
#
################################################################################
{	my $cwd = shift;
	

	# Does the scan list file even exist?
	if ( ! -f $scan_list )
		{	$scan_last_mtime		= undef;
			$scan_last_size			= undef;
			$scan_last_directory	= undef;
			
			return( undef );
		}
		
	if ( ! -s $scan_list )
		{	$scan_last_mtime		= undef;
			$scan_last_size			= undef;
			$scan_last_directory	= undef;
			
			return( undef );
		}
		
	
	# Are the date/times different in the scan list file since the last time I looped?
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $scan_list;	
	$mtime = 0 + $mtime;
	$size = 0 + $size;
	
	# Has anything changed?
	return( undef ) if ( ( $scan_last_mtime )  &&  ( $scan_last_size )  &&  ( $mtime == $scan_last_mtime )  &&  ( $size == $scan_last_size ) );
	
	
	return( undef ) if ( ! open( SCANLIST, "<$scan_list" ) );
	
	my $directory;
	my $counter = 0 + 0;
	my $skipped++;
	my $found_last_directory;
	
	while ( my $line = <SCANLIST> )
		{	my $loopevent = Win32::Event->open( $event_name );
			if ( ! $loopevent )
				{	&BadError( "Parent process has disappeared - exiting now\n" );
					last;
				}
				
			# Signal the inevent		
			$loopevent->set if ( $loopevent );
			
			chomp( $line );
			next if ( ! $line );

			# Is this the last directory that I ran?
			if ( ( $scan_last_directory )  &&  ( $scan_last_directory eq $line ) )
				{	$found_last_directory = 1;
					next;
				}
			
			
			# Am I still trying to skip to the last directory that I ran?
			if ( ( $scan_last_directory )  &&  ( ! $found_last_directory ) )
				{	$skipped++;
					next;
				}
			
			
			# Does the directory exist?
			next if ( ! -d $line );
			
			$directory = $line;
			
			lprint "ScanList directory $counter: $directory\n";
			my $cmd = "VirusScanList \"$directory\"";
			lprint "System command: $cmd\n";
			
			system $cmd;
			
			$counter++;
		}
		
	close( SCANLIST );
	
	
	# Did I find the last directory?
	# If not then this is a whole new file - and so I need to read it from line 1
	if ( ( $scan_last_directory )  &&  ( ! $found_last_directory ) )
		{	$scan_last_mtime		= undef;
			$scan_last_size			= undef;
			$scan_last_directory	= undef;
			
			return( $skipped );
		}
	
	
	# Did I process a directory?
	# If so then keep track
	$scan_last_mtime		= $mtime;
	$scan_last_size			= $size;
	$scan_last_directory	= $directory if ( defined $directory );

		
	return( $counter );
}



################################################################################
#
sub VirusProcessLoop( $$ )
#
#  Read through the incoming virus directories and set it up for VirusProcess.exe
#  to run
#
################################################################################
{	my $incoming_dir	= shift;
	my $cwd				= shift;

	
	return( undef ) if ( ! defined $incoming_dir );
	return( undef ) if ( ! -d $incoming_dir );
	
	return( undef ) if ( ! defined $cwd );
	return( undef ) if ( ! -d $cwd );


	lprint "Checking directory $incoming_dir ...\n";
	
	my $virusdir;
	if ( ! opendir( $virusdir, $incoming_dir ) )
		{	lprint "Error opening directory $incoming_dir: $!\n" ;
			return( undef );
		}
		
	my $counter = 0 + 0;
	while ( my $file = readdir( $virusdir ) )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );


			my $loopevent = Win32::Event->open( $event_name );
			if ( ! $loopevent )
				{	&BadError( "Parent process has disappeared - exiting now\n" );
					last;
				}
				
			# Signal the inevent		
			$loopevent->set if ( $loopevent );
			
			
			my $fullfile = "$incoming_dir\\$file";

			lprint "Virus processing $fullfile ...\n";
			
			$counter++;
			
			# Is this a subdirectory?
			if ( -d $fullfile )
				{	lprint "Virus processing subdir $fullfile ...\n";
					
					my $subcounter = &VirusProcessLoop( $fullfile, $cwd );
					$counter += $subcounter if ( defined $subcounter );

					# Can I remove the subdirectory?
					rmdir( $fullfile ) if ( ( defined $subcounter )  &&  ( $subcounter == 0 ) );
					next;	
				}
			
			
			# Ignore empty files			
			if ( ! -s $fullfile )
				{	unlink( $fullfile );	# Delete it if I can
					next;
				}


			# Ignore any log file
			my $log_file;
			foreach ( @log_files )
				{	my $l_file = $_;
					next if ( ! defined $l_file );
					
					my $ql_file = quotemeta( $l_file );
					
					$log_file = 1 if ( $file =~ m/^$ql_file$/i );
				}
				
			if ( $log_file )
				{	unlink( $fullfile );	# Delete it if I can
					next;
				}
			
			
			# Can I figure out a file ID?
			my $file_id = &ApplicationFileID( $fullfile );
			my $hex_file_id;
			if ( ! $file_id )
				{	lprint "Unable to calculate a file ID for $fullfile\n";	
					unlink( $fullfile );	# Delete it if I can
					next;
				}			
			else
				{	$hex_file_id = &StrToHex( $file_id );
				}
				

			# First - figure what what email address sent this
			if ( ! open( FILE, "<$fullfile" ) )
				{   &lprint( "Error opening file $fullfile: $!\n" );
					&VirusErrors( $fullfile );  
					next;
				}

			lprint "Looking for the FROM: email address in $fullfile ...\n";
			
			my $header_email_from;
			my $first_line = 1;
			my $email_from;
			my $envelope_email_to;
			my $external_ip_address;
			
			my $line_counter = 0 + 0;
			while ( my $line = <FILE> )
				{	chomp( $line );
					next if ( ! $line );
					
					$line_counter++;
					
					# Give up if it has taken more that 50 lines
					last if ( $line_counter > 50 );
					
					my $no_comments = lc( $line );
						
					if ( ( $first_line )  &&  ( $line =~ m/^\(externalipaddress/i ) )
						{   $first_line = undef;

							my $comment = $line;
							
							# Read additional lines until I get the trailing )
							while ( ( $line )  &&  ( ! ( $line =~ m/\)/ ) ) )
								{	$line = <FILE>;
									chomp( $line );
									
									# Get rid of leading whitespace
									$line =~ s/^\s+// if ( $line );

									# Get rid of trailing whitespace
									$line =~ s/\s+$// if ( $line );
									
									$comment .= "," . $line if ( $line );
								}

							$comment =~ s/\(//;
							$comment =~ s/\)//;
		
							my @parts = split /\s/, $comment;
							my $part_no = 0;
							foreach ( @parts )
								{  $part_no++;
									my $keyword = lc( $_ );
									#  Check for a blank value
									next if ( !$parts[ $part_no ] );
									next if ( index( "emailfrom:emailto:externalipaddress:", lc( $parts[ $part_no ] ) ) != -1 );
									
									if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
									if ( $keyword eq "emailto:" )            {  $envelope_email_to = lc ( $parts[ $part_no ] );  }
									if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
								}

							next;
						}  # end of first line processing
						
						
					#  Consume any comments in the header - to avoid being deceived
					#  Do this to the lc variable, to preserver () in other cases
					if ( $no_comments =~ m/\(.*\)/ )
						{  $no_comments =~ s/\(.*\)//;
							$no_comments = "\(\)" if ( !$no_comments );  # if nothing left, pad it to be a blank comment
						}

					#  Am I a setting the header email from?
					if ( $no_comments =~ m/^from:/ )
						{   my $stuff = $line;
							
							$stuff =~ s/^from://i;
							
							$header_email_from = $stuff;
							$header_email_from =~ s/^\s//g;
							$header_email_from =~ s/\s$//g;
							
							#  Grab anything inside < > as the email address if <> exists
							$header_email_from = $1 if ( $stuff =~ m/\<(.*?)\>/ );

							$header_email_from = &CleanEmail( $header_email_from );
							last if ( $header_email_from );
						}
				}
				
			close( FILE );


			$header_email_from = "unknown" if ( ! defined $header_email_from );
			
			lprint( "Email message from: $header_email_from\n" );
			lprint( "Envelope message from: $email_from\n" ) if ( defined $email_from );
			
			
			# If the email is from virus@lightspeedsystems.com I can ignore it
			if ( ( $email_from )  &&  ( $email_from eq "virus\@lightspeedsystems.com" ) )
				{	lprint( "Ignoring email messages from: $email_from\n" );
					unlink( $fullfile );
					next;
				}
			
				
			my $virus_subdir = "$shared_dir\\$header_email_from";
			my $ok = &MakeDirectory( $virus_subdir );
			if ( ! $ok )
				{	&VirusErrors( $fullfile );
					next;
				}
			
			# Use a timestamp as the subdirectory
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
			$year = 1900 + $year;
			$mon = $mon + 1;
			my $timestamp_dir = sprintf( "%04d%02d%02d-%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );

			$virus_subdir = "$shared_dir\\$header_email_from\\$timestamp_dir";
			$ok = &MakeDirectory( $virus_subdir );
			if ( ! $ok )
				{	&VirusErrors( $fullfile );
					next;
				}
			
			
			# Copy the original file into the new directory
			my ( $dir, $shortfile ) = &SplitFileName( $fullfile );

			my $new_filename = "$virus_subdir\\$shortfile";
			
			unlink( $new_filename ) if ( -f $new_filename );
			$ok = copy( $fullfile, $new_filename );
			if ( ! $ok )
				{	&lprint( "Error copying $fullfile to $new_filename: $!\n" );
					&VirusErrors( $fullfile );
					next;
				}
				
			lprint( "Copied file to $new_filename ...\n" );


			# Update any rows in the CheckFile table with this filename with the correct file ID
			my $qfullfile = $fullfile;
			$qfullfile =~ s/'/''/g;
			
			if ( $hex_file_id )
				{	my $sth = $dbhProgram->prepare( "UPDATE CheckFile SET FileID = '$hex_file_id' WHERE TempFile = '$qfullfile'" );
					$sth->execute();
					$sth->finish();
				}
				
				
			# Change to the virus subdirectory and run VirusProcess.exe
			chdir( $virus_subdir );
			$ok = &LaunchVirusProcess( $virus_subdir, $new_filename );			
			
			if ( ! $ok )
				{	&VirusErrors( $fullfile );
					next;
				}


			# OK - add the directory to the scan list to start the other Mail-Virus?? machines scanning
			if ( ! open( SCANLIST, ">>$scan_list" ) )
				{	lprint "Error opening scanlist file $scan_list: $!\n";
				}
			else	
				{	print SCANLIST "$virus_subdir\n";
			
					close( SCANLIST );
					
					lprint "Added $virus_subdir to the scan list\n";
				}
				

			# I should flag the other virus scanners to start
			lprint "Creating the flag file $log_directory\\waiting.log to signal the other virus scanners ...\n";
			
			( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
			$year = 1900 + $year;
			$mon = $mon + 1;
			my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );

			open( WAIT, ">>$log_directory\\waiting.log" );
			print WAIT "$datestr : HOST $hostname - Directory $virus_subdir\n";
			close( WAIT );
		

			chdir( $cwd );
			
			
			# Get rid of the original file now that I've fully processed it
			lprint "Deleting the original file $fullfile ...\n";
			unlink( $fullfile );
		}
		
	closedir( $virusdir );
	
	print "Processed $counter virus email messages\n" if ( $counter );
	
	return( $counter );
}



################################################################################
# 
sub VirusErrors( $ )
#
#  I had some sort of problem processing a file, so copy it into a errors
#  directory and delete the original file
#  does exist
#
################################################################################
{	my $fullfile = shift;

	return( undef ) if ( ! -f $fullfile );

	lprint "Giving up on processing $fullfile so copying into $virus_errors ...\n";
	
	my ( $dir, $shortfile ) = &SplitFileName( $fullfile );
	
	my $errors_filename = "$virus_errors\\$shortfile";
	
	# If the target exists then delete it
	unlink( $errors_filename ) if ( -f $errors_filename );
	
	my $ok = copy( $fullfile, $errors_filename );
	if ( ! $ok )
		{	&lprint( "Error copying $fullfile to $errors_filename: $!\n" );
			return( undef );
		}

	lprint "Deleting the original file $fullfile ...\n";
	$ok = unlink( $fullfile );
	
	if ( ! $ok )
		{	lprint "Error deleting $fullfile: $!\n";
		}
		
	return( $ok );
}
				
				

################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $filename = "$log_directory\\QueueVirusErrors-$hostname.log";
	
	my $MYLOG;
   
	# If the error log is getting really big then delete it
	my $size = -s $filename;
	unlink( $filename ) if ( ( $size )  &&  ( $size > 1000000 ) );

	if ( ! open( $MYLOG, ">>$filename" ) )
		{	&lprint( "Unable to open $filename: $!\n" );  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	&lprint( "Error trapping set to file $filename\n" ); 
}



################################################################################
# 
sub CheckDirectories()
#
#  Check to see that all the required directories still exist
#  Do a fatal error if they don't exist.  Return undef if everything
#  does exist
#
################################################################################
{

	&MakeDirectory( $program_dest ) if ( ! -d $program_dest );

	if ( ! -d $program_dest )
		{	&BadError( "Can not find program destination directory $program_dest\n" );
		}

	if ( ! -d $program_source )
		{	&BadError( "Can not find program source directory $program_source\n" );
		}

	if ( ! -d $check_root )
		{	&BadError( "Can not find the Check File directory $check_root\n" );
		}
		
	if ( ! -d $virus_errors )
		{	&BadError( "Can not find the Virus Errors directory $virus_errors\n" );
		}



	return( undef );
}



my $program_check_next_time;
################################################################################
# 
sub ProgramsCheck()
#
#  Copy any programs that have changed.  Return True if the QueueVirus program
#  has changed
#
################################################################################
{
	
	if ( $program_check_next_time )
		{  return if ( time() < $program_check_next_time );  #  Wait a while to do this processing if I have run before
		}

	$program_check_next_time = ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so

	
	lprint "Checking to see if any programs have been updated ...\n";
	
	foreach ( @programs )
		{	next if ( ! $_ );
			
			my $file = $_;
			
			my $prog_src	= $program_source . "\\$file";
			my $prog_dest	= $program_dest . "\\$file";
			
			next if ( ! -f $prog_src );
			
			lprint "Checking to see if $prog_src has been updated ...\n";
			
			my $size_src	= -s $prog_src;
			my $size_dest	= -s $prog_dest;
			
			next if ( ! $size_src );

			my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_src;	
			$mtime = 0 if ( ! $mtime );
			my $from_mtime = 0 + $mtime;

			( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_dest;
			$mtime = 0 if ( ! $mtime );
			my $to_mtime = 0 + $mtime;

			next if ( $to_mtime > $from_mtime );
			
			my $changed = 1 if ( $size_src != $size_dest );
			$changed = 1 if ( $from_mtime != $to_mtime );
				
			if ( $changed )
				{	lprint "$prog_src has changed\n";
					my $cmd = "c:\\content\\bin\\changedcopy.exe \"$prog_src\" \"$prog_dest\"";
					lprint "QueueVirus: Program copy command: $cmd\n";
					system $cmd;
				}
		}
				
	return( undef );
}



my $queuevirus_check_next_time;
################################################################################
# 
sub QueueVirusChanged( $ )
#
#	Return TRUE if the QueueVirus.exe program has changed
#
################################################################################
{	my $force_now = shift;
	
	if ( ( ! $force_now )  &&  ( $queuevirus_check_next_time ) )
		{  return if ( time() < $queuevirus_check_next_time );  #  Wait a while to do this processing if I have run before
		}

	$queuevirus_check_next_time = ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so
	
	# Check to see if the QueueVirus program itself has changed
	my $prog_src	= $program_source . "\\QueueVirus.exe";
	my $prog_dest	= $program_dest . "\\QueueVirus.exe";
	
	# If the source doesn't exist, then don't worry about it
	return( undef ) if ( ! -f $prog_src );
	
	
	lprint "Checking to see if $prog_src has been updated ...\n";

	my $size_src	= -s $prog_src;
	my $size_dest	= -s $prog_dest;

	return( 1 ) if ( ! $size_dest );


	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_src;	
	$mtime = 0 if ( ! $mtime );
	my $from_mtime = 0 + $mtime;

	( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_dest;
	$mtime = 0 if ( ! $mtime );
	my $to_mtime = 0 + $mtime;

	return( undef ) if ( $to_mtime > $from_mtime );
	
	my $changed = 1 if ( $size_src != $size_dest );
	$changed = 1 if ( $from_mtime != $to_mtime );
	
	lprint "$prog_src has changed\n" if ( $changed );

	return( $changed );
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
sub LaunchVirusProcess( $$ )
#
#	given a file that could be a message file - try to extract out the attachments
#
################################################################################
{	my $virus_subdir	= shift;
	my $new_filename	= shift;
	
	# Now run VirusProcess.exe
	chdir( $virus_subdir );
	
	my $processObj;
	my $retcode;
	my $cmd = "c:\\content\\bin\\VirusProcess.exe \"$new_filename\"";

	
	lprint "Running VirusProcess.exe in directory $virus_subdir\n";
	lprint "VirusProcess command: $cmd ...\n";

	
	if ( ! Win32::Process::Create( $processObj, "c:\\content\\bin\\VirusProcess.exe", $cmd, 0, NORMAL_PRIORITY_CLASS, "." ) )
		{	&lprint( "Error executing command $cmd\n" );
			my $str = Win32::FormatMessage( Win32::GetLastError() );
			&lprint( "$str\n" );
			return( undef );
		}	


	if ( $processObj->Wait( ( 600 * 1000 ) ) )  #  Wait up to 600 seconds - or 5 minutes
		{	$processObj->GetExitCode( $retcode );
		}
	else  # Kill it if it's taking too long
		{	$processObj->Kill( 0 );  # Kill the process
			&lprint( "5 minutes passed trying to virus process $new_filename so killing subtasks ...\n" );
			
			&lprint( "Killed the VirusProcess.exe process\n" );
			
			&lprint( "Killing any IpmRealtimeSpam processes ...\n" );	
			&ProcessKillName( "IpmRealtimeSpam.exe" );
			
			&lprint( "Killing any CheckFile processes ...\n" );	
			&ProcessKillName( "CheckFile.exe" );

			return( undef );
		}
	
	
	lprint "VirusProcess completed OK\n";
	
	return( 1 );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
# 
sub EmailProcessLoop()
#
#	Check to see if I need to send any emails.  Return the count of emails sent,
#   or 0 if I sent nothing
#
################################################################################
{	my $email_counter = 0 + 0;
	
	lprint "Checking to see if I need to send any emails ...\n";
	
	# First - do I have any emails that I need to send to customers?  Get the new entries ...
	my $sth = $dbhProgram->prepare( "SELECT ID, EmailFrom, Conclusion, Notes FROM CheckFile WHERE EmailFrom <> '' AND EmailTime IS NULL" );
			
	$sth->execute();

	my %id;	# This is a hash containing the original IDs and data
	my $count = 0 + 0;
	while ( my ( $id, $email_from, $conclusion, $notes ) = $sth->fetchrow_array() )
		{	next if ( ! $id );
			$email_from = &CleanEmailList( $email_from );
			next if ( ! $email_from );
			next if ( ! $conclusion );
			$notes = "" if ( ! defined $notes );
			
			$id{ $id } = "$email_from\t$conclusion\t$notes";
			
			$count++;
		}
	
	$sth->finish();
	
	lprint "Found $count CheckFiles that could be emailed ...\n";
	
	
	# Now get the old entries that have changed
	$sth = $dbhProgram->prepare( "SELECT ID, EmailFrom, Conclusion, Notes FROM CheckFile WHERE EmailFrom <> '' AND EmailTime < AnalyzeTime" );
			
	$sth->execute();

	# Add this to the existing id hash
	my $changed_count = 0 + 0;
	while ( my ( $id, $email_from, $conclusion, $notes ) = $sth->fetchrow_array() )
		{	next if ( ! $id );
			$email_from = &CleanEmailList( $email_from );
			next if ( ! $email_from );
			next if ( ! $conclusion );
			$notes = "" if ( ! defined $notes );
			
			$id{ $id } = "$email_from\t$conclusion\t$notes";
			
			$changed_count++;
		}
	
	$sth->finish();


	lprint "Found $changed_count old CheckFiles that have changed ...\n";
	
	
	# Email each customer
	while ( my ( $id, $data ) = each( %id ) )
		{	next if ( ! $id );
			next if ( ! $data );
			my ( $email_from, $conclusion, $notes ) = split /\t/, $data;
			next if ( ! $conclusion );
			$notes = "" if ( ! defined $notes );
			
			my $loopevent = Win32::Event->open( $event_name );
			if ( ! $loopevent )
				{	&BadError( "Parent process has disappeared - exiting now\n" );
					last;
				}
			
			# Signal the inevent		
			$loopevent->set if ( $loopevent );
			
			lprint "Emailing $email_from about CheckFile ID $id ...\n";
			my $ok = &EmailCustomer( $id, $email_from, $conclusion, $notes );
			
			next if ( ! $ok );
			
			# Update the CheckFile table
			$sth = $dbhProgram->prepare( "UPDATE CheckFile SET EmailTime = getdate() WHERE [ID] = \'$id\'" );
			$sth->execute();
			$sth->finish();	
			
			$email_counter++;
		}
	
	
	# Now figure out what I need to forward for more analysis internally
	$sth = $dbhProgram->prepare( "SELECT ID, EmailFrom, Conclusion, Notes FROM CheckFile WHERE Conclusion LIKE '%$further_analysis%' AND ForwardTime IS NULL" );
			
	$sth->execute();

	my %forward_id;
	while ( my ( $id, $email_from, $conclusion, $notes ) = $sth->fetchrow_array() )
		{	next if ( ! $id );
			$email_from = &CleanEmailList( $email_from );
			$email_from = "no reply email address" if ( ! defined $email_from );
			next if ( ! defined $conclusion );
			$notes = "" if ( ! defined $notes );
			
			$forward_id{ $id } = "$email_from\t$conclusion\t$notes";
		}
	
	$sth->finish();


	# Were there some files that have gotten updated?
	$sth = $dbhProgram->prepare( "SELECT ID, EmailFrom, Conclusion, Notes FROM CheckFile WHERE Conclusion LIKE '%$further_analysis%' AND ForwardTime < AnalyzeTime" );
			
	$sth->execute();

	while ( my ( $id, $email_from, $conclusion, $notes ) = $sth->fetchrow_array() )
		{	next if ( ! $id );
			$email_from = &CleanEmailList( $email_from );
			$email_from = "no reply email address" if ( ! defined $email_from );
			next if ( ! defined $conclusion );
			$notes = "" if ( ! defined $notes );
			
			$forward_id{ $id } = "$email_from\t$conclusion";
		}
	
	$sth->finish();


	# Forward each problem to support to check out furthur
	while ( my ( $id, $data ) = each( %forward_id ) )
		{	next if ( ! $id );
			next if ( ! $data );
			my ( $email_from, $conclusion, $notes ) = split /\t/, $data;
			next if ( ! defined $conclusion );
			$notes = "" if ( ! defined $notes );
			
			my $loopevent = Win32::Event->open( $event_name );
			if ( ! $loopevent )
				{	&BadError( "Parent process has disappeared - exiting now\n" );
					last;
				}
			
			# Signal the inevent		
			$loopevent->set if ( $loopevent );
			
			lprint "Emailing $analysis_email_addresses about CheckFile ID $id ...\n";
			my $ok = &EmailSupport( $id, $email_from, $conclusion, $notes );
			next if ( ! $ok );
			
			# Update the CheckFile table
			$sth = $dbhProgram->prepare( "UPDATE CheckFile SET ForwardTime = getdate() WHERE [ID] = \'$id\'" );
			$sth->execute();	
			$sth->finish();
			
			$email_counter++;
		}

	lprint "Emailed $email_counter messages\n" if ( $email_counter ) ;
	lprint "Emailed no messages\n" if ( ! $email_counter );
	
	return( $email_counter );	
}



################################################################################
# 
sub EmailCustomer( $$$$ )
#
#	Given a ID, a email address, and a conclusion, email a customer
#   Return True if emailed ok, or undef if not
#
################################################################################
{	my $id				= shift;
	my $email_address	= shift;
	my $conclusion		= shift;
	my $notes			= shift;
	
	my $ok = 1;
	
	return( undef ) if ( ! $id );
	return( undef ) if ( ! $email_address );
	return( undef ) if ( ! $conclusion );

	
	lprint "Emailing CheckFile results to email address: $email_address ...\n";

	
	# Now get all of the information about the files that were extracted
	my $sth = $dbhProgram->prepare( "SELECT Filename, MD5, Conclusion FROM CheckFileResults WHERE [ID] = '$id'" );
			
	$sth->execute();

	# Get the list of files that were in the original uploaded file
	my @file_data;
	my $analyze_further;
	while ( my ( $filename, $md5, $file_conclusion ) = $sth->fetchrow_array() )
		{	next if ( ! $md5 );
			push @file_data, "$filename\t$md5\t$file_conclusion";
			
			lprint "File Data: Filename: $filename MD5: $md5 File conclusion: $file_conclusion\n";
			
			$analyze_further = 1 if ( $file_conclusion =~ m/$further_analysis/i );
		}
	
	$sth->finish();
	
	
	# Put all the results into a string
	my $body_results = "File Analysis Results\n";
	foreach ( @file_data )
		{	my $file_data = $_;
			next if ( ! defined $file_data );
			
			my ( $filename, $md5, $file_conclusion ) = split /\t/, $file_data, 3;
			my ( $dir, $shortfile ) = &SplitFileName( $filename );
			
			if ( defined $body_results )
				{	$body_results .= "File name: $shortfile\n";
					$body_results .= "Conclusion: $file_conclusion\n";
					$body_results .= "Details: http://virus.lightspeedsystems.com?md5=$md5\n\n";
				}
			else
				{	$body_results = "File name: $shortfile\n";
					$body_results .= "Conclusion: $file_conclusion\n";
					$body_results .= "Details: http://virus.lightspeedsystems.com?md5=$md5\n\n";
				}
		}
	
	
	# Did I find anything to report?
	if ( $#file_data < 0 )
		{	&BlatSendIt( $email_address, "The message you emailed to virus\@lightspeedsystems.com did not contain any attached files", undef );
		}
	elsif ( $analyze_further )
		{	my $subject = "The files you uploaded to virus\@lightspeedsystems.com are getting further analysis right now";

			my $body = "Conclusion: $conclusion\n\n";
			$body .= "Notes: $notes\n\n" if ( defined $notes );
			
			$body .= "Your files have been forwarded to the Virus Research team here at Lightspeed for further analysis.";
			$body .= "  The team will immediately start working on this to make sure that you are protected.";
			$body .= "  If it is discovered that your file is a previously unknown virus then your Total Traffic server will be updated within an hour with a signature to block this.";
			$body .= "  As the team works you will be immediately emailed if there is any change in the status of your uploaded file.\n\n";
			$body .= "Please contact Lightspeed customer support at 661-716-7600 if you have additional questions.\n\n";

			$body .= $body_results;
			
			$body .= "\nThank you for your help\n\nThe Virus Research Team\n";
			
			$ok = &BlatSendIt( $email_address, $subject, $body );
		}
	else	# I'm done analyzing this
		{	my $subject = "Thank you for uploading your suspicious files to virus\@lightspeedsystems.com";

			my $body = "Conclusion: $conclusion\n\n";
			$body .= "Notes: $notes\n\n" if ( defined $notes );
			
			$body .= "Your files do not need further analysis.  Please contact Lightspeed customer support at 661-716-7600 if you have additional questions.\n\n";
			$body .= $body_results;
			
			$body .= "\nThank you for your help\n\nThe Virus Research Team\n";
			
			$ok = &BlatSendIt( $email_address, $subject, $body );
		}
	
	return( $ok );
}



################################################################################
# 
sub EmailSupport( $$$$ )
#
#	Given a ID, and a conclusion, email a support about a virus problem
#   Return True if emailed ok, or undef if not
#
################################################################################
{	my $id			= shift;
	my $email_from	= shift;
	my $conclusion	= shift;
	my $notes		= shift;
	
	my $ok = 1;
	
	return( undef ) if ( ! $id );
	return( undef ) if ( ! $conclusion );
	
	
	# Now get all of the information about the files that were extracted
	my $sth = $dbhProgram->prepare( "SELECT Filename, MD5, Conclusion FROM CheckFileResults WHERE [ID] = '$id'" );
			
	$sth->execute();


	# Get the list of files that were in the original uploaded file
	my @file_data;
	while ( my ( $filename, $md5, $file_conclusion ) = $sth->fetchrow_array() )
		{	next if ( ! $md5 );
			push @file_data, "$filename\t$md5\t$file_conclusion";
			lprint "File Data: Filename: $filename MD5: $md5 File conclusion: $file_conclusion\n";
		}
	
	$sth->finish();
	
	
	# Put all the results into a string
	my $body_results = "File Analysis Results\n";
	foreach ( @file_data )
		{	my $file_data = $_;
			next if ( ! defined $file_data );
			
			my ( $filename, $md5, $file_conclusion ) = split /\t/, $file_data, 3;
			my ( $dir, $shortfile ) = &SplitFileName( $filename );
			
			if ( defined $body_results )
				{	$body_results .= "File name: $shortfile\n";
					$body_results .= "Conclusion: $file_conclusion\n";
					$body_results .= "Details: http://virus.lightspeedsystems.com?md5=$md5\n\n";
				}
			else
				{	$body_results = "File name: $shortfile\n";
					$body_results .= "Conclusion: $file_conclusion\n";
					$body_results .= "Details: http://virus.lightspeedsystems.com?md5=$md5\n\n";
				}
		}
	
	
	my $subject = "This file needs further analysis right now";

	my $body = "Conclusion: $conclusion\n\n";
	$body .= "Notes: $notes\n\n" if ( defined $notes );
	$body .= "Reply Email: $email_from\n" if ( defined $email_from );
	$body .= "\n";
	
	$body .= $body_results;
		
	$ok = &BlatSendIt( $analysis_email_addresses, $subject, $body );
	
	return( $ok );
}



################################################################################
# 
sub BlatSendIt( $$$ )
#
#	Given an email address, a subject, and a body - send the message
#   Return True if emailed ok, or undef if not
#
################################################################################
{	my $email_address	= shift;
	my $subject			= shift;
	my $body			= shift;
	
	# Make sure that we don't email to virus@lightspeedsystems.com
	return( undef ) if ( $email_address eq "virus\@lightspeedsystems.com" );
	
	# Get a temp directory to create the body text file in
	my $tmp_dir = $ENV{ TMP };

	$tmp_dir = "c:\tmp" if ( ! defined $tmp_dir );
	&MakeDirectory( $tmp_dir ) if ( ! -d $tmp_dir );

	# Set the subject to something if it is defined
	$subject = "Virus Research" if ( ! defined $subject );
	
	# Set the body to the subject line if there is no body
	$body = $subject if ( ! defined $body );
	
	my $temp_file;
	$temp_file = "$tmp_dir\\BlatBody.txt";
	if ( ! open( BLATBODY, ">$temp_file" ) )
		{	lprint "Error opening BlatBody.txt: $!\n";
			return( undef );
		}
	
	print BLATBODY $body;	
	close( BLATBODY );	


	# handle the case of a list of email addresses separated by ';'
	my @email_list = split /;/, $email_address;
	
	foreach ( @email_list )
		{	my $email_addr = $_;
			next if ( ! $email_addr );
			
			my $clean_email = &CleanEmail( $email_addr );
			next if ( ! $clean_email );
			
			lprint "Emailing to $clean_email using blat.exe ...\n";
			
			my $blat_cmd = "c:\\content\\bin\\blat.exe";
			$blat_cmd = "c:\\content\\bin\\blat.exe \"$temp_file\"" if ( defined $body );
			$blat_cmd .= " -f virus\@lightspeedsystems.com";
			$blat_cmd .= " -t $clean_email";
			$blat_cmd .= " -server e2k7-fe";
			$blat_cmd .= " -s \"$subject\"" if ( defined $subject );
			
			
			# Keep a log of the blat results
			my $blat_filename = "$log_directory\\BlatQueueVirus-$hostname.log";		# The name of the log file to use

			# Delete the log file if it is getting too big
			unlink( $blat_filename ) if ( ( -f $blat_filename )  &&  ( -s $blat_filename > 100000 ) );
										 
			lprint "System command: $blat_cmd >>\"$blat_filename\"\n";
			
			system $blat_cmd;
			
			unlink( $temp_file ) if ( -f $temp_file );
		}
		
	return( 1 );
}



################################################################################
# 
sub BadError( $ )
#
#	A bad error has happened.  Do what I can to report it
#
################################################################################
{	my $error = shift;	# This should be a description of the error
	
	chomp( $error );
	
	lprint "Bad Error in Queue Virus: $error\n";
	
	if ( $#email_alert < 0 )
		{	print "No email alert addresses configured so exiting here\n";
			exit( 1 );	
		}
	
	my $log_file = &GetLogFilename();
	
	my $ret = &EmailLogFile( "QueueVirusEmail.txt", "QueueVirus Error", "Error Message: $error", $log_file );
	
	sleep( 2 );	# Give the mail message a little time
	
#	exec( "c:\\content\\bin\\waitfor directorysync" );	
}



################################################################################
# 
sub EmailLogFile( $$$$ )
#
#  Given the file name prefix to use, the subject line, message test, and
#  the log file, email the log file to support@lightspeedsystems.
#
################################################################################
{	my $email_file		= shift;
	my $subject			= shift;
	my $message_text	= shift;
	my $log_file		= shift;	# This could be undefined
	
use MIME::Base64;
	
use Socket;
use Sys::Hostname;
	
	
	&lprint( "Emailing a log file $email_file to @email_alert\n" );
	
	
	# Get a good hostname to use for the local host
	my $host = hostname();
	my $packed_ip = ( gethostbyname( $host ) )[ 4 ];
	my $myipaddress = inet_ntoa( $packed_ip ) if ( defined $packed_ip );
	$myipaddress = "0.0.0.0" if ( ! defined $packed_ip );

	# Default a reasonable hostname for version 5.0 and 5.1 servers 
	my $hostname = $host . " - IP $myipaddress";


	my ( $dir, $short_file  ) = &SplitFileName( $log_file ) if ( defined $log_file );
	$short_file = "none.txt" if ( ! defined $short_file );
	
		
	# Make sure that we are in the current directory	
	chdir( $cwd );
		
		
	# Build up the email message
	my $from = "support\@lightspeedsystems.com";
	
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d.%02d.%02d", $year, $mon, $mday, $hour, $min, $sec );
	my $filestr = sprintf( "%04d%02d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );

	$email_file .= $filestr;
	$email_file .= $email_alert[ 0 ] . ".txt";
	
	$subject = $subject . " from $hostname" if ( $hostname );
	
	# Build the message to send
	my ( $header, $b ) = &MailHeader( $from, $subject, @email_alert );

	my $message = $header;
   
	# Buid up a text message as the first part of the multipart
    $message .= sprintf"\n--%s\n",$b;       
	$message .= "Content-Type: text/plain;\n";
	$message .= "	charset=\"us-ascii\"\n";
	$message .= "Content-Transfer-Encoding: quoted-printable\n\n";
	
    $message .= "=20\n\n";
	
	
	$message .= $message_text . "=20\n\n";
	
	$message .= sprintf"\n--%s\n",$b;
		  
	$message .= "Content-Type: application/text;
	name=\"$short_file\"
Content-Transfer-Encoding: base64
Content-Description: $short_file
Content-Disposition: attachment;
	filename=\"$short_file\"
\n";
	
   
	if ( defined $log_file )
		{	open( LOGFILE, "<$log_file" );
			binmode( LOGFILE );
			
			my $buf;
			my $len = 0 + 57;
			
			while ( read( LOGFILE, $buf, $len ) )
				{	my $outbuf = encode_base64( $buf );
					$message .= "$outbuf";
				}
				
			close( LOGFILE );
		}
		
		
	$message .= sprintf"\n--%s\n",$b;
	$message .= ".\n";
	
	my ( $ok, $msg ) = &PostMessageFile( $monitor_server, "$cwd\\$email_file", $from, $message, undef, undef, @email_alert );

	return( 1 ) if ( $ok );
	
	&lprint( "Error emailing: $msg" );
	
	return( undef );
}



################################################################################
# 
sub CheckLogFile
#
#	Check to make sure the log file isn't getting too big.  Close it, delete the
#   file, and reopen it if it is ...
#
################################################################################
{
	return( undef ) if ( ! $log_filename );
	
	# Delete the log file if it is getting too big
	my $log_size = -s $log_filename;
	
	return( undef ) if ( ! $log_size );

	return( 1 ) if ( $log_size < 1000000 );
	
	&CloseLogFile();
	
	my $deleted_ok = unlink( $log_filename );
	my $err = $!;
	
	&SetLogFilename( $log_filename, 1 );

	&lprint( "Deleted old $log_filename because if was larger than 1000000 bytes\n" ) if ( $deleted_ok );
	&lprint( "Error trying to delete old $log_filename: $err\n" ) if ( ! $deleted_ok );
	
	return( 1 );
}



################################################################################
#
sub MoveShared( $$ )
#
#  Read through the incoming virus directories and set it up for VirusProcess.exe
#  to run
#
################################################################################
{	my $shared_dir			= shift;
	my $shared_dir_backup	= shift;

	
	return( undef ) if ( ! defined $shared_dir );
	return( undef ) if ( ! -d $shared_dir );
	
	return( undef ) if ( ! defined $shared_dir_backup );
	return( undef ) if ( ! -d $shared_dir_backup );


	lprint "Checking directory $shared_dir for old work ...\n";
	
	my $dir;
	if ( ! opendir( $dir, $shared_dir ) )
		{	lprint "Error opening directory $shared_dir: $!\n" ;
			return( undef );
		}
	

	my $time = time();	
	my $moved = 0 + 0;
	while ( my $file = readdir( $dir ) )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			my $fulldir = "$shared_dir\\$file";

			next if ( ! -d $fulldir );
			
			my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat( $fulldir );	
			$mtime	= 0 + $mtime;

			my $age = ( $time - $mtime ) / ( 60 * 60 * 24 );
			
			# If the directory is less than a day old then don't move it
			next if ( $age < 1 );
			
			my $loopevent = Win32::Event->open( $event_name );

			# Signal the inevent		
			$loopevent->set if ( $loopevent );

			my $fulldir_backup = "$shared_dir_backup\\$file";
			lprint "Moving directory $fulldir to $fulldir_backup ...\n";

			&MoveDir( $fulldir, $fulldir_backup, 1 );
			
			$moved++;
		}
		
	
	closedir( $dir );

	lprint "Moved $moved directories from $shared_dir to $shared_dir_backup\n";
	
	return( 1 );	
}



################################################################################
#
sub MoveDir( $$$ )
#
#  Move a directory and optionally remove the original
#
################################################################################
{	my $src		= shift;
	my $target	= shift;
	my $remove	= shift;
	
	return( undef ) if ( ! defined $src );
	return( undef ) if ( ! defined $target );
	
	return( undef ) if ( ! -d $src );
	
	my $ok = &MakeDirectory( $target );
	if ( ! $ok )
		{	print "Unable to make directory $target: $!\n";
			return( undef );	
		}
	
	system "xcopy \"$src\" \"$target\" /s /Y /F /H /R";
	
	system "rmdir \"$src\" /s /q" if ( $remove );
	
	return( 1 );
}



################################################################################
#
sub CleanEmailList( $ )
#
#  Give an email list, return it cleaned up
#
################################################################################
{	my $email_list	= shift;
	
	return( undef ) if ( ! defined $email_list );
	
	my @email = split /;/, $email_list;
	
	my $clean_email_list;
	foreach ( @email )
		{	my $email = $_;
			next if ( ! $email );
			
			my $clean_email = &CleanEmail( $email );
			next if ( ! defined $clean_email );
			
			$clean_email_list .= ';' . $clean_email if ( defined $clean_email_list );
			$clean_email_list = $clean_email if ( ! defined $clean_email_list );
		}
	
	return( $clean_email_list );	
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "QueueVirus";

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
Try '$me --help' for more information.
.
    exit( 2 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "QueueVirus";
    print <<".";
Usage: $me [OPTION(s)]
Watch over the processing of the virus\@lightspeedsystems.com and the 
virus.lightspeedsystems.com website.

The -i option is for monitoring a directory for incoming viruses
the -s option is for scanning directories on the scan list
the -e option is for sending out any emails that are required

  -e, --email         Do any email processing
  -i, --incoming DIR  The ';' separated list of virus directories to monitor
                      Monitoring one directory per task is best
  -m, --move          Just move any old shared directories to backup
  -s, --scan          Do the scan processing on Mail-Virus02, etc.
 
  -h, --help          display this help and exit
  -v, --version       display version information and exit
  
.
    exit( 3 );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "QueueVirus";

    print <<".";
$me $_version
.
    exit( 4 );
}



################################################################################

__END__

:endofperl
