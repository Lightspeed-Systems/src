################################################################################
#!perl -w
#
# Setup everything to download and categorize on the army servers
# Rob McCarthy 7/9/2005
#
################################################################################



# Pragmas
use strict;
use warnings;



use Socket;
use Errno qw(EAGAIN);
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use Win32::Process;
use Cwd;
use Sys::Hostname;



use Content::File;
use Content::Process;
use Content::SQL;
use Content::Category;
use Content::EmailError;
use Content::DisinfectCommand;



# Useful directories
my $recategorize_directory		= 'F:\\Content\\recategorize';
my $unknown_directory			= 'F:\\Content\\unknown';
my $stuck_directory				= 'F:\\Content\\stuck';
my $dump_errors					= "C:\\Content\\DumpErrors";

my $status_directory			= 'I:\\Content\\Status\\HOSTNAME';
my $status_filename				= 'I:\\Content\\Status\\HOSTNAME.log';

my $queue_directory				= 'C:\\Content\\Queue';
my $dump_directory				= 'C:\\Content\\Dump';
my $opt_final_directory			= 'C:\\Content\\Dump\\processed';

my $program_root				= 'I:\\Content\\bin';
my $program_source				= 'J:\\Content\\bin';
my $program_dest				= 'C:\\Content\\bin';

my $keywords_src				= 'J:\\Content\\keywords';
my $keywords_dest				= 'C:\\Content\\keywords';

my $archive_dir					= 'I:\\HashArchive';

my $opt_prog_dir				= 'J:\\DonePrograms';	# This is the root directory of the program done directory
my $categorize_done_directory	= 'J:\\DoneTokens';	# This is the root of the categorize done directory

my $log_directory				= 'C:\\Content\\Log';		# This is the directory to write the logs to
my $tmp_directory				= 'C:\\Content\\tmp';		# This is the tmp directory to download programs to

my $dump_hold_file				= ".dump_hold.tokens.txt";
my $categorize_hold_file		= ".categorize_hold.txt";



# Options
my $opt_help;
my $opt_version;
my $opt_dump = 0 + 2;					# This is the number of QueueDump tasks to launch
my $opt_kill;							# If true, then just kill off any queue processes and die
my $opt_no_dump;						# If True, then don't start any dumptokens tasks and don't copy any tokens files
my $opt_categorize_child = 0 + 2;		# The number of child tasks to have the QueueCategorize command run
my $opt_queue_restart;					# If True, then do a graceful Queue Restart
my $wait_time = 30 * 60;	  	        # This is the amount of time in seconds to give stuck children before killing them


# Globals
my $home_dir;
my $_version = "1.0.0";
my $my_pid;

my $dbhCategory;
my $dbh;
my $dbhLookup;
my $dbhProgram;



################################################################################
#
MAIN:
#
################################################################################
{	$SIG{'INT'} = 'INT_handler';
 


    # Get the options
    Getopt::Long::Configure("bundling");


    my $options = Getopt::Long::GetOptions
    (
		"c|child=i"		=>	\$opt_categorize_child,
		"d|dump"		=>	\$opt_no_dump,
		"k|kill"		=>	\$opt_kill,
		"r|restart"		=>	\$opt_queue_restart,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &StdHeader( "QueueStart" );

	if ( $opt_kill )
		{	&KillQueueProcesses();
			print "Done\n";
			exit( 1 );
		}
	

	# Figure out the hostname
	my $hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );


	# Use the hostname to figure out the status directory
	$status_directory		=~ s/HOSTNAME/$hostname/;
	$status_filename		=~ s/HOSTNAME/$hostname/;


    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	&MakeDirectory( $log_directory ) if ( ! -d $log_directory );
	&SetLogFilename( "$log_directory\\QueueStart.log", undef );
	
	$my_pid = &ProcessGetCurrentProcessId();

	my $path = $ENV{ path };
	my @path_parts = split /;/, $path;
	
	my $lc_prog_dir = lc( $program_dest );
	my $prog_dir_found;
	foreach ( @path_parts )
		{	next if ( ! $_ );
			my $lc_part = lc( $_ );
			$prog_dir_found = 1 if ( $lc_part eq $lc_prog_dir );
		}

	&DisableDrWatson();


	# Map drive F: if it isn't already mapped
	if ( ! -d $recategorize_directory )
		{	lprint "QueueStart: Mapping drive F: to \\\\Process\\Developers ...";
			system "net use f: \\\\Process\\Developers";
		}


	if ( ! $prog_dir_found )
		{	my ( $ok, $msg ) = &EmailError( "Program directory $program_dest is not in the current path", "QueueStart", $my_pid );
			&QueueFatalError( "Program directory $program_dest is not in the current path\n" );
		}
		
	lprint "QueueStart: Setting up to categorize URL files from $recategorize_directory ...\n";
	
	
	if ( $opt_queue_restart )
		{	lprint "QueueStart: Graceful queue restart option selected ...\n";
		}
		
	if ( $opt_no_dump )
		{	lprint "QueueStart: No dump option selected ...\n";
			lprint "QueueStart: Not starting any QueueDump tasks ...\n";
		}
		

	# Make sure all the required directories exist
	&CheckDirectories();


	#  Open the database and load all the arrays
	lprint "QueueStart: Opening a connection to the ODBC System DSN \'TrafficRemote\' ...\n";
	$dbh = &ConnectRemoteServer();

	if ( ! $dbh )
		{
lprint "Unable to open the Remote Content database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.
Also add the Category SQL Server as a System DSN named \'TrafficCategory\'
with default database \'Category\'.\n";
			my ( $ok, $msg ) = &EmailError( "Unable to open the Remote Content database", "QueueStart", $my_pid );
			&QueueFatalError( "Unable to open the Remote Content database\n" );
		}

	lprint "QueueStart: Opening a connection to the ODBC System DSN \'TrafficCategory\' ...\n";

	# Connect to the category database
	$dbhCategory = &CategoryConnect();
	if ( ! $dbhCategory )
		{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";
			my ( $ok, $msg ) = &EmailError( "Unable to open the Remote Category database", "QueueStart", $my_pid );
			&QueueFatalError( "Unable to open the Remote Category database\n" );
		}
		
	
	lprint "QueueStart: Opening a connection to the ODBC System DSN \'TrafficLookup\' ...\n";

	# Connect to the category database
	$dbhLookup = &CategoryLookupConnect();
	if ( ! $dbhLookup )
		{
lprint "Unable to open the Traffic Lookup database.
Run ODBCAD32 and add the Armyxxx platoon leader SQL Server as a System DSN named
\'TrafficLookup\' with default database \'IpmContent\'.\n";
			my ( $ok, $msg ) = &EmailError( "Unable to open the Traffic Lookup database", "QueueStart", $my_pid );
			&QueueFatalError( "Unable to open the Traffic Lookup database\n" );
		}
		
	
	lprint "QueueStart: Opening a connection to the ODBC System DSN \'ProgramRemote\' ...\n";
	
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			&QueueFatalError( "Unable to open the Remote Program database\n" );
		}
		
		
	#  Now that I've made sure I can connect to the databases, close them up
	lprint "QueueStart: Closing all the database connections now that I've tested them ...\n";
	
	$dbh->disconnect		if ( $dbh );
	&CategoryClose()		if ( $dbhCategory );
	&CategoryLookupClose()	if ( $dbhLookup );
	&ProgramClose()			if ( $dbhProgram );
	
	
	# Figure out my starting directory
	$home_dir = getcwd;
	$home_dir =~ s#\/#\\#gm;


	# Clean out the tmp directorys
	lprint "Cleaning out the tmp directories ...\n";
	system "del $tmp_directory\\*.* /q";
	system "del $log_directory\\*.* /q";
	system "del $opt_final_directory\\*.* /q";
	system "del $dump_errors\\*.* /q";


	# Clean out the log files
	lprint "Cleaning out the old log files ...\n";
	system "del $status_directory\\*.log /q";


	# Am I gracefully restarting?
	if ( $opt_queue_restart )
		{	&ProcessKillName( "QueueStart.exe" );
			
			&ProcessKillName( "QueueDump.exe" );
					
			&ProcessKillName( "QueueCategorize.exe" );
			
#			&ProcessKillName( "Archive.exe" );
			
			&QueuePrintStatusFile( "Restarting QueueStart - waiting for all old QueueProcesses to finish ...\n" );
			
			my $counter = 0 + 0;
			while ( &QueueProcessesRunning() )
				{	lprint "QueueStart: Waiting another minute for all old QueueStart processes to gracefully end ...\n";
					sleep( 60 );
					
					my $counter++;
					
					if ( $counter > 60 )
						{	&QueuePrintStatusFile( "Restarting QueueStart - still waiting ...\n" );
							$counter = 0 + 0;
						}
				}
				
			lprint "QueueStart: No old QueueStart processes are still running ...\n";
			
			lprint "QueueStart: Deleting old DumpTokens work logs  ...\n";
			system "del $dump_directory\\*.log";
			
			# Move any old url files to the dump\processed
			lprint "QueueStart: Moving url files to the $opt_final_directory ...\n";
			my $cmd = "move $dump_directory\\*.* $opt_final_directory";
			lprint "QueueStart: Move command: $cmd\n";
			system $cmd;

			my $ok = &CheckQueueStart();
			if ( ! $ok )
				{	&QueuePrintStatusFile( "Detected new QueueStart.exe so exiting now ...\n" );
					&MyExit( 0 );
				}
		}
		
		
	# Kill any old programs that are still running
	&KillQueueProcesses();
	
	
	# Clear out any hold files
	&ClearHoldFiles();
	
	
	&QueuePrintStatusFile( "Restarted QueueStart OK\n" );
	
	
	# Delete old queuedump and queuecategorize logs
	lprint "QueueStart: Deleting old QueueDump logs ...\n";
	system "del $log_directory\\QueueDump*.log";
	
	lprint "QueueStart: Deleting old QueueCategorize logs ...\n";
	system "del $log_directory\\QueueCategorize*.log";
	
	lprint "QueueStart: Deleting old DumpTokens logs ...\n";
	system "del $log_directory\\DumpTokens*.log";
	
	lprint "QueueStart: Deleting old Categorize logs ...\n";
	system "del $log_directory\\Categorize*.log";
	
	lprint "QueueStart: Deleting old stuck logs ...\n";
	system "del $log_directory\\*.stuck";
	
	lprint "QueueStart: Deleting old OK files ...\n";
	system "del $log_directory\\*.OK";
	
	lprint "QueueStart: Deleting old DumpTokens work logs  ...\n";
	system "del $dump_directory\\*.log";
	
	
	# Move any old url files back to the recategorize directory
	my $cmd = "move $dump_directory\\*.* $recategorize_directory";
	lprint "QueueStart: Move command: $cmd\n";
	system $cmd;
	
	
	# Copy any new versions of programs that I need
	my $prog_src	= $program_source . "\\QueueDump.exe";
	my $prog_dest	= $program_dest . "\\QueueDump.exe";
	
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;
	
					
	$prog_src	= $program_source . "\\QueueCategorize.exe";
	$prog_dest	= $program_dest . "\\QueueCategorize.exe";
	
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;
	

	$prog_src	= $program_source . "\\Categorize.exe";
	$prog_dest	= $program_dest . "\\Categorize.exe";
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;


	$prog_src	= $program_source . "\\DumpTokens.exe";
	$prog_dest	= $program_dest . "\\DumpTokens.exe";
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;


	$prog_src	= $program_source . "\\Archive.exe";
	$prog_dest	= $program_dest . "\\Archive.exe";
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;


	$prog_src	= $program_source . "\\PArchive.exe";
	$prog_dest	= $program_dest . "\\PArchive.exe";
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;


	$prog_src	= $program_source . "\\QueuePlatoon.exe";
	$prog_dest	= $program_dest . "\\QueuePlatoon.exe";
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;


	$prog_src	= $program_source . "\\ssleay32.dll";
	$prog_dest	= $program_dest . "\\ssleay32.dll";
	
	$cmd = "changedcopy $prog_src $prog_dest";
	lprint "QueueStart: Program copy command: $cmd\n";
	system $cmd;


	&KeywordsCheck();
	
	
	# Make sure all the queue directories exist
	lprint "QueueStart: Making sure all the queue directories exist ...\n";
	
	chdir( $queue_directory );
	for ( my $i = 0 + 1;  $i < 25;  $i++ )
		{	my $queue_dir = sprintf( "Q%02d", $i );
			
			my $qdir = $queue_directory . "\\" . $queue_dir;
			&MakeDirectory( $qdir );
			
			# If the directory doesn't exist then don't try to clean it out
			next if ( ! -d $qdir );
			
			my $tmp_cmd = "del $qdir\\*.tmp";
			system $tmp_cmd;
			
			$tmp_cmd = "del $qdir\\*.err";
			system $tmp_cmd;

			$tmp_cmd = "del $qdir\\*.exe";
			system $tmp_cmd;

			$tmp_cmd = "del $qdir\\*.dll";
			system $tmp_cmd;

			$tmp_cmd = "del $qdir\\*.zip";
			system $tmp_cmd;
			
			$tmp_cmd = "del $qdir\\*.jpg";
			system $tmp_cmd;
			
			$tmp_cmd = "del $qdir\\*.gif";
			system $tmp_cmd;
		}
	
	
	# Clear out any hold files
	&ClearHoldFiles();
	
	
	# Run the QueueCategorize
	&Launch( $queue_directory, "$program_dest\\QueueCategorize.exe", "QueueCategorize -c $opt_categorize_child" );
	sleep( 7 );
	
	
	if ( ! $opt_no_dump )
		{	for ( my $i = 0 + 0;  $i < $opt_dump;  $i++ )
				{	&Launch( $dump_directory, "$program_dest\\QueueDump.exe", "QueueDump" );
					sleep( 7 );
				}
		}
		
		
	# Run the Archive program to clean out .zip files in the root directory
# Not needed anymore
#	&Launch( "C:\\", "$program_dest\\Archive.exe", "Archive" );
	
	
	my $copy_time = 0 + 0;
	
	my $done;
	while ( ! $done )
		{	lprint "QueueStart: Sleeping for $wait_time seconds ...\n";
			sleep( $wait_time );
			
			$done = &CheckDirectories();
			
			&CheckChildren() if ( ! $done );
			
			$copy_time += $wait_time;
			
			if ( $copy_time >= ( 60 * 60 ) )
				{	&KeywordsCheck();
					$copy_time = 0 + 0;	
					lprint "QueueStart: Waiting for 1 hour before copying keywords again ... \n";
					
					&QueueCopyErrorLogs();
					
					my $ok = &CheckQueueStart();
					
					if ( $ok )
						{	&QueuePrintStatusFile( "Running normally\n" );
						}
					else
						{	&QueuePrintStatusFile( "Detected new QueueStart.exe so exiting now ...\n" );
							$done = 1;
						}
				}
		}
	
	chdir( $home_dir );
	
	&StdFooter();
	
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
	#  Close up the databases
	$dbhCategory->disconnect	if ( $dbhCategory );
	$dbhCategory = undef;
	
	$dbhProgram->disconnect		if ( $dbhProgram );
	$dbhProgram = undef;

	$dbh->disconnect			if ( $dbh );
	$dbh = undef;

	$dbhLookup->disconnect		if ( $dbhLookup );
	$dbhLookup = undef;

	exit( 253 ); 
}



################################################################################
# 
sub MyExit( $ )
#
#  Do a graceful exit
#
################################################################################
{	my $exitcode = shift;
	
	chdir( $home_dir );
	
	#  Close up the databases
	$dbhCategory->disconnect	if ( $dbhCategory );
	$dbhCategory = undef;
	
	$dbhProgram->disconnect		if ( $dbhProgram );
	$dbhProgram = undef;

	$dbh->disconnect			if ( $dbh );
	$dbh = undef;

	$dbhLookup->disconnect		if ( $dbhLookup );
	$dbhLookup = undef;

	&StdFooter();
	
    exit( $exitcode );
}



################################################################################
# 
sub CheckQueueStart()
#
#  Return True if the running QueueStart and the program root QueueStart are the same
#
################################################################################
{	
	my $program_local = "$program_dest\\QueueStart.exe";
	my $program_root = "$program_root\\QueueStart.exe";
	
	my $size_local = -s $program_local;
	my $size_root = -s $program_root;
	
	return( 1 ) if ( ( ! $size_local )  ||  ( ! $size_root ) );
	
	return( undef ) if ( $size_local != $size_root );

	# Are the date/times different?
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $program_local;	
	my $from_mtime = 0 + $mtime;

	( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $program_root;
	my $to_mtime = 0 + $mtime;
	
	return( undef ) if ( $to_mtime != $from_mtime );

	return( 1 );
}



my %log_file_hash;
################################################################################
# 
sub QueueCopyErrorLogs( $ )
#
#  Copy any error logs that have something in them to the status directory
#
################################################################################
{	lprint "QueueStart: Checking for any error logs ... \n";	
	
	# Process the log directory
	if ( ! opendir( LOGDIR, $log_directory ) )
		{	lprint "QueueStart: Error opening $log_directory: $!\n";
			return( undef );
		}

	while ( defined( my $logfile = readdir( LOGDIR ) ) )
		{	next if ( $logfile eq "." );
			next if ( $logfile eq ".." );
			
			# Ignore everything but error logs
			next if ( ! ( $logfile =~ m/error/i ) );
			
			my $full_file = "$log_directory\\$logfile";
			next if ( -d $full_file  );
			
			my $log_size = -s $full_file;
			
			# Ignore 0 length files
			next if ( ! $log_size );
			
			# Have I already copied this file?
			next if ( ( defined $log_file_hash{ $full_file } )  &&  ( $log_size == $log_file_hash{ $full_file } ) );
			
			lprint "QueueStart: Copying error log $logfile to $status_directory ...\n";
			
			my $dest = "$status_directory\\$logfile";
			unlink( $dest );
			my $ok = copy( $full_file, $dest );
			next if ( ! $ok );
			
			$log_file_hash{ $full_file } = $log_size;
		}
		
	closedir( LOGDIR );
	
	return( 1 );
}



################################################################################
# 
sub QueueFatalError( $ )
#
#  Something bad has happened and I need to stop
#
################################################################################
{	my $err_msg = shift;
	
	print "QueueStart Fatal Error: $err_msg\n";
	
	&QueueCopyErrorLogs();
	
	&QueuePrintStatusFile( "QueueStart Fatal Error: $err_msg\n" );
		
	chdir( $home_dir ) if ( $home_dir );

	$dbhCategory->disconnect	if ( $dbhCategory );
	$dbhCategory = undef;
	
	$dbhProgram->disconnect		if ( $dbhProgram );
	$dbhProgram = undef;

	$dbh->disconnect			if ( $dbh );
	$dbh = undef;

	$dbhLookup->disconnect		if ( $dbhLookup );
	$dbhLookup = undef;

	&StdFooter();

	exit( 1 );
}



################################################################################
# 
sub CheckDirectories()
#
#  Check to see that all the required directories still exist
#  Do a fatal error if the don't exist.  Return undef if everything
#  does exist
#
################################################################################
{
	if ( ! -d $recategorize_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find directory $recategorize_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find directory $recategorize_directory\n" );
		}

	if ( ! -d $unknown_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find directory $unknown_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find directory $unknown_directory\n" );
		}

	&MakeDirectory( $stuck_directory ) if ( ! -d $stuck_directory );
	if ( ! -d $stuck_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find directory $stuck_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find directory $stuck_directory\n" );
		}

	&MakeDirectory( $dump_errors ) if ( ! -d $dump_errors );
	if ( ! -d $dump_errors )
		{	my ( $ok, $msg ) = &EmailError( "Can not find directory $dump_errors", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find directory $dump_errors\n" );
		}

	&MakeDirectory( $queue_directory ) if ( ! -d $queue_directory );
	
	if ( ! -d $queue_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find queue directory $queue_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find queue directory $queue_directory\n" );
		}
		
	&MakeDirectory( $status_directory ) if ( ! -d $status_directory );
	
	if ( ! -d $status_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find status directory $status_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find status directory $status_directory\n" );
		}
		
	&MakeDirectory( $dump_directory ) if ( ! -d $dump_directory );
	
	if ( ! -d $dump_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find dump directory $dump_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find dump directory $dump_directory\n" );
		}
	
	&MakeDirectory( $opt_final_directory ) if ( ! -d $opt_final_directory );
	
	if ( ! -d $opt_final_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find dump processed directory $opt_final_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find dump directory $opt_final_directory\n" );
		}
		
	if ( ! -d $program_root )
		{	my ( $ok, $msg ) = &EmailError( "Can not find program root directory $program_root", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find program source directory $program_root\n" );
		}
		
	if ( ! -d $program_source )
		{	my ( $ok, $msg ) = &EmailError( "Can not find program source directory $program_source", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find program source directory $program_source\n" );
		}
		
	if ( ! -d $program_dest )
		{	my ( $ok, $msg ) = &EmailError( "Can not find program destination directory $program_dest", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find program destination directory $program_dest\n" );
		}
		
	if ( ! -d $keywords_src )
		{	my ( $ok, $msg ) = &EmailError( "Can not find keywords source directory $keywords_src", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find keywords source directory $keywords_src\n" );
		}

	&MakeDirectory( $keywords_dest ) if ( ! -d $keywords_dest );

	if ( ! -d $keywords_dest )
		{	my ( $ok, $msg ) = &EmailError( "Can not find keywords destination directory $keywords_dest", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find keywords destination directory $keywords_dest\n" );
		}

	if ( ! -d $archive_dir )
		{	my ( $ok, $msg ) = &EmailError( "Can not find archive directory $archive_dir", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find archive directory $archive_dir\n" );
		}
		
	&MakeDirectory( $opt_prog_dir ) if ( ! -d $opt_prog_dir );

	if ( ! -d $opt_prog_dir )
		{	my ( $ok, $msg ) = &EmailError( "Can not find program archive directory $opt_prog_dir", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find program archive directory $opt_prog_dir\n" );
		}

	&MakeDirectory( $log_directory ) if ( ! -d $log_directory );

	if ( ! -d $log_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not find log directory $log_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not find log directory $log_directory\n" );
		}

	&MakeDirectory( $tmp_directory ) if ( ! -d $tmp_directory );

	if ( ! -d $tmp_directory )
		{	my ( $ok, $msg ) = &EmailError( "Can not create tmp directory $tmp_directory", "QueueStart", $my_pid );
			&QueueFatalError( "Can not create tmp directory $tmp_directory\n" );
		}

	return( undef );
}



my %logfiles_size;

################################################################################
# 
sub CheckChildren()
#
#  Check to see that the child processes are not stuck on something
#
################################################################################
{	lprint "QueueStart: Checking for stuck child tasks ... \n";
	
	# First find my children
	my %process_hash = &ProcessHash();
	
	my %children_hash;
	
	my $queuedump_count = 0 + 0;
	my $queuecategorize_count = 0 + 0;

# Not needed any more
#	my $archive_count = 0 + 0;
	
	while ( my ( $pid, $process ) = each( %process_hash ) )
		{	my $lc_name = lc( $process );
			
			# Is it a QueueDump task?
			if ( $lc_name =~ m/queuedump\.exe/ )
				{	$queuedump_count++;
				}
			# Is it a QueueCategorize task?
			if ( $lc_name =~ m/queuecategorize\.exe/ )
				{	$queuecategorize_count++;
				}
			# Is it a DumpTokens task?
			elsif ( $lc_name =~ m/dumptokens\.exe/ )
				{	$children_hash{ $pid } = $process;
				}
			# Is it a Categorize task?
			elsif ( $lc_name =~ m/categorize\.exe/ )
				{	$children_hash{ $pid } = $process;
				}
			# Is it a Archive task?
# Not needed any more
#			elsif ( $lc_name =~ m/archive\.exe/ )
#				{	$archive_count++;
#				}
		}
	
	
	# Did I find all the Queue Tasks?
	if ( ! $queuecategorize_count )
		{	lprint "The QueueCategorize program has exited early so the QueueStart program is quitting too!\n";
			my ( $ok, $msg ) = &EmailError( "The QueueCategorize program has exited early so the QueueStart program is quitting too!", "QueueStart", $my_pid );
			&QueuePrintStatusFile( "The QueueCategorize program has exited early so the QueueStart program is quitting too!\n" );
			&MyExit( 5 );
		}
		
	if ( ( ! $opt_no_dump )  &&  ( $queuedump_count != $opt_dump ) )
		{	lprint "The QueueDump program has exited early so the QueueStart program is quitting too!\n";
			my ( $ok, $msg ) = &EmailError( "The QueueDump program has exited early so the QueueStart program is quitting too!", "QueueStart", "QueueStart", $my_pid );
			&QueuePrintStatusFile( "The QueueDump program has exited early so the QueueStart program is quitting too!\n" );
			&MyExit( 6 );
		}
	

# Not needed any more
#	if ( ! $archive_count )
#		{	# Run the Archive program to clean out .zip files in the root directory
#			lprint "The QueueStart program launching another copy of Archive.exe ...\n";
#			&Launch( "C:\\", "$program_dest\\Archive.exe", "Archive" );
#		}
		
		
	# Now that I've found the children, check each one's log size
	my %pid_log_size;
	my %pid_log_name;
	while ( my ( $pid, $process ) = each( %children_hash ) )
		{	my ( $dir, $short_name ) = &SplitFileName( $process );

			my $name = $short_name;
			$name =~ s/\.exe$//;
			my $log_name = "$log_directory\\$name-$pid.log";
			my $size = -s $log_name;
			
			# Skip stuff that doesn't have a size
			next if ( ! $size );
			
			$pid_log_size{ $pid } = $size;
			$pid_log_name{ $pid } = $log_name;
		}
		
		
	# Now look at the last logfile size I have, and see if the size is stuck
	my $stuck_count = 0 + 0;
	while ( my ( $pid, $size ) = each( %pid_log_size ) )
		{
			my $last_size = $logfiles_size{ $pid };
			next if ( ! $last_size );
			
			if ( $size == $last_size )
				{	my $log_name = $pid_log_name{ $pid };
					my $stuck_log = $log_name . ".stuck";
					
					&lprint( "QueueStart: Copying stuck child task log to $stuck_log ...\n" );
					copy( $log_name, $stuck_log );
					
					&RestartDumptokens( $pid ) if ( $log_name =~ m/dumptoken/i );
					
					my $process = $children_hash{ $pid };
					&lprint( "QueueStart: Killing stuck $process pid $pid ...\n" );
					
					$stuck_count++;
					
					&ProcessTerminate( $pid );
				}
		}
		
	
	# Save the last sizes for the next loop
	%logfiles_size = %pid_log_size;
	
	return( $stuck_count );	
}



################################################################################
# 
sub RestartDumptokens( $ )
#
#  I've got a stuck DumpTokens process, so figure out what it got stuck on
#  and set it up to restart
#
################################################################################
{	my $pid = shift;	# This is the pid of the stuck DumpTokens process
	
	return( undef ) if ( ! defined $pid );
	
	# Figure out the file that has the current work the DumpTokens program is on
	my $current_work = $dump_directory . "\\DumpTokensWork-$pid.log";
	
	return( undef ) if ( ! -e $current_work );
	return( undef ) if ( ! -s $current_work );
		
	return( undef ) if ( ! open( CURRENT_WORK, "<$current_work" ) );
	my $line = <CURRENT_WORK>;
	chomp( $line );
	close( CURRENT_WORK );
	
	return( undef ) if ( ! $line );
	return( undef ) if ( ! length( $line ) );
	
	&lprint( "QueueStart: Restarting stuck DumpTokens work file $current_work ...\n" );
	
	my ( $url_file, $stuck_url, $working_dir ) = split /\t/, $line, 3;
	
	return( undef ) if ( ! $url_file );
	return( undef ) if ( ! $stuck_url );
	

	# OK - at this point I have the url file and the url that the DumpTokens process got stuck on ...
	# So try to clean up the mess and go on ...
	my $dir;
	my $short_name = $url_file;
	( $dir, $short_name ) = &SplitFileName( $url_file ) if ( $url_file =~ m/\\/ );
	
	
	# Put the new file into the recategorize directory
	# Create a tmp file in the recategorize directory, and then rename it
	my $new_url_file = $recategorize_directory . "\\c-" . $short_name;
	my $tmp_url_file = $recategorize_directory . "\\z-" . $short_name;
	
	
	# Read the urls from the old file
	my @urls;
	return( undef ) if ( ! open( INFILE, "<$url_file" ) );
	
	&lprint( "QueueStart: Reading urls from stuck file $url_file ...\n" );
	
	my $ignore = 1;
	my $count = 0 + 0;
	while (<INFILE>)
		{	chomp;
			next if ( ! $_ );
			my $url = $_;
			
			next if ( ! defined $url );
			$url =~ s/^\s+//;
			
			my $junk;
			( $url, $junk ) = split /\s/, $url, 2;
			
			$url = &CleanUrl( $url );
			next if ( ! defined $url );
			
			if ( $url eq $stuck_url )
				{	$ignore = undef;
					next;
				}
				
			next if ( $ignore );	
			push @urls, $url;
			$count++;
		}
		
	close( INFILE );
	
	&lprint( "QueueStart: Read $count urls from stuck file $url_file\n" );
	
	return( undef ) if ( ! $count );
	
	
	# Create the tmp file and write all the remaining urls out to it ...
	&lprint( "QueueStart: Creating tmp file $tmp_url_file ...\n" );
	return( undef ) if ( ! open( OUTFILE, ">$tmp_url_file" ) );
	foreach ( @urls )
		{	print OUTFILE "$_\n";
		}	
	close( OUTFILE );

	&lprint( "QueueStart: Renaming $tmp_url_file to $new_url_file ...\n" );
	my $ok = rename( $tmp_url_file, $new_url_file );
	&lprint( "Error renaming $tmp_url_file to $new_url_file ...\n" ) if ( ! $ok );
	
	
	# Now add the stuck url to the list in the archive directory
	my $stuck_list = $stuck_directory . "\\stuck.urls";
	&lprint( "QueueStart: Adding the stuck url $stuck_url to the stuck list $stuck_list ...\n" );
	
	return( undef ) if ( ! open( STUCK, ">>$stuck_list" ) );
	print STUCK "$stuck_url\n";
	close( STUCK );
	
		
	# Delete the current work file now that I've cleaned everything else up
	unlink( $current_work );

	&lprint( "QueueStart: Restarted DumpTokens process $pid OK\n" ) if ( $ok );
	
	return( 1 );
}



################################################################################
# 
sub KillQueueProcesses()
#
#  Kill off any queue processes
#
################################################################################
{	lprint "QueueStart: Killing any existing Queue processes ...\n";
	
	&ProcessKillName( "QueueStart.exe" );
	&ProcessKillName( "QueueDump.exe" );
	&ProcessKillName( "QueueCategorize.exe" );
	&ProcessKillName( "Categorize.exe" );
	&ProcessKillName( "DumpTokens.exe" );
	&ProcessKillName( "changedcopy.exe" );
#	&ProcessKillName( "archive.exe" );
	
	return( 1 );
}



################################################################################
# 
sub QueueProcessesRunning()
#
#  Return True if any QueueProcesses are still running
#
################################################################################
{	
	return( 1 ) if ( &ProcessRunningName( "QueueDump.exe" ) );
	return( 1 ) if ( &ProcessRunningName( "QueueCategorize.exe" ) );
	return( 1 ) if ( &ProcessRunningName( "Categorize.exe" ) );
	return( 1 ) if ( &ProcessRunningName( "DumpTokens.exe" ) );
	return( 1 ) if ( &ProcessRunningName( "changedcopy.exe" ) );
#	return( 1 ) if ( &ProcessRunningName( "archive.exe" ) );
		
	return( undef );
}



################################################################################
# 
sub KeywordsCheck()
#
#  Copy any keywords files that have changed
#
################################################################################
{
	# Process the source directory
	opendir( DIR, $keywords_src ) or return( undef );

	while ( my $file = readdir( DIR ) )
		{
			my $src = "$keywords_src\\$file";
			my $dest = "$keywords_dest\\$file";
			
			next if ( ! -f $src );
			
			my $size_src	= -s $src;
			my $size_dest	= -s $dest;
			
			if ( ( ! defined $size_dest )  ||  ( $size_src != $size_dest ) )
				{	lprint "QueueStart: Copying $src to $dest ...\n";
					
					my $success = copy( $src, $dest );
			
					if ( ! $success )
						{	lprint "QueueStart: File copy error: $!\n";						
						}
				}
		}
		
	closedir(  DIR );
	
	return( 1 );
}



################################################################################
# 
sub ClearHoldFiles()
#
#  Clear out any hold files that exist
#
################################################################################
{
	# Process the queue directory
	if ( ! opendir( QUEUEDIR, $queue_directory ) )
		{	lprint "QueueStart: Error opening the queue directory: $!\n";
			return( undef );
		}

	my $directory_count = 0 + 0;
	
	while ( defined( my $subdir = readdir( QUEUEDIR ) ) )
		{	next if ( $subdir eq "." );
			next if ( $subdir eq ".." );
			
			my $full_subdir = $queue_directory . "\\" . $subdir;

			# Only check subdirectories
			next if (! -d $full_subdir );
							
			$directory_count++;
			
			my $dump_hold = $full_subdir . "\\" . $dump_hold_file;
			unlink( $dump_hold );
			
			my $categorize_hold = $full_subdir . "\\" . $categorize_hold_file;
			unlink( $categorize_hold );
		}

	closedir QUEUEDIR;
	
	if ( ! $directory_count )
		{	lprint "QueueStart: There are no subdirectories in $queue_directory\n";
			return( undef );
		}
		
	return( 1 );
}



################################################################################
# 
sub Launch( $$$ )
#
#  Given the directory and command to launch - run it
#
################################################################################
{	my $dir = shift;
	my $full_filename = shift;
	my $cmd = shift;
	
	lprint "QueueStart: Launching $full_filename in directory $dir ...\n";
	
	chdir( $dir );
	
	my $outgoing_process;	
	my $ok = Win32::Process::Create( $outgoing_process, $full_filename, $cmd, 0, NORMAL_PRIORITY_CLASS, $dir );
	if ( ! $ok )
		{	my $str = Win32::FormatMessage( Win32::GetLastError() );
			lprint "QueueStart: Unable to create outgoing process $full_filename: $str\n";
			my ( $ok, $msg ) = &EmailError( "Unable to launch $full_filename in directory $dir", "QueueStart", $my_pid );
			&QueuePrintStatusFile( "Unable to launch $full_filename in directory $dir\n" );
			&MyExit( 7 );
		}	
	
	chdir( $home_dir );
		
	return( 1 );	
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
sub QueuePrintStatusFile( @ )
#
#  Print a line of text to the log file with a date/time
#
################################################################################
{	
	return( undef ) if ( ! -d $status_directory );
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year = 1900 + $year;
	$mon = $mon + 1;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );


	open( ERRLOG, ">>$status_filename" ) or print "Can not create status log file $status_filename: $!\n";
		
		
	# Print the timestamp if the text is anything but a line feed	
	print ERRLOG ( "$datestr : " ) if ( $_[ 0 ] ne "\n" );
	print ERRLOG ( @_ );


	close( ERRLOG );
	
	return( 1 );
}



################################################################################
# 
sub DisableDrWatson()
#
#  Disable the Dr. Watson debugger
#
################################################################################
{	&lprint( "Checking to see if the Dr. Watson debugger is enabled ...\n" );

use Win32API::Registry 0.21 qw( :ALL );
	
	my $key;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", 0, KEY_ALL_ACCESS, $key );
	
	return( undef ) if ( ! $ok );
	
	# Does the value even exist?
	my $type;
	my $data;

	my $exists = &RegQueryValueEx( $key, "Debugger", [], $type, $data, [] );

	&RegCloseKey( $key );

	return( undef ) if ( ! defined $exists );
	return( undef ) if ( ! length( $data ) );
	return( undef ) if ( ! defined $data );
	

	# Does it look like Dr. Watson?
	return( undef ) if ( $data =~ m/drwtsn32/i );

	&lprint( "Disabling the Dr. Watson debugger ...\n" );
	
	# Delete the entire key
	&DisinfectCommandRegDeleteKey( "HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug" );

	return( 1 );
}


################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "QueueStart";

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
Try '$me --help' for more information.
.
    exit( 8 );
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "QueueStart";
    print <<".";
Usage: $me [OPTION(s)]
Setup and launch all the tasks to download and categorize on an army server

Directories used are:

Recategorize: $recategorize_directory
Unknown: $unknown_directory
Stuck: $stuck_directory
DumpErrors: $dump_errors

Queue: $queue_directory
Dump: $dump_directory
Final: $opt_final_directory

Program Source: $program_source
Program Destination: $program_dest

Keywords Source: $keywords_src
Keywords Destination: $keywords_dest

Web Archive: $archive_dir

Program Archive: $opt_prog_dir
Categorize Done: $categorize_done_directory

Logs: $log_directory


Options:
  -c, --child NUM   the number of Categorize child tasks to run - default 2    
  -d, --dump        to NOT start any DumpTokens tasks
  -k, --kill        kill any running queue processes
  -r, --restart     to do a graceful queue restart  
  -h, --help        display this help and exit
  -v, --version     display version information and exit
.
    exit( 9 );
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "QueueStart";

    print <<".";
$me $_version
.
    exit( 10 );
}



################################################################################

__END__

:endofperl
