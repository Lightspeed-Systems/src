################################################################################
#!perl -w
#
# QueueCategorize
#
# Loop around categorizing URLs to files forever from Queue directories
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
use Cwd;
use Sys::Hostname;
use Win32::Process;



use Content::File;
use Content::Process;



# Directories used by QueueCategorize
my $recategorize_directory		= 'F:\\Content\\recategorize';
my $unknown_directory			= 'F:\\Content\\unknown';

my $queue_directory				= 'C:\\Content\\Queue';
my $program_source				= 'J:\\Content\\bin';
my $log_directory				= 'C:\\Content\\Log';		# This is the directory to write the logs to

my $status_directory			= 'I:\\Content\\Status\\HOSTNAME';
my $status_filename				= 'I:\\Content\\Status\\HOSTNAME.log';

my $categorize_done_directory	= 'J:\\DoneTokens';	# This is the root of the categorize done directory


my $dump_hold_file				= ".dump_hold.tokens.txt";
my $categorize_hold_file		= ".categorize_hold.txt";


# This is the list of .dlls that need to be in the current working directory in order to analyze an image
my @image_dlls = (
	"AnalyzeImage.dll",
	"IAEngine.dll",
	"IAImageReader.dll"
	);


my %active_queue;			# A hash of the currently active QueueCategorize directories in this program


# Options
my $opt_help;
my $opt_version;
my $opt_child				= 0 + 2;   # How many child tasks to launch to categorize a lot of urls by default
my $_version = "1.0.0";
my $logfile;
my $home_dir;
my $opt_noqueue;			# If True then don't look for a running QueueStart program




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
        "c|child=i"		=>	\$opt_child,
        "n|noqueue"		=>	\$opt_noqueue,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &StdHeader( "QueueCategorize" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	# Figure out the current drive letter and add it to any directories that need it
	my $curdir = getcwd;
	$curdir =~ s#\/#\\#gm;
	my ( $drive, $junk ) = split /\:/, $curdir, 2;
	$drive = $drive . ":" if ( length( $drive ) == 1 );
	$home_dir = $curdir;
	
	
	# Figure out the hostname
	my $hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );


	# Use the hostname to figure out the queue directory
	$status_directory		=~ s/HOSTNAME/$hostname/;
	$status_filename		=~ s/HOSTNAME/$hostname/;
		

	mkdir( $log_directory ) if ( ! -d $log_directory );
	my $my_pid = &ProcessGetCurrentProcessId();
	$logfile = "$log_directory\\QueueCategorize$my_pid.log";
	&SetLogFilename( $logfile, undef );


	# Check to make sure the required directories still exist
	&CheckDirectories();
	

	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;


	&ClearHoldFiles();
	
	lprint "Not looking for a running QueueStart program ...\n" if ( $opt_noqueue );
	
	lprint "Starting $opt_child child processes of QueueCategorize running ...\n";
	
	
	my  $pid;
	for ( my $i = 0;  $i < $opt_child - 1;  $i++ )
		{	#  Now fork off my child processes
			FORK:
				{
					if ( $pid = fork )
						{	lprint "Started child process $pid\n"; 
							sleep 10;  # Sleep for 10 seconds to give the child time to get started 
							next;
						}

					elsif ( defined $pid )
						{	lprint "Child process started\n";
							goto CONTINUE;
						}

					elsif ( $! == EAGAIN )
						{	sleep 15;
							redo FORK;
						}

					else
						{	die "Can't fork: $!\n";
						}

				}  # end of FORK
		}  # end of for loop


	CONTINUE:


	my $queue_start_pid = &ProcessNamePID( "QueueStart" );
	

	# Loop forever
	while ( 1 )
		{	# Make sure QueueStart is still running - if not, then die
			# But don't bother looking if I don't care about QueueStart
			if ( ! $opt_noqueue )
				{	if ( ( ! &ProcessRunningName( "QueueStart" ) )  ||  ( ! &ProcessPIDName( $queue_start_pid ) ) )
						{	lprint "Parent program QueueStart is not running, so quitting myself now ...\n";
							&QueuePrintStatusFile( "Parent program QueueStart is not running, so quitting QueueCategorize now ...\n" );
							
							sleep( 1 );
							chdir( $dir );
							
							&ProcessKillName( "QueueCategorize.exe" );
							&ProcessTerminate( $my_pid );
												
							&StdFooter();
							
							&QueueFatalError( "Parent QueueStart is not running\n" );
							
							exit( 1 );
						}
				}
			
				
			# Get an full queue directory
			my $full_queue_directory = &GetFullQueueDirectory();
						
			# Did I get an full queue directory?
			if ( defined $full_queue_directory )
				{	# Process the source directory
					
					$active_queue{ $full_queue_directory } = 0 + 1;
					
					# Copy a fresh version of the Categorize program
					my $prog_src	= "$program_source\\Categorize.exe";
					my $prog_dest	= "$full_queue_directory\\Categorize.exe";
					
					my $cmd = "changedcopy \"$prog_src\" \"$prog_dest\"";
					lprint "Program copy: $cmd\n";
					
					system $cmd;
					
					
					# make sure that we have the most current image dlls
					foreach ( @image_dlls )
						{	my $image_dll = $_;
							next if ( ! $image_dll );
							
							# Copy a fresh version of the Categorize program
							my $dll_src	= "$program_source\\$image_dll";
							my $dll_dest	= "$full_queue_directory\\$image_dll";
							
							my $cmd = "changedcopy \"$dll_src\" \"$dll_dest\"";
							lprint "Program copy: $cmd\n";
							
							system $cmd;
						}
						
						
					chdir( $full_queue_directory );
					
					my $full_file = $full_queue_directory . "\\" . $categorize_hold_file;
					
					# Did the changecopy command work?
					my $ok;
					my $fatal;
					
					my $categorize_process;
					if ( -f $prog_dest )
						{	lprint "Launching Categorize.exe in directory: $full_queue_directory\n";
					
							# Now run the program that I just copied
							$cmd = "Categorize -a -z";
							$ok = Win32::Process::Create( $categorize_process, $prog_dest, $cmd, 0, NORMAL_PRIORITY_CLASS, $full_queue_directory );
						}
					else
						{	$ok = undef;
							&lprint( "ERROR: Unable to create $prog_dest\n" );
						}
						
				
					# If I created the task ok, did everything go all right from there?
					if ( ( $ok )  &&  ( $categorize_process ) )
						{	my $categorize_pid = $categorize_process->GetProcessID();
					
							# Wait for it to finish
							$categorize_process->Wait( INFINITE );
							
							# Get the exitcode
							my $exitcode = 0 + 0;
							$categorize_process->GetExitCode( $exitcode );
							
							if ( ( $exitcode != 0 )  &&  ( $exitcode != 256 ) )
								{	$ok = undef;
									&lprint( "Command $cmd terminated with exit code $exitcode ...\n" );
								}
							
							# Did the process create the right log files?
							my $log_file			= "$log_directory\\Categorize-$categorize_pid.log";
							my $finished_log_file	= "$log_directory\\Categorize-$categorize_pid.OK";
							
							if ( ! -f $finished_log_file )
								{	$ok = undef;
									&lprint( "The Categorize process did not create $log_file!\n" );
								}
								
							if ( ! -f $finished_log_file )
								{	$ok = undef;
									&lprint( "The Categorize process did not create $finished_log_file!\n" );
								}
						}
					else
						{	&lprint( "ERROR: Unable to create $prog_dest process!\n" );
							&lprint( "Deleting $prog_dest ...\n" );
							my $deleted = unlink( $prog_dest );
							
							if ( ! $deleted )
								{	&lprint( "Error deleting $prog_dest\n" );
									rename( $prog_dest, "$prog_dest.err" );
								}
								
							# If I can't delete or rename the bad program then I really do have problems
							$fatal = 1 if ( -f $prog_dest );
							
							$ok = undef;
						}
						
						
					if ( ! $ok )
						{	lprint "Command $cmd did not normally terminate\n";
							&QueuePrintStatusFile( "Command $cmd did not normally terminate\n" );
							
							# Was this a really bad problem?	
							if ( $fatal )	
								{	lprint "Exiting QueueCategorize because of fatal error ...\n";
									&QueuePrintStatusFile( "Command $cmd caused a fatal error so exiting QueueCategorize\n" );
									sleep( 1 );
									
									chdir( $dir );
									sleep( 20 );
									
									&StdFooter();
									
									&QueueFatalError( "QueueCategorize comand $cmd had a fatal error\n" );
									
									exit( 2 );
								}	
						}
					else	# I think that the Categorize command did everything right
						{	# Move the unknown urls file to the unknown directory
							system "move unknown*.urls $unknown_directory";
							
							
							# Check to make sure that the Categorize command archived all the files correctly
							$ok = &ArchivedOK( $full_queue_directory, $categorize_hold_file );
							
							# Do I have a problem with stuck tokens files?
							if ( ! $ok )
								{	lprint "Directory $full_queue_directory has stuck tokens files so exiting QueueCategorize\n";
									&QueuePrintStatusFile( "Directory $full_queue_directory has stuck tokens files so exiting QueueCategorize\n" );
									sleep( 1 );
									&ProcessKillName( "QueueCategorize.exe" );
																	
									chdir( $dir );
									sleep( 20 );
									
									&StdFooter();
									
									&QueueFatalError( "QueueCategorize stuck tokens files in $full_queue_directory\n" );
									
									exit( 3 );
								}
						}
					
					# Delete the hold file
					unlink( $full_file );
					
					$active_queue{ $full_queue_directory } = 0 + 0;
				}
			
			
			if ( ! defined $full_queue_directory )
				{	lprint "Did not find a full queue directory to process ...\n";
					
					# Go to sleep for 5 minutes until checking the directory again
					lprint "Waiting for 5 minutes before restarting ... \n";
					sleep( 300 );
					
					# Make sure all the directories exist - if not then die!
					&CheckDirectories();
				}
			else	# Wait just a little bit before tyring to launch another process
				{  sleep( 30 );
				}
		}


	chdir( $dir );
	
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
	exit( 253 ); 
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
	if ( ( $logfile )  &&  ( ! -f $logfile ) )
		{	&QueueFatalError( "Could not find logfile $logfile\n" );
		}
		
	if ( ! -d $recategorize_directory )
		{	&QueueFatalError( "Can not find directory $recategorize_directory\n" );
		}

	if ( ! -d $unknown_directory )
		{	&QueueFatalError( "Can not find directory $unknown_directory\n" );
		}

	if ( ! -d $queue_directory )
		{	&QueueFatalError( "Can not find queue directory $queue_directory\n" );
		}

	if ( ! -d $program_source )
		{	&QueueFatalError( "Can not find program source directory $program_source\n" );
		}

	if ( ! -d $categorize_done_directory )
		{	&QueueFatalError( "Can not find categorize done directory $categorize_done_directory\n" );
		}

	if ( ! -d $log_directory )
		{	&QueueFatalError( "Can not find log directory $log_directory\n" );
		}

	return( undef );
}



################################################################################
# 
sub ArchivedOK( $$ )
#
#  Given a queue directory path, and the categorize hold file name, return True
#  if there are no tokens files to archive, or undef if there are
#
################################################################################
{	my $full_queue_directory = shift;
	my $categorize_hold_file = shift;
	

	if ( ! opendir( QDIR, $full_queue_directory ) )
		{	lprint "Error opening the queue directory $full_queue_directory: $!\n";
			return( undef );
		}

	
	# Look for a .txt file
	while ( defined( my $file = readdir( QDIR ) ) )
		{	next if ( $file eq "." );
			next if ( $file eq ".." );
			
			next if ( lc( $file ) eq lc( $categorize_hold_file ) );
			
			my $full_file = "$full_queue_directory\\$file";
			
			# Is it a text file?
			if ( $file =~ m/\.txt/i )
				{	# Try to delete the files
					unlink( $full_file );
					
					# Try to rename it
					rename( $full_file, "$full_file.err" );
					
					# If the file is still there, then return a problem	
					if ( -f $full_file )
						{	closedir( QDIR );
							return( undef );
						}
				}
		}
		
	closedir( QDIR );
	
	return( 1 );
}



################################################################################
# 
sub GetFullQueueDirectory()
#
#  Return an full queue directory, or undef if none exist
#
################################################################################
{
	# Process the queue directory
	if ( ! opendir( QUEUEDIR, $queue_directory ) )
		{	lprint "Error opening the queue directory: $!\n";
			return( undef );
		}

	my $full_queue_directory;
	my $directory_count = 0 + 0;
	my %full_queue;		# This is a hash of the full queue directories, and their ages
	
	while ( defined( my $subdir = readdir( QUEUEDIR ) ) )
		{	next if ( ! $subdir );
			next if ( $subdir eq "." );
			next if ( $subdir eq ".." );
			
			# Queue subdirectories should start with a q
			next if ( ! ( $subdir =~ m/^q/i ) );
			
			my $full_subdir = $queue_directory . "\\" . $subdir;

			# Only check subdirectories
			next if ( ! -d $full_subdir );
				
			# Is this QueueCategorize already using this directory?
			my $active;
			$active = $active_queue{ $full_subdir } if ( defined $active_queue{ $full_subdir } );
			next if ( $active );
					
			next if ( ! opendir( SUBDIR, $full_subdir ) );
			
			my $empty = 1;
			my $found_hold;
			
			$directory_count++;
			
			while ( ( ! $found_hold )  &&  ( $empty )  &&  ( defined( my $file = readdir( SUBDIR ) ) ) )
				{	$file = lc( $file );
					
					# If I find a hold file then the QueueDump is still working on the directory
					if ( $file eq lc( $dump_hold_file ) )
						{	$found_hold = 1;
							next;
						}
					
					# Maybe QueueCategorize is already working on this directory
					elsif ( $file eq lc( $categorize_hold_file ) )
						{	$found_hold = 1;
							next;
						}
					
					# If I find a site file then the directory is not empty
					elsif ( ( $empty )  &&  ( ( $file =~ m/site\.txt$/ )  ||  ( $file =~ m/tokens\.txt$/ )  ||  ( $file =~ m/links\.txt$/ )  ||  ( $file =~ m/image\.zip$/ ) ) )
						{	$empty = undef;
							
							# Now keep track of how old the site file is ...
							my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat "$full_subdir\\$file";	
							$mtime = 0 + $mtime;
			
							my $key = sprintf "%10d", $mtime;
			
							$full_queue{ $key } = $full_subdir;
						}
				}
				
			closedir( SUBDIR );
		}

	closedir( QUEUEDIR );
	
	
	if ( ! $directory_count )
		{	lprint "There are no subdirectories in $queue_directory\n";
			return( undef );
		}
	
	
	# At this point I have a hash of full queue directories, so pick the oldest to categorize
	my @keys = sort keys %full_queue;
	
	
	# Do I have any full queues at all?
	if ( $#keys < 0 )
		{	lprint "There are no full queue directories ready to be categorized\n";
			return( undef );
		}
		
		
	# The oldest full queue directory should be the first ones in the keys list	
	my $full_file;
	foreach ( @keys )
		{	my $oldest_key = $_;
			next if ( ! $oldest_key );
			next if ( $full_file );
			
			$full_queue_directory = $full_queue{ $oldest_key };
			
			$full_file = $full_queue_directory . "\\" . $categorize_hold_file;
			
			# Check to make sure another task hasn't put a hold file on this category in the meantime ...
			if ( -e $full_file )
				{	lprint "Whoops - another categorize task is already using $full_queue_directory\n";
					$full_file = undef;
					next;
				}
		}

	# Did I find a directory that wasn't already being worked on?
	return( undef ) if ( ! $full_file );		
	
	# Write out a categorize hold file ...							
	open( HOLDFILE, ">$full_file" );
	print HOLDFILE "on hold\n";
	close( HOLDFILE );
	
	lprint "Found the oldest full queue directory to categorize: $full_queue_directory\n";
	
	return( $full_queue_directory );
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
		{	lprint "Error opening the queue directory: $!\n";
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

	closedir( QUEUEDIR );
	
	if ( ! $directory_count )
		{	lprint "There are no subdirectories in $queue_directory\n";
			return( undef );
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
sub QueueFatalError( $ )
#
#  Something bad has happened and I need to stop
#
################################################################################
{	my $err_msg = shift;
	
	print "QueueCategorize Fatal Error: $err_msg\n";

	&QueuePrintStatusFile( "QueueCategorize Fatal Error: $err_msg\n" );
		
	chdir( $home_dir ) if ( $home_dir );

	&StdFooter();

	exit( 1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "QueueCategorize";

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
    my $me = "QueueCategorize";
    print <<".";
Usage: $me [OPTION(s)]
Spawn off tasks that categorize tokens files from the queue directory.

Directories used are:

$recategorize_directory
$unknown_directory
$queue_directory
$program_source
$log_directory

  -c, --child       number of child tasks to dump the urls
                    default is $opt_child.
					
  -n, --noqueue     don't look for a running QueueStart program

  -h, --help        display this help and exit
  -v, --version     display version information and exit
.
    exit( 3 );
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "QueueCategorize";

    print <<".";
$me $_version
.
    exit( 4 );
}



################################################################################

__END__

:endofperl
