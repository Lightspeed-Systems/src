################################################################################
#!perl -w
#
# Loop around processing Websense URL files
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
use Content::Category;
use Content::SQL;



my $websense_directory			= "F:\\Content\\websense";
my $websense_errors				= "F:\\Content\\WebsenseErrors";

my $queue_directory				= 'C:\\Content\\Queue';
my $program_source				= 'F:\\Content\\bin';
my $log_directory				= 'C:\\Content\\Log';		# This is the directory to write the logs to

my $status_directory			= 'C:\\Content\\Status\\HOSTNAME';
my $status_filename				= 'C:\\Content\\Status\\HOSTNAME.log';

my $websense_hold_file			= ".websense_hold.txt";



# Options
my $opt_help;
my $opt_version;
my $opt_child				= 0 + 3;   # How many child tasks to launch to categorize a lot of urls
my $_version = "1.0.0";
my $home_dir;
my $opt_restart;
my $opt_dns_lookup;				# If True then do a DNS lookup for each domain before checking it



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
        "c|child=i"		=> \$opt_child,
        "d|dns"			=> \$opt_dns_lookup,
        "r|restart"		=> \$opt_restart,
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help
    );

    &StdHeader( "QueueWebsense" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	# Figure out the current drive letter and add it to any directories that need it
	my $curdir = getcwd;
	$curdir =~ s#\/#\\#gm;
	$home_dir = $curdir;
	
	
	# Figure out the hostname
	my $hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );


	# Use the hostname to figure out the queue directory
	$status_directory		=~ s/HOSTNAME/$hostname/;
	$status_filename		=~ s/HOSTNAME/$hostname/;
		
	
	# Make sure all the required directories exist
	&CheckDirectories();


	my $my_pid = &ProcessGetCurrentProcessId();
	&SetLogFilename( "$log_directory\\QueueWebsense$my_pid.log", undef );


	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;


	&CleanUpQueue() if ( $opt_restart );
	
	lprint "Looking up domain names in DNS before querying Websense ...\n" if ( $opt_dns_lookup );


	lprint "Starting $opt_child child processes of QueueWebsense running ...\n";
	
	my  $pid;
	for ( my $i = 0;  $i < $opt_child - 1;  $i++ )
		{	#  Now fork off my child processes
			FORK:
				{
					if ( $pid = fork )
						{	lprint "Started child process $pid\n"; 
							sleep 12;  # Sleep for 12 seconds to give the child time to get started 
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

	
	# Loop forever
	while ( 1 )
		{	
			# Get an open queue directory
			my $open_queue_directory = &GetOpenQueueDirectory();
			
			
			# Check to make sure that the SQL servers are still going if I have a queue directory
			my $sql_ok = &QueueWebsenseSqlCheck() if ( $open_queue_directory );
			
			
			# Did I get an open queue directory and a good SQL connection?
			my $found_file;
			
			if ( ( $open_queue_directory )  &&  ( $sql_ok ) )
				{	# Process the source directory
					opendir( DIR, $websense_directory );

					my @allfiles = sort readdir( DIR );
					
					closedir(  DIR );
					
					foreach ( @allfiles )
						{	my $file = $_;
							next if ( ! defined $file );
							
							next if ( $file =~ m/^zz/i );
							next if ( length( $file ) > 64 );
							
							my $fullfile = "$websense_directory\\$file";
							
							# Skip subdirectories
							next if ( -d $fullfile );
					
							# Is it still there?
							next if ( ! -f $fullfile );
							
							my $nospace_file = $file;
							$nospace_file =~ s/\s/\_/g;	# Make sure that I don't have any spaces in the file name
							
							my $rand    = int rand( 1000 );
   							my $src		= $websense_directory . "\\" . $file;
							my $tmpsrc	= $websense_directory . "\\zz" . $nospace_file . ".rand$rand";
							my $dest	= $open_queue_directory . "\\" . $nospace_file . ".rand$rand";
					
					
							# Does the file exist?  It might have been deleted by another task
							next if ( ! -e $src );
							
							lprint "Processing file $file ...\n";
							lprint "Renaming $src to $tmpsrc\n";
					
							my $success = rename( $src, $tmpsrc );
					
							if ( ! $success )
								{	lprint "File rename error: $!\n";
									next;
								}
							
							# Does the file exist?  It might have been renamed by another task
							next if ( ! -e $tmpsrc );
							
							
							lprint "Moving $tmpsrc to $dest\n";
					
							$success = move( $tmpsrc, $dest );
					
							if ( ! $success )
								{	lprint "File move error: $!\n";
									next;
								}
								
							# Does the file exist?  It might have been deleted by another task
							next if ( ! -e $dest );
							
							
							# Copy a fresh version of the Websense file
							my $prog_src	= "$program_source\\Websense.exe";
							my $prog_dest	= "$open_queue_directory\\Websense.exe";
							
							my $cmd = "changedcopy \"$prog_src\" \"$prog_dest\"";
							lprint "Program copy: $cmd\n";
							
							chdir( $open_queue_directory );
							
							system $cmd;
							
							# Did the changedcopy command work?
							my $ok;
							my $fatal;
							
							my $websense_process;	
							if ( -f $prog_dest )
								{	&lprint( "Launching Websense.exe in directory: $open_queue_directory\n" );
									
									# Figure out the shoft file name of the list of URLs that I just moved
									my ( $current_dir, $shortfile ) = &SplitFileName( $dest );

									# Now run the program that I just copied
									$cmd = 'Websense ' . $shortfile;
									$cmd = 'Websense -d ' . $shortfile if ( $opt_dns_lookup );

									# Launch websense.exe and figure out what websense pid I started
									$ok = Win32::Process::Create( $websense_process, $prog_dest, $cmd, 0, NORMAL_PRIORITY_CLASS, $open_queue_directory );
								}
							else
								{	$ok = undef;
									&lprint( "ERROR: Unable to create $prog_dest\n" );
								}
								
								
							# If I created the task ok, did everything go all right from there?
							if ( ( $ok )  &&  ( $websense_process ) )
								{	my $websense_pid = $websense_process->GetProcessID();
							
									# Wait for it to finish
									$websense_process->Wait( INFINITE );
										
									# Get the exitcode
									my $exitcode = 0 + 0;
									$websense_process->GetExitCode( $exitcode );
									
									if ( ( $exitcode != 0 )  &&  ( $exitcode != 256 ) )
										{	$ok = undef;
											&lprint( "Command $cmd terminated with exit code $exitcode ...\n" );
										}
									
									# Did the process create the right log files?
									my $log_file			= "$log_directory\\Websense-$websense_pid.log";
									my $finished_log_file	= "$log_directory\\Websense-$websense_pid.OK";
									
									if ( ! -f $finished_log_file )
										{	$ok = undef;
											&lprint( "The Websense process did not create $log_file!\n" );
											$fatal = 1;
										}
										
									if ( ! -f $finished_log_file )
										{	$ok = undef;
											&lprint( "The Websense process did not create $finished_log_file!\n" );
											$fatal = 1;
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
								
								
							# If I had a problem then try to put everything back together again
							if ( ! $ok )
								{	&QueuePrintStatusFile( "Command $cmd did not terminate normally\n" );
									
									my $errors = $websense_errors . "\\" . $file;
									lprint "Moving $dest back to $errors ...\n";
					
									$success = move( $dest, $errors );
					
									if ( ! $success )
										{	lprint "File move error: $!\n";
										}
											
										
									# Was this a really bad problem?	
									if ( $fatal )	
										{	lprint "Exiting QueueWebsense because of fatal error ...\n";
											&QueuePrintStatusFile( "Command $cmd caused a fatal error so exiting QueueWebsense\n" );
											sleep( 1 );
											&ProcessKillName( "QueueWebsense.exe" );
											
											chdir( $dir );
											sleep( 20 );
											
											&StdFooter();
											
											&QueueFatalError( "Command $cmd caused a fatal error so quitting QueueWebsense\n" );
										}	
								}
							else	# I think that the Websense command did everything right
								{	lprint "Deleting $dest ...\n";
					
									$success = unlink( $dest );
							
									if ( ! $success )
										{	lprint "File delete error: $!\n";
										}
									else
										{	$found_file = 1;
										}
								}
								
							last;	
						}

					lprint "Did not find any URL files to dump ...\n" if ( ! defined $found_file );
				}
			else
				{	lprint "Did not find an open queue directory ...\n";
				}
			
			
			if ( $open_queue_directory )	
				{	# Remove the hold file
					my $full_file = $open_queue_directory . "\\" . $websense_hold_file;
					unlink( $full_file );
				}
				
			if ( ! $found_file )
				{	# Go to sleep for 5 minutes until checking the directory again
					lprint "Waiting for 5 minutes before restarting ... \n";
					sleep( 300 );
					
					# Make sure that all the required directories still exist
					&CheckDirectories();
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
#  Do a fatal error if the don't exist.  Return undef if everything
#  does exist
#
################################################################################
{
	if ( ! -d $websense_directory )
		{	&QueueFatalError( "Can not find directory $websense_directory\n" );
		}

	&MakeDirectory( $queue_directory ) if ( ! -d $queue_directory );
	
	if ( ! -d $queue_directory )
		{	&QueueFatalError( "Can not find queue directory $queue_directory\n" );
		}
		
	&MakeDirectory( $status_directory ) if ( ! -d $status_directory );
	
	if ( ! -d $status_directory )
		{	&QueueFatalError( "Can not find status directory $status_directory\n" );
		}
		
	&MakeDirectory( $websense_errors ) if ( ! -d $websense_errors );
	
	if ( ! -d $websense_errors )
		{	&QueueFatalError( "Can not find errors directory $websense_errors\n" );
		}
	
	&MakeDirectory( $log_directory ) if ( ! -d $log_directory );

	if ( ! -d $log_directory )
		{	&QueueFatalError( "Can not find log directory $log_directory\n" );
		}

	return( undef );
}



################################################################################
# 
sub QueueWebsenseSqlCheck()
#
#  Return True if I can connect to the SQL databases OK
#
################################################################################
{
	# Connect to the category database
	sleep( 10 );
	my $dbh = &ConnectServer();
	if ( ! $dbh )
		{	lprint "Unable to open the IpmContent database on <local> ...\n";
			return( undef );
		}
				
	$dbh->disconnect;

	return( 1 );
}



################################################################################
# 
sub CleanUpQueue()
#
#  Clean up the queue directories for a restart
#
################################################################################
{
	&lprint( "Cleaning up the queue directories before restarting ...\n" );
	
	# Process the queue directory
	if ( ! opendir( QUEUEDIR, $queue_directory ) )
		{	lprint "Error opening the queue directory: $!\n";
			return( undef );
		}

	my @allfiles = sort readdir( QUEUEDIR );
	close( QUEUEDIR );
	
	foreach ( @allfiles )
		{	my $subdir = $_;
			next if ( ! defined $subdir );
			next if ( $subdir eq "." );
			next if ( $subdir eq ".." );
			
			my $full_subdir = $queue_directory . "\\" . $subdir;

			# Only check subdirectories
			next if (! -d $full_subdir );
			
			unlink( "$full_subdir\\Websense.exe" );

			unlink( "$full_subdir\\Websense.unknown" );
			unlink( "$full_subdir\\Websense.known" );
			unlink( "$full_subdir\\Websense.blocked" );
			
			next if ( ! opendir( SUBDIR, $full_subdir ) );
			
			while ( defined( my $file = readdir( SUBDIR ) ) )
				{	next if ( $file eq "." );
					next if ( $file eq ".." );
					
					$file = lc( $file );
					
					# If I find a hold file then the directory is not empty
					if ( $file =~ m/hold\.txt$/i )
						{	my $fullfile = "$full_subdir\\$file";
							unlink( $fullfile );
							last;
						}
				}
				
			closedir( SUBDIR );
		}
		
	
	my $cmd = "del $log_directory\\*.OK";
	system $cmd;

	$cmd = "del $log_directory\\*.log";
	system $cmd;

}



################################################################################
# 
sub GetOpenQueueDirectory()
#
#  Return an empty queue directory, or undef if none exist
#
################################################################################
{
	# Process the queue directory
	if ( ! opendir( QUEUEDIR, $queue_directory ) )
		{	lprint "Error opening the queue directory: $!\n";
			return( undef );
		}

	my $open_queue_directory;
	my $directory_count = 0 + 0;
	
	while ( ( defined( my $subdir = readdir( QUEUEDIR ) ) )  &&  ( ! $open_queue_directory ) )
		{	next if ( $subdir eq "." );
			next if ( $subdir eq ".." );
			
			my $full_subdir = $queue_directory . "\\" . $subdir;


			# Only check subdirectories
			next if (! -d $full_subdir );
				
			next if ( ! opendir( SUBDIR, $full_subdir ) );
			
			my $empty = 1;
			$directory_count++;
			
			while ( ( defined( my $file = readdir( SUBDIR ) ) )  &&  ( $empty ) )
				{	$file = lc( $file );
					
					# If I find a hold file then the directory is not empty
					if ( $file =~ m/hold\.txt$/i )
						{	$empty = undef;
							last;
						}
				}
				
			closedir( SUBDIR );
			
			if ( $empty )
				{	my $full_file = $full_subdir . "\\" . $websense_hold_file;
					
					# Make sure another task hasn't just grabbed this
					if ( -e $full_file )
						{	lprint "Whoops - another task is using directory: $full_subdir\n";
							$open_queue_directory = undef;
						}
					else	
						{	open( HOLDFILE, ">$full_file" );
							close( HOLDFILE );
							
							$open_queue_directory = $full_subdir;
							lprint "Found an open queue directory: $open_queue_directory\n";
						}
				}
		}

	closedir( QUEUEDIR );
	
	if ( ! $directory_count )
		{	lprint "There are no subdirectories in $queue_directory\n";
			return( undef );
		}
		
	return( $open_queue_directory );
}



################################################################################
# 
sub QueueFatalError( $ )
#
#  Something bad has happened and I need to stop
#
################################################################################
{	my $err_msg = shift;
	
	print "QueueWebsense Fatal Error: $err_msg\n";

	&QueuePrintStatusFile( "QueueWebsense Fatal Error: $err_msg\n" );
		
	chdir( $home_dir ) if ( $home_dir );

	&StdFooter();

	exit( 1 );
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
sub UsageError ($)
#
################################################################################
{
    my $me = "QueueWebsense";

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
    my $me = "QueueWebsense";
    print <<".";
Usage: $me [OPTION(s)]
Spawn off 4 tasks that monitor the websense urls directory on drive I:.
When new files come in, grab then, and then check with the Websense server.
If nothing is going on, sleep for 10 minutes before checking for more files.

Directories used are:

$websense_directory
$websense_errors
$queue_directory
$program_source
$log_directory

  -c, --child       number of child tasks to dump the urls
                    default is 4.
  -d, --dns         to do a DNS lookup before checking each URL
  -r, restart       restart and clean up the queue directories
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
    my $me = "QueueWebsense";

    print <<".";
$me $_version
.
    exit( 4 );
}



################################################################################

__END__

:endofperl
