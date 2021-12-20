################################################################################
#!perl -w
#
# Loop around dumping URLs to files forever into Queue directories
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



my $recategorize_directory		= "F:\\Content\\recategorize";
my $dump_errors					= "C:\\Content\\DumpErrors";

my $dump_directory				= 'C:\\Content\\Dump';
my $opt_final_directory			= 'C:\\Content\\Dump\\processed';

my $queue_directory				= 'C:\\Content\\Queue';
my $program_source				= 'J:\\Content\\bin';
my $log_directory				= 'C:\\Content\\Log';		# This is the directory to write the logs to
my $tmp_directory				= 'C:\\Content\\tmp';		# This is the tmp directory to download programs to
my $opt_prog_dir				= 'J:\\DonePrograms';		# This is the root directory of the program done directory
my $keywords_dest				= 'C:\\Content\\keywords';

my $status_directory			= 'I:\\Content\\Status\\HOSTNAME';
my $status_filename				= 'I:\\Content\\Status\\HOSTNAME.log';
my $dumplog_filename			= 'I:\\Content\\Status\\Dumplog.HOSTNAME.log';

my $dump_hold_file				= ".dump_hold.tokens.txt";
my $categorize_hold_file		= ".categorize_hold.txt";



# Options
my $opt_help;
my $opt_version;
my $opt_child				= 0 + 3;   # How many child tasks to launch to categorize a lot of urls
my $_version = "1.0.0";
my $home_dir;



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
        "d|directory=s" =>	\$recategorize_directory,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &StdHeader( "QueueDump" );

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
	$dumplog_filename		=~ s/HOSTNAME/$hostname/;
		
	
	# Make sure all the required directories exist
	&CheckDirectories();


	my $my_pid = &ProcessGetCurrentProcessId();
	&SetLogFilename( "$log_directory\\QueueDump$my_pid.log", undef );


	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;


	lprint "Starting $opt_child child processes of QueueDump running ...\n";
	
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


	my $queue_start_pid = &ProcessNamePID( "QueueStart" );

	
	# Loop forever
	while ( 1 )
		{	# Make sure my QueueStart is still running - if not, then die
			if ( ( ! &ProcessRunningName( "QueueStart" ) )  ||  ( ! &ProcessPIDName( $queue_start_pid ) ) )
				{	lprint "Parent program QueueStart is not running, so quitting myself now ...\n";
					&QueuePrintStatusFile( "Parent program QueueStart is not running, so quitting QueueDump now ...\n" );
					sleep( 1 );
					chdir( $dir );
					&ProcessKillName( "QueueDump.exe" );
					&ProcessTerminate( $my_pid );
					
					&StdFooter();
					
					&QueueFatalError( "Parent program QueueStart is not running so quitting QueueDump\n" );
				}
			
			
			# Get an open queue directory
			my $open_queue_directory = &GetOpenQueueDirectory();
			
			
			# Check to make sure that the SQL servers are still going if I have a queue directory
			my $sql_ok = &QueueDumpSqlCheck() if ( $open_queue_directory );
			
			
			# Did I get an open queue directory and a good SQL connection?
			my $found_file;
			
			if ( ( $open_queue_directory )  &&  ( $sql_ok ) )
				{	# Process the source directory
					
					opendir( DIR, $recategorize_directory );

					# I have to get a sorted list because the BSD servers do not give a sorted directory from readdir
					my @allfiles = sort readdir( DIR );
					
					foreach ( @allfiles )
						{	my $file = $_;
							next if ( ! defined $file );
							
							# Ignore files that already start with zz so that I don't go into a never ending loop
							next if ( $file =~ m/^zz/i );
							next if ( length( $file ) > 128 );
						
							my $fullfile = "$recategorize_directory\\$file";
							
							# Skip subdirectories
							next if ( -d $fullfile );
					
							my $nospace_file = $file;
							$nospace_file =~ s/\s/\_/g;	# Make sure that I don't have any spaces in the file name for DumpTokens
							
							my $rand    = int rand( 1000 );
   							my $src		= $recategorize_directory . "\\" . $file;
							my $tmpsrc	= $recategorize_directory . "\\zz" . $nospace_file . ".rand$rand";
							my $dest	= $dump_directory . "\\" . $nospace_file . ".rand$rand";
							my $final	= $opt_final_directory . "\\" . $nospace_file;
					
					
							# Does the file exist?  It might have been deleted by another task
							next if ( ! -e $src );
							
							lprint "Processing file $file ...\n";
							lprint "Renaming $src to $tmpsrc\n";
					
							my $success = rename( $src, $tmpsrc );
					
							if ( ! $success )
								{	lprint "File rename error: $!\n";
									sleep( 5 );
									next;
								}
							
							# Wait a second for the file system to catch up
							sleep( 1 );
							
							# Does the file exist?  It might have been renamed by another task
							if ( ! -e $tmpsrc )
								{	lprint "$tmpsrc not found after rename ...\n";
									sleep( 10 );
									next;	
								}
							
							
							lprint "Moving $tmpsrc to $dest\n";
					
							$success = move( $tmpsrc, $dest );
					
							if ( ( ! $success )  ||  ( ! -e $dest ) )
								{	lprint "File move error: $!\n";
									
									# Try to rename the file back
									lprint "Trying to rename the file back to $src ...\n";
									$success = rename( $tmpsrc, $src );
									sleep( 10 );
									next;
								}
							
								
							# Get rid of the tmp file if the move went weird
							unlink( $tmpsrc );
							
							# Keep track of the files that I have tried to dump
							open( DUMPLOG, ">>$dumplog_filename" );
							
							my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
							$year = 1900 + $year;
							$mon = $mon + 1;
							my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );

							print DUMPLOG "$datestr : $src\n";
							
							close( DUMPLOG );
							
							
							# Copy a fresh version of the ssleay32.dll Open SSL DLL file
							my $dll_src	= "$program_source\\ssleay32.dll";
							my $dll_dest	= "$open_queue_directory\\ssleay32.dll";
							
							my $cmd = "changedcopy \"$dll_src\" \"$dll_dest\"";
							lprint "Program copy: $cmd\n";

							# Copy a fresh version of the DumpTokens file
							my $prog_src	= "$program_source\\DumpTokens.exe";
							my $prog_dest	= "$open_queue_directory\\Dumptokens.exe";
							
							$cmd = "changedcopy \"$prog_src\" \"$prog_dest\"";
							lprint "Program copy: $cmd\n";
							
							chdir( $open_queue_directory );
							
							system $cmd;
							
							# Did the changedcopy command work?
							my $ok;
							my $fatal;
							
							my $dumptokens_process;	
							if ( -f $prog_dest )
								{	
									
									&lprint( "Launching DumpTokens.exe in directory: $open_queue_directory\n" );
									
									# Now run the program that I just copied
									$cmd = 'DumpTokens ' . $dest . ' ' . $open_queue_directory;

									# Launch dumptokens and figure out what dumptokens pid I started
									$ok = Win32::Process::Create( $dumptokens_process, $prog_dest, $cmd, 0, NORMAL_PRIORITY_CLASS, $open_queue_directory );
								}
							else
								{	$ok = undef;
									&lprint( "ERROR: Unable to create $prog_dest\n" );
								}
								
								
							# If I created the task ok, did everything go all right from there?
							if ( ( $ok )  &&  ( $dumptokens_process ) )
								{	my $dumptokens_pid = $dumptokens_process->GetProcessID();
							
									# Wait for it to finish
									$dumptokens_process->Wait( INFINITE );
										
									# Get the exitcode
									my $exitcode = 0 + 0;
									$dumptokens_process->GetExitCode( $exitcode );
									
									if ( ( $exitcode != 0 )  &&  ( $exitcode != 256 ) )
										{	$ok = undef;
											&lprint( "Command $cmd terminated with exit code $exitcode ...\n" );
										}
									
									# Did the process create the right log files?
									my $log_file			= "$log_directory\\DumpTokens-$dumptokens_pid.log";
									my $finished_log_file	= "$log_directory\\DumpTokens-$dumptokens_pid.OK";
									
									if ( ! -f $finished_log_file )
										{	$ok = undef;
											&lprint( "The DumpTokens process did not create $log_file!\n" );
										}
										
									if ( ! -f $finished_log_file )
										{	$ok = undef;
											&lprint( "The DumpTokens process did not create $finished_log_file!\n" );
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
									
									my $errors = $dump_errors . "\\" . $file;
									lprint "Moving $dest back to $errors ...\n";
					
									$success = move( $dest, $errors );
					
									if ( ! $success )
										{	lprint "File move error: $!\n";
										}
											
										
									# Was this a really bad problem?	
									if ( $fatal )	
										{	lprint "Exiting QueueDump because of fatal error ...\n";
											&QueuePrintStatusFile( "Command $cmd caused a fatal error so exiting QueueDump\n" );
											sleep( 1 );
											&ProcessKillName( "QueueDump.exe" );
											
											chdir( $dir );
											sleep( 20 );
											
											&StdFooter();
											
											&QueueFatalError( "Command $cmd caused a fatal error so quitting QueueDump\n" );
										}	
								}
							else	# I think that the DumpTokens command did everything right
								{	lprint "Moving $dest to final location $final\n";
					
									$success = move( $dest, $final );
							
									if ( ! $success )
										{	lprint "File move error: $!\n";
										}
									else
										{	$found_file = 1;
										}
								}
								
							last;	
						}

					closedir( DIR );
					
					lprint "Did not find any URL files to dump ...\n" if ( ! defined $found_file );
				}
			else
				{	lprint "Did not find an open queue directory ...\n";
				}
			
			
			if ( ! $found_file )
				{	# Go to sleep for 5 minutes until checking the directory again
					lprint "Waiting for 5 minutes before restarting ... \n";
					sleep( 300 );
					
					# Make sure that all the required directories still exist
					&CheckDirectories();
				}
				
				
			# Remove the hold file if I created it
			if ( $open_queue_directory )	
				{	# Remove the hold file
					my $full_file = $open_queue_directory . "\\" . $dump_hold_file;
					unlink( $full_file );
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
	if ( ! -d $recategorize_directory )
		{	&QueueFatalError( "Can not find directory $recategorize_directory\n" );
		}

	&MakeDirectory( $queue_directory ) if ( ! -d $queue_directory );
	
	if ( ! -d $queue_directory )
		{	&QueueFatalError( "Can not find queue directory $queue_directory\n" );
		}
		
	&MakeDirectory( $status_directory ) if ( ! -d $status_directory );
	
	if ( ! -d $status_directory )
		{	&QueueFatalError( "Can not find status directory $status_directory\n" );
		}
		
	&MakeDirectory( $dump_directory ) if ( ! -d $dump_directory );
	
	if ( ! -d $dump_directory )
		{	&QueueFatalError( "Can not find dump directory $dump_directory\n" );
		}
	
	&MakeDirectory( $opt_final_directory ) if ( ! -d $opt_final_directory );
	
	if ( ! -d $opt_final_directory )
		{	&QueueFatalError( "Can not find dump directory $opt_final_directory\n" );
		}
		
	if ( ! -d $keywords_dest )
		{	&QueueFatalError( "Can not find keywords destination directory $keywords_dest\n" );
		}

	&MakeDirectory( $opt_prog_dir ) if ( ! -d $opt_prog_dir );

	if ( ! -d $opt_prog_dir )
		{	&QueueFatalError( "Can not find program archive directory $opt_prog_dir\n" );
		}

	&MakeDirectory( $log_directory ) if ( ! -d $log_directory );

	if ( ! -d $log_directory )
		{	&QueueFatalError( "Can not find log directory $log_directory\n" );
		}

	&MakeDirectory( $tmp_directory ) if ( ! -d $tmp_directory );

	if ( ! -d $tmp_directory )
		{	&QueueFatalError( "Can not create tmp directory $tmp_directory\n" );
		}

	return( undef );
}



################################################################################
# 
sub QueueDumpSqlCheck()
#
#  Return True if I can connect to the SQL databases OK
#
################################################################################
{
	# Connect to the category database
	my $dbhCategory = &CategoryConnect();
	if ( ! $dbhCategory )
		{	lprint "Unable to open the Remote Category database ...\n";
		}
				
	
	# Connect to the program database			
	my $dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{	lprint "Unable to open the Remote Program database ...\n";
		}

	# Give it 2 seconds before closing
	sleep( 2 );

	&CategoryClose()	if ( $dbhCategory );	
	&ProgramClose()		if ( $dbhProgram );

	return( undef )		if ( ! $dbhCategory );
	return( undef )		if ( ! $dbhProgram );

	return( 1 );
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
			
			while ( ( $empty )  &&  ( defined( my $file = readdir( SUBDIR ) ) ) )
				{	$file = lc( $file );
					
					# If I find a dump hold file then the directory is not empty
					if ( $file =~ m/\.dump_hold\.tokens\.txt$/ )
						{	$empty = undef;
						}
						
					# If I find a links file then the directory is not empty
					if ( $file =~ m/links\.txt$/ )
						{	$empty = undef;
						}
						
					# If I find a tokens file then the directory is not empty
					if ( $file =~ m/tokens\.txt$/ )
						{	$empty = undef;
						}
						
					# If I find a site file then the directory is not empty
					if ( $file =~ m/site\.txt$/ )
						{	$empty = undef;
						}
				}
				
			closedir( SUBDIR );
			
			if ( $empty )
				{	my $full_file = $full_subdir . "\\" . $dump_hold_file;
					
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

	closedir QUEUEDIR;
	
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
	
	print "QueueDump Fatal Error: $err_msg\n";

	&QueuePrintStatusFile( "QueueDump Fatal Error: $err_msg\n" );
		
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
    my $me = "QueueDump";

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
    my $me = "QueueDump";
    print <<".";
Usage: $me [OPTION(s)]
Spawn off 4 tasks that monitor the recategorize urls directory drive G.
When new files come in, grab then, and then dump the URLs to disk.
If nothing is going on, sleep for 10 minutes before checking for more files.

Directories used are:

$recategorize_directory
$dump_directory
$opt_final_directory
$queue_directory
$program_source
$log_directory

  -c, --child       number of child tasks to dump the urls
                    default is 4.
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
    my $me = "QueueDump";

    print <<".";
$me $_version
.
    exit( 4 );
}



################################################################################

__END__

:endofperl
