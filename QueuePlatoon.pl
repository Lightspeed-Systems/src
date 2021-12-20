################################################################################
#!perl -w
#
# QueuePlatoon - Do all the functions of an Army Queue Platoon Leader
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



# Options
my $opt_help;
my $opt_version;



# Directories used by QueuePlatoon
my $program_source				= 'I:\\Content\\bin';
my $program_dest				= 'J:\\Content\\bin';
my $program_local				= 'C:\\Content\\bin';


# Theses next two directories are different values than in QueueStart
my $keywords_src				= 'I:\\Content\\Keywords';
my $keywords_dest				= 'J:\\Content\\Keywords';


my $opt_prog_dir				= 'J:\\DonePrograms';	# This is the root directory of the program done directory
my $categorize_done_directory	= 'J:\\DoneTokens';		# This is the root of the categorize done directory


# These are my archive directory and the archive backup directory
my $main_dest_directory			= 'I:\\HashArchive';	# This is the root of the main archive directory
my $backup_dest_directory;								# This is the root of the backup archive directory


my @programs = (	"Categorize.exe",
					"DumpTokens.exe",
					"QueueStart.exe",
					"QueueCategorize.exe",
					"QueueDump.exe",
					"Archive.exe",
					"PArchive.exe",
					"QueuePlatoon.exe",
					"AnalyzeImage.dll",
					"IAEngine.dll",
					"IAImageReader.dll",
					"ssleay32.dll"
			   );


my $log_directory				= 'C:\\Content\\Log';		# This is the directory to write the logs to


my $_version = "1.0.0";
my $curdir;



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
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &StdHeader( "QueuePlatoon" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	# Figure out the current drive letter and add it to any directories that need it
	$curdir = getcwd;
	$curdir =~ s#\/#\\#gm;
	
	
	# Figure out the hostname
	my $hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );


	&MakeDirectory( $log_directory );
	
	my $logfile = "$log_directory\\QueuePlatoon.log";
	&SetLogFilename( $logfile, undef );
		
	if ( ! -e $logfile )
		{	&BadError( "Could not open logfile $logfile\n" );
		}
		

	# Make sure all the required directories exist
	&CheckDirectories();


	my $done;
	
	while ( ! $done )
		{	&KeywordsCheck();
			
			&ExecutePArchive();
			
			&ExecuteArchive();
				
			# Wait for a few minutes
			lprint "QueuePlatoon: Waiting for 5 minutes to loop the QueuePlatoon ...\n";
			sleep( 5 * 60 );	
			
			# Make sure all the required directories exist
			&CheckDirectories();

			$done = &ProgramsCheck();
		}


	chdir( $curdir );
	
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
	&MakeDirectory( $keywords_dest ) if ( ! -d $keywords_dest );

	if ( ! -d $keywords_dest )
		{	&BadError( "Can not find keywords destination directory $keywords_dest\n" );
		}

	if ( ! -d $keywords_src )
		{	&BadError( "Can not find keywords source directory $keywords_src\n" );
		}

	&MakeDirectory( $program_dest ) if ( ! -d $program_dest );

	if ( ! -d $program_dest )
		{	&BadError( "Can not find program destination directory $program_dest\n" );
		}

	if ( ! -d $program_source )
		{	&BadError( "Can not find program source directory $program_source\n" );
		}

	if ( ! -d $program_local )
		{	&BadError( "Can not find program local directory $program_local\n" );
		}

	&MakeDirectory( $opt_prog_dir ) if ( ! -d $opt_prog_dir );

	if ( ! -d $opt_prog_dir )
		{	&BadError( "Can not find program download directory $opt_prog_dir\n" );
		}

	&MakeDirectory( $categorize_done_directory ) if ( ! -d $categorize_done_directory );

	if ( ! -d $categorize_done_directory )
		{	&BadError( "Can not find categorize done directory $categorize_done_directory\n" );
		}

	&MakeDirectory( $log_directory ) if ( ! -d $log_directory );

	if ( ! -d $log_directory )
		{	&BadError( "Can not find log directory $log_directory\n" );
		}

	if ( ! -d $main_dest_directory )
		{	&BadError( "Can not find archive directory $main_dest_directory\n" );
		}

	if ( ( $backup_dest_directory )  &&  ( ! -d $backup_dest_directory ) )
		{	&BadError( "Can not find backup archive directory $backup_dest_directory\n" );
		}

	return( undef );
}



################################################################################
# 
sub BadError( $ )
#
#  Show the error message and exit
#
################################################################################
{	my $err_msg = shift;
	
	$err_msg = "Unknown error\n" if ( ! $err_msg );
	&lprint( "QueuePlatoon fatal error\n" );
	&lprint( $err_msg );
			
	exit( 1 );
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
				{	lprint "QueuePlatoon: Copying $src to $dest ...\n";
					
					my $success = copy( $src, $dest );
			
					if ( ! $success )
						{	lprint "QueuePlatoon: File copy error: $!\n";						
						}
				}
		}
		
	closedir(  DIR );
	
	return( 1 );
}



################################################################################
# 
sub ProgramsCheck()
#
#  Copy any programs that have changed.  Return True if the QueuePlatoon program
#  has changed
#
################################################################################
{
	foreach ( @programs )
		{	next if ( ! $_ );
			
			my $file = $_;
			
			my $prog_src	= $program_source . "\\$file";
			my $prog_dest	= $program_dest . "\\$file";
			
			next if ( ! -f $prog_src );
			
			my $size_src	= -s $prog_src;
			my $size_dest	= -s $prog_dest;
			
			next if ( ! $size_src );
			
			my $changed = 1 if ( ( ! $size_dest )  ||  ( $size_dest != $size_src ) );


			# Are the date/times different?
			if ( ! $changed )
				{	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_src;	
					my $from_mtime = 0 + $mtime;

					( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_dest;
					my $to_mtime = 0 + $mtime;
					
					$changed = 1 if ( $from_mtime != $to_mtime );
				}
				
			if ( $changed )
				{	my $cmd = "changedcopy $prog_src $prog_dest";
					lprint "QueuePlatoon: Program copy command: $cmd\n";
					system $cmd;
				}
		}
		
	
	# Check to see if the QueuePlatoon program itself has changed
	my $prog_src	= $program_source . "\\QueuePlatoon.exe";
	my $prog_dest	= $program_local . "\\QueuePlatoon.exe";
	
	# If the source doesn't exist, then don't worry about it
	return( undef ) if ( ! -f $prog_src );
	
	my $size_src	= -s $prog_src;
	my $size_dest	= -s $prog_dest;

	return( 1 ) if ( ! $size_dest );
	return( 1 ) if ( $size_dest != $size_src );
	
	# Are the date/times different?
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_src;	
	my $from_mtime = 0 + $mtime;

	( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $prog_dest;
	my $to_mtime = 0 + $mtime;
					
	return( 1 ) if ( $from_mtime != $to_mtime );
	
	return( undef );
}



################################################################################
# 
sub ExecutePArchive()
#
#  If the PArchive program isn't running then launch it
#
################################################################################
{	# First find my children
	my %process_hash = &ProcessHash();
	
	my $parchive_count = 0 + 0;
	
	while ( my ( $pid, $process ) = each( %process_hash ) )
		{	my $lc_name = lc( $process );
			
			# Is it a parchive task?
			if ( $lc_name =~ m/\\parchive\.exe/ )
				{	$parchive_count++;
				}
		}
	
	
	# Did I find the PArchive Task?  Return if it is already running
	return( 1 ) if ( $parchive_count );
	
	
	# Copy the latest version of PArchive.exe
	my $prog_src	= $program_source . "\\PArchive.exe";
	my $prog		= "$program_local\\PArchive.exe";
	my $cmd = "changedcopy $prog_src $prog";
	lprint "QueuePlatoon: Program copy command: $cmd\n";
	system $cmd;


	# Now run the program that I just copied
	$cmd = 'PArchive';

	# Launch parchive in the right directory
	chdir( $opt_prog_dir );
	
	my $process;
	
	lprint "QueuePlatoon: Launching $prog in directory $opt_prog_dir ...\n";
	
	my $ok = Win32::Process::Create( $process, $prog, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	
	chdir( $curdir );
	
	if ( ! $ok )
		{	lprint "QueuePlatoon: Error creating PArchive.exe process!\n";
			return( undef );	
		}
	
	return( 1 );	
}



################################################################################
# 
sub ExecuteArchive()
#
#  If the Archive program isn't running then launch it
#
################################################################################
{	# First find my children
	my %process_hash = &ProcessHash();
	
	my $archive_count = 0 + 0;
	
	while ( my ( $pid, $process ) = each( %process_hash ) )
		{	my $lc_name = lc( $process );

			# Is it a archive task?
			if ( $lc_name =~ m/\\archive\.exe/ )
				{	$archive_count++;
				}
		}
	
	# Did I find the Archive Task?  Return if it is already running
	return( 1 ) if ( $archive_count );

	
	# Copy the latest version of Archive.exe
	my $prog_src	= $program_source . "\\Archive.exe";
	my $prog		= "$program_local\\Archive.exe";
	my $cmd = "changedcopy $prog_src $prog";
	lprint "QueuePlatoon: Program copy command: $cmd\n";
	system $cmd;


	# Now run the program that I just copied
	$cmd = "Archive -q -s \"$categorize_done_directory\"";

	# Launch archive in the right directory
	chdir( $categorize_done_directory );
	
	my $process;
	
	lprint "QueuePlatoon: Launching $prog in directory $categorize_done_directory ...\n";
	
	my $ok = Win32::Process::Create( $process, $prog, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	
	chdir( $curdir );
	
	if ( ! $ok )
		{	lprint "QueuePlatoon: Error creating Archive.exe process!\n";
			return( undef );	
		}
	
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
    my $me = "QueuePlatoon";

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
    my $me = "QueuePlatoon";
    print <<".";
Usage: $me [OPTION(s)]
Spawn off tasks that each Platoon leader nneds to run.

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
    my $me = "QueuePlatoon";

    print <<".";
$me $_version
.
    exit( 4 );
}



################################################################################

__END__

:endofperl
