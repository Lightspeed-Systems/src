################################################################################
#!perl -w
#
# Loop around proxy testing lists of domains and IP addresses
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


use Content::File;
use Content::Process;



# Options
my $opt_help;
my $opt_version;
my $opt_child				= 0 + 3;   # How many child tasks to launch to proxy test
my $opt_source_directory	= "G:\\Content\\proxytest";
my $opt_tmp_directory		= 'C:\\Content\\proxy';
my $opt_final_directory		= 'C:\\Content\\proxy\\processed';
my $opt_program_directory	= 'C:\\Content\\bin';


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
    (
        "c|child=i"		=>	\$opt_child,
        "d|directory=s" =>	\$opt_source_directory,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &StdHeader( "QueueProxyTest" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	&SetLogFilename( "$opt_tmp_directory\\QueueProxyTest.log", undef );


	if ( ! -d $opt_source_directory )
		{	&FatalError( "Can not find directory $opt_source_directory\n" );
		}

	if ( ! -d $opt_tmp_directory )
		{	&FatalError( "Can not find directory $opt_tmp_directory\n" );
		}

	if ( ! -d $opt_final_directory )
		{	&FatalError( "Can not find directory $opt_final_directory\n" );
		}
		
	if ( ! -d $opt_program_directory )
		{	&FatalError( "Can not find directory $opt_program_directory\n" );
		}
		

	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;


	lprint "Starting $opt_child processes of QueueProxyTest running ...\n";
	
	
	my $pid;
	my $child = 0 + 0;
	
	for ( $child = 1;  $child < $opt_child;  $child++ )
		{	#  Now fork off my child processes
			FORK:
				{
					if ( $pid = fork )
						{	lprint "Started child process # $child: pid $pid\n"; 
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
		{	my $file;
			
			# Process the source directory
			opendir DIR, $opt_source_directory;

			while ( $file = readdir( DIR ) )
				{
					# Skip subdirectories
					next if (-d $file);
			
					
					my $rand    = int rand( 1000 );
   					my $src		= $opt_source_directory . "\\" . $file;
					my $tmpsrc	= $opt_source_directory . "\\zz" . $file . ".rand$rand";
					my $dest	= $opt_tmp_directory . "\\" . $file . ".rand$rand";
					my $final	= $opt_final_directory . "\\" . $file;
			
			
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
					
					
					# Copy a fresh version of the IpmProxyTest.exe file
					my $prog_src	= "f:\\content\\bin\\IpmProxyTest.exe";
					my $prog_dest	= "$opt_program_directory\\IpmProxyTest.exe";
					
					my $cmd = "changedcopy $prog_src $prog_dest";
					lprint "Program copy: $cmd\n";
					
					chdir( $opt_tmp_directory );
					
					system $cmd;
					
					lprint "Launching IpmProxyTest.exe in directory: $opt_tmp_directory\n";
					
					# Now run the program that I just copied
					my $logfile = "IpmProxyTest$child.log";
					
					$cmd = "IpmProxyTest -a -o -s 3 -f $logfile " . $dest;

					lprint "IpmProxyTest cmd: $cmd\n";
					
					system $cmd; 
			
					lprint "Moving $dest to final location $final\n";
			
					$success = move( $dest, $final );
			
					if ( ! $success )
						{	lprint "File move error: $!\n";
						}

					last;	
				}

			closedir DIR;
			
			lprint "Did not find any files to proxy test ...\n" if ( ! defined $file );
				
				
			if ( ! defined $file )
				{	# Go to sleep for 5 minutes until checking the directory again
					lprint "Waiting for 5 minutes before restarting ... \n";
					sleep( 300 );
				}
		}


	chdir( $dir );

    exit;
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "QueueProxyTest";

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me
Try '$me --help' for more information.
.
    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "QueueProxyTest";
    print <<".";
Usage: $me [OPTION(s)]
Spawns off 3 tasks that monitor the directory g:\\content\\proxytest directory
on drive G.  When new files come in, grabs them, and then runs the IpmProxyTest
program to test them.

Directories used are:

c:\\content\\proxy
c:\\content\\proxy\\processed
g:\\content\\proxytest

  -c, --child       number of child tasks to dump the urls
                    default is 3.
  -h, --help        display this help and exit
  -v, --version     display version information and exit
.
    exit;
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
    exit;
}



################################################################################

__END__

:endofperl
