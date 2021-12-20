################################################################################
#!perl -w
#
# Loop around dumping URLs to files forever
#
################################################################################



# Pragmas
use strict;
use Socket;
use Errno qw(EAGAIN);
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use Content::File;


# Options
my $opt_help;
my $opt_version;
my $opt_child				= 0 + 4;   # How many child tasks to launch to categorize a lot of urls
my $opt_source_directory	= "G:\\Content\\recategorize";
my $opt_tmp_directory		= 'C:\\Content\\dump';
my $opt_final_directory		= 'C:\\Content\\dump\\processed';
my $token_files_directory	= 'C:\\Content\\dumptokens';


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
        "c|child=s"		=>	\$opt_child,
        "d|directory=s" =>	\$opt_source_directory,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &StdHeader( "FileDump" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	if ( ! -d $opt_source_directory )
		{	&FatalError( "Can not find directory $opt_source_directory\n" );
		}

	if ( ! -d $opt_tmp_directory )
		{	&FatalError( "Can not find directory $opt_tmp_directory\n" );
		}

	if ( ! -d $opt_final_directory )
		{	&FatalError( "Can not find directory $opt_final_directory\n" );
		}
		
	if ( ! -d $token_files_directory )
		{	&FatalError( "Can not find directory $token_files_directory\n" );
		}


	my  $pid;
	for ( my $i = 0;  $i < $opt_child - 1;  $i++ )
		{	#  Now fork off my child processes
			FORK:
				{
					if ( $pid = fork )
						{	print "Started child process $pid\n"; 
							sleep 2;  # Sleep for 2 seconds to give the child time to get started 
							next;
						}

					elsif ( defined $pid )
						{	print "Child process started\n";
							goto CONTINUE;
						}

					elsif ( $! == EAGAIN )
						{	sleep 5;
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
		{	# Process the source directory
			opendir DIR, $opt_source_directory;

			my $file;
			while ( $file = readdir( DIR ) )
				{
					# Skip subdirectories
					next if (-d $file);
			
   					my $src		= $opt_source_directory . "\\" . $file;
					my $dest	= $opt_tmp_directory . "\\" . $file;
					my $final	= $opt_final_directory . "\\" . $file;
			
					# Does the file exist?  It might have been deleted by another task
					next if ( ! -e $src );
					
					print "Processing file $file ...\n";
					print "Copying $src to $dest\n";
			
					my $success = copy( $src, $dest );
			
					if ( ! $success )
						{	print "File copy error: $!\n";
							next;
						}
				
				
					print "Deleting file $src\n";
					$success = unlink( $src );
					
					if ( ! $success )
						{	print "Error deleting $src, $!\n";
						}
												
					my $cmd = 'DumpTokens ' . $dest . ' ' . $token_files_directory;

					system $cmd; 
			
					print "Moving $dest to final location $final\n";
			
					$success = move( $dest, $final );
			
					if ( ! $success )
						{	print "File move error: $!\n";
						}
						
					# Bail out here so that I re-read the directory and get the files to process alphabetically
					last;
				}

			closedir DIR;
			
			if ( ! $file )
				{	# Go to sleep for 10 minutes until checking the directory again
					print "Waiting for 10 minutes before restarting ... \n";
					sleep( 600 );
				}
		}


    exit;
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "FileDump";

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
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
    my $me = "FileDump";
    print <<".";
Usage: $me [OPTION(s)]
Spawn off 3 tasks that monitor the recategorize urls directory drive G.
When new files come in, grab then, and then dump the URLs to disk.
If nothing is going on, sleep for 10 minutes before checking for more files.

Directories used are:

c:\\content\\dump
c:\\content\\dump\\processed
g:\\content\\recategorize
c:\\content\\dumptokens

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
    my $me = "FileDump";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
