################################################################################
#!perl -w
#
# FileRetrieve Loop around retrieving URLs and categorizing forever
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use Content::File;


# Options
my $opt_help;
my $opt_version;
my $opt_source_directory		= "G:\\Content\\retrieve";
my $opt_tmp_directory			= 'C:\\Content\\retrieve';
my $opt_final_directory			= 'C:\\Content\\retrieve\\processed';
my $opt_recategorize_directory	= 'G:\\Content\\recategorize';


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
        "d|directory=s" =>	\$opt_source_directory,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &StdHeader( "FileRetrieve" );

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
		
	if ( ! -d $opt_recategorize_directory )
		{	&FatalError( "Can not find directory $opt_recategorize_directory\n" );
		}


	chdir( $opt_tmp_directory );
	

	# Loop forever
	while ( 1 )
		{	# Process the source directory
			opendir DIR, $opt_source_directory;

			my $file;
			while ( $file = readdir( DIR ) )
				{	# Skip subdirectories
					next if (-d $file);
			
			
   					my $src		= $opt_source_directory . "\\" . $file;
					my $dest	= $opt_tmp_directory . "\\" . $file;
					my $final	= $opt_final_directory . "\\" . $file;
					
					
					my $missing_file = "missing." . $file;
					my $missing	= $opt_tmp_directory . "\\" . $missing_file;
					my $missing_final = $opt_recategorize_directory . "\\" . $missing_file;
			
			
					my $unknown_file = "unknown." . $file;
					my $unknown	= $opt_tmp_directory . "\\" . $unknown_file;
					my $unknown_final = $opt_recategorize_directory . "\\" . $unknown_file;
					
					
					# Does the file exist?  It might have been deleted by another task
					next if ( ! -e $src );
					
					print "\nProcessing file $file ...\n";
					
					
					print "\nCopying $src to $dest\n";
					my $success = copy( $src, $dest );
					if ( ! $success )
						{	print "File copy error: $!\n";
							next;
						}
				
				
					print "\nDeleting file $src\n";
					$success = unlink( $src );
					if ( ! $success )
						{	print "Error deleting $src, $!\n";
						}
					
					
					my $cmd = "retrieve $dest -m $missing";
					print "Running the retrieve command = $cmd\n";	
					system $cmd; 
			
			
					# Move the missing file to the recategorize directory if it has anything in it
					if ( -s $missing )
						{	print "\nMoving $missing to final location $missing_final\n";
							$success = move( $missing, $missing_final );
							if ( ! $success )
								{	print "File move error: $!\n";
								}
						}
					else
						{	print "\nDeleting empty file $missing\n";
							unlink( $missing );
						}
						
						
					$cmd = "categorize -u $unknown";
					print "Running the categorize command = $cmd\n";
					system $cmd; 

			
					# Move the unknown file to the recategorize directory if it has anything in it
					if ( -s $unknown )
						{	print "\nMoving $unknown to final location $unknown_final\n";
							$success = move( $unknown, $unknown_final );
							if ( ! $success )
								{	print "File move error: $!\n";
								}
						}
					else
						{	print "\nDeleting empty file $unknown\n";
							unlink( $unknown );
						}
						

					print "\nMoving $dest to final location $final\n";
					$success = move( $dest, $final );
					if ( ! $success )
						{	print "File move error: $!\n";
						}
					
					
					print "\nDeleting the tokens files in directory $opt_tmp_directory\n";
					system "del *.tokens.txt";
					system "del *.links.txt";
					system "del *.labels.txt";
					

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
    my $me = "FileRetrieve";

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
    my $me = "FileRetrieve";
    print <<".";
Usage: $me [OPTION(s)]
Checks G:\\content\\retrieve for lists of urls to retrive and categorize.
When new files come in, grab then, and then retrieve the URLs to disk,
and run the categorize command.
If nothing is going on, sleep for 10 minutes before checking for more files.

Directories used are:

c:\\content\\retrieve
c:\\content\\retrieve\\processed
g:\\content\\recategorize
g:\\content\\retrieve

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
