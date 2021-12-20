################################################################################
#!perl -w
#
# Utility program to run on the opndb servers to keep them in sync
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;



# Options
my $opt_help;
my $opt_version;
my $opt_time = 60;	# The number of seconds to wait before downloading again
my $opt_program_directory = "C:\\Program Files\\Lightspeed Systems\\Traffic";
my $opt_program = "IpmContentXMLTransfer -n";
my $opt_once;	# True if I should just run once

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
        "p|program=s" => \$opt_program,
        "d|directory=s" => \$opt_program_directory,
        "o|once" => \$opt_once,
        "t|time=s" => \$opt_time,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	print "Update the database just once\n" if ( $opt_once );


	# Loop forever
	while ( 1 )
		{	print "Changing to directory $opt_program_directory\n";			
			chdir( $opt_program_directory );
			
			print "Calling transfer program $opt_program ...\n";
			system( $opt_program );
			
			last if ( $opt_once );
			
			# Go to sleep for 1 minute until checking the directory again
			print "Waiting for $opt_time seconds before restarting ... \n";
			sleep( $opt_time );
			print "Restarting ...\n";
		}


    exit;
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "UpdateDB";

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
    my $me = "UpdateDB";
    print <<".";
Usage: $me [OPTION(s)]  input-file
Runs continuously the update database program, with one minute pauses.

Command line options:

-t, --time   to set the time between updates, in seconds
    
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "FileCategorize";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
