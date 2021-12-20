################################################################################
#!perl -w
#
# Rob McCarthy's WaitFor source code - wait for a running process to finish
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );


use Content::File;
use Content::Process;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_debug;



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
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help,
        "x|xxx"			=> \$opt_debug
    );

 
	my $process = shift;
	&Usage() if ( ! defined $process );
	
	&ProcessSetDebugPrivilege();

	print "Waiting for $process to finish ...\n";

	while ( &ProcessRunningName( $process ) )
		{	sleep( 1 );
		}

	print "$process is not running anymore\n";	

exit( 0 );
}
################################################################################



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "WaitFor";

    print <<".";
Usage: $me PROCESS
Wait For a running process to finish.  PROCESS should be the process name, with extension

  -h, --help       display this help and exit
  -v, --version    display version information and exit
  
.
   &StdFooter;

    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "WaitFor";

    print <<".";
$me $_version
.
   &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl

