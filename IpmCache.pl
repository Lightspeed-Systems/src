################################################################################
#!perl -w
#
# Rob McCarthy's IpmCache source code
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



use strict;
use Getopt::Long;
use Content::Cache qw( :log );
use Sys::Hostname;
use Content::File;
use HTTP::Request;
use IO::Socket;
use Win32API::Registry 0.21 qw( :ALL );
use Fcntl qw(:DEFAULT :flock);



my $opt_help;			# True if I should just display the help and exit
my $opt_version;		# True if I should just display the version and exit
my $opt_logging;		# True if I should log to the file IpmCache.log
my $opt_logall;			# True if I should log all, instead of just status
my $_version = "1.0.0";
my $debug;				#  True if debugging



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "IpmCache" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "a|all" => \$opt_logall,
        "l|logging" => \$opt_logging,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	
	
	# Figure out my IP address
	my $myhostname = hostname();	
	my $ipaddress = inet_ntoa( ( gethostbyname( $myhostname ) )[ 4 ] );


	# Create the cache object
	my $cache = Content::Cache->new( port => 8080, ipaddress => $ipaddress );

	
	# Set the level of logging info
	my $logging = NONE;
	$logging = STATUS if ( $opt_logging );
	$logging = ALL if ( $opt_logall );
	$opt_logging = 1 if ( $opt_logall );
	
	if ( $logging == NONE )  { print "No logging\n"; }
	elsif ( $logging == STATUS )  { print "Status logging only\n"; }
	elsif ( $logging == ALL )  { print "All events logged\n"; }
	
	$cache->logmask( $logging ); # NONE - Log only errors STATUS - Requested URL, reponse status and total number of connections processed PROCESS - Subprocesses information (fork, wait, etc.) HEADERS - Full request and response headers are sent along FILTER - Filter information ALL - Log all of the above

    # Get the log file set to go ...
	my $LOG = *STDERR;
	$LOG = &CacheOpenLogFile() if ( $opt_logging );
	$cache->logfh( $LOG );


    # Set the remaining options ...
	$cache->maxchild( 0 );
	$cache->timeout( 30 );  # Set to a 30 second timeout
	

	# Start working ...	
	$cache->start;


	&StdFooter;

exit;
}
################################################################################




################################################################################
# 
sub CacheOpenLogFile()
#
#  Open the file for logging events
#
################################################################################
{
    my  $key;
    my  $type;
    my  $data;

  
    my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

    $ok = RegQueryValueEx( $key, "Software Directory", [], $type, $data, [] )  if ( $ok );
	
	RegCloseKey( $key );

    $data = "C:\\IpMagic\\"  if ( !$ok );

    #  Default the file name to use - if it hasn't been set
    my $logFileShortName = "IpmCache.log";
	
    my $logFileName = $data . $logFileShortName;

	my $LOGFILEHANDLE;
	
    # If debugging, append to the file
    if ( $debug )
      {  open $LOGFILEHANDLE, ">>$logFileName";  }
	else
      {  open $LOGFILEHANDLE, ">$logFileName";  }
	  
    print "$logFileName log file opened\n"; 

    return( $LOGFILEHANDLE );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "IpmCache";

    bprint "$me\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
.
   &StdFooter;

    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmCache";

    bprint <<".";
Usage: $me [OPTION(s)]
IpmCache optimizes the local IIS server by caching to give faster response to
local web pages.

  -a, --all      log all events to the IpmCache.log file
  -l, --logging  log just requests and responses to the IpmCache.log file
  -h, --help     display this help and exit
  -v, --version  display version information and exit
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
    my $me = "IpmCache";

    bprint <<".";
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
