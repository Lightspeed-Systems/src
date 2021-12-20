################################################################################
#!perl -w
#
# Rob McCarthy's AutowhiteCheck source code
#  Copyright 2006 Lightspeed Systems Corp.
#
# Go through the autowhite list table and see if I am overblocking
# domains and IP addresses
#
################################################################################



# Pragmas
use strict;
use warnings;

use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;


use Content::File;
use Content::SQL;



# Options
my $opt_help;
my $opt_version;
my $opt_verbose;
my $opt_debug; 										# True if I should write to a debug log file
my $opt_filename = "AutowhiteCheck.txt";


# Globals
my $_version = "1.0.0";
my $dbh;
my $dbhStat;										# My database handle



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "AutowhiteCheck" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
		"f|file=s"		=> \$opt_filename,
		"v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help,
        "x|xxx"			=> \$opt_debug
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


	&SetLogFilename( "AutowhiteCheck.log", undef );
	
	
    #  Open the databases
     $dbh = &ConnectServer();
	 if ( ! $dbh )
		{	&FatalError( "Unable to connect to the Content database\n" );
			exit( 0 );	
		}


	$dbhStat = &ConnectStatistics();
	 if ( ! $dbhStat )
		{	&FatalError( "Unable to connect to the Statistics database\n" );
			exit( 0 );	
		}


	&lprint( "Loading categories ...\n" );	
	&LoadCategories();

	
	&AutowhiteCheck();
	

	#  Clean up everything and quit
	$dbh->disconnect if ( $dbh );
	$dbh = undef;

	$dbhStat->disconnect if ( $dbhStat );
	$dbhStat = undef;
	
	&StdFooter;

exit( 0 );
}
################################################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $dir = &SoftwareDirectory();
	my $filename = $dir . "\\SuspiciousQueryErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or die( "Unable to open $filename: $!\n" );  
		
	&CarpOut( $MYLOG );
   
	&debug( "Fatal error trapping set to file $filename\n" ); 
}



################################################################################
# 
sub AutowhiteCheck()
#
#  Go through the autowhite list to see if I am overblocking any domains or IP
#  addresses
#
################################################################################
{	
	if ( ! open( FILE, ">$opt_filename" ) )
		{
		}
		
		
	&lprint( "Reading autowhite list entries ...\n" );
	
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "SELECT Comp FROM AutoWhiteList" );
	
	$sth->execute();
	
	my %from_domains;
	my $counter = 0 + 0;
	while ( my $comp = $sth->fetchrow_array() )
		{	last if ( ! defined $comp );
		   
			my ( $to, $from ) = split /\:/, $comp, 2;
		   
			next if ( ! $from );
		   
			my ( $user, $domain ) = split /\@/, $from;
		   
			next if ( ! $domain );
		
			my $root = &RootDomain( $domain );
			
			next if ( ! $root );
			
			$counter++;
			if ( $from_domains{ $root } )
				{	$from_domains{ $root }++;
				}
			else
				{	$from_domains{ $root } = 0 + 1;
				}
		}
	   
	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	&lprint( "Read $counter autowhite list entries\n" );
			
	
	&lprint( "Looking up autowhite list domains ...\n" );
	my $domains = 0 + 0;
	$counter = 0 + 0;	
	
	my @keys = sort keys %from_domains;
	
	foreach ( @keys )
		{	my $root = $_;
			next if ( ! $root );
			
			$domains++;
			
			my $retcode = &LookupUnknown( $root, 0 );
			next if ( ! $retcode );
			
			my ( $catnum, $source ) = &FindCategory( $root, $retcode );
			my $catname = &CategoryName( $catnum );
			next if ( ! $catname );
			
			# Is it spam?
			my $spam = 1 if ( $catname =~ /spam/i );
			
			
			# Is this domain unblocked and not spam?
			next if ( ( ! $spam )  &&  ( $retcode > 3 ) );
			
			
			my $count = $from_domains{ $root };
			print FILE "$root\t\t$catname\t$count\n";
			
			$counter++;
		}
	
	my $unblocked = $domains - $counter;
	
	&lprint( "Found $unblocked unique unblocked root domains\n" );
	&lprint( "Wrote $counter unique blocked root domains to $opt_filename\n" );
	
	close( FILE );
}



################################################################################
# 
sub errstr($)
#  
################################################################################
{
    bprint shift;

    return( -1 );
}



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     lprint( @_ );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "AutowhiteCheck";

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
    my $me = "AutowhiteCheck";

    bprint <<".";
Usage: $me
This utility goes through autowhite list table, checking to see it domains
and/or IP addresses are being overblocked.

  -h, --help             display this help and exit
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
    my $me = "Suspicious Query";

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
