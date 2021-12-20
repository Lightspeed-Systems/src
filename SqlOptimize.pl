################################################################################
#!perl -w
#
#  SqlOptimize - sweep through the database, cleaning up everything, 
#  and rebuilding indexes
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use Benchmark;


use Content::File;
use Content::SQL;
use Content::Optimize;
use Pack::PackSQL;



my $opt_help;
my $opt_version;
my $opt_rebuild_rows;			# True if all I should do is rebuild the rows table
my $opt_rebuild_index;			# True if all I should do is rebuild the indexes to all the content tables
my $opt_wizard;					# True if run from the Wizard, and I don't want html headers
my $opt_shrink;					# True if I should shrink the databases only
my $opt_duplicates;				# True if I should remove duplicate domain names
my $opt_debug;
my $opt_truncate;
my $opt_check_index;
my $opt_no_sql_timeout;			# True if I should not do any SQL sleeping
my $opt_name_compress;			# True if I should name compress
my $opt_category;
my $opt_set_url_bit;
my $opt_purge_errors;			# True if I should purge out errors
my $sql_logging_options;		# True if I should reset the Content database logging options
my $opt_app;
my $opt_yyy;					# True if running a special purpose function
my $opt_journaling;				# True if I should optimize the IpmIndex message journaling database
my $opt_express;				# If True, and running on SQL express, then do the daily maintenance




my  $dbh;             #  My database handle
my	$dbhStat;
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
        "a|check"		=> \$opt_check_index,
        "b|app"			=> \$opt_app,
        "c|category=s"	=> \$opt_category,
        "d|duplicate"	=> \$opt_duplicates,
        "e|express"		=> \$opt_express,
        "i|index"		=> \$opt_rebuild_index,
        "j|journal"		=> \$opt_journaling,
        "l|logging"		=> \$sql_logging_options,
        "n|name"		=> \$opt_name_compress,
        "p|purge"		=> \$opt_purge_errors,
        "r|rows"		=> \$opt_rebuild_rows,
        "s|shrink"		=> \$opt_shrink,
        "t|timeout"		=> \$opt_no_sql_timeout,
        "u|url"			=> \$opt_set_url_bit,
        "w|wizard"		=> \$opt_wizard,
        "v|version"		=> \$opt_version,
		"x|xdebug"		=> \$opt_debug,
        "y|yyy"			=> \$opt_yyy,
        "h|help"		=> \$opt_help
       );


	&StdHeader( "SQLOptimize" ) if ( ! $opt_wizard );
	
    &Usage() if ( $opt_help );

	&SetLogFilename( "SqlOptimize.log", undef );
	my $log_filename = &GetLogFilename();
	lprint "SqlOptimize log file set to $log_filename\n";
	
	
	# Catch any errors 
	&TrapErrors() if ( ! $opt_debug );
	

	if ( $opt_no_sql_timeout )
		{	SqlSleepOff();
			&lprint( "Turned off all SQL sleeping timeouts\n" );
		}
		
		
     $dbh = &ConnectServer();
	 if ( ! $dbh )
		{	&FatalError( "Unable to connect to the Content database\n" );
			exit( 0 );	
		}


	$dbhStat = &ConnectStatistics();
	 if ( ! $dbhStat )
		{	$dbh->disconnect if ( $dbh );

			&FatalError( "Unable to connect to the Statistics database\n" );
			exit( 0 );	
		}


	 my $sql_version = &SqlVersion();
	 lprint "$sql_version\n" if ( $sql_version );
	 if ( $opt_version )
		{
			$dbh->disconnect if ( $dbh );
			$dbhStat->disconnect if ( $dbhStat );

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
		
		
	 if ( $opt_express )
		{	if ( &SqlExpress() )
				{	&SqlExpressDailyStoredProcedures( $dbhStat );
				}
			else
				{	lprint "The installed SQL server is not a SQL Express version\n";
				}
			
			$dbh->disconnect if ( $dbh );
			$dbhStat->disconnect if ( $dbhStat );

			&StdFooter if ( ! $opt_wizard );

			exit;
		}
		

	 if ( $opt_shrink )
		{	# Shrink the Content database
			&ShrinkContentDatabase();

			&ShrinkStatisticsDatabase();
			
			&lprint( "Shrinking the Index database ...\n" );
			&PackSqlShrinkDatabase();
			
			$dbh->disconnect if ( $dbh );
			$dbhStat->disconnect if ( $dbhStat );

			&StdFooter if ( ! $opt_wizard );

			exit;
		}
		
		
	 if ( $opt_truncate )
		{	# Shrink the Content database
			&SqlTruncateRows();
			
			$dbh->disconnect if ( $dbh );
			$dbhStat->disconnect if ( $dbhStat );

			&StdFooter if ( ! $opt_wizard );

			exit;
		}
		
		
	# Keep track of how long it takes to scan
	my $start = new Benchmark;
		
	
	&lprint( "Loading categories ...\n" );	
	&LoadCategories();


	if ( $opt_rebuild_index )
		{	&SqlRebuildIndexes();
		}
	elsif ( $opt_rebuild_rows )
		{	&SqlRebuildRows();
		}
	elsif ( $opt_app )
		{	&ApplicationProcesses();
		}
	elsif ( $opt_check_index )
		{	# Check the index fragmentation
			&SqlCheckIndexFragmentation();

			&SqlCheckIndexes();
		}
	elsif ( $opt_journaling )
		{	&PackSqlPurgeCurrent();
		}
	elsif ( $sql_logging_options )
		{	&SetSQLLoggingOptions();
		}
	elsif ( $opt_duplicates )
		{	&RemoveDuplicateURLs();
			&RemoveDuplicateIPAddresses();
			&RemoveDuplicateDomains();
			&RemoveDuplicateApplicationProcesses();
			&RemoveInvalidApplicationProcesses();
		}
	elsif ( $opt_purge_errors )
		{	&SqlPurgeErrors();
		}
	elsif ( $opt_name_compress )
		{	&ConsolidateDomainNames( $opt_category );
		}
	elsif ( $opt_set_url_bit )
		{	&SetUrlBit();
		}
	elsif ( $opt_yyy )
		{	&ErrorLongDomainNames();
		}
	else
		{	&SqlOptimize( $opt_rebuild_rows );
		}
		
		
	$dbh->disconnect if ( $dbh );
	$dbhStat->disconnect if ( $dbhStat );


	# Calc the benchmark statistics
	my $finish = new Benchmark;

	my $diff = timediff($finish, $start);
	my $strtime = timestr( $diff );

	lprint "Program execution time $strtime\n";
	
	
	&StdFooter if ( ! $opt_wizard );

exit;
}

exit;
################################################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename;
	my $dir = &SoftwareDirectory();

	$filename = $dir . "\\SqlOptimizeErrors.log";
	
	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or &lprint( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	&lprint( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SQLOptimize";

    bprint <<".";
Usage: $me
There are no command line arguments.

This utility checks, compresses, and optimizes the ContentDatabase using a
variety of methods.  Normally this is executed by the IpmCategorize command
automatically once a day.

This utility can be run at any time with no problems, but during the URL
optimization pass (which may take a few minutes), URLs that are blocked with
domains that are not blocked may not be handled correctly.

 -a   checks the indexes and rebuilds them if necessary
 -b   checks and updates the ApplicationProcesses tables
 -c   category for domain name consolidation.
 -e   do the daily maintenance on SQL Express
 -d   delete duplicate domains, IP addresses, and file IDs
 -i   rebuilds the indexes only.
 -j   optimize IpmIndex message journaling database
 -l   reset Content database logging options
 -n   do a domain name consolidate by category.
 -p   purge errors only.
 -r   rebuilds the fast lookup rows only.
 -s   shrinks the Content and Statistics databases.
 -t   run as fast as possible with no SQL timeouts
 -u   optimize long URL lookups only
 
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
    my $me = "SQLOptimize";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



__END__

:endofperl
