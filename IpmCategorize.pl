################################################################################
#!perl -w
#
#  Rob McCarthy's IpmCategorize perl source
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Cwd;
use Win32API::Registry 0.21 qw( :ALL );


use Content::File;
use Content::SQL;
use Content::Optimize;
use Content::SqlReload;
use Content::Categorize;
use Content::SAImport;
use Pack::PackSQL;

use Content::UpdateEvent;

# Options
my $opt_root_dir;						# Directory to look for the keywords file - default is &KeywordsFile()
my $opt_input_file;     				# The file name if supposed to read unknown urls from a file
my $max_tokens = 0 + 3000;				# The maximum number of tokens to read from a URL before quitting - this is usually smaller than when building keywords in IpmBuildKeywords					
my $opt_sensitivity;					# Keyword sensitivity - from 0 to 100, 30 is the default
my $opt_source = 0 + 3;                 # Source number = 4 is default, 3 is Lightspeed
my $opt_recategorize;                   # True if it should recategorize urls If the url alreadys exists in the database and wasn't set by hand
my $opt_no_purge;						# True if to NOT run the SqlOptimize purge
my $opt_show_most_interesting;      	# Show the most interesting picks
my $opt_category;                       # Option for categorizing just one category
my $opt_transfer = 1;					# True if I should not do the SQL transfer at the end of processing
my $opt_version;						# Display version # and exit
my $opt_local;							# True if I should locally categorize URLs
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_debug;							# True if debugging
my $_version = "2.0.0";					# Current version number
my $dbh;								# The global database handle
my $dbhStat;
my %options;							# The options hash to pass to other modules
my $opt_archive;						# If True, then archive the tokens files after categorizing
my $opt_log_file;						# The name of the log file to use
my $opt_output_dir;						# Output the caregorized URLs to domains.his files under the out_output_dir directory
my $opt_noname;							# If True then do no URL by name categorization
my $opt_name = 1;						# This is the flip of opt_noname
my $opt_delete;							# If True then delete any token file that doesn't match the opt_category
my $opt_match_delete;					# If True then delete any token file that does match the opt_category
my $opt_verbose;						# If True then show everything going on
my $recategorize_file;					# The full file name to write urls to that need to be recategorized
my $unknown_file;						# The full file name to write urls to that are unknown
my $opt_week;							# If True then do the weekly optimize process
my $opt_export;							# If True the just do a SecurityAgent export
my $opt_high_volume_reporting;			# If True the just do a high volume reporting clean up



# This is the default list of tables to backup and restore local data for
my @tables = qw( ApplicationProcesses BannedProcesses IntrusionRuleSet IpmContentCategoryHits
IpmContentCategoryMisses IpmContentDomain IpmContentIpAddress IpmContentURL RegistryControl
SpamPatterns VirusSignatures DisinfectScripts );



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
        "a|aaa"				=> \$opt_high_volume_reporting,
        "c|category=s"		=> \$opt_category,
		"e|export"			=> \$opt_export,
		"d|directory=s"		=> \$opt_root_dir,
		"f|logfile=s"		=> \$opt_log_file,
		"i|input=s"			=> \$opt_input_file,
        "k|keywords"		=> \$opt_show_most_interesting,
        "l|local"			=> \$opt_local,
        "n|number=s"		=> \$opt_source,         
        "o|output=s"		=> \$opt_output_dir,
        "p|purge"			=> \$opt_no_purge,
        "r|recategorize"	=> \$opt_recategorize,
        "s|sensitivity=s"	=> \$opt_sensitivity,
        "t|transfer"		=> \$opt_transfer,
        "v|verbose"			=> \$opt_verbose,
		"w|week"			=> \$opt_week,
		"x|xxx"				=> \$opt_debug,
        "h|help"			=> \$opt_help
    );


	# Default the log file name based on the input file name and the current directory
    #  If there still is an argument, it must be the input file name
    if ( $ARGV[0] )   
		{	$opt_input_file = shift;  
		}


	$opt_log_file = $opt_input_file . ".log" if ( $opt_input_file );
	if ( $opt_log_file )
		{	my $dir = getcwd;
			$dir =~ s#\/#\\#gm;

			# Does the opt_logfile incluse a pathname?  If not, use the current directory
			$dir = undef if ( $opt_log_file =~ m/\\/ );
			$opt_log_file = $dir . "\\" . $opt_log_file if ( $dir );
		}
	else
		{	$opt_log_file = "IpmCategorize.log";
		}


    &StdHeader( "IpmCategorize" ) if ( ! $opt_wizard );
    &SetLogFilename( $opt_log_file, undef );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    &UsageError() if ( ( $opt_sensitivity )  &&  ( $opt_sensitivity < 0  ||  $opt_sensitivity > 100 ) );


	# Is there already a conflicting process running?
	if ( &SqlLockConflict() )
		{	&lprint( "A conflicting process is already running so quitting now ...\n" );
			exit( 0 );
		}


	# Do I just need to clean up the High Volume Reporting directory?
	if ( $opt_high_volume_reporting )
		{	&HighVolumeReportingCleanup();
			&StdFooter if ( ! $opt_wizard );

			exit;
		}
		
		
    #  Make sure the source number is either customer automatic (4) or Lightspeed Automatic (3)
    $opt_source = 4 if ( $opt_source < 3 || $opt_source > 4 );


	# If using an output directory make sure that it exists
	if ( ( $opt_output_dir )  &&  ( ! -d $opt_output_dir ) )
		{	&lprint( "Output directory $opt_output_dir does not exist\n" );
			exit( 0 );
		}
 

	&TrapErrors() if ( ! $opt_debug );
	
	
	if ( ! $opt_export )
		{	lprint "No SQL optimize pass\n"				if ( $opt_no_purge );
			lprint "No local categorization\n"			if ( ! $opt_local );
			lprint "No SQL transfer of local data\n"	if ( $opt_transfer );
		}
		
	lprint "Only do an export of the Security Agent update data files\n" if ( $opt_export );


	# Clean out the tmp directory
	&CleanTmpDirectory();


	#  Open the database and load all the arrays
	$dbh = &ConnectServer() or &FatalError( "Unable to open the Content database" );
	&LoadCategories();
	$opt_root_dir = &KeywordsDirectory() if ( ! $opt_root_dir );

	$dbhStat = &ConnectStatistics();
	 if ( ! $dbhStat )
		{	&FatalError( "Unable to connect to the Statistics database\n" );
			exit( 0 );	
		}


	# Update the transaction time on critical security agent tables
	&UpdateTransactionTimeSA();
	
	
	# Export all the Security agent files
	# 4/4/2011 -- Don't do this anymore. IpmMonitor will handle all of this for us!
	#9/19/2011 -- make this an option
	# Commented back out by Rob M on 9/30/2011
#	&SAExport() if ( $opt_export );
	
	# In case something changed -- signal the SA (if installed)
	&SignalService();
	
	# Is that all I am supposed to do?
	if ( $opt_export )
		{	&StdFooter if ( ! $opt_wizard );
			
			#  Close up the databases and quit
			$dbh->disconnect if ( $dbh );
			$dbhStat->disconnect if ( $dbhStat );
			exit;
		}
			
	
	
	# Should I categorize the URLs locally?
	if ( $opt_local )
		{	# Build up the options hash to use to pass to the categorize module
			%options = (
				"database handle"		=> $dbh,
				"recategorize"			=> $opt_recategorize,
				"root dir"				=> $opt_root_dir,
				"input file"			=> $opt_input_file,
				"show most interesting"	=> $opt_show_most_interesting,
				"sensitivity"			=> $opt_sensitivity,
				"source"				=> $opt_source,
				"category"				=> $opt_category,
				"max tokens"			=> $max_tokens,
				"output dir"			=> $opt_output_dir,
				"name"					=> $opt_name,
				"delete"				=> $opt_delete,
				"matchdelete"			=> $opt_match_delete,
				"verbose"				=> $opt_verbose,
				"recategorizefile"		=> $recategorize_file,
				"unknownfile"			=> $unknown_file,
				"debug"					=> $opt_debug,
				"archive"				=> $opt_archive
				);

			&CategorizeOptions( \%options );
			&Categorize( undef );
		}


	# Run anything that the SQL Agent process normally does for us
	&SqlExpressDailyStoredProcedures( $dbhStat );
	
		
	# Transfer any requested Statistics tables if it is Saturday
#	my $ok = &SqlStatTransfer( $dbhStat ) if ( $wday == 6 );
	

	# Transfer any locally modifed database entries if sharing is enabled
	my $ok = &SqlTransfer( $dbh, undef, undef, undef, @tables ) if ( ! $opt_transfer );


	#  Clean up the database 
	if ( ! $opt_no_purge )
		{	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );

			# If Saturday then do the once a week stuff
			if ( ( $wday == 6 )  ||  ( $opt_week ) )
				{	lprint "Running the weekly database optimize process ...\n";
					
					&HighVolumeReportingCleanup();
					
					&SetSQLLoggingOptions();
					
					&ShrinkContentDatabase();

					&TableCounts();
			
					&SetUrlBit();
					
					&SqlPurgeErrors();
					
					&PackSqlPurgeCurrent();
					
					&ShrinkStatisticsDatabase();
					
					&PackSqlShrinkDatabase();
				}
				
			if ( &SqlMSDE() )
				{	lprint "MSDE SQL version\n";
					&SqlTruncateRows();
				}
			elsif ( &NoRowTableKey() )
				{	lprint "Full SQL version with row tables NOT enabled\n";
					&SqlTruncateRows();
				}
			
			&SqlCheckIndexFragmentation();
			
			&SqlCheckIndexes();
			
			&CleanTmpDirectory();
		}


	# Update the transaction time on critical security agent tables
	&UpdateTransactionTimeSA();
	

	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );
	$dbhStat->disconnect if ( $dbhStat );


	
	&StdFooter if ( ! $opt_wizard );

   exit;
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $dir = &SoftwareDirectory();

	my $filename = "$dir\\IpmCategorizeErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	lprint( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "IpmCategorize";

    bprint "$_[0]\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
.
    &StdFooter;

    exit;
}



################################################################################
# 
sub HighVolumeReportingCleanup()
#
# The High Volume Reporting option saves a bunch of files on disk. Sooner or 
# later they gotta be cleaned up
#
################################################################################
{	my  $key;
    my  $type;
    my  $data;
  
	lprint( "Checking to see if there is any High Volume Reporting data to purge ...\n" ); 
  
    my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\Data Host", 0, KEY_READ, $key );

	# If the key is totally missing, just return
    return( undef )  if ( ! $ok );
	
    $ok = &RegQueryValueEx( $key, "High Volume Storage", [], $type, $data, [] );
	if ( ! $ok )
		{	&RegCloseKey( $key );
			return( undef );
		}
	
	# Should be a 4 byte dword	
	if ( length( $data ) != 4 )
		{	&RegCloseKey( $key );
			return( undef );
		}

	if ( $data eq "\x00\x00\x00\x00" )
		{	&RegCloseKey( $key );
			return( undef );
		}

	
    $ok = &RegQueryValueEx( $key, "High Volume Path", [], $type, $data, [] );
	if ( ! $ok )
		{	&RegCloseKey( $key );
			return( undef );
		}

	# If I didn't read any data at all out of the registry, then I must not be using HVR
	if ( ! length( $data ) )
		{	&RegCloseKey( $key );
			return( undef );
		}
		
	if ( ! length( $data ) < 0 )
		{	&RegCloseKey( $key );
			return( undef );
		}
	
	if ( ! $data )
		{	&RegCloseKey( $key );
			return( undef );
		}

	my $path = $data;
	
    $ok = &RegQueryValueEx( $key, "High Volume Retention Days", [], $type, $data, [] );

	# If I didn't read any data at all out of the registry, then I must not be using HVR
	if ( ! $ok )
		{	&RegCloseKey( $key );
			return( undef );
		}

	if ( ! length( $data ) )
		{	&RegCloseKey( $key );
			return( undef );
		}
		
	if ( ! length( $data ) < 0 )
		{	&RegCloseKey( $key );
			return( undef );
		}
	
	# Should be a 4 byte dword
	if ( length( $data ) != 4 )
		{	&RegCloseKey( $key );
			return( undef );
		}
		
	if ( ! $data )
		{	&RegCloseKey( $key );
			return( undef );
		}

	&RegCloseKey( $key );


	# Check the path
	if ( ! -d $path )
		{	&lprint( "Unable to find the High Volume Path: $path\n" );
			return( undef );
		}
		
		
	# Convert the dword to an int
	my $days = unpack( "L", $data );
		
	
	# Calculate the oldest time that I want to retain
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() - ( $days * 24 * 60 * 60 ) );
	$year = 1900 + $year;
	$mon = $mon + 1;
	$mon = sprintf( "%02d", $mon );
	
 	&lprint( "Cleaning out High Volume Reporting data older than year $year month $mon ...\n" );
	
	
	if ( ! opendir( HVRDIR, $path ) )
		{	&lprint( "Error opening directory $path: $!\n" );
			return( undef );
		}
		
		
	lprint "Using starting directory $path ...\n";

	# Read the year directories
	while ( my $year_dir = readdir( HVRDIR ) )
		{	# Skip the dot dirs
			next if ( $year_dir eq "." );
			next if ( $year_dir eq ".." );
			
			# Make sure the year is valid numbers and the right size
			next if ( length( $year_dir ) != 4 );
			next if ( $year_dir =~ m/^D/ );
			next if ( $year_dir lt "2006" );
			next if ( $year_dir gt "2100" );

			# Skip if newer
			next if ( $year_dir gt $year );
			
			my $path_year = "$path\\$year_dir";
			
			# Skip if not a subdirectory
			next if ( ! -d $path_year );
			
			&CleanupYear( $path_year, $year_dir, $year, $mon, $mday );
			
			# Remove the year directory if it is too old
			next if ( $year_dir ge $year );
			
			my $ok = rmdir( $path_year );
			&lprint( "Error removing directory $path_year: $!\n" ) if ( ! $ok );
		}
				
	closedir( HVRDIR );
	
	return( 1 );
}



################################################################################
# 
sub CleanupYear( $ $$$$ )
#
# Cleanup directories and files that are too old
#
################################################################################
{	my $path_year	= shift;
	
	my $year_dir	= shift;
	my $year		= shift;
	my $mon			= shift;
	my $mday		= shift;
	
	
	lprint "Checking for old data from $year_dir ...\n";

	if ( ! opendir( HVR_YEAR_DIR, $path_year ) )
		{	&lprint( "Error opening directory $path_year: $!\n" );
			return( undef );
		}

	# Read the month directories inside the year directory
	while ( my $mon_dir = readdir( HVR_YEAR_DIR ) )
		{	# Skip the dot dirs
			next if ( $mon_dir eq "." );
			next if ( $mon_dir eq ".." );
			
			# Make sure the directory name makes sense
			next if ( length( $mon_dir ) != 2 );
			next if ( $mon_dir =~ m/\D/ );	# Make sure the month is all digits
			next if ( $mon_dir lt "01" );
			next if ( $mon_dir gt "12" );
			
			my $path_year_mon = "$path_year\\$mon_dir";
			
			# Skip if not a subdirectory
			next if ( ! -d $path_year_mon );

			# If the year is the same and the month is the same, then clean up the days inside the month
			if ( ( $year_dir eq $year )  &&  ( $mon_dir eq $mon ) )
				{	&CleanupCurrentMonth( $path_year_mon, $mday );
					next;	
				}
			
			# Skip if the year is the same, skip the month that is larger
			next if ( ( $year_dir eq $year )  &&  ( $mon_dir gt $mon ) );
						
			&CleanupYearMonth( $path_year_mon );
			
			my $ok = rmdir( $path_year_mon );
			&lprint( "Error removing directory $path_year_mon: $!\n" ) if ( ! $ok );
		}
				
	closedir( HVR_YEAR_DIR );
	
	return( 1 );
}



################################################################################
# 
sub CleanupYearMonth( $ )
#
# Given the path to a months worth of HVR data, delete all the files
#
################################################################################
{	my $path_year_mon	= shift;
	
	lprint "Cleaning out $path_year_mon ...\n";

	if ( ! opendir( HVR_YEAR_MON_DIR, $path_year_mon ) )
		{	&lprint( "Error opening directory $path_year_mon: $!\n" );
			return( undef );
		}

	# Delete the files inside the month directory
	while ( my $file = readdir( HVR_YEAR_MON_DIR ) )
		{	# Skip the dot dirs
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			# Make sure the file matches "URLs-day.x.tab
			next if ( ! ( $file =~ m/^URLs/ ) );
			next if ( ! ( $file =~ m/\.tab$/ ) );
			
			my $full_path = "$path_year_mon\\$file";
			
			# Skip if not a file
			next if ( -d $full_path );

			my $ok = unlink( $full_path );
			&lprint( "Error deleting file $full_path: $!\n" ) if ( ! $ok );
		}
				
	closedir( HVR_YEAR_MON_DIR );
	
	return( 1 );
}



################################################################################
# 
sub CleanupCurrentMonth( $$ )
#
# Cleanup the older data in the current month's directory
#
################################################################################
{	my $path_year_mon	= shift;
	my $mday			= shift;
	
	$mday += 0;
	lprint "Cleaning out $path_year_mon for days older than day $mday ...\n";

	if ( ! opendir( HVR_YEAR_MON_DIR, $path_year_mon ) )
		{	&lprint( "Error opening directory $path_year_mon: $!\n" );
			return( undef );
		}

	# Delete the files inside the month directory
	while ( my $file = readdir( HVR_YEAR_MON_DIR ) )
		{	# Skip the dot dirs
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			# Make sure the file matches "URLs-day.x.tab
			next if ( ! ( $file =~ m/^URLs/ ) );
			next if ( ! ( $file =~ m/\.tab$/ ) );
			
			# Figure out the day from the file name
			my ( $file_day, $junk ) = split /\./, $file, 2;
			next if ( ! $junk );
			( $junk, $file_day ) = split /\-/, $file_day, 2;
			next if ( ! $file_day );
			next if ( $file_day =~ m/\D/ );	# Make sure the file day is all digits
			
			$file_day += 0;
						
			# Don't delete days that are the same or after our mday
			next if ( $file_day >= $mday );

			my $full_path = "$path_year_mon\\$file";
			
			# Skip if not a file
			next if ( -d $full_path );
			
			my $ok = unlink( $full_path );
			&lprint( "Error deleting file $full_path: $!\n" ) if ( ! $ok );
		}
				
	closedir( HVR_YEAR_MON_DIR );
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmCategorize";

    bprint <<".";
Usage: $me [OPTION(s)] [urlfile]
Categorizes unknown URLs using the keywords for each category
Command argument will be assumed to be file name of a list of URLs.

Default dir is "\\Software Directory\\Website\\Reports\\ContentFilter\\keywords"

  -a                     purge any High Volume Reporting data
  -c, --category=name    to specify a single category to check the unknown URLs
  -d, --directory=PATH   to change default files directory
  -e, --export           to just do an export of the SecurityAgent data
  -f, --logfile          the name of the log file to use - default is 
                         IpmCategorize.log
  -h, --help             display this help and exit
  -i, --input=FILE       input file of URLs, default is from Content database
  -k, --keywords         show the keywords used to categorize each url
  -l, --local            to locally categorize URLs
  -n, --number=NUM       set the source number of new entries (3 or 4 only)
  -p, --purge            to NOT run the SqlOptimize purge
  -r, --recategorize     override existing categories unless set by hand
  -s, --sensitivity      keyword sensitivity, 30 default, 100 most aggressive
  -t, --notransfer       to NOT transfer local database to Lightspeed
  -w, --week             to do the weekly database optimization
  
  -v, --version          display version information and exit
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
    my $me = "IpmCategorize";

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
