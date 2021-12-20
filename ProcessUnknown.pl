################################################################################
#!perl -w
#
# Loop around Processing Unknown files forever
# Changed on 11/22/2014 by Rob McCarthy for the new QueueContent processing
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use File::Copy;
use DBI qw(:sql_types);
use DBD::ODBC;


use Content::File;
use Content::SQL;
use Content::Category;
use Content::Categorize;


# Options
my $opt_help;
my $opt_version;
my $opt_no_category;			# If true then I shouldn't connect to the category database
my $opt_clear_old_unknowns;


my $opt_source_directory	= "W:\\Content\\unknown";
my $opt_tmp_directory		= "C:\\tmp";
my $opt_final_directory		= "V:\\Content\\recategorize\\normal";

my $dbh;
my $dbhCategory;

my $max_in_memory			= 0 + 200000;	# This is the approximate maximum number of unique domains to hold in memory before dumping to disk
my $output_file_size		= 0 + 100;		# The size of each output file - 100 is roughly the number of domains 1 task can download in 1/2 hour



my $_version = "1.0.0";
my %domains;
my %recent_unknown;
my %recent_error;
my %looked_up;



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
        "c|clear"		=>	\$opt_clear_old_unknowns,
        "n|nocategory"	=>	\$opt_no_category,
        "d|directory=s" =>	\$opt_source_directory,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );


    &StdHeader( "ProcessUnknown" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	
	my $tmp_line = shift;
	$opt_source_directory = $tmp_line if ( $tmp_line );
	

	if ( ! -d $opt_source_directory )
		{	&FatalError( "Can not find directory $opt_source_directory\n" );
		}

	if ( ! -d $opt_tmp_directory )
		{	&FatalError( "Can not find directory $opt_tmp_directory\n" );
		}

	if ( ! -d $opt_final_directory )
		{	&FatalError( "Can not find directory $opt_final_directory\n" );
		}
		
		
	print "Opening a connection to the local SQL database ...\n";
	$dbh = &ConnectServer();
	if ( ! $dbh )
		{	print "Unable to connect to the Content database\n";
			exit;	
		}


	# Connect to the category database
	if ( ! $opt_no_category )
		{	$dbhCategory = &CategoryConnect();
			if ( ! $dbhCategory )
				{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";
					exit( 10 );
				}
		}
		

	if ( ( ! $opt_no_category )  &&  ( $opt_clear_old_unknowns ) )
		{	# Get rid of older recent unknowns ...
			#  Figure out 1 month ago ( 30 days ) time in the correct format
			my $time_sec = time() - ( 30 * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $time_sec );
			$year = 1900 + $year;
			$mon = $mon + 1;	 
			my $datestr = sprintf( "%02d\/%02d\/%04d", $mon, $mday, $year );
			
			print "Cleaning out older recent unknown URLs ...\n";
			my $str = "DELETE RecentUnknown WHERE TransactionTime < \'$datestr\' AND TransactionTime IS NOT NULL";
			my $sth = $dbhCategory->prepare( $str );
			$sth->execute();
			
			my $rows = 0 + $sth->rows;
			print "Deleted $rows rows\n" if ( $rows );
			
			$sth->finish();
		}
		

	&ProcessUnknown( $opt_source_directory );
	
	
	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );
	&CategoryClose() if ( $dbhCategory );


	print "\nDone\n";
	
    exit;
}



################################################################################
# 
sub ProcessUnknown( $ )
#
################################################################################
{	my $source_directory = shift;

	return( undef ) if ( ! $source_directory );

	print "Processing unknown URLs from directory $source_directory ...\n";
	
	# Process the source directory
	opendir( DIR, $source_directory );

	%domains = ();

	my $file;
	my $counter = 0 + 0;
	my $last_file;
			
	while ( $file = readdir( DIR ) )
		{	next if ( $file eq "." );
			next if ( $file eq ".." );
			
   			my $src	= $source_directory . "\\" . $file;
			my $tmp	= $opt_tmp_directory . "\\" . $file;
	
			# Skip subdirectories
			next if (-d $src);
	
			# Does the file exist?  It might have been deleted by another task
			next if ( ! -e $src );
			
			print "Processing file $file ...\n";
			print "Copying $src to $tmp\n";
	
			my $success = copy( $src, $tmp );
	
			if ( ! $success )
				{	print "File copy error: $!\n";
					next;
				}
		
		
			print "Deleting source file $src\n";
			$success = unlink( $src );
			
			if ( ! $success )
				{	print "Error deleting source $src: $!\n";
				}
				
				
			# Keep track of the last file name used so that I can use it for the output file names
			$last_file = $file;
			
			# Remove any white space in the file name
			$last_file =~ s/\s//g if ( $last_file );
			
			if ( ! $last_file )
				{	my $time = time();
					$last_file = "unknown-$time.txt";
				}
				
			open( TMPFILE, "<$tmp" ) or next;
			
			my $tmp_counter = 0 + 0;
			my $add_counter = 0 + 0;
			my $line_counter = 0 + 0;
			my $print_counter = 0 + 0;
			
			print "Reading temp file $tmp ...\n";
			
			while ( my $line = <TMPFILE> )
				{	chomp( $line );
					next if ( ! $line );
					my $url = $line;
					
					$tmp_counter++;
					$line_counter++;
					$print_counter++;
					
					if ( $print_counter >= 1000 )
						{	print "Read $line_counter lines from $tmp\n";
							$print_counter = 0 + 0;	
						}
						
					my $clean_url = &CleanUrl( $url );
					next if ( ! defined $url );
					
					my $root = &RootDomain( $clean_url );
					next if ( ! defined $root );
					
					
					# Is the domain already in one of the hashes?
					if ( exists $domains{ $root } )
						{	# Keep track of all of the readable urls that I have
							next if ( ! &ReadableUrl( $url, $root ) );
							
							# Keep each readable URL in a unique hash
							my $dhash_ref = $domains{ $root };
							$$dhash_ref{ $url } = 1;
							$domains{ $root } = $dhash_ref;
							next;
						}
						
					next if ( exists $looked_up{ $root } );
					next if ( exists $recent_unknown{ $root } );
					next if ( exists $recent_error{ $root } );
					
					
					# Is the domain already in the database?
					my $retcode = &LookupUnknown( $root, 0 );
					if ( $retcode )
						{	$looked_up{ $root } = 1;
							next;	
						}
					
					# Did I just check this domain recently?
					if ( ( ! $opt_no_category )  &&  ( &CategoryRecentUnknown( $root ) ) )
						{	$recent_unknown{ $root } = 1;
							next;	
						}
					
					# Did I just check this domain recenty and find an error?
					if ( ( ! $opt_no_category )  &&  ( &CategoryRecentError( $root ) ) )
						{	$recent_error{ $root } = 1;
							next;	
						}
					
					
					# Add it to my domain hash
					my %dhash;
					$dhash{ $url } = 1;
					$domains{ $root } = \%dhash;
					
					$counter++;
					$add_counter++;
				}
				
			close( TMPFILE );
			
			
			print "Read $line_counter lines from $tmp\n";
			print "Read $tmp_counter URLs from $tmp\n";
			print "Added $add_counter domains\n";
			print "Now have $counter unique domain names in memory\n";
			
			
			# Have I read in a bunch of domains?
			if ( $counter >= $max_in_memory )
				{	&DumpDomains( $opt_final_directory, $last_file );
					$counter = 0 + 0;
					%domains = ();
				}


			print "Deleting temp file $tmp\n";
			$success = unlink( $tmp );
			
			if ( ! $success )
				{	print "Error deleting temp $tmp: $!\n";
				}

		}  # end of $file = readdir( DIR )

	closedir( DIR );
	
	
	# Do I still have some domains in the hash?
	if ( $counter )
		{	&DumpDomains( $opt_final_directory, $last_file );
			$counter = 0 + 0;
			%domains = ();
		}
	else
		{
			print "\nNo unknown urls files found\n";
		}
		
	return( undef );
}



################################################################################
# 
sub DumpDomains( $$ )
#
################################################################################
{	my $dir				= shift;
	my $file			= shift;
	
	print "Dumping out domain files to directory $dir ...\n";
	print "Dump files using file name $file ...\n";
	
	# Open the output files
	my $filename = $dir . "\\d1$file.1.txt";

	open( OUTPUT, ">$filename" ) or die "Cannot create output file $filename: $!\n";
	print "Creating file $filename ...\n";

	my  $file_counter	= 0 + 0;
	my  $file_number	= 0 + 1;
	
	while ( my ( $root, $dhash_ref ) = each ( %domains ) )
		{	my %dhash = %$dhash_ref;
			my @urls = keys %dhash;
	
			print OUTPUT $root;
			
			# Add each URL after a tab
			foreach ( @urls )
				{	my $url = $_;
					next if ( ! $url );
					next if ( $url eq $root );
					print OUTPUT "\t$url";
				}
				
			print OUTPUT "\n";
						
			$file_counter++;;

			if ( $file_counter > $output_file_size )
				{	$file_counter = 0 + 0;
					$file_number++;

                     close( OUTPUT );
                     $filename = $dir . "\\d1$file.$file_number.txt";

                     open( OUTPUT, ">$filename" ) or die "Cannot create output file $filename: $!\n";
                     print "Creating file $filename ...\n";

                 }
         }


    close( OUTPUT );
	
	print "\nDone dumping domains\n";
	
	return( 1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "ProcessUnknown";

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
    my $me = "ProcessUnknown";
    print <<".";
Usage: ProcessUnknown UNKNOWN_DIR

Process the unknown URLs files from the UNKNOWN_DIR
and feed them into the download army.  This depends
on Drive V: being mapped to the Archive server.

If no UNKNOWN_DIR is specified, the default directory is
$opt_source_directory

Steps are:
1. Read in the unknown URLs files from the UNKNOWN_DIR and
move them to C:\\tmp

2. Spit out the unique unknown domains into 100 URL files
into directory: 
$opt_final_directory


Directories used are:

$opt_source_directory
$opt_tmp_directory
$opt_final_directory


  -c, --clear       clear out the old unknowns older than 1 month 
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
