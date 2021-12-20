################################################################################
#!perl -w
#
# ProcessErrors - process any errors from the previous day's categorization
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use DBI qw(:sql_types);
use DBD::ODBC;


use Content::File;
use Content::SQL;
use Content::Category;


# Options
my $opt_help;
my $opt_version;
my $opt_final_directory		= "F:\\Content\\recategorize\\normal";
my $dbhCategory;
my $max_in_memory			= 0 + 200000;	# This is the approximate maximum number of unique domains to hold in memory before dumping to disk
my $output_file_size		= 0 + 100;		# The size of each output file - 200 is roughly the number of domains 1 task can download in 1 hour



my $_version = "1.0.0";
my %domains;



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
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );


    &StdHeader( "ProcessErrors" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );



	if ( ! -d $opt_final_directory )
		{	&FatalError( "Can not find directory $opt_final_directory\n" );
		}
		
		
		
	lprint "Opening a connection to the Remote Category database ...\n";


	# Connect to the category database
	$dbhCategory = &CategoryConnect();
	if ( ! $dbhCategory )
		{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";
			exit( 10 );
		}
		

	&ProcessErrors();
	
	#  Close up the databases and quit
	$dbhCategory->disconnect if ( $dbhCategory );

	lprint "\nDone\n";
	
    exit;
}



################################################################################
# 
sub ProcessErrors()
#
################################################################################
{
	%domains = ();

	my $file;
	my $counter = 0 + 0;


	# Figure out the current day and yesterday
	my $yesterday_seconds = time() - ( 24 * 60 * 60 );	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year = 1900 + $year;
	$mon = $mon + 1;
	
	my $today = "$mon/$mday/$year";

	( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $yesterday_seconds );
	$year = 1900 + $year;
	$mon = $mon + 1;
	
	my $yesterday = "$mon/$mday/$year";
	
	my $last_file = sprintf( "ErrorCategorizing-%04d-%02d-%02d", $year, $mon, $mday );
	

	# Get the error domains from yesterday
	lprint "Processing the recent categorization errors from $yesterday ...\n";
	
	
	my $str = "SELECT DomainName FROM RecentErrors WITH(NOLOCK) WHERE TransactionTime >= '$yesterday' AND TransactionTime < '$today'";

	lprint "SQL Statement: $str\n";


	my $sth = $dbhCategory->prepare( $str );

	$sth->execute();

	
	my $loop = 0 + 0;	# Loop counter to count how many times I've called DumpDomains
	while ( ( ! $dbhCategory->err )  &&  ( my ( $domain ) = $sth->fetchrow_array() ) )
		{	next if ( ! $domain );
			$domain = &CleanUrl( $domain );
			next if ( ! $domain );
			
			$counter++;
			
			# Add it to my domain hash
			$domains{ $domain } = 1;
			
			$counter++;

			# Have I read in a bunch of domains?
			if ( $counter >= $max_in_memory )
				{	$loop++;
					&DumpDomains( $opt_final_directory, "$last_file.$loop" );
					$counter = 0 + 0;
					%domains = ();
				}

		}  # end of $file = readdir( DIR )
	
	
	$sth->finish();
	
	
	# Do I still have some domains in the hash?
	if ( $counter )
		{	$loop++;
			&DumpDomains( $opt_final_directory, "$last_file.$loop" );
			$counter = 0 + 0;
			%domains = ();
		}


	# Now clear out any errors that are over a month old
	lprint "Deleting recent errors that are over a month old ...\n";
	
	my $month_ago_seconds = time() - ( 30 * 24 * 60 * 60 );	
	( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $month_ago_seconds );
	$year = 1900 + $year;
	$mon = $mon + 1;
	
	my $month_ago = "$mon/$mday/$year";
	$str = "DELETE RecentErrors WHERE TransactionTime < '$month_ago'";
	lprint "SQL Statement: $str\n";

	$sth = $dbhCategory->prepare( $str );

	$sth->execute();
	$sth->finish();
	
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
	my $filename = $dir . "\\$file.1.txt";

	open( OUTPUT, ">$filename" ) or die "Cannot create output file $filename: $!\n";
	print "Creating file $filename ...\n";

	my  $file_counter	= 0 + 0;
	my  $file_number	= 0 + 1;

	my @url_list = sort keys %domains;
	
	foreach ( @url_list )
		{	my $new_url = $_;
			print OUTPUT "$new_url\n";
			$file_counter++;;

			if ( $file_counter > $output_file_size )
				{	$file_counter = 0 + 0;
					$file_number++;

                     close( OUTPUT );
                     $filename = $dir . "\\$file.$file_number.txt";

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
    my $me = "ProcessErrors";

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
    my $me = "ProcessErrors";
    print <<".";
Usage: $me [OPTION(s)]
Process the previous day's categorization errors.

Directories used are:

F:\\content\\recategorize

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
    my $me = "ProcessErrors";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
