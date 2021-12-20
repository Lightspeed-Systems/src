################################################################################
#!perl -w
#
#  SqlLookup - given a list of URLs - lookup everything about them in the Content 
#  database
#
#  Copyright 2008 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



use strict;
use warnings;



use Getopt::Long;
use Content::File;
use Content::SQL;
use Content::Category;



my $opt_version;						# Display version # and exit
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_category;                       # Option for ignoring one category
my $opt_unknown;						# If TRUE then ignore unknown or errors
my $opt_local;							# If True then open a handle to the local database rather than the TrafficRemote database
my $opt_block;							# If True then only print out URLs in blocked categories
my $opt_debug;
my $opt_fileid;							# If set, then read and lookup a list of file IDs
my $opt_reason;							# If set, then print the reason from the Category database
my $opt_transtime;					# If set, then use the TransactionTime in output "Time"

my $dbh;								# The global database handle
my $dbhCategory;						# The global handle to the Category database
my %summary;							# The summarized results


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
		"b|block"			=> \$opt_block,
		"c|category=s"		=> \$opt_category,
		"f|fileid"			=> \$opt_fileid,
		"l|local"			=> \$opt_local,
		"r|reason"			=> \$opt_reason,
		"u|unknown"			=> \$opt_unknown,
        "v|version"			=> \$opt_version,
        "t|trans"		=> \$opt_transtime,
		"w|wizard"			=> \$opt_wizard,
		"x|xxx"				=> \$opt_debug,
        "h|help"			=> \$opt_help
    );


    &StdHeader( "SqlLookup" ) if ( ! $opt_wizard );
	
    &Usage() if ( ( $opt_help )  ||  ( $opt_version ) );
	
	
    $opt_category = lc( $opt_category ) if ( $opt_category );

	my $input_file_name = shift;
	
	if ( ( ! $input_file_name )  ||  ( ! -e $input_file_name ) )
		{	&Usage();
			exit( 0 );
		}
	
	my $output_file_name = shift;
	if ( ! $output_file_name )
		{	&Usage();
			exit( 0 );
		}
	
	
	if ( ! open( INPUT, "<$input_file_name" ) )
		{	print "Error opening $input_file_name: $!\n";
			exit( 0 );
		}
		
	print "Opened file $input_file_name for input\n";

	if ( ! open( OUTPUT, ">$output_file_name" ) )
		{	print "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	print "Opened file $output_file_name for output\n";
	
	if ( $opt_local )
		{	print "Opening a connection to the local IpmContent database ...\n";
			$dbh = &ConnectServer();
			
			if ( ! $dbh )
				{	print "Unable to open a connection to the local IpmContent database.\n";
					exit( 9 );	
				}
		}
	else
		{	print "Opening a connection to the ODBC System DSN \'TrafficRemote\' ...\n";
			$dbh = &ConnectRemoteServer();

			if ( ! $dbh )
				{
lprint "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.\n";
					exit( 9 );
				}

			&SqlSetCurrentDBHandles( $dbh, undef );
		}
		
	&LoadCategories();
	

	if ( $opt_reason )	
		{	lprint "Opening a connection to the Category SQL server ...\n";
			$dbhCategory = &CategoryConnect();
			if ( ! $dbhCategory )
				{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";
					$dbh->disconnect if ( $dbh );

					exit( 10 );
				}
		}
		


	if ( $opt_fileid )
		{	my $in_counter = 0 + 0;
			while ( my $line = <INPUT> )
				{	chomp( $line );
					
					my ( $hex_file_id, $filename ) = split /\t/, $line, 2;
					
					next if ( ! defined $hex_file_id );
					next if ( ! defined $filename );
					next if ( length( $hex_file_id ) != 56 );
					
					&FileIDInfo( $hex_file_id, $filename );

					$in_counter++;
				}

			close( INPUT );
			
			print "\nLooked up $in_counter File IDs total\n";
			print OUTPUT "\nLooked up $in_counter File IDs total\n";

			close( OUTPUT );

			$dbh->disconnect if ( $dbh );
			
			exit( 0 );
		}
		
		
	# Check the names of any categories to ignore
	if ( $opt_category )
		{	my @categories = split /\,/, $opt_category;
			foreach ( @categories )
				{	my $catname = $_;
					next if ( ! $catname );
					my  $category_number = &CategoryNumber( $catname );
					die "Unable to find category number for category name $catname\n"  if ( ! $category_number );
				}
		}
		
	
	print "Reading URLs from $input_file_name and looking them up on ODBC DSN TrafficRemote ...\n" if ( ! $opt_local );
	print "Reading URLs from $input_file_name and looking them up on the local IpmContent database ...\n" if ( $opt_local );
	print "Only printing out URLs from blocked categories ...\n" if ( $opt_block );
	print "Looking up the categorization reason on the Category SQL server ...\n" if ( $opt_reason );
	print "Using TransactionTime for all output ...\n" if ( $opt_transtime );

	my $in_counter = 0 + 0;
	while ( my $url = <INPUT> )
		{	chomp( $url );
			next if ( ! $url );
			
			$url = &CleanUrl( $url );
			next if ( ! $url );
			
			&SqlInfo( $url );

			$in_counter++;
		}


	close( INPUT );
	
	print "\nLooked up $in_counter URLs total\n";
	print OUTPUT "\nLooked up $in_counter URLs total\n";
	
	my @keys = sort keys %summary;
	
	print OUTPUT "\nSummary:\n";
	my $summary_total = 0 + 0;
	
	foreach ( @keys )
		{	next if ( ! defined $_ );
			my $category_name = $_;
			my $value = $summary{ $category_name };
			next if ( ! defined $value );
			
			print OUTPUT "$category_name $value\n";
			$summary_total += $value;
		}
		
	close( OUTPUT );	
	
	$dbh->disconnect if ( $dbh );
	$dbhCategory->disconnect if ( $dbhCategory );
	
	print "Summary total = $summary_total\n";
	
	print "Done.\n";

exit;

}

exit;



################################################################################
# 
sub FileIDInfo( $$ )
#
#  Given a hex file ID, get all the info from the ApplicationProcesses table
#
################################################################################
{	my $hex_file_id = shift;
	my $filename	= shift;

	return if ( ! defined $hex_file_id );
	return if ( ! defined $filename );
	return if ( length( $hex_file_id ) != 56 );
	
	print OUTPUT "File: $filename\n";
	print OUTPUT "FileID: $hex_file_id\n";
	
	my $str = "SELECT AppName, Process, Description, Manufacturer, ProgramPermissions, CategoryNumber, SourceNumber, TransactionTime, AppType FROM ApplicationProcesses WHERE FileID = '$hex_file_id'";
	my $sth = $dbh->prepare( $str );
	
	$sth->execute();
	
	my ( $app_name, $process, $desc, $manu, $permissions, $catnum, $sourcenum, $transaction_time, $app_type ) = $sth->fetchrow_array();
	
	$sth->finish();
	
	# Did I get anything?
	if ( ! defined $app_name )
		{	print OUTPUT "Not in ApplicationProcess table\n";
			print OUTPUT "\n";
			return;
		}
		
	$catnum = 0 + $catnum;	
	my $category_name = &CategoryName( $catnum );
	$category_name = "unknown" if ( ! $category_name );

	my $virus = 1 if ( ( $catnum > 61 )  &&  ( $catnum < 65 ) );
	
	print OUTPUT "AppName: $app_name\n" if ( ! $virus );
	print OUTPUT "VirusName: $app_name\n" if ( $virus );
	
	print OUTPUT "Process: $process\n" if ( defined $process );
	
	print OUTPUT "Category: $catnum\t$category_name\n";
	print OUTPUT "Source: $sourcenum\tTime: $transaction_time\n";
	
	print OUTPUT "Description: $desc\n" if ( $desc );
	print OUTPUT "Manufacturer: $manu\n" if ( $manu );

	print OUTPUT "\n";	
	return;	
}



################################################################################
# 
sub SqlInfo( $ )
#
#  Given a url, print out everything about it
#
################################################################################
{	my $url = shift;

	return if ( ! $url );

	my  $lookupType = &LookupUnknown( $url, 0 );

	if ( ! $lookupType )
		{	return( 0 ) if ( $opt_unknown );
			return( 0 ) if ( $opt_block );
			
			print OUTPUT "$url\tUnknown\n";
			
			my $unknown_catname = "unknown";
			if ( ! defined $summary{ $unknown_catname } )
				{	$summary{ $unknown_catname } = 0 + 1;
				}
			else
				{	$summary{ $unknown_catname }++;
				}
				
			return( 0 );
		}
	   
	   
	my ( $category_number, $source_number, $transaction_time, $review_time ) = &FindCategory( $url, $lookupType );

	return if ( ( $opt_block )  &&  ( ! &BlockedCategoryNumber( $category_number ) ) );
	
	
	my $category_name = &CategoryName( $category_number );
	$category_name = "unknown" if ( ! $category_name );


	# Should I ignore this?
	if ( $opt_category )
		{	my $qcategory_name = quotemeta( $category_name );
			return( 0 ) if ( $opt_category =~ m/$qcategory_name/ );
			
			# Check to see if I am supposed to ignore the main category
			my ( $main_category, $junk ) = split /\./, $category_name, 2;
			
			my $qmain_category = quotemeta( $main_category );
			return( 0 ) if ( $opt_category =~ m/$qmain_category/ );
		}

	if ( $opt_unknown )
		{	return( 0 ) if ( $category_name =~ m/unknown/i );
			return( 0 ) if ( $category_name =~ m/error/i );
		}
		
	my $type = "Domain";
	$type = "URL" if ( ( $lookupType == 2 )  ||  ( $lookupType == 5 ) );
	$type = "IP" if ( ( $lookupType == 3 )  ||  ( $lookupType == 6 ) );
	
	my $time = $transaction_time;
	$time = $review_time if ( ( ! $opt_transtime ) && ( $review_time )  &&  ( $transaction_time )  &&  ( $review_time gt $transaction_time ) );
	$time = "Unknown time" if ( ! $time );

	my $reason = "";
	if ( $opt_reason )
		{	$reason = &CategoryGetDomainReason( $url );
			$reason = "None" if ( ! defined $reason );
			$reason =~ s/\n//g;
		}
		
		
	print OUTPUT "$url\tCategory: $category_number\t$category_name\tType: $type\tSource: $source_number\tTime: $time";
	print OUTPUT "\tReason: $reason\n" if ( $opt_reason );
	print OUTPUT "\n" if ( ! $opt_reason );


	if ( ! defined $summary{ $category_name } )
		{	$summary{ $category_name } = 0 + 1;
		}
	else
		{	$summary{ $category_name }++;
		}

		
	&RelatedUrls( $url, $lookupType );	
}



################################################################################
# 
sub RelatedUrls( $$ )
#
#  Given a url, and the lookup type, find any related urls
#
################################################################################
{	my $url			= shift;
	my $lookup_type = shift;
		
	$dbh = &SqlErrorCheckHandle( $dbh );

	my $domain = $url;
	my $url_ext;
	
	( $domain, $url_ext ) = split /\//, $url, 2 if ( ( $lookup_type == 2 )  ||  ( $lookup_type == 5 ) );
	

	my $quote_url = &quoteurl( $domain );

	my $str = "SELECT URL, CategoryNumber, SourceNumber, TransactionTime, ReviewTime FROM IpmContentURL WHERE URL LIKE \'$quote_url%\'";
	
	print "SQL Query: $str\n" if ( $opt_debug );
	
	my $sth = $dbh->prepare( $str );
	$sth->execute();
	
    while ( my ( $suburl, $category_number, $source_number, $transaction_time, $review_time ) = $sth->fetchrow_array() )
		{	my $time = $transaction_time;
			
			$time = $review_time if ( ( $review_time )  &&  ( $transaction_time )  &&  ( $review_time gt $transaction_time ) );
			$time = "Unknown time" if ( ! $time );
			
			my $category_name = &CategoryName( $category_number );
			$category_name = "unknown" if ( ! $category_name );
			
			print OUTPUT "\t$suburl\tCategory: $category_number\t$category_name\tSource: $source_number\tTime: $time\n";
			
			print "\t$suburl\tCategory: $category_number\t$category_name\tSource: $source_number\tTime: $time\n" if ( $opt_debug );
		}
	
	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlLookup";

    print <<".";
Syntax: SqlLookup URLFile URLInfoFile

SqlLookup reads a list of URLs from URLFile, and outputs everything known
in the Content database to the URLInfoFile.

  -b, --blockonly          only print out URLs in blocked categories
  -c, --category CATLIST   the name(s) of a categories to ignore, comma
                           separated
  -f, --fileid             to lookup a list of file IDs instead of URLs
  -l, --local              to use the local IpmContent database instead
                           of TrafficRemote
  -r, --reason             to display the reason from Category database
  -u, --unknown            if set then ignore unknown or error categories

.

    exit( 1 );
}



__END__

:endofperl
