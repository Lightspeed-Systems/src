################################################################################
#!perl -w
#
#  SqlMissing - compare 2 IpmContent databases and find the entries that are missing
#
################################################################################



use strict;
use warnings;



use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );


use Content::File;
use Content::SQL;
use Content::SQLCompare;



my $opt_version;						# Display version # and exit
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_compare;	                    # Option for building comparison tables
my $opt_ignore;							# If set, this is the list of categories to ignore
my $opt_domains_only;					# If True, then only compare domains
my $output_file_name;
my $opt_miss_file;						# If set, this is a file of URLs that are missing  from the remote database


my $dbh;								# The global database handle
my $dbhRemote;							# The golbal handle to the Remote database
my $local_company	= "Websense";		# These names are used in the Compare SQL tables
my $remote_company	= "Lightspeed";
my %compare_category_rating;			# A hash of key = compare_category_number, value = compare category rating (S, X, R, PG, G, Errors, Unknown )
my %compare_category_name;				# A hash of key = compare_category_number, value = compare category name
my $remote_unknown = 0 + 200;			# The unknown category number for the remote database - 200 is Lightspeed unknown
my $local_unknown  = 0 + 153;			# The unknown category for the local database - 153 is Websense unknown



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
		"c|compare"			=> \$opt_compare,
		"d|domains"			=> \$opt_domains_only,
		"i|ignore=s"		=> \$opt_ignore,
		"m|miss=s"			=> \$opt_miss_file,
        "v|version"			=> \$opt_version,
		"w|wizard"			=> \$opt_wizard,
        "h|help"			=> \$opt_help
    );


    &StdHeader( "SqlMissing" ) if ( ! $opt_wizard );
	
    &Usage() if ( ( $opt_help )  ||  ( $opt_version ) );
	
	
    print "Building compare tables\n" if ( $opt_compare );
	print "Ignoring category numbers $opt_ignore\n" if ( $opt_ignore );
	print "Only comparing domain tables\n" if ( $opt_domains_only );


	# Get the file name to use
	$output_file_name = shift;
	$output_file_name = "SqlMissing.txt" if ( ! $output_file_name );

	# Test to make sure the miss file is there, if specified
	if ( ( $opt_compare )  &&  ( $opt_miss_file )  &&  ( ! -f $opt_miss_file ) )
		{	print "Unable to find miss file $opt_miss_file\n";
			exit;
		}
	
	print "Opening a connection to the ODBC System DSN \'RemoteContent\' ...\n";
	$dbhRemote = &ConnectRemoteContent();

	if ( ! $dbhRemote )
		{
lprint "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'RemoteContent\' with default database \'IpmContent\'.\n";
			exit( 9 );
		}
		
		
    #  Open the local database
	print "Opening a connection to the local database ...\n";
    $dbh = &ConnectServer() or die;

    &LoadCategories();


	# Get the remote database categories if comparing
	if ( $opt_compare )
		{	my $str = "SELECT CategoryNumber, CategoryName, ContentRating FROM IpmContentCategory";
			my $sth = $dbhRemote->prepare( $str );
			$sth->execute();

			while (  my ( $CategoryNumber, $catname, $ContentRating ) = $sth->fetchrow_array() )
				{	next if ( ! $CategoryNumber );
					$CategoryNumber = 0 + $CategoryNumber;
					
					$catname = "no category name" if ( ! $catname );
					
					$ContentRating = "Not set" if ( ! $ContentRating );
					
					$compare_category_rating{ $CategoryNumber } = $ContentRating;
					$compare_category_name{ $CategoryNumber }	= $catname;
				}

			$sth->finish();
			
			# Add the unknown category for the remote database
			my $catnum = 0 + $remote_unknown;
			my $catname = "Unknown";
										
			$compare_category_rating{ $catnum } = "Unknown";
			$compare_category_name{ $catnum }	= $catname;
			
			my $ok = &CompareSetup( $dbh, $local_company, $remote_company, \%compare_category_rating, \%compare_category_name, undef );
			
			if ( ! $ok )
				{	print "Error setting up the Compare tables\n";
					$dbh->disconnect		if ( $dbh );
					$dbhRemote->disconnect	if ( $dbhRemote );
					
					exit;
				}
		}
		
	
		
	&SqlMissing();
		
	&CompareClose( $dbh )	if ( $opt_compare );	
	$dbh->disconnect		if ( $dbh );
	$dbhRemote->disconnect	if ( $dbhRemote );
	
	print "Done.\n";

exit;

}
exit;



################################################################################
# 
sub SqlMissing()
#
#  Compare the contents of the 3 main tables in the remote IpmContent database  
#  to the local IpmContent database
#
################################################################################
{
	my $str;
	my $sth;
	my $count	= 0 + 0;
	my $lookup	= 0 + 0;

	if ( ! open( OUTPUT, ">$output_file_name" ) )
		{	print "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	print "Opened file $output_file_name for output\n";
	
	
	# Should I insert the missing URLs from the remote database?
	if ( ( $opt_compare )  &&  ( $opt_miss_file )  &&  ( -f $opt_miss_file ) )
		{	open( MISSFILE, "<$opt_miss_file" ) or die "Unable to open miss file: $!\n";
			
			print "Inserting the missing domains, IP, and URLs from the remote database ...\n";
			$count = 0 + 0;
			while (<MISSFILE>)
				{	my $url = $_;
					chomp( $url );
					next if ( ! $url );
					&SqlSleep();
					
					$url = &CleanUrl( $url );
					next if ( ! $url );
					
					# Figure out the type
					my $type = 0 + 1;
					$type = 0 + 2 if ( $url =~ m/\// );
					$type = 0 + 3 if ( ( $type == 1 )  &&  ( &IsIPAddress( $url ) ) );
					
					my ( $category_number, $source_number ) = &FindCategory( $url, $type );
					
					# Skip the URL if the local database doesn't know it either
					next if ( ! $category_number );
					next if ( $category_number == $local_unknown );
					
					my $save_ok = &CompareSave( $dbh, $type, $url, $category_number, $remote_unknown );
					
					die "Error saving $url into the CompareURLTemp table\n" if ( ! $save_ok );
					
					$count++;
				}
				
			close( MISSFILE );
			
			print "Added $count missing domains, IP, and URLs for the remote database\n";
		}
	
	
	if ( ! $opt_domains_only )
		{	# First get the missing URLs addresses
			print "Looking for missing URLs ...\n";

			$str = "SELECT URL, CategoryNumber FROM IpmContentURL";
			$str = "SELECT URL, CategoryNumber FROM IpmContentURL WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

			$sth = $dbhRemote->prepare( $str );

			$sth->execute();
			$count	= 0 + 0;
			$lookup = 0 + 0;
			while ( ( ! $dbhRemote->err )  &&  ( my ( $url, $remote_category ) = $sth->fetchrow_array() ) )
				{	last if ( ! $url );
					&SqlSleep();
					$lookup++;
					
					next if ( ! $url );
					
					my $lookupType = &LookupUnknown( $url, 0 );
					if ( $lookupType )
						{	if ( $opt_compare )
								{	my ( $category_number, $source_number ) = &FindCategory( $url, $lookupType );
									&CompareSave( $dbh, 2, $url, $category_number, $remote_category );
								}
								
							&ShowLookup( "URLs", $count, $lookup );
							next;	
						}
					
					print OUTPUT "$url\n";
					
					$count++;
					
					&ShowCounter( "URLs", $count, $lookup );
				}

			$sth->finish();
			
			print "Looked up $lookup URLs, found $count missing URLs\n";
			
			
			# next get the missing IP addresses
			print "Looking for missing IP addressess ...\n";
			$str = "SELECT IPAddress, CategoryNumber FROM IpmContentIPAddress";
			$str = "SELECT IPAddress, CategoryNumber FROM IpmContentIPAddress WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
			$sth = $dbhRemote->prepare( $str );
			$sth->execute();
			
			$count	= 0 + 0;
			$lookup = 0 + 0;
			while ( ( ! $dbhRemote->err )  &&  ( my ( $ip, $remote_category ) = $sth->fetchrow_array() ) )
				{	last if ( ! $ip );
					&SqlSleep();
					$lookup++;
					
					my $str_ip = &IPToString( $ip );
					next if ( ! $str_ip );
					
					my $lookupType = &LookupUnknown( $str_ip, 0 );
					if ( $lookupType )
						{	if ( $opt_compare )
								{	my ( $category_number, $source_number ) = &FindCategory( $str_ip, $lookupType );
									&CompareSave( $dbh, 3, $str_ip, $category_number, $remote_category );
								}
								
							&ShowLookup( "IP addresses", $count, $lookup );
							next;	
						}
					
					print OUTPUT "$str_ip\n";
					
					$count++;
					
					&ShowCounter( "IP addresses", $count, $lookup );
				}

			$sth->finish();
			
			print "Looked up $lookup IP addresses, found $count missing IP addresses\n";
		}
		
	
	# Next get the missing domains
	print "Looking for missing domains ...\n";
	
	$str = "SELECT DomainName, CategoryNumber FROM IpmContentDomain";
	$str = "SELECT DomainName, CategoryNumber FROM IpmContentDomain WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
	$sth = $dbhRemote->prepare( $str );
	$sth->execute();

	$count	= 0 + 0;
	$lookup = 0 + 0;
	while ( ( ! $dbhRemote->err )  &&  ( my ( $reverse_domain, $remote_category ) = $sth->fetchrow_array() ) )
		{	last if ( ! $reverse_domain );
			&SqlSleep();
			$lookup++;
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! $domain );
			
			my $lookupType = &LookupUnknown( $domain, 0 );
			if ( $lookupType )
				{	if ( $opt_compare )
						{	my ( $category_number, $source_number ) = &FindCategory( $domain, $lookupType );
							&CompareSave( $dbh, 1, $domain, $category_number, $remote_category );
						}
					
					&ShowLookup( "domains", $count, $lookup );
					next;	
				}
			
			print OUTPUT "$domain\n";
			
			$count++;
			
			&ShowCounter( "domains", $count, $lookup );
		}

	$sth->finish();
	
	print "Looked up $lookup domains, found $count missing domains\n";
	
	close( OUTPUT );	
	
	return( 1 );
}



################################################################################
# 
sub ShowCounter()
#
#  Show a progress counter 
#
################################################################################
{	my $type	= shift;
	my $count	= shift;
	my $lookup	= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $count ) ||  ( ! $lookup ) );
	
	my $int = 10000 * sprintf( "%d", ( $count / 10000 ) );
	
	return( undef ) if ( $int != $count );
	
	print "Type: $type - looked up $lookup total, found $count missing so far ...\n";
	
	return( 1 );
}



################################################################################
# 
sub ShowLookup()
#
#  Show a lookup progress counter 
#
################################################################################
{	my $type	= shift;
	my $count	= shift;
	my $lookup	= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $count ) ||  ( ! $lookup ) );
	
	my $int = 100000 * sprintf( "%d", ( $lookup / 100000 ) );
	
	return( undef ) if ( $int != $lookup );
	
	print "Type: $type - looked up $lookup total, found $count missing so far ...\n";
	
	return( 1 );
}



################################################################################
# 
sub ConnectRemoteContent()
#
#  Find and connect to the remote Content database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbhRemote ) if ( $dbhRemote );
	
	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\RemoteContent", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	&RegCloseKey( $key );
	
	$dbhRemote = DBI->connect( "DBI:ODBC:RemoteContent", "IpmContent" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhRemote )
		{	sleep( 10 );
			$dbhRemote = DBI->connect( "DBI:ODBC:RemoteContent", "IpmContent" );
		}
		
	&SqlSetCurrentDBHandles( $dbhRemote, undef );
	
	return( $dbhRemote );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlMissing";

    print <<".";
Syntax: SqlMissing FILE

SqlMissing compares the local IpmContentDatabase to the RemoteContent database
and saves any missing entries in the local database to FILE.  The default name
for FILE is SqlMissing.txt.

  -c, --compare      build the summary comparison tables in SQL
  -d, --domains      only compare domains, not IPs and URLs
  -m, --miss MFILE   insert the missing URLs file from the remote database
                     (only used when building the summary comparison)
  -i, --ignore LIST  the list of category numbers to ignore, i.e. 152,153

  -h, --help         show this help

.

    exit( 1 );
}



__END__

:endofperl
