################################################################################
#!perl -w
#
#  SqlDiff - compare 2 IpmContent databases and find the entries that are diferent
#
################################################################################


use strict;
use warnings;


use Getopt::Long;


use Content::File;
use Content::SQL;


use DBI qw(:sql_types);
use DBD::ODBC;


# For the DDB socket connect
use IO::Handle;
use IO::Socket;



my $opt_version;						# Display version # and exit
my $opt_help;							# Display help and exit
my $opt_where;							# Is set then use this as a conditional SQL where
my $opt_ignore;							# If set, this is the list of categories to ignore
my $opt_domains_only;					# If True, then only compare domains
my $output_file_name;
my $opt_no_sql_timeout;					# True if I should not do any SQL sleeping
my $opt_virus;							# If set then just compare the virus tables
my $opt_missing;						# If set then touch and database entry found in the missing file
my $opt_fmiss;							# If set them only update the TransactionTime for SourceNumber <= $opt_fmiss
my $opt_no_update;						# If set then don't update the transaction time
my $opt_errors;							# If set then insert missing entries into the errors category
my $opt_compare_only;					# If set then compare domains, IPs, and URLs only
my $opt_print;							# If set then print the differences to a file
my $opt_older;							# If set then only compare entries that are older than so many days
my $opt_younger;						# If set then only compare entries that are younger than so many days
my $opt_source;							# If set then put any source problems into the error category
my $opt_debug;
my $opt_add;							# Add rows into the MISSING table
my $opt_remote;							# The IP address of the DDB server to compare to
my $opt_bspecial;						# Do something special in the special() function
my $opt_qsource;						# If true then don't update TransactionTime on SourceNumber conflicts, i.e.
										# if the remote source is lower than the local source, don't update the
										# TransactionTime on the local database, since it won't do anything to a downstream
										# database


my $dbh;								# The global database handle
my $dbhRemote;							# The golbal handle to the Remote database


# Globals used for the DDB lookup stuff
my $id;	# This is the ID counter that is used to keep requests and responses tied together
my $socket;
my $port_no;			# This is the port number that the DDB protocol uses


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
		"a|add=s"			=> \$opt_add,
		"b|bspecial"		=> \$opt_bspecial,
		"c|compare"			=> \$opt_compare_only,
		"e|errors"			=> \$opt_errors,
		"f|fmiss=i"			=> \$opt_fmiss,
		"d|domains"			=> \$opt_domains_only,
		"i|ignore=s"		=> \$opt_ignore,
		"n|noupdate"		=> \$opt_no_update,
        "m|missing=s"		=> \$opt_missing,
		"o|older=i"			=> \$opt_older,
		"p|print=s"			=> \$opt_print,
		"q|qsource"			=> \$opt_qsource,
 		"r|remote=s"		=> \$opt_remote,
        "s|source"			=> \$opt_source,
        "t|timeout"			=> \$opt_no_sql_timeout,
		"w|where=s"			=> \$opt_where,
		"v|virus"			=> \$opt_virus,
		"x|xxx"				=> \$opt_debug,
		"y|younger=i"		=> \$opt_younger,
        "h|help"			=> \$opt_help
    );



    &StdHeader( "SqlDiff" );
	
    &Usage() if ( ( $opt_help )  ||  ( $opt_version ) );
	
	&SetLogFilename( ".\\SqlDiff.log", undef );
	
	lprint "Ignoring category numbers $opt_ignore\n" if ( $opt_ignore );
	lprint "Only comparing domain tables\n"			if ( $opt_domains_only );
	lprint "Only comparing the virus tables\n"		if ( $opt_virus );
	lprint "Not updating the TransactionTime on different database entries\n" if ( $opt_no_update );
	lprint "Insert missing entries into the errors category in the local database\n" if ( $opt_errors );
	lprint "Compare only domains, IPs, and URLs\n" if ( $opt_compare_only );
	lprint "Printing the differences to file $opt_print\n" if ( defined $opt_print );
	lprint "Only comparing entries that are $opt_older days old or more\n" if ( defined $opt_older );
	lprint "Only comparing entries that are $opt_younger days young or more\n" if ( defined $opt_younger );
	lprint "Match up any source problems in the local database by changing SourceNumber, CategoryNumber, and TransactionTime\n" if ( defined $opt_source );
	lprint "Don't update the TransactionTime on source conflicts\n" if ( defined $opt_qsource );
	lprint "Use a SQL SELECT WHERE command: WHERE $opt_where\n" if ( defined $opt_where );
	
	
	# Get the file name to use
	$output_file_name = shift;
	$output_file_name = "SqlDiff.txt" if ( ! $output_file_name );

	
	# Default the remote IP if it isn't given	
	if ( ( $opt_remote )  &&  ( ! &IsIPAddress( $opt_remote ) ) )
		{	$opt_remote = "54.203.89.93";
			lprint "Defaulting the remote DDB server IP address to $opt_remote\n";
		}
		
		
	if ( $opt_remote )
		{	lprint "Opening a connection to the local database ...\n";
			$dbh = &ConnectServer() or die;

			&LoadCategories();
			
			&TrapErrors() if ( ! $opt_debug );

			&DDBRemote( $opt_remote );
			
			$dbh->disconnect if ( $dbh );
			
			lprint "Done.\n";
			exit;
		}
		
		
	if ( $opt_bspecial )
		{	lprint "Opening a connection to the local database ...\n";
			$dbh = &ConnectServer() or die;

			&LoadCategories();
			
			lprint "Opening a connection to the ODBC System DSN \'RemoteContent\' ...\n";
			$dbhRemote = &ConnectRemoteContent();

			if ( ! $dbhRemote )
				{
lprint "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'RemoteContent\' with default database \'IpmContent\'.\n";
					exit( 9 );
				}

			&SqlSpecial( $opt_bspecial );
			
			$dbh->disconnect if ( $dbh );
			$dbhRemote->disconnect	if ( $dbhRemote );
			
			lprint "Done.\n";
			exit;
		}
		
		
	if ( $opt_missing )
		{	lprint "Opening a connection to the local database ...\n";
			$dbh = &ConnectServer() or die;

			&LoadCategories();
			
			&SqlMissing( $opt_missing );
			
			$dbh->disconnect if ( $dbh );
			
			lprint "Done.\n";
			exit;
		}
		
		
	if ( $opt_add )
		{
			lprint "Opening a connection to the local database ...\n";
			$dbh = &ConnectServer() or die;

			&LoadCategories();
			
			&SqlAdd( $opt_add );
			
			$dbh->disconnect if ( $dbh );
			
			lprint "Done.\n";
			exit;
		}
		
		
	&TrapErrors() if ( ! $opt_debug );


	lprint "Opening a connection to the ODBC System DSN \'RemoteContent\' ...\n";
	$dbhRemote = &ConnectRemoteContent();

	if ( ! $dbhRemote )
		{
lprint "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'RemoteContent\' with default database \'IpmContent\'.\n";
			exit( 9 );
		}
		
		
    #  Open the local database
	lprint "Opening a connection to the local database ...\n";
    $dbh = &ConnectServer() or die "Can't connect to TrafficServer\n";
	

	&LoadCategories();

	&SqlDiff();
		
	$dbh->disconnect		if ( $dbh );
	$dbhRemote->disconnect	if ( $dbhRemote );
	
	lprint "Done.\n";

exit;

}
exit;



################################################################################
#
sub Test( $ )
#
#  Quick test
#
################################################################################
{
			my $local_str = "SELECT CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE DomainName = 'com.microsoft'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
			
			my ( $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
			
			# Die here if I have an error
			my $sql_errstr = $dbh->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
			$local_sth->finish();

print "microsoft local category = $local_category\n";

my $str_ip = "193.180.252.146";


  	$local_str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIpAddress WITH(NOLOCK) WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
	$local_sth = $dbh->prepare( $local_str );

	$local_sth->execute();
	
	# Die here if I have an error
	$sql_errstr = $dbh->errstr;
	die "SQL Error $sql_errstr\n" if ( $dbh->err );
				
	my $local_ip;						
	( $local_ip, $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
	
	$local_sth->finish();
					
print "local category = $local_category\n";



}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename;

	$filename = "SqlDiffErrors.log";
	
	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or &lprint( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	&lprint( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub DDBRemote( $ )
#
#  Compare the contents of the 3 main tables in the remote DDB server database  
#  to the local IpmContent database
#
################################################################################
{	my $server_ip = shift;	# This should be the IP address of the DDB service I want to compare to
	
	my $str;
	my $sth;
	my $count		= 0 + 0;
	my $lookup		= 0 + 0;
	my $different	= 0 + 0;
	
	
	# Make sure the socket is open
	if ( ! defined $socket )
		{	$port_no = 0 + 1311 if ( ! $port_no );	# This is the port number that the DDB protocol uses
			print "Opening UDP socket IP $server_ip port $port_no ...\n";
			$socket = IO::Socket::INET->new( Proto => 'udp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
			die "Unable to open socket: $!\n" if ( ! defined $socket );
		}
								
	
	if ( ! open( OUTPUT, ">$output_file_name" ) )
		{	lprint "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	lprint "Opened file $output_file_name for output\n";
		
	
	if ( ( $opt_print )  &&  ( ! open( PFILE, ">$opt_print" ) ) )
		{	lprint "Error opening difference file $opt_print: $!\n";
			exit( 0 );
		}

	lprint "Opened file $opt_print for printing differences\n" if ( $opt_print );
	lprint "Difference file: entry, local category, remote category, local source, remote source\n" if ( $opt_print );
	
	
	my $older_time;
	if ( $opt_older )
		{	# Calculate older time in SQL format
			my $older_time_seconds = time() - ( $opt_older * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $older_time_seconds );
			$year = 1900 + $year;
			$mon = $mon + 1;
			$older_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, 0, 0, 0, 0 );
		}


	my $younger_time;
	if ( $opt_younger )
		{	# Calculate younger time in SQL format
			my $younger_time_seconds = time() - ( $opt_younger * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $younger_time_seconds );
			$year = 1900 + $year;
			$mon = $mon + 1;
			$younger_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, 0, 0, 0, 0 );
		}


	# Figure out the expired category
	my $expired_category = &CategoryNumber( "expired" );
	$expired_category = 0 + 105 if ( ! $expired_category );

		
	if ( ! $opt_domains_only )		
		{	# Get the different IP addresses
			lprint "Looking for different IP addressess ...\n";
			
			$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK)";
			$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

			if ( $opt_older )
				{	$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
					$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
				}

			if ( $opt_younger )
				{	$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
					$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
				}

			if ( $opt_where )
				{	$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE $opt_where";
				}

			lprint "SQL Statement: $str\n";

			$sth = $dbh->prepare( $str );

			$sth->execute();
			
			# Die here if I have an error
			my $sql_errstr = $dbh->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
			
			$count		= 0 + 0;
			$lookup		= 0 + 0;
			$different	= 0 + 0;
			
			print OUTPUT "TABLE: IpmContentIpAddress\n";
			print PFILE "TABLE: IpmContentIpAddress\n" if ( $opt_print );
			while ( ( ! $dbh->err )  &&  ( my ( $str_ip, $local_category, $loc_source_number ) = $sth->fetchrow_array() ) )
				{	last if ( ! $str_ip );
					&SqlSleep() if ( ! $opt_no_sql_timeout );
					$lookup++;
										
					my $remote_category = &DDBLookup( $server_ip, $str_ip );
					
					
					if ( ! $remote_category )
						{	print OUTPUT "$str_ip\t$local_category\t$loc_source_number\n";
							
							$count++ if ( ( $local_category != 7 ) && ( $local_category != $expired_category ) );
						}
					elsif ( ! &DDBEquivalent( $local_category, $remote_category ) )
						{	$different++;
							
							print PFILE "$str_ip\t$local_category\t$remote_category\t$loc_source_number\n" if ( $opt_print );
						}
					
					&ShowCounter( "IP addresses", $count, $lookup, $different, 10000 );
				}

			$sth->finish();
			
			lprint "Looked up $lookup IP addresses, found $count missing and $different different IP addresses\n";
		}
		
	
	# Get the different domains
	lprint "Looking for different domains ...\n";
	
	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK)";
	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

	if ( $opt_older )
		{	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
			$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
		}

	if ( $opt_younger )
		{	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
			$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
		}

	if ( $opt_where )
		{	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE $opt_where";
		}

	lprint "SQL Statement: $str\n";

	$sth = $dbh->prepare( $str );
	
	$sth->execute();

	# Die here if I have an error
	my $sql_errstr = $dbh->errstr;
	die "SQL Error $sql_errstr\n" if ( $dbh->err );
											

	$count		= 0 + 0;
	$lookup		= 0 + 0;
	$different	= 0 + 0;
	
	print OUTPUT "TABLE: IpmContentDomain\n";
	print PFILE "TABLE: IpmContentDomain\n" if ( $opt_print );
	while ( ( ! $dbh->err )  &&  ( my ( $reverse_domain, $local_category, $loc_source_number ) = $sth->fetchrow_array() ) )
		{	last if ( ! $reverse_domain );
			&SqlSleep() if ( ! $opt_no_sql_timeout );
			$lookup++;
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! $domain );
			
			my $remote_category = &DDBLookup( $server_ip, $domain );
			
			if ( ! $remote_category )
				{	print OUTPUT "$domain\t$local_category\t$loc_source_number\n";
											
					$count++ if ( ( $local_category != 7 )  &&  ( $local_category != $expired_category ) );
				}
			elsif ( ! &DDBEquivalent( $local_category, $remote_category ) )
				{	$different++;
					
					print PFILE "$domain\t$local_category\t$remote_category\t$loc_source_number\n" if ( $opt_print );
				}
			
			&ShowCounter( "domains", $count, $lookup, $different, 10000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup domains, found $count missing and $different different domains\n";
	
	close( OUTPUT );	
	close( PFILE ) if ( $opt_print );
	
	print "Shutting down socket ...\n";
	$socket->shutdown( 2 );

	return( 1 );
}



################################################################################
# 
sub DDBEquivalent( $$ )
#
#  given two different categories, return TRUE if they are equivalent, or
#  undef if not
#
################################################################################
{	my $loc_category = shift;
	my $rem_category = shift;
	
	return( undef ) if ( ! defined $loc_category );
	return( undef ) if ( ! defined $rem_category );
	
	# Do the categories match?
	return( 1 ) if ( $loc_category == $rem_category );
	
	# Ads
	if ( ( $loc_category == 0 + 3 )	||
		 ( $loc_category == 0 + 52 ) ||
		 ( $loc_category == 0 + 53 ) ||
		 ( $loc_category == 0 + 54 ) ||
		 ( $loc_category == 0 + 35 ) )
		{	return( 1 ) if ( $rem_category == 0 + 3 );
			return( 1 ) if ( $rem_category == 0 + 52 );
			return( 1 ) if ( $rem_category == 0 + 53 );
			return( 1 ) if ( $rem_category == 0 + 54 );
			return( 1 ) if ( $rem_category == 0 + 35 );
		}
	elsif ( $loc_category == 0 + 46 )	# kids and teens
		{	return( 1 ) if ( $rem_category == 0 + 77 );
		}
	elsif ( $loc_category == 0 + 77 )
		{	return( 1 ) if ( $rem_category == 0 + 46 );
		}
	elsif ( ( $loc_category == 0 + 21 )	||	# Porn
		 ( $loc_category == 0 + 22 ) ||
		 ( $loc_category == 0 + 23 ) ||
		 ( $loc_category == 0 + 24 ) ||
		 ( $loc_category == 0 + 25 ) ||
		 ( $loc_category == 0 + 26 ) ||
		 ( $loc_category == 0 + 27 ) ||
		 ( $loc_category == 0 + 109 ) ||
		 ( $loc_category == 0 + 111 ) ||
		 ( $loc_category == 0 + 110 ) )
		{	return( 1 ) if ( $rem_category == 0 + 21 );
			return( 1 ) if ( $rem_category == 0 + 22 );
			return( 1 ) if ( $rem_category == 0 + 23 );
			return( 1 ) if ( $rem_category == 0 + 24 );
			return( 1 ) if ( $rem_category == 0 + 25 );
			return( 1 ) if ( $rem_category == 0 + 26 );
			return( 1 ) if ( $rem_category == 0 + 27 );
			return( 1 ) if ( $rem_category == 0 + 109 );
			return( 1 ) if ( $rem_category == 0 + 111 );
			return( 1 ) if ( $rem_category == 0 + 110 );
		}
	elsif ( ( $loc_category == 0 + 72 )	||	# Security
		 ( $loc_category == 0 + 16 ) ||
		 ( $loc_category == 0 + 65 ) ||
		 ( $loc_category == 0 + 125 ) ||
		 ( $loc_category == 0 + 62 ) ||
		 ( $loc_category == 0 + 64 ) ||
		 ( $loc_category == 0 + 63 ) ||
		 ( $loc_category == 0 + 130 ) ||
		 ( $loc_category == 0 + 33 ) )
		{	return( 1 ) if ( $rem_category == 0 + 72 );
			return( 1 ) if ( $rem_category == 0 + 16 );
			return( 1 ) if ( $rem_category == 0 + 65 );
			return( 1 ) if ( $rem_category == 0 + 125 );
			return( 1 ) if ( $rem_category == 0 + 62 );
			return( 1 ) if ( $rem_category == 0 + 64 );
			return( 1 ) if ( $rem_category == 0 + 63 );
			return( 1 ) if ( $rem_category == 0 + 130 );
			return( 1 ) if ( $rem_category == 0 + 33 );
		}
	elsif ( $loc_category == 0 + 31 )	# Suspicious
		{	return( 1 ) if ( $rem_category == 0 + 114 );
		}
	elsif ( $loc_category == 0 + 114 )
		{	return( 1 ) if ( $rem_category == 0 + 31 );
		}
	elsif ( ( $loc_category == 0 + 32 )	||	# Violence
		 ( $loc_category == 0 + 17 ) ||
		 ( $loc_category == 0 + 66 ) )
		{	return( 1 ) if ( $rem_category == 0 + 32 );
			return( 1 ) if ( $rem_category == 0 + 17 );
			return( 1 ) if ( $rem_category == 0 + 66 );
		}
		
	return( undef );
}



################################################################################
# 
sub DDBLookup( $$ )
#
#  Given a domain or an IP address, look it up on the remote DDB server .
#  Return the category number
#
################################################################################
{	my $server_ip	= shift;	# The IP address of the server that I am talking to
	my $lookup		= shift;
	
	$id = 0 + 0 if ( ! defined $id );
	$id++;	# Increment the ID
	my $category = &DDBQueryAsync( $socket, $lookup, $id );
	
	# Sometime I can get an undefined category. This indicates that there is a problem with the socket,
	# so shutdown the existing socket and open a new one
	if ( ! defined $category )
		{	print "Error on socket getting the category ...\n";
			print "Shutting down socket ...\n";
			$socket->shutdown( 2 );
			
			# Wait a bit
			sleep( 2 );
			
			print "Opening UDP socket IP $server_ip port $port_no ...\n";
			$socket = IO::Socket::INET->new( Proto => 'udp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
			die "Unable to open socket: $!\n" if ( ! defined $socket );
			
			# Reset the ID #
			$id = 0 + 0;
		}
		
	return( $category );
}



my %query;						# A hash of outstanding queries
################################################################################
# 
sub DDBQueryAsync( $$$ )
#
#  Given a socket and a domain, URL, or IP address name, a DDB server for the
#  category.  Return undef if an error, or the Lightspeed category number if OK.
#
# Request packet for getting the category of a domain called “domain.com”
# 0x00 0x00 | for a length of 0 – but later I fill with the overall length of the entire request, which in this case is 2 + 2 + 2 + 4 +2 + 2 + 2 + 2 + 10 = 22, or 0x00 0x16
# 0x00 0x01 | for a version of 1
# 0x00 0x14 | lookup code – in this case 0x14 for LOOKUP_URL, as opposed to 0x15 for LOOKUP_IP, or 0x16 for LOOKUP_IPv6
# 0x00 0x00 0x00 0x09 | the ID # – in this case “9” – but it is just a number, usually sequential, used to keep the requests and replies straight
# 0x00 0x10 | The length of the options part of the request packet, in this case 2 + 2 + 2 + 2 + 10 = 16 - you have include the length field itself
# 0x00 0x01 | for the # of options – in this case 1 for a domain, but 2 for a URL
# 0x00 0x02 | for OPT_HOST value of 2. This could be 1 for OPT_URL
# 0x00 0x0a | for the length of the string “domain.com”, i.e. 10
# domain.com | the string containing the domain name I am trying to look up as ascii, NOT padded to a round number of bytes
#
# If I am requesting a URL, I put the two byte length of the URL, the URL itself, and then the two byte length of the domain, and
# the domain itself into the options part of the request packet
#
################################################################################
{	my $socket	= shift;
	my $lookup	= shift;	# This is what I am looking up - could be a domain, a URL, or an IP
	my $id		= shift;
	
	return( undef ) if ( ! defined $lookup );
	
	my $domain;
	my $url;
	my $ip;
	
	my $type	= &UrlType( $lookup );
	$url		= $lookup if ( $type == 0 + 3 );
	$ip			= $lookup if ( $type == 0 + 2 );
	$domain		= $lookup if ( $type == 0 + 1 );
	
	
	# First build the options part of the request
	my $options_part;
	my $lookup_type;
	
	if ( defined $domain )
		{	$lookup_type = 0x14;
			my $domain_length = length( $domain );
			my $option_length = 8 + $domain_length;
			
			# Pack in the option length, the # of options (1), the OPT_HOST value of 2, the length of the domain name string, and the domain name
			$options_part = pack( "nnnn", $option_length, 1, 2, $domain_length ) . $domain;
		}
	elsif ( defined $ip )
		{	$lookup_type = 0x15;
			
			# For an IP lookup I just have to pack the IP address
			$options_part = &StringToIP( $ip );
		}
	else	# has to be a URL
		{	$lookup_type = 0x14;
		}
	
	
	# Calculate the overall request length
	my $request_length = 10 + length( $options_part );
	
	# Build up the request with request length, version, lookup type, ID, and options
	my $request = pack( "nnnN", $request_length, 1, $lookup_type, $id ) . $options_part;
	

	if ( $opt_debug )
		{	my $request_size = length( $request );
			print "Request size: $request_size\n";
			print "Request ID: $id\n";
			
			if ( defined $domain )
				{	print "Request Domain: $domain\n";
				}
			elsif ( defined $ip )
				{	print "Request IP: $ip\n";
				}
			else
				{	print "Request URL: $url\n";
				}
				
			my $hex = &HexPrint( $request );
			print "Full Request (Hex): $hex\n" if ( $hex );
			
		}
	

	# Keep track of the query
	$query{ $id } = $lookup;

	
	print $socket $request;

	my $resp_lookup;
	my $category;
	
	my $loop_counter = 0 + 0;
	while ( ! $resp_lookup )
		{	( $resp_lookup, $category ) = &DDBResponseAsync( $socket, $id );
			last if ( ! defined $category );
			
			# Am I just waiting?
			if ( ! $resp_lookup )
				{	$loop_counter++;
					&SqlSleep();
					
					# Try resending the request once
					if ( $loop_counter == 0 + 200 )
						{	print "After no response resending request, ID $id\n" if ( $opt_debug );
							print $socket $request;
						}
						
					# Try resending the request again
					if ( $loop_counter == 0 + 400 )
						{	print "After no response resending request, ID $id\n" if ( $opt_debug );
							print $socket $request;
						}
						
					last if ( $loop_counter > 600 );
				}
		}	
	
	# Did I have to wait too long for an answer?	
	if ( $loop_counter > 600 )
		{	print "Timeout waiting for DDB response for ID $id ...\n" if ( $opt_debug );
			return( undef );
		}
		
	return( $category );
}



################################################################################
# 
sub DDBResponseAsync( $$ )
#
#  Given a socket, return the url and the Lightspeed category if a response is waiting.
#  Return (undef, 1) if nothing is there, return (undef, undef) if an error
#
################################################################################
{	my $socket	= shift;
	my $resp_id	= shift;	# This is the ID of the response that i am looking for

	# Is it ready for reading?	
	my $rin ="";
	my $rout;
	vec( $rin, fileno( $socket ), 1 ) = 1;
	return( undef, 1 ) if ( select( $rout=$rin, undef, undef, 0 ) == 0 );

	my $data_len;
	
	my $num_read = 0 + 0;
	while ( ! $num_read )
		{	$num_read = read( $socket, $data_len, 2 );
			return( undef, 1 ) if ( ! defined $num_read );
		}
	
	print "Response read length: $num_read\n" if ( $opt_debug );
	
	my $response_len = unpack( "n", $data_len );
	print "Response length: $response_len\n" if ( $opt_debug );

	my $data;
	$num_read = read( $socket, $data, $response_len - 2 );
	
	my $response = $data_len . $data;
	
	if ( $opt_debug )
		{	my $hex = &HexPrint( $response );
			print "Response (Hex): $hex\n" if ( $hex );
		}
		
	# The response header is the first 10 bytes
	my $response_header  = substr( $response, 0, 10 );

	# Unpack the header
	my ( $resp_len, $version, $code, $rec_id  ) = unpack( "nnnN", $response_header );

	if ( $opt_debug )
		{	print "Response header length: $resp_len\n";
			print "Response version: $version\n";
			print "Header code: $code\n";
			print "Received ID: $rec_id\n";
		}
	
	
	# Is this the right ID?
	# Sometimes UDP packets will echo around the place
	if ( $resp_id != $rec_id )
		{	print "Received ID $rec_id, looking for response ID of $resp_id\n" if ( $opt_debug );
			
			# Just return that nothing is there
			return( undef, 1 );
		}
	
	
	if ( ( $code & 0x8000 ) == 0 )
		{	print "Missing response bit\n";
			return( undef, 1 );
		}
		
		
	# Turn off the response bit
	$code -= 0x8000;
	printf( "Returned code = 0x%02x\n", $code ) if ( $opt_debug );
	
	my $categoryNumber;
	
	
	if ( $code == 0x14 )	# It is a returned URL lookup
		{	my $len = $response_len - 10;
			my $response_value  = substr( $response, 10, $len );
			if ( ! defined $response_value )
				{	print "Got a undefined response value\n";
					return( undef, undef );
				}
			
			my $value_length = length( $response_value );
			print "Response value length: $value_length\n" if ( $opt_debug );
			
			if ( $value_length < 6 )
				{	print "Got a weird value length of $value_length\n";
					return( undef, undef );
				}
			
			my ( $category_num, $ttl, $options_length, $options_num ) = unpack( "nNnn", $response_value );
			
			$categoryNumber = $category_num;
			
			if ( $opt_debug )
				{	print "Response Lightspeed category number $categoryNumber\n";
					print "Response ttl $ttl\n";
					print "Response options length $options_length\n";
					print "Response options num $options_num\n";
				}
				
			$len = $response_len - 20;
			my $option_value  = substr( $response, 20, $len );

			my ( $opt, $opt_len ) = unpack( "nn", $option_value );
			
			if ( $opt_debug )
				{	print "opt = $opt\n";
					print "opt len = $opt_len\n";
				}
				
			if ( $opt == 3 )  # Then it is a domain name
				{	$len = length( $option_value ) - 4;
					my $domain = substr( $option_value, 4, $opt_len );
					
					print "Returned domain name = $domain\n" if ( $opt_debug );
				}
		}
	elsif ( $code == 0x15 )	# It is a returned IP address lookup
		{	my $len = $response_len - 10;
			my $response_value  = substr( $response, 10, $len );
			if ( ! defined $response_value )
				{	print "Got a undefined response value\n";
					return( undef, undef );
				}
			
			my $value_length = length( $response_value );
			print "Response value length: $value_length\n" if ( $opt_debug );
			
			if ( $value_length < 6 )
				{	print "Got a weird value length of $value_length\n";
					return( undef, undef );
				}
			
			my ( $category_num, $ttl ) = unpack( "nN", $response_value );
			
			$categoryNumber = $category_num;
			
			if ( $opt_debug )
				{	print "Response Lightspeed category number $categoryNumber\n";
					print "Response ttl $ttl\n";
				}
		}
	else
		{	printf( "Unknown response return code = 0x%02x\n", $code );
			return( undef, undef );
		}
		
		
	my $look = $query{ $id };
	
	# Delete the query from the hash
	delete $query{ $id };

	return( $look, $categoryNumber );
}



################################################################################
# 
sub SqlDiff()
#
#  Compare the contents of the main tables in the remote IpmContent database  
#  to the local IpmContent database
#
################################################################################
{
	my $str;
	my $sth;
	my $count		= 0 + 0;
	my $lookup		= 0 + 0;
	my $different	= 0 + 0;


	if ( ! open( OUTPUT, ">$output_file_name" ) )
		{	lprint "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	lprint "Opened file $output_file_name for output\n";
		
	
	if ( ( $opt_print )  &&  ( ! open( PFILE, ">$opt_print" ) ) )
		{	lprint "Error opening difference file $opt_print: $!\n";
			exit( 0 );
		}

	lprint "Opened file $opt_print for printing differences\n" if ( $opt_print );
	lprint "Difference file: entry, local category, remote category, local source, remote source\n" if ( $opt_print );
	
	
	my $older_time;
	if ( $opt_older )
		{	# Calculate older time in SQL format
			my $older_time_seconds = time() - ( $opt_older * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $older_time_seconds );
			$year = 1900 + $year;
			$mon = $mon + 1;
			$older_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, 0, 0, 0, 0 );
		}

	my $younger_time;
	if ( $opt_younger )
		{	# Calculate younger time in SQL format
			my $younger_time_seconds = time() - ( $opt_younger * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $younger_time_seconds );
			$year = 1900 + $year;
			$mon = $mon + 1;
			$younger_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, 0, 0, 0, 0 );
		}


	# Figure out the expired category
	my $expired_category = &CategoryNumber( "expired" );
	$expired_category = 0 + 105 if ( ! $expired_category );

		
	if ( ! $opt_domains_only )
		{	if ( ! $opt_compare_only )
				{	# First get the different VirusSignatures
					lprint "Looking for different Virus Signatures ...\n";

					$str = "SELECT VirusName, CategoryNumber, VirusType, AppSig, SigStart, SigEnd, Signature, SourceNumber FROM VirusSignatures WITH(NOLOCK)";
					$str = "SELECT VirusName, CategoryNumber, VirusType, AppSig, SigStart, SigEnd, Signature, SourceNumber FROM VirusSignatures WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

					if ( $opt_older )
						{	$str = "SELECT VirusName, CategoryNumber, VirusType, AppSig, SigStart, SigEnd, Signature, SourceNumber FROM VirusSignatures WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
							$str = "SELECT VirusName, CategoryNumber, VirusType, AppSig, SigStart, SigEnd, Signature, SourceNumber FROM VirusSignatures WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}
						
					if ( $opt_younger )
						{	$str = "SELECT VirusName, CategoryNumber, VirusType, AppSig, SigStart, SigEnd, Signature, SourceNumber FROM VirusSignatures WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
							$str = "SELECT VirusName, CategoryNumber, VirusType, AppSig, SigStart, SigEnd, Signature, SourceNumber FROM VirusSignatures WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}
						
					lprint "SQL Statement: $str\n";

					$sth = $dbhRemote->prepare( $str );

					$sth->execute();
					
					# Die here if I have an error
					my $sql_errstr = $dbhRemote->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );
					
					$count		= 0 + 0;
					$lookup		= 0 + 0;
					$different	= 0 + 0;
					
					print OUTPUT "TABLE: VirusSignatures\n";
					print PFILE "TABLE: VirusSignatures\n" if ( $opt_print );
					while ( ( ! $dbhRemote->err )  &&  ( my ( $virus_name, $remote_category, $rem_virus_type, $rem_appsig, $rem_sigstart, $rem_sigend, $rem_signature, $rem_source_number ) = $sth->fetchrow_array() ) )
						{	last if ( ! $virus_name );
							&SqlSleep() if ( ! $opt_no_sql_timeout );
							$lookup++;
							
							next if ( ! $virus_name );
							
							my $local_str = "SELECT CategoryNumber, VirusType, AppSig, SigStart, SigEnd, Signature, SourceNumber FROM VirusSignatures WWITH(NOLOCK) WHERE VirusName = '$virus_name'";

							my $local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
							
							my ( $local_category, $loc_virus_type, $loc_appsig, $loc_sigstart, $loc_sigend, $loc_signature, $loc_source_number ) = $local_sth->fetchrow_array();
												
							$local_sth->finish();
							
							my $rem_sig = lc( "$rem_virus_type\t$rem_appsig\t$rem_sigstart\t$rem_sigend\t$rem_signature" );
							my $loc_sig = lc( "$loc_virus_type\t$loc_appsig\t$loc_sigstart\t$loc_sigend\t$loc_signature" ) if ( defined $local_category );

							if ( ! defined $local_category )
								{	print OUTPUT "$virus_name\t$remote_category\t$rem_source_number\n";
									
									if ( ( $opt_errors )  &&  ( $remote_category != 7 ) )
										{	$local_str = "INSERT INTO VirusSignatures ( VirusName, VirusType, AppSig, SigStart, SigEnd, Signature, CategoryNumber, [Test], SourceNumber ) VALUES ( '$virus_name', '$rem_virus_type', '$rem_appsig', '$rem_sigstart', '$rem_sigend', '$rem_signature', '7', '0', '$rem_source_number' )";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE VirusSignatures SET TransactionTime = getutcdate(), CategoryNumber = '$remote_category', SourceNumber = '3' WHERE VirusName = '$virus_name'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$virus_name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number <= 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE VirusSignatures SET TransactionTime = getutcdate(), SourceNumber = '2', CategoryNumber = '$remote_category' WHERE VirusName = '$virus_name'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$virus_name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( ( $local_category != $remote_category )  ||  ( $rem_sig ne $loc_sig ) )
								{	if ( ( ! $opt_no_update )  &&  ( &ShouldUpdateTransactionTime( $loc_source_number, $rem_source_number ) ) )
										{	$local_str = "UPDATE VirusSignatures SET TransactionTime = getutcdate() WHERE VirusName = '$virus_name'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$virus_name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							
							&ShowCounter( "Virus Signatures", $count, $lookup, $different, 10 );
						}

					$sth->finish();
					
					lprint "Looked up $lookup Virus Signatures, found $count missing and $different different Virus Signatures\n";
					

					# Next check the Disinfect Scripts
					lprint "Looking for different Disinfect Scripts ...\n";

					$str = "SELECT VirusName, Description, Script, CategoryNumber, SourceNumber FROM DisinfectScripts WITH(NOLOCK)";
					$str = "SELECT VirusName, Description, Script, CategoryNumber, SourceNumber FROM DisinfectScripts WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

					if ( $opt_older )
						{	$str = "SELECT VirusName, Description, Script, CategoryNumber, SourceNumber FROM DisinfectScripts WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
							$str = "SELECT VirusName, Description, Script, CategoryNumber, SourceNumber FROM DisinfectScripts WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}
						
					if ( $opt_younger )
						{	$str = "SELECT VirusName, Description, Script, CategoryNumber, SourceNumber FROM DisinfectScripts WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
							$str = "SELECT VirusName, Description, Script, CategoryNumber, SourceNumber FROM DisinfectScripts WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}
						
					lprint "SQL Statement: $str\n";

					$sth = $dbhRemote->prepare( $str );

					$sth->execute();
					
					# Die here if I have an error
					$sql_errstr = $dbhRemote->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );

					$count		= 0 + 0;
					$lookup		= 0 + 0;
					$different	= 0 + 0;
					
					print OUTPUT "TABLE: DisinfectScripts\n";
					print PFILE "TABLE: DisinfectScripts\n" if ( $opt_print );
					while ( ( ! $dbhRemote->err )  &&  ( my ( $virus_name, $rem_description, $rem_script, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
						{	last if ( ! $virus_name );
							&SqlSleep() if ( ! $opt_no_sql_timeout );
							$lookup++;
							
							next if ( ! $virus_name );
							
							my $local_str = "SELECT [Description], [Script], CategoryNumber, SourceNumber FROM DisinfectScripts WITH(NOLOCK) WHERE VirusName = '$virus_name'";

							my $local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							my ( $loc_description, $loc_script, $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
												
							$local_sth->finish();
							
							my $rem_entry = lc( "$rem_description\t$rem_script\t$remote_category" );
							my $loc_entry = lc( "$loc_description\t$loc_script\t$local_category" ) if ( defined $local_category );

							if ( ! defined $local_category )
								{	print OUTPUT "$virus_name\t$remote_category\t$rem_source_number\n";
									
									if ( ( $opt_errors )  &&  ( $remote_category != 7 ) )
										{	$local_str = "INSERT INTO DisinfectScripts ( VirusName, [Description], [Script], CategoryNumber, SourceNumber ) VALUES ( '$virus_name', '$rem_description', '$rem_script', '7', '$rem_source_number' )";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE DisinfectScripts SET TransactionTime = getutcdate(), CategoryNumber = '$remote_category', SourceNumber = '3' WHERE VirusName = '$virus_name'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$virus_name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number <= 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE DisinfectScripts SET TransactionTime = getutcdate(), SourceNumber = '2', CategoryNumber = '$remote_category' WHERE VirusName = '$virus_name'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$virus_name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( ( $local_category != $remote_category )  ||  ( $rem_entry ne $loc_entry ) )
								{	if ( ( ! $opt_no_update )  &&  ( &ShouldUpdateTransactionTime( $loc_source_number, $rem_source_number ) ) )
										{	$local_str = "UPDATE DisinfectScripts SET TransactionTime = getutcdate() WHERE VirusName = '$virus_name'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$virus_name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							
							&ShowCounter( "Disinfect Scripts", $count, $lookup, $different, 10 );
						}

					$sth->finish();
					
					lprint "Looked up $lookup Disinfect Scripts, found $count missing and $different different Disinfect Scripts\n";
					

					# Next get the different ApplicationProcesses
					lprint "Looking for different File IDs ...\n";

					$str = "SELECT FileID, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK)";
					$str = "SELECT FileID, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

					if ( $opt_older )
						{	$str = "SELECT FileID, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
							$str = "SELECT FileID, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}
						
					if ( $opt_younger )
						{	$str = "SELECT FileID, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
							$str = "SELECT FileID, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}
						
					lprint "SQL Statement: $str\n";

					$sth = $dbhRemote->prepare( $str );

					$sth->execute();

					# Die here if I have an error
					$sql_errstr = $dbhRemote->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );
											
					$count		= 0 + 0;
					$lookup		= 0 + 0;
					$different	= 0 + 0;
					
					print OUTPUT "TABLE: ApplicationProcesses\n";
					print PFILE "TABLE: ApplicationProcesses\n" if ( $opt_print );
					while ( ( ! $dbhRemote->err )  &&  ( my ( $file_id, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
						{	last if ( ! $file_id );
							&SqlSleep() if ( ! $opt_no_sql_timeout );
							$lookup++;
							
							next if ( ! $file_id );
							
							my $local_str = "SELECT CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE FileID = '$file_id'";
							my $local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
							
							my ( $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
							
							$local_sth->finish();
							
							if ( ! defined $local_category )
								{	print OUTPUT "$file_id\t$remote_category\t$rem_source_number\n";
									
									if ( ( $opt_errors )  &&  ( $remote_category != 7 ) )
										{	$local_str = "INSERT INTO ApplicationProcesses ( FileID, AppName, Process, CategoryNumber, SourceNumber ) VALUES ( '$file_id', 'Error fixup', 'Error', '7', '$rem_source_number' )";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE ApplicationProcesses SET TransactionTime = getutcdate(), CategoryNumber = '$remote_category', SourceNumber = '3' WHERE FileID = '$file_id'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$file_id\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number <= 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE ApplicationProcesses SET TransactionTime = getutcdate(), SourceNumber = '2', CategoryNumber = '$remote_category' WHERE FileID = '$file_id'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$file_id\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( $local_category != $remote_category )
								{	if ( ( ! $opt_no_update )  &&  ( &ShouldUpdateTransactionTime( $loc_source_number, $rem_source_number ) ) )
										{	$local_str = "UPDATE ApplicationProcesses SET TransactionTime = getutcdate() WHERE FileID = '$file_id'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$file_id\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							
							&ShowCounter( "File IDs", $count, $lookup, $different, 100 );
						}

					$sth->finish();
					
					lprint "Looked up $lookup File IDs, found $count missing and $different different File IDs\n";
					
					
					# If just comparing virus tables then I can quit here
					if ( $opt_virus )
						{	close( OUTPUT );
							return( 1 );
						}
						
					# Get the different SpamPatterns
					lprint "Looking for different SpamPatterns ...\n";

					$str = "SELECT [Name], CategoryNumber, SourceNumber, [Result], TYPE1, VALUE1 FROM SpamPatterns WITH(NOLOCK)";
					$str = "SELECT [Name], CategoryNumber, SourceNumber, [Result], TYPE1, VALUE1 FROM SpamPatterns WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

					if ( $opt_older )
						{	$str = "SELECT [Name], CategoryNumber, SourceNumber, [Result], TYPE1, VALUE1  FROM SpamPatterns WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
							$str = "SELECT [Name], CategoryNumber, SourceNumber, [Result], TYPE1, VALUE1  FROM SpamPatterns WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}

					if ( $opt_younger )
						{	$str = "SELECT [Name], CategoryNumber, SourceNumber, [Result], TYPE1, VALUE1  FROM SpamPatterns WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
							$str = "SELECT [Name], CategoryNumber, SourceNumber, [Result], TYPE1, VALUE1  FROM SpamPatterns WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
						}

					lprint "SQL Statement: $str\n";

					$sth = $dbhRemote->prepare( $str );

					$sth->execute();

					# Die here if I have an error
					$sql_errstr = $dbhRemote->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );

					$count		= 0 + 0;
					$lookup		= 0 + 0;
					$different	= 0 + 0;
					
					print OUTPUT "TABLE: SpamPatterns\n";
					print PFILE "TABLE: SpamPatterns\n" if ( $opt_print );
					while ( ( ! $dbhRemote->err )  &&  ( my ( $name, $remote_category, $rem_source_number, $rem_result, $rem_type1, $rem_value1 ) = $sth->fetchrow_array() ) )
						{	last if ( ! defined $name );
							&SqlSleep() if ( ! $opt_no_sql_timeout );
							$lookup++;
							
							my $qname = $name;
							$qname =~ s/'/''/g;
							
							my $local_str = "SELECT CategoryNumber, SourceNumber, TYPE1, VALUE1 FROM SpamPatterns WITH(NOLOCK) WHERE [Name] = '$qname'";
							my $local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							my ( $local_category, $loc_source_number, $loc_type1, $loc_value1 ) = $local_sth->fetchrow_array();
							
							$local_sth->finish();
							
							if ( ! defined $local_category )
								{	print OUTPUT "$name\t$remote_category\t$rem_source_number\n";
									
									if ( ( $opt_errors )  &&  ( $remote_category != 7 ) )
										{	$local_str = "INSERT INTO SpamPatterns ( [Name], CategoryNumber, SourceNumber, [Result], [TYPE1], VALUE1, TYPE2, VALUE2, TYPE3, VALUE3, TYPE4, VALUE4 ) VALUES ( '$qname', '7', '$rem_source_number', '$rem_result', 'BODY', 'Error - deleting entry', '', '', '', '', '', '' )";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE SpamPatterns SET TransactionTime = getutcdate(), CategoryNumber = '$remote_category', SourceNumber = '3' WHERE [Name] = '$qname'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( ( $opt_source )  &&  ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number <= 0 + 2 ) )
								{	if ( ! $opt_no_update )
										{	$local_str = "UPDATE SpamPatterns SET TransactionTime = getutcdate(), SourceNumber = '2', CategoryNumber = '$remote_category' WHERE [Name] = '$qname'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							elsif ( ( $local_category != $remote_category )  ||
								( ! $loc_type1 )  ||
								( ! $loc_value1 )  ||
								( $loc_type1 ne $rem_type1 )  ||
								( $loc_value1 ne $rem_value1 ) )
								{	if ( ! $opt_no_update )
										{	$loc_type1 = "BODY" if ( ! $loc_type1 );
											my $qloc_type1 = &quoteurl( $loc_type1 );
											
											$loc_value1 = "Error - entry program in SpamPatterns" if ( ! $loc_value1 );
											my $qloc_value1 = &quoteurl( $loc_value1 );
											
											$local_str = "UPDATE SpamPatterns SET TransactionTime = getutcdate(), TYPE1 = '$qloc_type1', VALUE1 = '$qloc_value1',
											TYPE2 = '', VALUE2 = '', TYPE3 = '', VALUE3 = ' ', TYPE4 = '', VALUE4 = '' WHERE [Name] = '$qname'";
											$local_sth = $dbh->prepare( $local_str );
											
											$local_sth->execute();
											
											# Die here if I have an error
											my $sql_errstr = $dbh->errstr;
											die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
											$local_sth->finish();
										}
										
									$different++;
									
									print PFILE "$name\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
								}
							
							&ShowCounter( "SpamPatterns", $count, $lookup, $different, 10 );
						}

					$sth->finish();
					
					lprint "Looked up $lookup SpamPatterns, found $count missing and $different different patterns\n";
			
				}	# End of ! $opt_compare_only
				
				
			
			# Get the different URLs
			lprint "Looking for different URLs ...\n";

			$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK)";
			$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

			if ( $opt_older )
				{	$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
					$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
				}

			if ( $opt_younger )
				{	$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
					$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
				}

			lprint "SQL Statement: $str\n";

			$sth = $dbhRemote->prepare( $str );

			$sth->execute();

			# Die here if I have an error
			my $sql_errstr = $dbhRemote->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );

			$count		= 0 + 0;
			$lookup		= 0 + 0;
			$different	= 0 + 0;
			
			print OUTPUT "TABLE: IpmContentURL\n";
			print PFILE "TABLE: IpmContentURL\n" if ( $opt_print );
			while ( ( ! $dbhRemote->err )  &&  ( my ( $url, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
				{	last if ( ! $url );
					&SqlSleep() if ( ! $opt_no_sql_timeout );
					$lookup++;
					
					next if ( ! $url );
					
					my $qurl = &quoteurl( $url );
					my $local_str = "SELECT CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE URL = '$qurl'";
					my $local_sth = $dbh->prepare( $local_str );
					
					$local_sth->execute();
					
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					my ( $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
					
					$local_sth->finish();
					
					if ( ! defined $local_category )
						{	print OUTPUT "$url\t$remote_category\t$rem_source_number\n";
							
							if ( ( $opt_errors )  &&  ( $remote_category != 7 ) )
								{	$local_str = "INSERT INTO IpmContentURL ( URL, CategoryNumber, SourceNumber ) VALUES ( '$qurl', '7', '$rem_source_number' )";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
									
									$local_sth->finish();
								}
								
							$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
						}
					elsif ( ( $opt_source )  &&  ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
						{	if ( ! $opt_no_update )
								{	$local_str = "UPDATE IpmContentURL SET TransactionTime = getutcdate(), CategoryNumber = '$remote_category', SourceNumber = '3' WHERE URL = '$qurl'";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
									
									$local_sth->finish();
								}
								
							$different++;
							
							print PFILE "$url\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					elsif ( ( $opt_source )  &&  ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number <= 0 + 2 ) )
						{	if ( ! $opt_no_update )
								{	$local_str = "UPDATE IpmContentURL SET TransactionTime = getutcdate(), SourceNumber = '2', CategoryNumber = '$remote_category' WHERE URL = '$qurl'";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
									$local_sth->finish();
								}
								
							$different++;
							
							print PFILE "$url\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					elsif ( $local_category != $remote_category )
						{	if ( ( ! $opt_no_update )  &&  ( &ShouldUpdateTransactionTime( $loc_source_number, $rem_source_number ) ) )
								{	$local_str = "UPDATE IpmContentURL SET TransactionTime = getutcdate() WHERE URL = '$qurl'";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
									$local_sth->finish();
								}
								
							$different++;
														
							print PFILE "$url\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}

					&ShowCounter( "URLs", $count, $lookup, $different, 1000 );
				}

			$sth->finish();
			
			lprint "Looked up $lookup URLs, found $count missing and $different different URLs\n";
			

			# next get the different IP addresses
			lprint "Looking for different IP addressess ...\n";
			
			$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK)";
			$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

			if ( $opt_older )
				{	$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
					$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
				}

			if ( $opt_younger )
				{	$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
					$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
				}

			lprint "SQL Statement: $str\n";

			$sth = $dbhRemote->prepare( $str );

			$sth->execute();
			
			# Die here if I have an error
			$sql_errstr = $dbhRemote->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );
											
			
			$count		= 0 + 0;
			$lookup		= 0 + 0;
			$different	= 0 + 0;
			
			print OUTPUT "TABLE: IpmContentIpAddress\n";
			print PFILE "TABLE: IpmContentIpAddress\n" if ( $opt_print );
			while ( ( ! $dbhRemote->err )  &&  ( my ( $str_ip, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
				{	last if ( ! $str_ip );
					&SqlSleep() if ( ! $opt_no_sql_timeout );
					$lookup++;
					
  					my $local_str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIpAddress WITH(NOLOCK) WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
					my $local_sth = $dbh->prepare( $local_str );
				
					$local_sth->execute();
					
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
								
											
					my ( $local_str_ip, $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
					
					$local_sth->finish();
					
					if ( ! defined $local_category )
						{	print OUTPUT "$str_ip\t$remote_category\t$rem_source_number\n";
							
							if ( ( $opt_errors )  &&  ( $remote_category != 7 ) )
								{	my $str = "INSERT INTO IpmContentIpAddress ( IpAddress, CategoryNumber, SourceNumber ) VALUES ( dbo.IpmConvertIpToChar( '$str_ip' ), '$remote_category', '$rem_source_number' )";

									$local_sth = $dbh->prepare( $str );
								
									if ( ! $local_sth->execute() )
										{	&lprint( "Error adding IP address $str_ip\n" );
										}
										
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
									$local_sth->finish();
								}
								
							$count++ if ( ( $remote_category != 0 + 7 )  &&  ( $remote_category != $expired_category ) );
						}
					elsif ( ( $opt_source )  &&  ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
						{	if ( ! $opt_no_update )
								{	$local_str = "UPDATE IpmContentIpAddress SET TransactionTime = getutcdate(), CategoryNumber = '$remote_category', SourceNumber = '3' WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
									$local_sth->finish();
								}
								
							$different++;
							
							print PFILE "$str_ip\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					elsif ( ( $opt_source )  &&  ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number <= 0 + 2 ) )
						{	if ( ! $opt_no_update )
								{	$local_str = "UPDATE IpmContentIpAddress SET TransactionTime = getutcdate(), SourceNumber = '2', CategoryNumber = '$remote_category' WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
									$local_sth->finish();
								}
								
							$different++;
							
							print PFILE "$str_ip\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					elsif ( $local_category != $remote_category )
						{	if ( ( ! $opt_no_update )  &&  ( &ShouldUpdateTransactionTime( $loc_source_number, $rem_source_number ) ) )
								{	$local_str = "UPDATE IpmContentIpAddress SET TransactionTime = getutcdate() WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
									$local_sth->finish();
								}
								
							$different++;
							
							print PFILE "$str_ip\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					
					&ShowCounter( "IP addresses", $count, $lookup, $different, 10000 );
				}

			$sth->finish();
			
			lprint "Looked up $lookup IP addresses, found $count missing and $different different IP addresses\n";
		}
	
	
	# Next get the different domains
	lprint "Looking for different domains ...\n";
	
	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK)";
	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

	if ( $opt_older )
		{	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime < '$older_time'";
			$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime < '$older_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
		}

	if ( $opt_younger )
		{	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime > '$younger_time'";
			$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE TransactionTime > '$younger_time' AND CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );
		}

	lprint "SQL Statement: $str\n";

	$sth = $dbhRemote->prepare( $str );
	
	$sth->execute();

	# Die here if I have an error
	my $sql_errstr = $dbhRemote->errstr;
	die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );
											

	$count		= 0 + 0;
	$lookup		= 0 + 0;
	$different	= 0 + 0;
	
	print OUTPUT "TABLE: IpmContentDomain\n";
	print PFILE "TABLE: IpmContentDomain\n" if ( $opt_print );
	while ( ( ! $dbhRemote->err )  &&  ( my ( $reverse_domain, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
		{	last if ( ! $reverse_domain );
			&SqlSleep() if ( ! $opt_no_sql_timeout );
			$lookup++;
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! $domain );
			
			my $local_str = "SELECT CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE DomainName = '$reverse_domain'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
			
			# Die here if I have an error
			my $sql_errstr = $dbh->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
			my ( $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
			
			$local_sth->finish();
			
			if ( ! defined $local_category )
				{	print OUTPUT "$domain\t$remote_category\t$rem_source_number\n";
					
					if ( ( $opt_errors )  &&  ( $remote_category != 7 ) )
						{	$local_str = "INSERT INTO IpmContentDomain ( DomainName, CategoryNumber, SourceNumber ) VALUES ( '$reverse_domain', '7', '$rem_source_number' )";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
						}
								
					$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
				}
			elsif ( ( $opt_source )  &&  ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
				{	if ( ! $opt_no_update )
						{	$local_str = "UPDATE IpmContentDomain SET TransactionTime = getutcdate(), CategoryNumber = '$remote_category', SourceNumber = '3' WHERE DomainName = '$reverse_domain'";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
						}
						
					$different++;
					
					print PFILE "$domain\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
				}
			elsif ( ( $opt_source )  &&  ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number <= 0 + 2 ) )
				{	if ( ! $opt_no_update )
						{	$local_str = "UPDATE IpmContentDomain SET TransactionTime = getutcdate(), SourceNumber = '2', CategoryNumber = '$remote_category' WHERE DomainName = '$reverse_domain'";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
						}
						
					$different++;
					
					print PFILE "$domain\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
				}
			elsif ( $local_category != $remote_category )
				{	if ( ( ! $opt_no_update )  &&  ( &ShouldUpdateTransactionTime( $loc_source_number, $rem_source_number ) ) )
						{	$local_str = "UPDATE IpmContentDomain SET TransactionTime = getutcdate() WHERE DomainName = '$reverse_domain'";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
						}
						
					$different++;
					
					print PFILE "$domain\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
				}
			
			&ShowCounter( "domains", $count, $lookup, $different, 10000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup domains, found $count missing and $different different domains\n";
	
	close( OUTPUT );	
	close( PFILE ) if ( $opt_print );
	
	return( 1 );
}



################################################################################
# 
sub ShouldUpdateTransactionTime( $$ )
#
#  Should I update the transaction time? It depends ...
#
################################################################################
{	my $loc_source_number		= shift;
	my $rem_source_number		= shift;
	
	# If I don't change about source problems, then update the transation time
	return( 1 ) if ( ! $opt_qsource );
	
	$loc_source_number = 0 + $loc_source_number;
	$rem_source_number = 0 + $rem_source_number;
	
	# Remote source 999 gets updated for sure
	return( 1 ) if ( $rem_source_number == 0 + 999 );
	
	# Remote source 1 doesn't get updated for sure
	return( undef ) if ( $rem_source_number == 0 + 1 );
	
	# If the local source is 999, and the remote source is not manual, then update
	return( 1 ) if ( ( $loc_source_number == 0 + 999 )  &&  ( $rem_source_number > 0 + 2 ) );
	
	# If the remote source is manual, and the local source isn't manual, then don't update
	return( undef ) if ( ( $rem_source_number < 0 + 3 )  &&  ( $loc_source_number > 0 + 2 ) );
	
	return( 1 );
}



my $last_cnt;
my $last_diff;
my $last_look;
################################################################################
# 
sub ShowCounter( $$$$$ )
#
#  Show a progress counter 
#
################################################################################
{	my $type		= shift;
	my $count		= shift;
	my $lookup		= shift;
	my $different	= shift;
	my $divisor		= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $lookup )  ||  ( ! $divisor ) );
	
	# If nothing much has happened then return
	return( undef ) if ( ( $count < $divisor )  &&  ( $different < $divisor )  &&  ( $lookup < 100000 ) );
	
	my $look = 100000 * sprintf( "%d", ( $lookup / 100000 ) ); 

	my $cnt = $divisor * sprintf( "%d", ( $count / $divisor ) );
	
	my $diff = $divisor * sprintf( "%d", ( $different / $divisor ) );
	
	# Nothing happening yet?
	return( undef ) if ( ( ! $look )  &&  ( ! $cnt )  &&  ( ! $diff ) );

	# Has something reached a round divisor number?
	return( undef ) if ( ( $cnt != $count )  &&  ( $diff != $different )  &&  ( $look != $lookup ) );
	

	my $lookup_show = 1 if ( ( $look )  &&  ( $look == $lookup ) );
	$lookup_show = undef if ( ( $last_look )  &&  ( $last_look == $look ) ); 

	my $count_show = 1 if ( ( $cnt )  &&  ( $cnt == $count ) );
	$count_show = undef if ( ( $last_cnt )  &&  ( $last_cnt == $cnt ) ); 

	my $diff_show = 1 if ( ( $diff )  &&  ( $diff == $different ) );
	$diff_show = undef if ( ( $last_diff )  &&  ( $last_diff == $diff ) ); 


	return( undef ) if ( ( ! $lookup_show )  &&  ( ! $count_show )  &&  ( ! $diff_show ) );
	
	print "Type: $type - looked up $lookup total, found $count missing, $different different so far ...\n";
	
	$last_cnt	= $cnt;
	$last_diff	= $diff;
	$last_look	= $look;
	
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
		
	$dbhRemote = DBI->connect( "DBI:ODBC:RemoteContent", "IpmContent" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhRemote )
		{	sleep( 10 );
			$dbhRemote = DBI->connect( "DBI:ODBC:RemoteContent", "IpmContent" );
			
			return( undef ) if ( ! $dbhRemote );
		}
	
	# Make sure that I can read long disinfect scripts up to 50 k in size
	$dbhRemote->{LongReadLen} = 50 * 1024;
				
	return( $dbhRemote );
}



################################################################################
# 
sub SqlMissing( $ )
#
#  Touch and update the transaction time of any database entries found in the  
#  missing file or different file
#
################################################################################
{	my $missing_file = shift;
	
	return( undef ) if ( ! defined $missing_file );
	
	if ( ! open( MISSING, "<$missing_file" ) )
		{	lprint "Error opening $missing_file: $!\n";
			return( undef );
		}
	
	
	lprint "Updating the TransactionTime in the local database for entries in file $missing_file ...\n";
	lprint "Changing the existing SourceNumber to 3\n" if ( $opt_source );
	lprint "Only updating the TransactionTime for SourceNumber <= $opt_fmiss\n" if ( $opt_fmiss );

	my @ignore_list;
	if ( $opt_ignore )
		{	my @tmp_list = split /\,/, $opt_ignore;
			foreach( @tmp_list )
				{	my $cat_num = 0 + $_;
					next if ( $cat_num < 0 + 1 );
					next if ( $cat_num > 0 + 200 );
					push @ignore_list, $cat_num;
				}
				
			lprint "Ignoring categories @ignore_list\n";
		}
		
	
	my $table;
	my $counter = 0 + 0;
	while ( my $line = <MISSING> )
		{	chomp( $line );
			next if ( ! defined $line );
			next if ( $line eq "" );
			
			# Is this line setting the table?
			if ( $line =~ m/^TABLE:/ )
				{	lprint "Updated the TransactionTime in $counter rows of table $table\n" if ( ( $counter )  &&  ( $table ) );
					
					$table = $line;
					$table =~ s/^TABLE://;
					$table =~ s/^\s+//;
					$table =~ s/\s+$//;
					
					$counter = 0 + 0;
					
					lprint "Now updating the TransactionTime in table $table\n";
					next;	
				}
			
			next if ( ! $table );
			
			if ( $table =~ m/IpmContentIpAddress/i )
				{	my ( $str_ip, $category_number, $source_number, $junk ) = split /\t/, $line, 4;
					next if ( ! $str_ip );
					
					$category_number = 0 + $category_number;
					next if ( ( $opt_ignore )  &&  ( &IgnoreList( $category_number, @ignore_list ) ) );
						
					# Should I ignore this source number?
					$source_number = 0 + $source_number;
					next if ( ( $opt_fmiss )  &&  ( $source_number > $opt_fmiss ) );
										
					my $str = "UPDATE IpmContentIpAddress SET TransactionTime = getutcdate() WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
					$str = "UPDATE IpmContentIpAddress SET SourceNumber = '3', TransactionTime = getutcdate() WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )" if ( $opt_source );
					
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/IpmContentDomain/i )
				{	my ( $domain, $category_number, $source_number, $junk ) = split /\t/, $line, 4;
					next if ( ! $domain );
					
					$category_number = 0 + $category_number;
					next if ( ( $opt_ignore )  &&  ( &IgnoreList( $category_number, @ignore_list ) ) );

					# Should I ignore this source number?
					$source_number = 0 + $source_number;
					next if ( ( $opt_fmiss )  &&  ( $source_number > $opt_fmiss ) );
					
					my $reverse_domain = &ReverseDomain( $domain );
					next if ( ! $reverse_domain );
					
					my $str = "UPDATE IpmContentDomain SET TransactionTime = getutcdate() WHERE DomainName = '$reverse_domain'";
					$str = "UPDATE IpmContentDomain SET SourceNumber = '3', TransactionTime = getutcdate() WHERE DomainName = '$reverse_domain'" if ( $opt_source );

					my $sth = $dbh->prepare( $str );

					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/SpamPatterns/i )			
				{	my ( $name, $category_number, $source_number, $junk ) = split /\t/, $line, 4;
					next if ( ! defined $name );
					
					$category_number = 0 + $category_number;
					next if ( ( $opt_ignore )  &&  ( &IgnoreList( $category_number, @ignore_list ) ) );

					# Should I ignore this source number?
					$source_number = 0 + $source_number;
					next if ( ( $opt_fmiss )  &&  ( $source_number > $opt_fmiss ) );
					
					my $qname = $name;
					$qname =~ s/'/''/g;
					
					my $str = "UPDATE SpamPatterns SET TransactionTime = getutcdate() WHERE [Name] = '$qname'";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/IpmContentURL/i )			
				{	my ( $url, $category_number, $source_number, $junk ) = split /\t/, $line, 4;
					next if ( ! $url );
					
					$category_number = 0 + $category_number;
					next if ( ( $opt_ignore )  &&  ( &IgnoreList( $category_number, @ignore_list ) ) );

					# Should I ignore this source number?
					$source_number = 0 + $source_number;
					next if ( ( $opt_fmiss )  &&  ( $source_number > $opt_fmiss ) );
					
					my $qurl = &quoteurl( $url );
					my $str = "UPDATE IpmContentURL SET TransactionTime = getutcdate() WHERE URL = '$qurl'";
					$str = "UPDATE IpmContentURL SET SourceNumber = '3', TransactionTime = getutcdate() WHERE URL = '$qurl'" if ( $opt_source );

					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/VirusSignatures/i )
				{	my ( $virus_name, $category_number, $source_number, $junk ) = split /\t/, $line, 4;
					next if ( ! $virus_name );
					
					$category_number = 0 + $category_number;
					next if ( ( $opt_ignore )  &&  ( &IgnoreList( $category_number, @ignore_list ) ) );

					# Should I ignore this source number?
					$source_number = 0 + $source_number;
					next if ( ( $opt_fmiss )  &&  ( $source_number > $opt_fmiss ) );
					
					my $str = "UPDATE VirusSignatures SET TransactionTime = getutcdate() WHERE VirusName = '$virus_name'";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/DisinfectScripts/i )
				{	my ( $virus_name, $category_number, $source_number, $junk ) = split /\t/, $line, 4;
					next if ( ! $virus_name );
					
					$category_number = 0 + $category_number;
					next if ( ( $opt_ignore )  &&  ( &IgnoreList( $category_number, @ignore_list ) ) );

					# Should I ignore this source number?
					$source_number = 0 + $source_number;
					next if ( ( $opt_fmiss )  &&  ( $source_number > $opt_fmiss ) );
					
					my $str = "UPDATE DisinfectScripts SET TransactionTime = getutcdate() WHERE VirusName = '$virus_name'";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/ApplicationProcesses/i )
				{	my ( $file_id, $category_number, $source_number, $junk ) = split /\t/, $line, 4;
					next if ( ! $file_id );
					
					$category_number = 0 + $category_number;
					next if ( ( $opt_ignore )  &&  ( &IgnoreList( $category_number, @ignore_list ) ) );

					# Should I ignore this source number?
					$source_number = 0 + $source_number;
					next if ( ( $opt_fmiss )  &&  ( $source_number > $opt_fmiss ) );
					
					my $str = "UPDATE ApplicationProcesses SET TransactionTime = getutcdate() WHERE FileID = '$file_id'";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
		}
		
	close( MISSING );
	
	lprint "Updated the TransactionTime in $counter rows of table $table\n" if ( ( $counter )  &&  ( $table ) );
	
	return( 1 );
}



################################################################################
# 
sub IgnoreList( @ )
#
#  Given a category number, return TRUE if it is on the ignore list
#
################################################################################
{	my $cat_num = shift;
	
	return( undef ) if ( ! $cat_num );
	
	while ( my $ignore = shift )
		{	return( $ignore ) if ( $cat_num == $ignore );
		}
		
	return( undef );
}



################################################################################
# 
sub SqlAdd( $ )
#
#  Add any entries into the MISSING table
#
################################################################################
{	my $add_file = shift;
	
	return( undef ) if ( ! defined $add_file );
	
	if ( ! open( ADD, "<$add_file" ) )
		{	lprint "Error opening $add_file: $!\n";
			return( undef );
		}
	
	
	lprint "Adding entries into the MISSING table from file $add_file ...\n";

	# Don't bother syncing up expired domains that don't exist
	my $expired_category = &CategoryNumber( "expired" );
	$expired_category = 0 + 105 if ( ! $expired_category );
	
	my $table;
	my $counter = 0 + 0;
	while ( my $line = <ADD> )
		{	chomp( $line );
			next if ( ! defined $line );
			next if ( $line eq "" );
			
			# Is this line setting the table?
			if ( $line =~ m/^TABLE:/ )
				{	lprint "Added into MISSING table $counter rows of table $table\n" if ( ( $counter )  &&  ( $table ) );
					
					$table = $line;
					$table =~ s/^TABLE://;
					$table =~ s/^\s+//;
					$table =~ s/\s+$//;
					
					$counter = 0 + 0;
					
					lprint "Now adding into MISSING table from $table\n";
					next;	
				}
			
			next if ( ! $table );
			
			if ( $table =~ m/IpmContentIpAddress/i )
				{	my ( $str_ip, $category_number, $remote_category_number, $source_number, $remote_source_number ) = split /\t/, $line;
					next if ( ! $str_ip );

					$source_number			= 0 + $source_number;
					$remote_source_number	= 0 + $remote_source_number;
					$remote_category_number = 0 + $remote_category_number;
					
					next if ( $remote_source_number != 0 + 2 );
					next if ( $remote_category_number == 0 + 7 );

					$category_number = 0 + $category_number;
					next if ( $category_number == ( 0 + 7 ) );
					next if ( $category_number == $expired_category );
										
					my $str = "INSERT INTO MISSING ( DomainName, CategoryNumber, SourceNumber ) VALUES ( '$str_ip', '$category_number', '$source_number' )";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/IpmContentDomain/i )
				{	my ( $domain, $category_number, $remote_category_number, $source_number, $remote_source_number ) = split /\t/, $line;
					next if ( ! $domain );
					next if ( ! $source_number );
					next if ( ! $remote_source_number );
					
					$source_number			= 0 + $source_number;
					$remote_source_number	= 0 + $remote_source_number;
					$remote_category_number = 0 + $remote_category_number;
					
					next if ( $remote_source_number != 0 + 2 );
					next if ( $remote_category_number == 0 + 7 );
					
					$category_number = 0 + $category_number;
					next if ( $category_number == ( 0 + 7 ) );
					next if ( $category_number == $expired_category );

					my $reverse_domain = &ReverseDomain( $domain );
					next if ( ! $reverse_domain );
					
					my $str = "INSERT INTO MISSING ( DomainName, CategoryNumber, SourceNumber ) VALUES ( '$domain', '$category_number', '$source_number' )";
					my $sth = $dbh->prepare( $str );

					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/SpamPatterns/i )			
				{	my ( $name, $category_number, $source_number ) = split /\t/, $line;
					
					next if ( ! defined $name );
					
					$category_number = 0 + $category_number;
					next if ( $category_number == ( 0 + 7 ) );
					next if ( $category_number == $expired_category );

					my $qname = $name;
					$qname =~ s/'/''/g;
					
					my $str = "";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/IpmContentURL/i )			
				{	my ( $url, $category_number, $source_number ) = split /\t/, $line;
					
					next if ( ! $url );
					
					$category_number = 0 + $category_number;
					next if ( $category_number == ( 0 + 7 ) );
					next if ( $category_number == $expired_category );

					my $qurl = &quoteurl( $url );
					my $str = "";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/VirusSignatures/i )
				{	my ( $virus_name, $category_number, $source_number ) = split /\t/, $line;
					
					next if ( ! $virus_name );
					
					$category_number = 0 + $category_number;
					next if ( $category_number == ( 0 + 7 ) );
					next if ( $category_number == $expired_category );

					my $str = "";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/DisinfectScripts/i )
				{	my ( $virus_name, $category_number, $source_number ) = split /\t/, $line;

					next if ( ! $virus_name );
					
					$category_number = 0 + $category_number;
					next if ( $category_number == ( 0 + 7 ) );
					next if ( $category_number == $expired_category );

					my $str = "";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
			elsif ( $table =~ m/ApplicationProcesses/i )
				{	my ( $file_id, $category_number, $source_number ) = split /\t/, $line;
					
					next if ( ! $file_id );
					
					$category_number = 0 + $category_number;
					next if ( $category_number == ( 0 + 7 ) );
					next if ( $category_number == $expired_category );

					my $str = "";
					my $sth = $dbh->prepare( $str );
							
					$sth->execute();
							
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$sth->finish();
					
					$counter++;
				}
		}
		
	close( ADD );
	
	lprint "Added $counter rows of $table into the MISSING table\n" if ( ( $counter )  &&  ( $table ) );
	
	return( 1 );
}



################################################################################
# 
sub SqlSpecial( $ )
#
#  Run some sort of special process to clean up the local database  
#
################################################################################
{	
	
	lprint "Correcting SourceNumber errors in the local database\n";

	if ( ! open( OUTPUT, ">$output_file_name" ) )
		{	lprint "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	lprint "Opened file $output_file_name for output\n";
		
	
	if ( ( $opt_print )  &&  ( ! open( PFILE, ">$opt_print" ) ) )
		{	lprint "Error opening difference file $opt_print: $!\n";
			exit( 0 );
		}

	lprint "Opened file $opt_print for printing source differences\n" if ( $opt_print );
	lprint "Difference file: entry, local category, remote category, local source, remote source\n" if ( $opt_print );
	
	
	my @ignore_list;
	if ( $opt_ignore )
		{	my @tmp_list = split /\,/, $opt_ignore;
			foreach( @tmp_list )
				{	my $cat_num = 0 + $_;
					next if ( $cat_num < 0 + 1 );
					next if ( $cat_num > 0 + 200 );
					push @ignore_list, $cat_num;
				}
				
			lprint "Ignoring categories @ignore_list\n";
		}
		
	
	# Figure out the expired category
	my $expired_category = &CategoryNumber( "expired" );
	$expired_category = 0 + 105 if ( ! $expired_category );


	my $str;
	my $sth;
	
	my $count		= 0 + 0;
	my $lookup		= 0 + 0;
	my $different	= 0 + 0;

	if ( ! $opt_domains_only )
		{	# Get the different URLs
			lprint "Looking for different source URLs ...\n";

			$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK)";
			$str = "SELECT URL, CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );


			lprint "SQL Statement: $str\n";

			$sth = $dbhRemote->prepare( $str );

			$sth->execute();

			# Die here if I have an error
			my $sql_errstr = $dbh->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );
											
											
			$count		= 0 + 0;
			$lookup		= 0 + 0;
			$different	= 0 + 0;
					
			print OUTPUT "TABLE: IpmContentURL\n";
			print PFILE "TABLE: IpmContentURL\n" if ( $opt_print );
			while ( ( ! $dbhRemote->err )  &&  ( my ( $url, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
				{	last if ( ! $url );
					$lookup++;
					
					next if ( ! $url );
					
					my $qurl = &quoteurl( $url );
					my $local_str = "SELECT CategoryNumber, SourceNumber FROM IpmContentURL WITH(NOLOCK) WHERE URL = '$qurl'";
					my $local_sth = $dbh->prepare( $local_str );
					
					$local_sth->execute();
					
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					my ( $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
					
					$local_sth->finish();
					
					if ( ! defined $local_category )
						{	print OUTPUT "$url\t$remote_category\t$rem_source_number\n";
								
							$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
						}
					elsif ( ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
						{	$local_str = "UPDATE IpmContentURL SET SourceNumber = '$rem_source_number' WHERE URL = '$qurl'";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
								
							$different++;
							
							print PFILE "$url\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					elsif ( ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number < 0 + 3 ) )
						{	$local_str = "UPDATE IpmContentURL SET SourceNumber = '2' WHERE URL = '$qurl'";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
				
							$different++;
							
							print PFILE "$url\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					
					&ShowCounter( "URLs", $count, $lookup, $different, 1000 );
				}

			$sth->finish();
			
			lprint "Looked up $lookup URLs, found $count missing and $different different source URLs\n";
			
			
			# next get the different IP addresses
			lprint "Looking for different source IP addressess ...\n";
			
			$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK)";
			$str = "SELECT dbo.IpmConvertIpToString( IpAddress ), CategoryNumber, SourceNumber FROM IpmContentIPAddress WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );


			lprint "SQL Statement: $str\n";

			$sth = $dbhRemote->prepare( $str );

			$sth->execute();
			
			# Die here if I have an error
			$sql_errstr = $dbhRemote->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );
											
			
			$count		= 0 + 0;
			$lookup		= 0 + 0;
			$different	= 0 + 0;
			
			print OUTPUT "TABLE: IpmContentIpAddress\n";
			print PFILE "TABLE: IpmContentIpAddress\n" if ( $opt_print );
			while ( ( ! $dbhRemote->err )  &&  ( my ( $str_ip, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
				{	last if ( ! $str_ip );
					$lookup++;
										
					my $local_str = "SELECT CategoryNumber, SourceNumber FROM IpmContentIpAddress WITH(NOLOCK) WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
					my $local_sth = $dbh->prepare( $local_str );
					
					$local_sth->execute();
					
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					my ( $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
					
					$local_sth->finish();
					
					if ( ! defined $local_category )
						{	print OUTPUT "$str_ip\t$remote_category\t$rem_source_number\n";
							
							$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
						}
					elsif ( ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
						{	$local_str = "UPDATE IpmContentIpAddress SET SourceNumber = '$rem_source_number' WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
								
							$different++;
							
							print PFILE "$str_ip\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					elsif ( ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number < 0 + 3 ) )
						{	if ( ! $opt_no_update )
								{	$local_str = "UPDATE IpmContentIpAddress SET SourceNumber = '2' WHERE IPAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
									$local_sth = $dbh->prepare( $local_str );
									
									$local_sth->execute();
									
									# Die here if I have an error
									my $sql_errstr = $dbh->errstr;
									die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
									$local_sth->finish();
								}
								
							$different++;
							
							print PFILE "$str_ip\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
						}
					
					&ShowCounter( "IP addresses", $count, $lookup, $different, 10000 );
				}

			$sth->finish();
			
			lprint "Looked up $lookup IP addresses, found $count missing and $different different source IP addresses\n";
		}
		
	
	# Next get the different domains
	lprint "Looking for different source domains ...\n";
	
	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK)";
	$str = "SELECT DomainName, CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE CategoryNumber NOT IN ($opt_ignore)" if ( $opt_ignore );

	lprint "SQL Statement: $str\n";

	$sth = $dbhRemote->prepare( $str );
	
	$sth->execute();

	# Die here if I have an error
	my $sql_errstr = $dbhRemote->errstr;
	die "SQL Error $sql_errstr\n" if ( $dbhRemote->err );
											

	$count		= 0 + 0;
	$lookup		= 0 + 0;
	$different	= 0 + 0;
	
	print OUTPUT "TABLE: IpmContentDomain\n";
	print PFILE "TABLE: IpmContentDomain\n" if ( $opt_print );
	while ( ( ! $dbhRemote->err )  &&  ( my ( $reverse_domain, $remote_category, $rem_source_number ) = $sth->fetchrow_array() ) )
		{	last if ( ! $reverse_domain );
			$lookup++;
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! $domain );
			
			my $local_str = "SELECT CategoryNumber, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE DomainName = '$reverse_domain'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
			
			# Die here if I have an error
			my $sql_errstr = $dbh->errstr;
			die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
			my ( $local_category, $loc_source_number ) = $local_sth->fetchrow_array();
			
			$local_sth->finish();
			
			if ( ! defined $local_category )
				{	print OUTPUT "$domain\t$remote_category\t$rem_source_number\n";
					
					$count++ if ( ( $remote_category != 7 )  &&  ( $remote_category != $expired_category ) );
				}
			elsif ( ( $loc_source_number == 0 + 2 )  &&  ( $rem_source_number > 0 + 2 ) )
				{	$local_str = "UPDATE IpmContentDomain SET SourceNumber = '$rem_source_number' WHERE DomainName = '$reverse_domain'";
					$local_sth = $dbh->prepare( $local_str );
					
					$local_sth->execute();
					
					# Die here if I have an error
					my $sql_errstr = $dbh->errstr;
					die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
					$local_sth->finish();
	
					$different++;
					
					print PFILE "$domain\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
				}
			elsif ( ( $loc_source_number > 0 + 2 )  &&  ( $rem_source_number < 0 + 3 ) )
				{	if ( ! $opt_no_update )
						{	$local_str = "UPDATE IpmContentDomain SET SourceNumber = '2' WHERE DomainName = '$reverse_domain'";
							$local_sth = $dbh->prepare( $local_str );
							
							$local_sth->execute();
							
							# Die here if I have an error
							my $sql_errstr = $dbh->errstr;
							die "SQL Error $sql_errstr\n" if ( $dbh->err );
											
							$local_sth->finish();
						}
						
					$different++;
					
					print PFILE "$domain\t$local_category\t$remote_category\t$loc_source_number\t$rem_source_number\n" if ( $opt_print );
				}
			
			&ShowCounter( "domains", $count, $lookup, $different, 10000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup domains, found $count missing and $different different source domains\n";
	
	close( OUTPUT );	
	close( PFILE ) if ( $opt_print );
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlDiff";

    print <<".";
Syntax: SqlDiff FILE

SqlDiff compares the local IpmContentDatabase to the RemoteContent database
and updates the TransactionTime in the local database for any entry that
is different.  Any entry that is missing is written to FILE.  The default name
for FILE is SqlDiff.txt.

  -a, --add FILE      add into the MISSING table any entries in FILE
  -b, --bspecial      special one off processing
  -c, --compare       compare domains, IPs, and URLs only
  -d, --domains       only compare domains, not IPs, URLs, or virus
  -e, --errors        insert missing entries in to the errors category
  -f, --fmiss SOURCE  when using option -m, only undate the TransactionTime
                      for SourceNumber <= SOURCE
  -i, --ignore LIST   the list of category numbers to ignore, i.e. 7,105
  -m, --missing FILE  update the TransactionTime for any database entry
                      found in FILE
  -n, --noupdate      don't update the TransactionTime on differing entries
  -o, --older DAYS    only compare entries that are older than DAYS
  -p, --print PFILE   print the differences to file PFILE
                      database entry, local category, remote category,
                      local source, remote source
  -q, --qsource       don't update TransactionTime on source conflicts
                      This is used for Category/Content database compares
  -r, --remote IP     Compare the remote database using the DDB protocol
                      IP is the address of the server (default 54.203.89.93)  
  -s, --source        Match up any source problems in the local database by
                      fixing SourceNumber, CategoryNumber, and TransactionTime
  -t, --timeout       run as fast as possible with no SQL timeouts
  -v, --virus         just compare the virus tables
  -w, --where STR     use a SQL WHERE STR on all of the SELECTs
  -y, --younger       only compare entries that are younger than DAYS

  -h, --help         show this help

.

    exit( 1 );
}



__END__

:endofperl
