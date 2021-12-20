################################################################################
#!perl -w
#
#  SqlCategory - Check the DomainReason in the Category database against IpmContent
#
#  5/6/2010 Rob McCarthy
#
################################################################################



use strict;
use warnings;


use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );
use Sys::Hostname;

use DBI qw(:sql_types);
use DBD::ODBC;

use Win32;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;

use Content::File;
use Content::SQL;
use Content::Category;



my $opt_version;
my $opt_verbose;						# Display verbose
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_debug;


my $dbh;								# The global database handle
my $dbhRemote;							# The handle to the remote database
my $dbhCategory;						# The global handle to the Category database
my $hostname;			# Global hostname value - just figure it out once to save time


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
		"x|xxx"				=> \$opt_debug,
		"v|verbose"			=> \$opt_verbose,
		"w|wizard"			=> \$opt_wizard,
        "h|help"			=> \$opt_help
    );


    &StdHeader( "SqlCategory" ) if ( ! $opt_wizard );
	
    &Usage() if ( ( $opt_help )  ||  ( $opt_version ) );
	
	
&SqlTemp();
die;


	&SetLogFilename( ".\\SqlCategory.log", undef );
	
		
	&TrapErrors() if ( ! $opt_debug );


    #  Open the local database
	lprint "Opening a connection to the local database ...\n";
    $dbh = &ConnectServer() or die;



	lprint "Opening a connection to the Category SQL server ...\n";
	$dbhCategory = &CategoryConnect();
	if ( ! $dbhCategory )
		{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";
		}
				
	# This function just flags in the DomainReason table all the currently active domains and IP addresses
	# from the IpmContent database
#	&SqlActiveFlags();
	
	
# Temporary to correct problems in the database
#&SqlCorrect();
	
#	&SqlContent();
	
#	&SqlCategory();
		
		
	$dbh->disconnect		if ( $dbh );
	&CategoryClose() if ( $dbhCategory );
	$dbhCategory = undef;
	
	lprint "Done.\n";

exit;

}
exit;



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename;

	$filename = "SqlCategoryErrors.log";
	
	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or &lprint( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	&lprint( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub SqlCategory()
#
#  Compare the contents of local IpmContent database to the DomainReason table
#  in the remote Category database
#
################################################################################
{
	open( OUTPUT, ">SqlCategory.txt" ) or die "Error opening SqlCategory.txt: $!\n";

	lprint "Looking for different domain categorizations ...\n";
	
	my $str = "SELECT DomainName, [Reason], CategoryNumber, TransactionTime FROM DomainReason WITH(NOLOCK) WHERE [Reason] LIKE 'Manually%' order by DomainName";

	my $sth = $dbhCategory->prepare( $str );
	
	$sth->execute();

	my $lookup		= 0 + 0;
	my $different	= 0 + 0;
	my $missing		= 0 + 0;
	my $changed_remote = 0 + 0;
	my $changed_local = 0 + 0;
	
	my @update_category;	# This is the list of updates to the category database
	my @delete_category;
	
	while ( ( ! $dbhCategory->err )  &&  ( my ( $domain, $reason, $remote_category, $remote_transaction_time ) = $sth->fetchrow_array() ) )
		{	$lookup++;
			next if ( ! defined $domain );
			next if ( ! $reason );
			
			my $original_domain = $domain;
			
			# Trim off leading and trailing spaces
			$domain =~ s/^\s+//;
			$domain =~ s/\s+$//;
			
			$domain = &CleanUrl( $domain );
			next if ( ! defined $domain );
			
			# Ignore urls
			next if ( $domain =~ m/\// );
			
			my $reverse_domain = &ReverseDomain( $domain );
			next if ( ! defined $reverse_domain );
			
			my $local_str = "SELECT CategoryNumber, SourceNumber, TransactionTime FROM IpmContentDomain WITH(NOLOCK) WHERE DomainName = '$reverse_domain'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
			
			my ( $local_category, $loc_source_number, $local_transaction_time ) = $local_sth->fetchrow_array();
			
			$local_sth->finish();
			
			$remote_transaction_time	= " " if ( ! $remote_transaction_time );
			$local_transaction_time		= " " if ( ! $local_transaction_time );
			
			if ( ( ! defined $loc_source_number )  ||  ( ! defined $local_category ) )
				{	if ( ! defined $remote_category )
						{	push @delete_category, $original_domain;
							next;
						}
						
					# If the Category server has it in errors, it is not really a problem
					next if ( $remote_category == 7 );  # Ignore errors
					next if ( $remote_category == 0 );  # Ignore old stuff
					
					$missing++;
					
					my $remote_catname;
					if ( ! defined $remote_category )
						{	$remote_catname = "None";
							$remote_category = " ";
						}
					else
						{	$remote_catname = &CategoryName( $remote_category );
						}

					print OUTPUT "Missing: $domain Category server $remote_category: $remote_catname, $remote_transaction_time\n";
				}
			elsif ( $loc_source_number > 2 )
				{	
					$different++;
					
					my $local_catname = &CategoryName( $local_category );
					$local_catname = "None" if ( ! $local_catname );

					print OUTPUT "Different Source: $domain $local_category: $local_catname, Source: $loc_source_number, $local_transaction_time\n";

					# Correct the source number and the category number if possible
					next if ( ! $remote_category );
					next if ( &IsIPAddress( $domain ) );
					
					$local_str = "UPDATE IpmContentDomain SET SourceNumber = '1', CategoryNumber = '$remote_category', TransactionTime = getutcdate() WHERE DomainName = '$reverse_domain'";
					$local_sth = $dbh->prepare( $local_str );
			
					$local_sth->execute();
						
					$local_sth->finish();
					
					$changed_local++;
				}
			elsif ( ( ! defined $remote_category )  ||  ( $local_category != $remote_category ) )
				{	
					$different++;
					
					my $local_catname = &CategoryName( $local_category );
					$local_catname = "None" if ( ! $local_catname );
					
					my $remote_catname;
					if ( ! defined $remote_category )
						{	$remote_catname = "None";
							$remote_category = " ";
						}
					else
						{	$remote_catname = &CategoryName( $remote_category );
						}
					
					
					print OUTPUT "Different Category: $domain $local_category: $local_catname, $local_transaction_time, Category server $remote_category: $remote_catname, $remote_transaction_time\n";
					
					push @update_category, "$original_domain\t$local_category\t$local_transaction_time";
				}
				
			&ShowCounter( "domains", $missing, $lookup, $different, 10000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup domains, found $different different and $missing missing domain cartegorizations\n";

	lprint "Changed $changed_local entries in the local database\n";
	
	close( OUTPUT );	

	lprint "Updating the Category server with missing or different category numbers from Content ...\n";

	foreach ( @update_category )
		{	my $line = $_;
			next if ( ! $line );
			my ( $domain, $local_category, $local_transaction_time ) = split /\t/, $line, 3;
			
			next if ( ! defined $domain );
			next if ( ! defined $local_category );
			next if ( ! defined $local_transaction_time );
			
			$str = "UPDATE DomainReason SET CategoryNumber = '$local_category', TransactionTime = '$local_transaction_time' WHERE DomainName = '$domain'";
			$sth = $dbhCategory->prepare( $str );
	
			$sth->execute();
				
			$sth->finish();
			
			$changed_remote++;
		}
		
	lprint "Changed $changed_remote entries in the Category database\n";
	
	
	my $deleted_remote = 0 + 0;	
	foreach ( @delete_category )
		{	my $domain = $_;
			next if ( ! defined $domain );
			
			$str = "DELETE DomainReason WHERE DomainName = '$domain'";
			$sth = $dbhCategory->prepare( $str );
	
			$sth->execute();
				
			$sth->finish();
			
			$changed_remote++;
		}
		
	lprint "Deleted $deleted_remote entries in the Category database\n";
		
	return( 1 );
}



################################################################################
# 
sub SqlContent()
#
#  Compare the contents of DomainReason table in the Category database to the 
#  local IpmContent database
#
################################################################################
{
	open( OUTPUT, ">SqlContent.txt" ) or die "Error opening SqlContent.txt: $!\n";

	# Get a good hostname to use
	$hostname = hostname if ( ! defined $hostname );
	$hostname = "undefined" if ( ! defined $hostname );
	$hostname = lc( $hostname );

	lprint "Making sure that the DomainReason exists for every manual entry on the local database ...\n";
	
	my $str = "SELECT DomainName, CategoryNumber, TransactionTime FROM IpmContentDomain WITH(NOLOCK) WHERE SourceNumber IN (1,2)";

	my $sth = $dbh->prepare( $str );
	
	$sth->execute();

	my $lookup		= 0 + 0;
	my $different	= 0 + 0;
	my $missing		= 0 + 0;
	
	while ( ( ! $dbh->err )  &&  ( my ( $reverse_domain, $local_category, $local_transaction_time ) = $sth->fetchrow_array() ) )
		{	$lookup++;
			next if ( ! defined $reverse_domain );
			next if ( ! $local_category );
			next if ( ! $local_transaction_time );
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! defined $domain );

			my $remote_str = "SELECT CategoryNumber, [Reason] FROM DomainReason WITH(NOLOCK) WHERE DomainName = '$domain'";
			my $remote_sth = $dbhCategory->prepare( $remote_str );
			
			$remote_sth->execute();
			
			my ( $remote_category, $reason ) = $remote_sth->fetchrow_array();
			
			$remote_sth->finish();
			
			$local_category = 0 + $local_category;
			$remote_category = 0 + $remote_category if ( defined $remote_category );

			# Does this exist at all in the DomainReason table?
			if ( ( defined $remote_category )  &&  ( defined $reason ) )
				{	# Do they match?
					if ( $remote_category != $local_category )
						{	$different++;
							print OUTPUT "Different: $domain Content Catnum: $local_category - DomainReason Catnum: $remote_category, Reason: $reason\n";
						}						
				}
			else
				{	$missing++;
			
					print OUTPUT "Missing From DomainReason: $domain, Content Catnum: $local_category\n";
					
					$reason = "Manually reviewed on $local_transaction_time";
					my $qreason = quotemeta( $reason );
					
					$remote_str = "INSERT INTO DomainReason ( DomainName, Reason, CategoryNumber, HostName, TransactionTime ) VALUES ( \'$domain\', \'$qreason\', \'$local_category\', \'$hostname\', \'$local_transaction_time\' )";

					$remote_sth = $dbhCategory->prepare( $remote_str );
					$remote_sth->execute();
					
					$remote_sth->finish();
				}
				
			&ShowCounter( "Category", $missing, $lookup, $different, 10000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup domains in the Category DomainReason table, found $missing missing and $different different domain cartegorizations\n";
	
	close( OUTPUT );	
		
	return( 1 );
}



################################################################################
# 
sub SqlActiveFlags()
#
# This function just flags in the DomainReason table all the currently active 
# domains and IP addresses from the IpmContent database
#
################################################################################
{
	lprint "Flagging as active the entries in the DomainReason table that are in IpmContent  ...\n";
	
	my $str = "SELECT DomainName FROM IpmContentDomain WITH(NOLOCK) WHERE CategoryNumber IN ( '21','22','23','24','25','26','27','28','94','4','100','101','102','70','103','8','12','13','126','109','110','111','31','32','17' ) AND SourceNumber > '2'";

	my $sth = $dbh->prepare( $str );
	
	$sth->execute();

	my $lookup		= 0 + 0;
	
	while ( ( ! $dbh->err )  &&  ( my ( $reverse_domain ) = $sth->fetchrow_array() ) )
		{	$lookup++;
			next if ( ! defined $reverse_domain );
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! defined $domain );

			my $remote_str = "UPDATE DomainReason Set [Active] = '1' WHERE DomainName = '$domain'";
			my $remote_sth = $dbhCategory->prepare( $remote_str );
			
			$remote_sth->execute();
						
			$remote_sth->finish();
			
			&ShowCounter( "Domains", 0, $lookup, 0, 100000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup domains in the IpmContentDomain table\n";
						
			
	return( 1 );
}



################################################################################
# 
sub SqlTemp()
#
# This function is a temp function used from running strange queries
#
################################################################################
{

	lprint "Opening a connection to the local database ...\n";
	$dbh = DBI->connect( "DBI:ODBC:TrafficServer", "IpmContent" ) or die;

	lprint "Opening a connection to the ODBC System DSN \'RemoteContent\' ...\n";
	$dbhRemote = &ConnectRemoteContent();

			if ( ! $dbhRemote )
				{
lprint "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'RemoteContent\' with default database \'IpmContent\'.\n";
					exit( 9 );
				}
				
				
	lprint "Checking IP Address Pand and Unpack ...\n";
	
	my $str = "SELECT dbo.IpmConvertIpToString( IpAddress ) FROM IpmContentIpAddress WITH(NOLOCK)";

	my $sth = $dbh->prepare( $str );
	
	$sth->execute();

	my $lookup		= 0 + 0;
	
	while ( ( ! $dbh->err )  &&  ( my ( $str_ip ) = $sth->fetchrow_array() ) )
		{	$lookup++;
			next if ( ! defined $str_ip );

			print "\nstr ip = $str_ip\n";
			
			my $packed_ip = &StringToIP( $str_ip );

			$str = "SELECT dbo.IpmConvertIpToString( IpAddress ) from IpmContentIpAddress where IpAddress = dbo.IpmConvertIpToChar( '$str_ip' )";
			my $remote_sth = $dbhRemote->prepare( $str );
			#$remote_sth->bind_param( 1, $packed_ip,  DBI::SQL_BINARY );
			
			$remote_sth->execute();
			
			my ( $remote_str_ip ) = $remote_sth->fetchrow_array();
			
			$remote_sth->finish();


			if ( ! $remote_str_ip )
				{	print "Could not find $str_ip\n";
				}
			elsif ( $str_ip ne $remote_str_ip )
				{	print "IP conflict - remote IP = $remote_str_ip\n\n";	
				}
			else
				{	print "Compared OK\n";
				}
				
			&ShowCounter( "Ip Addresses", 0, $lookup, 0, 100000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup IPs in the IpmContentIpAddress table\n";
						
			
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
	my $missing		= shift;
	my $lookup		= shift;
	my $different	= shift;
	my $divisor		= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $lookup )  ||  ( ! $divisor ) );
	
	# If nothing much has happened then return
	return( undef ) if ( ( $missing < $divisor )  &&  ( $different < $divisor )  &&  ( $lookup < $divisor ) );
	
	my $look = $divisor * sprintf( "%d", ( $lookup / $divisor ) ); 

	my $cnt = $divisor * sprintf( "%d", ( $missing / $divisor ) );
	
	my $diff = $divisor * sprintf( "%d", ( $different / $divisor ) );
	
	# Nothing happening yet?
	return( undef ) if ( ( ! $look )  &&  ( ! $cnt )  &&  ( ! $diff ) );

	# Has something reached a round divisor number?
	return( undef ) if ( ( $cnt != $missing )  &&  ( $diff != $different )  &&  ( $look != $lookup ) );
	

	my $lookup_show = 1 if ( ( $look )  &&  ( $look == $lookup ) );
	$lookup_show = undef if ( ( $last_look )  &&  ( $last_look == $look ) ); 

	my $count_show = 1 if ( ( $cnt )  &&  ( $cnt == $missing ) );
	$count_show = undef if ( ( $last_cnt )  &&  ( $last_cnt == $cnt ) ); 

	my $diff_show = 1 if ( ( $diff )  &&  ( $diff == $different ) );
	$diff_show = undef if ( ( $last_diff )  &&  ( $last_diff == $diff ) ); 


	return( undef ) if ( ( ! $lookup_show )  &&  ( ! $count_show )  &&  ( ! $diff_show ) );
	
	print "Type: $type - looked up $lookup total, found $missing missing, $different different so far ...\n";
	
	$last_cnt	= $cnt;
	$last_diff	= $diff;
	$last_look	= $look;
	
	return( 1 );
}



################################################################################
# 
sub SqlCorrect()
#
#  This is a temporary function used to correct different problems in the IpmContent
#  database
#
################################################################################
{

	# Get a good hostname to use
	$hostname = hostname if ( ! defined $hostname );
	$hostname = "undefined" if ( ! defined $hostname );
	$hostname = lc( $hostname );

	lprint "Correcting problems in the local database ...\n";
	
	my $str = "SELECT DomainName, CategoryNumber, TransactionTime FROM IpmContentDomain WITH(NOLOCK) WHERE SourceNumber IN (1,2)
 AND CategoryNumber in (62,63)
 AND ReviewTime < '1/1/2010'";

	lprint "SQL Statement: $str\n";
	
	my $sth = $dbh->prepare( $str );
	
	$sth->execute();

	my $lookup		= 0 + 0;
	my $different	= 0 + 0;
	my $missing		= 0 + 0;
	
	my @change_list;
	while ( ( ! $dbh->err )  &&  ( my ( $reverse_domain, $local_category, $local_transaction_time ) = $sth->fetchrow_array() ) )
		{	$lookup++;
			next if ( ! defined $reverse_domain );
			next if ( ! $local_category );
			next if ( ! $local_transaction_time );
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! defined $domain );

			my $remote_str = "SELECT CategoryNumber, [Reason] FROM DomainReason WITH(NOLOCK) WHERE DomainName = '$domain'";
			my $remote_sth = $dbhCategory->prepare( $remote_str );
			
			$remote_sth->execute();
			
			my ( $remote_category, $reason ) = $remote_sth->fetchrow_array();
			
			$remote_sth->finish();
			
			$local_category = 0 + $local_category;
			$remote_category = 0 + $remote_category if ( defined $remote_category );

			# Is there a reason at all?
			next if ( ! defined $reason );
			
			
			# Does it look like an automatically created entry?
#			next if ( $reason =~ m/security\.virus \-/ );
#			next if ( $reason =~ m/security\.spyware \-/ );
#			next if ( $reason =~ m/security\.proxy \-/ );
			next if ( $reason =~ m/manually/i );
			
			
			print "Domain: $domain - $reason\n" if ( $opt_verbose );
			
			push @change_list, $reverse_domain;
			$different++;

			&ShowCounter( "Category", $missing, $lookup, $different, 10000 );
			
		}

	$sth->finish();

die;

	
	lprint "Changing the category to errors ...\n";
	my $changed = 0 + 0;
	foreach ( @change_list )
		{	my $reverse_domain = $_;
			next if ( ! $reverse_domain );
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! defined $domain );

			my $str = "UPDATE IpmContentDomain SET CategoryNumber = '7', TransactionTime = getutcdate() WHERE DomainName = '$reverse_domain'";

			my $sth = $dbh->prepare( $str );
			
			$sth->execute();
			
			$sth->finish();
			
			# I gotta set theis source to '1' so that it will override in the Category database
			my $source = 0 + 1;
			
			&CategorySaveDomainReason( $domain, "errors", "No longer active virus infected website", $source, 1 );
			
			$changed++;
		}
		
	
	lprint "Changed $changed domains to errors\n";
	
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
#	$data = undef;
#	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\RemoteContent", 0, KEY_READ, $key );
#	return( undef ) if ( ! $ok );
#	&RegCloseKey( $key );
	
	$dbhRemote = DBI->connect( "DBI:ODBC:RemoteContent", "IpmContent" );

	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhRemote )
		{	sleep( 10 );
			$dbhRemote = DBI->connect( "DBI:ODBC:RemoteContent", "IpmContent" );
			
			return( undef ) if ( ! $dbhRemote );
		}
	
	# Make sure that I can read long disinfect scripts up to 50 k in size
	$dbhRemote->{LongReadLen} = 50 * 1024;
			
	&SqlSetCurrentDBHandles( $dbhRemote, undef );
	
	return( $dbhRemote );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlCategory";

    print <<".";
Syntax: SqlCategory

SqlCategory compares the local IpmContentDatabase to the remote Category
database and prints out any crazy mistakes.


  -h, --help         show this help

.

    exit( 1 );
}



__END__

:endofperl
