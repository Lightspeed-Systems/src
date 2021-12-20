################################################################################
#!perl -w
#
#  SqlRandom - delete all but a random 10% of the major tables
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
my $opt_random = 0 + 10;				# This is the percentage of the random database to NOT delete

my $dbh;								# The global database handle
my $dbhRandom;							# The golbal handle to the Random database



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
		"w|wizard"			=> \$opt_wizard,
        "h|help"			=> \$opt_help
    );


    &StdHeader( "SqlRandom" ) if ( ! $opt_wizard );
	
    &Usage() if ( ( $opt_help )  ||  ( $opt_version ) );
	
	&SetLogFilename( ".\\SqlRandom.log", undef );
	
	
	lprint "Opening a connection to the ODBC System DSN \'RandomContent\' ...\n";
	$dbhRandom = &ConnectRandomContent();

	if ( ! $dbhRandom )
		{
lprint "Unable to open the Random Content database.
Run ODBCAD32 and add the CONTENT SQL Server as a System DSN named
\'RandomContent\' with default database \'IpmContent\'.\n";
			exit( 9 );
		}
		
		
    #  Open the local database
	lprint "Opening a connection to the local database ...\n";
    $dbh = &ConnectServer() or die;


	lprint "Deleting all but a random $opt_random \% of database entries in the local IpmContent database ...\n";


	&SqlRandom();
		
	$dbh->disconnect		if ( $dbh );
	$dbhRandom->disconnect	if ( $dbhRandom );
	
	lprint "Done.\n";

exit;

}
exit;



################################################################################
# 
sub SqlRandom()
#
#  Given two database handles, delete all but a random $opt_random of the local
#  database handle
#
################################################################################
{
	my $str;
	my $sth;
	my $lookup		= 0 + 0;
	my $deleted		= 0 + 0;
	
	
	lprint "Deleting random Virus Signatures in the local database ...\n";

	$str = "SELECT VirusName FROM VirusSignatures";
		
	$sth = $dbhRandom->prepare( $str );

	$sth->execute();
	

	$lookup		= 0 + 0;
	$deleted	= 0 + 0;
	
	my $delete_counter = 0 + 0;
	
	while ( ( ! $dbhRandom->err )  &&  ( my $virus_name = $sth->fetchrow_array() ) )
		{	last if ( ! $virus_name );
			$lookup++;
			
			next if ( ! $virus_name );
	
			$delete_counter++;
			
			$delete_counter = 0 + 0 if ( $delete_counter > 99 );
			
			# Have I gotten to the section that I should delete yet?
			next if ( $delete_counter < $opt_random );
					
			my $local_str = "DELETE VirusSignatures WHERE VirusName = '$virus_name'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
											
			$local_sth->finish();
			
			$deleted++;
			
			&ShowCounter( "Virus Signatures", $deleted, $lookup, 10 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup Virus Signatures in RandomContent, deleted $deleted Virus Signatures locally\n";
	

	lprint "Deleting random File IDs in the local database ...\n";

	$str = "SELECT FileID FROM ApplicationProcesses";
		
	$sth = $dbhRandom->prepare( $str );

	$sth->execute();

	$lookup		= 0 + 0;
	$deleted	= 0 + 0;
	
	$delete_counter = 0 + 0;
	
	while ( ( ! $dbhRandom->err )  &&  ( my $file_id = $sth->fetchrow_array() ) )
		{	last if ( ! $file_id );
			$lookup++;
			
			next if ( ! $file_id );
			
			$delete_counter++;
			
			$delete_counter = 0 + 0 if ( $delete_counter > 99 );
			
			# Have I gotten to the section that I should delete yet?
			next if ( $delete_counter < $opt_random );

			my $local_str = "DELETE ApplicationProcesses WHERE FileID = '$file_id'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
						
			$local_sth->finish();
								
			$deleted++;
			
			&ShowCounter( "File IDs", $deleted, $lookup, 100 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup File IDs in RandomContent, deleted $deleted File IDs locally\n";
	
									
	lprint "Deleting random SpamPatterns in the local database ...\n";

	$str = "SELECT [Name] FROM SpamPatterns";

	$sth = $dbhRandom->prepare( $str );

	$sth->execute();


	$lookup		= 0 + 0;
	$deleted	= 0 + 0;
	
	$delete_counter = 0 + 0;
	
	while ( ( ! $dbhRandom->err )  &&  ( my $name = $sth->fetchrow_array() ) )
		{	last if ( ! defined $name );
			$lookup++;
			
			my $qname = $name;
			$qname =~ s/'/''/g;
			
			$delete_counter++;
			
			$delete_counter = 0 + 0 if ( $delete_counter > 99 );
			
			# Have I gotten to the section that I should delete yet?
			next if ( $delete_counter < $opt_random );

			my $local_str = "DELETE SpamPatterns WHERE [Name] = '$qname'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
			
			$local_sth->finish();
			
			$deleted++;
			
			&ShowCounter( "SpamPatterns", $deleted, $lookup, 10 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup SpamPatterns, deleted $deleted SpamPatterns locally\n";
	
	
	lprint "Deleting random URLs in the local database ...\n";

	$str = "SELECT URL FROM IpmContentURL";

	$sth = $dbhRandom->prepare( $str );

	$sth->execute();


	$lookup		= 0 + 0;
	$deleted	= 0 + 0;
	
	$delete_counter = 0 + 0;
	
	while ( ( ! $dbhRandom->err )  &&  ( my $url = $sth->fetchrow_array() ) )
		{	last if ( ! $url );
			$lookup++;
			
			next if ( ! $url );
						
			$delete_counter++;
			
			$delete_counter = 0 + 0 if ( $delete_counter > 99 );
			
			# Have I gotten to the section that I should delete yet?
			next if ( $delete_counter < $opt_random );

			my $local_str = "DELETE IpmContentURL WHERE URL = '$url'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
			
			$deleted++;
			
			&ShowCounter( "URLs", $deleted, $lookup, 1000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup URLs, deleted $deleted URLs locally\n";
	
	
	lprint "Deleting random IP addressess in the local database ...\n";
	
	$str = "SELECT IPAddress FROM IpmContentIPAddress";

	$sth = $dbhRandom->prepare( $str );

	$sth->execute();
	
	
	$lookup		= 0 + 0;
	$deleted	= 0 + 0;
	
	$delete_counter = 0 + 0;
	
	while ( ( ! $dbhRandom->err )  &&  ( my $ip = $sth->fetchrow_array() ) )
		{	last if ( ! $ip );
			$lookup++;
			
			my $str_ip = &IPToString( $ip );
			next if ( ! $str_ip );
						
			$delete_counter++;
			
			$delete_counter = 0 + 0 if ( $delete_counter > 99 );
			
			# Have I gotten to the section that I should delete yet?
			next if ( $delete_counter < $opt_random );

			my $local_str = "DELETE IpmContentIpAddress WHERE IPAddress = ?";
			my $local_sth = $dbh->prepare( $local_str );
			$local_sth->bind_param( 1, $ip, DBI::SQL_BINARY );
			
			$local_sth->execute();
						
			$local_sth->finish();
			
			$deleted++;
			
			&ShowCounter( "IP addresses", $deleted, $lookup, 10000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup IP addresses, deleted $deleted IP addresses locally\n";
		
	
	lprint "Deleting random domains in the local database ...\n";
	
	$str = "SELECT DomainName FROM IpmContentDomain";

	$sth = $dbhRandom->prepare( $str );
	
	$sth->execute();


	$lookup		= 0 + 0;
	$deleted	= 0 + 0;
	
	$delete_counter = 0 + 0;
	
	while ( ( ! $dbhRandom->err )  &&  ( my $reverse_domain = $sth->fetchrow_array() ) )
		{	last if ( ! $reverse_domain );
			$lookup++;
			
			my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! $domain );
				
			$delete_counter++;
			
			$delete_counter = 0 + 0 if ( $delete_counter > 99 );
			
			# Have I gotten to the section that I should delete yet?
			next if ( $delete_counter < $opt_random );

			my $local_str = "DELETE IpmContentDomain WHERE DomainName = '$reverse_domain'";
			my $local_sth = $dbh->prepare( $local_str );
			
			$local_sth->execute();
						
			$local_sth->finish();
			
			$deleted++;
			
			&ShowCounter( "domains", $deleted, $lookup, 10000 );
		}

	$sth->finish();
	
	lprint "Looked up $lookup domains, deleted $deleted domains locally\n";
	
	
	return( 1 );
}



my $last_cnt;
my $last_look;
################################################################################
# 
sub ShowCounter( $$$$$ )
#
#  Show a progress counter 
#
################################################################################
{	my $type		= shift;
	my $deleted		= shift;
	my $lookup		= shift;
	my $divisor		= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $lookup )  ||  ( ! $divisor ) );
	
	# If nothing much has happened then return
	return( undef ) if ( ( $deleted < $divisor )  &&  ( $lookup < 100000 ) );
	
	my $look = 100000 * sprintf( "%d", ( $lookup / 100000 ) ); 

	my $cnt = $divisor * sprintf( "%d", ( $deleted / $divisor ) );
	
	
	# Nothing happening yet?
	return( undef ) if ( ( ! $look )  &&  ( ! $cnt ) );

	# Has something reached a round divisor number?
	return( undef ) if ( ( $cnt != $deleted )  &&  ( $look != $lookup ) );
	

	my $lookup_show = 1 if ( ( $look )  &&  ( $look == $lookup ) );
	$lookup_show = undef if ( ( $last_look )  &&  ( $last_look == $look ) ); 

	my $deleted_show = 1 if ( ( $cnt )  &&  ( $cnt == $deleted ) );
	$deleted_show = undef if ( ( $last_cnt )  &&  ( $last_cnt == $cnt ) ); 

	return( undef ) if ( ( ! $lookup_show )  &&  ( ! $deleted_show ) );
	
	print "Type: $type - looked up $lookup total, deleted $deleted so far ...\n";
	
	$last_cnt	= $cnt;
	$last_look	= $look;
	
	return( 1 );
}



################################################################################
# 
sub ConnectRandomContent()
#
#  Find and connect to the random Content database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbhRandom ) if ( $dbhRandom );
	
	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\RandomContent", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	&RegCloseKey( $key );
	
	$dbhRandom = DBI->connect( "DBI:ODBC:RandomContent", "IpmContent" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhRandom )
		{	sleep( 10 );
			$dbhRandom = DBI->connect( "DBI:ODBC:RandomContent", "IpmContent" );
		}
	
	return( $dbhRandom );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlRandom";

    print <<".";
Syntax: SqlRandom

SqlRandom deletes all but a random amount of the RandomContent database.

  -r, random PERCENT percentage of the database to NOT delete, default is 10\%
  
  -h, --help         show this help

.

    exit( 1 );
}



__END__

:endofperl
