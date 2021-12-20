################################################################################
#!perl -w
#
# Rob McCarthy's barracuda test program
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Cwd;
use Win32API::Registry 0.21 qw( :ALL );
use Net::CIDR;


use Content::File;
use Content::Mail;
use Content::SQL;



# Options
my $opt_help;
my $opt_version;
my $opt_verbose;
my $opt_unlink;		# If True, then unlink any mail file that isn't archived
my $opt_dir;		# If set, this is the directory to process
my $opt_cidr;
my $opt_reset;
my $opt_asn;
my $opt_network;	# If set the create a new network reputation file



my $barracuda_ip = "10.16.1.47";
my $_version = "1.0.0";
my $original_dir;	# This is the directory that the original statistics was gathered for


my $dbhLocalSpam;			# The database handle to the local spam database
my $dbhRemoteStatistics;	# The database handle to the remote statistics database
my @cidr;					# The cidr table in memory


################################################################################
#
MAIN:
#
################################################################################
{
#&ReadCIDR();
#my $ip = "209.225.139.73";
#my $asn = &IPToASN( $ip );
#print "asn = $asn\n";
#die;

#my $network = "67.214.160.0/20";
#my @network;
#push @network, $network;

#my @range = Net::CIDR::cidr2range( @network );
#print "range = @range\n";
#die;

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "a|asn"		=>	\$opt_asn,
        "c|cidr=s"	=>	\$opt_cidr,
        "d|dir=s"	=>	\$opt_dir,
		"n|network"	=>	\$opt_network,
        "u|unlink"	=>	\$opt_unlink,
        "s|source=s"=>	\$original_dir,
        "r|reset" =>	\$opt_reset,
        "v|version" =>	\$opt_verbose,
        "h|help"	=>	\$opt_help
    );


    &Usage()	if ( $opt_help );
    &Version() if ( $opt_version );


	&StdHeader( "Barracuda Test" );
	
	&SetLogFilename( "Barracuda.log", undef );
	my $log_filename = &GetLogFilename();
	lprint "Barracuda log file set to $log_filename\n";

	if ( $opt_cidr )
		{	&CreateCIDR( $opt_cidr );
			print "\nDone\n";

			exit( 0 );
		}


	lprint "Unlink any mail files that are not archived\n" if ( $opt_unlink );
	

	$dbhLocalSpam = &ConnectLocalSpam();
	
	if ( ! $dbhLocalSpam )
		{
lprint "Unable to open the Remote Statistics database.
Run ODBCAD32 and add the SpamArchive SQL Server as a System DSN named
\'Spam\' with default database \'Spam\'.\n";

			exit( 1 );
		}
		

	# Read in the CIDR file if it exists
	&ReadCIDR();
	

	if ( $opt_reset )
		{	&ResetASN();
			
			$dbhLocalSpam->disconnect if ( $dbhLocalSpam );
			$dbhLocalSpam = undef;
			
			print "\nDone\n";
			exit( 1 );
		}
		
		
	if ( $opt_asn )
		{	&CalculateASNSummary();
			
			$dbhLocalSpam->disconnect if ( $dbhLocalSpam );
			$dbhLocalSpam = undef;
			
			print "\nDone\n";
			exit( 1 );
		}
		
		
	if ( $opt_network )
		{	&CalculateNetworkReputation();
			
			$dbhLocalSpam->disconnect if ( $dbhLocalSpam );
			$dbhLocalSpam = undef;
			
			print "\nDone\n";
			exit( 1 );
		}
		
		
	$dbhRemoteStatistics = &ConnectRemoteStatistics();
	
	if ( ! $dbhRemoteStatistics )
		{
lprint "Unable to open the Remote Statistics database.
Run ODBCAD32 and add the TTC-62 SQL Server as a System DSN named
\'RemoteStatistics\' with default database \'IpmStatistics\'.\n";

			exit( 1 );
		}
		

	lprint "Starting Barracuda test ...\n";

	if ( ! defined $original_dir )
		{	&lprint( "The original dir is not defined\n" );
			exit( 1 );
		}
		
	# Figure out my starting directory
	my $home_dir = getcwd;
	$home_dir =~ s#\/#\\#gm;
	$opt_dir = $home_dir if ( ! defined $opt_dir );
	
	
	# Process the queue directory
	if ( ! opendir( DIR, $opt_dir ) )
		{	lprint "Error opening the directory $opt_dir: $!\n";
			exit( 0 );
		}

	my $count = 0 + 0;
	
	while ( defined( my $file = readdir( DIR ) ) )
		{	next if ( -d $file );

			my $file = lc( $file );
			
			# Ignore clue files
			next if ( $file =~ m/\.clue$/i );
			
			my $full_filename = $opt_dir . "\\" . $file;
			my $forward_email;
			
			$forward_email = 1 if ( $file =~ m/^h/ );
			$forward_email = 1 if ( $file =~ m/^s/ );
			$forward_email = 1 if ( $file =~ m/^v/ );
	
			my $clue_filename = $full_filename . ".clue";
			
			if ( ! $forward_email )
				{	unlink( $full_filename ) if ( $opt_unlink );
					unlink( $clue_filename ) if ( $opt_unlink );
					next;	
				}
			
			my %info;
			if ( ! &SpamLookupDatabase( $full_filename, \%info ) )
				{	unlink( $full_filename ) if ( $opt_unlink );
					unlink( $clue_filename ) if ( $opt_unlink );
					next;	
				}
			
			if ( ! &ForwardFilename( $full_filename ) )
				{	unlink( $full_filename ) if ( $opt_unlink );
					unlink( $clue_filename ) if ( $opt_unlink );
					next;	
				}
			
			$count++;

			&SpamSaveDatabase( $full_filename, \%info );
		}

	closedir( DIR );
	
	$dbhRemoteStatistics->disconnect if ( $dbhRemoteStatistics );
	$dbhRemoteStatistics = undef;

	$dbhLocalSpam->disconnect if ( $dbhLocalSpam );
	$dbhLocalSpam = undef;

	lprint "Sent $count emails to the Barracuda test machine\n";
	
	print "Done\n";
    exit;
}



################################################################################
# 
sub CalculateNetworkReputation()
#
#  Calculate the ASN summary data
#
################################################################################
{	
	print "Calculating the network reputations ...\n";
			
	my $str = "SELECT ASN, Spam, Ham FROM ASNSummary";	
	print "SQL statement: $str\n" if ( $opt_verbose );
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();

	my $count = 0 + 0;
	my %asn_reputation;	# Key is asn, value is the reputation
	while ( ( ! $dbhLocalSpam->err )  &&  (  my ( $asn, $spam, $ham ) = $sth->fetchrow_array() ) )
		{	$count++;
			next if ( ! $asn );
			next if ( ! $spam );
			
			$asn = 0 + $asn;
			$spam = 0 + 0 if ( ! $spam );
			$ham = 0 + 0 if ( ! $ham );
			
			my $total = $spam + $ham;
			
			# Ignore low counts
			next if ( $total < 50 );
			
			my $spam_percent = 100 * $spam / $total;
			$spam_percent = sprintf( "%d", $spam_percent );
			$spam_percent = 100 if ( $spam == $total );
			
			# Use a cutoff of 95%
			next if ( $spam_percent < 95 );
			
			my $this_reputation = "$spam_percent% of the mail from AS# $asn is spam";
			print "$this_reputation\n";
			$asn_reputation{ $asn } = $spam_percent;
		}	
		
	$sth->finish();


	# Write the network reputation data out to disk
	my $reputation_file = &SoftwareDirectory() . "\\NetworkReputation.dat";
	print "Writing out the reputation data to $reputation_file ...\n";
	
	my $write_count = 0 + 0;
	if ( ! open( REPUTATION, ">$reputation_file" ) )
		{	print "Error opening $reputation_file: $!\n";
			return( undef );
		}
		
	my $reputation_count = 0 + 0;
	for ( my $i = 0 + 0;  $i < 256;  $i++ )
		{	for ( my $k = 0 + 0;  $k < 256;  $k++ )
				{	my $current_val = $cidr[ $i ][ $k ];
					next if ( ! defined $current_val );

					my @vals = split /\t/, $current_val;	

					my $reputations;
					foreach ( @vals )
						{	my $val = $_;
							next if ( ! defined $val );

							my ( $istart, $iend, $asn ) = split /\s/, $val;
							next if ( ! defined $istart );
							next if ( ! defined $iend );
							next if ( ! defined $asn );
							
							$istart		= 0 + $istart;
							$iend		= 0 + $iend;
							$asn		= 0 + $asn;
							
							my $this_reputation = $asn_reputation{ $asn };
							next if ( ! $this_reputation );
							
							# Flip spaces to underlines
							$this_reputation =~ s/ /_/g;
							
							my $rep_val = "$istart $iend $asn $this_reputation";
							$reputations .= "\t" . $rep_val if ( defined $reputations );
							$reputations = $rep_val if ( ! defined $reputations );
							
							$reputation_count++;
						}
					
					next if ( ! defined $reputations );					
					print REPUTATION "$i\t$k\t$reputations\n";
				}
		}
		
	close( REPUTATION );	
	
	print "Created a network reputation file with $reputation_count entries\n";
	
	return( undef );
}



################################################################################
# 
sub CalculateASNSummary()
#
#  Calculate the ASN summary data
#
################################################################################
{	

	print "Calculating the ASN summary data ...\n";
	
	# Open a second handle to the Spam database
	my $dbhSpam = DBI->connect( "DBI:ODBC:Spam", "Spam" );
	
	# If I get an error, give up
	if ( ! $dbhSpam )
		{	print "Error getting a second handle to the Spam database\n";
			return( undef );
		}

	# Get all the mail files
	my $str = "SELECT MailFile, IpAddress, IpStr, ASN FROM MailFileIpAddress WHERE ASN IS NOT NULL";
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	
	my %asn_summary;
	my %ip_summary;
	
	my $count = 0 + 0;
	my $print_count = 0 + 0;
	while ( ( ! $dbhLocalSpam->err )  &&  (  my ( $full_filename, $ip_address, $str_ip_address, $asn ) = $sth->fetchrow_array() ) )
		{	$count++;
			$print_count++;
			if ( $print_count >= 1000 )
				{	print "Processed $count emails so far ...\n";
					$print_count = 0 + 0;
				}
				
			# Do I need to calculate any of the columns?
			if ( ( ! $str_ip_address )  ||  ( ! $asn ) )
				{	$str_ip_address = &IPToString( $ip_address );
					next if ( ! $str_ip_address );
			
					$asn = &IPToASN( $str_ip_address );
					next if ( ! $asn );
					
					if ( $opt_verbose )
						{	print "IP $str_ip_address ASN $asn\n";
						}
						
					# Stick the mail file clue into the database
					my $update_str = "UPDATE MailFileIpAddress SET IpStr = \'$str_ip_address\', ASN = \'$asn\' WHERE MailFile = \'$full_filename\'";
					
					print "SQL Statement: $update_str\n" if ( $opt_verbose );
					
					my $update_sth = $dbhSpam->prepare( $update_str );
					$update_sth->execute();
					$update_sth->finish();
				}
			
			$asn = 0 + $asn;
			
			
			# Add the new entry to the asn hash
			my $val = $asn_summary{ $asn };
			
			my ( $spam, $ham, $virus ) = split /\t/, $val if ( defined $val );
			$spam	= 0 + 0 if ( ! $spam );
			$ham	= 0 + 0 if ( ! $ham );
			$virus	= 0 + 0 if ( ! $virus );
			
			$spam	= 0 + $spam;
			$ham	= 0 + $ham;
			$virus	= 0 + $virus;
			
			$spam++		if ( $full_filename =~ m/\\s/ );
			$ham++		if ( $full_filename =~ m/\\h/ );
			$virus++	if ( $full_filename =~ m/\\v/ );
			
			$val = "$spam\t$ham\t$virus";
			
			$asn_summary{ $asn } = $val;


			# Add the new entry to the ip hash
			$spam	= 0 + 0;
			$ham	= 0 + 0;
			$virus	= 0 + 0;
			$val = $ip_summary{ $str_ip_address };
			
			( $spam, $ham, $virus ) = split /\t/, $val if ( defined $val );
			$spam	= 0 + 0 if ( ! $spam );
			$ham	= 0 + 0 if ( ! $ham );
			$virus	= 0 + 0 if ( ! $virus );
			
			$spam	= 0 + $spam;
			$ham	= 0 + $ham;
			$virus	= 0 + $virus;
			
			$spam++		if ( $full_filename =~ m/\\s/ );
			$ham++		if ( $full_filename =~ m/\\h/ );
			$virus++	if ( $full_filename =~ m/\\v/ );
			
			$val = "$spam\t$ham\t$virus";
			
			$ip_summary{ $str_ip_address } = $val;

		}

	$sth->finish();
	
	print "Processed $count emails in total\n";
	
	# Dump the current ASNSummary table
	print "Deleting the existing ASNSummary table ...\n";
	$str = "DELETE ASNSummary";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	
	# Now insert the totals into the table 
	print "Inserting the new summary data into ASNSummary ...\n";
	while ( my ( $asn, $val ) = each( %asn_summary ) )
		{	next if ( ! $asn );
			next if ( ! defined $val );
			
			my ( $spam, $ham, $virus ) = split /\t/, $val if ( defined $val );
			$spam	= 0 + 0 if ( ! $spam );
			$ham	= 0 + 0 if ( ! $ham );
			$virus	= 0 + 0 if ( ! $virus );
			
			$spam	= 0 + $spam;
			$ham	= 0 + $ham;
			$virus	= 0 + $virus;
			
			my $total = $spam + $ham + $virus;
			
			# If I got nothing, then quit
			next if ( ! $total );
			
			my $spam_total = $spam + $ham;
			next if ( ! $spam_total );
			
			my $spam_percent = 100 * $spam / $spam_total;
			
			$spam_percent = sprintf "%d", $spam_percent;
			$spam_percent = 0 + 100 if ( $spam == $spam_total );
			
			my $virus_percent = 100 * $virus / $total;
			
			$virus_percent = sprintf "%d", $virus_percent;
			$virus_percent = 0 + 100 if ( $virus == $total );
			
			$str = "INSERT INTO ASNSummary ( ASN, Spam, Ham, Virus, SpamPercent, VirusPercent, Total ) VALUES ( \'$asn\', \'$spam\', \'$ham\', \'$virus\', \'$spam_percent\', \'$virus_percent\', \'$total\' )";
			
			print "SQL statement: $str\n" if ( $opt_verbose );
			
			$sth = $dbhLocalSpam->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
	
	
	# Dump the current IPSummary table
	print "Deleting the existing IPSummary table ...\n";
	$str = "DELETE IPSummary";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	# Now insert the totals into the table 
	print "Inserting the new summary data into IPSummary ...\n";
	while ( my ( $ip_str, $val ) = each( %ip_summary ) )
		{	next if ( ! $ip_str );
			next if ( ! defined $val );
			
			my ( $spam, $ham, $virus ) = split /\t/, $val if ( defined $val );
			$spam	= 0 + 0 if ( ! $spam );
			$ham	= 0 + 0 if ( ! $ham );
			$virus	= 0 + 0 if ( ! $virus );
			
			$spam	= 0 + $spam;
			$ham	= 0 + $ham;
			$virus	= 0 + $virus;
			
			my $total = $spam + $ham + $virus;
			
			# If I got nothing, then quit
			next if ( ! $total );
			
			my $spam_total = $spam + $ham;
			next if ( ! $spam_total );
			
			my $spam_percent = 100 * $spam / $spam_total;
			
			$spam_percent = sprintf "%d", $spam_percent;
			$spam_percent = 0 + 100 if ( $spam == $spam_total );
			
			my $virus_percent = 100 * $virus / $total;
			
			$virus_percent = sprintf "%d", $virus_percent;
			$virus_percent = 0 + 100 if ( $virus == $total );
			
			$str = "INSERT INTO IPSummary ( IpStr, Spam, Ham, Virus, SpamPercent, VirusPercent, Total ) VALUES ( \'$ip_str\', \'$spam\', \'$ham\', \'$virus\', \'$spam_percent\', \'$virus_percent\', \'$total\' )";
			
			print "SQL statement: $str\n" if ( $opt_verbose );
			
			$sth = $dbhLocalSpam->prepare( $str );
			$sth->execute();
			$sth->finish();
		}

	$dbhSpam->disconnect if ( $dbhSpam );
	$dbhSpam = undef;
	
	return( undef );
}



################################################################################
# 
sub ResetASN()
#
#  Reset the ASN number in the mailFileIpAddress
#  Return True if I saved the data OK, undef if not
#
################################################################################
{	

	print "Resetting the ASN in the MailFileIpAddress table ...\n";
	
	# Open a second handle to the Spam database
	my $dbhSpam = DBI->connect( "DBI:ODBC:Spam", "Spam" );
	
	# If I get an error, give up
	if ( ! $dbhSpam )
		{	print "Error getting a second handle to the Spam database\n";
			return( undef );
		}

	# Get all the mail files
	my $str = "SELECT MailFile, IpAddress, IpStr FROM MailFileIpAddress WHERE ASN IS NULL OR IpStr IS NULL";
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	
	my $count = 0 + 0;
	my $changed_count = 0 + 0;
	while ( ( ! $dbhLocalSpam->err )  &&  (  my ( $full_filename, $ip_address, $str_ip ) = $sth->fetchrow_array() ) )
		{	$count++;
			my $str_ip_address = &IPToString( $ip_address );
			next if ( ! $str_ip_address );
			
			my $asn = &IPToASN( $str_ip_address );
			
			# If I didn't get an ASN, and I know the string IP in the database, go to the next row
			next if ( ( ! $asn )  &&  ( $str_ip ) );
			
			if ( $opt_verbose )
				{	print "IP $str_ip_address ASN $asn\n";
				}
				
			# Stick the mail file data back into the database
			my $update_str = "UPDATE MailFileIpAddress SET IpStr = \'$str_ip_address\', ASN = \'$asn\' WHERE MailFile = \'$full_filename\'" if ( $asn );
			$update_str = "UPDATE MailFileIpAddress SET IpStr = \'$str_ip_address\', ASN = NULL WHERE MailFile = \'$full_filename\'" if ( ! $asn );
			
			$changed_count++;
			
			print "SQL statement: $update_str\n" if ( $opt_verbose );
			print "Count: $count, changed: $changed_count\n" if ( $opt_verbose );
			
			my $update_sth = $dbhSpam->prepare( $update_str );
			$update_sth->execute();
			$update_sth->finish();
		}

	$sth->finish();
	
	$dbhSpam->disconnect if ( $dbhSpam );
	$dbhSpam = undef;
	
	return( undef );
}



################################################################################
# 
sub CreateCIDR( $ )
#
#  Read in the BGP data and create the CIDR table and write it to disk
#  Return True if I saved the data OK, undef if not
#
################################################################################
{	my $bgp_file = shift;
	
	my $cidr_file = &SoftwareDirectory() . "\\CIDR.dat";
	
	print "Reading in $bgp_file to creat CIDR file $cidr_file ...\n";

	if ( ! open( BGP, "<$bgp_file" ) )
		{	print "Can not open BGP file $bgp_file: $!\n";
			return( undef );
		}


	my $count = 0 + 0;	
	while( my $line = <BGP> )
		{	chomp( $line );
			next if ( ! $line );

			# Is this a valid line?
			# Valid lines start with '*>i' or '* i'
			my $valid;
			
			$valid = 1 if ( $line =~ m/^\*\>i/ );
			$valid = 1 if ( $line =~ m/^\*\si/ );
			next if ( ! $valid );
			
			my $original_line = $line;
			
			# Clean off the front and back of the line
			$line =~ s/\s+i$//;
			$line =~ s/\s+e$//;
			$line =~ s/\s+\?$//;
			$line =~ s/\s+$//;
			
			$line =~ s/^\*\>i//;
			$line =~ s/^\*\si//;
			
			$line =~ s/^\s+//;
			
			my @parts = split /\s+/, $line;
			
			my $network = $parts[ 0 ];

			next if ( ! defined $network );
			
			# Knock off any whitespace on the front or back of the network
			$network =~ s/\s+$// if ( defined $network );
			$network =~ s/^\s+// if ( defined $network );
			
			next if ( ! length( $network ) );
			
			# Sometime network blocks leave off the /bits if it is class A, class B, or class C block
			if ( ( defined $network )  &&  ( ! ( $network =~ m/\// ) ) )
				{	
					print "Classic network: $network\n" if ( $opt_verbose );					
					my @octets = split /\./, $network, 4;
					
					my $first_octet = $octets[ 0 ];
					
					if ( $first_octet =~ m/\D/ )
						{	print "Bad network: $network from original line: $original_line\n";							
							next;
						}
						
					$first_octet = 0 + $first_octet;
					
					if ( $network =~ m/\.0\.0\.0$/ )
						{	if ( ( $first_octet > 0 )  &&  ( $first_octet < 127 ) )
								{	$network .= "/8";
								}
							elsif ( ( $first_octet > 127 )  &&  ( $first_octet < 192 ) )
								{	$network .= "/16";
								}	
							elsif ( ( $first_octet >= 192 )  &&  ( $first_octet < 224 ) )
								{	$network .= "/24";
								}		
						}
					elsif ( $network =~ m/\.0\.0$/ )
						{	$network .= "/16";
						}
					elsif ( $network =~ m/\.0$/ )	
						{	$network .= "/24";
						}
					print "CIDR formatted network: $network\n" if ( $opt_verbose );						
				}
				
			$count++;

			# Does it look like a valid network now?
			my ( $net_ip, $cidr_bits ) = split /\//, $network, 2;
			
			next if ( ! defined $cidr_bits );
			
			next if ( ! &IsIPAddress( $net_ip ) );

			my @network;
			push @network, $network;

			my @range = Net::CIDR::cidr2range( @network );
			my $range = $range[ 0 ];
			next if ( ! defined $range );
			my ( $start, $stop ) = split /\-/, $range, 2;
			next if ( ! defined $start );
			next if ( ! defined $stop );
			
			# Are there enough parts for an ASN?
			if ( $#parts < 2 )
				{	print "Did not get enough parts for the ASN from this line:\n";
					print "$original_line\n";
					next;
				}
			
			my $asn = $parts[ $#parts ];
			
			# Did I get a valid number for an asn?
			if ( $asn =~ m/\D/ )
				{	$asn = $parts[ ( $#parts - 1 ) ];
				}
			
			if ( $asn =~ m/\D/ )
				{	print "Got an invalid ASN from this line:\n";
					print "$original_line\n";
					next;
				}
			
			$asn = 0 + $asn;
			
			if ( $opt_verbose )
				{	print "Original line: $original_line\n";
					print "Network: $network\n";
					print "ASN: $asn\n";
					print "Range: @range\n";
					print "Start: $start\n";
					print "Stop: $stop\n"
				}
				
			my $istart = unpack( "N", &StringToIP( $start ) );
			my $istop = unpack( "N", &StringToIP( $stop ) );
						
			@parts = split /\./, $start;
			my $class_a = 0 + $parts[ 0 ];
			
			my $start_class_b = 0 + $parts[ 1 ];
			@parts = split /\./, $stop;
			
			# Is this network too big?
			my $end_class_a = 0 + $parts[ 0];
			if ( $class_a != $end_class_a )
				{	print "Network $network is too big!\n";
					next;
				}
				
			my $end_class_b = 0 + $parts[ 1 ];
			
			for ( my $k = $start_class_b;  $k <= $end_class_b;  $k++ )
				{	my $add_val = "$istart $istop $asn";
					
					my $current_val = $cidr[ $class_a ][ $k ];
					
					if ( defined $current_val )
						{	$current_val .= "\t" . $add_val;
						}
					else
						{	$current_val = $add_val;
						}
					
					$cidr[ $class_a ][ $k ] = $current_val;
				}
		}
		
	close( BGP );
	

	# Write the CIDR data out to disk
	my $write_count = 0 + 0;
	if ( ! open( CIDR, ">$cidr_file" ) )
		{	print "Error opening $cidr_file: $!\n";
			return( undef );
		}
	
	for ( my $i = 0 + 0;  $i < 256;  $i++ )
		{	for ( my $k = 0 + 0;  $k < 256;  $k++ )
				{	my $current_val = $cidr[ $i ][ $k ];
					next if ( ! defined $current_val );
										
					print CIDR "$i\t$k\t$current_val\n";
				}
		}
		
	close( CIDR );	
}



################################################################################
# 
sub ReadCIDR()
#
#  Read in the the CIDR table from disk
#  Return True if I read the data OK, undef if not
#
################################################################################
{
	my $cidr_file = &SoftwareDirectory() . "\\CIDR.dat";
	
	print "Reading in CIDR file $cidr_file ...\n";

	if ( ! open( CIDR, "<$cidr_file" ) )
		{	print "Error opening $cidr_file: $!\n";
			return( undef );
		}
	
	@cidr = ();
	
	while ( my $line = <CIDR> )
		{	my ( $class_a, $class_b, $current_val ) = split /\t/, $line, 3;
			next if ( ! defined $class_a );
			next if ( ! defined $class_b );
			next if ( ! defined $current_val );
			
			$class_a = 0 + $class_a;
			$class_b = 0 + $class_b;
			
			$cidr[ $class_a ][ $class_b ] = $current_val;
		}
				
	close( CIDR );	
	
}



################################################################################
# 
sub IPToASN( $ )
#
#  Given an IP address in string format, return the ASN number of the network,
#  or 0 if I could not find it
#
################################################################################
{	my $ip = shift;

    return( undef ) if ( ! &IsIPAddress( $ip ) );

	my @parts = split /\./, $ip;
	my $class_a = 0 + $parts[ 0 ];
	my $class_b = 0 + $parts[ 1 ];
	
	my $ip_num = unpack( "N", &StringToIP( $ip ) );

	$ip_num = 0 + $ip_num;

	my $the_asn = 0 + 0;

	my $current_val = $cidr[ $class_a ][ $class_b ];


	# Is there anything at all?
	return( $the_asn ) if ( ! defined $current_val );
	my @vals = split /\t/, $current_val;	

	foreach ( @vals )
		{	my $val = $_;
			next if ( ! defined $val );

			my ( $istart, $iend, $asn ) = split /\s/, $val;
			next if ( ! defined $istart );
			next if ( ! defined $iend );
			next if ( ! defined $asn );
			
			$istart		= 0 + $istart;
			$iend		= 0 + $iend;

			$the_asn	= $asn if ( ( $ip_num >= $istart )  &&  ( $ip_num <= $iend ) );
			
			last if ( $the_asn );
		}
		
	return( $the_asn );	
}



################################################################################
# 
sub SpamSaveDatabase( $$ )
#
#  Save the info about the email into the local Spam database
#  Return True if I saved the data OK, undef if not
#
################################################################################
{	my $full_filename	= shift;
	my $info_ref		= shift;
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $info_ref );
	
	my @parts = split /\\/, $full_filename;
	
	my $i = $#parts - 1;
	return( undef ) if ( $i < 0 );
	
	my $date_str = $parts[ $i ];
	return( undef ) if ( ! $date_str );
	return( undef ) if ( length( $date_str ) != 8 );
	
	my $yr		= substr( $date_str, 0, 4 );
	my $mon		= substr( $date_str, 4, 2 );
	my $mday	= substr( $date_str, 6, 2 );
	
	my $date = "$mon/$mday/$yr";


	my %info = %$info_ref;
	
	my $str_ip			= $info{ 'ip' };
	my $dbemail_from	= $info{ 'email from' };
	my $dbemail_to		= $info{ 'email to' };
	my $subject			= $info{ 'subject' };
	my $code			= $info{ 'code' };
	my $status			= $info{ 'status' };
	
	my $result = "Ham";
	my $method;
	my $method_value;
	
	if ( defined $status )
		{	$result = "Spam" if ( $status =~ m/^Spam/ );
			$result = "Virus" if ( $status =~ m/virus infected/i );
		}
		
	( $method, $method_value ) = split /===/, $status if ( defined $status );
	$method =~ s/\s+$// if ( $method );
	$method_value =~ s/^\s+// if ( $method_value );


	# Clean up the method and method values as much as possible
	if ( defined $method )
		{	$method =~ s/^OK //;
			$method =~ s/^Spam //;
			$method =~ s/\(Realtime Spam Checker\)// if ( $method );
			$method =~ s/\(//g if ( $method );
			$method =~ s/\)//g if ( $method );
			
			$method =~ s/^\s+// if ( $method );
			$method =~ s/\s+$// if ( $method );
			$method = "Spam Pattern" if ( ( $method )  &&  ( $method =~ m/Pattern/ ) );
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Sender / ) )
		{	( $method, $method_value ) = split ' ', $method, 2;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Recipient / ) )
		{	( $method, $method_value ) = split ' ', $method, 2;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Adult Subject / ) )
		{	$method_value = $method;
			$method_value =~ s/^Adult Subject //;
			$method = "Adult Subject";
		}
		
	if ( ( defined $method_value )  &&  ( $method_value =~ m/^Blocked URL\:/ ) )
		{	$method_value =~ s/Blocked URL\://;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Content DB IP/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Unresolvable/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Domain/ ) )
		{	( $method, $method_value ) = split ' ', $method, 2;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^IP/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Auto White Listed/ ) )
		{	$method_value = $dbemail_from;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^RBL IP/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Realtime Spam Checker - Virus / ) )
		{	$method =~ s/Realtime Spam Checker - Virus //;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Spam Pattern/ ) )
		{	$method_value =~ s/Name\: // if ( $method_value );
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Dangerous Attachment/ ) )
		{	$method_value =~ s/Attachment\: // if ( $method_value );
			$method_value =~ s/\s+//g if ( $method_value );
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Virus Infected/ ) )
		{	$method_value =~ s/Virus\: // if ( $method_value );
			my $company;
			( $method_value, $company ) = split /\s/, $method_value, 2 if ( $method_value );
		}

	if ( ( defined $method )  &&  ( $method =~ m/^Challenge email sent/ ) )
		{	$method_value =~ s/ is unknown so challenging it// if ( $method_value );
		}

	if ( ( defined $method )  &&  ( $method =~ m/^Subject/ ) )
		{	( $method, $method_value ) = split ' ', $method, 2;
		}

	# Clean up leading and trailing white space		
	$method =~ s/^\s+// if ( $method );
	$method =~ s/\s+$// if ( $method );

	$method_value =~ s/^\s+// if ( $method_value );
	$method_value =~ s/\s+$// if ( $method_value );
		
		
	&lprint( "Saving info for file $full_filename ...\n" );

	my $str = "DELETE MailFile WHERE MailFile = \'$full_filename\'";
	
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();

	# Clean up any quote marks, etc
	my $qdbemail_from	= &SqlFormat( $dbemail_from, 128 );
	my $qdbemail_to		= &SqlFormat( $dbemail_to, 128 );
	my $qsubject		= &SqlFormat( $subject, 255 );
	my $qmethod		= &SqlFormat( $method, 50 );
	my $qmethod_value	= &SqlFormat( $method_value, 128 );
	

	# Stick the mail file data into the database
	$str = "INSERT INTO MailFile ( MailFile, EmailFrom, EmailTo, Subject, Result, Method, MethodValue, [Date] ) 
	VALUES ( \'$full_filename\', \'$qdbemail_from\', \'$qdbemail_to\', \'$qsubject\', \'$result\', \'$qmethod\', \'$qmethod_value\', \'$date\' )";
	
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();


	# Add any clues I want from the clue filename
	my $clue_filename = $full_filename . ".clue";
	&SpamSaveClues( $full_filename, $clue_filename, $info_ref ) if ( -f $clue_filename );
	
	return( 1 );
}



################################################################################
# 
sub SpamSaveClues( $$$ )
#
#  Save any clues I want from the clue file
#  Return True if I saved the data OK, undef if not
#
################################################################################
{	my $full_filename	= shift;
	my $clue_filename	= shift;
	my $info_ref		= shift;
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $clue_filename );
	return( undef ) if ( ! $info_ref );
	
	
	# Delete any previous clues saved
	# Stick the mail file clue into the database
	my $str = "DELETE MailFileDomain WHERE MailFile = \'$full_filename\'";
	
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	$str = "DELETE MailFileIpAddress WHERE MailFile = \'$full_filename\'";
	
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	if ( ! open( CLUE, "<$clue_filename" ) )
		{	my $err = $!;
			$err = "Unknown" if ( ! $err );
			&lprint( "Unable to open clue file $clue_filename: $err\n" );
			return( undef );
		}
	
	# Make sure that I only add a clue once for each MailFile
	my %domains;

	while ( my $line = <CLUE> )
		{	chomp( $line );
			next if ( ! $line );
			my ( $key, $val ) = split /\t/, $line;
			next if ( ! $key );
			next if ( ! $val );
			
			# Save the types of clues that I am interested in
			if ( $key eq "DOMAIN" )
				{	# Stop duplicate MailFile & Domains & IPs
					next if ( exists $domains{ $val } );
					
					&SpamSaveClueDomain( $full_filename, $val );
					
					$domains{ $val } = 1;
				}	
			elsif ( $key eq "EXTERNAL-IP" )
				{	# Stop duplicate MailFile & Domains & IPs
					next if ( exists $domains{ $val } );
					
					&SpamSaveClueIpAddress( $full_filename, $val );
					
					$domains{ $val } = 1;
				}
		}
		
	close( CLUE );	
	
	return( 1 );
}



################################################################################
# 
sub SpamSaveClueDomain( $$ )
#
#  Save a domain clue for the given full filename
#  Return True if I saved the data OK, undef if not
#
################################################################################
{	my $full_filename	= shift;
	my $domain			= shift;
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $domain );
	
	# Is the Domain actually an IP address?
	return( &SpamSaveClueIpAddress( $domain ) ) if ( &IsIPAddress( $domain ) );
	
	my ( $reverseDomain ) = &ReverseDomain( $domain );

	# Stick the mail file clue into the database
	my $str = "INSERT INTO MailFileDomain ( MailFile, Domain ) 
	VALUES ( \'$full_filename\', \'$reverseDomain\' )";
	
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	return( undef );
}



################################################################################
# 
sub SpamSaveClueIpAddress( $$ )
#
#  Save an IP address clue for the given full filename
#  Return True if I saved the data OK, undef if not
#
################################################################################
{	my $full_filename	= shift;
	my $str_ip_address	= shift;
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $str_ip_address );
	
	# Figure out the asn
	my $asn = &IPToASN( $str_ip_address );
	
	my $ip_address = &StringToIP( $str_ip_address );
	$ip_address =~ s/\'/\'\'/g;
	
	# Stick the mail file clue into the database
	my $str = "INSERT INTO MailFileIpAddress ( MailFile, IpAddress, IpStr, ASN ) 
	VALUES ( \'$full_filename\', \'$ip_address\', \'$str_ip_address\', \'$asn\' )" if ( $asn );
	
	$str = "INSERT INTO MailFileIpAddress ( MailFile, IpAddress, IpStr ) 
	VALUES ( \'$full_filename\', \'$ip_address\', \'$str_ip_address\' )" if ( ! $asn );
	
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	return( undef );
}



################################################################################
# 
sub ConnectRemoteStatistics()
#
#  Find and connect to the remote IpmStatistics database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbhRemoteStatistics ) if ( $dbhRemoteStatistics );
	
	&lprint( "Connecting to the remote Statistics database ...\n" );

	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\RemoteStatistics", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	RegCloseKey( $key );
	
	my $dbh = DBI->connect( "DBI:ODBC:RemoteStatistics", "IpmStatistics" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbh )
		{	sleep( 10 );
			$dbh = DBI->connect( "DBI:ODBC:RemoteStatistics", "IpmStatistics" );
		}
			
	return( $dbh );
}



################################################################################
# 
sub ConnectLocalSpam()
#
#  Find and connect to the local Spam database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbhLocalSpam ) if ( $dbhLocalSpam );
	
	&lprint( "Connecting to the local Spam database ...\n" );

	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\Spam", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	RegCloseKey( $key );
	
	my $dbh = DBI->connect( "DBI:ODBC:Spam", "Spam" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbh )
		{	sleep( 10 );
			$dbh = DBI->connect( "DBI:ODBC:Spam", "Spam" );
		}
			
	return( $dbh );
}



################################################################################
# 
sub SpamLookupDatabase( $$ )
#
#  Given a filename, look up it's statistics information in the remote SQL server,
#  Return True and the info hash if found ok, undef if not
#
################################################################################
{	my $full_filename	= shift;
	my $info_ref		= shift;	# A reference to the info hash
	
	if ( ! -e $full_filename )
		{	lprint "Filename $full_filename does not exist\n";		  
			return( undef );
		}
	
	
	my $size = -s $full_filename;
	if ( $size > 1000000 )
		{	lprint "Not emailing a big file - $full_filename\n";		  
			return( undef );
		}
	
	
	if ( ! open( SPAM, "<$full_filename" ) )
		{   lprint "Error opening file $full_filename: $!\n";		  
			return( undef );
		}


	# Read the fist line of the file - it should be the Lightspeed comment
	my $comment = <SPAM>;
	
	if ( ( ! $comment )  ||
		 ( ! ( $comment =~ m/\(ExternalIpAddress/ ) )  ||
		 ( ! ( $comment =~ m/EmailTo/ ) ) )
		{	lprint "$full_filename is not a Lightspeed message file\n";
			close( SPAM );
			return( undef );
		}

		   
	# First, try to get as much information as possible from the email file itself
	my $email_from;
	my $email_to;
	my $external_ip_address;
	my $resolved_domain;
	my $internal_ip_address;

	
	my @parts = split /\s/, $comment;
	my $part_no = 0;
	foreach ( @parts )
		{	$part_no++;
			my $keyword = lc( $_ );
			
			#  Check for a blank value
			next if ( !$parts[ $part_no ] );
			
			next if ( index( "emailfrom:emailto:externalipaddress:resolveddomain:internalipaddress:", lc( $parts[ $part_no ] ) ) != -1 );
						 
			if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
			if ( $keyword eq "emailto:" )            {  $email_to = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "internalipaddress:" )  {  $internal_ip_address = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "resolveddomain:" )     {  $resolved_domain = lc ( $parts[ $part_no ] );  }
		}
						  

	# Make sure it is a valid email
	$email_to = &CleanEmail( $email_to );
	$email_to = lc( $email_to );
	$email_from = lc( $email_from );
		
	my $ret;
	
	
	# Emails to ignore
	my @ignore_from = (
	"support\@lightspeedsystems.com",
	"spam\@lightspeedsystems.com",
	"notspam\@lightspeedsystems.com"
	);
	
	
	my @ignore_to = (
	"al\@litnetworks.com",
	"support\@lightspeedsystems.com",
	"spam\@lightspeedsystems.com",
	"notspam\@lightspeedsystems.com",
	"blockedcontent\@lightspeedsystems.com"
	);
	
	
	my $not_ignore;
	$not_ignore = 1 if ( $email_to eq "virus\@lightspeedsystems.com" );
						
	foreach ( @ignore_from )
		{	my $ignore = $_;
			next if ( ! defined $ignore );
			next if ( $not_ignore );
			
			next if ( ! defined $email_from );
			
			if ( $email_from eq $ignore )
				{	lprint "Ignoring email from $ignore - file $full_filename\n";
					close( SPAM );
					return( undef );
					
				}
		}
		
		
	foreach ( @ignore_to )
		{	my $ignore = $_;
			next if ( ! defined $ignore );
			next if ( $not_ignore );
			
			next if ( ! defined $email_to );
			
			if ( $email_to eq $ignore )
				{	lprint "Ignoring email to $ignore - file $full_filename\n";
					close( SPAM );
					return( undef );
					
				}
		}
		
		
	if ( ( defined $email_from )  &&  ( $email_from =~ m/blackberry\.net$/ ) )
		{	lprint "Not testing blackberry email - file $full_filename\n";
			close( SPAM );
			return( undef );
		}
				
	# Now see if I can find this email in the remote statistics database
	my %info;	# A hash of all the info about this file
	my $ok = &SpamStatistics( $full_filename, \%info );
	
	return( undef ) if ( ! $ok );
	
	my $str_ip			= $info{ 'ip' };
	my $dbemail_from	= $info{ 'email from' };
	my $dbemail_to		= $info{ 'email to' };
	my $subject			= $info{ 'subject' };
	my $code			= $info{ 'code' };
	my $status			= $info{ 'status' };

	if ( ( $subject )  &&  ( $subject =~ m/spam summary/i ) )
		{	lprint "Ignoring subject $subject - file $full_filename\n";
			return( undef );	
		}

	if ( ( $status )  &&  ( $status =~ m/lightspeed systems admin message/i ) )
		{	lprint "Ignoring status $status - file $full_filename\n";
			return( undef );	
		}

	if ( ( $status )  &&  ( $status =~ m/User Preferences set to No Spam Block/i ) )
		{	lprint "Ignoring status $status - file $full_filename\n";
			return( undef );	
		}

	if ( ( $dbemail_to )  &&  ( ! ( $dbemail_to =~ m/\@lightspeedsystems.com$/i ) ) )
		{	lprint "Ignoring email to $dbemail_to\n";
			return( undef );	
		}

	# OK - at this point I probably want to test this email
	%$info_ref = %info;
	
	return( 1 );
}



################################################################################
# 
sub SpamStatistics( $$ )
#
#  Pull all the info out of the remote statistics database about the given filename
#  Return True if I got the info OK, undef if not
#
################################################################################
{	my $full_filename	= shift;
	my $info_ref		= shift;
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $info_ref );
	
	my ( $dir, $file ) = &SplitFileName( $full_filename );
	
	my $original_filename = $original_dir . "\\$file";
	
	&lprint( "Looking up original mail file $original_filename ...\n" );

	my $str = "SELECT ExternalIpAddress, EmailFrom, EmailTo, EmailSubject, Code, [Status] FROM SpamMailBlocker WHERE MailFile = \'$original_filename\'";
	
	my $sth = $dbhRemoteStatistics->prepare( $str );
	$sth->execute();

	my ( $ipaddr, $email_from, $email_to, $subject, $code, $status ) = $sth->fetchrow_array();

	$sth->finish();
	
	if ( ! defined $email_to )
		{	&lprint( "Unable to find any data for $original_filename\n" );
			
			my @parts = split /\\/, $dir;
			my $day_dir = $parts[ $#parts ];
			$original_filename = "C:\\Program Files\\Lightspeed Systems\\Traffic\\Mail Archive\\$day_dir" . "\\$file";
	
			&lprint( "Now trying original mail file $original_filename ...\n" );

			$str = "SELECT ExternalIpAddress, EmailFrom, EmailTo, EmailSubject, Code, Status FROM SpamMailBlocker WHERE MailFile = \'$original_filename\'";
	
			$sth = $dbhRemoteStatistics->prepare( $str );
			$sth->execute();

			( $ipaddr, $email_from, $email_to, $subject, $code, $status ) = $sth->fetchrow_array();

			$sth->finish();
	
			if ( ! defined $email_to )
				{	&lprint( "Unable to find any data for $original_filename either ...\n" );
					return( undef );
				}
		}
	
	my %info;
	
	my $str_ip = &IPToString( $ipaddr );


	$info{ 'ip' }			= $str_ip;
	$info{ 'email from' }	= $email_from;
	$info{ 'email to' }		= $email_to;
	$info{ 'subject' }		= $subject;
	$info{ 'code' }			= $code;
	$info{ 'status' }		= $status;
	
	%$info_ref = %info;

	return( 1 );
}



################################################################################
# 
sub ForwardFilename( $ )
#
#  SMTP forward the given filename to the given email address
#  Return True if forwarded OK - undef if not
#
################################################################################
{	my $full_filename		= shift;
	
	if ( ! -e $full_filename )
		{	lprint "Filename $full_filename does not exist\n";		  
			return( undef );
		}
	
	
	my $size = -s $full_filename;
	if ( $size > 1000000 )
		{	lprint "Not emailing a big file - $full_filename\n";		  
			return( undef );
		}
	
	
	if ( ! open( SPAM, "<$full_filename" ) )
		{   lprint "Error opening file $full_filename: $!\n";		  
			return( undef );
		}


	# Read the fist line of the file - it should be the Lightspeed comment
	my $comment = <SPAM>;
	
	if ( ( ! $comment )  ||
		 ( ! ( $comment =~ m/\(ExternalIpAddress/ ) )  ||
		 ( ! ( $comment =~ m/EmailTo/ ) ) )
		{	lprint "$full_filename is not a Lightspeed message file\n";
			close( SPAM );
			return( undef );
		}

		   
	# First, try to get as much information as possible from the email file itself
	my $email_from;
	my $email_to;
	my $external_ip_address;
	my $resolved_domain;
	my $internal_ip_address;

	
	my @parts = split /\s/, $comment;
	my $part_no = 0;
	foreach ( @parts )
		{	$part_no++;
			my $keyword = lc( $_ );
			
			#  Check for a blank value
			next if ( !$parts[ $part_no ] );
			
			next if ( index( "emailfrom:emailto:externalipaddress:resolveddomain:internalipaddress:", lc( $parts[ $part_no ] ) ) != -1 );
						 
			if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
			if ( $keyword eq "emailto:" )            {  $email_to = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "internalipaddress:" )  {  $internal_ip_address = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "resolveddomain:" )     {  $resolved_domain = lc ( $parts[ $part_no ] );  }
		}
						  

	# Make sure it is a valid email
	$email_to = &CleanEmail( $email_to );
	$email_to = lc( $email_to );
	$email_from = lc( $email_from );
		

	my $original_email_from = lc( $email_from ) if ( $email_from );
	$original_email_from = &CleanEmail( $original_email_from );
	
	
	# If I don't have a valid to address, bail out here
	if ( ! $email_to )
		{	lprint "No valid TO: address for filename $full_filename\n";
			close( SPAM );
			return( undef );
		}
		
		
	# What host should I try to send it to?
	my $host = $barracuda_ip;
	
		
	my ( $dir, $short_file ) = &SplitFileName( $full_filename );
	$short_file = "barracuda-" . $short_file;


	# I need to read the whole file into the msg variable
	my $header = 1;	# True if I'm reading the header
	my $subject;
	
	# Use blank as the email from is there isn't one
	$email_from = "blank" if ( ! $email_from );
	
	
	my $msg;	# Save the entire message - without the comment line - into $msg
	
	# Set the first comment line to be the original filename
	$msg = "( Original Filename: $full_filename )\n";
	
	while ( my $line = <SPAM> )
		{	if ( ( $header )  &&  ( $line =~ m/^subject/i ) )
				{	$subject = $line;
				}
			
			if ( ( $line eq "\n" )  &&  ( $header ) )
				{	$header = undef;
				}
				
			# Ignore crap addresses in the header
			next if ( ( $header )  &&  ( $line =~ m/\@/ )  &&  ( ! ( $line =~ m/\:/ ) ) );
					 
			$msg .= $line if ( $msg );
			$msg = $line if ( ! defined $msg );
		}
		
	close( SPAM );


	# Send the message to the original user as if nothing has happened
	lprint "Sending $full_filename to SMTP server: $host\n" if ( $host );
	
	
	my ( $ret, $errmsg ) = &SMTPMessageFile( $short_file, $email_from, $msg, $host, undef, $email_to );	
	lprint "Error from SMTPMessageFile: $errmsg\n" if ( ! $ret );
	
	return( $ret );
}



#################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... 
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
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
Usage: $me [OPTION(s)]  
    
  -a, --asn           Calculate the ASN and IP summary table
  -c, --cidr BGPFILE  read the BGPFILE and create the CIDR.dat file
  -n, --network       Create a new network reputation file
                      (Should be done after creating ASN summary)  
  -r, --reset         reset the ASN in the MailFileIpAddress table
  -s, --source DIR    the original directory that the statistics were
                      gathered for
  -u, --unlink        Unlink any mail files that aren't archived
  -h, --help          display this help and exit
  -v, --verbose       verbose mode
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
$me $_version
.
    exit;
}


################################################################################

__END__

:endofperl
