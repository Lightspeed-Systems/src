################################################################################
#!perl -w
#
#  Undetected - Given a Antivirus company name, figure out the files in the
#  Lightspeed Virus Archive that the antivirus package can not detect
#
#  Copyright 2006 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;



use Cwd;
use Getopt::Long();
use File::Copy;
use DBI qw(:sql_types);
use DBD::ODBC;


use Content::File;
use Content::ScanUtil;
use Content::SQL;
use Content::FileIntegrity;
use Content::Category;



my $opt_help;
my $opt_logtype;		# This is the type of virus log file I am analyzing
my $opt_copy;			# If set, then copy the virus infected files to this directory
my $opt_verbose;		# True if I should be verbose about what I am doing
my $opt_update;			# True if I should update the viruses table
my $opt_recent;			# If set, then copy the recent virus infected files to this directory
my $opt_archive;		# If True, then check for missing files in the virus archive
my $opt_update_exename;	# If True then update the ExeName in the Programs and Viruses tables


my %program_info;		# The hash of file IDs and filenames and viruses

my %detected_type;		# The hash of virus types and counts
my %undetected_type;

my %recent_detected_type;		# The hash of virus types and counts
my %recent_undetected_type;

my $dbhProgram;			# Handle to the Program database
my $virus_archive_dir = "Q:\\Virus Archive";	# The directory containing the virus archive



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
		"a|archive"		=> \$opt_archive,
		"e|exe"			=> \$opt_update_exename,
		"l|logtype=s"	=> \$opt_logtype,
		"c|copy=s"		=> \$opt_copy,
		"r|recent=s"	=> \$opt_recent,
		"v|verbose"		=> \$opt_verbose,
		"u|unlink"		=> \$opt_update,
        "h|help"		=> \$opt_help
      );


    &StdHeader( "Undetected" );
	&Usage() if ( $opt_help );


	$opt_logtype	= shift;
			

	print "Copy undetected viruses to directory $opt_copy ...\n" if ( $opt_copy );
	print "Copy recent undetected viruses to directory $opt_recent ...\n" if ( $opt_recent );

	$opt_update = 1 if ( $opt_archive );
	print "Updating the viruses table ...\n" if ( $opt_update );
	print "Checking for missing files in the Virus Archive ...\n" if ( $opt_archive );
	
	
	&Usage() if ( ! $opt_logtype );
	
	
	# Check to make sure that I have a valid log file type
	my $ok = 1;
	$ok = undef if ( ( lc( $opt_logtype ) ne "f-prot" )  &&
		( lc( $opt_logtype ) ne "adaware" )  &&
		( lc( $opt_logtype ) ne "clam" )  &&
		( lc( $opt_logtype ) ne "clamscan" )  &&
		( lc( $opt_logtype ) ne "drweb" )  &&
		( lc( $opt_logtype ) ne "mcafee" )  &&
		( lc( $opt_logtype ) ne "norton" )  &&
		( lc( $opt_logtype ) ne "nortonexport" )  &&
		( lc( $opt_logtype ) ne "sophos" )  &&
		( lc( $opt_logtype ) ne "fsecure" )  &&
		( lc( $opt_logtype ) ne "f-secure" )  &&
		( lc( $opt_logtype ) ne "winlog" )  &&
		( lc( $opt_logtype ) ne "nod32" )  &&
		( ! ( $opt_logtype =~ m/^windefen/i ) )  &&
		( ! ( $opt_logtype =~ m/^kasp/i ) )  &&
		( ! ( $opt_logtype =~ m/^trend/i ) )  &&
		( lc( $opt_logtype ) ne "sa" ) );
				
					
	if ( ! $ok )
		{	print "Invalid log file type.\n";
			print "Must be AdAware, Clam, ClamScan, DrWeb, F-Prot, F-ProtOld, F-Secure, Kaspersky,\nMcAfee, NOD32, Norton, NortonExport, SA, Sophos, TrendMicro, PCCillin, \nWindefender, AVG, MalwareBytes, or Winlog.\n";
			exit( 1 );	
		}


	if ( ! -d $virus_archive_dir )
		{	print "Unable to find virus archive directory $virus_archive_dir\n";
			exit( 2 );
		}
		
		
	if ( ( $opt_copy )  &&  ( ! -d $opt_copy ) )
		{	print "Unable to find copy directory $opt_copy\n";
			exit( 4 );
		}
		
		
	if ( ( $opt_recent )  &&  ( ! -d $opt_recent ) )
		{	print "Unable to find recent copy directory $opt_recent\n";
			exit( 5 );
		}
		
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 7 );
		}
		

	if ( $opt_update )
		{	&UpdateVirusTable();
		}

	if ( $opt_update_exename )
		{	&UpdateExeName();
			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;
			
				
			&StdFooter;
			
			exit( 0 );
		}
		
	&Undetected( $opt_logtype );
	
	
	&VirusCopy( $opt_logtype ) if ( ( $opt_copy )  ||  ( $opt_recent ) );
	
	
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
		
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub Undetected( $ )
#
#  Given a logtype, figure out what viruses are undetected
#
################################################################################
{	my $log_type = shift;
	
	my $log_company = &CategoryLogCompany( $log_type );
	
	if ( ! $log_company )
		{	print "Unable to find the log company name\n";
			exit( 8 );	
		}
	
	# Purge out from the undetected table any viruses that have been detected
	print "Deleting from the UndetectedVirus table any virues that $log_company now detects ...\n";
	
	my $str = "DELETE FROM UndetectedVirus WHERE Company = '$log_company' AND FileID IN ( SELECT FileID FROM FileIDVirus WITH(NOLOCK) WHERE Company = \'$log_company\' )";
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	my $rows = $sth->rows;
	$rows = 0 + 0 if ( ! $rows );
	
	$sth->finish();
	print "Deleted $rows viruses from the Undetected table that $log_company now detects\n";
	
	
	print "Getting new files virus names from the Program database that $log_company does not detect ...\n";
	&ProgramInfoHash( $log_company );
	
	
	%detected_type = ();
	my $count = 0 + 0;
	
	
	while ( my ( $hex_file_id, $program_data ) = each( %program_info ) )
		{	next if ( ! defined $program_data );
			
			my ( $file, $virus ) = split /\t/, $program_data, 2;
			next if ( ! defined $virus );
							
			my $type = &VirusTypeName( $virus );
			next if ( ! $type );
			
			my $ret = &AddUndetectedVirus( $hex_file_id, $log_company, $virus, $type, $file );
			$count++ if ( $ret );
		}
	
	
	# Figure out the recent time - within 7 days ...
	my $recent_seconds = time() - ( 7 * 24 * 60 * 60 );
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $recent_seconds );
	$year = 1900 + $year;
	$mon = $mon + 1;
	my $recent_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, $hour, $min, $sec, 0 );

	
	# Now calculate the summary by type information
	print "Calculating the undetected summary by type ...\n";
	$str = "SELECT VirusType, Count (*) FROM UndetectedVirus WITH(NOLOCK) WHERE Company = '$log_company' GROUP BY VirusType";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	$count = 0 + 0;
	my $undetected = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $virus_type, $type_count ) = $sth->fetchrow_array() ) )
		{	$virus_type = "Unknown" if ( ! defined $virus_type );
			next if ( ! $type_count );
			
			$undetected_type{ $virus_type } = 0 + $type_count;
			$undetected += 0 + $type_count;
			
			$count++;
		}

	$sth->finish();
	print "Found $count different undetected virus types with a total of $undetected undetected viruses of all types\n";
	
	
	print "Calculating the detected summary by type ...\n";
	$str = "SELECT VirusType, Count (*) FROM FileIDVirus WITH(NOLOCK) WHERE Company = '$log_company' AND FileID IN ( SELECT FileID FROM Viruses WITH(NOLOCK) ) GROUP BY VirusType";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	$count = 0 + 0;
	my $detected = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $virus_type, $type_count ) = $sth->fetchrow_array() ) )
		{	$virus_type = "Unknown" if ( ! defined $virus_type );
			next if ( ! $type_count );
			
			$detected_type{ $virus_type } = 0 + $type_count;
			$detected += 0 + $type_count;
			
			$count++;
		}

	$sth->finish();
	print "Found $count different detected virus types with a total of $detected detected viruses of all types\n";
	
	
	print "Calculating the total viruses ...\n";
	$str = "SELECT Count (*) FROM Viruses WITH(NOLOCK)";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	my $total = $sth->fetchrow_array();
	$total = 0 + 0 if ( ! defined $total );
	$total = 0 + $total;

	$sth->finish();
	
	print "Found $total viruses in the Viruses table in the Program database\n";
	
	
	print "Updating the summary information for $log_company ...\n";
	&UpdateUndetectedSummary( $log_company, $total, $undetected );
	
	
	print "Calculating the recent undetected summary by type (using cutoff date of $recent_time) ...\n";
	$str = "SELECT VirusType, Count (*) FROM UndetectedVirus WITH(NOLOCK) WHERE Company = '$log_company' AND TransactionTime > '$recent_time' GROUP BY VirusType";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	$count = 0 + 0;
	my $recent_undetected = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $virus_type, $type_count ) = $sth->fetchrow_array() ) )
		{	$virus_type = "Unknown" if ( ! defined $virus_type );
			next if ( ! $type_count );
			
			$recent_undetected_type{ $virus_type } = 0 + $type_count;
			$recent_undetected += 0 + $type_count;
			
			$count++;
		}

	$sth->finish();
	print "Found $count different recent undetected virus types with a total of $recent_undetected undetected viruses of all types\n";
	
	
	print "Calculating the recent detected summary by type (using cutoff date of $recent_time) ...\n";
	$str = "SELECT VirusType, Count (*) FROM FileIDVirus WITH(NOLOCK) WHERE Company = '$log_company' AND FileID IN ( SELECT FileID FROM Viruses WITH(NOLOCK) WHERE TransactionTime > '$recent_time' ) GROUP BY VirusType";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	$count = 0 + 0;
	my $recent_detected = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $virus_type, $type_count ) = $sth->fetchrow_array() ) )
		{	$virus_type = "Unknown" if ( ! defined $virus_type );
			next if ( ! $type_count );
			
			$recent_detected_type{ $virus_type } = 0 + $type_count;
			$recent_detected += 0 + $type_count;
			
			$count++;
		}

	$sth->finish();
	print "Found $count different recent detected virus types with a total of $recent_detected detected viruses of all types\n";
	
	
	print "Calculating the total recent viruses (using cutoff date of $recent_time) ...\n";
	$str = "SELECT Count (*) FROM Viruses WITH(NOLOCK) WHERE TransactionTime > '$recent_time'";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	my $recent_total = $sth->fetchrow_array();
	$total = 0 + 0 if ( ! defined $total );
	$total = 0 + $total;

	$sth->finish();
	
	print "Found $recent_total viruses in the Viruses table in the Program database added since $recent_time\n";
	
	&UpdateRecentUndetectedSummary( $log_company, $recent_total, $recent_undetected );
	
	return( 1 );
}



################################################################################
# 
sub AddUndetectedVirus( $$$ $$$ )
#
#	Add the undetected virus info to the database
#
################################################################################
{	my $hex_file_id = shift;
	my $company		= shift;
	my $virus_name	= shift;
	
	my $virus_type	= shift;
	my $filename	= shift;
	
	return( undef ) if ( ! $hex_file_id );
	return( undef ) if ( length( $hex_file_id ) != 56 );
	
	$virus_name			= &quoteurl( $virus_name );
	$virus_name			= &SqlColumnSize( $virus_name, 64 );

	$virus_type			= &quoteurl( $virus_type );
	$virus_type			= &SqlColumnSize( $virus_type, 32 );

	$company			= &quoteurl( $company );
	$company			= &SqlColumnSize( $company, 32 );

	$filename			= &quoteurl( $filename );
	$filename			= &SqlColumnSize( $filename, 255 );

	
	# Convert them to values for the insert
	my $vhex_file_id	= "\'" . $hex_file_id . "\'";
	my $vvirus_name		= "\'" . $virus_name . "\'";
	my $vvirus_type		= "\'" . $virus_type . "\'";
	my $vcompany		= "\'" . $company . "\'";
	my $vfilename		= "\'" . $filename . "\'";
	
	
	# Insert the row into the UndetectedVirus table
	my $str = "INSERT INTO UndetectedVirus ( FileID, Company, VirusName, VirusType, Filename ) VALUES ( $vhex_file_id, $vcompany, $vvirus_name, $vvirus_type, $vfilename )";
	my $sth = $dbhProgram->prepare( $str );
	my $ok = $sth->execute();

	my $rows = 0 + $sth->rows;

	$ok = undef if ( $rows ne 1 );
	
	$sth->finish();

	return( $ok );
}



################################################################################
# 
sub UpdateUndetectedSummary( $$$ )
#
#	Add the undetected virus info to the database
#
################################################################################
{	my $company		= shift;
	my $total		= shift;
	my $undetected	= shift;
	

	return( undef ) if ( ! $company );
	return( undef ) if ( ! $total );
	
	$total		= 0 + $total;
	$undetected = 0 + 0 if ( ! $undetected );
	
	my $detected = $total - $undetected;
	
	my $detected_percent = 100 * ( $detected / $total );
	$detected_percent = sprintf( "%.2f", $detected_percent );
	
	print "$company has a detected percentage of $detected_percent\n";
	
	my $undetected_percent = 100 * ( $undetected / $total );
	$undetected_percent = sprintf( "%.2f", $undetected_percent );
	
	print "$company has a undetected percentage of $undetected_percent\n";
	
	$company			= &quoteurl( $company );
	$company			= &SqlColumnSize( $company, 32 );

	# Convert them to values for the insert
	my $vcompany			= "\'" . $company . "\'";
	my $vtotal				= "\'" . $total . "\'";
	my $vdetected			= "\'" . $detected . "\'";
	my $vundetected			= "\'" . $undetected . "\'";
	my $vdetected_percent	= "\'" . $detected_percent . "\'";
	my $vundetected_percent	= "\'" . $undetected_percent . "\'";
	
	
	# Get rid of any old record
	my $str = "DELETE UndetectedSummary WHERE Company = $vcompany";
	my $sth = $dbhProgram->prepare( $str );
	my $ok = $sth->execute();
	$sth->finish();

	
	# Insert the row into the database
	$str = "INSERT INTO UndetectedSummary ( Company, TotalScanned, TotalDetected, TotalUndetected, DetectedPercent, UndetectedPercent ) 
									VALUES ( $vcompany, $vtotal, $vdetected, $vundetected, $vdetected_percent, $vundetected_percent )";

	$sth = $dbhProgram->prepare( $str );
	$ok = $sth->execute();

	my $rows = 0 + $sth->rows;
	$ok = undef if ( $rows ne 1 );
	
	$sth->finish();


	# Now put the type info into the database
	# Get rid of any old records
	$str = "DELETE DetectedType WHERE Company = $vcompany";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	$str = "DELETE UndetectedType WHERE Company = $vcompany";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	$sth->finish();

	
	# Put the detected counts in
	while ( my ( $virus_type, $count ) = each( %detected_type ) )
		{	next if ( ! $virus_type );
			next if ( ! $count );
			
			$count = 0 + $count;
			
			my $vvirus_type = "\'" . $virus_type . "\'";
			my $vcount = "\'" . $count . "\'";
			
			$str = "INSERT INTO DetectedType ( Company, VirusType, [Count] ) 
									VALUES ( $vcompany, $vvirus_type, $vcount )";

			$sth = $dbhProgram->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
	
	
	# Put the undetected counts in
	while ( my ( $virus_type, $count ) = each( %undetected_type ) )
		{	next if ( ! $virus_type );
			next if ( ! $count );
			
			$count = 0 + $count;
			
			my $vvirus_type = "\'" . $virus_type . "\'";
			my $vcount = "\'" . $count . "\'";
			
			$str = "INSERT INTO UndetectedType ( Company, VirusType, [Count] ) 
									VALUES ( $vcompany, $vvirus_type, $vcount )";

			$sth = $dbhProgram->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
	
	
	return( 0 + 1 );
}



################################################################################
# 
sub UpdateRecentUndetectedSummary( $$$ )
#
#	Add the recent undetected virus info to the database
#
################################################################################
{	my $company		= shift;
	my $total		= shift;
	my $undetected	= shift;
	

	return( undef ) if ( ! $company );
	return( undef ) if ( ! $total );
	
	$total		= 0 + $total;
	$undetected = 0 + 0 if ( ! $undetected );
	
	my $detected = $total - $undetected;
	
	my $detected_percent = 100 * ( $detected / $total );
	$detected_percent = sprintf( "%.2f", $detected_percent );
	
	print "$company has a recent detected percentage of $detected_percent\n";
	
	my $undetected_percent = 100 * ( $undetected / $total );
	$undetected_percent = sprintf( "%.2f", $undetected_percent );
	
	print "$company has a recent undetected percentage of $undetected_percent\n";
	
	$company			= &quoteurl( $company );
	$company			= &SqlColumnSize( $company, 32 );

	# Convert them to values for the insert
	my $vcompany			= "\'" . $company . "\'";
	my $vtotal				= "\'" . $total . "\'";
	my $vdetected			= "\'" . $detected . "\'";
	my $vundetected			= "\'" . $undetected . "\'";
	my $vdetected_percent	= "\'" . $detected_percent . "\'";
	my $vundetected_percent	= "\'" . $undetected_percent . "\'";
	
	
	# Get rid of any old record
	my $str = "DELETE RecentUndetectedSummary WHERE Company = $vcompany";
	my $sth = $dbhProgram->prepare( $str );
	my $ok = $sth->execute();
	$sth->finish();

	
	# Insert the row into the database
	$str = "INSERT INTO RecentUndetectedSummary ( Company, TotalScanned, TotalDetected, TotalUndetected, DetectedPercent, UndetectedPercent ) 
									VALUES ( $vcompany, $vtotal, $vdetected, $vundetected, $vdetected_percent, $vundetected_percent )";

	$sth = $dbhProgram->prepare( $str );
	$ok = $sth->execute();

	my $rows = 0 + $sth->rows;
	$ok = undef if ( $rows ne 1 );
	
	$sth->finish();


	# Now put the type info into the database
	# Get rid of any old records
	$str = "DELETE RecentDetectedType WHERE Company = $vcompany";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	$str = "DELETE RecentUndetectedType WHERE Company = $vcompany";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	$sth->finish();

	
	# Put the detected counts in
	while ( my ( $virus_type, $count ) = each( %recent_detected_type ) )
		{	next if ( ! $virus_type );
			next if ( ! $count );
			
			$count = 0 + $count;
			
			my $vvirus_type = "\'" . $virus_type . "\'";
			my $vcount = "\'" . $count . "\'";
			
			$str = "INSERT INTO RecentDetectedType ( Company, VirusType, [Count] ) 
									VALUES ( $vcompany, $vvirus_type, $vcount )";

			$sth = $dbhProgram->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
	
	
	# Put the undetected counts in
	while ( my ( $virus_type, $count ) = each( %recent_undetected_type ) )
		{	next if ( ! $virus_type );
			next if ( ! $count );
			
			$count = 0 + $count;
			
			my $vvirus_type = "\'" . $virus_type . "\'";
			my $vcount = "\'" . $count . "\'";
			
			$str = "INSERT INTO RecentUndetectedType ( Company, VirusType, [Count] ) 
									VALUES ( $vcompany, $vvirus_type, $vcount )";

			$sth = $dbhProgram->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
	
	
	return( 0 + 1 );
}



################################################################################
# 
sub UpdateVirusTable()
#
#	Updating the virus table with the newest viruses
#
################################################################################
{
	print "Deleting from the Virus table files that have moved ...\n";
	my $str = "DELETE FROM Viruses WHERE [Filename] NOT IN
( SELECT [Filename] FROM Programs WITH(NOLOCK) WHERE [Filename] like 'Q:\\Virus Archive\\%' )";
	
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	my $rows = $sth->rows;
	print "Deleted $rows moved files from table Viruses ...\n";
	
	$sth->finish();
	
	
	print "Adding in new files into the Virus table ...\n";
	$str = "INSERT INTO Viruses ( FileID, AppName, [Filename], MD5, TransactionTime, ExeName )
SELECT FileID, AppName, [Filename], MD5, TransactionTime, ExeName
FROM Programs WITH(NOLOCK)
WHERE [Filename] like 'Q:\\Virus Archive\\%' AND FileID NOT IN ( SELECT FileID From Viruses WITH(NOLOCK) )";
	
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	$rows = $sth->rows;
	print "Added $rows new files to table Viruses ...\n";
	
	$sth->finish();
	
	
	print "Purging the UndetectedVirus table of missing viruses ...\n";
	$str = "DELETE UndetectedVirus WHERE FileID NOT IN ( SELECT FileID FROM Viruses WITH(NOLOCK) )";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	$rows = $sth->rows;
	print "Deleted $rows of missing files from table UndetectedViruses ...\n";
	
	$sth->finish();
	
	
	# I can quit here if I'm not check for missing files
	return( 1 ) if ( $opt_archive );
	
	
	$str = "SELECT FileID, AppName, [Filename] FROM Viruses WITH(NOLOCK)";
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	
	print "Getting the list of viruses and checking that they exist on in Q:\\Virus Archive ...\n";

#	my @virus;  # Not used anymore


	my $count = 0 + 0;
	my @missing;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $hex_file_id, $virus, $file ) = $sth->fetchrow_array() ) )
		{	last if ( ! $hex_file_id );
			next if ( ! $virus );
			
			# Does the file exist?
			if ( ! -f $file )
				{	print "$hex_file_id $file is missing\n";
					push @missing, $hex_file_id;
					next;
				}
				
			my $data = "$hex_file_id\t$virus";
			
#			push @virus, $data;	# Not used anymore
			
			print "Found $file\n" if ( $opt_verbose );
			
			$count++;
		}

	$sth->finish();
	
	
	print "Found $count viruses in the Virus Archive ...\n";
	
	my $missing = $#missing + 1;	
	print "Found $missing viruses in the Virus Archive ...\n" if ( $missing );


	# Get rid of the missing entries from the program database
	my $deleted = 0 + 0;
	foreach ( @missing )
		{	my $hex_file_id = $_;
			next if ( ! defined $hex_file_id );
			
			$str = "DELETE From Programs WHERE FileID = '$hex_file_id'";
			$sth = $dbhProgram->prepare( $str );
			$sth->execute();
			$sth->finish();

			$deleted++;
		}
		
	print "Deleted $deleted missing files from the Programs table\n" if ( $deleted );
	@missing = ();
	

# Only needed to run this once	
#	print "Resetting the virus types ...\n";
#	my $resetting = 0 + 0;
#	foreach ( @virus )
#		{	my $data = $_;
#			next if ( ! $data );
#			my ( $hex_file_id, $virus ) = split /\t/, $data, 2;
			
#			next if ( ! $hex_file_id );
#			next if ( ! $virus );
			
#			my $type = &VirusTypeName( $virus );
#			next if ( ! $type );

#			$str = "UPDATE FileIDVirus SET VirusType = '$type' WHERE FileID = '$hex_file_id'";
#			$sth = $dbhProgram->prepare( $str );
#			$sth->execute();
#			$sth->finish();
			
#			$resetting += $sth->rows if ( $sth->rows );
#		}
		
#	print "Reset $resetting rows of table FileID virus types\n";
	
	return( 1 );
}



################################################################################
# 
sub ProgramInfoHash( $ )
#
#	Build up the program_info hash with filenames and the virus names of newly
#   added viruses in the Virus Archive that are not detected by the log company
#
################################################################################
{	my $log_company = shift;
	
	
	my $str = "SELECT FileID, [Filename], AppName, TransactionTime from Viruses WITH(NOLOCK)
	where FileID NOT IN ( select FileID FROM FileIDVirus WITH(NOLOCK) where Company = \'$log_company\' )
	AND FileID NOT IN ( select FileID FROM UndetectedVirus WITH(NOLOCK) where Company = \'$log_company\' )";
	
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();


	my $count = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $hex_file_id, $file, $virus, $transaction_time ) = $sth->fetchrow_array() ) )
		{	last if ( ! $hex_file_id );
			next if ( ! $file );
			
			next if ( ! ( $file =~ m/virus archive/i ) );
			
			&SqlSleep();
			
			$program_info{ $hex_file_id } = "$file\t$virus";
			$count++;
		}

	$sth->finish();

	print "Found $count files in the Virus Archive from the Program database that $log_company does not detect\n";
	
	return( $count );
}



################################################################################
# 
sub VirusCopy( $ )
#
#	Copy the undetected files
#
################################################################################
{	my $log_type = shift;
	
	my $log_company = &CategoryLogCompany( $log_type );
	
	if ( ! $log_company )
		{	print "Unable to find the log company name\n";
			exit( 8 );	
		}

	my $copy_count = 0 + 0;
	
	my @files;
	my $copy_dir;
	my %filelist;
	
	if ( $opt_recent )
		{	# Figure out the recent time - within 7 days ...
			my $recent_seconds = time() - ( 7 * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $recent_seconds );
			$year = 1900 + $year;
			$mon = $mon + 1;
			my $recent_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, $hour, $min, $sec, 0 );

			
			my $str = "SELECT Filename, AppName FROM Viruses WITH(NOLOCK) 
			WHERE FileID IN ( select FileID FROM UndetectedVirus WITH(NOLOCK) where Company = '$log_company' AND TransactionTime > '$recent_time' )";
	
			my $sth = $dbhProgram->prepare( $str );
			$sth->execute();

			my $count = 0 + 0;
			while ( ( ! $dbhProgram->err )  &&  ( my ( $file, $virus ) = $sth->fetchrow_array() ) )
				{	next if ( ! defined $file );
					next if ( ! defined $virus );
					
					push @files, $file;
					$filelist{ $file } = $virus;
					
					$count++;
				}

			$sth->finish();
			
			print "Found $count files to copy ...\n";
			
			$copy_dir = $opt_recent;
		}
	else
		{	my $str = "SELECT Filename, AppName FROM Viruses WITH(NOLOCK) 
			WHERE FileID IN ( select FileID FROM UndetectedVirus WITH(NOLOCK) where Company = '$log_company' )";
	
			my $sth = $dbhProgram->prepare( $str );
			$sth->execute();

			my $count = 0 + 0;
			while ( ( ! $dbhProgram->err )  &&  ( my ( $file, $virus ) = $sth->fetchrow_array() ) )
				{	next if ( ! defined $file );
					next if ( ! defined $virus );
					
					push @files, $file;
					$filelist{ $file } = $virus;
					
					$count++;
				}

			$sth->finish();

			print "Found $count files to copy ...\n";
			
			$copy_dir = $opt_copy;
		}
		
	
	foreach ( @files )
		{	my $file = $_;
			
			next if ( ! defined $file );
			
			my $virus = $filelist{ $file };
			next if ( ! defined $virus );
			
			if ( ! -f $file )
				{
					print "Error: Unable to find file $file\n";
					next;
				}
				
			my ( $dir, $short ) = &SplitFileName( $file );
			
			next if ( ! $short );
			
			# See if I can figure out if it is a VBS, W32, Linux, etc type of virus
			my $virus_dir = &VirusTypeDir( $virus );
			
			my $dest_dir = $copy_dir . "\\$virus";
			$dest_dir = $copy_dir . "\\$virus_dir" . "\\$virus" if ( $virus_dir ); 
			
			my $ok = &MakeDirectory( $dest_dir );
			if ( ! $ok )
				{	print "Error making directory $dest_dir: $!\n";
					exit( 9 );
				}
				
			my $dest = $dest_dir . "\\$short";
			
			# Add an underscore the file destingation filename if it doesn't already have one
			$dest =~ s/\_+$//;
			$dest .= '_' if ( ! ( $dest =~ m/\_$/ ) );
			
			# If the destination already exists, don't copy it again
			if ( ! -e $dest )
				{	print "Copying $file ...\n";
			
					$ok = copy( $file, $dest );
					
					$copy_count++ if ( $ok );
					
					if ( ! $ok )
						{	print "Error copying $file to $dest: $!\n";
							exit( 10 );
						}
						
					if ( ! -e $dest )
						{	print "Error copying $file to $dest\n";
							exit( 11 );
						}
				}
			else
				{	print "Skipping existing file $dest ...\n";
				}
		}
	
	print "Copied $copy_count virus infected programs ...\n";
	
	return( $copy_count );
}



################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Return OK if the directory already exists
	return( 1 ) if ( -d $dir );
	
	my @parts = split /\\/, $dir;
	
	my $created_dir;
	foreach ( @parts )
		{	next if ( ! defined $_ );
			
			$created_dir .= "\\" . $_ if ( defined $created_dir );
			$created_dir = $_ if ( ! defined $created_dir );

			if ( ! -d $created_dir )
				{	mkdir( $created_dir );
				}
		}
		
	# Return OK if the directory now exists
	return( 1 ) if ( -d $dir );
	
	return( undef );
}



################################################################################
# 
sub Trim($)
#  Given a path, trim off a level.  Return undef if down to nothing
################################################################################
{
   my  @parts = split /\\/, shift;
   my  $i;
   my  $trim;


   #  Return undef if down to the last parts
   return( undef ) if ( $#parts < 1 );
   
   for ( $i = 0;  $i < $#parts;  $i++ )
      {  if ( defined $trim )  {  $trim = $trim . "\\" . $parts[ $i ];  }
         else  {  $trim = $parts[ $i ];  }
      }

	return( undef ) if ( ! $trim =~ m/\\/ );
    return( $trim );
}



################################################################################
# 
sub UpdateExeName()
#
#	Updating the ExeName column in the Programs and Viruses table
#
################################################################################
{
	print "Updating the ExeName column in the Programs table ...\n";
	my $str = "SELECT FileID, [Filename] FROM Programs WITH(NOLOCK) WHERE ExeName IS NULL";
	
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	my @data;
	my $count = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $hex_file_id, $file ) = $sth->fetchrow_array() ) )
		{	last if ( ! $hex_file_id );
			next if ( ! defined $file );

			my ( $dir, $short ) = &SplitFileName( $file );

			$count++;
			
			next if ( ! defined $short );
			
			push @data, "$hex_file_id\t$short";
			
#			last if ( $count >= 1000000 );
		}

	$sth->finish();
	
	print "Found $count files in the Programs table\n";
	
	$count = 0 + 0;
	foreach ( @data )
		{	my $data = $_;
			next if ( ! defined $data );
			
			my ( $hex_file_id, $short ) = split /\t/, $data;
			last if ( ! $hex_file_id );
			
			my $qshort = &quoteurl( $short );
			$str = "UPDATE Programs SET ExeName = '$qshort' WHERE FileID = '$hex_file_id'";
	
			$sth = $dbhProgram->prepare( $str );
			$sth->execute();
			
			$sth->finish();
			
			$count++;
		}
		
	print "Updated $count rows in the Programs table\n";
	
	@data = ();
	

	print "Updating the ExeName column in the Viruses table ...\n";
	$str = "SELECT FileID, [Filename] FROM Viruses WITH(NOLOCK) WHERE ExeName IS NULL";
	
	$sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	$count = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $hex_file_id, $file ) = $sth->fetchrow_array() ) )
		{	last if ( ! $hex_file_id );
			next if ( ! defined $file );

			my ( $dir, $short ) = &SplitFileName( $file );

			$count++;
			
			next if ( ! defined $short );
			
			push @data, "$hex_file_id\t$short";
		}

	$sth->finish();
	
	print "Found $count files in the Viruses table\n";
	
	$count = 0 + 0;
	foreach ( @data )
		{	my $data = $_;
			next if ( ! defined $data );
			
			my ( $hex_file_id, $short ) = split /\t/, $data;
			last if ( ! $hex_file_id );
			
			my $qshort = &quoteurl( $short );
			$str = "UPDATE Viruses SET ExeName = '$qshort' WHERE FileID = '$hex_file_id'";
	
			$sth = $dbhProgram->prepare( $str );
			$sth->execute();
			
			$sth->finish();
			
			$count++;
		}
		
	print "Updated $count rows in the Viruses table\n";
	
	@data = ();
	return( 1 );	
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";

Usage: Undetected logtype [options]

Given the virus log type, return a list of the viruses in the Lightspeed
Virus Archive that the virus package does not detect.

This utility also updates the Undetected table in the Program database. 

Logtypes are: AdAware, DrWeb, Clam, ClamScan, F-Prot, F-ProtOld, F-Secure,
Kaspersky, McAfee, NOD32, Norton, NortonExport, SA (Security Agent), Sophos,
TrendMicro, PCCillin, Windefender, AVG, MalwareBytes, and 
Winlog (Windefender Log format)

Possible options are:

  -a, --archive         check for missing files in the Virus Archive
  -e, --exe             update the ExeName column in Programs and Viruses
  -c, --copy DESTDIR    copy the undetected viruses to DESTDIR
  -r, --recent DESDIR   to copy only recent viruses to DESTDIR
  -u, --update          update Viruses table with latest viruses
                        (This should be run once a week)
						
  -v, --verbose         verbose
  -h, --help            print this message and exit

.

exit( 12 );
}



################################################################################

__END__

:endofperl
