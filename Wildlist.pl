################################################################################
#!perl -w
#
#  Wildlist - given a list of Kaspersky virus name on the wildlist,
#  rebuild the Wildlist table in the Program database
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
use Digest::MD5;


use Content::File;
use Content::ScanUtil;
use Content::SQL;
use Content::FileIntegrity;
use Content::Category;



my $opt_help;
my $opt_filename;		# The is the filename of the virus log file
my $opt_logtype;
my $opt_verbose;		# True if I should be verbose about what I am doing
my $dbhProgram;			# Handle to the Program database
my $file_handle;		# Handle to the log file



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
		"f|file=s"		=> \$opt_filename,
		"v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help
      );


    &StdHeader( "Wildlist" );
	&Usage() if ( $opt_help );


	$opt_filename	= shift;
	$opt_logtype = shift;		

	print "Read the wildlist virus names from file $opt_filename\n" if ( $opt_filename );	
	
	&Usage() if ( ! $opt_filename );
	
	
	# Check to make sure that I have a valid log file type
	my $ok = 1;
	$ok = undef if ( ( lc( $opt_logtype ) ne "f-prot" )  &&
		( lc( $opt_logtype ) ne "adaware" )  &&
		( lc( $opt_logtype ) ne "clam" )  &&
		( lc( $opt_logtype ) ne "clamscan" )  &&
		( lc( $opt_logtype ) ne "mcafee" )  &&
		( lc( $opt_logtype ) ne "norton" )  &&
		( lc( $opt_logtype ) ne "nortonexport" )  &&
		( lc( $opt_logtype ) ne "sophos" )  &&
		( lc( $opt_logtype ) ne "fsecure" )  &&
		( lc( $opt_logtype ) ne "f-secure" )  &&
		( lc( $opt_logtype ) ne "winlog" )  &&
		( ! ( $opt_logtype =~ m/^windefen/i ) )  &&
		( ! ( $opt_logtype =~ m/^kasp/i ) )  &&
		( ! ( $opt_logtype =~ m/^trend/i ) )  &&
		( lc( $opt_logtype ) ne "sa" ) );
					
	if ( ! $ok )
		{	print "Invalid log file type.\n";
			print "Must be AdAware, Clam, ClamScan, F-Prot, F-Secure, Kaspersky, McAfee, Norton,\nNortonExport, SA, Sophos, TrendMicro, Windefender, or Winlog.\n";
			exit();	
		}


	if ( $opt_filename )
		{	if ( ! open( $file_handle, "<$opt_filename" ) )
				{	print "Unable to open file $opt_filename: $!\n";
					exit( 0 );
				}
		}
		
	
		
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 0 );
		}
		
	
	# Actually do the work	
	&ImportWildlist();
	
	
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
	
	close( $file_handle ) if ( ( $file_handle )  &&  ( $opt_filename ) );
	$file_handle = undef;
		
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub ImportWildlist()
#
#  Given a logtype, figure out what viruses are undetected
#
################################################################################
{
	my $log_company = &CategoryLogCompany( $opt_logtype );
	
	die "Unable to find the log company name\n" if ( ! $log_company );
	
	# Clear out the current wildlist
	print "Clearing out the old Wildlist ...\n";
	my $str = "DELETE Wildlist";
	
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();

	$sth->finish();


	# Read each line of the file looking for valid virus names
	my @wildlist_fileIDs;
	
	my $counter = 0 + 0;
	my $virus_counter++;
	while ( my $virus = <$file_handle> )
		{	next if ( ! $virus );
			
			$virus = &CleanVName( $virus );
			$counter++;
			
			my @vlist = &VirusList( $virus );
			
			my $vcount = 1 + $#vlist;
			if ( $count < 1 )
				{	print "Unable to find any file IDs that match virus name $virus\n";
					next;	
				}
			
			print "Found $vcount file IDs for $virus\n";	
			push @wildlist, @vlist;	
			
			$virus_counter += $vcount;
		}
		
		

	my @keys = sort keys %filelist;
	%undetected_type = ();
	%recent_undetected_type = ();
	
	foreach ( @keys )
		{	my $file = $_;
			next if ( ! $file );
			
			my $data = $filelist{ $file };
			next if ( ! $data );
			
			my ( $content_virus_name, $hex_file_id ) = split /\t/, $data, 2;
			next if ( ! $content_virus_name );
			next if ( ! $hex_file_id );
			
			my $type = &VirusTypeName( $content_virus_name );
			next if ( ! $type );
			
			print "$file\t$content_virus_name\t$hex_file_id\n" if ( $opt_verbose );
			print $file_handle "$file\t$content_virus_name\t$hex_file_id\n" if ( $file_handle );
			
			my $recent = 1 if ( defined $recent_filelist{ $file } );
			
			my $ret = &AddUndetectedVirus( $hex_file_id, $log_company, $content_virus_name, $type, $file, $recent );
			$file_id_unknown++ if ( $ret );

			# Keep track of the count of types of viruses detected
			if ( ! defined $undetected_type{ $type } )
				{	$undetected_type{ $type } = 0 + 1;
				}
			else
				{	my $type_count = $undetected_type{ $type };
					$type_count++;
					$undetected_type{ $type } = $type_count;
				}
				
			# Do the recent calculations
			next if ( ! $recent );
			
 			if ( ! defined $recent_undetected_type{ $type } )
				{	$recent_undetected_type{ $type } = 0 + 1;
				}
			else
				{	my $recent_type_count = $recent_undetected_type{ $type };
					$recent_type_count++;
					$recent_undetected_type{ $type } = $recent_type_count;
				}
		}
	
	
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
	my $recent		= shift;	# True if this is a recent virus
	
	return( undef ) if ( ! $hex_file_id );
	return( undef ) if ( length( $hex_file_id ) != 56 );
	
	$virus_name			= &quoteurl( $virus_name );
	$virus_name			= &SQLColumnSize( $virus_name, 64 );

	$virus_type			= &quoteurl( $virus_type );
	$virus_type			= &SQLColumnSize( $virus_type, 32 );

	$company			= &quoteurl( $company );
	$company			= &SQLColumnSize( $company, 32 );

	$filename			= &quoteurl( $filename );
	$filename			= &SQLColumnSize( $filename, 255 );

	
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

	return( 0 + 1 ) if ( ! $recent );
	
	
	# Insert the row into the RecentUndetectedVirus table
	$str = "INSERT INTO RecentUndetectedVirus ( FileID, Company, VirusName, VirusType, Filename ) VALUES ( $vhex_file_id, $vcompany, $vvirus_name, $vvirus_type, $vfilename )";
	$sth = $dbhProgram->prepare( $str );
	$ok = $sth->execute();

	$rows = 0 + $sth->rows;

	$ok = undef if ( $rows ne 1 );
	
	$sth->finish();

	return( 0 + 1 ) if ( $ok );
	
	return( 0 + 0 );
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
	$company			= &SQLColumnSize( $company, 32 );

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
	$company			= &SQLColumnSize( $company, 32 );

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
sub ProgramInfoHash()
#
#	Build up the program_info hash with filenames and the virus names
#
################################################################################
{	my $str = "SELECT FileID, Filename, AppName, TransactionTime from Programs where Filename like \'%virus archive%\'";
	
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();

	# Figure out the recent time - within 7 days ...
	my $recent_seconds = time() - ( 7 * 24 * 60 * 60 );
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $recent_seconds );
	$year = 1900 + $year;
	$mon = $mon + 1;
	my $recent_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, $hour, $min, $sec, 0 );

	my $count = 0 + 0;
	my $recent_count = 0 + 0;
	
	while ( ( ! $dbhProgram->err )  &&  ( my ( $hex_file_id, $file, $virus, $transaction_time ) = $sth->fetchrow_array() ) )
		{	last if ( ! $hex_file_id );
			next if ( ! $file );
			
			next if ( ! ( $file =~ m/virus archive/i ) );
			
			$program_info{ $hex_file_id } = "$file\t$virus";
			$count++;
			
			next if ( $transaction_time lt $recent_time );
			
			$recent_program_info{ $hex_file_id } = "$file\t$virus";
			$recent_count++;
		}

	$sth->finish();

	print "Found $count files in the Virus Archive from the Program database\n";
	print "Found $recent_count recent files\n";
	
	return( $count );
}



################################################################################
# 
sub VirusCopy()
#
#	Copy the files in the filelist hash
#
################################################################################
{
	my $copy_count = 0 + 0;
	
	my @files;
	my $copy_dir;
	
	
	if ( $opt_recent )
		{	@files = sort keys %recent_filelist;
			$copy_dir = $opt_recent;
		}
	else
		{	@files = sort keys %filelist;
			$copy_dir = $opt_copy;
		}
		
	
	foreach ( @files )
		{	my $vfile = $_;
			
			next if ( ! $vfile );
			
			my $data = $filelist{ $vfile };
			next if ( ! $data );
			
			my ( $virus, $hex_file_id ) = split /\t/, $data, 2;
			next if ( ! $virus );
			
			if ( ! -f $vfile )
				{
					print "Error: Unable to find file $vfile\n";
					next;
				}
				
			my ( $dir, $short ) = &SplitFileName( $vfile );
			
			next if ( ! $short );
			
			# See if I can figure out if it is a VBS, W32, Linux, etc type of virus
			my $virus_type = &VirusTypeName( $virus );
			
			my $dest_dir = $copy_dir . "\\$virus";
			$dest_dir = $copy_dir . "\\$virus_type" . "\\$virus" if ( $virus_type ); 
			
			my $ok = &MakeDirectory( $dest_dir );
			if ( ! $ok )
				{	print "Error making directory $dest_dir: $!\n";
					next;
				}
				
			my $dest = $dest_dir . "\\$short";
			
			# Add an underscore the file destingation filename if it doesn't already have one
			$dest .= '_' if ( ! ( $dest =~ m/\_$/ ) );
			
			# If the destination already exists, don't copy it again
			if ( ! -e $dest )
				{	print "Copying $vfile ...\n";
			
					$ok = copy( $vfile, $dest );
					
					$copy_count++ if ( $ok );
					
					print "Error copying $vfile to $dest: $!\n" if ( ! $ok );
					next if ( ! $ok );
				}
			else
				{	print "Skipping existing file $dest ...\n";
				}
				
			unlink( $vfile ) if ( $opt_unlink );
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
				{	mkdir $created_dir;
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
sub Usage
#
################################################################################
{
    print <<".";

Usage: Undetected logtype [options]

Given the virus log type, return a list of the viruses in the Lightspeed
Virus Archive that the virus package does not detect.

This utility also updates the Undetected table in the Program database. 

Logtypes are: F-Prot, AdAware, Clam, ClamScan, Kaspersky, McAfee, Norton,
TrendMicro, Sophos, SA (Security Agent), Windefender, and
Winlog (Windefender Log format)

Possible options are:

  -c, --copy DESTDIR    copy the undetected viruses to DESTDIR
  -f, --file FILELIST   create a text file with the list of undetected files
  -r, --recent DESDIR   to copy only recent viruses to DESTDIR
  -v, --verbose         verbose
  -h, --help            print this message and exit

.

exit;
}



################################################################################

__END__

:endofperl
