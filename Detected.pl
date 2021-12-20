################################################################################
#!perl -w
#
#  Detected - scan a directory and display the detected status of any files found
#
#  Copyright 2007 Lightspeed Systems Inc. by Rob McCarthy
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
use Content::Scanable;
use Content::Category;



my $opt_help;
my $opt_logtype;		# This is the type of virus log file I am analyzing
my $opt_filename;		# The is the filename of the virus log file
my $opt_copy;			# If set, then copy the virus infected files to this directory
my $opt_verbose;		# True if I should be verbose about what I am doing
my $opt_subdir;			# True if I should not scan subdirectories
my $opt_unlink;			# True if I am supposed to delete the source file after copying
my $opt_notscanned;		# True if I should display files that were not scanned by an av package



my $dbhProgram;			# Handle to the Program database
my $file_handle;		# Handle to the log file
my $file_counter = 0 + 0;
my %filelist;			# The list of files that I need to copy
my $log_company;		# The company name if I am only interested in one company
my @log_companies;		# The list of all the log companies



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
		"c|copy=s"		=> \$opt_copy,
		"f|file=s"		=> \$opt_filename,
		"l|logtype=s"	=> \$opt_logtype,
		"n|notscanneds"	=> \$opt_notscanned,
		"u|unlink"		=> \$opt_unlink,
		"v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help
      );


    &StdHeader( "Detected" );
	&Usage() if ( $opt_help );


	if ( $opt_filename )
		{	if ( ! open( $file_handle, ">$opt_filename" ) )
				{	print "Unable to open file $opt_filename: $!\n";
					exit( 0 );
				}
		}
		
	
	if ( ( $opt_copy )  &&  ( ! -d $opt_copy ) )
		{	print "Unable to find copy directory $opt_copy\n";
			exit( 0 );
		}
		
		
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 0 );
		}
		
		
	# Check to make sure that I have a valid log file type
	my $ok = 1;
	$ok = undef if ( ( $opt_logtype )  &&
		( lc( $opt_logtype ) ne "f-prot" )  &&
		( lc( $opt_logtype ) ne "f-protold" )  &&
		( lc( $opt_logtype ) ne "adaware" )  &&
		( lc( $opt_logtype ) ne "drweb" )  &&
		( lc( $opt_logtype ) ne "clam" )  &&
		( lc( $opt_logtype ) ne "clamscan" )  &&
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
			print "Must be AdAware, Clam, ClamScan, DrWeb, F-Prot, F-ProtOld, F-Secure, Kaspersky,\nMcAfee, NOD32, Norton, NortonExport, SA, Sophos, TrendMicro, Windefender, or Winlog.\n";
			exit();	
		}

	$log_company = &CategoryLogCompany( $opt_logtype ) if ( $opt_logtype );
	@log_companies = &CategoryLogList();

	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	my @dir_list;
	
	
	# If no arguments, scan the current directory and all subdirectories	
	if ( $#ARGV < 0 )
		{	my $temp = getcwd;
			$temp =~ s#\/#\\#gm;
			push @dir_list, $temp;
		}
		
		
	# Read the remaining arguments as files or directories to scan
	while ( my $temp = shift )
		{	if ( $temp eq "\." )
				{	push @dir_list, $cwd;
				}
			else	
				{	# If there are no back slashes, assume it needs a back slash
					$temp = $temp . "\\" if ( ! ( $temp =~ m/\\/ ) );
					$temp =~ s#\/#\\#gm;
					push @dir_list, $temp;
				}
		}
				

	&Detected( \@dir_list );
	
	
	&VirusCopy() if ( $opt_copy );
	
	
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
	
	close( $file_handle ) if ( ( $file_handle )  &&  ( $opt_filename ) );
	$file_handle = undef;
		
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub Detected( $ )
#
#  Display what files are detected by different virus scanners
#
################################################################################
{	my $dir_list_ref = shift;
	
	return( undef ) if ( ! $dir_list_ref );
	
	my @dir_list = @$dir_list_ref;
	
	foreach ( @dir_list )
		{	my $item = $_;
					
			next if ( $item =~ m/^\.$/ );	# Skip dot files
			next if ( $item =~ m/^\.\.$/ );	# Skip dot files
					
			if ( -d $item )
				{	lprint "Checking $item and subdirectories ...\n" if ( ! $opt_subdir );
					lprint "Checking $item ...\n" if ( $opt_subdir );
	
					&CheckDir( $item );
				}
			elsif ( -f $item )
				{	lprint "Checking file $item ...\n";
					
					my $ret = &CheckFile( $item );										
				}
		}
	
	
	lprint "\nFound $file_counter matching files\n" if ( $file_counter );
	
	return( 1 );
}



################################################################################
#
sub CheckDir( $ )
#
#  Check all the files in a given directory
#
################################################################################
{
	my $dir_path = shift;

	unless( -r $dir_path ) 
		{
			lprint "Permission denied at $dir_path\n";
			return;
		}
		
	if ( !opendir( DIRHANDLE, $dir_path ) )
		{	lprint "Can't open directory $dir_path: $!";
			return;
		}
	
	lprint "Checking directory $dir_path\n" if ( $opt_verbose );
	
	for my $item ( readdir( DIRHANDLE ) ) 
		{
			( $item =~ /^\.+$/o ) and next;
			
			#$dir_path eq "/" and $dir_path = "";
			my $f;
			if ( $dir_path =~ m#\\+$# )
				{	$f = $dir_path . $item;
				}
			else
				{	$f = $dir_path . "\\" . $item;
				}
			
			
			# If the file is a directory, call recursively
			# If it is a ordinary file, scan it
			if (-d $f )
				{	&CheckDir( $f ) if ( ! $opt_subdir );
					next;
				}
				
			my $ret = &CheckFile( $f );
		}
		
	closedir( DIRHANDLE );
	
	return;
}



################################################################################
#
sub CheckFile( $ )
#
#  Check a file's detected status
#
################################################################################
{	my $file = shift;

	return( undef ) if ( ! $file );
	return( undef ) if ( ! -f $file );

	
	my ( $dir, $short_file ) = &SplitFileName( $file );
	my $lc_dir = lc( $dir );
	
	
	# Is this the type of file that I can calculate a file ID for?
	my $scan_fileid_type = &ScanableFileID( $file, 1 );

	return( undef ) if ( ! $scan_fileid_type );
	
	
	if ( $opt_verbose )
		{	lprint "\nChecking File: $file\n";
			my $scan_desc = &ScanableDescription( $scan_fileid_type );
			lprint "Scan Type: $scan_desc\n";
		}
		

	my $file_id = &ApplicationFileID( $file );
	
	# If no file id, bag it
	if ( ! $file_id )
		{	lprint "$file does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}
		
	my $hex_file_id = &StrToHex( $file_id );
	
	
	# Show I show the info?
	if ( $opt_verbose )
		{
			# Get what infomation I can out of the file itself
			my ( $app_name, $company, $desc, $product_name ) = &GetFileInfo( $file );
			return( undef ) if ( ! defined $app_name );
				
				
			my $file_version = "";
			
			if ( $app_name =~ m/file version / )
				{	my $junk;
					( $junk, $file_version ) = split /file version /, $app_name, 2;
					$file_version = "" if ( ! defined $file_version );
				}
				
			
			my $file_size = -s $file;
			
			lprint "File ID: $hex_file_id\n";		
			lprint "AppName: $app_name\n";			
			lprint "File Version: $file_version\n";
			lprint "File Size; $file_size\n";
			lprint "Description: $desc\n";
			lprint "Company: $company\n";
		}
		
	
	# Does any virus scanner detect this file?
	my %scanned;
	my $not_scanned = "Not scanned";
	foreach ( @log_companies )
		{	my $company = $_;
			next if ( ! $company );
			$scanned{ $company } = $not_scanned;
		}
		
	my $sth;
	$sth = $dbhProgram->prepare( "SELECT FileID, VirusName, Company FROM FileIDVirus WHERE FileID = \'$hex_file_id\'" );
			
	$sth->execute();

	my %detected;
	my $detected = 0 + 0;
	while ( my ( $db_fileid, $db_virus_name, $db_company ) = $sth->fetchrow_array() )
		{	next if ( ! $db_company );
			next if ( ! $db_virus_name );
			
			$detected{ $db_company } = $db_virus_name;
			$scanned{ $db_company } = $db_virus_name;
			$detected++;
		}
 
	$sth->finish();
	
	
	# If I am only looking for single company detections, am I done?
	if ( $log_company )
		{	return( undef ) if ( $detected != 1 );
			return( undef ) if ( ! $detected{ $log_company } );
		}
		
	
	my $db_company;
	my $db_virus_name;
	
		
	if ( $detected )	
		{	lprint "$file ...\n";
			while ( ( $db_company, $db_virus_name ) = each( %detected ) )
				{	lprint "\tDetected by $db_company as $db_virus_name\n";
				}
		}
		
		
	# Quit here if nothing detects it
	return( undef ) if ( ! $detected );
	
	$filelist{ $file } = $db_virus_name;
	$file_counter++;
	
	
	$sth = $dbhProgram->prepare( "SELECT FileID, Company FROM UndetectedVirus WHERE FileID = \'$hex_file_id\'" );
			
	$sth->execute();

	my @undetected;
	
	while ( my ( $db_fileid, $db_company ) = $sth->fetchrow_array() )
		{	next if ( ! $db_company );
			
			push @undetected, $db_company;
			
			lprint "\tUndetected by $db_company\n" if ( $opt_verbose );
			$scanned{ $db_company } = "Undetected";
		}
	
	$sth->finish();
	
	while ( my ( $company, $status ) = each( %scanned ) )
		{	next if ( ! $status );
			next if ( ! $company );

			next if ( $status ne $not_scanned );
			
			lprint "\t$not_scanned by $company\n" if ( $opt_notscanned );
		}

	return( 1 );
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
	
	my $copy_dir;
	
	
	my @files = sort keys %filelist;
	$copy_dir = $opt_copy;
		
	
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
			$dest =~ s/\_+$//;
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
sub Usage
#
################################################################################
{
    print <<".";

Usage: Detected directory [options]

Given a directory, display what virus scanners detect each virus sample found.

Logtypes are: AdAware, Clam, ClamScan, DrWeb, F-Prot, F-Secure, Kaspersky,
McAfee, NOD32, Norton, NortonExport, SA (Security Agent), Sophos, TrendMicro,
Windefender, and Winlog (Windefender Log format)

Possible options are:

  -c, --copy DESTDIR     copy the undetected viruses to DESTDIR
  -l, --logtype LOGTYPE  to display viruses that are only detected by LOGTYPE
  -u, --unlink           to delete the source files after copying to DESTDIR
  -v, --verbose          verbose
  -h, --help             print this message and exit

.

exit;
}



################################################################################

__END__

:endofperl
