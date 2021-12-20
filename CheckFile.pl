################################################################################
#!perl -w
#
# Rob McCarthy's CheckFile.pl source code
#  Copyright 2009 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long();
use Cwd;
use File::Copy;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32API::Registry 0.21 qw( :ALL );
use Sys::Hostname;



use Content::File;
use Content::ScanUtil;
use Content::ScanFile;
use Content::Scanable;
use Content::FileIntegrity;
use Content::Category;
use Content::SQL;
use Content::FileInfo;



my $opt_file;
my $opt_help;
my $opt_debug;
my $opt_verbose;
my $check_root				= "Q:\\Virus Check";						# This is the root directory to put all virus check results into
my $platoon_leader_unc		= "\\\\Army-VM120\\Drive-J\\DonePrograms";	# This is used to copy files into the platoon leader so that it is virus scanned and archived
my $opt_copy;
my $opt_bcopy;
my $opt_move;
my $opt_dir;
my $log_company;
my $opt_path;	# If set this is the path to create log files in
my $hostname = hostname;
my $log_directory				= "Q:\\Virus Logs";
my $opt_original_file;
my $opt_id;
my $further_analysis = "further analysis";	# This is the phrase that I use when a file need further analysis by Lightspeed
my $opt_list;
my $opt_submit;		#  True if I should always submit the file to virus total
my $opt_check_local;
my $opt_email;
my $opt_notes;
my $opt_key = '14bfa15bda6954587facc46bc6d918f07cb146f206f8ed3cf3f863a7f8210220';



my $dbhProgram;					# Handle to the Program database
my $dbhApplication;				# The handle to the Application database
my $ua;							# The user agent for reuse
my $cache;						# The connection cache for reuse
my $cwd;


			
################################################################################
#
MAIN:
#
################################################################################
{
  
	my $options = Getopt::Long::GetOptions
       (
			"a|local"		=> \$opt_check_local,
			"b|bcopy=s"		=> \$opt_bcopy,
			"c|copy=s"		=> \$opt_copy,
			"d|dir=s"		=> \$opt_dir,
			"e|email=s"		=> \$opt_email,
			"f|file=s"		=> \$opt_file,
			"i|id=s"		=> \$opt_id,
			"k|key=s"		=> \$opt_key,
			"l|list=s"		=> \$opt_list,
			"m|move=s"		=> \$opt_move,
			"n|notes=s"		=> \$opt_notes,
			"o|original=s"	=> \$opt_original_file,
			"p|path=s"		=> \$opt_path,
			"r|root=s"		=> \$check_root,
			"s|submit"		=> \$opt_submit,
			"h|help"		=> \$opt_help,
			"v|verbose"		=> \$opt_verbose,
			"x|xxx"			=> \$opt_debug
      );

	&StdHeader( "CheckFile" );


	# Get the current directory right away
	$cwd = getcwd();
	$cwd =~ s#\/#\\#gm;
	$opt_path = $cwd if ( ! defined $opt_path );

	
	&Usage() if ( $opt_help );

	
	# Figure out the hostname
	$hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );


	my $file = shift;
	$file = $opt_file if ( ! defined $file );

	
	&Usage() if ( ( ! defined $file )  &&  ( ! $opt_list ) );


	if ( ( $opt_path )  &&  ( ! -d $opt_path ) )
		{	lprint "Can not find path $opt_path\n";
			exit( 1 );
		}


	$opt_copy = $opt_bcopy if ( $opt_bcopy );
	
	if ( ( $opt_copy )  &&  ( $opt_move ) )
		{	lprint "You can copy or move, but not both\n";
			exit( 0 + 1 );
		}
		
		
	my $log_type = $opt_move;
	$log_type = $opt_copy if ( $opt_copy );	
	

	# Do I have a key file?
	my $homepath = $ENV{ HOMEDRIVE } . $ENV{ HOMEPATH };
	my $keyfile = $homepath . "\\Checkfile.key";
	lprint "Looking for Virustotal key file $keyfile ...\n";
	
	if ( -f $keyfile )
		{	open( KEYFILE, "<$keyfile" );
			$opt_key = <KEYFILE>;
			chomp( $opt_key );
			close( KEYFILE );
			
		}
	
	lprint "Using Virustotal.com key: $opt_key\n";
		
		
	# Sort out all the log companies
	if ( $log_type )
		{	my @types = split /,/, $log_type;
			foreach ( @types )
				{	my $type = $_;
					next if ( ! $type );
					$type =~ s/^\s+//;
					$type =~ s/\s+$//;
					
					my $company = &CategoryLogCompany( $type );
					
					# If I don't find a matching log copy name then use whatever I was given
					$company = $type if ( ! defined $company );
					
					$log_company .= ", " . $company if ( $log_company );
					$log_company = $company if ( ! $log_company );
					if ( $type eq "*" )
						{	$log_company = "Any AV Company";
							last;
						}
				}
		}

	
	if ( ( $log_type )  &&  ( ! $log_company ) )
		{	lprint "Unable to find the log company name for log type $log_type\n";
			exit( 0 + 2 );	
		}


	lprint "Log company = $log_company\n" if ( $log_company );

	
	if ( ( $log_company )  &&  ( ! defined $opt_dir ) )
		{	lprint "No directory defined to copy or move to\n";
			exit( 0 + 3 );
		}

	if ( ( $log_company )  &&  ( ! -d $opt_dir ) )
		{	lprint "Can not find directory $opt_dir\n";
			exit( 0 + 4 );
		}
		
		
	lprint "Copying files detected by $log_company to directory $opt_dir ...\n" if ( $opt_copy );
	lprint "Copying files without virus subdirectories ...\n" if ( $opt_bcopy );
	lprint "Moving files detected by $log_company to directory $opt_dir ...\n" if ( $opt_move );
	
	
	# Am I running on the Lightspeed local network?  If not, then
	# there is very little I can do
	if ( ! &CheckLocal( $opt_check_local ) )
		{	&VirusTotalOnly( $file );
			exit;
		}


	if ( $opt_email )
		{	my @email_list = split /;/, $opt_email;
			
			foreach ( @email_list )
				{	my $email = $_;
					next if ( ! $email );
					my $clean_email = &CleanEmail( $email );
					
					if ( ! $clean_email )
						{	print "Email address $email is not a valid address\n";
							exit( 0 + 5 );	
						}
					print "Emailing results to $email ...\n";	
				}
				
			print "Notes: $opt_notes\n" if ( $opt_notes );
		}
		
		
	&TrapErrors() if ( ! $opt_debug );
	
	
	# Do I have a list of MD5 values to check?
	if ( $opt_list )
		{	open( LISTFILE, "<$opt_list" ) or die "Error opening $opt_list: $!\n";

			while ( my $line = <LISTFILE> )
				{	chomp( $line );
					next if ( ! $line );
					
					my ( $hex_md5, $junk ) = split /\s/, $line, 2;	
					next if ( ! $hex_md5 );
					
					my $len = length( $hex_md5 );

					next if ( $len != 32 );
					
					my $conclusion_file = ".\\Conclusion.$hex_md5.txt";
	
	
					if ( ! open( CONCLUSIONS, ">$conclusion_file" ) )
						{	lprint "Error opening conclusion file $conclusion_file: $!\n";
							next;
						}
		
					
					# See what virus total thinks - if it isn't a zip file
					my ( $found, $log_company_virus_name, $virus_total_infected ) = &VirusTotalCheck( $hex_md5, undef, undef );
					
					close( CONCLUSIONS );
				}
				
			close( LISTFILE );
			
			exit( 0 );
		}
		
	
	my $log_filename = "$log_directory\\CheckFile-$hostname.log";		# The name of the log file to use
	
	# Delete the log file if it is getting too big
	my $log_size = -s $log_filename;
	unlink( $log_filename ) if ( ( $log_size )  &&  ( $log_size > 1000000 ) );
	
	&SetLogFilename( $log_filename, 1 );


	my %original_file;	# This hash is used to keep track of the original file names
	my %original_file_id;	# This hash is used to keep track of the original file IDs

	my @files = &ExpandFiles( $file, \%original_file );
		
	# Quit here if I didn't find anything
	if ( $#files < 0 )
		{	lprint "No files found that match $file\n";
			exit( 1 );
		}
	
	
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
lprint "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 0 + 6 );
		}
	
	
	# I need to open the Application database
	$dbhApplication = DBI->connect( "DBI:ODBC:ApplicationRemote", "LIGHTSPEED\\Rob", "seeker" );
	$dbhApplication->do( "use IpmContent" ) if ( $dbhApplication );
			
	if ( ! $dbhApplication )
				{
lprint "Unable to open the Remote Application database.
Run ODBCAD32 and add the APPLICATION SQL Server as a System DSN named
\'ApplicationRemote\' with default database \'IpmContent\'.\n";

			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;

			exit( 1 );
		}
				

	# Check each of the files
	foreach ( @files )
		{	my $file = $_;
			next if ( ! defined $file );

			# Ignore log files
			next if ( $file =~ m/\.log$/ );
			
			# Make sure I pass I full file path into CheckFile
			my ( $dir, $short_file ) = &SplitFileName( $file );
			
			my $fullfile = $file;
			
			if ( ! defined $dir )
				{	$fullfile = "$cwd\\$file";
					$fullfile = $cwd . $file if ( $cwd =~ m/\\$/ );
				}
			
			print "File $fullfile\n";
			
			my $original_file = $original_file{ $fullfile };	
			$original_file = $opt_original_file if ( defined $opt_original_file );
			
			
			# Do I have a hex file ID for this original file?
			my $original_file_id = $original_file_id{ $original_file } if ( $original_file );
			
			if ( ( $original_file )  &&  ( ! $original_file_id ) )
				{	my $file_id = &ApplicationFileID( $original_file );
					$original_file_id = &StrToHex( $file_id ) if ( $file_id );
					$original_file_id{ $original_file } = $original_file_id if ( $original_file_id );
					
				}

			# Should I create a CheckFile record for this?
			if ( ( $opt_email )  &&  ( $original_file_id ) )
				{	my $ok = &CreateCheckFileRow( $original_file, $original_file_id, $opt_email, $opt_notes );
					exit( 0 + 6 ) if ( ! $ok );
				}
			elsif ( $opt_email )
				{	my $file_id = &ApplicationFileID( $fullfile );
					my $hex_file_id = &StrToHex( $file_id ) if ( $file_id );
					
					# If I have a file ID then create a checkfile row if I need to email ...
					if ( $hex_file_id )
						{	my $ok = &CreateCheckFileRow( $fullfile, $hex_file_id, $opt_email, $opt_notes );
							exit( 0 + 6 ) if ( ! $ok );
						}
				}
							
			my $ok = &CheckFile( $fullfile, $original_file, $original_file_id );
		}
		

	# Close any databases that I opened
	$dbhApplication->disconnect if ( $dbhApplication );
	$dbhApplication = undef;

	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
	
	exit( 0 );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	
	my $filename = "$log_directory\\CheckFileErrors-$hostname.log";
	
	my $MYLOG;
   
	# If the error log is getting really big then delete it
	my $size = -s $filename;
	unlink( $filename ) if ( ( $size )  &&  ( $size > 1000000 ) );

	if ( ! open( $MYLOG, ">>$filename" ) )
		{	lprint "Unable to open $filename: $!\n";  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
	
 	&lprint( "Error trapping set to file $filename\n" ); 
}



################################################################################
#
sub VirusTotalOnly( $ )
#
#  Given a filespec, that could be wildcarded, just print out the Virus Total
#  info.
#
################################################################################
{	my $file = shift;
	
	return( undef ) if ( ! defined $file );
	
	my %original_file;	# This hash is used to keep track of the original file names

	my @files = &ExpandFiles( $file, \%original_file );
		
	# Quit here if I didn't find anything
	if ( $#files < 0 )
		{	lprint "No files found that match $file\n";
			exit( 1 );
		}


	foreach ( @files )
		{	my $fullfile = $_;
			next if ( ! defined $fullfile );
			next if ( ! -f $fullfile );
			
			my $hex_md5 = &HexMD5File( $fullfile );
	
			if ( ! $hex_md5 )
				{	lprint "Unable to calculate the MD5 hash value of $file\n";
					next;
				}
			
			my $conclusion_file = ".\\Conclusion.$fullfile.txt";

			if ( ! open( CONCLUSIONS, ">$conclusion_file" ) )
				{	lprint "Error opening conclusion file $conclusion_file: $!\n";
					next;
				}

			
			# See what virus total thinks - if it isn't a zip file
			my ( $found, $log_company_virus_name, $virus_total_infected ) = &VirusTotalCheck( $hex_md5, $log_company, undef );
			
			close( CONCLUSIONS );
			
			# If it is a new file, and VirusTotal didn't know it, then submit it to VirusTotal for checking
			# Of it I am supposed to submit everything
			my $submitted = &VirusTotalUpload( $fullfile ) if ( ( ! $found )  ||  ( $opt_submit ) );

			&CheckFileCopyInfected( $opt_dir, $log_company_virus_name, $fullfile, $hex_md5 ) if ( ( $opt_dir )  &&  ( $log_company_virus_name ) );
		}
		
		
	return( 1 );
}



################################################################################
#
sub HexMD5File( $ )
#
#  Given a filespec, that could be wildcarded, return the list of files that exist
#  and match.  Also expand out any zip files
#
################################################################################
{	my $fullfile = shift;

use Digest::MD5;

	open( MD5HANDLE, $fullfile) or return( undef );
	
	binmode( MD5HANDLE );
	
	my $md5_object = Digest::MD5->new;

	$md5_object->new->addfile( *MD5HANDLE );
	
	my $hex_md5 = $md5_object->hexdigest;

	close( MD5HANDLE );	
	
	return( $hex_md5 );
}



################################################################################
#
sub ExpandFiles( $$ )
#
#  Given a filespec, that could be wildcarded, return the list of files that exist
#  and match.  Also expand out any zip files
#
################################################################################
{	my $file				= shift;
	my $original_file_ref	= shift;	# A reference to a hash containing the original file names of expanded out zip files
	
	
	my @files;
	
	return( @files ) if ( ! defined $file );
	
	# Do I have a wildcard specification?
	if ( ( $file =~ /\*/ )  ||  ( $file =~ m/\?/ ) )
		{	@files = &MyGlob( $file );
			
			return( @files ) if ( $#files < 0 );
		}
	else	# There could be a list of files separated by ';'
		{	my @list = split /;/, $file;
			foreach ( @list )
				{	my $list = $_;
					next if ( ! $list );
					next if ( ! -s $list );
					
					push @files, $list;
				}
				
			# Quit here if I didn't find anything
			return( @files ) if ( $#files < 0 );
		}
	
	
	# Expand out any zip files
	my @zip_files;	# This is the list of zip files that I've added
	
	
	foreach ( @files )
		{	my $file = $_;
			next if ( ! defined $file );

			# Ignore log files
			next if ( $file =~ m/\.log$/ );
			
			# Make sure I pass I full file path into CheckFile
			my ( $dir, $short_file ) = &SplitFileName( $file );
			
			my $fullfile = $file;
			
			if ( ! defined $dir )
				{	$fullfile = "$cwd\\$file";
					$fullfile = $cwd . $file if ( $cwd =~ m/\\$/ );
					$dir = $cwd;
				}
			
			# is it a zip file?
			next if ( ! &IsZip( $fullfile ) );
			
			lprint "Expanding zip file $fullfile ...\n" if ( $opt_verbose );
		
			my ( $err_msg, @new_zip_short ) = &ScanUnzipContents( $dir, $short_file, undef );
			
			
			# Now add the full paths of the newly unzipped files
			foreach ( @new_zip_short )
				{	my $short = $_;
					next if ( ! defined $short );
					my $new_file = $dir . "\\" . $short;
					push @zip_files, $new_file;
					
					# Keep track of where this new file came from
					$$original_file_ref{ $new_file } = $file;
				}
		}


	# Add the newly expanded out zip files to the list of files to check		
	push @files, @zip_files;

		
	return( @files );
}



################################################################################
#
sub CheckLocal( $ )
#
#  Check to see if I am running on the Lightspeed local network.  Return True if
#  I am, undef if not.
#
################################################################################
{	my $check_local = shift;
	
	if ( $check_local )
		{	$check_root = undef;
			print "Not using Lightspeed databases\n";
			return( undef );
		}

	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{	print "No access to Lightspeed Program database\n";
			print "Not running on the Lightspeed local network\n";
			$check_root = undef;
			return( undef );
		}

	if ( ! -d $check_root )
		{	# Does the fs06 share exist?
			print "Checking Lightspeed shared drive Q: access ...\n";
			if ( ! -d "\\\\fs06\\Drive-Q" )
				{	print "Not running on the Lightspeed local network\n";
					$check_root = undef;
					return( undef );
				}
				
			# Map drive Q: if it isn't already mapped
			print "Mapping drive Q: to \\\\fs06\\Drive-Q ...\n";
			system "net use Q: \\\\fs06\\Drive-Q /USER:LIGHTSPEED\\Rob seeker";
		}
		
	if ( ! -d $check_root )
		{	print "Unable to find the virus check results directory $check_root\n";
			return( undef );
		}
			
	if ( ! -d $log_directory )
		{	print "Unable to find the virus log directory $log_directory\n";
			return( undef );
		}

	print "Testing connection to UNC $platoon_leader_unc ...\n";
	if ( ! -d $platoon_leader_unc )
		{	print "Unable to connect to the Army Platoon leader UNC: $platoon_leader_unc\n";
			return( undef );
		}

	return( 1 );
}



################################################################################
#
sub CheckFile( $$$ )
#
#  Check a file's version info
#
################################################################################
{	my $file				= shift;
	my $original_file		= shift;	# If defined then this is the original file name before it was expanded (like in a zip)
	my $original_file_id	= shift;	# If defined this is the hex file ID of the original file


	return( undef ) if ( ! $file );
	return( undef ) if ( ! -f $file );

	# Don't worry about 0 length files
	my $file_size = -s $file;	
	return( undef ) if ( ! $file_size );


	my ( $dir, $short_file ) = &SplitFileName( $file );
	
	
	# Get all the file info that I can
	my %file_info;
	my @sections;
	my $ok = &FileInfo( $file, \%file_info, \@sections, $opt_verbose );	


	# Is this the type of file that I can calculate a file ID for?
	my $scan_fileid_type = $file_info{ FileIDType };
	
	lprint "Checking File: $file ...\n";
			
	if ( $opt_verbose )
		{	my $scanable_desc = $file_info{ ScanableDescription };
			lprint "Scan Type: $scanable_desc\n";
		}
		
		
	my $file_id = $file_info{ FileID };
	
	# If no file id, bag it
	if ( ! $file_id )
		{	lprint "$file does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}
		
		
	my $hex_file_id = $file_info{ HexFileID };		
	
	
	my $hex_md5 = $file_info{ HexMD5 };
	
	if ( ! $hex_md5 )
		{	lprint "Unable to calculate the MD5 hash value of $file\n";
			return( undef );
		}
	
	
	# Do I have a results directory to store in?
	return( undef ) if ( ! defined $check_root );
	my $virus_results_dir = &VirusResultsDir( $check_root, $hex_md5 );
	return( undef ) if ( ! defined $virus_results_dir );
	
	# Make sure the directory exists
	$ok = &MakeDirectory( $virus_results_dir );
	
	my $conclusion_file = $virus_results_dir . "\\$hex_md5.txt";
	
	
	if ( ! open( CONCLUSIONS, ">$conclusion_file" ) )
		{	lprint "Error opening conclusion file $conclusion_file: $!\n";
			return( undef );
		}
		
		
	print CONCLUSIONS "File ID|$hex_file_id\n";
	print CONCLUSIONS "File MD5|$hex_md5\n";
	print CONCLUSIONS "Original File Name|$file\n";
	

	if ( $opt_verbose )	
		{	lprint "File ID: $hex_file_id\n";
			lprint "File MD5: $hex_md5\n";
			lprint "Original file name: $file\n";
		}


	my $hex_crc32 = &HexCRC32File( $file );

		
	# Build up in the data string all the section info
	my $count = 0 + 1;
	foreach( @sections )
		{	my $section_data = $_;
			next if ( ! defined $section_data );
			
			my ( $name, $offset, $f_size, $v_addr, $characteristics, $hex_md5 ) = split /\t/, $section_data;
			next if ( ! defined $name );
			next if ( ! defined $offset );
			next if ( ! defined $f_size );
			next if ( ! defined $v_addr );
			next if ( ! defined $characteristics );
			next if ( ! defined $hex_md5 );

			my $hoffset = sprintf( "%08x", $offset );
			my $hf_size = sprintf( "%08x", $f_size );
			my $hv_addr = sprintf( "%08x", $v_addr );
			
			print CONCLUSIONS "Section $count|$name|Offset|$hoffset|Physical Size|$hf_size|VirtAddr|$hv_addr|MD5 Hash|$hex_md5\n";	
			
			$count++;
		}
		

	# Do I have this file in the NotVirus table on Application?
	# If so then it is definitely NOT a virus
	my $str = "SELECT [Filename] FROM NotVirus WITH(NOLOCK) WHERE FileID = '$hex_file_id'";
			
	my $sth = $dbhApplication->prepare( $str );
	$sth->execute();
	
	my ( $notvirus_filename ) = $sth->fetchrow_array();
	
	$sth->finish();
	
	
	# This is the string to hold the final conclusion in
	my $conclusion;
	
	
	# Figure out the application type and the initial conclusion
	if ( &IsZip( $file ) )
		{	print CONCLUSIONS "Application Type|This is a Zip archive - the contents are analyzed by Lightspeed separately\n";
			lprint "This file is a Zip archive - the contents are analyzed by Lightspeed separately\n";
			
			$conclusion = "This file is a Zip archive - the contents are analyzed by Lightspeed separately";
		}
	elsif ( defined $notvirus_filename )
		{	print CONCLUSIONS "Application Type|This file IS a common application: $notvirus_filename\n";
			lprint "This file IS a common application: $notvirus_filename\n";
			
			print CONCLUSIONS "Application Type|This file NOT a virus!\n";
			lprint "This file NOT a virus!\n";
			
			$conclusion = "Lightspeed is convinced that this file is NOT a virus";
		}
	else
		{	print CONCLUSIONS "Application Type|This file is NOT a common application\n";
			lprint "This file is NOT a common application\n";
			
			$conclusion = "This file is NOT a common application";
		}
	
	
	# Do I have this file in the ApplicationProcesses table on Application?
	$str = "SELECT AppName, Process, CategoryNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE FileID = '$hex_file_id'";
			
	$sth = $dbhApplication->prepare( $str );
	$sth->execute();
	
	my ( $app_name_application, $process, $category_number ) = $sth->fetchrow_array();
	
	$sth->finish();
	
	
	# Did I find anything on Application that tells me what this is?
	if ( ( defined $app_name_application )  &&  ( defined $process )  &&  ( defined $category_number ) )
		{	if ( $category_number == 62 )
				{	print CONCLUSIONS "Application Type|Spyware - $app_name_application\n";
					$conclusion = "Lightspeed detects this file as a virus called $app_name_application";
				}
			elsif ( $category_number == 63 )
				{	print CONCLUSIONS "Application Type|Virus - $app_name_application\n";
					$conclusion = "Lightspeed detects this file as a virus called $app_name_application";
				}
			elsif ( $category_number == 6 )
				{	print CONCLUSIONS "Application Type|Business - $app_name_application\n";
					$conclusion = "This is a common application named $app_name_application and is NOT a virus";
				}
			elsif ( $category_number == 118 )
				{	print CONCLUSIONS "Application Type|NetTool - $app_name_application\n";
					$conclusion = "This is a net tool named $app_name_application and is NOT a virus";
				}
			else 
				{	print CONCLUSIONS "Application Type|Other Application - $app_name_application\n";
					$conclusion = "This is a application named $app_name_application and is NOT a virus";
				}
		}

		
	# Do I have this file in the program table?
	$sth = $dbhProgram->prepare( "SELECT AppName, Filename, FileVersion, FileSize, Description, Company FROM Programs WITH(NOLOCK) WHERE FileID = \'$hex_file_id\'" );
			
	$sth->execute();

	
	my ( $papp_name, $archive_filename ) = $sth->fetchrow_array();
	

	# If it isn't in the Programs database and the NotVirus table, then I have never seen it before
	my $new_file = 1;	# Keep track if it is a new file
	if ( ! defined $papp_name )
		{	print CONCLUSIONS "Application History|This file is not in the Lightspeed Program Archive\n";
			lprint "This file is not in the Lightspeed Program Archive\n" if ( $opt_verbose );
			
			if ( ( $scan_fileid_type )  &&  ( $scan_fileid_type == 1 ) )
				{	&AddProgramArchive( \%file_info, \@sections );
				}
		}
	else	
		{	$new_file = undef;	# It is not a new file
			
			my $app_name		= $file_info{ AppName };
			my $file_version	= $file_info{ FileVersion };
			my $desc			= $file_info{ Description };
			my $company			= $file_info{ Company };
			
			
			print CONCLUSIONS "Archive Filename|$archive_filename\n"	if ( defined $archive_filename );
			print CONCLUSIONS "Application Name|$app_name\n"			if ( defined $app_name );
			print CONCLUSIONS "File Version|$file_version\n"			if ( defined $file_version );
			print CONCLUSIONS "File Size|$file_size\n"					if ( defined $file_size );
			print CONCLUSIONS "Description|$desc\n"						if ( defined $desc );
			print CONCLUSIONS "Company|$company\n"						if ( defined $company );

			if ( $opt_verbose )
				{	lprint "Archive filename: $archive_filename\n"		if ( defined $archive_filename );
					lprint "Application name: $app_name\n"				if ( defined $app_name );
					lprint "File version: $file_version\n"				if ( defined $file_version );
					lprint "File size: $file_size\n"					if ( defined $file_size );
					lprint "Description:$desc\n"						if ( defined $desc );
					lprint "Company: $company\n"						if ( defined $company );
				}
		}
 
	$sth->finish();
	
	
	# Does this file ID already exist in the FileIDVirus table in the Program database?
	$sth = $dbhProgram->prepare( "SELECT VirusName, Company FROM FileIDVirus WITH(NOLOCK) WHERE FileID = \'$hex_file_id\' ORDER BY Company" );
			
	$sth->execute();

	
	$count = 0 + 0;
	while ( my ( $virus_name, $company ) = $sth->fetchrow_array() )
		{	next if ( ! defined $company );
						
			print CONCLUSIONS "Detected|$company:$virus_name\n";
			lprint "Detected: $company: $virus_name\n";
			
			# Does Lightspeed think this is a virus?
			$conclusion = "Lightspeed detects this file as a virus called $virus_name" if ( $company =~ m/lightspeed/i );
		}
 
	$sth->finish();
	

	# Find any program links where I might have downloaded it
	$sth = $dbhProgram->prepare( "SELECT Website, ProgURL, TransactionTime FROM ProgramLink WITH(NOLOCK) WHERE FileID = \'$hex_file_id\' ORDER BY Website" );
			
	$sth->execute();


	my $url_count = 0 + 0;
	while ( my ( $website, $prog_url, $transaction_time ) = $sth->fetchrow_array() )
		{	next if ( ! $prog_url );
			print CONCLUSIONS "Website|$website|URL|$prog_url|Time|$transaction_time\n";
			lprint "Website: $website: URL: $prog_url: Time: $transaction_time\n" if ( $opt_verbose );
		}
		
	$sth->finish();
	
	
	# See what virus total thinks - if it isn't a zip file
	my ( $found, $log_company_virus_name, $virus_total_infected ) = &VirusTotalCheck( $hex_md5, $log_company, $hex_file_id ) if ( ! &IsZip( $file ) );
	
	
	# If one of the VirusTotal virus scanner thinks that the file is a virus, and Lightspeed doesn't, and
	# Lightspeed doesn't have this file in the NotVirus table, 
	# and it isn't a zip file (because zip files are not normally in the FileIDVirus table)
	# then it needs further checking
	if ( ( $virus_total_infected )  &&  
		( ! ( $conclusion =~ m/lightspeed detect/i ) )   &&
		( ! ( $conclusion =~ /is NOT a virus/i ) )  &&  
		( ! &IsZip( $file ) ) )
		{	$conclusion = "This file needs $further_analysis by Lightspeed";
		}
		
		
	# If it is a new file, and VirusTotal didn't know it, then submit it to VirusTotal for checking
	my $submitted = &VirusTotalUpload( $file ) if ( ( $opt_submit )  ||  ( ( $new_file )  &&  ( ! $found ) ) );
	
	
	# Now copy the file into the check directory so that I have it in case I need to rerun the check
	my @parts = split /\./, $short_file;
	my $ext = $parts[ $#parts ];
	
	# Is the extension a crazy value?
	$ext = undef if ( ( $ext )  &&  ( length( $ext ) > 5 ) );
	
	my $dest_short_file = $hex_md5 . '.' . $ext if ( defined $ext );
	$dest_short_file = $hex_md5 if ( ! defined $ext );
	
	# Tack on a underline if there isn't already one there
	$dest_short_file .= '_' if ( ! ( $dest_short_file =~ m/_$/ ) );

	my $destination_file = $virus_results_dir . "\\" . $dest_short_file if ( $check_root );	
	
	
	# Is the destination file already there?  If not then copy it there
	if ( ! defined $check_root )
		{	lprint "No virus results directory\n" if ( $opt_verbose );
		}
	elsif ( -f $destination_file )
		{	lprint "$destination_file already exists so not copying over\n" if ( $opt_verbose );
		}
	else
		{	lprint "Copying $file to $destination_file ...\n";
			
			$ok = copy( $file, $destination_file );
			if ( ! $ok )
				{	lprint "Error copying $file to $destination_file: $!\n";
					close( CONCLUSIONS );

					return( undef );
				}
		}
	
	
	# Did I store a copy of the file?
	if ( $check_root )		
		{	lprint "File temporarily stored at $destination_file\n" if ( ( -f $destination_file )  &&  ( $opt_verbose ) );
			print CONCLUSIONS "File Temporarily Stored|$destination_file\n";
		}
		
		
	print CONCLUSIONS "Final Conclusion|$conclusion\n";
	
	close( CONCLUSIONS );
	
	
	&CheckFileCopyInfected( $opt_dir, $log_company_virus_name, $file, $hex_md5 ) if ( ( $opt_dir )  &&  ( $log_company_virus_name ) );
			
	
	# Save the conclusion into the Program database if this file is there
	&CheckFileConclusion( $original_file, $original_file_id, $file, $hex_file_id, $hex_md5, $conclusion );
	
	lprint "CheckFile final conclusion: $conclusion\n";
	
	return( 1 );
}



################################################################################
# 
sub CheckFileCopyInfected( $$$$ )
#
#  Given the directory, the virus name, and the source file, copy or move the file
#
################################################################################
{	my $opt_dir					= shift;
	my $log_company_virus_name	= shift;
	my $file					= shift;
	my $hex_md5					= shift;
	
	my $virus = &CleanVirusName( $log_company_virus_name );	
			
	if ( ! defined $virus )
		{	lprint "Error making a clean virus name out of $log_company_virus_name\n";
			exit( 1 );
		}
		
	my $virus_dir = &VirusTypeDir( $virus );
	
	# What directory should I copy it to?			
	my $dest_dir = $opt_dir . "\\$virus";
	$dest_dir = $opt_dir . "\\$virus_dir" . "\\$virus" if ( $virus_dir ); 
	$dest_dir = $opt_dir if ( $opt_bcopy );

	my $ok = &MakeDirectory( $dest_dir );
	if ( ! $ok )
		{	lprint "Error making directory $dest_dir: $!\n";
			exit( 0 + 8 );
		}
	
	my ( $dir, $short_file ) = &SplitFileName( $file );

	my @parts = split /\./, $short_file;
	my $ext = $parts[ $#parts ];
	
	my $dest_short_file = $hex_md5 . '.' . $ext if ( defined $ext );
	$dest_short_file = $hex_md5 if ( ! defined $ext );
	
	# Tack on a underline if there isn't already one there
	$dest_short_file .= '_' if ( ! ( $dest_short_file =~ m/_$/ ) );
	
	# Figure out the final destination
	my $dest = $dest_dir . "\\" . $dest_short_file;
	

	# Make sure that I'm not copying to myself and it the file doesn't already exist
	if ( ( lc( $file ) ne lc( $dest ) )  &&  ( ! -f $dest ) )
		{	lprint "Copying file $file to $dest ...\n";
			
			$ok = copy( $file, $dest );
			
			# Copy errors are a real problem!
			if ( ! $ok )
				{	my $err = $^E;
					lprint "Error copying $file to $dest: $err\n";
					exit( 0 + 9 );
				}
		}
	elsif ( -s $dest )
		{	lprint "$dest already exists so not copying over\n";
		}
		

	# Am I actually moving the file?  If moving it then I need to delete the original
	unlink( $file ) if ( ( $ok )  &&  ( $opt_move )  &&  ( -s $dest ) );

	# Make sure the program database program table has this entry
	&ProgramTable( $dest, $hex_md5, $virus ) if ( -s $dest );
	
	return( $ok );
}



################################################################################
#
sub ProgramTable( $$$ )
#
#  Insert or update the data into the Program table in the Program database
#  Return True if everything is OK, undef if not
#
################################################################################
{	my $vfile	= shift;
	my $virus	= shift;

	# Make sure that I can talk to the Program database
	return( undef ) if ( ! defined $dbhProgram );

	return( undef ) if ( ! $vfile );
	return( undef ) if ( ! $virus );

	my $file_size = -s $vfile;	
	return( undef ) if ( ! $file_size );
	
	
	my ( $dir, $short_file ) = &SplitFileName( $vfile );
	$dir = lc( $dir );
	

	# Get all the file info that I can
	my %file_info;
	my @sections;
	my $ok = &FileInfo( $vfile, \%file_info, \@sections, $opt_verbose );	
	return( undef ) if ( ! $ok );
	

	my $type = &VirusTypeName( $virus );
	
	
	# Set the virus info into the file info hash
	$file_info{ VirusType } = $type;
	$file_info{ Virus }		= $virus;
	$file_info{ AppName }	= $virus;


	my $file_id = $file_info{ FileID };
	
	# If no file id, bag it
	if ( ! $file_id )
		{	print "$vfile does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}
		
	my $hex_file_id = $file_info{ HexFileID };		
	
	
	if ( $opt_verbose )
		{	print "File: $vfile\n";		
			print "File ID: $hex_file_id\n";
		}
		
		
	# If not a Win32/Win64 file then don't add it to the database	
	my $scan_fileid_type = $file_info{ ScanableFileID };
	if ( ( ! $scan_fileid_type )  ||  ( $scan_fileid_type != 1 ) )
		{	print "$vfile is not a Win32/Win64 PE file so not adding it to the Lightspeed Program database\n" if ( $opt_verbose );
			return( undef );
		}
	
	
	# Does this file ID already exist in the Programs table in the Program database?
	# And does it have a virus style filename?
	my $sth;
	$sth = $dbhProgram->prepare( "SELECT Filename FROM Programs WITH(NOLOCK) WHERE FileID = ?" );
			
	$sth->bind_param( 1, $hex_file_id,  DBI::SQL_VARCHAR );
	$sth->execute();
	my $rows = 0 + $sth->rows;
	my $db_filename = $sth->fetchrow_array();

	$sth->finish();
	
	
	# Should I overwrite the current data in the Program database?
	# If it already exists, and the filename hasn't changed, quit here
	return( 1 ) if ( ( $db_filename )  &&  ( lc( $db_filename ) eq lc( $vfile ) ) );
	
	my $old_archive = 1 if ( ( $db_filename )  &&  ( $db_filename =~ m/^q\:\\virus archive\\/i ) );
	my $new_archive = 1 if ( $vfile =~ m/^q\:\\virus archive\\/i );
	
	# If the old name is in the virus archive, and the new one isn't, return here
	return( 1 ) if ( ( $old_archive )  &&  ( ! $new_archive ) );
	
	
	my $hex_md5 = $file_info{ HexMD5 };
	$hex_md5 = "" if ( ! defined $hex_md5 );
	
	my $hex_crc32 = $file_info{ HexCRC32 };
	$hex_crc32 = "" if ( ! defined $hex_crc32 );


	my $source_id = 1;
	my $id = 0 + 0;	
	
	my $time_date	= $file_info{ TimeDate };
	$time_date = "" if ( ! defined $time_date );
	my $image_size	= $file_info{ ImageSize };
	$image_size = "" if ( ! defined $image_size );
	my $entry_point	= $file_info{ EntryPoint };
	$entry_point = "" if ( ! defined $entry_point );
	my $code_size	= $file_info{ CodeSize };
	$code_size = "" if ( ! defined $code_size );
	
	
	my $file_version	= $file_info{ FileVersion };
	my $desc			= $file_info{ Description };
	my $company			= $file_info{ Company };
	
	
	# Show I show the info?
	if ( $opt_verbose )
		{	print "AppName: $virus\n";			
			print "File Version: $file_version\n";
			print "File Size; $file_size\n";
			print "MD5: $hex_md5\n";		
			print "CRC32: $hex_crc32\n";		
			print "Description: $desc\n";
			print "Company: $company\n";
			print "Source ID: $source_id\n";
			print "Time Date: $time_date\n";
			print "Image Size: $image_size\n";
			print "Entry Point: $entry_point\n";
			print "Code Size: $code_size\n";
		}
		

	my $ret = &CategoryUpdateFileInfo( \%file_info, \@sections, $rows );
	return( undef ) if ( ! defined $ret );
		
	
	# If the old archive filename is different than the new one, then delete the old one
	if ( ( $old_archive )  &&  
		( $new_archive )  &&  
		( lc( $db_filename ) ne lc( $vfile ) ) )
		{	print "Deleting old archive file $db_filename ...\n";
			print "Replacing with new archive file $vfile ...\n";
			unlink( $db_filename );
		}
		
	
	return( 1 );
}



################################################################################
# 
sub CreateCheckFileRow( $$ $$ )
#
#  Create a row in the CheckFile table if one doesn't already exist
#  database.
#
################################################################################
{	my $original_file		= shift;	# The original file name
	my $original_file_id	= shift;	# This original hex file ID
	my $email				= shift;
	my $notes				= shift;
		
		
	# Make sure that I've got everything I need	
	return( undef ) if ( ! defined $original_file );
	return( undef ) if ( ! defined $original_file_id );
	return( undef ) if ( ! defined $email );
	
		
	my $qoriginal_file = $original_file;
	$qoriginal_file =~ s/'/''/g;
	
	
	# Is there already an ID in the CheckFile table for this file using the original file name?
	my $sth = $dbhProgram->prepare( "SELECT ID, Notes FROM CheckFile WITH(NOLOCK) WHERE TempFile = \'$qoriginal_file\'" );
			
	$sth->execute();

	my $found;
	my $database_notes;
	while ( my ( $id, $database_notes ) = $sth->fetchrow_array() )
		{	next if ( ! $id );
			$found = 1;
		}
	
	$sth->finish();
	
	
	my $qemail = $email;
	$qemail =~ s/'/''/g;
	
	
	# Add the notes together if they are different
	my $qnotes = $notes;
	$qnotes = '' if ( ! defined $qnotes );
	$qnotes .= $database_notes if ( ( $database_notes )  &&  ( $database_notes ne $qnotes ) );
	
	$qnotes =~ s/'/''/g;
	
	
	# If I found one then I can just make sure the email address is right
	if ( $found )
		{	&lprint( "A row already exists in the CheckFile table for $original_file ...\n" );

			$sth = $dbhProgram->prepare( "UPDATE CheckFile SET EmailFrom = '$qemail', Notes = '$qnotes' WHERE TempFile = \'$qoriginal_file\'" );
			
			$sth->execute();
			
			$sth->finish();

			return( 1 );	
		}
	
	

	# Insert the new row 
	my $str = "INSERT INTO CheckFile ( TempFile, FileID, EmailFrom, Notes ) VALUES ( '$qoriginal_file', '$original_file_id', '$qemail', '$qnotes' )";

	$sth = $dbhProgram->prepare( $str );
			
	$sth->execute();
	
	$sth->finish();

	&lprint( "Added a row in the CheckFile table for $original_file ...\n" );
	
	return( 1 );	
}



################################################################################
# 
sub CheckFileConclusion( $$ $$$$ )
#
#  Given the temp filename, save the CheckFile conclusion into the Program
#  database.
#
################################################################################
{	my $original_file		= shift;	# This is used to find the IDs in the CheckFile table
	my $original_file_id	= shift;	# This is used to find the IDs in the CheckFile table
	
	my $file				= shift;
	my $hex_file_id			= shift;
	my $hex_md5				= shift;
	my $conclusion			= shift;
		
		
	# Make sure that I've got everything I need	
	return( undef ) if ( ! defined $file );
	return( undef ) if ( ! defined $hex_file_id );
	return( undef ) if ( ! defined $hex_md5 );
	return( undef ) if ( ! defined $conclusion );
	
	
	# If there was an original file name then use that to look up in the table
	$original_file = $file if ( ! defined $original_file );
	
	my $qoriginal_file = $original_file;
	$qoriginal_file =~ s/'/''/g;
	
	
	# Is there an ID in the CheckFile table for this file using the original file name?
	my $sth = $dbhProgram->prepare( "SELECT ID, Conclusion FROM CheckFile WITH(NOLOCK) WHERE TempFile = \'$qoriginal_file\'" );
			
	$sth->execute();

	my %id;						# This is a hash containing the original IDs
	my %original_conclusion;	# This is a hash containing the original conclusions
	
	while ( my ( $id, $original_conclusion ) = $sth->fetchrow_array() )
		{	next if ( ! $id );
			$id{ $id } = 0 + 1;
			$original_conclusion{ $id } = $original_conclusion;
		}
	
	$sth->finish();


	# Is there an ID in the CheckFile table for this file using the original file ID?
	$original_file_id = $hex_file_id if ( ( ! defined $original_file_id )  ||  ( length( $original_file_id ) != 56 ) );
	$sth = $dbhProgram->prepare( "SELECT ID, Conclusion FROM CheckFile WITH(NOLOCK) WHERE FileID = \'$original_file_id\'" );
			
	$sth->execute();

	while ( my ( $id, $original_conclusion ) = $sth->fetchrow_array() )
		{	next if ( ! $id );
			$id{ $id } = 0 + 1;
			$original_conclusion{ $id } = $original_conclusion;
		}
	
	$sth->finish();


	# Now see if I have any entries in the CheckFileResults table for this hex_file_id
	$sth = $dbhProgram->prepare( "SELECT ID FROM CheckFileResults WITH(NOLOCK) WHERE FileID = \'$hex_file_id\'" );
			
	$sth->execute();

	while ( my $results_id = $sth->fetchrow_array() )
		{	next if ( ! $results_id );
			
			$id{ $results_id } = 0 + 0;	# Set the value to 0 so that I know to update this row, not add a new row
		}
	
	$sth->finish();
	
	
	# If I don't have any IDs then I don't need to do anything more
	my @id = keys %id;
	return( undef ) if ( ! $#id < 0 );
	
	
	
	# If I don't already have an ID in the CheckFileResults table then I need to add one for each ID in the hash
	my %change_id;	# This is a hash keeping track if a particular ID conclusion has changed
	while ( my ( $id, $add ) = each( %id ) )
		{	if ( $add )	# I need to add a new row to the CheckFileResults table
				{	$sth = $dbhProgram->prepare( "INSERT INTO CheckFileResults
					( ID, [Filename], FileID, MD5, Conclusion )
					VALUES
					( '$id', '$file', '$hex_file_id', '$hex_md5', '$conclusion' )" );
					
					$sth->execute();

					$sth->finish();
					
					# Mark that this is a change
					$change_id{ $id } = 1;
				}
			else	# I just need to update the CheckFileResults table
				{	# Get what the conclusion is currently set to
					$sth = $dbhProgram->prepare( "SELECT Conclusion FROM CheckFileResults WITH(NOLOCK) WHERE [ID] = \'$id\' AND FileID = \'$hex_file_id\'" );
					$sth->execute();
					
					my $old_conclusion = $sth->fetchrow_array();
					
					$sth->finish();
					
					# Did the conclusion change?
					next if ( ( $old_conclusion )  &&  ( $conclusion )  &&  ( lc( $conclusion ) eq lc( $old_conclusion ) )  &&  ( ! $opt_email ) );
					
					# Mark that this is a change
					$change_id{ $id } = 1;
					
					my $qfile = $file;
					$qfile =~ s/'/''/g;

					$sth = $dbhProgram->prepare( "UPDATE CheckFileResults
					SET [Filename] = '$qfile',
					MD5 = '$hex_md5',
					Conclusion = '$conclusion',
					TransactionTime = getdate()
					WHERE [ID] = \'$id\' AND FileID = \'$hex_file_id\'" );
					
					$sth->execute();

					$sth->finish();
				}
		}
	
	
	# Now update the AnalyzeTime and conclusion in the CheckFile table for each ID if this is a change
	# First get all the conclusions together
	while ( my ( $id, $add ) = each( %id ) )
		{	# Ignore IDs where there is no change
			next if ( ! $change_id{ $id } );
			
			$sth = $dbhProgram->prepare( "SELECT Conclusion, [Filename] FROM CheckFileResults WITH(NOLOCK) WHERE ID = \'$id\'" );
			
			$sth->execute();

			# Build the complete conclusion
			my @conclusions;
			my $con_str;
			while ( my ( $conclusion, $filename ) = $sth->fetchrow_array() )
				{	next if ( ! $conclusion );
					push @conclusions, $conclusion;
					my ( $dir, $shortfile ) = &SplitFileName( $filename );
					
					my $str = "File: $shortfile - $conclusion" . ".";
					
					$con_str .= "  " . $str if ( defined $con_str );
					$con_str = $str if ( ! defined $con_str );
				}
			
			$sth->finish();
			
			next if ( ! defined $con_str );
			my $sub = substr( $con_str, 0, 1024 );
			$con_str = $sub;
			
			# Did this complete conclusion change?
			my $original_conclusion = $original_conclusion{ $id };
			
			# If no change and I am not emailing then don't update the analyze time
			next if ( ( $original_conclusion )  &&  ( lc( $con_str ) eq lc( $original_conclusion ) )  &&  ( ! $opt_email ) );
			
			# Now update the CheckFile table with the complete conclusion
			$sth = $dbhProgram->prepare( "UPDATE CheckFile SET Conclusion = '$con_str', AnalyzeTime = getdate() WHERE [ID] = \'$id\'" );
					
			$sth->execute();
			
			$sth->finish();
		}
		
	return( 1 );	
}



################################################################################
# 
sub ConnectRemoteApplication()
#
#  Find and connect to the remote Content database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;
	
	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\ApplicationRemote", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	RegCloseKey( $key );
	
	my $dbhRemote = DBI->connect( "DBI:ODBC:ApplicationRemote", "IpmContent" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhRemote )
		{	sleep( 10 );
			$dbhRemote = DBI->connect( "DBI:ODBC:ApplicationRemote", "IpmContent" );
		}
			
	return( $dbhRemote );
}



################################################################################
# 
sub VirusTotalCheck( $$$ )
#
#  Given an MD5 hash value, check with VirusTotal to see if they think it is a virus.
#  If given a log company name, also return the virus name of that log company
#
################################################################################
{   my $hex_md5		= shift;
	my $log_company = shift;	# If this is set, return the virus name that this log company thinks it is
	my $hex_file_id = shift;	# This is the file ID that matches the MD5 hash - may be undefined
	
	return( undef, undef, undef ) if ( ! defined $hex_md5 );
	
use HTTP::Request;
use LWP::UserAgent;
		
	lprint "VirusTotal.com results for MD5 hash $hex_md5 ...\n";
	
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}

	$| = 1;

	if ( ! $ua )
		{	$ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 1000000 );
			$ua->timeout( 60 );  #  Wait for a 60 seconds

			$ua->conn_cache( $cache );
		}

	my $url = "https://www.virustotal.com/api/get_file_report.json";
		
	
	my $response = $ua->post(
		$url,
		[	'resource'		=> $hex_md5,
			'key'			=> $opt_key
		],
	'Content_Type' => 'form-data' );
	
	
	my $ok = $response->is_success();
	my $status = $response->status_line;
	my $content = $response->content;


	if ( ( ! $ok )  &&  ( ! ( $status =~ m/^303/ ) ) )
		{	lprint "Error: $status\n";

			return( undef, undef, undef );
		}
		
		
	# Did VirusTotal find anything?
	if ( $content =~ m/\{\"result\"\: 0\}/i )
		{	print CONCLUSIONS "VirusTotal Results|No results for MD5 hash $hex_md5\n";
			lprint "VirusTotal has no results for MD5 hash $hex_md5\n";
			
			return( undef, undef, undef );
		}


	my @results;
	my ( $av_count, $av_detected ) = &VirusTotalParse( $content, \@results );


	# Set this to True if VirusTotal thinks this is a virus
	my $found;
	my $virus_total_infected;

	my $log_company_virus_name;
	my $log_company_detected;
	foreach ( @results )
		{	my $result = $_;
			next if ( ! defined $result );
			
			my ( $av_package, $virus ) = split /\t/, $result;
			next if ( ! defined $av_package );
			next if ( ! defined $virus );

			if ( $virus ne '-' )
				{	print CONCLUSIONS "VirusTotal AV Package|$av_package|Detected|$virus\n";
					lprint "VirusTotal AV Package:$av_package:Detected:$virus\n";
					
					$virus_total_infected = 1;
					
					# Am I looking for a match for the log company so that I can return the virus name?
					# And i haven't already matched it?
					if ( ( $log_company )  &&  ( ! $log_company_virus_name ) )
						{	
							my ( $first_name, $stuff ) = split /\s/, $log_company, 2;
							
							my $qfirst_name = quotemeta( $first_name );
							
							# Did I match the first name of the virus company I am looking for?
							if ( $av_package =~ m/^$qfirst_name/i )
								{	$log_company_virus_name = $virus;
									$log_company_detected = $av_package;
								}
							# Or am I looking for any AV company at all?	
							elsif ( $log_company =~ m/^any/i )
								{	$log_company_virus_name = $virus;
									$log_company_detected = $av_package;
								}
						}
																
					# Is this one of the AV companies that we keep track of?
					my $av_log_company = &CategoryLogCompany( $av_package );

					# Add this into the FileIDVirus table - if I can
					my $type = &VirusTypeName( $virus );

					&UpdateFileIDVirus( $hex_file_id, $av_log_company, $virus, $type ) if ( ( $av_log_company )  &&  ( defined $hex_file_id )  &&  ( $dbhProgram ) );
				}
			else	
				{	print CONCLUSIONS "VirusTotal AV Package|$av_package|Not Detected\n";
					lprint "VirusTotal AV Package:$av_package:Not Detected\n";
				}
				
			$found = 1;
		}

	print CONCLUSIONS "VirusTotal Detected Rate|$av_detected / $av_count\n";
	lprint "VirusTotal Detected Rate: $av_detected / $av_count\n";


	# Did I find a match for copying or moving?
	if ( $log_company )
		{	lprint "Detected by log company $log_company_detected as $log_company_virus_name\n" if ( defined $log_company_virus_name );
			lprint "NOT detected by log company $log_company\n" if ( ! defined $log_company_virus_name );
		}
			
	return( $found, $log_company_virus_name, $virus_total_infected );
}



################################################################################
# 
sub VirusTotalParse( $$ )
#
#  Given some HTML content, and a reference to an array to return the results, 
#  parse the content to figure out how many AV packages detect this file as a virus
#
################################################################################
{   my $content = shift;
	my $results_ref = shift;
	
	my @lines = split /\,/, $content;
	
	my $table_start;
	my $permalink;
	
	my $av_count	= 0 + 0;
	my $av_detected = 0 + 0;
	
	foreach ( @lines )
		{	my $line = $_;
			next if ( ! $line );

			if ( ! $table_start )
				{	$table_start = 1 if ( $line =~ m/\"report\"/i );
				}
			elsif ( $line =~ m/\"permalink\"/i )
				{	my $junk;
					( $junk, $permalink ) = split /\:/, $line, 2;
					$permalink =~ s/^\s+\"// if ( $permalink );
					$permalink =~ s/\s+$// if ( $permalink );
					$permalink =~ s/\"+$// if ( $permalink );
				}
			else
				{	last if ( $line =~ m/\"result\"/ );
					
					# Have I reached all the data for this row?
					if ( $line =~ m/\"(.+)\"\:\s+\"(.+)\"/ )
						{	# Ignore the table heading stuff
							my $company = $1;
							my $virus = $2;
							my $result = "$company\t$virus" if ( ( defined $company )  &&  ( defined $virus ) );

							if ( defined $result )
								{	push @$results_ref, $result;
									$av_detected++;
								}
							elsif ( defined $company )	# If I got a company, but not a virus, then that company didn't detect it
								{	push @$results_ref, "$company\t-";
								}
								
							$av_count++ if ( defined $company );
						}
					elsif ( $line =~ m/\"(.+)\"\:\s+\"\"/ )
						{	# Ignore the table heading stuff
							my $company = $1;
							if ( defined $company )	# If I got a company, but not a virus, then that company didn't detect it
								{	push @$results_ref, "$company\t-";
								}
								
							$av_count++ if ( defined $company );
						}
				}
		}


	return( $av_count, $av_detected );
}



################################################################################
# 
sub VirusResultsDir( $$ )
#
#	Given a destination root directory, and an md5 hash, return the final 
#   destination directory
#
################################################################################
{	my $dest_root	= shift;
	my $hex_md5		= shift;
	
	return( undef ) if ( ! defined $dest_root );
	return( undef ) if ( ! defined $hex_md5 );
	
	my $len = length( $hex_md5 );
	return( undef ) if ( ! $len );
	
	$hex_md5 = lc( $hex_md5 );
	return( undef ) if ( $len != 32 );
	
	# Get the top level directory
	my $top = substr( $hex_md5, 0, 2 );
	
	# Get the second level directory
	my $second = substr( $hex_md5, 2, 2 );
	
	my $dest_dir;
	$dest_dir = $dest_root . "\\" . $top . "\\" . $second;

	return( $dest_dir );				
}



################################################################################
# 
sub MyGlob( $ )
#
#  The File::Glob::Windows doesn't work - it screws up the stack, so this is
#  my implementation
#
################################################################################
{	my $filespec = shift;
	
use File::DosGlob;
use Cwd;

	my $cwd;
	
	my ( $dir, $short ) = &SplitFileName( $filespec );

	if ( defined $dir )
		{	$cwd = getcwd;
			$cwd =~ s#\/#\\#g;
			$cwd =~ s/\\$//;   # Trim off a trailing slash
			
			chdir( $dir );
		}
		
	my @files = glob( $short );

	return( @files ) if ( ! defined $dir );

	chdir( $cwd ) if ( defined $cwd );
	
	my @return;
	
	foreach( @files )
		{	my $file = $_;
			next if ( ! defined $file );
			
			my $filename = "$dir\\$file";
			$filename = $dir . $file if ( $dir =~ m/\\$/ );
			
			push @return, $filename;
		}
		
	return( @return );
}



################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( 1 ) if ( ! defined $dir );
	
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
sub HexMD5FileSection( $$$ )
#
#  Given a filename, an offset, and a length, return the hex MD5 hash of that section
#  of the file, or undef if an error
#
################################################################################
{	my $file	= shift;
	my $offset	= shift;
	my $length	= shift;


use Digest::MD5;

	return( undef ) if ( ! defined $file );
	
	return( undef ) if ( ! -s $file );
				
	return( undef ) if ( ( ! $length )  ||  ( $length < 0 ) );
	
	# If I can't open the file - try setting normal access and permissions	
	if ( ! open( MD5HANDLE, "<$file" ) )
		{	my $ok = &DisinfectCommandFileAccessNormal( $file );
			return( undef ) if ( ! $ok );
			
			if ( ! open( MD5HANDLE, "<$file" ) )
				{	lprint "Still having an error opening $file: $!\n";
					return( undef );
				}
		}
		
		
	binmode( MD5HANDLE );
	
	my $md5 = Digest::MD5->new;

	sysseek( MD5HANDLE, $offset, 0 ) if ( $offset );

	my $buf;
	my $nbytes = sysread( MD5HANDLE, $buf, $length, 0 );
				

	if ( ( ! $nbytes )  ||  ( $nbytes != $length ) )
		{	close( MD5HANDLE );
			
			lprint "Error reading from $file: $!\n";
			return( undef );
		}
		
	$md5->new->add( $buf );
	
	my $hex_md5 = $md5->hexdigest;

	close( MD5HANDLE );	
	
	# If I got some sort of error then return undef
	if ( length( $hex_md5 ) != 32 )
		{	lprint "Error calculating the MD5 hash of $file, section at offset $offset, length $length\n";
			return( undef );
		}
	
	return( lc( $hex_md5 ) );
}



################################################################################
# 
sub PESections( $ )
#
#  Give a filename, return the PE data, if I can
#  Reference URL: http://msdn.microsoft.com/en-us/library/ms809762.aspx
#
################################################################################
{	my $fullfile = shift;
	
	# This is the array of section data to return
	my @sections;
	
	
	open( FILE, "<$fullfile" ) or return( @sections );
	binmode( FILE );
	
	my $buff;
	my $bytes = sysread( FILE, $buff, 4048, 0 );
	
	close( FILE );

	return( @sections ) if ( $bytes < 1024 );
	
	my $peoff_str = substr( $buff, 0x3c, 4 );
	
	my $peoff = unpack( 'V', $peoff_str );
	
	my $hpeoff = sprintf( "%x", $peoff );

	return( @sections ) if ( $peoff > ( 1024 - 24 - 56 - 4 ) );
	
	my $pe_signature = substr( $buff, $peoff, 4 );

	# Did I find the PE signature?
	return( @sections ) if ( $pe_signature ne "PE\x00\x00" );
	
	my $cpu_type = substr( $buff, $peoff + 4, 2 );
	
	my $num_of_sections = substr( $buff, $peoff + 6, 2 );
	my $sections = unpack( 'v', $num_of_sections );

	# Return here if I get a crazy number of sections
	return( @sections ) if ( ( $sections < 1 )  ||  ( $sections > 96 ) );

	# Get the size of the optional header
	my $size_str = substr( $buff, $peoff + 20, 2 );
	my $optional_header_size = unpack( 'v', $size_str );
	
	# The optional header size should make sense
	return( @sections ) if ( $optional_header_size > 1024 );
	
	my $stamp_str = substr( $buff, ( $peoff + 8 ), 4 );
	my $time_date = &StrToFHex( $stamp_str );

	my $image_size_str = substr( $buff, ( $peoff + 24 + 56 ), 4 );
	my $image_size = &StrToFHex( $image_size_str );

	my $entry_point_str = substr( $buff, ( $peoff + 24 + 16 ), 4 );
	my $entry_point = &StrToFHex( $entry_point_str );

	my $code_size_str = substr( $buff, ( $peoff + 24 + 4 ), 4 );
	my $code_size = &StrToFHex( $code_size_str );
	
	# This is the size of the IMAGE_FILE_HEADER
	my $image_header_size = 20;
	
	# Find the image option sig by adding the PE header sig size (4) to the image header size
	my $image_optional_sig = substr( $buff, $peoff + $image_header_size + 4, 2 );

	my $section_offset = $peoff + $image_header_size + 4 + $optional_header_size;

	# The image optional sig should be 0x0b01 - if not then I have a problem
	return( @sections ) if ( $image_optional_sig ne "\x0b\x01" );
	
	my $section_buff = substr( $buff, $section_offset, 3036 );
	

	# Now decode out the fields in each section	
	for ( my $i = 0;  $i < $sections;  $i++ )
		{	my $buf = substr( $section_buff, $i * 40, 40 );

			my $stuff = substr( $buf, 0, 8 );
			my ( $name, $junk ) = split /\x00/, $stuff, 2;
		
			my ( $val, $pack ) = &DwordUnpack( $buf, 8 );
			my $physical_address = $val;

			( $val, $pack ) = &DwordUnpack( $buf, 12 );
			my $v_addr = $val;

			( $val, $pack ) = &DwordUnpack( $buf, 16 );
			my $f_size = $val;

			( $val, $pack ) = &DwordUnpack( $buf, 20 );
			my $offset = $val;
			
			( $val, $pack ) = &DwordUnpack( $buf, 36 );
			my $characteristics = $val;
			
			push @sections, "$name\t$offset\t$f_size\t$v_addr\t$characteristics";
		}


	return( @sections );
}



################################################################################
# 
sub DwordUnpack( $$ )
#
#	Unpack out a DWORD from the given offset in the buffer
#
################################################################################
{	my $buff	= shift;
	my $offset	= shift;
	
	my $stuff = substr( $buff, $offset, 4 );

	my $value = unpack( 'V', $stuff );
	my $packed = pack( 'N', $value );
	my $hex_packed = &StrToHex( $packed );

	return( $value, $hex_packed );
}



################################################################################
# 
sub StrToFHex( $ )
#
#	Given a normal representation of a string, return the FLIPPED hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my @list = split //, $str;
	
	my $flip = "";
	
	for ( my $j = $#list;  $j > -1;  $j-- )
		{	$flip .= $list[ $j ];
		}
		
	my $hex = unpack( "H*", $flip );

	return( $hex );
}



################################################################################
# 
sub HexCRC32File( $ )
#
#	Given a file name, return the hex CRC-32 hash
#   Return undef if not found
#
################################################################################
{	my $file = shift;
	
use String::CRC32;
  
	open( CRCHANDLE, "<$file" ) or return( undef );
	
    binmode( CRCHANDLE );
	
	my $crc = crc32( *CRCHANDLE );

	close( CRCHANDLE );	
	
	return( undef ) if ( ! defined $crc );
	
	my $hex_crc = uc( sprintf( "%08x", $crc ) );

	return( $hex_crc );
}



################################################################################
# 
sub VirusTotalUpload( $ )
#
#  Given a filename, upload it to VirusTotal 
#
################################################################################
{   my $file = shift;
	
	return( undef ) if ( ! defined $file );
	return( undef ) if ( ! -f $file );
	
use HTTP::Request;
use LWP::UserAgent;
		
	lprint "Uploading $file to VirusTotal.com ...\n";
	
	
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}

	$| = 1;

	if ( ! $ua )
		{	$ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 1000000 );
			$ua->timeout( 5 * 60 );  #  Wait for a long time

			$ua->conn_cache( $cache );
		}

	my $url = "http://www.virustotal.com/api/scan_file.json";
		
	
	# The post command wants to see a reference to an array instead of a simple string
	my @files;
	push @files, $file;

	my $response = $ua->post(
		$url,
		[	'files'	=> $file,
			'key'	=> $opt_key
		],
	'Content_Type' => 'form-data' );
	
	
	my $ok = $response->is_success();
	my $status = $response->status_line;
	my $content = $response->content;


	if ( ( ! $ok )  &&  ( ! ( $status =~ m/^303/ ) ) )
		{	lprint "Error: $status\n";
			return( undef );
		}


	# If content is a result 0 then VirusTotal.com has this file already
	return( 1 ) if ( $content =~ m/\{\"result\"\: 0\}/i );
	
	lprint "VirusTotal.com is scanning file $file right now ...\n";

	return( 1 );
}



################################################################################
# 
sub AddProgramArchive( $$ )
#
#  Given all the program info, update the program database and copy the file
#  to the program archive
#
################################################################################
{	my $file_info_ref	= shift;
	my $sections_ref	= shift;

	
	my $file = $$file_info_ref{ Filename };


	# If not a Win32/Win64 file then don't add it to the database	
	my $scan_fileid_type = $$file_info_ref{ ScanableFileID };
	if ( ( $scan_fileid_type )  &&  ( $scan_fileid_type == 1 ) )
		{	lprint "Making sure that Win32/Win64 program $file is in the Lightspeed Program Database ...\n";
	
			my $ret = &CategoryUpdateFileInfo( $file_info_ref, $sections_ref, undef );
			
			if ( ! defined $ret )
				{	lprint "Error adding program info for $file into the Program database\n";
				}
		}
		
	
	my @parts = split /\./, $file;
	my $ext = $parts[ $#parts ];

	# End the extension in a "_"
	$ext =~ s/_+$//;
	$ext .= "_";
	
	# If the extension is too long, just use an "_"
	$ext = undef if ( length( $ext ) > 5 );

	# Now copy the file to an Army platoon leader for further processing
	my $dest_dir = "$platoon_leader_unc\\LightspeedCheckFile.com";
	
	mkdir( $dest_dir ) if ( ! -d $dest_dir );
	
	if ( ! -d $dest_dir )
		{	lprint "Unable to make the destination directory $dest_dir: $!\n";
			return( undef );
		}
	
	my $hex_md5 = $$file_info_ref{ HexMD5 };
	my $dest = $dest_dir . "\\$hex_md5.$ext" if ( defined $ext );
	$dest = $dest_dir . "\\$hex_md5" . "_" if ( ! defined $ext );
	
	# Does the target file already exist?
	if ( -f $dest )
		{	lprint "File $dest already exists\n";
			return( 1 );
		}

	
	lprint "Copying $file to $dest for further virus processing and archiving ...\n";
	my $ok = copy( $file, $dest );
	if ( ! $ok )
		{	lprint "Error copying $file to $dest: $!\n";
			return( undef );
		}
	
	return( 1 );
}



################################################################################
# 
sub UpdateFileIDVirus( $$$$ )
#
#	Put the new information into the database
#   Return 1 if added, undef if an error
#
################################################################################
{	my $hex_file_id	= shift;
	my $company		= shift; 
	my $virus_name	= shift;
	my $virus_type	= shift;
	
	
	return( undef ) if ( ! $hex_file_id );
	return( undef ) if ( ! $virus_name );
	return( undef ) if ( ! $company );
	$virus_type = "Virus" if ( ! defined $virus_type );
	
	my $original_virus_name = $virus_name;
	
	$virus_name			= &quoteurl( $virus_name );
	$virus_name			= &SqlColumnSize( $virus_name, 64 );

	$company			= &quoteurl( $company );
	$company			= &SqlColumnSize( $company, 32 );

	
	# Convert them to values for the insert
	my $vhex_file_id	= "\'" . $hex_file_id . "\'";
	my $vvirus_name	= "\'" . $virus_name . "\'";
	my $vcompany	= "\'" . $company . "\'";
	my $vvirus_type	= "\'" . $virus_type . "\'";

	
	# Show I show the info?
	if ( $opt_verbose )
		{
			print "Antivirus Company: $company\n";			
			print "Virus: $virus_name\n";
		}


	# Does this already exist?
	my $str = "SELECT VirusName, VirusType FROM FileIDVirus WITH(NOLOCK) WHERE FileID = $vhex_file_id AND Company = $vcompany";

	my $sth = $dbhProgram->prepare( $str );

	my $ok = $sth->execute();
	
	my ( $db_virus_name, $db_virus_type ) = $sth->fetchrow_array();	
	
	my $rows = 0 + $sth->rows;

	$sth->finish();
	
	
	# If the virus name already exists, and it is the same in the database, then return here
	# Also make sure the virus type is the same
	if ( ( $db_virus_name )  &&
		( lc( $db_virus_name ) eq lc( $original_virus_name ) )  &&
		( $db_virus_type )  &&
		( lc( $db_virus_type ) eq lc( $virus_type ) ) )
		{	return( undef );
		}
	
		
	# If it already exists in the database, but the virus name is different, then update the virus name here
	if ( $rows )
		{	$str = "UPDATE FileIDVirus SET VirusName = $vvirus_name, VirusType = $vvirus_type WHERE FileID = $vhex_file_id AND Company = $vcompany";
			
			$sth = $dbhProgram->prepare( $str );
			
			$ok = $sth->execute();

			$rows = 0 + $sth->rows;

			print "Error updating the virus name $virus_name in the FileIDVirus table\n" if ( $rows ne 1 );
			
			$sth->finish();
			
			return( undef );
		}
		
		
	# Insert the row into the database
	$str = "INSERT INTO FileIDVirus ( FileID, VirusName, Company, VirusType ) VALUES ( $vhex_file_id, $vvirus_name, $vcompany, $vvirus_type )";

	$sth = $dbhProgram->prepare( $str );
	
	$ok = $sth->execute();

	$rows = 0 + $sth->rows;

	print "Error inserting FileID $hex_file_id into the FileIDVirus table\n" if ( $rows ne 1 );
	
	$sth->finish();
	
	return( 0 + 1 ) if ( $ok );
	
	return( undef );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";
Usage: CheckFile [options] filespec

Given a filename, or a wildcard filename, display if the file is detected as a 
virus.

LOGTYPES are: AdAware, DrWeb, Clam, ClamScan, F-Prot, F-ProtOld, F-Secure,
Kaspersky, McAfee, NOD32, Norton, NortonExport, SA (Security Agent), Sophos,
TrendMicro, PCCillin, Windefender, AVG, MalwareBytes, Microsoft, 
or * for any.

  -b, --bcopy LOGTYPE    Sames as -c option but without subdirectories
  -c, --copy LOGTYPE     Copy infected files matched by LOGTYPE to DIR
  -d, --dir DIR          Directory DIR to copy or move LOGTYPE files to
  -e, --email ADDRESSES  Email address(es) to email results to
  -i, --file_id FILE_ID  The file ID of the original file (if known)
  -k, --key KEY          The Virustotal key ID to use
  -l, --list MD5LIST     Check VirusTotal.com with a list of MD5 values
  -m, --move LOGTYPE     Move infected files matched by LOGTYPE to DIR
  -n, --notes TEXT       Note text to include in email
  -o, --original FILE    The original file name (if known)
  -s, --submit           Always submit files to VirusTotal.com
  -v, --verbose          Verbose mode
  
  -h, --help             print this message and exit
.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
