################################################################################
#!perl -w
#
# Rob McCarthy's ProgramArchive source code
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use DBI qw(:sql_types);
use DBD::ODBC;
use Digest::MD5;
use String::CRC32;
use File::Copy;


use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Content::Scanable;
use Content::FileIntegrity;
use Content::Category;
use Content::FileInfo;
use Content::Archive;



my $opt_help;
my $opt_debug;
my $opt_subdir;						# True if I should not scan subdirectories
my $opt_wizard;						# True if I shouldn't display headers or footers
my $opt_append;						# True if it should be appended to the file
my $opt_database = 1;				# True if it shoud inject the file into the database
my $opt_file;						# Name of the file to create
my $opt_verbose;					# True if we should be chatty
my $opt_insert;						# True if I should just insert the programs.txt file into the database
my $opt_export;						# True if I should export from the database to the programs.txt file
my $opt_overwrite;					# True if I should overwrite existing entries in the database
my $_version = '1.00.00';
my $opt_logging;					# If True then log in debug mode
my $opt_recalc;						# If set, then recalculate the program archive file locations


my $main_dest0_directory			= "P:\\Program Archive";			# This is the root of the main program archive directory for x00 to x7f
my $main_dest1_directory			= "O:\\Program Archive 2";			# This is the root of the main program archive directory for x80 to xff



# Globals
my $file_counter	= 0 + 0;		# Count of files found
my $add_counter		= 0 + 0;		# Count of files added to the database
my $update_counter	= 0 + 0;		# Count of files updated in the database
my $deleted_counter	= 0 + 0;
my $dbh;							# Handle to the Content database
my $dbhProgram;						# Handle to the Program database
my %category;
my @category;
my $opt_category;					# True if I should import/export just a single category name
my $opt_category_num = 0 + 6;		# The category number to use when importing
my $opt_unlink;



# This is the list of directories and files to ignore
my @ignore_list = (
"\\Temporary ASP.NET Files",
"\\VSWebCache",
"\\Temporary Internet Files",
"\\System Volume Information",
"\\Mail Archive",
"\\RECYCLER",
);



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
        "a|append"		=> \$opt_append,
		"c|category=s"	=> \$opt_category,
		"d|database"	=> sub { $opt_database = undef; },
		"e|export"		=> \$opt_export,
		"f|file=s"		=> \$opt_file,
        "h|help"		=> \$opt_help,
		"i|insert"		=> \$opt_insert,
		"l|logging"		=> \$opt_logging,
		"o|overwrite"	=> \$opt_overwrite,
		"r|recalc"		=> \$opt_recalc,
		"s|subdir"		=> \$opt_subdir,
		"u|unlink"		=> \$opt_unlink,
		"v|verbose"		=> \$opt_verbose,
		"x|xxx"			=> \$opt_debug
      );


	print( "Lightspeed ProgramArchive Utility\n" ) if ( ! $opt_wizard );	

	print "Overwriting existing programs in the database\n" if ( $opt_overwrite );
	print "Delete programs from their old locations from the Program database\n" if ( $opt_unlink );
	print "Recalculating file locations in the Program database ...\n" if ( $opt_recalc);


	# Make sure that I can access the program archive
	if ( ! -d $main_dest0_directory )
		{	print "Unable to access the program archive at \"$main_dest0_directory\"\n";
			exit( 0 );
		}
		
	# Make sure that I can access the program archive 2
	if ( ! -d $main_dest1_directory )
		{	print "Unable to access the program archive at \"$main_dest1_directory\"\n";
			exit( 0 );
		}
		
		
	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
    &Usage() if ( $opt_help );

	
	if ( $opt_logging )
		{	&SetLogFilename( "$cwd\\Programs.log", 1 );
			my $log_filename = &GetLogFilename();
			lprint "Log file set to $log_filename\n";
		}
		

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
				

	if ( ( $opt_database )  ||  ( $opt_insert )  ||  ( $opt_export )  ||  ( $opt_recalc ) )
		{	$dbhProgram = &ConnectRemoteProgram();
	
			if ( ! $dbhProgram )
				{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

					exit( 0 );
				}
				
			$dbh = &ConnectRemoteServer();
			
			if ( ! $dbh )
				{
print "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.\n";

					exit( 0 );
				}
			
			if ( ! &SqlTableExists( "ApplicationProcesses" ) )
				{	print "The ApplicationProcesses table does not exist in the IpmContent database\n";
					exit;
				}
				
			&LoadCategories();
	
			# Build a local list of the categories as both a array and a hash
			for ( my $i = 1;  $i < 100;  $i++ )
				{	my $catname = &CategoryName( $i );
			
					if ( $catname )
						{	push @category, $catname;
							$category{ $catname } = 0 + $i;
						}
				}	
				
			if ( $opt_category )
				{	my $catnum;
					$opt_category = lc( $opt_category );
					$catnum = $category{ $opt_category } if ( defined $category{ $opt_category } );
					
					if ( $catnum )
						{	lprint "Using category $opt_category, number $catnum for all applications found\n";
							$opt_category_num = 0 + $catnum;
						}
					else	
						{	lprint "Unable to find the category number for category name $opt_category\n";
							exit;
						}
				}
		}

	
	# Am I just supposed to insert the file into the database?
	if ( $opt_insert )
		{	&InsertFile( $opt_file );
			$dbh->disconnect if ( $dbh );
			$dbh = undef;
			$dbhProgram->disconnect if ( $dbhProgram );
			$dbhProgram = undef;
			lprint "Added $add_counter entries to the programs table\n";
			lprint "Updated $update_counter entries to the Programs table\n";

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
	
	
	# Am I just supposed to export database to a file?
	if ( $opt_export )
		{	&ExportFile( $opt_file );
			$dbh->disconnect if ( $dbh );
			$dbh = undef;
			$dbhProgram->disconnect if ( $dbhProgram );
			$dbhProgram = undef;

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
	
	
	if ( $opt_file )
		{	if ( $opt_append )
				{	open( OUTPUT, ">>$opt_file" ) or die "Unable to open file $opt_file: $!\n";
				}
			else
				{	open( OUTPUT, ">$opt_file" ) or die "Unable to open file $opt_file: $!\n";
				}
		}
		
	
	my $windir;
	$windir = $ENV{windir} if ( defined $ENV{windir} );
	for ( my $i = 0;  $ignore_list[ $i ];  $i++ )
		{	$ignore_list[ $i ] =~ s/WINDIR/$windir/g if ( $windir );
			$ignore_list[ $i ] = lc( $ignore_list[ $i ] );
		}
		
		
	# Make sure that the scan list is not ignored
	# I.e. if I specifically want to scan a directory, don't ignore it
	foreach ( @dir_list )
		{	next if ( ! $_ );
			my $lc_path = lc( $_ );

			for ( my $i = 0;  $ignore_list[ $i ];  $i++ )
				{	my $ignore = $ignore_list[ $i ];

					my $pos = index( $lc_path, $ignore );
					if ( $pos > ( 0 - 1 ) )
						{	splice( @ignore_list, $i, 1 );
						}
				}
		}
		
		
	lprint "Writing programs information to file $opt_file ...\n" if ( $opt_file );
	lprint "Adding or updating the programs table in the database\n" if ( $opt_database );
	
	
#	&TrapErrors() if ( ! $opt_debug );


	# Am I just recaculating file locations?
	if ( $opt_recalc )
		{	&RecalculateFileLocations();
			
			$dbh->disconnect if ( $dbh );
			$dbh = undef;
			$dbhProgram->disconnect if ( $dbhProgram );
			$dbhProgram = undef;
			
			&StdFooter if ( ! $opt_wizard );
			
			exit;
		}
		
		
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
				{	lprint "Checking file # $file_counter: $item ...\n";
					
					my $ret = &CheckFile( $item );										
				}
		}
	
	
	lprint "\nChecked $file_counter files\n" if ( $file_counter );
	if ( $opt_database )
		{	lprint "Added $add_counter entries to the Programs table\n";
			lprint "Updated $update_counter unique file ID entries to the programs table\n";
		}
		
	lprint "Deleted $deleted_counter files from their old locations\n" if ( $opt_unlink );
	
	close( OUTPUT ) if ( $opt_file );
	
	lprint "Created file $opt_file\n" if ( $opt_file );
	
	$dbh->disconnect if ( $dbh );
	$dbh = undef;
	$dbhProgram->disconnect if ( $dbhProgram );
	$dbhProgram = undef;
	
	&StdFooter if ( ! $opt_wizard );
	
	exit;
}
###################    End of MAIN  ################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $filename = "ProgramArchiveErrors.log";
	
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	&lprint( "Unable to open $filename: $!\n" );  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	print "Error trapping set to file $filename ...\n"; 
	
	return( 1 );
}



################################################################################
# 
sub RecalculateFileLocations()
#
#	Recalculate and update the file locations lin the Program database
#
################################################################################
{
	
	my $dbhP2 = DBI->connect( "DBI:ODBC:ProgramRemote", "Program" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhP2 )
		{	sleep( 10 );
			$dbhP2 = DBI->connect( "DBI:ODBC:ProgramRemote", "Program" );
		}
		
	die "Unable to open up a second handle to the Program database\n" if ( ! $dbhP2 );
	
	print "Opened a second handle to the Program database ...\n";
	
	
	print "Selecting the non-categorized programs in the Program database ...\n";
	
	my $str = "SELECT [Filename], MD5, FileID FROM Programs WITH(NOLOCK) WHERE CategoryNumber IS NULL";
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();
		
	my $total	= 0 + 0;
	my $correct = 0 + 0;
	my $missing = 0 + 0;
	my $weird	= 0 + 0;
	my $fixed	= 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  (  my ( $dbfilename, $hex_md5, $hex_file_id ) = $sth->fetchrow_array() ) )
		{	next if ( ! $hex_md5 );
			next if ( length( $hex_md5 ) != 32 );
			next if ( ! $dbfilename );
			next if ( ! $hex_file_id );
			
			print "Filename: $dbfilename\n" if ( $opt_verbose );
			$total++;

			my $delete;

				
			if ( $dbfilename =~ m/\.png_$/i )
				{	$delete = 1;
				}
				
			if ( $dbfilename =~ m/\.ini_$/i )
				{	$delete = 1;
				}
				
			if ( $dbfilename =~ m/\.zip_$/i )
				{	$delete = 1;
				}
				
			if ( $dbfilename =~ m/\.cab_$/i )
				{	$delete = 1;
				}

			if ( $dbfilename =~ m/\.msi_$/i )
				{	$delete = 1;
				}

			if ( $dbfilename =~ m/\.vbs_$/i )
				{	$delete = 1;
				}

			if ( $dbfilename =~ m/\.vb_$/i )
				{	$delete = 1;
				}

			if ( $dbfilename =~ m/\.bat_$/i )
				{	$delete = 1;
				}

			if ( $dbfilename =~ m/\.cmd_$/i )
				{	$delete = 1;
				}

			if ( $dbfilename =~ m/\.pl_$/i )
				{	$delete = 1;
				}
				
			if ( $dbfilename =~ m/\.eml_$/i )
				{	$delete = 1;
				}


			if ( $delete )
				{	print "Deleting database entry: $dbfilename\n" if ( $opt_verbose );
					
					my $str2 = "DELETE Programs WHERE FileID = '$hex_file_id'";
					my $sth2 = $dbhP2->prepare( $str2 );
					$sth2->execute();
					$sth2->finish();
					next;	
				}
			
						
			my ( $dir, $short_file ) = &SplitFileName( $dbfilename );
			my $dest = &PArchiveFilename( $short_file, $main_dest0_directory, $main_dest1_directory );
			
			if ( ! $dest )
				{	# See if I can figure out the name that it should have in the Program Archive
					my ( $file, $ext ) = split /\./, $short_file;
					$ext = "_" if ( ! defined $ext );
					
					# make sure that the extension ends in a "_"
					$ext .= "_" if ( ! ( $ext =~ m/_$/ ) );
					
					my $archive_file = $hex_md5 . "." . $ext;
					$dest = &PArchiveFilename( $archive_file, $main_dest0_directory, $main_dest1_directory );
					if ( ! $dest )
						{	$weird++;
							print "Weird Filename: $dbfilename, MD5: $hex_md5\n" if ( $opt_verbose );
						}
				}
			
			
			# Could I figure out the right name in the Program Archive?
			if ( ! defined $dest )
				{	my $str2 = "DELETE Programs WHERE FileID = '$hex_file_id'";
					my $sth2 = $dbhP2->prepare( $str2 );
					$sth2->execute();
					$sth2->finish();
				}
			# Is it right in the database now?
			elsif ( lc( $dbfilename ) eq lc( $dest ) )
				{	$correct++;
				}		
			# Does the dest file exist?
			elsif ( ! -f $dest )
				{	$missing++;
					print "Missing file: $dest\n" if ( $opt_verbose );
					my $str2 = "DELETE Programs WHERE FileID = '$hex_file_id'";
					my $sth2 = $dbhP2->prepare( $str2 );
					$sth2->execute();
					$sth2->finish();
				}
			else # I need to fixup the name in the Program database
				{	$fixed++;
					print "Fixed file: $dest\n" if ( $opt_verbose );
					
					my $str2 = "UPDATE Programs SET [Filename] = '$dest' WHERE FileID = '$hex_file_id'";
					my $sth2 = $dbhP2->prepare( $str2 );
					$sth2->execute();
					$sth2->finish();
				}
				
			&Status( $total, $correct, $fixed, $missing, $weird );	
		}
		
	$sth->finish();

		
	$dbhP2->disconnect if ( $dbhP2 );
	$dbhP2 = undef;
	
	return( 1 );
}



################################################################################
# 
sub Status( $$$$$ )
#
#	Show the status of the RecalculateFileLocations function
#
################################################################################
{	my $total	= shift;
	my $correct = shift;
	my $fixed	= shift;
	my $missing = shift;
	my $weird	= shift;
	
	return( undef ) if ( ! $total );
	
	my $total_cnt = 1000 * sprintf( "%d", ( $total / 1000 ) ); 
	return( undef ) if ( ! $total_cnt );
	return( undef ) if ( $total_cnt != $total );
	
	print "Total: $total_cnt\tCorrect: $correct\tFixed: $fixed\tMissing: $missing\tWeird: $weird\n";
	
	return( 1 );
}



################################################################################
# 
sub ExportFile( $ )
#
#	Export the database into a file 
#
################################################################################
{	my $file = shift;
	
	lprint "Exporting the database into file $file\n";
	
	if ( ! open( OUTPUT, ">$file" ) )
		{	lprint "Unable to open file $file: $!\n";
			return;
		}
		
	my $sth;
	
	$sth = $dbhProgram->prepare( "SELECT FileID, AppName, Filename, FileVersion, FileSize, MD5, Description, Company, TransactionTime FROM Programs WITH(NOLOCK) ORDER BY AppName" );
		
	$sth->execute();
	
	
	my $counter = 0 + 0;
	while ( my ( $id, $hex_file_id, $app_name, $filename, $file_version, $file_size, $hex_md5, $desc, $company, $transaction_time ) = $sth->fetchrow_array() )
		{	$counter++;
			
			print OUTPUT "$hex_file_id\t$app_name\t$filename\t$file_version\t$file_size\t$hex_md5\t$desc\t$company\t$transaction_time\n"; 
		}
		
	$sth->finish();	
		
			
	close( OUTPUT );
	
	lprint "Exported $counter programs\n";
}



################################################################################
# 
sub InsertFile( $ )
#
#	Just insert the app process text file into the database
#
################################################################################
{	my $file = shift;
	
	lprint "Inserting file $file directly into the database\n";
	
	if ( ! open( INPUT, "<$file" ) )
		{	lprint "Unable to open file $file: $!\n";
			return;
		}
		
		
	while ( my $line = <INPUT> )
		{	next if ( ! $line );
			
			chomp( $line );
			
			next if ( ! $line );

			my ( $hex_file_id, $app_name, $filename, $file_version, $file_size, $hex_md5, $desc, $company, $time_date, $image_size, $entry_point, $code_size, $hex_crc32 ) = split /\t/, $line;
			
			# Was I handed a blank file ID?
			# Skip it if I don't have a valid file ID
			next if ( ( ! defined $hex_file_id )  ||  ( $hex_file_id eq "" )  ||  ( length( $hex_file_id ) != 56 ) );
						
			my $ret = &CategoryUpdateProgramsTable( $hex_file_id, $app_name, $filename, $file_version, $file_size, $hex_md5, $hex_crc32, $desc, $company, $time_date, $image_size, $entry_point, $code_size, undef, 1 );
	
			$file_counter++;
	
			next if ( ! defined $ret );
	
			$add_counter++ if ( $ret > 0 );
			$update_counter++ if ( $ret < 0 );
		}
	
	close( INPUT );
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
#  Check a file's version info
#
################################################################################
{	my $file = shift;

	return( undef ) if ( ! defined $file );
	return( undef ) if ( ! -f $file );

	
	my ( $dir, $short_file ) = &SplitFileName( $file );
	my $lc_dir = lc( $dir );
	
	
	# Should I ignore this file?
	foreach( @ignore_list )
		{	next if ( ! $_ );
			my $ignore = $_;
				
			my $pos = index( $lc_dir, $ignore );
			return if ( $pos > -1 );
		}
		

	# Ignore Javascript
	return if ( $file =~ m/\.js_$/i );
	return if ( $file =~ m/\.js$/i );
	
	
	# Ignore other stuff
	return if ( $file =~ m/\.cab_$/i );
	return if ( $file =~ m/\.jar_$/i );
	return if ( $file =~ m/\.zip_$/i );
	return if ( $file =~ m/\.msi_$/i );


	if ( $opt_verbose )
		{	lprint "\nChecking File: $file ...\n";
		}
		
		
	# Get all the file info that I can
	my %file_info;
	my @sections;
	my $ok = &FileInfo( $file, \%file_info, \@sections, $opt_verbose );	
	return( undef ) if ( ! $ok );
	

	# Is this the type of file that I can calculate a file ID for?
	my $scan_fileid_type = $file_info{ FileIDType };

	if ( ! $scan_fileid_type )
		{	lprint "Not scanable\n" if ( $opt_verbose );
			return( undef );	
		}
	

	if ( $opt_verbose )
		{	my $scanable_desc = $file_info{ ScanableDescription };
			lprint "Scan Type: $scanable_desc\n" if ( $scanable_desc );
		}
		
		
	# If this isn't an executable program, and I'm not supposed to calc this stuff, then return
	if ( $scan_fileid_type != 1 )
		{	lprint "Ignoring this scan type\n" if ( $opt_verbose );
			return( undef );	
		}
	
	
	my $app_name = $file_info{ AppName };


	my $file_id = $file_info{ FileID };
	
	# If no file id, bag it
	if ( ! $file_id )
		{	lprint "$file does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}
		
	my $hex_file_id = $file_info{ HexFileID };		
	
	
	# Does this file ID already exist in the Programs table in the Program database?
	my $sth;
	$sth = $dbhProgram->prepare( "SELECT FileID, Filename, CRC32, AppName FROM Programs WITH(NOLOCK) WHERE FileID = \'$hex_file_id\'" );
			
	$sth->execute();

	my ( $db_fileid, $db_filename, $db_crc32, $db_app_name ) = $sth->fetchrow_array();
 
	$sth->finish();
	
	my $already_exists = 1 if ( ( $db_fileid )  &&  ( $db_filename ) );
	
	my $same_filename = 1 if ( ( $already_exists )  &&  ( lc( $db_filename ) eq lc( $file ) ) );
	
	
	# If the database has the file as a virus or as a good program, then don't overwrite the app name and filename in the database
	# If the virus archive copy is missing, replace it
	if ( ( ! $opt_overwrite )  
		&&  ( ! $same_filename )  
		&&  ( $already_exists )  
		&&  ( $db_filename =~ m/virus archive/i ) )
		{	my $not_virus = 1 if ( $db_filename =~ m/notvirus archive/i );
			
			&lprint( "$file is a KNOWN GOOD program called $db_app_name so not changing the database\n" ) if ( $not_virus );
			&lprint( "$file is a virus called $db_app_name so not changing the database\n" ) if ( ! $not_virus );
			
			# Make sure that the file exists in the virus archive
			if ( ( ! -e $db_filename )  &&  ( ! $not_virus ) )
				{	&lprint( "Copying $file to $db_filename ...\n" );
					my $ok = copy( $file, $db_filename );
				}
				
			return( undef );
		}
	
	
	# It may already exist, but do I need to update the crc32 or the app name?
	if ( ( $already_exists )  &&  ( $same_filename )  &&  ( ! $opt_overwrite ) )
		{	if ( ( ! $db_crc32 )  ||  ( $db_crc32 eq "00000000" )  ||  ( $app_name ne $db_app_name ) )
				{	&lprint( "Updating the CRC32, AppName for $file ...\n" ) if ( $opt_verbose );
					my $hex_crc32 = $file_info{ HexCRC32 };
					&UpdateCRC32( $hex_file_id, $hex_crc32, $app_name ) if ( defined $hex_crc32 );
				}
			
			lprint "$file already exists in the database with the same name\n" if ( $opt_verbose );
			
			return( undef );
		}
	
	
	if ( ! $already_exists )
		{	&lprint( "$hex_file_id is not in the database\n" ) if ( $opt_verbose );
		}
		
	if ( ( $already_exists )  &&  ( ! $same_filename ) )
		{	&lprint( "The filename has changed from $db_filename to $file\n" ) if ( $opt_verbose );
		}
		

	my $hex_md5 = $file_info{ HexMD5 };
	$hex_md5 = "" if ( ! defined $hex_md5 );
	
	my $hex_crc32 = $file_info{ HexCRC32 };
	$hex_crc32 = "" if ( ! defined $hex_crc32 );


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
	my $file_size		= $file_info{ FileSize };
	
	
	# Show I show the info?
	if ( $opt_verbose )
		{	my @keys = sort keys %file_info;

			lprint "\nFile: $file\n";
			
			foreach( @keys )
				{	my $key = $_;
					next if ( ! $key );
					
					# Ignore the file ID - if is a binary value
					next if ( $key eq "FileID" );
					my $val = $file_info{ $key };
					
					$val = "" if ( ! defined $val );
					
					lprint "$key: $val\n";
				}
				
			if ( $#sections > -1 )
				{	lprint "\nSection Data\n";
					foreach ( @sections )
						{	my $data = $_;
							next if ( ! $data );
							lprint "$data\n";
						}
				}
				
			lprint "\n";	
		}
		

	if ( $opt_file )
		{	print OUTPUT "$hex_file_id\t$app_name\t$file\t$file_version\t$file_size\t$hex_md5\t$desc\t$company\t$time_date\t$image_size\t$entry_point\t$code_size\n"; 
		}
		

	# Make sure that the filename in the Program database is the final filename it will end up with in the
	# Program Archive	
	my $dest = &PArchiveFilename( $file, $main_dest0_directory, $main_dest1_directory );
	return( undef ) if ( ! $dest );
	$file_info{ Filename } = $dest;


	my $ret = &CategoryUpdateFileInfo( \%file_info, \@sections, $opt_overwrite );
	return( undef ) if ( ! defined $ret );
	
	
	$file_counter++;

	$add_counter++ if ( $ret > 0 );
	$update_counter++ if ( $ret < 0 );
	
	print "Updated the datebase\n" if ( ( $ret < 0 )  &&  ( $opt_verbose ) );
	print "Added to the datebase\n" if ( ( $ret > 0 )  &&  ( $opt_verbose ) );
	
	# Should I delete this file from the old location?
	return( 1 ) if ( ! $opt_unlink );
	return( 1 ) if ( $same_filename );
	
	$ok = unlink( $db_filename );
	
	if ( $ok )
		{	&lprint( "Deleted the file in the old location: $db_filename\n" );
			$deleted_counter++;
		}
	else
		{	&lprint( "Unable to delete the file in the old location: $db_filename\n" );
		}
		
	return( 1 );
}



################################################################################
# 
sub UpdateCRC32( $$$ )
#
#	Given a file ID, update the crc32 value and the AppName
#
################################################################################
{	my $hex_file_id = shift;
	my $hex_crc32	= shift;
	my $app_name	= shift;
	
	# Does this file ID already exist in the Programs table in the Program database?
	my $sth;
	$sth = $dbhProgram->prepare( "UPDATE Programs SET CRC32 = \'$hex_crc32\', AppName = \'$app_name\' WHERE FileID = \'$hex_file_id\'" );
	$sth->execute();

	$sth->finish();

	return( 1 );
}



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     lprint( @_ );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "Programs";

    print <<".";
scan $_version
.

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "ProgramArchive";
	
    print <<".";

Usage: ProgramArchive [options]
Go through the Program Archive directories updating all the program info
in the Program database of the Program SQL server. 


Possible options are:

  -d, --database        don\'t add the app/process info to the database
  -f, --file=name       write the results to a text file called \'name\'
  -i, --insert          insert the app process file into the database
  -o, --overwrite       overwrite existing file IDs in the database
  -r, --recalc          recalculate the Program Archive file location
  -s, --subdir          to NOT recursively go though subdirectories
  -u, --unlink          delete the old file location if it exists
  -v, --verbose         show work as it progresses
  -x, --nonexecutable   also include non-executable but scanable files
  
  -h, --help            print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
