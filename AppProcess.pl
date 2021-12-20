################################################################################
#!perl -w
#
# Rob McCarthy's AppProcess source code
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Content::Scanable;
use Content::FileIntegrity;
use Content::Category;


use Cwd;
use Getopt::Long();
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use DBI qw(:sql_types);
use DBD::ODBC;



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_dir;
my $opt_subdir;							# True if I should not scan subdirectories
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_append;							# True if it should be appended to the file
my $opt_database = 1;					# True if it shoud inject the file into the database
my $opt_file;							# Name of the file to create
my $opt_name;							# Set the applcation name to Virus Archive format
my $opt_verbose;						# True if we should be chatty
my $opt_path;							# True if I use the full path of the process
my $opt_program;						# True if I should display all the program information
my $opt_insert;							# True if I should just insert the appprocess.txt file into the database
my $opt_export;							# True if I should export from the database to the appprocess.txt file
my $opt_windows;						# True if I should force the app name to the windows application
my $opt_category;						# True if I should import/export just a single category name
my $opt_update;							# True if I should turn on the inherit bit for an update package
my $opt_overwrite;						# True if I should overwrite existing entries in the database
my $opt_source_num = 0 + 3;				# The source number to use when adding a row
my $opt_category_num = 0 + 6;			# The category number to use when importing
my $opt_rec		= 0 + 0;				# Recommended bit
my $opt_dang	= 0 + 0;				# Dangerous bit
my $opt_current = 0 + 0;				# CurrentVersion bit
my $opt_mistake;						# If True then revese any blocked programs found to unblocked
my $opt_nonexecutable;					# If True the calculate file IDs for scanable but non executable files
my $opt_remote_database;				# If True then use the remote Content and Statistics databases
my $opt_testfile;						# If set, then this is the name of the testfile to read and write out their file IDs that are in the database
my $opt_testfileid;						# If set, then read a list of file IDS to set them to errors in the database


my $_version = '1.00.00';
my $opt_logging;						# If True then log in debug mode
my $opt_recommended;					# If True then turn on the recommended bit
my $inherit_permissions = "40000200";	# This is the permissions to inset into the database if turning on the inherit bit
my $normal_permissions = "00000000";	# This is the normal permissions value



# Globals
my $file_counter = 0 + 0;				# Count of files found
my $add_counter = 0 + 0;				# Count of files added to the database
my $update_counter = 0 + 0;				# Count of files updated in the database
my %installed;
my %uninstalled;
my @applications;
my @install_locations;
my @uninstall_locations;
my $dbh;
my $windows_app_name = "Microsoft® Windows® Operating System";
my %category;
my @category;
my %file_id;					# A hash of file IDs found so far



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
		"0|remote"		=> \$opt_remote_database,
        "a|append"		=> \$opt_append,
		"c|category=s"	=> \$opt_category,
		"d|database"	=> sub { $opt_database = undef; },
		"e|export"		=> \$opt_export,
		"f|file=s"		=> \$opt_file,
        "h|help"		=> \$opt_help,
		"i|insert"		=> \$opt_insert,
		"l|logging"		=> \$opt_logging,
		"m|mistake"		=> \$opt_mistake,
		"n|name"		=> \$opt_name,
		"o|overwrite"	=> \$opt_overwrite,
		"p|program"		=> \$opt_program,
		"q|testfileid=s"=> \$opt_testfileid,
		"r|recommended"	=> \$opt_recommended,
		"s|source=s"	=> \$opt_source_num,
		"t|test=s"		=> \$opt_testfile,
		"u|update"		=> \$opt_update,
		"v|verbose"		=> \$opt_verbose,
		"w|windows"		=> \$opt_windows,
		"x|xxx"			=> \$opt_nonexecutable
      );


	$opt_source_num = 0 + $opt_source_num;
	if ( ( $opt_source_num <= 0 )  ||  ( $opt_source_num >= 100 ) )
		{	print "Bad source number = $opt_source_num\n";
			exit( 0 );
		}
	
	print( "Lightspeed Application/Process utility\n" ) if ( ! $opt_wizard );


	$opt_program = 1 if ( $opt_verbose );
	

	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	$opt_dir = $cwd if ( !$opt_dir );
	
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	
	if ( $opt_logging )
		{	&SetLogFilename( "$cwd\\AppProcess.log", 1 );
			my $log_filename = &GetLogFilename();
			lprint "Log file set to $log_filename\n";
		}
		

	$opt_database = undef if ( ( $opt_file )  &&  ( ! $opt_insert ) );
	
	lprint "Labeling all the processes as $windows_app_name\n" if ( $opt_windows );
	lprint "Giving all the processes the inherit bit for software updates\n" if ( $opt_update );
	lprint "Overwriting existing file IDs in the database\n" if ( $opt_overwrite );
	lprint "Reversing blocked programs to unblocked in the database\n" if ( $opt_mistake );
	lprint "Set the application name to Virus Archive format\n" if ( $opt_name );
	lprint "Saving to the local database ApplicationProcesses table\n" if ( ( $opt_database )  &&  ( ! $opt_remote_database ) );
	lprint "NOT Saving to the local database\n" if ( ! $opt_database );
	lprint "Writing the ApplicationProcesses information to file $opt_file\n" if ( ( $opt_file )  &&  ( ! $opt_insert ) );
	lprint "Importing the ApplicationProcesses information from file $opt_file\n" if ( ( $opt_file )  &&  ( $opt_insert ) );
	lprint "Saving to the remote IpmContent database ApplicationProcesses table\n" if ( ( $opt_database )  &&  ( $opt_remote_database ) );
	lprint "Verbose mode\n" if ( $opt_verbose );
	lprint "Reading a virus list in $opt_testfile and writing out in file AppProcess.txt their File IDs that are in the database\n" if ( $opt_testfile );
	lprint "Reading a list of file IDs in $opt_testfileid and setting their category to errors in the database\n" if ( $opt_testfileid );
	
	
	if ( $opt_recommended )
		{	print "Turning on the recommended bit on all programs added to the database\n";
			$opt_rec = 0 + 1;	
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
				

	if ( ( $opt_database )  ||  ( $opt_insert )  ||  ( $opt_category )  ||  ( $opt_export )  ||  ( $opt_mistake )  ||  ( $opt_testfile )  ||  ( $opt_testfileid ) )
		{	if ( ! $opt_remote_database )
				{	$dbh = &ConnectServer() or &FatalError( "Unable to connect to Content SQL database\n" );
				}
			else
				{	$dbh = &RemoteDatabases();
print "Run ODBCAD32 and add the Application SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.\n" if ( ! $dbh );
exit( -1 ) if ( ! $dbh );
				}
			
			if ( ! &SqlTableExists( "ApplicationProcesses" ) )
				{	print "The ApplicationProcesses table does not exist in the local IpmContent database\n";
					exit;
				}
				
			if ( ( ! $opt_remote_database )  &&  ( ! &SqlTableExists( "NotVirus" ) ) )
				{	print "The NotVirus table does not exist in the local IpmContent database\n";
					exit;
				}
				
			&LoadCategories();
	
			# Build a local list of the categories as both an array and a hash
			for ( my $i = 1;  $i < 150;  $i++ )
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
		
		
	&GetInstalledApplications();
	
	
	# Am I just supposed to insert the file into the database?
	if ( $opt_insert )
		{	&InsertFile( $opt_file );
			$dbh->disconnect if ( $dbh );
			$dbh = undef;
			lprint "Added $add_counter entries to the ApplicationProcesses table\n";
			lprint "Updated $update_counter entries to the ApplicationProcesses table\n";

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
	
	
	# Am I just supposed read a list of files and write out their file IDs?
	if ( $opt_testfile )
		{	&TestFile( $opt_testfile );
			$dbh->disconnect if ( $dbh );
			$dbh = undef;

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
	
	
	# Am I just supposed to read a list of file IDs and set them to errors in the database?
	if ( $opt_testfileid )
		{	&TestFileFileID( $opt_testfileid );
			$dbh->disconnect if ( $dbh );
			$dbh = undef;

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
	
	
	# Am I just supposed to export database to a file?
	if ( $opt_export )
		{	&ExportFile( $opt_file );
			$dbh->disconnect if ( $dbh );
			$dbh = undef;
			
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
		
		
	my $tmp_dir = &ScanTmpDirectory();
	my $quarantine_dir = &ScanQuarantineDirectory();
	
	# Make sure the ignore list is ok
	# Switch the WINDIR entries in the ignore list to the actual directory, and set everything to lowercase
	push @ignore_list, $tmp_dir;
	push @ignore_list, $quarantine_dir;
	
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
		
		
	
	foreach ( @dir_list )
		{	my $item = $_;
					
			next if ( $item =~ m/\.$/ );	# Skip dot files
					
			if ( -d $item )
				{	lprint "Checking $item and subdirectories ...\n" if ( ! $opt_subdir );
					lprint "Checking $item ...\n" if ( $opt_subdir );
	
					&CheckDir( $item );
				}
			elsif ( -e $item )
				{	lprint "Checking file $item ...\n";
					
					my $ret = &CheckFile( $item );										
				}
		}
	
	
	lprint "\nChecked $file_counter files\n" if ( $file_counter );
	if ( $opt_database )
		{	lprint "Added $add_counter entries to the ApplicationProcesses table\n";
			lprint "Updated $update_counter unique file ID entries to the ApplicationProcesses table\n";
		}
		
	close( OUTPUT ) if ( $opt_file );
	
	lprint "Created file $opt_file\n" if ( $opt_file );
	
	$dbh->disconnect if ( $dbh );
	$dbh = undef;
	
	&StdFooter if ( ! $opt_wizard );
	
	exit;
}
###################    End of MAIN  ################################################



################################################################################
# 
sub RemoteDatabases()
#
#  Find and connect to the remote Content database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbh ) if ( $dbh );
	
	lprint "Connecting to the remote SQL database TrafficRemote ...\n";
	
	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\TrafficRemote", 0, KEY_READ, $key );
	
	&RegCloseKey( $key );
	&FatalError( "Unable to connect to Remote IpmContent SQL database\n" ) if ( ! $ok );
	
	return( undef ) if ( ! $ok );
	
	
	my $dbhRemote = DBI->connect( "DBI:ODBC:TrafficRemote", "IpmContent" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhRemote )
		{	sleep( 10 );
			$dbhRemote = DBI->connect( "DBI:ODBC:TrafficRemote", "IpmContent" );
		}
		
	&FatalError( "Unable to connect to Remote IpmContent SQL database\n" ) if ( ! $dbhRemote );
		
	&SqlSetCurrentDBHandles( $dbhRemote, undef );
	
	return( $dbhRemote );
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
	
	if ( $opt_category )
		{	my $category_num = $opt_category_num;
				
			$sth = $dbh->prepare( "SELECT FileID, AppName, Process, Description, Manufacturer, Recommended, Dangerous, CurrentVersion, Ports, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE CategoryNumber = ? ORDER BY PROCESS" );
			$sth->bind_param( 1, $category_num,  DBI::SQL_INTEGER );
		}
	else	
		{	$sth = $dbh->prepare( "SELECT FileID, AppName, Process, Description, Manufacturer, Recommended, Dangerous, CurrentVersion, Ports, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) ORDER BY Process" );
		}
		
	$sth->execute();
	
	
	my $counter = 0 + 0;
	while ( my ( $hex_file_id, $app_name, $process, $desc, $manu, $rec, $dang, $current, $ports, $category_num, $source_num ) = $sth->fetchrow_array() )
		{	$counter++;
			
			$ports = " " if ( ! $ports );
			
			print OUTPUT "$hex_file_id\t$process\t$app_name\t$manu\t$desc\t$rec\t$dang\t$current\t$ports\t$category_num\t$source_num\n"; 
		}
		
	$sth->finish();	
		
			
	close( OUTPUT );
	
	lprint "Exported $counter application/processes\n";
}



################################################################################
# 
sub InsertFile( $ )
#
#	Just insert the app process text file into the database
#
################################################################################
{	my $file = shift;
	
	if ( $opt_category )
		{	my $category_num = $opt_category_num;			
		}
		
	lprint "Inserting file $file directly into the database\n";
	
	if ( ! open INPUT, "<$file" )
		{	lprint "Unable to open file $file: $!\n";
			return;
		}
		
		
	while ( my $line = <INPUT>)
		{	next if ( ! $line );
			
			chomp( $line );
			
			next if ( ! $line );

			print "Importing: $line\n" if ( $opt_verbose );
		
			my @parts = split /\t/, $line;

			my $hex_file_id = $parts[ 0 ];
			my $file = $parts[ 1 ];
			my $app_name = $parts[ 2 ];
			my $company = $parts[ 3 ];
			my $description = $parts[ 4 ];
			
			my $rec = 0 + $parts[ 5 ];
			
			# Set the rec bit to whatever the command line option is
			$rec = $opt_rec;

			my $dang = 0 + $parts[ 6 ];
			my $current = 0 + $parts[ 7 ];
			my $ports = $parts[ 8 ];
			my $category_num = 0 + $parts[ 9 ];
			my $source_num = 0 + $parts[ 10 ];
			my $virus_name = $parts[ 11 ];
			
			# Was I handed a blank file ID?
			my $file_id = &HexToStr( $hex_file_id );
			$file_id =~ s/\s+$//;
			$file_id =~ s/\^\s+//;
			
			# Skip it if I don't have a valid file ID
			if ( ( ! defined $file_id )  ||  ( $file_id eq "" ) )
				{	print "Bad file ID\n" if ( $opt_verbose );
					next;
				}
			
			# Clean up the virus name
			if ( defined $virus_name )
				{	$virus_name =~ s/\s+$//;
					$virus_name =~ s/\^\s+//;
				}
				
			$virus_name = undef if ( ( defined $virus_name )  &&  ( $virus_name eq "" ) );
		
			my ( $dir, $short_file ) = &SplitFileName( $file );

			my $fname = $short_file;
			$fname = $file if ( $opt_path );


			# Can I guess a category name from the directory?
			my $actual_category_num = &VirusGuessCategory( $file, $category_num, $virus_name ) if ( defined $virus_name );
			$actual_category_num = $category_num if ( ! defined $virus_name );
			
	
			# Handle scanned viruses correctly
			if ( ( defined $virus_name )  &&  ( $virus_name ne "Unknown executable" ) )
				{	next if ( $virus_name =~ m/Permission denied/ );
					
					my $lc_app_name = lc( $app_name );
					
					# Bad filename from some weird server
					next if ( $lc_app_name =~ m/^page.*\.scr$/ );
					
					lprint "\n";
					lprint "\n";
					lprint "File ID: $hex_file_id\n";
					lprint "Found virus: $virus_name\n";
					lprint "Found app_name: $app_name\n" if ( defined $app_name );
					lprint "Found file: $file\n" if ( defined $file );
					lprint "Found company: $company\n" if ( defined $company );
					lprint "Found categoryNumber: $actual_category_num\n" ;
					
					my ( $appName, $process, $desc, $manu, $recommended, $dangerous, $categoryNumber, $sourceNumber ) = &LookupHexFileID( $hex_file_id );
					
					if ( defined $appName )
						{	$categoryNumber = 0 + $categoryNumber;
							
							if ( $categoryNumber == 63 )	# Is it already maked as a virus
								{	&lprint( "Already defined as a virus\n" );
									next;
								}
								
							if ( $categoryNumber == 62 )	# Is it already maked as spyware
								{	&lprint( "Already defined as spyware\n" );
									next;
								}
							
							lprint "Found matching file ID in database - $hex_file_id\n";
							
							lprint "Database appName: $appName\n" if ( defined $appName );
							lprint "Database process: $process\n" if ( defined $process );
							lprint "Database manu: $manu\n" if ( defined $manu );
							lprint "Database categoryNumber: $categoryNumber\n" ;
							lprint "\n";
							
							next;
						}
				}
			
			# Have I already seen this file ID?
			next if ( defined $file_id{ $file_id } );
			$file_id{ $file_id } = $fname;


			my $ret = &UpdateAppProcessTable( $app_name, $company, $fname, $description, $ports, $hex_file_id, $rec, $dang, $current, $actual_category_num, $source_num );
				
			# Show I show the info?
			if ( ( $opt_program )  &&  ( $ret ) )
				{	lprint "\nAppName: $app_name\n";			
					lprint "Company: $company\n";
					lprint "Description: $description\n" if ( $description );
					lprint "File ID: $hex_file_id\n";	
					
					if ( $opt_database )
						{	my $catname = &CategoryName( $actual_category_num );
							lprint "Category: $catname\n";		
						}
				}

			if ( ( $opt_program )  &&  ( $opt_database ) )
				{	lprint "No change to database\n" if ( ! $ret );
					lprint "Changed database\n" if ( $ret );
				}
		
			$file_counter++;
	
			next if ( ! $ret );
	
			$add_counter++ if ( $ret > 0 );
			$update_counter++ if ( $ret < 0 );
		}
	
	close INPUT;
	
	
	return;
}



################################################################################
# 
sub TestFile( $ )
#
#	Read a list of files and write out their file IDs in AppProcess.txt that are in the database
#
################################################################################
{	my $file = shift;
	
		
	lprint "Reading a list of files in $file ...\n";
	
	if ( ! open( INPUT, "<$file" ) )
		{	lprint "Unable to open file $file: $!\n";
			return;
		}
		
	
	if ( ! open( OUTPUT, ">AppProcess.txt" ) )
		{	lprint "Unable to open file AppProcess.txt: $!\n";
			return;
		}
		
	my $total = 0 + 0;
	my $found = 0 + 0;
	
	while ( my $line = <INPUT> )
		{	next if ( ! $line );
			
			chomp( $line );
			
			next if ( ! $line );
		
			my ( $file, $stuff ) = split /\: Infection:/, $line, 2;
			next if ( ! $file );

		
			my $file_id = &ApplicationFileID( $file );
			next if ( ! $file_id );
			
			my $hex_file_id = &StrToHex( $file_id );
			
			
			# Skip it if I don't have a valid file ID
			if ( length( $hex_file_id ) != 56 )
				{	print "Bad file ID\n" if ( $opt_verbose );
					next;
				}
			
			$total++;
				
			my ( $appName, $process, $desc, $manu, $recommended, $dangerous, $categoryNumber, $sourceNumber ) = &LookupHexFileID( $hex_file_id );
					
			if ( defined $appName )
				{	$categoryNumber = 0 + $categoryNumber;
					
					# Ignore file IDs that are already errors
					next if ( $categoryNumber == 7 );
					
					$found++;
					
					print OUTPUT "$hex_file_id\n";
					
					if ( $opt_verbose )
						{	lprint "total = $total, found = $found, file = $file\n";	
					
							lprint "Found matching file ID in database - $hex_file_id\n";
							
							lprint "Database appName: $appName\n" if ( defined $appName );
							lprint "Database process: $process\n" if ( defined $process );
							lprint "Database manu: $manu\n" if ( defined $manu );
							lprint "Database categoryNumber: $categoryNumber\n" ;
							lprint "\n";					
						}
				}			
		}
	
	close( INPUT );
	close( OUTPUT );
	
	&lprint( "Found $found file IDs out of $total total\n" );
	
	return;
}



################################################################################
# 
sub TestFileFileID( $ )
#
#	Read a text file of hex file IDs and set the ApplicationProcesses table to category '7' - errors
#
################################################################################
{	my $file = shift;
	
		
	lprint "Changing the file IDs in $file in the database to the errors category ...\n";
	
	if ( ! open( INPUT, "<$file" ) )
		{	lprint "Unable to open file $file: $!\n";
			return;
		}
		
	
	my $total = 0 + 0;
	my $found = 0 + 0;
	
	while ( my $line = <INPUT> )
		{	next if ( ! $line );
			
			chomp( $line );
			
			next if ( ! $line );
		
			my $hex_file_id = $line;
			next if ( ! $hex_file_id );
			$hex_file_id =~ s/^\s+//;
			next if ( ! $hex_file_id );
			$hex_file_id =~ s/\s+$//;
			next if ( ! $hex_file_id );
			
			
			# Skip it if I don't have a valid file ID
			if ( length( $hex_file_id ) != 56 )
				{	print "Bad file ID\n" if ( $opt_verbose );
					next;
				}
			
			$total++;
										
			my $sth;
			$sth = $dbh->prepare( "UPDATE ApplicationProcesses SET CategoryNumber = '7', TransactionTime = getutcdate() WHERE FileID = ? AND CategoryNumber <> '7'" );
					
			$sth->bind_param( 1, $hex_file_id,  DBI::SQL_VARCHAR );
			$sth->execute();

			$found++ if ( $sth->rows );
			
			&SqlErrorHandler( $dbh );
			$sth->finish();					
													
			lprint "Total $total, found $found, matching file ID\n" if ( ( $sth->rows )  &&  ( $opt_verbose ) );
		}
	
	close( INPUT );
	
	&lprint( "Changed $found file IDs out of $total total\n" );
	
	return;
}



################################################################################
#
sub GetInstalledApplications()
#
#  Load all the installed applications and possibles paths out of the registry
#
################################################################################
{
	my $key;
	my $type;
	my $data;
	
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, $key );


	# First get all the subkeys
	my @subkeys;
	my $uIndex = 0 + 0;
	while ( $ok )
		{	my $iolClass;
			my $iolName;
			my $subkey;
			$ok = RegEnumKeyEx( $key, $uIndex, $subkey, $iolName, [], [], $iolClass, [] );
			
			push @subkeys, $subkey if ( $ok );
				
			$uIndex++;
		}
		
	RegCloseKey( $key );
		
		
	# For each subkey get the DisplayName, the Install Location or the UninstallString
	foreach ( @subkeys )
		{	my $subkey = $_;
			
			my $fullkey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" . $subkey;

			my $newkey;
			$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, $fullkey, 0, KEY_READ, $key );

			if ( $ok )
				{
					$ok = RegQueryValueEx( $key, "DisplayName", [], $type, $data, [] );
					
					my $display_name;
					$display_name = $data if ( $ok );
	
					$ok = RegQueryValueEx( $key, "InstallLocation", [], $type, $data, [] );
					
					my $install_location;
					if ( $ok )
						{	$install_location = lc( $data );
							$install_location =~ s/\\$//;
						}
	
					$ok = RegQueryValueEx( $key, "UninstallString", [], $type, $data, [] );
					
					RegCloseKey( $key );

					my $uninstall_string;
					$uninstall_string = $data if ( $ok );

					push @applications, $display_name if ( $display_name );
					push @install_locations, $install_location if ( $install_location );
					push @uninstall_locations, $uninstall_string if ( $uninstall_string );
					
					$installed{ $install_location } = $display_name if ( ( $display_name )  &&  ( $install_location ) );
					$uninstalled{ $uninstall_string } = $display_name if ( ( $display_name )  &&  ( $uninstall_string ) );

					if ( $opt_debug )
						{	lprint "subkey = $subkey\n";
							lprint "display name = $display_name\n" if ( $display_name );	
							lprint "install_location = $install_location\n" if ( $install_location );	
							lprint "uninstall_string = $uninstall_string\n" if ( $uninstall_string );	
						}
				}
		}
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
		{	lprint "Can't open directory $dir_path: $!\n";
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
	return( undef ) if ( -d $file );
	
	
	my ( $dir, $short_file ) = &SplitFileName( $file );
	my $lcdir = lc( $dir );
	

	# Should I ignore this file?
	foreach( @ignore_list )
		{	next if ( ! $_ );
			my $ignore = $_;
				
			my $pos = index( $lcdir, $ignore );
			return if ( $pos > -1 );
		}


	# Is this the type of file that I can calculate a file ID for?
	my $scan_fileid_type = &ScanableFileID( $file, $opt_nonexecutable );
	
		
	if ( ( $opt_program )  ||  ( $opt_verbose ) )
		{	my $desc = &ScanableDescription( $scan_fileid_type );
			lprint "\nChecking File/Process: $file\n";
			lprint "Scan Type: $desc\n";
		}
		


	return( undef ) if ( ! $scan_fileid_type );
	
	# If this isn't an executable program, and I'm not supposed to calc this stuff, then return
	if ( ( $scan_fileid_type != 1 )  &&  ( ! $opt_nonexecutable ) )
		{	lprint "Ignoring this scan type\n" if ( ( $opt_program )  ||  ( $opt_verbose ) );
			return( undef );	
		}
		
		
	# Get what infomation I can out of the file itself
	my ( $app_name, $company, $description, $product_name ) = &GetFileInfo( $file );
	if ( ! defined $app_name )
		{	lprint "No file info available\n" if ( ( $opt_program )  ||  ( $opt_verbose ) );
			return( undef );	
		}
		

	# Am I forcing the app_name to something?
	$app_name = $windows_app_name if ( $opt_windows );
	$app_name = &VirusArchiveName( $dir ) if ( $opt_name );
	die "No application name is defined!\n" if ( ! $app_name );
	
	
	my $file_id = &ApplicationFileID( $file );
	
	# If no file id, bag it
	if ( ! $file_id )
		{	lprint "$file does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}
		
	my $hex_file_id = &StrToHex( $file_id );
	

	my $category_num = $opt_category_num;
	
	# Set the rec bit to whatever the command line was
	my $rec = $opt_rec;
	
	my $dang = $opt_dang;
	my $current = $opt_current;
	my $ports = "";
	
	my $fname = $short_file;
	$fname = $file if ( $opt_path );
	
	# Have I already seen this file ID?
	return if ( defined $file_id{ $file_id } );
	$file_id{ $file_id } = $fname;

			
	# Can I guess a category name from the directory?
	my $actual_category_num = &VirusGuessCategory( $file, $category_num, $app_name );

	
	my $ret = 1;
	if ( $opt_file )	
		{	print OUTPUT "$hex_file_id\t$fname\t$app_name\t$company\t$description\t$rec\t$dang\t$current\t$ports\t$actual_category_num\t$opt_source_num\n"; 
		}
	else	
		{	$ret = &UpdateAppProcessTable( $app_name, $company, $fname, $description, $ports, $hex_file_id, $rec, $dang, $current, $actual_category_num, $opt_source_num ) if ( $opt_database );			
		}
		

	# Show I show the info?
	if ( ( $opt_program )  &&  ( $ret ) )
		{	lprint "AppName: $app_name\n";			
			lprint "Company: $company\n";
			lprint "Description: $description\n" if ( $description );
			lprint "File ID: $hex_file_id\n";	
			
			if ( $opt_database )
				{	my $catname = &CategoryName( $actual_category_num );
					lprint "Category: $catname\n";
				}
		}
		
	if ( ( $opt_program )  &&  ( $opt_database ) )
		{	lprint "No change to database\n\n" if ( ! $ret );
			lprint "Changed database\n\n" if ( $ret );
		}
		
	$file_counter++;
	
	return if ( ! $ret );
	
	$add_counter++ if ( $ret > 0 );
	$update_counter++ if ( $ret < 0 );
}



################################################################################
# 
sub LookupHexFileID( $ )
#
#	Given a hex file ID, look it up in the database
#   Return undef if not found, or True and all the fields if it is found
#
################################################################################
{	my $hex_file_id	= shift;
	return( undef ) if ( ! defined $hex_file_id );
	
	my $sth;
	$sth = $dbh->prepare( "SELECT AppName, Process, Description, Manufacturer, Recommended, Dangerous, CategoryNumber, SourceNumber FROM ApplicationProcesses WITH(NOLOCK) WHERE FileID = ?" );
			
	$sth->bind_param( 1, $hex_file_id,  DBI::SQL_VARCHAR );
	$sth->execute();
	my ( $appName, $process, $desc, $manu, $recommended, $dangerous, $categoryNumber, $sourceNumber ) = $sth->fetchrow_array();
	$sth->finish();

	return( $appName, $process, $desc, $manu, $recommended, $dangerous, $categoryNumber, $sourceNumber );
}



################################################################################
# 
sub UpdateAppProcessTable( $$$$$ $$$ $$$ )
#
#	Put the new information into the database
#   Return 1 if added, -1 if changed, undef if an error, 0 if no change
#
################################################################################
{	my $app_name		= shift;
	my $company			= shift;
	my $file			= shift;
	my $description		= shift;
	my $ports			= shift;
	
	my $hex_file_id		= shift;
	my $rec				= shift;
	my $dang			= shift;
	
	my $current			= shift;
	my $category_num	= shift;
	my $source_num		= shift;
	
	
	return( 0 + 0 ) if ( ! $opt_database );
	
	my $len = length( $hex_file_id );
	if ( $len != 56 )
		{	lprint "Invalid file ID = $hex_file_id\n";
			return( 0 + 0 );
		}
		

	my $ok = &CheckFileIDCategory( $hex_file_id, $category_num );
	
	if ( ! $ok )
		{	print "File $file is in the NotVirus table with file ID $hex_file_id\n";
			exit( 1 );
		}
	
	
	# Make sure that stuff isn't too long
	$app_name		= substr( $app_name, 0, 255 )		if ( defined $app_name );
	$description	= substr( $description, 0, 511 )	if ( defined $description );
	$company		= substr( $company, 0, 255 )		if ( defined $company );
	
	
	# Fix up any quotes, etc
	$app_name		= &quoteurl( $app_name );
	$company		= &quoteurl( $company );
	$file			= &quoteurl( $file );
	$description	= &quoteurl( $description );
	
	$rec = $opt_rec if ( $opt_rec );
	
	
	# Make sure that the errors category has the recommended bit turned on
	# This makes sure that the file integrity file stays in sync with the fileID files
	$rec = 0 + 1 if ( $category_num == 7 );
	
	
	# Clean up the ports field
	$ports = "" if ( ! defined $ports );
	$ports =~ s/\s// if ( defined $ports );


	# Convert the columns to values for the insert
	my $vapp_name = "\'" . $app_name . "\'";
	my $vcompany = "\'" . $company . "\'";
	my $vfile = "\'" . $file . "\'";
	my $vdescription = "\'" . $description . "\'";
	my $vports = "\'" . $ports . "\'";
	my $vhex_file_id = "\'" . $hex_file_id . "\'";
	my $vrec = "\'" . $rec . "\'";
	my $vdang = "\'" . $dang . "\'";
	my $vcurrent = "\'" . $current . "\'";
	my $vcategory_num = "\'" . $category_num . "\'";
	my $vsource_num = "\'" . $source_num . "\'";
	
	my $permissions = $normal_permissions;
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	
	my $sth;
	$sth = $dbh->prepare( "SELECT AppName, Process, Description, Manufacturer, Recommended, Dangerous, CurrentVersion, CategoryNumber, SourceNumber, ProgramPermissions FROM ApplicationProcesses WITH(NOLOCK) WHERE FileID = ?" );
			
	$sth->bind_param( 1, $hex_file_id,  DBI::SQL_VARCHAR );
	$sth->execute();
	my $rows = 0 + $sth->rows;
	my ( $appName, $process, $desc, $manu, $recommended, $dangerous, $current_version, $categoryNumber, $sourceNumber, $program_permissions ) = $sth->fetchrow_array();

	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	
	# Did I find an existing process?
	my $ret = 0 + 1;

	if ( $rows )
		{
			# Check to see if I should overwrite an existing entry
			# Make sure everything is a number that I am comparing
			$recommended		= 0 + $recommended;
			$rec				= 0 + $rec;
			$dangerous			= 0 + $dangerous;
			$dang				= 0 + $dang;
			$current_version	= 0 + $current_version;
			$current			= 0 + $current;
			$sourceNumber		= 0 + $sourceNumber;
			$category_num		= 0 + $category_num;
			$categoryNumber		= 0 + $categoryNumber;
			
			if ( ( ! $opt_overwrite )  &&  ( ! $opt_mistake ) )
				{	# Was it entered by hand?  If so, don't change it
					if ( $sourceNumber < $opt_source_num )
						{	lprint "Not changing because the existing source number is $sourceNumber\n";
							return( 0 + 0 );
						}
					
					# Is the new category a test category and the other category a real category?
					if ( ( $category_num == 64 )  &&  ( $category_num != $categoryNumber ) )
						{	lprint "Not changing from $categoryNumber to the security.test category!\n";
							return( 0 + 0 );	
						}
					
					# Did important anything change?
					return( 0 + 0 ) if ( ( lc( $appName ) eq lc( $app_name ) )  &&
									( $categoryNumber == $category_num )  &&	
									( $recommended == $rec )  &&	
									( $dangerous == $dang )  &&	
									( lc( $file ) eq lc( $process ) )  &&	
									( $current_version == $current ) );	
					
					# If not importing in a virus file, then a different app name or version doesn't matter
					if ( ( $categoryNumber == 6 )  &&  ( $category_num == 6 ) )
						{	return( 0 + 0 ) if ( $appName ne $app_name );
							return( 0 + 0 ) if ( $current_version ne $current );
							return( 0 + 0 ) if ( $recommended != $rec );
							return( 0 + 0 ) if ( lc( $file ) ne lc( $process ) );
						}
				}


			# Am I correcting mistakes?
			if ( $opt_mistake )
				{	my $blocked = $dangerous;
					
					# Is it spyware or a virus?
					$blocked = 1 if ( $categoryNumber == 63 );
					$blocked = 1 if ( $categoryNumber == 62 );
					$blocked = 1 if ( $categoryNumber == 116 );
					
					return( 0 + 0 ) if ( ! $blocked );
					
					# Keep the same source number
					$vsource_num = "\'" . $sourceNumber . "\'";
					
					# Turn on recommended and turn off dangerous bits, set the category to business
					$vrec	= "\'1\'";
					$vdang	= "\'0\'";
					$vcategory_num = "\'6\'";
					
					lprint( "Correcting file ID $hex_file_id ...\n" );
				}
				
				
			$dbh = &SqlErrorCheckHandle( $dbh );

			my $str = "DELETE ApplicationProcesses WHERE FileID = ?";

			$sth = $dbh->prepare( $str );
			$sth->bind_param( 1, $hex_file_id,  DBI::SQL_VARCHAR );

			my $ok = $sth->execute();
			
			my $delete_rows = 0 + $sth->rows;

			lprint "Error deleting FileID $hex_file_id\n" if ( $delete_rows < 1 );
			$ok = undef if ( $delete_rows < 1 );
			
			&SqlErrorHandler( $dbh );
			$sth->finish();

			return( 0 + 0 ) if ( ! $ok );
			
			$ret = 0 - 1;
		}
	elsif ( $opt_mistake )		# Just return here if correcting mistakes
		{	return( 0 + 0 );
		}
		

	if ( ( $rows )  &&  ( $opt_program ) )
		{	# Print what changed
			print "Changed: New app name\n"			if ( lc( $appName ) ne lc( $app_name ) );
			print "Changed: New category number\n"	if ( $categoryNumber != $category_num );
			print "Changed: New recommended bit\n"	if ( $recommended != $rec );	
			print "Changed: New dangerous bit\n"	if ( $dangerous != $dang );	
			print "Changed: New process\n"			if ( lc( $file ) ne lc( $process ) );	
			print "Changed: New version\n"			if ( $current_version != $current );	
		}
	
		
	# Insert the row into the database
	$dbh = &SqlErrorCheckHandle( $dbh );
	
	my $str = "INSERT INTO ApplicationProcesses ( FileID, AppName, Process, Description, Manufacturer, Recommended, Dangerous, CurrentVersion, Ports, CategoryNumber, SourceNumber ) VALUES ( $vhex_file_id, $vapp_name, $vfile, $vdescription, $vcompany, $vrec, $vdang, $vcurrent, $vports, $vcategory_num, $vsource_num )";
	$str = "INSERT INTO ApplicationProcesses ( FileID, AppName, Process, Description, Manufacturer, Recommended, Dangerous, CurrentVersion, Ports, CategoryNumber, SourceNumber, ProgramPermissions ) VALUES ( $vhex_file_id, $vapp_name, $vfile, $vdescription, $vcompany, $vrec, $vdang, $vcurrent, $vports, $vcategory_num, $vsource_num, \'$permissions\'  )";

	&lprint( "SQL Statement: $str\n" ) if ( $opt_verbose );

	$sth = $dbh->prepare( $str );
	
	$ok = $sth->execute();

	$rows = 0 + $sth->rows;

	lprint "Error inserting FileID $hex_file_id\n" if ( $rows != 1 );
	
	&SqlErrorHandler( $dbh );
	
	$sth->finish();

	return( $ret ) if ( $ok );
	
	return( 0 + 0 );
}



################################################################################
#
sub CheckFileIDCategory( $$ )
#
#  Given a hex file ID, and a category number, check to see against the NotVirus
#  table if this is a good idea.
#
#  Return OK if this is OK, undef if not
#
################################################################################
{	my $hex_file_id		= shift;
	my $category_num	= shift;
	
	
	# Is it in a virus category?  If not, then it is OK
	return( 1 ) if ( ( $category_num != 62 )  &&  ( $category_num != 63 )  &&  ( $category_num != 125 ) );

	my $str = "SELECT FileID from NotVirus WITH(NOLOCK) where FileID = '$hex_file_id'";
	my $sth = $dbh->prepare( $str );
	
	my $ok = $sth->execute();

	my $rows = 0 + $sth->rows;

	&SqlErrorHandler( $dbh );
	
	$sth->finish();
	
	# Did I find a match?  If so, then I have this file ID in the NotVirus table
	return( undef ) if ( $rows );
	
	# Return OK
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
    my $me = "AppProcess";

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
    my $me = "AppProcess";
	
    print <<".";

Usage: scan [list]
Scan a list of directories and/or files to build file IDs for .exes

Possible options are:

  -0, --remote          use remote database TrafficRemote
  -a, --append          append to the existing file
  -c, --category=cat    set the category name of the applications
  -d, --database        don\'t add the app/process info to the database
  -f, --file NAME.TXT   write the results to a text file called NAME.TXT
  -i, --insert          insert the app process file into the database
  -m, --mistake         set any blocked programs found to unblocked
                        in the database
  -n, --name            set the application name to Virus Archive format
  -o, --overwrite       overwrite existing file IDs in the database
  -p, --program         show the info for each program found
  -q, --TESTFILEID      Read a list of File IDs and set them to errors in
                        the database
  -r, --recommended     turn on the recommended bit for each program found
  -s, --source SNUM     the source number to use for inserts - default is 3
  -t, --test TESTFILE   read a list of virus infected files and write out in
                        AppProcess.txt their File IDs that are in the database
  -u, --update          turn on inherit bit for an update package
  -v, --verbose         show work as it progresses
  -w, --windows         label all the app processes as Windows OS  
  -x, --nonexecutable   find info for scanable files that are not .exes
  -h, --help            print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
