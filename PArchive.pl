################################################################################
#!perl -w
#
# PArchive - archives downloaded program files
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;
use DBI qw(:sql_types);
use DBD::ODBC;


use Content::File;
use Content::Archive;
use Content::Category;
use Content::ScanUtil;
use Content::FileIntegrity;
use Content::SQL;
use Content::FileInfo;
use Content::Scanable;



# Options
my $opt_help;
my $opt_verbose;
my $opt_nocopy;
my $opt_keep;					# If True, then keep the local program files after archiving
my $opt_filearchive;			# If True, then connect to the IpmStatistics database on SandboxGW and update the Program database on Program
my $opt_maxfiles = 0 + 1000;	# This is the maximum number of files to move in one shot


# This is the list in string format of the program urls file extension that I am interested in - removed .js,.java, .class, &.jar
my $interested_extensions = ".exe.cab.msi.dll.ocx.vbd.cpl.scr.bat.pif.cmd.zip.bz2.rar.php.html.png.aspx.asp.htm.swf.ini.cgi.";


my $opt_source_directory;												# This is the directory of token, link, and label files to archive
my $main_dest0_directory			= "P:\\Program Archive";			# This is the root of the main program archive directory for x00 to x7f
my $main_dest1_directory			= "O:\\Program Archive 2";			# This is the root of the main program archive directory for x80 to xff


my @prog_dir	= (	"S:\\Current1",
				   "S:\\Current2",
				   "S:\\Current3",
				   "S:\\Current4",
				   "S:\\Current5",
				   "S:\\Current6",
				   "S:\\Current7",
				   "S:\\Current8",
				   "S:\\Current9" );

my $_version = "1.0.0";


my $dbhProgram;						# The handle to the Program database
my $dbhSandboxGW;					# The handle to the SandboxGW statistics database
my $running_count = 0 + 0;
my $deleted_count = 0 + 0;



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
        "f|filearchive"		=>	\$opt_filearchive,
        "k|keep"			=>	\$opt_keep,
        "m|maxfiles=i"		=>	\$opt_maxfiles,
        "n|nocopy"			=>	\$opt_nocopy,
        "s|source=s"		=>	\$opt_source_directory,
        "v|verbose"			=>	\$opt_verbose,
        "h|help"			=>	\$opt_help
    );
	

    &StdHeader( "PArchive" );


	# Read the command line
	$opt_source_directory = shift if ( ! $opt_source_directory );
	
	
	# If nothing specified, then use the current directory as the source directory
	if ( ( ! $opt_source_directory )  ||  ( $opt_source_directory eq "." ) )
		{	$opt_source_directory = getcwd;
			$opt_source_directory =~ s#\/#\\#gm;	
		}
		
	my $str = shift;
	$main_dest0_directory = $str if ( $str );
	
	$str = shift;
	$main_dest1_directory = $str if ( $str );


    &Usage() if ( $opt_help );


	if ( ! -d $opt_source_directory )
		{	print "Can not find source directory $opt_source_directory\n";
			exit( 0 );
		}

	if ( ! -d $main_dest0_directory )
		{	print "Can not find archive directory 0 $main_dest0_directory\n";
			exit( 0 );
		}

	if ( ! -d $main_dest1_directory )
		{	print "Can not find archive directory 1 $main_dest1_directory\n";
			exit( 0 );
		}


	# Do I need to add additional file extensions?
	if ( $opt_filearchive )
		{	$interested_extensions .= "htm.html.php.bz.zip.asp.aspx.cgi.png.swf.";
		}
		
	
	# Find a program directory to write programs to for later virus analysis
	my $prog_dir = $prog_dir[ 0 ];	# Default to the first program directory
	
	if ( ! $opt_nocopy )
		{	my $last_dir;
			foreach ( @prog_dir )
				{	next if ( ! $_ );
					
					my $pdir = $_;
					$prog_dir = $pdir if ( -d $pdir );	# Use the last main program directory that exists
					$last_dir = $pdir;
				}
			
			if ( ! -d $prog_dir )
				{	print "Can not find virus program directory $prog_dir\n";
					exit( 0 );
				}
			
			# If the last program dir exists, and the first program dir exists, use the first program dir, i.e.
			# loop around a program directory queue
			$prog_dir = $prog_dir[ 0 ] if ( ( -d $prog_dir[ 0 ] )  &&  ( $last_dir )  &&  ( -d $last_dir ) );
			
			print "Program copying from directory $opt_source_directory to $prog_dir ...\n";
		}
		
		
	$dbhProgram = &ConnectRemoteProgram();
			
	if ( ! $dbhProgram )
		{
lprint "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";
			exit( 1 );
		}
	
				
	# Do I need to open the database for the SandboxGW filearchive?
	if ( $opt_filearchive )
		{	$dbhSandboxGW = &ConnectSandboxGW();
			
			if ( ! $dbhSandboxGW )
				{
lprint "Unable to open the SandboxGW Statistics database.
Run ODBCAD32 and add the SandboxGW SQL Server as a System DSN named
\'SandboxGW\' with default database \'IpmStatistics\'.\n";

					ProgramClose() if ( $dbhProgram );
					
					exit( 1 );
				}
		}	# end of if $opt_filearchive
		
		

	print "Program archiving from directory $opt_source_directory ...\n";
	print "Archive copying program files from x00 to x7f to directory $main_dest0_directory ...\n";
	print "Archive copying program files from x80 to xff to directory $main_dest1_directory ...\n";
	print "Interested file extentions: $interested_extensions\n";
	
	
		
	# Process the source directory
	die "Error opening directory $opt_source_directory: $!\n" if ( ! opendir( DIR, $opt_source_directory ) );

	print "Loading up program files to copy and archive ...\n";
	my @files;
	
	while ( my $file = readdir( DIR ) )
		{	next if ( ! $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			# Check subdirectories
			if ( -d $file )			
				{	my $subdir = "$opt_source_directory\\$file";
					my @subfiles = &Subdirectory( $subdir, 1 );
					push @files, @subfiles;		
					$running_count += 1 + $#subfiles;
				}
			else	# Normal files
				{	my $full_file = "$opt_source_directory\\$file";
					
					# Should I ignore it?
					if ( ( $opt_filearchive )  &&  ( $file =~ m/^temp/i ) )
						{	next;
						}
						
					my ( $name, $ext ) = split /\./, $file, 2;

					$name = lc( $name );
					my $len = length( $name ) if ( defined $name );
					
					if ( ( ! $len )  ||  ( $len != 32 )  ||  ( $name =~ m/[^0-9,a-f]/ ) )
						{	lprint "Deleting $file - not an md5 hash file name!\n";
							unlink( $full_file );
							$deleted_count++;
						}
					elsif ( &ProgramExt( $file ) )
						{	push @files, $full_file;
							$running_count++;
						}
					else
						{	print "Deleting non-executable file $full_file ...\n";
							unlink( $full_file );
							$deleted_count++;
						}
				}
				
			last if ( $running_count >= $opt_maxfiles );	
 		}

	closedir( DIR );


	my $fcount = $#files + 1;
	print "Found $fcount program files to copy and archive ...\n";
	print "Deleted $deleted_count non-executable files ...\n";
	
	
	# Do I need to open the databases for the SandboxGW filearchive?
	if ( $opt_filearchive )
		{	my @renamed_files;
			print "Updating the Program database with file info from SandboxGW ...\n";
			my $ok = &ProgramDatabaseUpdate( \@files, \@renamed_files );
			if ( ! $ok )
				{	print "Error updating the Program database from SandboxGW\n";
									
					# Close any databases that I opened
					ProgramClose()		if ( $dbhProgram );
					CloseSandboxGW()	if ( $dbhSandboxGW );
					
					exit( 2 );	
				}
			
			# Set the files array to the renamed file array
			@files = @renamed_files;
		}

		
	if ( ! $opt_nocopy )
		{	print "Waiting 60 seconds for all copies to finish ...\n";
			sleep( 60 );

			print "Program virus copying to $prog_dir ...\n";
			my $ok = &ArchiveVirusCopyFiles( $opt_source_directory, $prog_dir, \@files );
			if ( ! $ok )
				{	print "Error virus copying program files\n";
					
					# Close any databases that I opened
					ProgramClose()		if ( $dbhProgram );
					CloseSandboxGW()	if ( $dbhSandboxGW );
					
					exit( 2 );	
				}
		}
		
		
		
	print "Program archive copying for x00 to x6f to $main_dest0_directory ...\n";
	print "Program archive copying for x70 to xff to $main_dest1_directory ...\n";
	&PArchive( $opt_source_directory, $main_dest0_directory, $main_dest1_directory, \@files, $opt_keep ) if ( $#files > -1 );


	# Close any databases that I opened
	ProgramClose()		if ( $dbhProgram );
	CloseSandboxGW()	if ( $dbhSandboxGW );

	
	if ( ! $opt_keep )
		{	print "Removing empty directories from $opt_source_directory ...\n";
			my $removed = &EmptyDir( $opt_source_directory );
			print "Removed $removed empty directories\n";
		}
		
	
	&StdFooter;

    exit;
}



################################################################################
#
sub ProgramDatabaseUpdate( $$ )
#
#  Given the source directory, and a list of files,
#  update the Program database with info from the SandboxGW Statistics database
#  Return True if everything worked OK
#
################################################################################
{	my $files_ref			= shift;
	my $renamed_files_ref	= shift;
		
	
	my $count		= 0 + 0;
	my $ok_count	= 0 + 0;
	
	foreach ( @$files_ref )
		{	my $file = $_;
			next if ( ! $file );
			$count++;

			next if ( ! -f $file );
			
			my $file_size = -s $file;	
	
			next if ( ! $file_size );

			# Get all the file info that I can
			my %file_info;
			my @sections;
			my $ok = &FileInfo( $file, \%file_info, \@sections, $opt_verbose );
			next if ( ! $ok );
			
			
			# Calculate the MD5 hash to use as the file name
			my $hex_md5 = $file_info{ HexMD5 };

			# Skip it if I didn't get a good md5 hash
			next if ( ! $hex_md5 );
				
			my ( $fullpath, $renamed, $deleted ) = &RenameMD5( $file, $hex_md5 );
			next if ( ! $fullpath );
		
			push @$renamed_files_ref, $fullpath;


			# Is this a Win32/Win64 file that I should add to the Programs database?
			my $scan_fileid_type = $file_info{ ScanableFileID };

			if ( ( $scan_fileid_type )  &&  ( $scan_fileid_type == 1 ) )
				{	# Make sure that the filename in the Program database is the final filename it will end up with in the
					# Program Archive
					my $dest = &PArchiveFilename( $file, $main_dest0_directory, $main_dest1_directory );
					next if ( ! $dest );
					$file_info{ Filename } = $dest;
					
					my $ret = &CategoryUpdateFileInfo( \%file_info, \@sections, undef );
					next if ( ! defined $ret );
				}
				
			
			next if ( ! $opt_filearchive );


			# Find the URL that the program file was downloaded from
			my ( $dir, $short_file ) = &SplitFileName( $file );
			my $qfile = &quoteurl( $short_file );

			my $str = "SELECT URL FROM TrafficClassFileRecords WHERE FileName = \'$qfile\'";
			my $sth = $dbhSandboxGW->prepare( $str );
			$sth->execute();
			
			my ( $prog_url ) = $sth->fetchrow_array();
			my $url = &RootDomain( $prog_url ) if ( $prog_url );
			
			$sth->finish();


			# Don't try to save the Program Link if I didn't actually find one
			next if ( ! $prog_url );
			
			my $hex_file_id = $file_info{ HexFileID };
			next if ( ! $hex_file_id );
			
			&CategorySaveProgramLink( $hex_file_id, $prog_url, $url );
			
			$ok_count++;
		}
		
	print "Found $count programs total\n";
	print "Found $ok_count program links in the Statistics database\n" if ( $opt_filearchive );
	
	return( 1 );	
}



################################################################################
# 
sub RenameMD5( $$ )
#
#  Given a full path filename, rename it to the MD5 file name, and return the new
#  name, and the rename status.  Delete duplicate files. Return undef if an error
#
################################################################################
{	my $fullpath	= shift;
	my $hex_md5		= shift;
	
	my ( $dir, $shortfile ) = &SplitFileName( $fullpath );
	
	my $ext;
	
	my @parts = split /\./, $shortfile;
	
	# Is there a name extension?
	if ( $#parts > 0 )
		{	$ext = lc( $parts[ $#parts ] );
			$ext .= "_" if ( ! ( $ext =~ m/_$/ ) );
		}

	# Clean up the extension
	if ( $ext )
		{	$ext =~ s/\s+//g;
			$ext = lc( $ext ) if ( $ext );
			$ext = undef if ( ( $ext )  &&  ( $ext eq "_" ) );
		}
		
	if ( $ext )
		{	$ext = undef if ( length( $ext ) > 5 );
			$ext = undef if ( ( $ext )  &&  ( length( $ext ) < 3 ) );
		}
		
	my $new_name = $hex_md5;
	$new_name = $hex_md5 . "." . $ext if ( $ext );
	
	my $full_new_name = $new_name;
	$full_new_name = $dir . "\\" . $new_name;
	
	# Is the file already named the right thing?
	return( $full_new_name, undef, undef ) if ( $full_new_name eq $fullpath );
	
	my $ok = rename( $fullpath, $full_new_name );


	# If renamed ok, return here
	if ( $ok )
		{	return( $full_new_name, 1, undef );
		}
		
		
	# If not ok, was it because the file already exists?
	if ( -f $full_new_name )
		{	rename( $full_new_name, $full_new_name );  # Rename it again to make sure the upper/lowercase is right

			# Is there an upper/lower case problem?
			if ( lc( $fullpath ) eq lc( $full_new_name ) )
				{	return( $full_new_name, 1, undef );
				}
				
			# Get rid of the duplicate	
			unlink( $fullpath );
			return( $full_new_name, undef, 1 );
		}
	
	# If I got to here, then I couldn't rename it at all
	return( $fullpath, undef, undef );
}



################################################################################
#
sub EmptyDir( $ )
#
#  Given a directory, delete all the empty subdirectories
#
################################################################################
{	my $dir = shift;
	
	my $removed = 0 + 0;
	my $count = 0 + 0;

	return( $removed ) if ( ! $dir );
	return( $removed ) if ( ! -d $dir );
	
	return( $removed ) if ( ! opendir( MAINDIR, $opt_source_directory ) );
	
	while ( my $file = readdir( MAINDIR ) )
		{	next if ( ! $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			# Check subdirectories
			next if ( ! -d $file );
	
			$count++;
			last if ( $count > $opt_maxfiles );
			
			my $subdir = "$dir\\$file";

			my $files = &Subdirectoryfiles( $subdir );

			next if ( $files );
			
			print "Removing empty subdirectory $subdir ...\n" if ( $opt_verbose );
			
			rmdir( $subdir );
			
			$removed++;
		}

	closedir( MAINDIR );
	
	return( $removed );
}



################################################################################
#
sub Subdirectory( $$ )
#
#  Given a directory, return a list of the files in the directory
#
################################################################################
{	my $dir				= shift;
	my $programs_only	= shift;	# If true, then return only programs
	
	my @subfiles;
	
	return( @subfiles ) if ( ! $dir );
	return( @subfiles ) if ( ! -d $dir );
	
	# Process the source directory
	my $dir_handle;
	return( @subfiles ) if ( ! opendir( $dir_handle, $dir ) );

	while ( my $file = readdir( $dir_handle ) )
		{	next if ( ! $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );	
			
			my $full_file = "$dir\\$file";
			
			if ( -d $full_file )
				{	my @recursive = &Subdirectory( $full_file, $programs_only );
					push @subfiles, @recursive;
				}
			elsif ( $programs_only )
				{	# Should I ignore it?
					if ( ( $opt_filearchive )  &&  ( $file =~ m/^temp/i ) )
						{	next;
						}	

					my ( $name, $ext ) = split /\./, $file, 2;

					$name = lc( $name );
					my $len = length( $name ) if ( defined $name );
					
					if ( ( ! $len )  ||  ( $len != 32 )  ||  ( $name =~ m/[^0-9,a-f]/ ) )
						{	lprint "Deleting $file - not an md5 hash file name!\n";
							unlink( $full_file );
							$deleted_count++;
						}
					elsif ( &ProgramExt( $file ) )
						{	push @subfiles, $full_file;
						}
					else
						{	print "Deleting non-executable file $full_file ...\n";
							unlink( $full_file );
							$deleted_count++;
						}					
				}
			else 
				{	push @subfiles, $full_file;
				}
		}

	closedir( $dir_handle );

	return( @subfiles );
}



################################################################################
#
sub Subdirectoryfiles( $ )
#
#  Given a directory, return TRUE if there are files inside it
#
################################################################################
{	my $dir	= shift;
		
	return( undef ) if ( ! $dir );
	return( undef ) if ( ! -d $dir );
	
	# Process the source directory
	my $dir_handle;
	return( undef ) if ( ! opendir( $dir_handle, $dir ) );

	my $files;	# True if there is a regular file in the directory
	
	while ( my $file = readdir( $dir_handle ) )
		{	next if ( ! $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );	
			
			my $full_file = "$dir\\$file";
			
			if ( -d $full_file )
				{	my $files = &Subdirectoryfiles( $full_file );
				}
			else 
				{	$files = 1;
				}
				
			last if ( $files );	
		}

	closedir( $dir_handle );

	return( $files );
}



################################################################################
#
sub ProgramExt( $ )
#
#  Given a file, return True if it looks like a file that should be archived
#
################################################################################
{	my $file = shift;

	return( undef ) if ( ! $file );
	
	my $lc_file = lc( $file );
	$lc_file =~ s/_+$//;	# Trim off any trailing underscores
	
	# Does the extension match one of the program extensions?
	my @parts = split /\./, $lc_file;
		
	my $ext = $parts[ $#parts ];
	$ext = lc( $ext );
	my $len = length( $ext );
	
	return( undef ) if ( ! $len );
	
	# Is the extension the right length?  It should be 2 or 3 or 4 chars long
	if ( ( $len == 4 )  ||  ( $len == 3 )  ||  ( $len == 2 ) )
		{	my $qext = "." . $ext . ".";
			$qext = quotemeta( $qext );
			
			# Does the extension match one of the program extensions?
			return( 1 ) if ( $interested_extensions =~ m/$qext/ );
		}
	
	return( undef );
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "PArchive [sourcedir] [archivedir0] [archivedir1]";
    print <<".";
Program Archive utility - copies program files from the source directory
to directory S:\\Current? for virus processing, and then archives the 
program files to:
$main_dest0_directory
$main_dest1_directory

Usage: $me [OPTION(s)]

    
  -f, --filearchive        process program files from the SandboxGW archive
  -k, --keep               keep the local copy after program archiving
  -n, --nocopy             do NOT do virus program copying.
  -s, --source=SOURCEDIR   source directory of program files to archive.
                           Default is the current directory.
  -h, --help               display this help and exit
  -v, --version            display version information and exit
.
    exit;
}



################################################################################

__END__

:endofperl
