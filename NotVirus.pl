################################################################################
#!perl -w
#
# NotVirus - archives not virus files for virus scanning testing
#
# Rob McCarthy 3/18/2008
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;
use DBI qw(:sql_types);
use DBD::ODBC;
use File::Copy;


use Content::File;
use Content::Scanable;
use Content::SQL;
use Content::FileIntegrity;
use Content::Category;
use Content::FileInfo;



# Options
my $opt_help;
my $opt_verbose;
my $opt_name;			# If true then check for the existance to the filename in the NotVirus table
my $opt_unlink;			# If set, the read a list of MD5 values to delete, and delete them
my $opt_debug;


my $source_directory	= ".";							# This is the source directory
my $old_directory		= 'R:\\NotVirus Archive';		# This is the root of the old NotVirus archive directory
my $dest_directory		= 'R:\\NewNotVirus Archive';	# This is the root of the new NotVirus archive directory

my $dbhApplication;				# The handle to the Application database
my $dbhProgram;					# Handle to the Program database

my $total_copied = 0 + 0;
my $total_checked = 0 + 0;


# This is the list of directories and files to ignore
my @ignore_list = (
"\\Temporary ASP.NET Files",
"\\VSWebCache",
"\\Temporary Internet Files",
"\\System Volume Information",
"\\Mail Archive",
"\\RECYCLER",
"HOMEDRIVE\\hiberfil.sys",
"HOMEDRIVE\\pagefile.sys",
"\\hiberfil.sys",
"\\pagefile.sys",
"\\SecurityAgent\\ScanTemp",
"\\SecurityAgent\\quarantine",
"\\SecurityAgent\\Tmp"
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
		"d|destination=s"	=> \$dest_directory,
		"n|name"			=> \$opt_name,
		"s|source=s"		=> \$source_directory,
		"u|unlink=s"		=> \$opt_unlink,
		"v|verbose"			=> \$opt_verbose,
        "h|help"			=> \$opt_help,
        "x|xdebug"			=> \$opt_debug
    );
	

    &StdHeader( "NotVirus" );
	

    &Usage() if ( $opt_help );


	# Do I have a list to unlink?
	if ( $opt_unlink )
		{	die "Unable to find MD5 list file $opt_unlink\n" if ( ! -f $opt_unlink );
			
			&UnlinkMD5( $opt_unlink );
			exit( 0 );
		}

	# If nothing specified, then use the current directory as the source directory
	if ( ( ! $source_directory )  ||  ( $source_directory eq "." ) )
		{	$source_directory = getcwd;
			$source_directory =~ s#\/#\\#gm;	
		}

	if ( ! -d $dest_directory )
		{	print "Can not find New NotVirus archive directory $dest_directory\n";
			exit( 0 );
		}

	if ( ! -d $old_directory )
		{	print "Can not find Old NotVirus archive directory $old_directory\n";
			exit( 0 );
		}

	if ( ! -d $source_directory )
		{	print "Can not find source directory $source_directory\n";
			exit( 0 );
		}


	# Check that I am not copying to myself
	if ( lc( $dest_directory ) eq lc( $source_directory ) )
		{	print "Can not archive to myself\n";
			exit( 0 );
		}
		
	# Check that I am not copying to myself
	if ( lc( $old_directory ) eq lc( $source_directory ) )
		{	print "Can not archive to myself\n";
			exit( 0 );
		}
	
	
	# I need to open the Application database
	$dbhApplication = &ConnectRemoteApplication();
			
	if ( ! $dbhApplication )
		{
lprint "Unable to open the Remote Application database.
Run ODBCAD32 and add the APPLICATION SQL Server as a System DSN named
\'ApplicationRemote\' with default database \'IpmContent\'.\n";
			exit( 1 );
		}
				

	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

					exit( 0 + 5 );
		}


	print "NotVirus archiving from directory $source_directory to $dest_directory ...\n";
	print "Also using old NotVirus directory $old_directory ...\n";
	print "Check for the existance of files in the NotVirus archive by original file name ...\n" if ( $opt_name );

	
	&TrapErrors() if ( ! $opt_debug );

		
	# Process the source directory
	&NotVirusArchive( $source_directory, $dest_directory, $old_directory );
	
	
	# Close any databases that I opened
	$dbhApplication->disconnect if ( $dbhApplication );
	$dbhApplication = undef;
		
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
		
	print "Checked $total_checked files\n";
	print "Copied $total_copied files\n";
	
	
	&StdFooter;

    exit;
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $dir = &SoftwareDirectory();
	my $filename = "NotVirusErrors.log";
	
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	print "Unable to open $filename: $!\n";  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	print "Error trapping set to file $filename ...\n"; 
	
	return( 1 );
}



################################################################################
#
sub HashDelete( )
#
#  Temp function
#
################################################################################
{
	
	open( HASHLIST, "<hashlist.txt" ) or die "Error opening hashlist: $!\n";
	
	while ( my $line = <HASHLIST> )
		{	chomp( $line );
			next if ( ! $line );
			my $renamed = $line;
	
			my $sub1 = substr( $renamed, 0, 2 );
			my $sub2 = substr( $renamed, 2, 2 );
			
			
			my $subdir = "AppSlave01";
			
			if ( ( $sub1 ge "40" )  &&  ( $sub1 lt "80" ) )
				{	$subdir = "AppSlave02";
				}
			elsif ( ( $sub1 ge "80" )  &&  ( $sub1 lt "c0" ) )
				{	$subdir = "AppSlave03";
				}
			elsif ( $sub1 ge "c0" )
				{	$subdir = "AppSlave04";
				}
			
			my $full_dir = "R:\\NewNotVirus Archive\\" . $subdir . "\\$sub1" . "\\$sub2";
			
			if ( ! -d $full_dir )
				{	print "Could not find $full_dir\n";
					next;
				}
				
			print "chdir = $full_dir\n";
			chdir( $full_dir );
			
			my $cmd = "del $renamed.*";
			print "cmd = $cmd\n";
			system $cmd;
		}
		
	close( HASHLIST );
}



################################################################################
#
sub HashCopy( )
#
#  Temp function
#
################################################################################
{
	
	open( HASHLIST, "<hashlist.txt" ) or die "Error opening hashlist: $!\n";
	
	while ( my $line = <HASHLIST> )
		{	chomp( $line );
			next if ( ! $line );
			my $renamed = $line;
	
			my $sub1 = substr( $renamed, 0, 2 );
			my $sub2 = substr( $renamed, 2, 2 );
			
			
			my $subdir = "AppSlave01";
			
			if ( ( $sub1 ge "40" )  &&  ( $sub1 lt "80" ) )
				{	$subdir = "AppSlave02";
				}
			elsif ( ( $sub1 ge "80" )  &&  ( $sub1 lt "c0" ) )
				{	$subdir = "AppSlave03";
				}
			elsif ( $sub1 ge "c0" )
				{	$subdir = "AppSlave04";
				}
			
			my $full_dir = "C:\\$subdir" . "\\$sub1" . "\\$sub2";
			
			if ( ! -d $full_dir )
				{	print "Could not find $full_dir\n";
					next;
				}
				
			print "chdir = $full_dir\n";
			chdir( $full_dir );
			
			my $cmd = "del $renamed.*";
			print "cmd = $cmd\n";
			system $cmd;
		}
		
	close( HASHLIST );
}



################################################################################
# 
sub ConnectRemoteApplication()
#
#  Find and connect to the remote Content database SQL Server, if possible.  
#  Return undef if not possible
#
#  This function is mainly called by the Categorize command
#
################################################################################
{  	
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
sub NotVirusArchive( $$$ )
#
#  Process the given source directory to the target directory
#
################################################################################
{	my $src_dir = shift;
	my $dst_dir = shift;
	my $old_dir	= shift;
	
	
	print "Checking directory $src_dir ...\n" if ( $opt_verbose );


	# Check to make sure that I shouldn't ignore this directory	
	foreach ( @ignore_list )
		{	next if ( ! defined $_ );
			my $ignore = $_;
			if ( $ignore eq $src_dir )
				{	print "Ignoring $src_dir ...\n" if ( $opt_verbose );
					return( 1 );	
				}
				
			my $quoted = quotemeta( $ignore );
			
			if ( $src_dir =~ m/$quoted$/ )
				{	print "Ignoring $src_dir ...\n" if ( $opt_verbose );
					return( 1 );	
				}
		}

	
	my $current_dir_handle;
	if ( ! opendir( $current_dir_handle, $src_dir ) )
		{	print "Error opening source directory $src_dir: $!\n";
			return( undef );
			
		}

	
	while ( my $file = readdir( $current_dir_handle ) )
		{	next if ( ! $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			my $full_file = "$src_dir\\$file";
			
			# Check subdirectories
			if ( -d $full_file )			
				{	&NotVirusArchive( $full_file, $dst_dir, $old_dir );
				}
			else	# Normal files
				{	my $scanable = &Scanable( $full_file, 1 );
					next if ( ! $scanable );
					
					# Also ignore text files
					next if ( $file =~ m/\.txt$/i );
					next if ( $file =~ m/\.txt_$/i );
					
					next if ( $file =~ m/\.log$/i );
					next if ( $file =~ m/\.log_$/i );
					
					next if ( $file =~ m/\.xml$/i );
					next if ( $file =~ m/\.xml_$/i );
					
					my $final_file_name = &CopyArchive( $full_file, $dst_dir, $old_dir );					
					next if ( ! $final_file_name );

					# Add it to the Program database as a known good program if it is a Win32/Win64 program
					next if ( $scanable != 1 );
					
					# Get all the file info that I can
					my %file_info;
					my @sections;
					my $ok = &FileInfo( $full_file, \%file_info, \@sections, $opt_verbose );	
					next if ( ! $ok );
					
					$ok = &FileInfoOriginalFilename( $full_file, \%file_info );	
					next if ( ! $ok );

					# Set the file as category 6
					$file_info{ CategoryNumber } = 0 + 6;
					
					# Set the filename in the Program database as the file name that it will end up as in the Not Virus Archive
					$file_info{ Filename } = $final_file_name;
					
					&CategoryUpdateFileInfo( \%file_info, \@sections, 1 );
				}
 		}

	closedir( $current_dir_handle );

	return( 1 );	
}



################################################################################
#
sub CopyArchive( $$$ )
#
#  Given the a full path of a file, copy it to the NotVirus archive if it isn't 
#  already there.  Update the NotVirus table
#
#  Return the final file location if everything worked OK
#
################################################################################
{	my $file	= shift;
	my $dst_dir = shift;
	my $old_dir	= shift;
	
	
	$total_checked++;
	
	
	# Calculate the MD5 hash to use as the file name
	my $hex_md5 = &HexMD5File( $file );

	# Skip it if I didn't get a good md5 hash
	return( undef ) if ( ! $hex_md5 );
				
	my ( $renamed ) = &RenameMD5( $file, $hex_md5 );
	return( undef ) if ( ! $renamed );
		

	my $sub1 = substr( $renamed, 0, 2 );
	my $sub2 = substr( $renamed, 2, 2 );
	
	
	my $subdir = "AppSlave01";
	
	if ( ( $sub1 ge "40" )  &&  ( $sub1 lt "80" ) )
		{	$subdir = "AppSlave02";
		}
	elsif ( ( $sub1 ge "80" )  &&  ( $sub1 lt "c0" ) )
		{	$subdir = "AppSlave03";
		}
	elsif ( $sub1 ge "c0" )
		{	$subdir = "AppSlave04";
		}


	my $old_full_dir = $old_dir . "\\$subdir" . "\\$sub1" . "\\$sub2";
	&MakeDirectory( $old_full_dir );
	
	if ( ! -d $old_full_dir )
		{	print "Unable to make destination directory $old_full_dir: $!\n";
			exit( 0 );
		}


	my $old_final_file = $old_full_dir . "\\$renamed";
	
	
	# Should I check the NotVirus table using the filename to see if I already have this in the NotVirus archive?
	if ( $opt_name )
		{	my $qfile = &quoteurl( $file );

			my $str = "SELECT FileID FROM NotVirus WHERE [Filename] = '$qfile'";
			
			my $sth = $dbhApplication->prepare( $str );
			$sth->execute();
			
			my $rows = $sth->rows;
			
			$sth->finish();
			
			# Was there any rows?
			print "$file is already in the NotVirus table by name\n" if ( ( $rows )  &&  ( $opt_verbose ) );
			return( $old_final_file ) if ( $rows );
		}
		

	# Does this file already exist in the NotVirus table?
	# I had to add this in when we moved the NotVirus Archive to a new drive - Rob M 7-18-2012
	if ( &CheckNotVirusTable( $hex_md5) )
		{	return( $old_final_file );
		}
	

	
	# First - does this file already exist in the old NotVirus archive?
	# If so, then I don't have to do anything
	if ( ( -d $old_full_dir )  &&  ( -f $old_final_file ) )
		{	return( $old_final_file );
		}
	
	
	my $full_dir = $dst_dir . "\\$subdir" . "\\$sub1" . "\\$sub2";
	&MakeDirectory( $full_dir );
	
	if ( ! -d $full_dir )
		{	print "Unable to make destination directory $full_dir: $!\n";
			exit( 0 );
		}

	my $final_file = $full_dir . "\\$renamed";
	
	
	# If the file already exists, then I just have to check the database
	if ( -f $final_file )
		{	my $str = "SELECT FileID FROM NotVirus WHERE MD5 = '$hex_md5'";
			
			my $sth = $dbhApplication->prepare( $str );
			$sth->execute();
			
			my $rows = $sth->rows;
			
			$sth->finish();
			
			# Was there any rows?
			print "$file is already in the NotVirus table\n" if ( ( $rows )  &&  ( $opt_verbose ) );
			return( $old_final_file ) if ( $rows );
			
			my $ok = &InsertNotVirus( $file, $hex_md5 );
			if ( ! $ok )
				{	print "Error inserting the file data into NotVirus table\n";
					exit( 0 );
				}
			
			return( $old_final_file );
		}
	
	
	# The file doesn't exist, so I have to copy it
	print "Copying $file to $final_file ...\n";
	my $ok = copy( $file, $final_file );
	
	if ( ! $ok )
		{	print "Error copying $file to $final_file: $!\n";
			exit( 0 );
		}
	

	# Also copy it to the main Not Virus archive directory
	print "Copying $file to $old_final_file ...\n";
	$ok = copy( $file, $old_final_file );
	
	if ( ! $ok )
		{	print "Error copying $file to $old_final_file: $!\n";
			exit( 0 );
		}
	

	$ok = &InsertNotVirus( $file, $hex_md5 );
	if ( ! $ok )
		{	print "Error inserting the file data into NotVirus table\n";
			exit( 0 );
		}
	
	$total_copied++;
	
	return( $old_final_file );	
}



################################################################################
#
sub InsertNotVirus( $$ )
#
#  Given a filename, insert the file data into the NotVirus table
#
################################################################################
{	my $file	= shift;
	my $hex_md5 = shift;
	
	return( undef ) if ( ! $file );
	return( undef ) if ( ! $hex_md5 );
	
	# Calculate the file ID
	my $file_id = &ApplicationFileID( $file );
	
	# Skip it if I didn't get a good file ID
	return( undef ) if ( ! $file_id );
	
	print "Adding $file to the NotVirus table ...\n" if ( $opt_verbose );
	
	my $hex_file_id = &StrToHex( $file_id );
	
	my $short_file = substr( $file, 0, 250 );
	my $qfile = &quoteurl( $short_file );

	# Now update the NotVirus table in the database
	my $str = "INSERT INTO NotVirus ( FileID, MD5, Filename ) VALUES ( \'$hex_file_id\', \'$hex_md5\', \'$qfile\' )";

	my $sth = $dbhApplication->prepare( $str );
	$sth->execute();
	
	if ( $dbhApplication->err )
		{	print "SQL Error inserting into NotVirus, str = $str\n";
			my $errmsg = $dbhApplication->errstr;
			my $err	= $dbhApplication->err;
			$errmsg = "SQL error number = $err" if ( ! $errmsg );
			print "$errmsg\n";
			exit( 1 );
		}
		
	$sth->finish();

	return( 1 );
}



################################################################################
#
sub CheckNotVirusTable( $ )
#
#  Given a MD5 hash, check to see if it is already in the NotVirus table
#  Return TRUE if it is in the table, undef if not
#
################################################################################
{	my $hex_md5 = shift;
	
	return( undef ) if ( ! $hex_md5 );
	

	# Now update the NotVirus table in the database
	my $str = "SELECT FileID FROM NotVirus WHERE MD5 = \'$hex_md5\'";

	my $sth = $dbhApplication->prepare( $str );
	$sth->execute();
	
	if ( $dbhApplication->err )
		{	print "SQL Error checking MD5 hash $hex_md5 in table NotVirus, str = $str\n";
			my $errmsg = $dbhApplication->errstr;
			my $err	= $dbhApplication->err;
			$errmsg = "SQL error number = $err" if ( ! $errmsg );
			print "$errmsg\n";
			exit( 1 );
		}
		
	my $rows = $sth->rows;

	$sth->finish();


	# Did I find anything?
	print "$hex_md5 is already in the NotVirus table\n" if ( ( $rows )  &&  ( $opt_verbose ) );
	return( 1 ) if ( $rows );
	
	return( undef );
}



################################################################################
#
sub HexMD5File( $ )
#
#  Given a filename, return the hex MD5 hash, or undef if an error
#
################################################################################
{	my $file = shift;

use Digest::MD5;

	return( undef ) if ( ! $file );
	
	return( undef ) if ( ! -s $file );
					
	open( MD5HANDLE, $file ) or return( undef );
	
	binmode( MD5HANDLE );
	
	my $md5 = Digest::MD5->new;

	$md5->new->addfile( *MD5HANDLE );
	
	my $hex_md5 = $md5->hexdigest;

	close( MD5HANDLE );	
	
	return( $hex_md5 );
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
	
	return( $new_name );
}



my $last_dir;	# The last directory that I checked
################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Return OK if I just checked this directory
	return( 1 ) if ( ( $last_dir )  &&  ( $last_dir eq $dir ) );
		
	# Return OK if the directory already exists
	if ( -d $dir )
		{	$last_dir = $dir;
			return( 1 );
		}

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
	
	# Did it create OK?
	return( undef ) if ( ! -d $dir );	
	
	$last_dir = $dir;
	
	return( 1 );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
# 
sub UnlinkMD5( $ )
#
#	Given a file containing a list of MD5 values, delete matching files from
#   the NotVirus directories
#
################################################################################
{	my $delete_list = shift;
	
	open( DELETE_LIST, "<$delete_list" ) or die "Error opening $delete_list: $!\n";
	
	
	while ( my $line = <DELETE_LIST> )
		{	chomp( $line );
			next if ( ! $line );
			
			# Is it the right length for an MD5 value?
			next if ( length( $line ) != 32 );
			
			my $sub1 = substr( $line, 0, 2 );
			my $sub2 = substr( $line, 2, 2 );
			
			
			my $subdir = "AppSlave01";
			
			if ( ( $sub1 ge "40" )  &&  ( $sub1 lt "80" ) )
				{	$subdir = "AppSlave02";
				}
			elsif ( ( $sub1 ge "80" )  &&  ( $sub1 lt "c0" ) )
				{	$subdir = "AppSlave03";
				}
			elsif ( $sub1 ge "c0" )
				{	$subdir = "AppSlave04";
				}
	
	
			# First - does this file already exist ing the old NotVirus archive?
			# If so, then I don't have to do anything
			my $old_full_dir = $old_directory . "\\$subdir" . "\\$sub1" . "\\$sub2\\$line.*";

			my $cmd = "del \"$old_full_dir\"";
			print "Cmd: $cmd\n";
			system $cmd;
			
			my $full_dir = $dest_directory . "\\$subdir" . "\\$sub1" . "\\$sub2\\$line.*";

			$cmd = "del \"$full_dir\"";
			print "Cmd: $cmd\n";
			system $cmd;
		}
		
	close( DELETE_LIST );
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "NotVirus";
    print <<".";
NotVirus Archive utility - copies scanable files from the source directory
to directory $dest_directory for virus signature checking.

Usage: $me [OPTION(s)]

    
  -d, --dest=NOTVIRUSDIR   root directory to save the NotVirus files to.
                           Default is $dest_directory
  -n, --name               Check for the existance of the files in the NotVirus
                           archive using the filename  
  -s, --src=SOURCEDIR      source directory to copy the NotVirus files from.
                           Default is the current directory

  -u, --unlink MD5LIST     Given a list of MD5 values, delete matching files 
                           from NotVirus.
  -h, --help               display this help and exit
  -v, --version            display version information and exit
.
    exit;
}



################################################################################

__END__

:endofperl
