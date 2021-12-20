################################################################################
#!perl -w
#
#  VirusArchive - go recursively through the not virus archive making sure that
#  each good program is entered into the Program database OK
#
#  Copyright 2010 Lightspeed Systems Inc. by Rob McCarthy
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
use Win32API::Registry 0.21 qw( :ALL );


use Content::File;
use Content::Category;
use Content::FileInfo;



my $opt_help;
my $opt_verbose;					# True if I should be verbose about what I am doing
my $opt_debug;


my $dbhApplication;				# The handle to the Application database
my $dbhProgram;


my $add_count		= 0 + 0;
my $update_count	= 0 + 0;



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
        "v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help,
        "x|xdebug"		=> \$opt_debug
      );


    &StdHeader( "NotVirusArchive" );
	&Usage() if ( $opt_help );

	print "Debugging ...\n" if ( $opt_debug );

#	&TrapErrors() if ( ! $opt_debug );
	
	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	if ( ! ( $cwd =~ m/NotVirus Archive/i ) )
		{	print "This utility is designed to only work in one of the NotVirus Archive directories\n";
			exit( 1 );	
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


	# Recursively go through the NotVirus archive
	&NotVirusDir( $cwd );

	
	$dbhApplication->disconnect if ( $dbhApplication );
	$dbhApplication = undef;

	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;

	print "Updated the database for $update_count files\n"		if ( $update_count );
	print "Added $add_count files to the database\n"			if ( $add_count );

	&StdFooter;
	
	exit( 0 + 0 );
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
	my $filename = "NotVirusArchiveErrors.log";
	
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
sub NotVirusDir( $ )
#
#  Process the given directory
#
################################################################################
{	my $dir = shift;
	
	
	print "Checking directory $dir ...\n" if ( $opt_verbose );

	
	if ( ! ( $dir =~ m/NotVirus Archive/i ) )
		{	print "This utility only works when run in one of the NotVirus Archive directories\n";
			exit( 1 );
		}
		
		
		
	my $current_dir_handle;
	if ( ! opendir( $current_dir_handle, $dir ) )
		{	print "Error opening source directory $dir: $!\n";
			return( undef );
			
		}

	
	my @file_list;
	my $valid_dir;
	my $dest_dir;
	
	
	while ( my $file = readdir( $current_dir_handle ) )
		{	next if ( ! defined $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			my $full_file = "$dir\\$file";
			
			# Check subdirectories
			if ( -d $full_file )			
				{	&NotVirusDir( $full_file );
					next;
				}

			# Is it a real file?
			next if ( ! -f $full_file );

			# With real data?
			next if ( ! -s $full_file );
							
							
			# Check to make sure the program database is correct
			my $ret = &CheckProgramDatabase( $full_file );
			
			next if ( ! $ret );
			
			$add_count++ if ( $ret > 0 );
			$update_count++ if ( $ret < 0 );
 		}

	closedir( $current_dir_handle );

		
	return( 1 );	
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
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	
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
sub CheckProgramDatabase( $ )
#
#	Make sure the not virus entry is right in the Program database
#
################################################################################
{	my $file	= shift;
	
	
	return( undef ) if ( ! defined $file );
	
	print "Checking $file ...\n" if ( $opt_verbose );
	
	
	# Figure out the MD5 hash value from the filename
	my ( $dir, $short ) = &SplitFileName( $file );
	return( undef ) if ( ! defined $short );
	return( undef ) if ( ! defined $dir );
	
	my ( $md5, $ext ) = split /\./, $short;
	
	# Make sure the length is right
	return( undef ) if ( length( $md5 ) != 32 );
	
	$md5 = lc( $md5 );
	
	# Make sure it is a valid MD5
	return( undef) if ( $md5 =~ m/[^0-9a-f]/ );
	

	
	# Get all the file info that I can
	my %file_info;
	my @sections;
	my $ok = &FileInfo( $file, \%file_info, \@sections, $opt_verbose );	
	return( undef ) if ( ! $ok );
		
	my $file_id = $file_info{ FileID };
	
	# If no file id, bag it
	if ( ! $file_id )
		{	print "$file does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}

	
	# If not a Win32/Win64 file then don't add it to the database	
	my $scan_fileid_type = $file_info{ ScanableFileID };
	if ( ! $scan_fileid_type )
		{	print "Not scanable by File ID\n" if ( $opt_verbose );
			return( undef );
		}
		
	return( undef ) if ( $scan_fileid_type != 1 );
	
	
	# Can I find the original file name in the NotVirus table on the Application SQL server?
	my $hex_file_id = $file_info{ HexFileID };
		
	my $str = "SELECT [Filename] FROM NotVirus WHERE FileID = '$hex_file_id'";
	
	my $sth = $dbhApplication->prepare( $str );
	$sth->execute();
	
	my ( $original_filename ) = $sth->fetchrow_array();
	
	$sth->finish();

	print "Found original filename = $original_filename\n" if ( ( $original_filename )  &&  ( $opt_verbose ) );
	

	# Figure out the final filename that this will have in the NotVirus archive
	my $hex_md5 = $file_info{ HexMD5 };

	# If no hex md5, bag it
	if ( ! $hex_md5 )
		{	print "$file does not have a Hex MD5 value\n";
			return( undef );
		}
		
	
	my $sub1 = substr( $hex_md5, 0, 2 );
	my $sub2 = substr( $hex_md5, 2, 2 );


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
	
	my $full_dir = "R:\\NotVirus Archive" . "\\$subdir" . "\\$sub1" . "\\$sub2";
	my $final_file = $full_dir . "\\$short";

	print "Final filename = $final_file\n" if ( $opt_verbose );

	$file_info{ Filename } = $final_file;
	
	
	# If I found the original filename then normalize it and add it into the database
	if ( defined $original_filename )
		{	$ok = &FileInfoOriginalFilename( $original_filename, \%file_info );	
			return( undef ) if ( ! $ok );
		}
		
		
	# Set the right category number for a NotVirus
	my $category_num = 0 + 6;
	$file_info{ CategoryNumber } = $category_num;
	
	my $ret = &CategoryUpdateFileInfo( \%file_info, \@sections, 1 );
	
	return( $ret );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";

Usage: NotVirusArchive

This utility goes recursively through the Not Virus Archive making sure that
the Not Virus files are entered into the Program database correctly.

Possible options are:

  -v, --verbose         verbose mode
  -h, --help            print this message and exit

.

exit( 0 + 13 );
}



################################################################################

__END__

:endofperl
