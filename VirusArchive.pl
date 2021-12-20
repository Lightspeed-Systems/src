################################################################################
#!perl -w
#
#  VirusArchive - go recursively through the virus archive making sure that
#  each virus is stored in the proper directory
#
#  Copyright 2009 Lightspeed Systems Inc. by Rob McCarthy
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
use String::CRC32;
use Win32::File::VersionInfo;


use Content::File;
use Content::ScanUtil;
use Content::Scanable;
use Content::SQL;
use Content::Category;
use Content::FileIntegrity;
use Content::FileInfo;



my $opt_help;
my $opt_verbose;					# True if I should be verbose about what I am doing
my $opt_debug;
my $opt_startdir;					# If set, this the the first subdirectory to start processing in
my $file_version;					# If set, just get the file version info of the given file
my $opt_num_subdir;						# If set, then just go this level down in subdirectories


my $dbhProgram;
my $add_count		= 0 + 0;
my $move_count		= 0 + 0;
my $update_count	= 0 + 0;
my $found_startdir;




################################################################################
#
MAIN:
#
################################################################################
{

	# Get the options
	Getopt::Long::Configure("bundling");

	my $options = Getopt::Long::GetOptions
       ("f|fileversion=s" => \$file_version,
        "n|numsubdir=i"	  => \$opt_num_subdir,
        "s|startdir=s"	  => \$opt_startdir,
        "v|verbose"		  => \$opt_verbose,
        "h|help"		  => \$opt_help,
        "x|xdebug"		  => \$opt_debug
      );


    &StdHeader( "VirusArchive" );
	&Usage() if ( $opt_help );

	print "Debugging ...\n" if ( $opt_debug );


	# Am I just checking to see if I can figure out file version info?
	if ( $file_version )
		{	if ( ! -f $file_version )
				{	print "Unable to find file $file_version\n";
					exit( 0 );	
				}
				
			my $finfo = &GetFileVersionInfo( $file_version );
	
			if ( $finfo )
				{
				}
				
			exit( 0 );
		}
		
		
	print "Starting directory $opt_startdir\n" if ( $opt_startdir );

	print "Only go $opt_num_subdir subdirectory levels deep\n" if ( $opt_num_subdir );
	
	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 0 + 5 );
		}


#	&TrapErrors() if ( ! $opt_debug );


	&VirusDir( $cwd );
	

	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;

	print "Moved $move_count files to different directories\n"	if ( $move_count );
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
	my $filename = "VirusArchiveErrors.log";
	
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	&lprint( "Unable to open $filename: $!\n" );  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	print "Error trapping set to file $filename ...\n"; 
	
	return( 1 );
}



my $subdir_level = 0;
################################################################################
#
sub VirusDir( $ )
#
#  Process the given directory
#
################################################################################
{	my $dir = shift;
	
	
	print "Checking directory $dir ...\n" if ( $opt_verbose );

	
	if ( ! ( $dir =~ m/^q:\\virus archive/i ) )
		{	print "This utility only works when run in the directory Q:\\Virus Archive\n";
			exit( 1 );
		}
		
		
	# Does this directory have a valid virus name?	
	my $virus = &VirusArchiveName( $dir );
	return( 1 ) if ( ! defined $virus );
		
	my $current_dir_handle;
	if ( ! opendir( $current_dir_handle, $dir ) )
		{	print "Error opening source directory $dir: $!\n";
			return( undef );
			
		}

	
	my @file_list;
	my $valid_dir;
	my $dest_dir;
	
	$subdir_level++;
	
	while ( my $file = readdir( $current_dir_handle ) )
		{	next if ( ! defined $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			my $full_file = "$dir\\$file";
			
			
			if ( ( $opt_startdir )  &&  ( ! $found_startdir ) )
				{	if ( lc( $opt_startdir ) eq lc( $file ) )
						{	print "Found starting directory $opt_startdir\n";
							$found_startdir = 1;
							
							next;
						}
					elsif ( -d $full_file )			
						{	&VirusDir( $full_file ) if ( ( ! $opt_num_subdir )  ||  ( $opt_num_subdir >= $subdir_level ) );
							next;
						}
					else
						{	next;
						}
				}
				
				
			# Check subdirectories
			if ( -d $full_file )			
				{	&VirusDir( $full_file ) if ( ( ! $opt_num_subdir )  ||  ( $opt_num_subdir >= $subdir_level ) );
				}
			
			# Have I already figured out that this is a valid dir?	
			if ( $valid_dir )
				{	# Check to make sure the program database is correct
					&CheckProgramDatabase( $full_file, $virus );
					next;
				}

			# Is it a real file?
			next if ( ! -f $full_file );

			# With real data?
			next if ( ! -s $full_file );
							
			# Is it a normal file and I need to figure out if it is in the right place?
			if ( ! defined $dest_dir )
				{	my $virus_dir = &VirusTypeDir( $virus );
					
					$dest_dir = "Q:\\Virus Archive" . "\\$virus";
					$dest_dir = "Q:\\Virus Archive" . "\\$virus_dir" . "\\$virus" if ( defined $virus_dir ); 
					
					# Do they match?
					if ( lc( $dir ) eq lc( $dest_dir ) )
						{	$valid_dir = 1;
							print "$dir is a valid virus archive directory\n" if ( $opt_verbose );
							
							# Check to make sure the program database is correct
							&CheckProgramDatabase( $full_file, $virus );
							next;
						}
						
					# If they don't match then I need to copy them to the right place
					push @file_list, $full_file;
				}
				
			# It is a normal file, and it isn't in the right place	
			elsif ( defined $dest_dir )
				{	push @file_list, $full_file;
				}
 		}

	closedir( $current_dir_handle );

	$subdir_level--;

	return( 1 ) if ( $valid_dir );
	return( 1 ) if ( $#file_list < 0 );
	
	
	# Move the files into the right place
	foreach( @file_list )
		{	my $full_file = $_;
			next if ( ! defined $full_file );
			
			my $dest = &VirusCopy( $full_file, $dest_dir );
			exit( 1 ) if ( ! $dest );
			
			$move_count++;
			
			unlink( $full_file );
			
			# Check to make sure the program database is correct
			&CheckProgramDatabase( $dest, $virus );
		}
		
	return( 1 );	
}



################################################################################
# 
sub VirusCopy( $$ )
#
#	Copy the file to the right directory.  Return the filename created.  Exit
#   if a problem happens
#
################################################################################
{	my $file		= shift;
	my $dest_dir	= shift;

	
	# If I can't make the directory then this is a real problem
	my $ok = &MakeDirectory( $dest_dir );
	if ( ! $ok )
		{	print "Error making directory $dest_dir: $!\n";
			exit( 0 + 8 );
		}
	
	my ( $dir, $short ) = &SplitFileName( $file );	
	my $dest = $dest_dir . "\\$short";
	
	# Add an underscore the file destination filename if it doesn't already have one
	$dest =~ s/\_+$//;
	$dest .= '_' if ( ! ( $dest =~ m/\_$/ ) );
	
	# Check to make sure that I'm not copying to myself
	if ( lc( $file ) eq lc( $dest ) )
		{	print "Source and destination are the same, so skipping copy ...\n";
			return(  $dest);
		}
		
	print "Copying $file to $dest ...\n";
	
	$ok = copy( $file, $dest );
	
	# Copy errors are a real problem!
	if ( ! $ok )
		{	my $err = $^E;
			print "Error copying $file to $dest: $err\n";
			return( $file );
		}
			
		
	return( $dest );
}



################################################################################
# 
sub CheckProgramDatabase( $$ )
#
#	Make sure the virus entry is right in the Program database
#
################################################################################
{	my $file	= shift;
	my $virus	= shift;
	
	
	return( undef ) if ( ! defined $file );
	return( undef ) if ( ! defined $virus );
	
	
	print "Checking file $file ...\n" if ( $opt_verbose );
	
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
	
	my $sth;
	$sth = $dbhProgram->prepare( "SELECT Filename FROM Programs WITH(NOLOCK) WHERE MD5 = ?" );
			
	$sth->bind_param( 1, $md5,  DBI::SQL_VARCHAR );
	$sth->execute();
	my $rows = 0 + $sth->rows;
	my $db_filename = $sth->fetchrow_array();

	$sth->finish();

	
	# If the filename doesn't exist in the database then add it
	if ( ! defined $db_filename )
		{	my $ret = &AddProgramDatabase( $file, $virus, undef );
			
			if ( $ret )
				{	$add_count++;
					print "Added $file into the Program database\n" if ( $opt_verbose );
				}
		}
	else	# Just update the database
		{	my $ret = &AddProgramDatabase( $file, $virus, 1 );
			
			if ( $ret )
				{	$update_count++;
					print "Updated $file in the Program database\n" if ( $opt_verbose );
				}
		}
		
		
	return( 1 );
}



################################################################################
# 
sub AddProgramDatabase( $$$ )
#
#	Make sure the virus entry is right in the Program database
#
################################################################################
{	my $file		= shift;
	my $virus		= shift;
	my $overwrite	= shift;


	# Get all the file info that I can
	my %file_info;
	my @sections;
	my $ok = &FileInfo( $file, \%file_info, \@sections, $opt_verbose );	
	return( undef ) if ( ! $ok );
		
	my $file_id = $file_info{ FileID };
	
	# If no file id, bag it
	if ( ! $file_id )
		{	print "$file does not have a file ID\n";
			return( undef );
		}

	
	# If not a Win32/Win64 file then don't add it to the database	
	my $scan_fileid_type = $file_info{ ScanableFileID };
	return( undef ) if ( ! $scan_fileid_type );
	return( undef ) if ( $scan_fileid_type != 1 );
	
	
	my $type = &VirusTypeName( $virus );
	
	# Set the virus info into the file info hash
	$file_info{ VirusType } = $type;
	$file_info{ Virus }		= $virus;
	$file_info{ AppName }	= $virus;

	# Set the right category number for this type of virus
	my $category_num = VirusGuessCategory( $file, 0 + 63, $virus );
	$file_info{ CategoryNumber } = $category_num;
	
	my $ret = &CategoryUpdateFileInfo( \%file_info, \@sections, $overwrite );
	
	return( $ret );
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
sub Usage
#
################################################################################
{
    print <<".";

Usage: VirusArchive

This utility goes recursively through the Virus Archive making sure that the
virus files are in the proper directory.  If the files are not in the proper
directory then this utility moves them.


Possible options are:

  -n, --numsubdir NUM   the level of subdirectories to go down
  -s, --startdir        directory to start in
  -v, --verbose         verbose mode
  -h, --help            print this message and exit

.

exit( 0 + 13 );
}



################################################################################

__END__

:endofperl
