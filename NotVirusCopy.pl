################################################################################
#!perl -w
#
# NotVirusCopy - Copy NotVirus files over to the Program Archive
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;
use File::Copy;


use Content::File;
use Content::Archive;



# Options
my $opt_help;
my $opt_verbose;


my $total_count = 0 + 0;

# This is the list in string format of the program urls file extension that I am interested in
my $interested_extensions = ".exe.cab.msi.dll.ocx.vbd.cpl.scr.bat.pif.cmd.js.java.class.jar.zip.bz2.rar.php.html.png.aspx.asp.htm.swf.ini.cgi.";


my $opt_source_directory;												# This is the directory of token, link, and label files to archive
my $main_dest0_directory			= "P:\\Program Archive";			# This is the root of the main program archive directory for x00 to x7f
my $main_dest1_directory			= "O:\\Program Archive 2";			# This is the root of the main program archive directory for x80 to xff



my $_version = "1.0.0";



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
        "s|source=s"		=>	\$opt_source_directory,
        "v|verbose"			=>	\$opt_verbose,
        "h|help"			=>	\$opt_help
    );
	

    &StdHeader( "NotVirusCopy" );


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
		{	print "Can not find program archive directory 0 $main_dest0_directory\n";
			exit( 0 );
		}

	if ( ! -d $main_dest1_directory )
		{	print "Can not find program archive directory 1 $main_dest1_directory\n";
			exit( 0 );
		}
		
		

	print "Program archiving from directory $opt_source_directory ...\n";
	print "Archive copying program files from x00 to x7f to directory $main_dest0_directory ...\n";
	print "Archive copying program files from x80 to xff to directory $main_dest1_directory ...\n";
	print "Interested file extentions: $interested_extensions\n";
	
		
	&DirectoryCommand( $opt_source_directory, $main_dest0_directory, $main_dest1_directory );
		
	
	print "Total files copied: $total_count\n";
	
	&StdFooter;

    exit;
}



################################################################################
#
# 
sub DirectoryCommand( $$$ )
#
#  Recursively go though a directory structure
#
################################################################################
{	my $dir			= shift;
	my $dest0_dir	= shift;
	my $dest1_dir	= shift;


	chdir( $dir );
	my $dir_handle;
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";

	my $count = 0 + 0;
	while ( my $subdir = readdir( $dir_handle ) )
		{	
			next if ( ! defined $subdir );

			next if ( $subdir eq "." );
			next if ( $subdir eq ".." );

			my $fulldir = "$dir\\$subdir";
	
			if ( -d $fulldir )
				{	&DirectoryCommand( $fulldir, $dest0_dir, $dest1_dir );
					chdir( $dir );
				}
			else
				{	my $fullfile = $fulldir;
					my $copied = &NotVirusCopy( $fullfile, $dest0_dir, $dest1_dir );
					
					# Keep count of how many files I copied
					if ( $copied )
						{	$count++;
							$total_count++;
						}
				}
		}


	closedir( $dir_handle );

	print "Copied $count files from $dir\n" if ( ( $count )  ||  ( $opt_verbose ) );
	return( 0 );
}



################################################################################
# 
sub NotVirusCopy( $$$ )
#
#	Given a filename, make sure that it is in MD5 format, and copy it to the
#	Program Archive if it is not already there.  Return True if copied OK, undef 
#   if not (or undef if it already existed)
#
################################################################################
{	my $fullfile	= shift;
	my $dest0_dir	= shift;
	my $dest1_dir	= shift;


	# Does the file exist?  It might have been deleted by another task
	return( undef ) if ( ! -f $fullfile );

	# Does the file extension match one that I am interested in?
	return( undef ) if ( ! &ProgramExt( $fullfile ) );

	# Figure out the MD5 hash value from the filename
	my ( $dir, $short ) = &SplitFileName( $fullfile );
	return( undef ) if ( ! defined $short );
	return( undef ) if ( ! defined $dir );
	
	my ( $md5, $ext ) = split /\./, $short;
	
	# Make sure the length is right
	return( undef ) if ( length( $md5 ) != 32 );
	
	$md5 = lc( $md5 );
	
	# Make sure it is a valid MD5
	return( undef) if ( $md5 =~ m/[^0-9a-f]/ );

			
	my $dest = &PArchiveFilename( $fullfile, $dest0_dir, $dest1_dir );
	return( undef ) if ( ! $dest );
			
	# Get the final directory name ...
	my ( $final_dir, $short_file ) = &SplitFileName( $dest );
						
	&MakeDirectory( $final_dir );
			
	if ( ! -d $final_dir )
		{	print "Unable to make destination directory $final_dir\n";
			exit( 0 );
		}
	
	
	if ( lc( $fullfile ) eq lc( $dest ) )
		{	print "Skipping $fullfile - source and destination paths are the same!\n";
			next;	
		}
			
				
	# Is the source file empty?
	if ( ! -s $fullfile )
		{	# If the source is empty then delete the target to save disk space from empty files
			print "Removing empty file $fullfile\n";
			unlink( $fullfile );
			return( undef );
		}
	elsif ( -s $dest )
		{	print "$dest has not changed\n" if ( $opt_verbose );
			return( undef );
		}
		
		
	# Copy the file
	print "Copying $fullfile to $dest ...\n";
	my $success = copy( $fullfile, $dest );
			
	if ( ! $success )
		{	print "File copy error: $!\n";
			print "Source file: $fullfile\n";
			print "Destination file: $dest\n";
			exit( 0 );
		}
		
	return( 1 );
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
    my $me = "NotVirusCopy [sourcedir] [archivedir0] [archivedir1]";
    print <<".";
NotVirusCopy utility - copies program files from the source directory
to the Program Archive.

$main_dest0_directory
$main_dest1_directory

Usage: $me

    
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
