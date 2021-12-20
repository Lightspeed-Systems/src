################################################################################
#!perl -w
#
# ArchiveCompress - compress the archive downloaded token, link, and label files
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;
use File::Copy;
use Archive::Zip qw( :ERROR_CODES );

use Content::File;
use Content::Archive;


# Options
my $opt_help;
my $opt_version;
my $opt_startdir;				# This is the directory of to start working in


my $main_dest_directory			= 'I:\\HashArchive';	# This is the root of the main archive directory

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
        "s|startdir=s"		=>	\$opt_startdir,

        "v|version"			=>	\$opt_version,
        "h|help"			=>	\$opt_help
    );
	

    &StdHeader( "Archive Compress" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


    my $curdir = getcwd;
    $curdir =~ s#\/#\\#gm;

		
	# Process the current directory
	opendir( CURDIR, $curdir );


	print "Cleaning up the archive files in $curdir and subdirectories ...\n";
	
	my $start_reached = 1 if ( ! defined $opt_startdir );
	
	while ( my $file = readdir( CURDIR ) )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			$file = lc( $file );
			
			my $dir = $curdir . "\\" . $file;
			
			# Skip regular files
			next if ( ! -d $dir );
	
			$start_reached = 1 if ( ( ! $start_reached )  &&  ( $file eq lc( $opt_startdir ) ) );
								   
			# Skip if I haven't reached the starting directory
			next if ( ! $start_reached );
			
			&ArchiveCompress( $dir );
		}


	closedir( CURDIR );

		
	&StdFooter;

    exit;
}



################################################################################
#
sub ArchiveCompress()
#
#  Given a directory, compress all the archive files found
#
################################################################################
{	my $dir = shift;
	
	# Process the given directory
	my $dir_handle;
	opendir( $dir_handle, $dir );
	die "Unable to open $dir\n" if ( ! defined $dir_handle );


	my $dest_dir;
	my $dest_zip;
	my $dump_files = 0 + 0;
	
	print "Checking $dir ...\n";
	
	while ( my $file = readdir( $dir_handle ) )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			my $subdir = $dir . "\\" . $file;
			
			# Process subdirectories
			if ( -d $subdir )
				{	&ArchiveCompress( $subdir );
				}
			else	# It must be an ordinary file 
				{	$file = lc( $file );

					my $is_dump_zip = 1	if ( $file =~ m/\.dump\.zip$/ );
					next if ( ! $is_dump_zip );
					
					my $domain = $file;
					$domain =~ s/\.dump\.zip//;
					
					( $dest_dir, $dest_zip ) = &DomainDestinationDir( $main_dest_directory, $domain ) if ( ! defined $dest_dir );
					
					# If I found a dump file then count it
					$dump_files++;

					# Have I found a bunch of files?
					last if ( $dump_files > ( 0 + 200 ) );
				}
		}

	closedir( $dir_handle );


	# If I didn't find enough stuff I can quit here
	return( 1 ) if ( $dump_files < ( 0 + 200 ) );
	
	
	# Zip up everything in the destination dir
	if ( defined $dest_dir )
		{	print "Zipping up all the dump zip files in $dest_dir ...\n";
			&ArchiveZipDestDir( $dest_dir, $dest_zip );
		}
		
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "ArchiveCompress";
    print <<".";
Usage: $me [OPTION(s)]

Just a temp program to compress the archive of downloaded tokens files.
    
  -s, --startdir=SOURCEDIR   starting directory to begin work
  -h, --help                 display this help and exit
  -v, --version              display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "ArchiveCompress";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
