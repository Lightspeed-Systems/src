################################################################################
#!perl -w
#
# EmptyDir - remove empty directories from the source directory
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Cwd;


# Options
my $opt_help;
my $opt_verbose;
my $opt_source_directory;

my $total 	= 0 + 0;
my $removed	= 0 + 0;

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
	

 
	# Read the command line
	$opt_source_directory = shift if ( ! $opt_source_directory );
	
	
	# If nothing specified, then use the current directory as the source directory
	if ( ( ! $opt_source_directory )  ||  ( $opt_source_directory eq "." ) )
		{	$opt_source_directory = getcwd;
			$opt_source_directory =~ s#\/#\\#gm;	
		}
		

    &Usage() if ( $opt_help );


	if ( ! -d $opt_source_directory )
		{	print "Can not find source directory $opt_source_directory\n";
			exit( 0 );
		}

	
	print "Removing empty subdirectories from $opt_source_directory ...\n";

	#  Figure out what directory to use
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;

	my $local_removed = &EmptyDir( $opt_source_directory );

	$removed += $local_removed;

	chdir( $cwd );

	print "Removed $removed empty subdirectories from $opt_source_directory\n";
	
	print "\nDone\n";

    exit;
}



################################################################################
#
sub EmptyDir( $ )
#
#  Given a directory, delete all the empty subdirectories
#
################################################################################
{	my $dir = shift;
	
	my $local_removed = 0 + 0;

	return( $local_removed ) if ( ! $dir );
	return( $local_removed ) if ( ! -d $dir );
	
	return( $local_removed ) if ( ! opendir( MAINDIR, $opt_source_directory ) );
	
	while ( my $file = readdir( MAINDIR ) )
		{	next if ( ! $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			# Check subdirectories
			next if ( ! -d $file );
	
			my $subdir = "$dir\\$file";

			my $files = &Subdirectoryfiles( $subdir );

			next if ( $files );
			
			print "Removing empty subdirectory $subdir ...\n" if ( $opt_verbose );
			rmdir( $subdir );
			$local_removed++;
		}

	closedir( MAINDIR );
	
	return( $local_removed );
}



################################################################################
#
sub Subdirectoryfiles( $ )
#
#  Given a directory, return TRUE if there are files inside it or it's not a directory
#
################################################################################
{	my $dir	= shift;
		
	return( 1 ) if ( ! defined $dir );
	return( 1 ) if ( ! -d $dir );
	
	# Process the source directory
	my $dir_handle;
	return( 1 ) if ( ! opendir( $dir_handle, $dir ) );

	print "Checking $dir ...\n" if ( $opt_verbose );

	my $files;	# True if there is a regular file in the directory
	
	while ( my $file = readdir( $dir_handle ) )
		{	next if ( ! defined $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );	
			
			my $full_file = "$dir\\$file";
			
			if ( -d $full_file )
				{	$files = &Subdirectoryfiles( $full_file );

					if ( ! $files )
						{	print "Removing empty subdirectory $full_file ...\n" if ( $opt_verbose );
							rmdir( $full_file );
							$removed++;
						}
					else
						{	$files = 1;
						}

				}
			else 
				{	$files = 1;
				}
				
		}

	closedir( $dir_handle );

	return( $files );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "EmptyDir [sourcedir]";
    print <<".";
Empty directory utility - removes empty directories from the source directory.

Usage: $me [OPTION(s)]

    
   -s, --source=SOURCEDIR  source directory to remove empty directories.
                           Default is the current directory.
  -h, --help               display this help and exit
  -v, --version            display version information and exit
.
    exit;
}



################################################################################

__END__

:endofperl
