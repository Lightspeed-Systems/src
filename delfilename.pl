################################################################################
#!perl -w
#
#  Delete files that have the same filename
#
#  Copyright 2007 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();
use Digest::MD5;
use Content::File;
use Content::Scanable;



my $opt_help;
my $opt_dir;
my $opt_keep;


my %filename_hash;


my $unique_total	= 0 + 0;
my $deleted_total	= 0 + 0;



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
		"d|dir=s"		=> \$opt_dir,
        "k|keep"		=> \$opt_keep,
        "h|help"		=> \$opt_help
      );


	&Usage() if ( $opt_help );

	print "Delete duplicated files based on their file names\n";
	
	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	my $dir = $cwd;
	
	$dir = $opt_dir if ( $opt_dir );
	

	if ( $opt_keep )
		{	print "Keeping duplicated files ...\n";
		}
	else
		{	print "Deleting from directory $dir and subdirectories ...\n";
		}
		
    &Delfilename( $dir );

	chdir( $cwd );
	
	print "Found $unique_total total unique files.\n";
	print "Deleted $deleted_total duplicated files.\n" if ( $deleted_total );
	
    exit;
}



################################################################################
# 
sub Delfilename( $ )
#
################################################################################
{	my $dir = shift;

	print "Directory: $dir\n"; 
	chdir "$dir";

	my $dir_handle;
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";

	while ( my $file = readdir $dir_handle )
		{	
			next if ( ! defined $file );

			next if ( $file eq "." );
			next if ( $file eq ".." );

			my $filelc = lc( $file );
			my $fullpath = "$dir\\$file";
					
			if ( -f $fullpath )
				{	next if ( ! -s $fullpath );
					
					if ( exists $filename_hash{ $filelc } )
						{	my $original_file = $filename_hash{ $filelc };
							
							# Is it the same file - just renamed?
							next if ( lc( $original_file ) eq lc( $fullpath ) );
							
							print "$file is a duplicate of $original_file\n";
							next if ( $opt_keep );
							
							# Delete the latest file
							unlink( $fullpath );
							$deleted_total++;
							
						}
					else
						{	# Keep track of the unique files	
							$unique_total++ if ( ! exists $filename_hash{ $filelc } );
							
							$filename_hash{ $filelc } = $fullpath;
						}
				}
			elsif ( -d $fullpath )
				{	&Delfilename( $fullpath );
					chdir( $dir );
				}
		}


	closedir( $dir_handle );

	return( 0 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Delfilename";
	
    print <<".";

Usage: delfilename [options]

This utility deletes duplicated files in subdirectories with the same name. 

Possible options are:

  -d, --dir DIR         the start in directory DIR
  -k, --keep            to keep the duplicated files
  -h, --help            print this message and exit

.

exit;
}


################################################################################

__END__

:endofperl
