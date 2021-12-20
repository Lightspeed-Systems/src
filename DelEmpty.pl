################################################################################
#!perl -w
#
#  Delete files that are empty in the current directory
#
#  Copyright 2007 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();



my $opt_help;


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
        "h|help"		=> \$opt_help
      );


	&Usage() if ( $opt_help );

	print "Delete duplicated files based on their file names\n";
	
	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	my $dir = $cwd;
	
	print "Deleting empty files from directory $dir ...\n";
		
    &DelEmpty( $dir );

	chdir( $cwd );
	
	print "Deleted $deleted_total empty files.\n" if ( $deleted_total );
	
    exit;
}



################################################################################
# 
sub DelEmpty( $ )
#
################################################################################
{	my $dir = shift;


	my $dir_handle;
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";

	while ( my $file = readdir $dir_handle )
		{	
			next if ( ! defined $file );

			next if ( $file eq "." );
			next if ( $file eq ".." );

			my $filelc = lc( $file );
			my $fullpath = "$dir\\$file";
					
			if ( ( -f $fullpath )  &&  ( ! -s $fullpath ) )
				{	# Delete the latest file
					print "Deleting empty file $fullpath ...\n";
					unlink( $fullpath );
					$deleted_total++;
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

Usage: DelEmpty [options]

This utility deletes empty files in the current directory.
The size of the file has to be '0' to be deleted.

Possible options are:

  -h, --help            print this message and exit

.

exit;
}


################################################################################

__END__

:endofperl
