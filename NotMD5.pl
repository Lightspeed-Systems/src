################################################################################
#!perl -w
#
#  NotMD5 - go recursively through a directory printing out any file that
#  is not in MD5 file format
#
#  Copyright 2010 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;



use Cwd;
use Getopt::Long();


my $opt_help;
my $opt_verbose;					# True if I should be verbose about what I am doing
my $opt_debug;




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


    print "NotMD5\n\n";
	&Usage() if ( $opt_help );

	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	

	# Recursively go through the directories
	&NotMD5( $cwd );


	print "\nDone\n";;
	
	exit( 0 + 0 );
}



################################################################################
#
sub NotMD5( $ )
#
#  Process the given directory
#
################################################################################
{	my $dir = shift;
	
	
	print "Checking directory $dir ...\n" if ( $opt_verbose );

		
	my $current_dir_handle;
	if ( ! opendir( $current_dir_handle, $dir ) )
		{	print "Error opening source directory $dir: $!\n";
			return( undef );
			
		}

	
	while ( my $file = readdir( $current_dir_handle ) )
		{	next if ( ! defined $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			my $full_file = "$dir\\$file";
			
			# Check subdirectories
			if ( -d $full_file )			
				{	&NotMD5( $full_file );
					next;
				}

			# Is it a real file?
			next if ( ! -f $full_file );

			my ( $short, $ext ) = split /\./, $file, 2;
			
			$short =~ s/_+$// if ( ! defined $ext );
			
			my $len = length( $short );
			
			if ( ( ! $len )  ||  ( $len != 32 ) )
				{	print "$full_file\n";
					next;	
				}
				
			$short = lc( $short );	
			if ( $short =~ m/![0-9,a-f]/i )
				{	print "$full_file\n";
					next;	
				}
 		}

	closedir( $current_dir_handle );

		
	return( 1 );	
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";

Usage: NotMD5

This utility goes recursively through directories printing out any file that is
not in MD5 file format.

Possible options are:

  -v, --verbose         verbose mode
  -h, --help            print this message and exit

.

exit( 0 + 13 );
}



################################################################################

__END__

:endofperl
