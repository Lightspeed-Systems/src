################################################################################
#!perl -w
#
# Rob McCarthy's VirusDir.pl source code
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long();
use Cwd;
use File::Copy;



use Content::File;



my $opt_file = "c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\scan.log";
my $opt_dir;
my $opt_help;
my $opt_debug;
my $opt_unlink;



################################################################################
#
MAIN:
#
################################################################################
{
	my $options = Getopt::Long::GetOptions
       (
			"d|dir=s"		=> \$opt_dir,
			"f|file=s"		=> \$opt_file,
			"u|unlink"		=> \$opt_unlink,
			"h|help"		=> \$opt_help,
			"x|xxx"			=> \$opt_debug
      );

	&StdHeader( "VirusDir" );

    &Usage() if ( $opt_help );	
	
	
	my $temp = shift;
	$opt_dir	= $temp if ( $temp );
	$temp = shift;
	$opt_file	= $temp if ( $temp );
	
	
	&Usage() if ( ( ! $opt_file )  ||  ( ! $opt_dir ) );
	
	
	print "Copying virus infected files to $opt_dir ...\n";
	print "Reading scan log $opt_file ...\n";
	
	
 	open( INPUT, "<$opt_file" ) or die( "Unable to open scan log $opt_file: $!\n" );

	my $counter = 0 + 0;


	while (<INPUT>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );

			# Ignore corrupted
			next if ( $line =~ m/corrupted executable/i );

			# Ignore encrypted
			next if ( $line =~ m/encrypted program in archive/i );

			# Ignore unknown
			next if ( $line =~ m/an unknown virus/i );

			# Ignore unknown
			next if ( $line =~ m/could be a suspicious file/i );

			my ( $drive, $fullpath, $infection ) = split /\:/, $line, 3;

			next if ( ! $fullpath );
			next if ( ! $infection );

			$fullpath = $drive . ":" . $fullpath;
			
			next if ( ! -e $fullpath );
			
			my ( $src_dir, $short_file ) = SplitFileName( $fullpath );
			
			my $dest = "$opt_dir\\$short_file";
		
			print "Copying $fullpath to $dest ...\n";
			
			my $ok = copy( $fullpath, $dest );
			
			if ( ! $ok )
				{	print "Error copying $fullpath: $!\n";
					next;	
				}
			
			$counter++;
			
			if ( $opt_unlink )
				{	print "Deleting $fullpath ...\n";
					$ok = unlink( $fullpath );
					
					print "Error deleting $fullpath: $!\n" if ( ! $ok );
				}
		}
	
	print "Copied $counter virus infected files\n" if ( $counter );
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";
Usage: VirusDir [options] DIR SCANLOG

Read a SCANLOG from a virus or spyware scan and copy all the detected virus
infected files to DIR.

Possible options are:

  -d, --dir DIR        the directory to copy virus infected files to
  -f, --file SCANLOG   the filename of the virus scan log
                       default is c:\\Program Files\\Lightspeed Systems\\
                       SecurityAgent\\scan.log
  -u, --unlink         unlink (delete) the original virus infected files
  -h, --help           print this message and exit
.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
