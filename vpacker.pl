################################################################################
#!perl -w
#
# Rob McCarthy's vpacker source code
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use DBI qw(:sql_types);
use DBD::ODBC;
use Digest::MD5;
use String::CRC32;
use File::Copy;


use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Content::Scanable;
use Content::FileIntegrity;
use Content::Category;



my $opt_help;
my $opt_debug;
my $opt_wizard;						# True if I shouldn't display headers or footers
my $opt_verbose;					# True if we should be chatty
my $_version = '1.00.00';
my $opt_unlink;						# If True then delete any file that is not detected as a virus by any AV package
my $opt_file;
my $opt_ignore;
my $opt_dir;



# Globals
my $copied = 0 + 0;



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
 		"f|file=s"		=> \$opt_file,
		"d|dir=s"		=> \$opt_dir,
        "h|help"		=> \$opt_help,
		"v|verbose"		=> \$opt_verbose,
		"u|unlink"		=> \$opt_unlink
      );


	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
    &Usage() if ( $opt_help );


	$opt_file = shift if ( ! defined $opt_file );
	$opt_dir = shift if ( ! defined $opt_dir );
		
		
	if ( ( ! defined $opt_file )  ||  ( ! -f $opt_file ) )
		{	print "Can not find packers text file to parse\n";
			exit( 0 + 1 );
		}
		
		
	if ( ( ! defined $opt_dir )  ||  ( ! -d $opt_dir ) )
		{	print "Can not find directory to copy packed files to\n";
			exit( 0 + 1 );
		}
		

	open( PACKERS, "<$opt_file" ) or die "Error opening $opt_file: $!\n";
	
	while ( my $line = <PACKERS> )
		{	chomp( $line );
			next if ( ! length( $line ) );
			next if ( ! ( $line =~ m/\:\:/ ) );
			
			my ( $file, $packer ) = split /\:\:/, $line, 2;
			next if ( ! $file );
			next if ( ! $packer );
			$file =~ s/\s+$//;
			$packer =~ s/^\s+//;
			
			# Should I ignore this file?
			next if ( $packer =~ m/^nothing/i );
			next if ( $packer =~ m/^microsoft/i );
			next if ( $packer =~ m/^not/i );
			
			my ( $type, $other ) = split /\s/, $packer, 2;
			
			my $dest_dir = "$opt_dir\\$type";
			
			&MakeDirectory( $dest_dir );
			
			my ( $dir, $shortfile ) = &SplitFileName( $file );

			my $dest = "$dest_dir" . "\\$shortfile";
			
			if ( $opt_verbose )
				{	print "Copying $file to $dest ...\n";
					print "Packer: $packer\n";
				}
				
			if ( ! -f $file )
				{	print "Can not find file from this line: $line\n";
					next;
				}
			
			my $ok = copy( $file, $dest );
			
			print "Error copying $file to $dest: $!\n";
			next if ( ! $ok );
	
			$copied++;
			
			unlink( $file ) if ( $opt_unlink );
		}
	
	close( PACKERS );
	
	
	print "Copied $copied files\n" if ( $copied );
	
	exit( 0 + 0 );
}
###################    End of MAIN  ################################################



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
sub Version
#
################################################################################
{
    my $me = "vpacker";

    print <<".";
scan $_version
.

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "vpacker";
	
    print <<".";

Usage: vpacker FILE DIR

Copies files into subdirectories based on parsing a packers format file.
FILE is the packers file to parse, DIR is the root directory to copy to

Possible options are:

  -d, --dir DIR           root directory DIR to copy to
  -f, --file FILE         packers file to parse 
  -u, --unlink            to delete source files after copying
  -v, --verbose           verbose mode
  -h, --help              print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
