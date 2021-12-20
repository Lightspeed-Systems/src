################################################################################
#!perl -w
#
# MoveDir - Given a list of domains and IPs, move any directory that match
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;
use File::Copy;

use Content::File;


# Options
my $opt_help;
my $opt_version;
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
        "v|version"			=>	\$opt_version,
        "h|help"			=>	\$opt_help
    );
	

    &StdHeader( "MoveDir" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


	# Read the command line
	my $domain_file = shift;
	die "You must enter a file of possible directories to move\n" if ( ! $domain_file );
	die "You must enter a file of possible directories to move\n" if ( ! -e $domain_file );
	
	
	my $dest_dir = shift;
	die "You must enter a destination directory\n" if ( ! $dest_dir );
	die "$dest_dir does not exist or is not a directory\n" if ( ! -d $dest_dir );
	

	my $src_dir = shift;
	$src_dir = '.' if ( ! $src_dir );
	die "$src_dir does not exist or is not a directory\n" if ( ! -d $src_dir );
	

	print "Loading up possible directory names to move ...\n";
	my %domains;
	open( DOMAIN, "<$domain_file" ) or die( "Unable to open $domain_file: $!\n" );

	my $count = 0 + 0;
	while ( my $domain = <DOMAIN> )
		{	chomp( $domain );
			next if ( ! $domain );
			
			$domain = lc( $domain );

			$domains{ $domain } = 1;
			$count++;
		}
		
	close( DOMAIN );
	
	
	die( "Unable to read any directory names from $domain_file\n" ) if ( ! $count );
	
	
	# Process the source directory
	opendir DIR, $src_dir;


	print "Checking subdirectories of $src_dir :\n";


	my @move_dir;
	while ( my $dir = readdir( DIR ) )
		{	next if ( ! $dir );
			
			next if ( ! -d $dir );
			next if ( $dir eq '.' );
			next if ( $dir eq '..' );
			
			$dir = lc( $dir );

			if ( defined $domains{ $dir } )
				{	print "Found $dir\n";
					push @move_dir, $dir;
				}
 		}

	closedir DIR;


	die( "Did not find any directories to move\n" ) if ( $#move_dir < 0 );


	foreach ( @move_dir )
		{	my $subdir = $_;
			next if ( ! $subdir );
			
			my $full_src = "$src_dir\\$subdir";
			my $full_target = "$dest_dir\\$subdir";
			
			&MoveDir( $full_src, $full_target );
		}
		
	&StdFooter;

    exit;
}



################################################################################
#
sub MoveDir( $$ )
#
#  Move a directory
#
################################################################################
{	my $src		= shift;
	my $target	= shift;
	
	return( undef ) if ( ! $src );
	return( undef ) if ( ! $target );
	
	mkdir( $target );
	
	system "xcopy $src $target /s /Y /F";
	
	die "Unable to create $target\n" if ( ! -e $target );
	
	system "rmdir $src /s /q";
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "MoveDir subdirlist dest_dir [src_dir]";
    print <<".";
Usage: $me [OPTION(s)]

    
  -h, --help               display this help and exit
  -v, --version            display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "MoveDir";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
