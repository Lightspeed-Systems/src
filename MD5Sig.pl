################################################################################
#!perl -w
#
# Rob McCarthy's MD5 Sig builder program
#
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


my $_version = '1.00.00';


use Getopt::Long();
use Cwd;


use Content::File;
use Content::ScanUtil;



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_wizard;								# True if I shouldn't display headers or footers
my $global_count = 0 + 0;



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
			"h|help"		=> \$opt_help,
			"x|xxx"			=> \$opt_debug
       ) or die( Usage() );


	print "MD5 Signature Builder\n" if ( ! $opt_wizard );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	
	print "Debugging mode\n" if ( $opt_debug );
	
	my $dir = getcwd;
    $dir =~ s#\/#\\#gm;

	&MD5Sig( $dir );

	chdir( $dir );
	
	print "Total count of signatures created = $global_count\n";
	
	exit;
}
###################    End of MAIN  ################################################



################################################################################
# 
sub MD5Sig( $$ )
#
################################################################################
{	my $dir 	= shift;

	print "Directory: $dir\n"; 
	chdir "$dir";


	# First, run SigDesign against all the .exe_ in the directory
	my $file_handle;
	opendir( $file_handle, $dir ) or die "Unable to open directory $dir: $!\n";

	my @filelist;
	
	while ( my $file = readdir( $file_handle ) )
		{	
			next if ( ! defined $file );
			next if ( -d $file );
			
			next if ( ! ( $file =~ m/\.exe_$/i ) );
			
			my $fullfile = "$dir\\$file";
			
			next if ( ! -e $fullfile );
			
			push @filelist, $fullfile;
		}
	
	closedir( $file_handle );
	
	
	my $found = $#filelist + 1;
	
	print "Found $found files to build signatures for ...\n";
	
	# Build signatures for the files I've got
	&SigDesign( @filelist ) if ( $found );
	
	
	# Finally, go down into the subdirectories looking for more program with .exe_
	my $dir_handle;
	opendir( $dir_handle, $dir ) or die "Unable to open directory $dir: $!\n";

	while ( my $subdir = readdir( $dir_handle ) )
		{	
			next if ( ! defined $subdir );

			next if ( $subdir eq "." );
			next if ( $subdir eq ".." );

			next if ( ! -d $subdir );
	
			my $fulldir = "$dir\\$subdir";

			&MD5Sig( $fulldir );

			chdir( $dir );
		}


	closedir( $dir_handle );

	return( 0 );
}



################################################################################
# 
sub SigDesign()
#
#  Given a list of files, build MD5 signatures for each one
#
################################################################################
{
	my @filelist;
	
	while ( my $fullfile = shift )
		{	push @filelist, $fullfile;
		}
		
		
	my $total_count = $#filelist + 1;
	return( 0 + 0 ) if ( ! $total_count );
	
	my $count = 0 + 0;
	
	foreach ( @filelist )
		{	my $fullfile = $_;
			next if ( ! $fullfile );
			
			print "Building MD5 signature for $fullfile ...\n";
			
			# Figure out a good virus name ...
			my ( $dir, $file ) = &SplitFileName( $fullfile );
			
			die "Bad directory structure\n" if ( ! $dir );
			
			my @parts = split /\\/, $dir;
			
			my $subdir = $parts[ $#parts ];
			
			my $virus = $subdir;
			
			# Trim off any .exe
			$virus =~ s/\.exe$//i;
			
			# Should I add the file name to the virus name?
			$virus .= ".$file" if ( $total_count > 1 );
			
			# Trim off any .exe_
			$virus =~ s/\.exe_$//i;
			
			$virus .= ".MD5";
			
			$virus = &CleanVirusName( $virus );
			
			die "Invalid virus name\n" if ( ! $virus );
			
			system "sigdesign \"$file\" -s 1 -n $virus";
			
			$count++;
			$global_count++;
		}

	return( $count );	
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "MD5Sig";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "MD5Sig";


    bprint <<".";

Usage: MD5Sig

The MD5Sig builder program goes recursively through the directory structure
running the SigDesign program on any file it finds with the .exe_ extension.


  -h, --help          print this message and exit
.
    &StdFooter;

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
