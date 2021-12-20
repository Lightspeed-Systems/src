################################################################################
#!perl -w
#
# Rob McCarthy's Clean Sweep utility
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long;
use Content::File;


my $opt_version;	# Display version # and exit
my $opt_help;		# Display help and exit
my $opt_logging;
my $opt_days;		# The number of days to decide if an older file
my $opt_debug;		# True if debugging - main difference is the URLs used
my $version			= "1.00.00";	# Current version number
my $current_time;	# The current time to compare by
my $older_time;		# The time in seconds to delete older file by
my $total_count = 0 + 0;



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
		"d|days=i"		=> \$opt_days,
		"l|logging"		=> \$opt_logging,
		"v|version"		=> \$opt_version,
		"h|help"		=> \$opt_help,
		"x|xxxdebug"	=> \$opt_debug
    );


	if ( ( ! defined $opt_days )  ||  ( $opt_days < 2 ) )
		{	die "You must set the number of days to delete by with the -d switch\n";
		}
		
	$current_time = time;
	
	my $seconds = $opt_days * 24 * 60 * 60;
	$older_time = $current_time - $seconds;
	
	
	print "Deleting DumpTokens files older than $opt_days days ...\n";
	
    my $dir = getcwd;
    $dir =~ s#\/#\\#gm;

    &CleanSweep( $dir );

	print "Deleted $total_count files in all directories\n";
	
	chdir( $dir );
    
	exit;
}



################################################################################
# 
sub CleanSweep( $ )
#
################################################################################
{	my $dir = shift;


	print "Clean Sweep directory: $dir\n"; 
	chdir($dir );

	my $dir_handle;
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";

	my $directory_count = 0 + 0;
	
	my ( $junk, $path ) = split /\:/, $dir, 2;
	$path =~ s#^\\##;
	$path =~ s#\\#-#g;

	
	if ( $opt_logging )
		{	my $logfile = "$dir\\$path.cleansweep.log";
			open( LOGFILE, ">>$logfile" ) or die "Unable to open $logfile: $!\n";;
			print "Logging deleted files to $logfile\n";
		}
	
	while ( my $file = readdir $dir_handle )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );

			if ( -d $file )
				{	my $fulldir = "$dir\\$file";
					&CleanSweep( $fulldir );
				}
			else
				{	my $fullfile = "$dir\\$file";
					
					my $url = $file;
					
					$url =~ s/\.links\.txt$//;
					$url =~ s/\.tokens\.txt$//;
					$url =~ s/\.lables\.txt$//;
					$url =~ s/\.site\.txt$//;
					$url =~ s/\.content\.txt$//;
					$url =~ s/\.content\.htm$//;
					$url =~ s/\.dump\.zip$//;
					
					# Is it an old file?		
					if ( &CleanProcess( $fullfile ) )
						{	$directory_count++;
							
							print LOGFILE "$url\n" if ( $opt_logging );
						}
					elsif ( ! &CleanUrl( $url ) )	# Or is it an illegal URL
						{	$directory_count++;
							
							print "Deleting illegal file $fullfile\n";
							$total_count++;
							unlink( $fullfile );
							
							print LOGFILE "$url\n" if ( $opt_logging );
						}
				}
				
			chdir( $dir );
		}


	closedir $dir_handle;
	close LOGFILE if ( $opt_logging );
	
	
	print "Deleted $directory_count files in directory $dir\n";
	
	return( 0 );
}



################################################################################
# 
sub CleanProcess( $ )
#
#  I've found a file in a directory - process it
#  Return True if deleted, undef if not
#
################################################################################
{	my $fullfile = shift;
		
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $fullfile;	
	$mtime = 0 + $mtime;

	if ( $older_time > $mtime )
		{	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $mtime );
			$year += 1900;
			$mon++;
			my $date = "$mon\/$mday\/$year";

			print "Deleting file created $date $fullfile\n";
			$total_count++;
			unlink( $fullfile );
			return( 1 );
		}
		
		
	return( undef );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "CleanSweep";

    print <<".";
This utility sweeps through the directory structure, starting in the current
directory, deleting any DumpTokens file that is older than the days parameter.


  -d, --days DAYS        the number of days to delete files older than
  -h, --help             display this help and exit
  -v, --version          display version information and exit
.
    &StdFooter;

    exit( 1 );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "CleanSweep";

    print <<".";
$me version: $version
.
    &StdFooter;

    exit( 1 );
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
