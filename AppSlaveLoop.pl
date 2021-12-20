################################################################################
#!perl -w
#
# Loop around processing for the AppSlaves
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use File::Copy;
use Cwd;
use Sys::Hostname;



use Content::File;



# Options
my $opt_help;
my $opt_version;
my $_version = "1.0.0";



my $appslave_dir	= "R:\\AppSlave";
my $scan_dir		= "C:\\NotVirus";



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
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help
    );

    &StdHeader( "AppSlaveLoop" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	my $cwd = getcwd();
	$cwd =~ s#\/#\\#gm;

	# Figure out the hostname
	my $hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );
	
	my $junk;
	
	( $hostname, $junk ) = split /\./, $hostname, 2;
	 

	print "This machine is hostname $hostname\n";

	if ( ! ( $hostname =~ m/AppSlave/i ) )
		{	print "This program will only run on the AppSlave machines\n";
			exit( 1 );
		}
	
	my $done;
	
	while ( ! $done )
		{	my $ok = &CheckAppSlaveLoop();
			if ( ! $ok )
				{	print "Detected new AppSlaveLoop.exe so exiting now ...\n";
					last;
				}

			my $go_file = "$appslave_dir\\AppSlaveScan.go.txt";
			
			if ( ! -f $go_file )
				{	print "Waiting for 5 minutes before checking again for $go_file ...\n";
					sleep( 300 );
					next;
				}
			
			
			# Make sure all the required directories exist
			if ( ! &CheckDirectories() )
				{	print "Waiting for 5 minutes before checking the directories again ...\n";
					sleep( 300 );
					next;
				}
				
			chdir( "c:\\content\\bin" );


# Commented out by Rob M so that a 64 bit scan.exe is not replaced by a 32 bit scan.exe
#			my $cmd = "changedcopy f:\\Content\\Bin\\Scan.exe c:\\Content\\Bin\\Scan.exe";
#			print "$cmd\n";
#			system $cmd;
			
			my $cmd = "changedcopy f:\\Content\\Bin\\Update.exe c:\\Content\\Bin\\Update.exe";
			print "$cmd\n";
			system $cmd;
			
			$cmd = "changedcopy f:\\Content\\Bin\\Scan.dll c:\\Content\\Bin\\Scan.dll";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\ScanPoly.dll c:\\Content\\Bin\\ScanPoly.dll";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\ScanClient.dll c:\\Content\\Bin\\ScanClient.dll";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\ScriptScan.dll c:\\Content\\Bin\\ScriptScan.dll";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\Scan.exe \"c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\Scan.exe\"";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\Scan.dll \"c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\Scan.dll\"";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\ScanPoly.dll \"c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\ScanPoly.dll\"";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\ScanClient.dll \"c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\ScanClient.dll\"";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\ScriptScan.dll \"c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\ScriptScan.dll\"";
			print "$cmd\n";
			system $cmd;

			$cmd = "changedcopy f:\\Content\\Bin\\Update.exe \"c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\Update.exe\"";
			print "$cmd\n";
			system $cmd;
	
	
				
			chdir( $appslave_dir );
			
			# If I can't get to the directory then try again later
			next if ( ! -d $appslave_dir );
			
			my $finished_file = "$appslave_dir\\HOSTNAME.finished.txt";
			$finished_file =~ s/HOSTNAME/$hostname/;
			unlink( $finished_file );
			
			my $started_file = "$appslave_dir\\HOSTNAME.started.txt";
			$started_file =~ s/HOSTNAME/$hostname/;
			
			$cmd = "copy $appslave_dir\\go.txt $started_file /y";
			print "$cmd\n";
			system $cmd;


			# Get the current virus signature files
			$cmd = "ChangedCopy $appslave_dir\\VirusSignatures c:\\Windows\\System32\\Drivers\\VirusSignatures";
			print "$cmd\n";
			system $cmd;

			$cmd = "ChangedCopy $appslave_dir\\FileMD5.dat c:\\Windows\\System32\\Drivers\\FileMD5.dat";
			print "$cmd\n";
			system $cmd;

			$cmd = "ChangedCopy $appslave_dir\\FileMD5.def c:\\Windows\\System32\\Drivers\\FileMD5.def";
			print "$cmd\n";
			system $cmd;

			$cmd = "ChangedCopy $appslave_dir\\FileMD5.idx c:\\Windows\\System32\\Drivers\\FileMD5.idx";
			print "$cmd\n";
			system $cmd;


			# Signal the service that things have changed
			$cmd = "c:\\content\\bin\\update.exe -s";
			print "$cmd\n";
			system $cmd;

			chdir( $scan_dir );

			my $log_file = "$appslave_dir\\HOSTNAME.log";
			$log_file =~ s/HOSTNAME/$hostname/;
			
			$cmd = "c:\\content\\bin\\scan.exe -3 -z -l $log_file -j 100";
			print "$cmd\n";
			system $cmd;

			while ( ! -d $appslave_dir )
				{	print "Waiting for directory $appslave_dir to become accessable ...\n";
					sleep( 60 );
					next;
				}
				
			my $scan_log = "$appslave_dir\\HOSTNAMEScan.log";
			$scan_log =~ s/HOSTNAME/$hostname/;
			
			$cmd = "copy \"c:\\Program Files\\Lightspeed Systems\\SecurityAgent\\scan.log\" $scan_log /y";
			print "$cmd\n";
			system $cmd;

			unlink( $started_file );
			
			$cmd = "copy $appslave_dir\\go.txt $finished_file /y";
			print "$cmd\n";
			system $cmd;
	
	
			# Wait for 5 minutes
			print "Waiting for 5 minutes before starting again ...\n";
			sleep( 300 );
		}

	chdir( $cwd );

	&StdFooter();
	
    exit( 0 );
}



################################################################################
# 
sub CheckDirectories()
#
#  Check to see that all the required directories still exist
#  Do a fatal error if the don't exist.  Return undef if everything
#  does exist
#
################################################################################
{
	if ( ! -d $appslave_dir )
		{	print "Can not find directory $appslave_dir\n";
			return( undef );
		}

	if ( ! -d $scan_dir )
		{	print "Can not find directory $scan_dir\n";
			return( undef );
		}

	if ( ! -d "F:\\content\\bin" )
		{	print "Can not find directory F:\\content\\bin\n";
			return( undef );
		}

	if ( ! -d "c:\\content\\bin" )
		{	print "Can not find directory c:\\content\\bin\n";
			return( undef );
		}

	if ( ! -d "c:\\Program Files\\Lightspeed Systems\\SecurityAgent" )
		{	print "Can not find directory c:\\Program Files\\Lightspeed Systems\\SecurityAgent\n";
			return( undef );
		}

	if ( ! -f "$appslave_dir\\VirusSignatures" )
		{	print "Can not find file $appslave_dir\\VirusSignatures\n";
			return( undef );
		}


	return( 1 );
}



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
		
	return( 1 );
}



################################################################################
# 
sub CheckAppSlaveLoop()
#
#  Return True if the running AppSlaveLoop.exe and the program root AppSlaveLoop.exe are the same
#
################################################################################
{	
	my $program_local = "c:\\content\\bin\\AppSlaveLoop.exe";
	my $program_root = "f:\\content\\bin\\AppSlaveLoop.exe";
	
	my $size_local = -s $program_local;
	my $size_root = -s $program_root;
	
	return( 1 ) if ( ( ! $size_local )  ||  ( ! $size_root ) );
	
	return( undef ) if ( $size_local != $size_root );

	# Are the date/times different?
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $program_local;	
	my $from_mtime = 0 + $mtime;

	( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $program_root;
	my $to_mtime = 0 + $mtime;
	
	return( undef ) if ( $to_mtime != $from_mtime );

	return( 1 );
}


################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "AppSlaveLoop";

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
Try '$me --help' for more information.
.
    exit( 2 );
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "AppSlaveLoop";
    print <<".";
Usage: $me [OPTION(s)]
Loop around doing all the app slave processing.

Directories used are:

$appslave_dir
$scan_dir

  -h, --help        display this help and exit
  -v, --version     display version information and exit
.
    exit( 3 );
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "AppSlaveLoop";

    print <<".";
$me $_version
.
    exit( 4 );
}



################################################################################

__END__

:endofperl
