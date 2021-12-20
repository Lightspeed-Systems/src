################################################################################
#!perl -w
#
# Rob McCarthy's TTCUpdate - update all the TTC exe's, .dlls. registry, etc
# All the support routines are in this file
# The actual installation functions are in Content::Install
#
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


my $_version = "8.01.00";				# Current version number



use Getopt::Long;
use MIME::Base64;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use Win32;
use Win32::File;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Fcntl qw(:DEFAULT :flock);

use Content::File;
use Content::ScanFile;
use Content::Install;
use Content::SQL;
use Content::Process;
use Content::Mail;
use Cwd;



# Options
my $opt_version;						# Display version # and exit
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_debug;							# True if debugging
my $opt_nowait;							# True if I should wait a random period before starting
my $opt_file;							# True if installing from an update package in the current directory
my $opt_download;						# True if I should download the update pachage even if I have already done so
my $opt_set;							# If I should set the version 



# Globals
my $working_dir;						# The working software directory
my $tmp_dir;							# The tmp directory
my @package_files;						# The list of files unpacked into the tmp directory to be installed		
my $default_monitor_server		= "monitor.lightspeedsystems.com";
my $monitor_server				= $default_monitor_server;




# 5.2 URLs - the default
my $update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update52\.htm";
my $package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage52\.htm";

my $updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update52\.htm";
my $packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage52\.htm";
my $package_file = "\\updatepackage52\.htm";



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
		"d|download"=> \$opt_download,
		"f|file"	=> \$opt_file,
		"n|nowait"	=> \$opt_nowait,
		"s|set=s"	=> \$opt_set,
		"v|version" => \$opt_version,
		"w|wizard"	=> \$opt_wizard,
        "h|help"	=> \$opt_help,
		"x|xxx"		=> \$opt_debug
    );


    &StdHeader( "TTC Update Program version $_version" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
    &Version() if ($opt_version);

	$opt_nowait = 1 if ( $opt_download );
	
	my $ver;
	
	if ( $opt_set )
		{	if ( ( $opt_set ne "5.0" )  &&
				 ( $opt_set ne "5.1" )  &&
				 ( $opt_set ne "5.2" )  &&
				 ( $opt_set ne "5.3" )  &&
				 ( $opt_set ne "6.0" )  &&
				 ( $opt_set ne "6.1" )  &&
				 ( $opt_set ne "6.2" )  &&
				 ( $opt_set ne "6.3" )  &&
				 ( $opt_set ne "6.4" )  &&
				 ( $opt_set ne "7.0" )  &&
				 ( $opt_set ne "7.1" )  &&
				 ( $opt_set ne "7.2" )  &&
				 ( $opt_set ne "7.3" )  &&
				 ( $opt_set ne "8.0" )	&&
				 ( $opt_set ne "8.1" )	&&
				 ( $opt_set ne "8.2" )	&&
				 ( $opt_set ne "8.3" )	&&
				 ( $opt_set ne "9.0" )	&&
				 ( $opt_set ne "9.1" )	&&
				 ( $opt_set ne "9.2" )	&&
				 ( $opt_set ne "9.3" ) )
				{	print "Bad version to set = $opt_set\n";
					exit( 0 );
				}
				
			$ver = $opt_set;
		}
	else
		{	$ver = &TTCFindVersion();
			&lprint( "TTC Update for Total Traffic version $ver\n" ) if ( $ver );
		}
		
		
	if ( $ver eq "5.0" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update50\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage50\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update50\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage50\.htm";
			
			$package_file = "\\updatepackage50\.htm";
		}
	elsif ( $ver eq "5.1" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update51\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage51\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update51\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage51\.htm";
			
			$package_file = "\\updatepackage51\.htm";
		}
	elsif ( $ver eq "5.2" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update52\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage52\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update52\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage52\.htm";
			
			$package_file = "\\updatepackage52\.htm";
		}
	elsif ( $ver eq "5.3" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update53\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage53\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update53\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage53\.htm";
			
			$package_file = "\\updatepackage53\.htm";
		}
	elsif ( $ver eq "6.0" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update60\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage60\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update60\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage60\.htm";
			
			$package_file = "\\updatepackage60\.htm";
		}
	elsif ( $ver eq "6.1" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update61\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage61\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update61\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage61\.htm";
			
			$package_file = "\\updatepackage61\.htm";
		}
	elsif ( $ver eq "6.2" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update62\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage62\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update62\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage62\.htm";
			
			$package_file = "\\updatepackage62\.htm";
		}
	elsif ( $ver eq "6.3" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update63\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage63\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update63\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage63\.htm";
			
			$package_file = "\\updatepackage63\.htm";
		}
	elsif ( $ver eq "6.4" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update64\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage64\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update64\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage64\.htm";
			
			$package_file = "\\updatepackage64\.htm";
		}
	elsif ( $ver eq "7.0" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update70\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage70\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update70\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage70\.htm";
			
			$package_file = "\\updatepackage70\.htm";
		}
	elsif ( $ver eq "7.1" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update71\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage71\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update71\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage71\.htm";
			
			$package_file = "\\updatepackage71\.htm";
		}
	elsif ( $ver eq "7.2" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update72\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage72\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update72\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage72\.htm";
			
			$package_file = "\\updatepackage72\.htm";
		}
	elsif ( $ver eq "7.3" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update73\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage73\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update73\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage73\.htm";
			
			$package_file = "\\updatepackage73\.htm";
		}
	elsif ( $ver eq "8.0" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update80\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage80\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update80\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage80\.htm";
			
			$package_file = "\\updatepackage80\.htm";
		}
	elsif ( $ver eq "8.1" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update81\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage81\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update81\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage81\.htm";
			
			$package_file = "\\updatepackage81\.htm";
		}
	elsif ( $ver eq "8.2" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update82\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage82\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update82\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage82\.htm";
			
			$package_file = "\\updatepackage82\.htm";
		}
	elsif ( $ver eq "8.3" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update83\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage83\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update83\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage83\.htm";
			
			$package_file = "\\updatepackage83\.htm";
		}
	elsif ( $ver eq "9.0" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update90\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage90\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update90\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage90\.htm";
			
			$package_file = "\\updatepackage90\.htm";
		}
	elsif ( $ver eq "9.1" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update91\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage91\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update91\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage91\.htm";
			
			$package_file = "\\updatepackage91\.htm";
		}
	elsif ( $ver eq "9.2" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update92\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage92\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update92\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage92\.htm";
			
			$package_file = "\\updatepackage92\.htm";
		}
	elsif ( $ver eq "9.3" )
		{	$update_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/update93\.htm";
			$package_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/updatepackage93\.htm";

			$updatetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=update93\.htm";
			$packagetime_url = "http://opendb\.lightspeedsystems\.com/softwareupdate/GetLastUpdate.aspx?file=updatepackage93\.htm";
			
			$package_file = "\\updatepackage93\.htm";
		}
	else
		{	print "Unsupported version $ver\n";
			exit( 0 );
		}
		

	my $cur_dir = getcwd();	
	$cur_dir =~ s#/#\\#g;


	# make sure that the update source is set to opendb.lightspeedsystems.com if it is sa3
	&FixUpdateSource();
	
	
	# Should I sleep for a random period of between 0 and 180 minutes
	if ( ! $opt_nowait )
		{	my $max_wait = 60 * 180;
			my $sec = rand( $max_wait );
			$sec = 0 + sprintf( "%f", $sec );
			my $min = &Truncate( $sec / 60 );
			print "Sleeping for $min minutes before starting ...\n";
			sleep( $sec );
		}


	$working_dir = &SoftwareDirectory();	# This is the IPMSOFTWARE directory
	$tmp_dir = &TmpDirectory() . "\\TU";				# This is the IPMTMP directory
	&BuildDirectory( $tmp_dir );


	my $ttcupdate_log = "TTCUpdate.log";
	&SetLogFilename( $ttcupdate_log, undef );

	&TrapErrors() if ( ! $opt_debug );

	lprint "Started running TTC Update program version $_version ...\n";
	
	
	# Make sure that I'm the only TTCUpdate and IpmUpgradeDB running
	&KillOtherTTCUpdates();
	
	
	# Start doing some work
	my ( $old_updatetime, $old_packagetime, $old_packageversion ) = &GetProperties();
	my $result = "Unable to connect to Lightspeed Systems";		# The result of the last major operation
	
	
	# Am I just installing from the local directory?
	if ( $opt_file )
		{	&InstallFile( $ver, $tmp_dir );
			&StdFooter if ( ! $opt_wizard );
			&AddHistoryLog( $working_dir, $ttcupdate_log );
			exit(0 );
		}


	# Figure out if I need to update anything
	lprint "Getting current update program and package times ... \n";
	my $new_updatetime = &GetUpdatetime();
	my $new_packagetime = &GetPackagetime();
	my $new_packageversion = $old_packageversion;
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $date = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d", $year, $mon, $mday, $hour, $min, $sec );

	
	# Did I have trouble getting the times?
	if ( ( ! $new_updatetime )  ||  ( !  $new_packagetime ) )
		{	$result = "Unable to connect to Lightspeed software update website";
			lprint( "$result\n" );
			
			&SetProperties( $old_updatetime, $old_packagetime, $result, $old_packageversion, undef );
			
			&StdFooter if ( ! $opt_wizard );
			&AddHistoryLog( $working_dir, $ttcupdate_log );
			exit( 0 );
		}
	
	
	# If I've got a new update program, get it and run it
	if ( ( ! $old_updatetime ) || ( $new_updatetime ne $old_updatetime ) )
		{	
			&lprint( "New update program available, so downloading it now ... \n" );
			
			my $ok = &GetUpdate( $working_dir );
			
			$result = "Got new TTCUpdate program ok";
			$result = "Unable to get new TTCUpdate program" if ( ! $ok );
			&lprint( "$result\n" );
			
			if ( ! $ok )
				{	&StdFooter if ( ! $opt_wizard );
					&AddHistoryLog( $working_dir, $ttcupdate_log );
					exit( 0 );
				}
				
			&SetProperties( $new_updatetime, $old_packagetime, $result, $old_packageversion, undef );
			
			# This function will not return if successful
			# It will return OK if the TTCUpdate program did not change
			$ok = &ReplaceUpdate( $working_dir );	
			
			if ( ! $ok )
				{	$result = "Did not install new TTCUpdate program";
					&lprint( "$result\n" );
			
					&SetProperties( $old_updatetime, $old_packagetime, $result, $old_packageversion, undef );
			
					&StdFooter if ( ! $opt_wizard );
					&AddHistoryLog( $working_dir, $ttcupdate_log );
					exit( 0 );
				}
				
			&lprint( "Did not change TTCUpdate.exe\n" );	
		}
	else
		{	&lprint( "The latest TTCUpdate program is already installed\n" );
			$result = "The latest TTCUpdate program is already installed as of $date";
		}
	
	
	# If I've got a new package, get it and install it
	if ( ( ! $old_packagetime )  ||  ( $new_packagetime ne $old_packagetime )  ||  ( $opt_download ) )
		{
			lprint "New software update package available, so downloading it now ... \n";
			
			my $ok = &GetUpdatePackage( $tmp_dir );
			lprint "Got new software update package ok\n" if ( $ok );
			
			$result = "Got new update package ok";
			
			if ( ! $ok )
				{	$result = "Unable to get software update package";
					$new_packagetime = $old_packagetime;
					
				}
			else	
				{	lprint "Installing new software update package... \n";
					( $new_packageversion, $result ) = &InstallPackage( $ver, $old_packageversion, @package_files );
					
					# If I had a problem, don't change the package time or package version
					if ( $result ne "OK" )
						{	$new_packagetime	= $old_packagetime;
							$new_packageversion = $old_packageversion;
							
							my $full_log = $working_dir . "\\" . $ttcupdate_log;
							lprint "Emailing log file $full_log ...\n";
							my $ret = &EmailLogFile( "TTCUpdateInstallError", "TTCUpdate Install Errors", "Errors occurred trying to install the last TTC Update package to this server", $full_log );
							lprint "Email log file return: $ret\n";
						}
				}
				
				
			# Remove the package files so that a service register doesn't accidently screw up
			foreach ( @package_files )
				{	my $file = $_;
					next if ( ! $file );
					unlink( $file );
				}
				
			@package_files = ();
			
			lprint( "Install result: $result\n" );	
		}
	else
		{	lprint "The latest software update has already been installed\n";
			$result = "The latest software update has already been installed as of $date";
		}
	
	     
	&SetProperties( $new_updatetime, $new_packagetime, $result, $new_packageversion, $date );
	
	
# TJB - 1/5/04 - Commented this out (for now) since all it shows are errors stopping/starting the services...
#	# Did I have some program errors?
#	my $full_log = $working_dir . "\\TTCUpdateErrors.log";
#	if ( ( -e $full_log )  &&  ( -s $full_log ) )
#		{	lprint "Emailing log file $full_log ...\n";
#			my $ret = &EmailLogFile( "TTCUpdateError", "TTCUpdate Errors", "Errors occurred trying to install the last TTC Update package to this server", $full_log );
#			lprint "Email log file return: $ret\n";
#		}
		
		
	lprint "Finished running TTC Update program\n";

	&StdFooter if ( ! $opt_wizard );
	&AddHistoryLog( $working_dir, $ttcupdate_log );
	
	exit( 0 );
}



################################################################################
#
sub AddHistoryLog( $$ )
#
#  In the given directory, merge the history log with the new log file
#
################################################################################
{	my $dir		= shift;
	my $logname = shift;
	
	# Return undef if the logfile doesn't exist
	return( undef ) if ( ! $logname );
	return( undef ) if ( ! -e $logname );
	
	my $history_log = $dir . "\\TTCUpdateHistory.log";
	
	my $size = -s $history_log;
	
	my $mode = ">>";	# Default is append mode
	$mode = ">" if ( ( $size  )  &&  ( $size > ( 0 + 2000000 ) ) );	# If the size is larger than 2 megs, rewrite the file
	
	open HISTORY, "$mode$history_log" or return( undef );
	
	if ( ! open LOG, "<$logname" )
		{	close HISTORY;
			return( undef );	
		}
	
	print HISTORY "\n\n";
	
	while (my $line = <LOG>)
		{	print HISTORY "$line" if ( defined $line );
		}
		
	close LOG;
	close HISTORY;
	

	return( 1 );
}



################################################################################
# 
sub KillOtherTTCUpdates()
#
#  Make sure that I'm the only TTCUpdate program running
#
################################################################################
{	
	
	# At this point I've been nice - now I'm getting mean
	my $my_pid = &ProcessGetCurrentProcessId();

	my %processes = &ProcessHash();
	
	# Figure out if there are any IpmMonitor processes running besides myself
	my @process_names	= values %processes;
	my @process_pids	= keys %processes;
	
	my @kill_pids;
	
	my $index = 0 - 1;
	foreach ( @process_names )
		{	$index++;
			
			next if ( ! $_ );
			
			my $name = lc( $_ );
			
			my $kill_it;
			
			# Is this an TTCUpdate process?
			$kill_it = 1 if ( $name =~ m/ttcupdate\.exe/ );
			
			# Is this an IpmUpgradeDB process?
			$kill_it = 1 if ( $name =~ m/ipmupgradedb\.exe/ );
			
			next if ( ! $kill_it );
			
			my $this_pid = $process_pids[ $index ];
			
			# Is this me?
			next if ( $this_pid eq $my_pid );
	
			push @kill_pids, $this_pid;				 
		}


	lprint "Found TTCUpdate and IpmUpgradeDB processes running, so killing them now ...\n" if ( $kill_pids[ 0 ] );
	
	# If I found any, kill them
	foreach ( @kill_pids )
		{	next if ( ! $_ );
			my $kill_pid = $_;
			lprint "Killing process $kill_pid\n";
			ProcessTerminate( $kill_pid );
		}
		
		
	return( 1 );
}



################################################################################
#
sub FixUpdateSource( $ )
#
#  If update source # 3 is something crazy, fix it
#  Somehow bad updates sources got sent out, so they have to be fixed
#
################################################################################
{	
	&lprint( "Checking the update sources ...\n" );
	
	my $dbh = &ConnectServer();
	&lprint( "Unable to connect to Content database\n" ) if ( ! $dbh );
	&lprint( "Connected to Content database\n" ) if ( $dbh );
	
	return( undef ) if ( ! $dbh );
	
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "select SourceUrl from IpmContentSource where SourceNumber = 3" );
	$sth->execute();


	my $ok = 1;
	my $count = 0 + 0;
	while ( ( ! $dbh->err )  &&  (  my ( $source_url ) = $sth->fetchrow_array() ) )
		{	next if ( ! $source_url );
			
			$ok = undef if ( $source_url =~ m/sa3/ ); 
			$ok = undef if ( $source_url =~ m/contentdb/ ); 
			$ok = undef if ( $source_url =~ m/opendb1/ ); 
			
			$count++;
		}
		

	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	
	# Fix it if it is bad
	if ( ! $ok )
		{	&lprint( "Setting update source 3 to opendb.lightspeedsystems.com\n" );
			$sth = $dbh->prepare( "UPDATE IpmContentSource set SourceUrl = \'http:\/\/opendb.lightspeedsystems.com\' where SourceNumber = 3" );
			$sth->execute();
			$sth->finish();
		}
	else
		{	&lprint( "Update sources are ok\n" );
		}
		
	$dbh->disconnect if ( $dbh );

	return( 1 );	
}



################################################################################
#
sub GetUpdate( $ )
#
#  Get the new TTCUpdate program.  Save it as TTCUpdate.new in the software directory
#  Return undef if a problem happened
#
################################################################################
{	my $dir = shift;
			
	# Switch to the working directory
	my $cur_dir = getcwd();	
	$cur_dir =~ s#/#\\#g;

	chdir( $dir );

 	$| = 1;

	my $full_filename = $dir . "\\update50\.htm";
	unlink( $full_filename );

	my $response = LWP::Simple::getstore( $update_url, $full_filename );

	my $ok = is_success( $response );

     if ( !$ok )
		{	my $error = HTTP::Status::status_message($response);
		     &lprint( "Get Update Request Error ($response): $error\n" );
			chdir( $cur_dir );
			return( undef );  #  Return that an error happened
		}

	&lprint( "Finished getting zipped TTCUpdate program\n" );
	
	
	# Delete any previous attempts
	unlink( "TTCUpdate\.new" );
	
	
	&lprint( "Unzipping TTCUpdate program\n" );
	
	my ( $err_msg, @files ) = &ScanUnzipFile( $dir, $full_filename );

	if ( $err_msg )
		{	&lprint( "Unable to unzip TTCUpdate program $full_filename: $err_msg\n" );
			chdir( $cur_dir );
			return( undef );					
		}
	
	if ( ! $files[ 0 ] )
		{	&lprint( "Unable to unzip TTCUpdate program $full_filename\n" );
			chdir( $cur_dir );
			return( undef );					
		}
	
	my $error = &ScanLastUnzipError();
	if ( $error )
		{	&lprint( "Error unzipping TTCUpdate program: $error\n" );
			chdir( $cur_dir );
			return( undef );					
		}
	
	
	my $new_file = $files[ 0 ];
	$new_file = lc( $new_file );
	$new_file = "nothing" if ( ! $new_file );
							  
	# At this point, there should have been one file in the zip called TTCUpdate.new
	if ( ! ( $new_file =~ m/ttcupdate\.new/ ) )
		{	&lprint( "New TTCUpdate program not found in TTCUpdate\.htm, found $new_file instead\n" );
			chdir( $cur_dir );
			return( undef );
		}
		
	&lprint( "Got and unzipped TTCUpdate program $new_file ok\n" );
		
	# Switch back to the original directory
	chdir( $cur_dir );
	
	return( 1 );
}



################################################################################
#
sub GetUpdatePackage( $ )
#
#  Get the new TTCUpdate package.  Unpack the contents in the tmp directory
#  Return undef if a problem happened, or True if ok
#  Put the unpacked files into the global variable @package_files
#
################################################################################
{	my $dir = shift;
	
	# Switch to the tmp directory
	my $cur_dir = getcwd();
	$cur_dir =~ s#/#\\#g;

	chdir( $dir );

 	$| = 1;

	my $full_filename = $dir . $package_file;
	my $response = LWP::Simple::getstore( $package_url, $full_filename );

	my $ok = is_success( $response );

     if ( !$ok )
		{	my $error = HTTP::Status::status_message($response);
		     &lprint( "Get Update Package Request Error ($response): $error\n" );
			chdir( $cur_dir );
			return( undef );  #  Return that an error happened
		}

	&lprint( "Finished getting zipped TTCUpdate package\n" );
	
		
	&lprint( "Unzipping TTCUpdate package\n" );
	
	@package_files = ();
	my $err_msg;
	( $err_msg, @package_files ) = &ScanUnzipFile( $dir, $full_filename );


	if ( $err_msg )
		{	&lprint( "Unable to unzip TTCUpdate package $full_filename: $err_msg\n" );
			chdir( $cur_dir );
			return( undef );					
		}
	
	if ( ! $package_files[ 0 ] )
		{	&lprint( "Unable to unzip TTCUpdate package $full_filename\n" );
			chdir( $cur_dir );
			return( undef );					
		}
	
	my $error = &ScanLastUnzipError();
	if ( $error )
		{	&lprint( "Error unzipping TTCUpdate package: $error\n" );
			chdir( $cur_dir );
			return( undef );					
		}
	
								  
	# At this point, there should have been one file in the zip called package.txt
	my $found;
	
	foreach ( @package_files )
		{	my $new_file = $_;
			next if ( ! $new_file );
			$new_file = lc( $new_file );
			
			$found = 1 if ( $new_file =~ m/package\.txt/ );
		}
		
		
	# Is the package.txt file in the zip?
	if ( ! $found )
		{	&lprint( "Package\.txt not found inside $full_filename\n" );
			return( undef );
		}
		
		
	&lprint( "Got and unzipped TTCUpdate package ok\n" );
		
	# Switch back to the original directory
	chdir( $cur_dir );
	
	return( 1 );
}



################################################################################
#
sub InstallFile( $ )
#
#  Install everything from a zipped package in the current directory
#  Used for testing
#
################################################################################
{	my $ttc_version = shift;
    my $dir = shift;
	
	my $cur_dir = getcwd();
	$cur_dir =~ s#/#\\#g;
	
	&lprint( "Installing package from directory $cur_dir\n" );
	
	my $full_filename = $cur_dir . $package_file;
	
	if ( ! -e $full_filename )
		{	&lprint( "Update package file $full_filename does not exist in the current directory\n" );
			return( undef );
		}
		
	@package_files = ();
	my $err_msg;
	( $err_msg, @package_files ) = &ScanUnzipFile( $dir, $full_filename );

	if ( $err_msg )
		{	&lprint( "Unable to unzip TTCUpdate package $full_filename: $err_msg\n" );
			return( undef );					
		}
	
	if ( ! $package_files[ 0 ] )
		{	&lprint( "Unable to unzip TTCUpdate package $full_filename\n" );
			return( undef );					
		}
	
	my $error = &ScanLastUnzipError();
	if ( $error )
		{	&lprint( "Error unzipping TTCUpdate package: $error\n" );
			return( undef );					
		}
	
								  
	# At this point, there should have been one file in the zip called package.txt
	my $found;
	
	foreach ( @package_files )
		{	my $new_file = $_;
			next if ( ! $new_file );
			$new_file = lc( $new_file );
			
			$found = 1 if ( $new_file =~ m/package\.txt/ );
		}
		
		
	# Is the package.txt file in the zip?
	if ( ! $found )
		{	&lprint( "Package\.txt not found inside $full_filename\n" );
			return( undef );
		}
		
		
	&lprint( "Unzipped TTCUpdate package ok\n" );
	
    my ( $new_packageversion, $result ) = &InstallPackage( $ttc_version, "test install", @package_files );
	
	&lprint ( "New package version = $new_packageversion\n" );

	&lprint ( "$result\n" );
}



################################################################################
#
sub GetUpdatetime()
#
#  Return the Date/time of the Update program on the Lightspeed website
#  Return undef if a problem happened
#
################################################################################
{
	my $url = $updatetime_url;
			
	$| = 1;

	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 100000 );
	$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			&lprint( "Request Error: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef);  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&lprint( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		}


	# Make sure the date and time I get back makes some sense
	my $lc_content = lc( $content );
	
	return( undef ) if ( ! ( $lc_content =~ m/last modified/ ) );
	
	
	# Return whatever Ryan put there
	return( $content );	
}



################################################################################
#
sub GetPackagetime()
#
#  Return the Date/time of the Update package on the Lightspeed website
#  Return undef if I had a problem
#
################################################################################
{
	my $url = $packagetime_url;
			
	$| = 1;

	my $ua = LWP::UserAgent->new();
	$ua->agent("Schmozilla/v9.14 Platinum");

	$ua->max_size( 100000 );
	$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			&lprint( "Request Error: ", $error, "\n" );
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef);  #  Return that an error happened
		}

	my $content = $response->content;
	
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	&lprint( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef );
		}


	# Return whatever Ryan put there
	return( $content );	
}



################################################################################
#
sub SetProperties( $$$$$ )
#
#  Set the properties in the registry.
#
################################################################################
{	my $new_updatetime		= shift;
	my $new_packagetime		= shift;
	my $result				= shift;
	my $new_packageversion	= shift;
	my $date				= shift;
	
	my $key;
	my $type;
	my $data;
	
	
	#  See if the key already exists
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_WRITE, $key );

	# if not, return undef
	if ( ! $ok )
		{	lprint "Unable to set the registry properties\n";
			return( undef );
		}
		
		
	RegSetValueEx( $key, "Last Software Update Time", 0,  REG_SZ, $new_updatetime );
	RegSetValueEx( $key, "Last Software Package Time", 0,  REG_SZ, $new_packagetime );
	RegSetValueEx( $key, "Last Software Update Package Version", 0,  REG_SZ, $new_packageversion );
	RegSetValueEx( $key, "Last Software Update Result", 0,  REG_SZ, $result );
	RegSetValueEx( $key, "Last Software Update Install Time", 0,  REG_SZ, $date ) if ( $date );
	
	RegCloseKey( $key );

	return( 1 );
}



################################################################################
#
sub GetProperties()
#
#  Return the properties from the registry.  Return never if they aren't there
#
################################################################################
{
	my $key;
	my $type;
	my $data;
	
	#  See if the main key already exists
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

	# if not, return undef
	return( "never", "never", "never" ) if ( ! $ok );

	$ok = RegQueryValueEx( $key, "Last Software Update Time", [], $type, $data, [] );
	my $last_updatetime = "never";
	$last_updatetime = $data if ( ( $ok )  &&  ( length( $data ) ) );

	$ok = RegQueryValueEx( $key, "Last Software Package Time", [], $type, $data, [] );
	my $last_packagetime = "never";
	$last_packagetime = $data if ( ( $ok )  &&  ( length( $data ) ) );
	
	$ok = RegQueryValueEx( $key, "Last Software Update Package Version", [], $type, $data, [] );
	my $last_packageversion = "n/a";
	$last_packageversion = $data if ( ( $ok )  &&  ( length( $data ) ) );
	
	RegCloseKey( $key );

	return( $last_updatetime, $last_packagetime, $last_packageversion );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = "$working_dir\\TTCUpdateErrors.log";
	
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	&lprint( "Unable to error logging set to $filename\n" );
			return;
		}
   
	&CarpOut( $MYLOG );
	&lprint( "Set error logging set to $filename\n" );
}



################################################################################
#
sub ReplaceUpdate( $ )
#
#  There is a new ttcupdate program called TTCUpdate.new
#  Rename the old update program to ttcupdate.old
#  rename the new update program from ttcupdate.new to ttcupdate.exe
#  And finally, run the new TTCUpdate program
#  If the new TTCUpdate is the same or old than the exisitng program, return OK
#
################################################################################
{	my $dir = shift;

	&lprint( "Updating the TTCUpdate program itself ...\n" );


	# Switch to the given directory
	my $ok = chdir( $dir );
	if ( ! $ok )
		{	&lprint( "Error: unable to switch to the directory $dir\n" );
			return( undef );	
		}
	
			
	# Make sure the TTCUpdate files are not readonly
	&NoReadOnly( "TTCUpdate\.old" );
	&NoReadOnly( "TTCUpdate\.new" );
	&NoReadOnly( "TTCUpdate\.exe" );
		
		
	# Make sure the TTCUpdateExt program is there
	if ( ! -e "TTCUpdateExt\.exe" )
		{	&lprint( "Error: the TTCUpdateExt\.exe program is not in the current directory $dir\n" );
			return( undef );	
		}
	
	
	# Make sure the new version is there
	if ( ! -e "TTCUpdate\.new" )
		{	&lprint( "Error: the new TTCUpdate\.new program is not in the current directory $dir\n" );
			return( undef );	
		}
	
	
	# Make sure that the new TTCUpdate program is on the file integrity database
	my @files;
	push @files, "TTCUpdate.new";
	&UpdateFileIntegrity( @files );


	# Make sure the old version is there
	if ( ! -e "TTCUpdate\.exe" )
		{	&lprint( "Error: the old TTCUpdate\.exe program is not in the current directory $dir\n" );
			return( undef );	
		}
	
	
	# Make sure the 2 files are different
	if ( ! &FileCompare( "TTCUpdate\.new", "TTCUpdate\.exe" ) )
		{	&lprint( "The new TTCUpdate\.exe program is the same or older than the existing program, so not updating it.\n" );
			unlink( "TTCUpdate\.old" );
			rename( "TTCUpdate\.new", "TTCUpdate\.old" );
			return( 1 );
		}
		
		
	# Make sure the older version isn't still hanging around
	unlink( "TTCUpdate\.old" );
	
	# Run the TTCUpdateExt program with the right arguments  
	exec "TTCUpdateExt\.exe TTCUpdate\.exe TTCUpdate\.old TTCUpdate\.new TTCUpdate\.exe TTCUpdate\.exe";
}



################################################################################
# 
sub NoReadOnly( $ )
#
#  Given a file name - make sure the readonly bit is turned off
#
################################################################################
{	my $file = shift;
	
	if ( -e $file )
		{	my $attrib;
			
			Win32::File::GetAttributes( $file, $attrib );
	
			# Is the readonly bit set?  If so, turn it off
			if ( $attrib & READONLY )
				{	$attrib = $attrib - READONLY;
					Win32::File::SetAttributes( $file, $attrib );
				}
		}
}



################################################################################
sub Truncate( $ )	# Truncate off to an integer value
################################################################################
{	my $val = shift;
	
	$val =~ s/\,/\./g;	# Get rid of commas
	my $int = 0 + $val;
	my $truc = sprintf( "%i", 0 + $int );
	$truc =~ s/\,/\./g;	# Get rid of commas
	$truc = 0 + $truc;

	return( $truc );
}



################################################################################
# 
sub EmailLogFile( $$$$ )
#
#  Given the file name prefix to use, the subject line, message test, and
#  the log file, email the log file to support@lightspeedsystems.
#
################################################################################
{	my $email_file		= shift;
	my $subject			= shift;
	my $message_text	= shift;
	my $log_file		= shift;
use MIME::Base64;
	
	my ( $dir, $short_file  ) = &SplitFileName( $log_file );
	
	my $software_dir = &SoftwareDirectory();
	
	chdir( $software_dir );
		
	# Build up the email message
	my $from		= "support\@lightspeedsystems.com";
	
	my @to;
	
	push @to, "support\@lightspeedsystems.com";
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d", $year, $mon, $mday, $hour, $min, $sec );
	my $filestr = sprintf( "%04d%02d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );

	$email_file .= $filestr;
	$email_file .= $to[ 0 ] . ".txt";
	
	my $hostname = &MonitorHostname();
	
	$subject = $subject . " from $hostname" if ( $hostname );
	
	# Build the message to send
	my ( $header, $b ) = &MailHeader( $from, $subject, @to );

	my $message = $header;
   
	# Buid up a text message as the first part of the multipart
    $message .= sprintf"\n--%s\n",$b;       
	$message .= "Content-Type: text/plain;\n";
	$message .= "	charset=\"us-ascii\"\n";
	$message .= "Content-Transfer-Encoding: quoted-printable\n\n";
	
    $message .= "=20\n\n";
	
	
	$message .= $message_text . "=20\n\n";
	
	$message .= sprintf"\n--%s\n",$b;
		  
	$message .= "Content-Type: application/text;
	name=\"$short_file\"
Content-Transfer-Encoding: base64
Content-Description: $short_file
Content-Disposition: attachment;
	filename=\"$short_file\"
\n";
	
   
	open INFILE, "<$log_file";
	binmode INFILE;
	
	my $buf;
	my $len = 0 + 57;
	
	while ( read( INFILE, $buf, $len ) )
		{	my $outbuf = encode_base64( $buf );
			$message .= "$outbuf";
		}
		
	close INFILE;
		 
	$message .= sprintf"\n--%s\n",$b;
	$message .= ".\n";
	
	my ( $ok, $msg ) = &PostMessageFile( $monitor_server, $email_file, $from, $message, undef, undef, @to );

	return( "OK" ) if ( $ok );
	
	return( "Error emailing log $log_file: $msg" );
}



################################################################################
# 
sub BuildDirectory( $ )
#
# Given a directory, do the best job possible in building it
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Does the directory already exist?
	return( 1 ) if ( -e $dir );
	
	my $ok = 1;
	
	my @parts = split /\\/, $dir;
	
	my $parent;
	foreach ( @parts )
		{	next if ( ! $_ );
			my $part = $_;
			
			$parent = $parent . "\\" . $part if ( $parent );
			
			$parent = $part if ( ! $parent );
			
			next if ( -e $parent );
			
			$ok = undef if ( ! mkdir( $parent ) );
		}
	
	return( $ok );
}


################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "Update";

    bprint "$_[0]\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
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
    my $me = "TTCUpdate";

    bprint <<".";
This program keeps Total Traffic Control software up to date by either 
contacting Lightspeed Systems at http://opendb.lightspeedsystems.com, or
by installing an install package directly from the current directory.
By default it waits a random period from 0 to 60 minutes before starting.


  -d, --download         force a software download immediately
  -f, --file             install from the current directory
  -n, --nowait           no waiting before starting to process
  -h, --help             display this help and exit
  -v, --version          display version information and exit
.
    &StdFooter;

    exit;
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "TTCUpdate";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
