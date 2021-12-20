################################################################################
#!perl -w
#
# SpamArchive - origanize and run all the stuff to keep up a spam archive
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;

use Content::File;


# Options
my $opt_help;
my $opt_verbose;


my $opt_source_directory		= "C:\\Program Files\\Lightspeed Systems\\Traffic\\Mail Archive";	# This is the mail files to archive on the original TTC server
my $opt_local_source_directory	= "E:\\Program Files\\Lightspeed Systems\\Traffic\\Mail Archive";	# This is the mail files to archive on this server
my $opt_target_directory		= "S:\\Mail Archive";		# This is where to archive to
my $opt_incoming_spool			= "S:\\IncomingSpool";		# This is the directory of the incoming mail files from Barracuda
my $opt_outgoing_spool			= "C:\\Program Files\\Lightspeed Systems\\Traffic\\Mail Archive\\Spool";	# This is the directory of the outgoing spool files
my $opt_spam_for_review			= "H:\\Spam For Review";	# The location of the Spam for Review directory

my $opt_date;				# This is the date I'm working on in the format MM/DD/YYYY
my $opt_unlink;				# Delete work files when done
my $last_file_count = 0 + 0;
my $last_file_size	= 0 + 0;

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
        "d|date=s"			=>	\$opt_date,
        "i|incoming"		=>	\$opt_incoming_spool,
        "s|source=s"		=>	\$opt_source_directory,
        "l|local=s"			=>	\$opt_local_source_directory,
        "r|review=s"		=>	\$opt_spam_for_review,
        "t|target=s"		=>	\$opt_target_directory,
        "u|unlink"			=>	\$opt_unlink,
		"v|verbose"			=>	\$opt_verbose,
		"h|help"			=>	\$opt_help
    );
	

    &StdHeader( "SpamArchive" );


    &Usage() if ( $opt_help );


	# Figure out my starting directory
	my $home_dir = getcwd;
	$home_dir =~ s#\/#\\#gm;

	&SetLogFilename( "$home_dir\\SpamArchive.log", undef );


	if ( ! -d $opt_local_source_directory )
		{	lprint "Can not find local source directory $opt_local_source_directory\n";
			exit( 0 );
		}

	if ( ! -d $opt_target_directory )
		{	lprint "Can not find target directory $opt_target_directory\n";
			exit( 0 );
		}

	if ( ! -d $opt_incoming_spool )
		{	lprint "Can not find incoming spool directory $opt_incoming_spool\n";
			exit( 0 );
		}

	if ( ! -d $opt_outgoing_spool )
		{	lprint "Can not find outgoing spool directory $opt_outgoing_spool\n";
			exit( 0 );
		}

	if ( ! -d $opt_spam_for_review )
		{	lprint "Can not find spam for review directory $opt_spam_for_review\n";
			exit( 0 );
		}



	# If the date isn't set, pick 3 days ago
	if ( ! $opt_date )
		{	my $old_time = time - ( 72 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );
			$year	= 1900 + $year;
			$mon	= $mon + 1;
			
			$mon	= sprintf( "%02d", $mon );
			$mday	= sprintf( "%02d", $mday );
			
			$opt_date = "$mon/$mday/$year";
		
		}
		
	my $ok = &ValidateDate( $opt_date );
	
	if ( ! $ok )
		{	lprint "$opt_date is not a valid date in the format MM/DD/YYYY\n";
			exit( 1 );
		}
		
	lprint "Spam Archiving for date $opt_date ...\n";
	
	
	# Create the target directory and copy the mail files to it
	my ( $mon, $mday, $year ) = split /\//, $opt_date;
	$mon	= sprintf( "%02d", $mon );
	$mday	= sprintf( "%02d", $mday );
	
	my $date_dir = "$year$mon$mday";
	
	my $source			= $opt_local_source_directory . "\\$date_dir";
	my $target			= $opt_target_directory . "\\$date_dir";
	my $original_dir	= $opt_source_directory . "\\$date_dir";
	
	if ( ! -d $source )
		{	lprint "Source directory $source does not exist!\n";
			exit( 1 );
		}
	
	mkdir( $target );
	
	if ( ! -d $target )
		{	lprint "Can not create target directory $target\n";
			exit( 1 );
		}
	
	
	# Xcopy the files into the correct directory
	my $cmd = "xcopy \"$source\\*.*\" \"$target\" /s /y /c";
	lprint "Running command: $cmd\n";
	sleep( 10 );
	system $cmd;
	
	lprint "Waiting 60 seconds before running the next command ...\n";
	sleep( 60 );
	
	
	# Build the clue files for each message file with IpmRealtimeSpam
	$cmd = "IpmRealtimeSpam -e -n \"$target\"";
	lprint "Running command: $cmd\n";
	sleep( 10 );
	system $cmd;
	
	lprint "Waiting 60 seconds before running the next command ...\n";
	sleep( 60 );
	
	
	# Run the Barracuda command in the right directory
	$cmd = "Barracuda -u -d \"$target\" -s \"$original_dir\"" if ( $opt_unlink );
	$cmd = "Barracuda -d \"$target\" -s \"$original_dir\""	if ( ! $opt_unlink );
	lprint "Running command: $cmd\n";
	sleep( 10 );
	system $cmd;
	
	lprint "Waiting 60 seconds before running the next command ...\n";
	sleep( 60 );
	
	
	# Run the IpmSMTPRelay command to send the file through the Barracuda test machine
	$cmd = "IPMSMTPRelay -d -s -e";
	lprint "Running command: $cmd\n";
	sleep( 10 );
	system $cmd;
	
	
	# Waiting around until IPMSMTPRelay has finished ...
	$last_file_count	= 0 + 0;
	$last_file_size		= 0 + 0;
	while ( &DirectoryChanged( $opt_outgoing_spool ) )
		{	lprint "Waiting for the outgoing spool directory to finish ...\n";
			sleep( 60 );
			
			$cmd = "IPMSMTPRelay -d -s -e";
			lprint "Running command: $cmd\n";
			sleep( 10 );
			system $cmd;
		}
		
		
	# Waiting around until IPMSMTPRelay has finished ...
	$last_file_count	= 0 + 0;
	$last_file_size		= 0 + 0;
	while ( &DirectoryChanged( $opt_incoming_spool ) )
		{	lprint "Waiting for the incoming spool directory to finish ...\n";
			sleep( 60 );
		}
		
		
	# Run the Barracuda Results command in the right directory
	$cmd = "BarracudaResults -u -b \"$opt_incoming_spool\" -d $opt_date -s \"$opt_spam_for_review\"";
	$cmd = "BarracudaResults -b \"$opt_incoming_spool\" -d $opt_date -s \"$opt_spam_for_review\"" if ( ! $opt_unlink );
	lprint "Running command: $cmd\n";
	sleep( 10 );
	system $cmd;

	
	chdir( $home_dir );
	
	&StdFooter;

    exit;
}



################################################################################
# 
sub DirectoryChanged( $ )
#
#  Return True if the directory has changed since the last check, undef if not
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! -d $dir );
	
	lprint "Checking $dir to see if it has changed ...\n";
	
	# Process the queue directory
	if ( ! opendir( DIR, $dir ) )
		{	print "Error opening the directory $dir: $!\n";
			return( undef );
		}
	
	my $file_count = 0 + 0;
	my $file_size = 0 + 0;
	while ( defined( my $file = readdir( DIR ) ) )
		{	next if ( ! defined $file );
			
			$file_count++;
			my $full_filename = "$dir\\$file";
			
			my $size = -s $full_filename;
			next if ( ! $size );
			
			$file_size += $size;
		}

	closedir( DIR );
	
	# How does it compare to the last check?
	if ( ( $last_file_count == $file_count )  &&  ( $last_file_size == $file_size ) )
		{	print "$dir has not changed\n";
			return( undef );
		}

	# Save the values for the next check
	$last_file_count = $file_count;
	$last_file_size = $file_size;
	
	lprint "$dir has changed\n";
	
	return( 1 );	
}



################################################################################
# 
sub ValidateDate( $ )
#
#  Check that a date string is valid
#
################################################################################
{	my $date = shift;
	return( 1 ) if ( ! defined $date );
	
	my ( $mon, $mday, $year ) = split /\//, $date;
	
	return( undef ) if ( ! $mon );
	return( undef ) if ( ! $mday );
	return( undef ) if ( ! $year );
	
	return( undef ) if ( $mon =~ m/\D/ );
	return( undef ) if ( $mday =~ m/\D/ );
	return( undef ) if ( $year =~ m/\D/ );
	
	$mon = 0 + $mon;
	return( undef ) if ( ( $mon < 1 )  ||  ( $mon > 12 ) );
	return( undef ) if ( ( $mday < 1 )  ||  ( $mday > 31 ) );
	return( undef ) if ( ( $year < 2007 )  ||  ( $year > 2100 ) );
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SpamArchive";
    print <<".";
Spam Archive utility - copies mail files from the source directory
to the target directory, and then executes the various programs to 
test and classify the mail.

Usage: $me [OPTION(s)]
  
  -d, --date=DATE          date in the format MM/DD/YYYY.
                           Default is 3 days ago.
  -i, --incoming           incoming spool directory.
                           Default is $opt_incoming_spool
  -r, --review=REVIEWEDIR  directory of spam for review.
                           Default is $opt_spam_for_review
  -s, --source=SOURCEDIR   source directory of mail files to archive.
                           Default is $opt_source_directory
  -l, --local=LOCALDIR     local source directory of mail files to archive.
                           Default is $opt_local_source_directory
  -t, --target=TARGETDIR   target directory of mail files to archive.
                           Default is $opt_target_directory
  -u, --unlink             delete work files when done
  -h, --help               display this help and exit
  -v, --verbose            display verbose information
.
    exit;
}



################################################################################

__END__

:endofperl
