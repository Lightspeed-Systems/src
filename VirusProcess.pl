################################################################################
#!perl -w
#
# Rob McCarthy's VirusProcess.pl source code
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long();
use Cwd;
use File::Copy;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Process;
use Sys::Hostname;



use Content::File;
use Content::FileIntegrity;


my $opt_file;
my $opt_help;
my $opt_debug;
my $opt_verbose;
my $hostname = hostname;
my $log_directory				= "Q:\\Virus Logs";





# This is the list of log file that could be created in the directory
my @log_files = (
"IpmRealtimeSpam.log",
"IpmRealtimeSpamErrors.log",
"IpmCategorizeErrors.log",
"Conclusions.txt",
"salist.log",
"kasplist.log",
"clamlist.log",
"VirusProcess.log",
"VirusProcessErrors.log",
"CheckFile.log",
"CheckFileErrors.log"
);


			
################################################################################
#
MAIN:
#
################################################################################
{
	my $options = Getopt::Long::GetOptions
       (
			"f|file=s"		=> \$opt_file,
			"h|help"		=> \$opt_help,
			"v|verbose"		=> \$opt_verbose,
			"x|xxx"			=> \$opt_debug
      );


	&StdHeader( "VirusProcess" );


	&Usage() if ( $opt_help );
	
	
	# Figure out the hostname
	$hostname = hostname;
	$hostname = "unknown" if ( ! defined $hostname );
	
	
	&TrapErrors() if ( ! $opt_debug );
	
	
	my $fullfile = shift;
	$fullfile = $opt_file if ( ! defined $fullfile );
	
	
	&Usage() if ( ! defined $fullfile );
	
	
	my $cwd = getcwd();
	$cwd =~ s#\/#\\#gm;


	if ( ! -d $log_directory )
		{	print "Unable to find the log directory $log_directory\n";
			exit( 1 );
		}
		
	
	my $log_filename = "$log_directory\\VirusProcess-$hostname.log";		# The name of the log file to use
	
	# Delete the log file if it is getting too big
	my $log_size = -s $log_filename;
	unlink( $log_filename ) if ( ( $log_size )  &&  ( $log_size > 10000000 ) );
	
	&SetLogFilename( $log_filename, 1 );
	
	
	if ( ! -s $fullfile )
		{	lprint "Unable to find file $fullfile\n";
			exit( 1 );
		}
		
	
	# Actually do something now	
	my $ok = &VirusProcess( $fullfile );
	
	chdir( $cwd );
	
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $filename = "$log_directory\\VirusProcessErrors-$hostname.log";
	
	my $MYLOG;
   
	# If the error log is getting really big then delete it
	my $size = -s $filename;
	unlink( $filename ) if ( ( $size )  &&  ( $size > 1000000 ) );
	
	if ( ! open( $MYLOG, ">>$filename" ) )
		{	&lprint( "Unable to open $filename: $!\n" );  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	&lprint( "Error trapping set to file $filename\n" ); 
}



################################################################################
# 
sub VirusProcess( $ )
#
#  Given a full path to a message file that may contain virus infected attachments,
#  do the best job possible of analzing the file.  Return True if OK, undef if a problem.
#
################################################################################
{	my $fullfile = shift;
	

	lprint( "Expanding file $fullfile ...\n" );
	
	my $ok = 1;

	
	# Does the file look like an email file?
	my $email_file;
	$email_file = 1 if ( $fullfile =~ m/\.txt$/i );
	$email_file = 1 if ( $fullfile =~ m/\.lscom\.net$/i );
	
	
	# First - figure what what email address sent this - if it is an email file
	my $header_email_from;
	
	if ( $email_file )
		{	if ( ! open( FILE, "<$fullfile" ) )
				{   &lprint( "Error opening file $fullfile: $!\n" );
					  
					return( undef );
				}

			
			while ( my $line = <FILE> )
				{	chomp( $line );
					next if ( ! $line );
					
					my $no_comments = lc( $line );
						

					#  Consume any comments in the header - to avoid being deceived
					#  Do this to the lc variable, to preserver () in other cases
					if ( $no_comments =~ m/\(.*\)/ )
						{  $no_comments =~ s/\(.*\)//;
							$no_comments = "\(\)" if ( !$no_comments );  # if nothing left, pad it to be a blank comment
						}

					#  Am I a setting the header email from?
					if ( $no_comments =~ m/^from:/ )
						{   my $stuff = $line;
							
							$stuff =~ s/^from://i;
							
							$header_email_from = $stuff;
							$header_email_from =~ s/^\s//g;
							$header_email_from =~ s/\s$//g;
							
							#  Grab anything inside < > as the email address if <> exists
							$header_email_from = $1 if ( $stuff =~ m/\<(.*?)\>/ );

							$header_email_from = &CleanEmail( $header_email_from );
							last if ( $header_email_from );
						}
				}
				
			close( FILE );
		}
		
	lprint( "Email message from: $header_email_from\n" ) if ( defined $header_email_from );
		
		
	my ( $virus_subdir, $shortfile ) = &SplitFileName( $fullfile );
	
	# If I don't have a full pathname then use the current directory
	if ( ! defined $virus_subdir )
		{	$virus_subdir = getcwd();
			$virus_subdir =~ s#\/#\\#gm;
			
			$fullfile = "$virus_subdir\\$fullfile";
		}
		
	
	lprint "Switching current directory to: $virus_subdir ...\n";
	chdir( $virus_subdir );
	
	
	# Do I need to extact out attachments?
	if ( $email_file )
		{	lprint "Extracting in directory: $virus_subdir ...\n";
			&AttachmentExtract( $virus_subdir, $fullfile );
		}
		
	
	my @attached_files;
	
	my $qnew_filename = quotemeta( $fullfile );
	
	
	# Now build a list of the files I've got ...
	if ( ! opendir( VIRUS_SUBDIR, $virus_subdir ) )
		{	lprint( "Error opening directory $virus_subdir: $!\n" );
			return( undef );
		}

		
	while ( my $file = readdir( VIRUS_SUBDIR ) )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );
			

			# Ignore any log file
			my $log_file;
			foreach ( @log_files )
				{	my $l_file = $_;
					next if ( ! defined $l_file );
					
					my $ql_file = quotemeta( $l_file );
					
					$log_file = 1 if ( $file =~ m/^$ql_file$/i );
				}
				
			next if ( $log_file );
			
			my $this_file = "$virus_subdir\\$file";		
			
			next if ( -d $this_file );

			# Ignore myself if I am an email file
			next if ( ( $email_file )  &&  ( $this_file =~ m/^$qnew_filename$/i ) );
			
			
			push @attached_files, $this_file;
		}
		
	closedir( VIRUS_SUBDIR );
	
	
	# Extract out any attached message files
	foreach ( @attached_files )
		{	my $this_file = $_;
			next if ( ! defined $this_file );
			
			if ( $this_file =~ m/\.eml$/i )
				{	&AttachmentExtract( $virus_subdir, $this_file );
				}
			elsif ( $this_file =~ m/\.txt$/i )
				{	&AttachmentExtract( $virus_subdir, $this_file );
				}
		}
		
		
	# Now build the final list of the files I've got ...
	@attached_files = ();
	if ( ! opendir( VIRUS_SUBDIR, $virus_subdir ) )
		{	lprint( "Error opening directory $virus_subdir: $!\n" );
			return( undef );
		}
		

	# Calculate up a file ID for the original file
	my $file_id = &ApplicationFileID( $fullfile );
	if ( ! $file_id )
		{	lprint "Unable to calculate a file ID for $fullfile\n";
			next;	
		}
		
	my $hex_file_id = &StrToHex( $file_id );
	
	
	my %file_id;
	
	while ( my $file = readdir( VIRUS_SUBDIR ) )
		{	next if ( ! defined $file );
			
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			
			# Ignore any log file
			my $log_file;
			foreach ( @log_files )
				{	my $l_file = $_;
					next if ( ! defined $l_file );
					
					my $ql_file = quotemeta( $l_file );
					
					$log_file = 1 if ( $file =~ m/^$ql_file$/i );
				}
				
			next if ( $log_file );
		
			my $contained_file = "$virus_subdir\\$file";

			next if ( -d $contained_file );
					
			# Ignore myself if I am an email file
			next if ( ( $email_file )  &&  ( $contained_file =~ m/^$qnew_filename$/i ) );	
			
			my $file_id = &ApplicationFileID( $contained_file );

			# Keep track of the file IDs for each file I created
			$file_id{ $contained_file } = $file_id if ( defined $file_id );
			
			push @attached_files, $contained_file;
		}
		
	closedir( VIRUS_SUBDIR );
	
	
	my $cmd = "scan -c -z -l salist.log";
	lprint "System command: $cmd\n";
	
	system $cmd;

	$cmd = "vlogcopy salist.log sa -p";
	lprint "System command: $cmd\n";
	
	system $cmd;

	
	# Launch the checkfile program for each file that has a file ID
	my @file_id_files = keys %file_id;
	foreach ( @file_id_files )
		{	my $contained_file = $_;
			next if ( ! $contained_file );
			next if ( ! -f $contained_file );
			
			&LaunchCheckFile( $virus_subdir, $contained_file, $hex_file_id );
		}
	
	
	return( $ok );
}



################################################################################
# 
sub LaunchCheckFile( $$$ )
#
#	Given a directory and a full path, launch CheckFile.exe to analyze the file
#
################################################################################
{	my $virus_subdir	= shift;
	my $contained_file	= shift;
	my $hex_file_id		= shift;
	
	# Now run CheckFile.exe in the virus subdirectory
	chdir( $virus_subdir );
	
	my $processObj;
	my $retcode;
	my $cmd = "c:\\content\\bin\\CheckFile.exe \"$contained_file\" -i \"$hex_file_id\"";
	
	
	lprint "Running CheckFile.exe in directory $virus_subdir\n";
	lprint "CheckFile command: : $cmd ...\n";


	if ( ! Win32::Process::Create( $processObj, "c:\\content\\bin\\CheckFile.exe", $cmd, 0, NORMAL_PRIORITY_CLASS, "." ) )
		{	&lprint( "Error executing command $cmd\n" );
			my $str = Win32::FormatMessage( Win32::GetLastError() );
			&lprint( "$str\n" );
			return( undef );
		}	


	if ( $processObj->Wait( ( 120 * 1000 ) ) )  #  Wait up to 120 seconds
		{	$processObj->GetExitCode( $retcode );
		}
	else  # Kill it if it's taking too long
		{	$processObj->Kill( 0 );  # Kill the process
			&lprint( "Killed the VirusProcess.exe process\n" );
			return( undef );
		}
	
	
	lprint "CheckFile completed OK\n";
	
	return( 1 );
}



################################################################################
# 
sub AttachmentExtract( $$ )
#
#	given a file that could be a message file - try to extract out the attachments
#
################################################################################
{	my $virus_subdir	= shift;
	my $full_file		= shift;
	
	
	lprint "Extracting out any attachments from $full_file ...\n";
	
	# Now run IpmRealtimeSpam to break apart the file
	chdir( $virus_subdir );
	
	my $processObj;
	my $retcode;
	my $cmd = "c:\\content\\bin\\IpmRealtimeSpam.exe -0 -k -t . -n \"$full_file\"";
	
	if ( ! Win32::Process::Create( $processObj, "c:\\content\\bin\\IpmRealtimeSpam.exe", $cmd, 0, NORMAL_PRIORITY_CLASS, "." ) )
		{	&lprint( "Error executing command $cmd\n" );
			my $str = Win32::FormatMessage( Win32::GetLastError() );
			&lprint( "$str\n" );
			return( undef );
		}	


	if ( $processObj->Wait( ( 600 * 1000 ) ) )  #  Wait up to 600 seconds
		{	$processObj->GetExitCode( $retcode );
		}
	else  # Kill it if it's taking too long
		{	$processObj->Kill( 0 );  # Kill the process
			&lprint( "Killed the IpmRealtimeSpam process\n" );
			return( undef );
		}
	
	
	# Do I have the unzip and unrar programs?
	if ( ! -f "C:\\Program Files\\WinZip\\wzunzip.exe" )
		{	&lprint( "Could not file unzip program C:\\Program Files\\WinZip\\wzunzip.exe\n" );
			return( 1 );
		}
		
	if ( ! -f "C:\\content\\bin\\unrar.exe" )
		{	lprint "Could not file unrar program C:\\content\\bin\\unrar.exe\n";
			return( 1 );
		}

	# Now unzip and unrar anything that I got ...
	lprint "Unzipping any archives ...\n";
	
	system "\"C:\\Program Files\\WinZip\\wzunzip.exe\" -o -jhrs -ybc -s\"infected\" *.zip";
	system "unrar e -o+ -p- *.rar";

	return( 1 );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";
Usage: VirusProcess [options] emailfile

Given an file, or an email message, break it apart, expand any attachments, and
run the CheckFile utility to analyze the file and/or attachments.

  
  -h, --help           print this message and exit
.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
