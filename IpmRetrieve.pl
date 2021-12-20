################################################################################
#!perl -w
#
# Rob McCarthy's IpmRetrieve source code
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::File;
use Cwd;
use MIME::Base64;


use Pack::PackFile;
use Pack::PackUtil;
use Pack::PackSQL;
use Pack::Pack;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging = 1;			# True if I should log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_wizard;					# True if run from a Wizard dialog
my $opt_dir;					# If set, unpack the file to dir, but don't email it
my $opt_file;					# If set, this is the file name to extract to


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
        "d|dir=s"		=> \$opt_dir,
        "f|file=s"		=> \$opt_file,
        "l|logging"		=> \$opt_logging,
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help,
        "w|wizard"		=> \$opt_wizard,
        "x|xxx"			=> \$opt_debug,
    );

	
    &StdHeader( "IpmRetrieve" ) if ( ! $opt_wizard );
	
	
    &Usage() if ( $opt_help );
    &Version() if ($opt_version);
	

	# If unpacking to a directory - does the directory exist?
	if ( ( $opt_dir )  &&  ( ! -d $opt_dir ) )
		{	print "Directory $opt_dir doesn't exist\n";
			exit( 1 );
		}


	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
		
		
	&SetLogFilename( 'IpmRetrieve.log', $opt_debug ) if ( $opt_logging );


	&lprint( "Unpacking to directory $opt_dir but not emailing ...\n" ) if ( $opt_dir );
	
	
	# Start up packing - readonly mode
	my $ok = &PackStart( 1 );
	if ( ! $ok )
		{	&lprint( "Error starting to pack\n" );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 2 );
		}
		

	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	# Get the docid and the email address - unless I'm just unpacking to a directory
	my $docid_str = shift;
	if ( ! $docid_str )
		{	&lprint( "No document IDs specified\n" );
			exit( 4 );
		}
				 
	my @docid = split /\;/, $docid_str;
	if ( ! $docid[ 0 ] )
		{	&lprint( "Invalid document ID specified\n" );
			exit( 5 );
		}
	
	my $email;
	
	if ( ! $opt_dir )
		{	$email = shift;
			$email = &CleanEmail( $email );
			
			if ( ! $email )
				{	&lprint( "Invalid email address\n" );
					exit( 3 );
				}
		}
	
	
	# Keep a list of the tmp files I created
	my @tmp_file;
	
	my $exitcode = 0 + 0;
	
	my $counter = 0 + 1;
	foreach ( @docid )
		{	my $docid = $_;
			next if ( ! $docid );
			
			# Figure out a tmp file to use
			my $pid = &PackUtilPID();
			my $tmp_file = &TmpDirectory() . "\\IpmRetrieve$pid$counter.tmp";
			$tmp_file = $opt_dir . "\\IpmRetrieve$pid$counter.tmp" if ( $opt_dir );
			$tmp_file = $opt_dir . "\\$opt_file" if ( ( $opt_dir )  &&  ( $opt_file ) );
			
			
			# If I'm unpacking the file to a directory then also unpack the metadata
			my $meta_file = $tmp_file . ".metadata" if ( $opt_dir );


			&lprint( "Unpacking Doc ID $docid to file $tmp_file ...\n" );
			$ok = &UnpackDocID( $docid, $tmp_file, $meta_file );		
			
			
			# Did I have a problem unpacking the file?
			if ( ! $ok )
				{	&lprint( "Error unpacking $docid\n" );
					my $last_err = &PackLastError();
					&lprint( "$last_err\n" ) if ( defined $last_err );
					$exitcode = 100 + $counter if ( ! $exitcode );
					
				}
			else
				{	push @tmp_file, $tmp_file;
				}
				
			$counter++;
		}
		
		
	# If I'm supposed to email the file(s) - do so now ...
	if ( ( $ok )  &&  ( ! $opt_dir ) )
		{	# Email the temporary file to the email address
			&lprint( "Emailing @docid to $email ...\n" );
			my $message_filename_ref;
			( $ok, $message_filename_ref ) = &PackEmailFile( \@docid, \@tmp_file, $email );

			if ( ! $ok )
				{	&lprint( "Error emailing Doc ID(s) @docid to $email\n" ) if ( ! $ok );
					my $last_err = &PackLastError();
					&lprint( "$last_err\n" ) if ( defined $last_err );
					$exitcode = 0 + 6;
				}	
			else
				{	my @message_filename = @$message_filename_ref;
					
					for ( my $i = 0 + 0;  $message_filename[ $i ];  $i++ )
						{	my $message_filename = $message_filename[ $i ];
							next if ( ! $message_filename );
							
							&lprint( "Copied message file to $message_filename\n" );
							
							# Wait around for a few seconds to see if it went out
							my $count = 0 + 0;
							while ( -e $message_filename )
								{	sleep( 1 );
									$count++;
									
									last if ( $count > 3 );
								}
							
							my $docid = $docid[ $i ];
							
							if ( ! -e $message_filename )	
								{	&lprint( "Emailed doc ID $docid (message file $message_filename) to $email OK\n" );
								}
							else
								{	&lprint( "$message_filename is still waiting to be mailed in the SMTP spool directory\n" );
								}
						}
				}
				
			# Clean up any tmp files that I created
			foreach ( @tmp_file )
				{	my $tmp_file = $_;
					next if ( ! $tmp_file );
					unlink( $tmp_file ) if ( -e $tmp_file );	
				}
		}
		
	chdir( $cwd );
	
	&PackStop();
	
	&StdFooter;

	exit( $exitcode );
}
################################################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = &SoftwareDirectory() . "\\IpmRetrieveErrors.log";
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	print( "Unable to open $filename for error logging: $!\n" ); 
			return;
		}
		
	&CarpOut( $MYLOG );
   
	print( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmRetrieve";

    print <<".";
Usage: $me docid emailaddress [OPTION(s)]

IpmRetrieve unpacks a given docID and emails it.

IpmRetrieve with the directory option will unpack a doc ID into the
directory and will NOT email it.  The file option is only used with
the directory option.

To unpack a list of docids you must separate each docID with a \';\',
for example 000001;000002;000004

  -d, --dir DIR   to unpack the doc ID to a directory without mailing
  -f, --file FILE to unpack to a FILE name instead of the default
  -h, --help      display this help and exit
  -v, --version   display version information and exit
  
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
    my $me = "IpmRetrieve";

    print <<".";
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

