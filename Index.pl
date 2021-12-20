################################################################################
#!perl -w
#
# Rob McCarthy's Index source code
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::File;
use Cwd;


use Pack::PackFile;
use Pack::PackSQL;
use Pack::Pack;
use Index::Index;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging = 1;			# True if I should log to the file IpmCache.log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_wizard;					# True if run from a Wizard dialog
my $opt_unpack;
my $opt_file;
my $opt_dir;					# If True, then index everything in this directory


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
        "u|unpack=s"	=> \$opt_unpack,
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help,
        "w|wizard"		=> \$opt_wizard,
        "x|xxx"			=> \$opt_debug,
    );

	
    &StdHeader( "Index" ) if ( ! $opt_wizard );
	
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	

	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
	
		
	if ( $opt_logging )	
		{	my $logfile = &SoftwareDirectory() . "\\Index.log";
			&SetLogFilename( $logfile, $opt_debug );
			print "Logging to file $logfile\n";
		}
		
	
	# If I'm indexing a directory, make sure it exists
	if ( ( $opt_dir )  &&  ( ! -d $opt_dir ) )
		{	&lprint( "Directory $opt_dir does not exist\n" );
			exit;
		}
		

	# Start up packing
	my $ok = &PackStart( undef );
	if ( ! $ok )
		{	&lprint( "Error starting to pack\n" );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 0 );
		}
		

	# Start up indexing
	$ok = &IndexStart();
	if ( ! $ok )
		{	&lprint( "Error starting to index\n" );
			my $last_err = &IndexLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 0 );
		}
		

	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	if ( $opt_dir )
		{	&IndexDir( $opt_dir );
		}
	else	
		{	while ( my $file = shift )
				{	&lprint( "Indexing $file ...\n" );

					my $fullfile = $file;
					$fullfile = "$cwd\\$file" if ( ! ( $file =~ m/\\/ ) );
					
					my $ok = &Index( $fullfile, undef );
					my $last_err = &IndexLastError();
					&lprint( "$last_err\n" ) if ( ( ! $ok )  &&  ( defined $last_err ) );
				}
		}
		
		
	chdir( $cwd );
	
	
	&IndexStop();
	&PackStop();
	
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
#
sub IndexDir( $ )
#
#  Index all the files in a directory - return the count of files indexed
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! $dir );
	return( undef ) if ( ! -e $dir );
						
	# Process the directory
	return( undef ) if ( ! opendir( DIR, $dir ) );
	
	my $file_counter = 0 + 0;
	while ( my $file = readdir( DIR ) )
		{	# Skip metadata files ...
			next if ( $file =~ m/\.metadata$/i );

			my $fullfile = "$dir\\$file";
			
			# Skip subdirectories ...
			next if ( -d $fullfile );

			# Skip empty files ...
			next if ( ! -s $fullfile );
					
			# Skip spam files
			next if ( ( $file =~ m/^s/i )  &&  ( $file =~ m/\.txt$/i ) );
			
			# Skip virus files
			next if ( ( $file =~ m/^v/i )  &&  ( $file =~ m/\.txt$/i ) );
			
			# Skip temp files
			next if ( ( $file =~ m/^x/i )  &&  ( $file =~ m/\.txt$/i ) );
			
			$file_counter++;
			&lprint( "Indexing # $file_counter: $file ...\n" );
			
			my $ok = &Index( $fullfile, undef );
			my $last_err = &IndexLastError();
			&lprint( "$last_err\n" ) if ( ( ! $ok )  &&  ( defined $last_err ) );
		}

	close( DIR );
	
	return( $file_counter );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = &SoftwareDirectory() . "\\IndexErrors.log";
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
    my $me = "Index";

    print <<".";
Usage: $me [OPTION(s)]
Index indexes email and documents.


  -l, --logging  log events
  -h, --help     display this help and exit
  -v, --version  display version information and exit
  
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
    my $me = "Index";

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

