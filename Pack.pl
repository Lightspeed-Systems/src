################################################################################
#!perl -w
#
# Rob McCarthy's Pack source code
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::File;
use Cwd;
use Archive::Zip qw( :ERROR_CODES );


use Pack::PackUtil;
use Pack::PackFile;
use Pack::PackSQL;
use Pack::Pack;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging;				# True if I should log to the file IpmCache.log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_wizard;					# True if run from a Wizard dialog
my $opt_unpack;
my $opt_file;
my $opt_all;
my $opt_directory;
my $opt_pack;
my $opt_verbose;



my $_version = "1.0.0";
my $p;							# Global error string



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
		"a|all"			=> \$opt_all,
		"d|dir=s"		=> \$opt_directory,
        "f|file=s"		=> \$opt_file,
        "l|logging"		=> \$opt_logging,
		"p|pack=s"		=> \$opt_pack,
		"u|unpack=s"	=> \$opt_unpack,
		"v|version"		=> \$opt_verbose,
		"h|help"		=> \$opt_help,
		"w|wizard"		=> \$opt_wizard,
		"x|xxx"			=> \$opt_debug
    );

	
    &StdHeader( "Pack" ) if ( ! $opt_wizard );
	
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	

	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
	$opt_verbose = 1 if ( $opt_debug );
	
		
	&SetLogFilename( 'Pack.log', $opt_debug ) if ( $opt_logging );
	

	# Start up packing
	my $readonly = 1 if ( $opt_unpack );
		

	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	# Default the directory
	$opt_directory = $cwd if ( ! $opt_directory );
	
	
	# Should I unpack?
	if ( $opt_all )
		{	if ( ( ! $opt_file )  ||  ( ! -f $opt_file ) )
				{	&lprint( "Unable to find Archive file $opt_file\n" ) if ( $opt_file );
					&lprint( "No Archive file specified with -f\n" ) if ( ! $opt_file );
					chdir( $cwd );
					&PackStop();
					&StdFooter;
					exit;
				}

			&lprint( "Unapack all the files from $opt_file\n" );
			&UnpackAll( $opt_file, $opt_directory );
		}
	elsif ( $opt_unpack )
		{
			my $ok = &PackStart( $readonly );
			if ( ! $ok )
				{	&lprint( "Error starting to pack\n" );
					my $last_err = &PackLastError();
					&lprint( "$last_err\n" ) if ( defined $last_err );
					exit( 0 );
				}
			
			if ( ( ! $opt_file )  ||  ( ! -f $opt_file ) )
				{	&lprint( "Unable to find Archive file $opt_file\n" ) if ( $opt_file );
					&lprint( "No Archive file specified with -f\n" ) if ( ! $opt_file );
					chdir( $cwd );
					&PackStop();
					&StdFooter;
					exit;
				}
				
			&lprint( "Unpacking file ID $opt_unpack to file $opt_file ...\n" );
			
			my $fileid = &PackFileStrFileID( $opt_unpack );
			
			$ok = &Unpack( $fileid, $opt_file );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( ( ! $ok )  &&  ( defined $last_err ) );
			&PackStop();			
		}
	elsif ( $opt_pack )	# Or should I pack?
		{
			
			my $ok = &PackStart( $readonly );
			if ( ! $ok )
				{	&lprint( "Error starting to pack\n" );
					my $last_err = &PackLastError();
					&lprint( "$last_err\n" ) if ( defined $last_err );
					exit( 0 );
				}

			if ( ( ! $opt_file )  ||  ( ! -f $opt_file ) )
				{	&lprint( "Unable to find Archive file $opt_file\n" ) if ( $opt_file );
					&lprint( "No Archive file specified with -f\n" ) if ( ! $opt_file );
					chdir( $cwd );
					&PackStop();
					&StdFooter;
					exit;
				}
				
			my $file = $opt_pack;
			&lprint( "Packing $file ...\n" );
					
			my $fullfile = $file;
			$fullfile = "$cwd\\$file" if ( ! ( $file =~ m/\\/ ) );
			
			my ( $packfile, $offset, $fileid ) = &Pack( $fullfile );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( ( ! defined $fileid )  &&  ( defined $last_err ) );

			&PackStop();
		}
		
		
	chdir( $cwd );
	
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
#
sub UnpackAll( $$ )
#
#  Given an archive file, unpack all the files within it
#
################################################################################
{	my $packfile	= shift;
	my $dir			= shift;
	
	&lprint( "Unpacking all the files from Lightspeed Archive file $packfile ...\n" );
	&lprint( "Unpacking to directory $dir ...\n" );

	my $offset = 0 + 6;
	
	my $size = -s $packfile;
	my $count = 0 + 0;
	my $ok;
	my $ending_offset;
	while ( ( ! $p )  &&  ( $offset < $size ) )
		{	( $ok, $ending_offset ) = &UnpackOffset( $packfile, $offset, $dir, $opt_debug, $opt_verbose );
			
			if ( ! $ok )
				{	&lprint( "Error unpacking $packfile: $p\n" ) if ( $p );
					&lprint( "Error unpacking $packfile\n" ) if ( ! $p );
					last;	
				}
			
			$offset = $ending_offset;
			$count++;
		}
	
	&lprint( "Unpacked $count files related metadata\n" );
	
	return( $ok );
}


################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = &SoftwareDirectory() . "\\PackErrors.log";
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
    my $me = "Pack";

    print <<".";
Usage: $me [OPTION(s)]

Pack packs and unpacks files to/from Lightspeed Archive pack format.


  -a, --all              Unpack all the files from an Archive file
						 This does NOT require SQL
  -d, --dir DIR          Directory to use for unpacking - default is current  
  -f, --file ARCHIVE     Archive file to use - default is the current days file
  -l, --logging          Log events
  -p, --pack PACKFILE    Pack a single file into Archive format
  -u, --unpack FileID    Unpack a single file ID from Archive format

  -h, --help             Display this help and exit
  -v, --verbose          Display verbose information
  
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
    my $me = "Pack";

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

