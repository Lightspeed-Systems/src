################################################################################
#!perl -w
#
#  Rob McCarthy's Categorize perl source
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Cwd;


use Content::File;
use Content::SQL;
use Content::Category;
use Content::Categorize;
use Content::Process;
use Content::EmailError;



# Common directories
my $log_directory	= 'C:\\Content\\Log';		# This is the directory to write the logs to
my $tmp_directory	= 'C:\\Content\\tmp';		# This is the tmp directory to download programs and images to



# Options
my $opt_debug;							# True if debugging
my $opt_root_dir;						# Directory to look for the keywords file - default is &KeywordsFile()
my $opt_input_file;     				# The file name if supposed to read unknown urls from a file
my $max_tokens = 0 + 2000;				# The maximum number of tokens to read from a URL before quitting - this is usually smaller than when building keywords in IpmBuildKeywords					
my $opt_sensitivity;					# Keyword sensitivity - from 0 to 100, 50 is the default
my $opt_source = 0 + 3;                 # Source number = 4 is default, 3 is Lightspeed
my $opt_show_most_interesting;			# Show the most interesting picks
my $opt_category;                       # Option for categorizing just one category
my $opt_version;						# Display version # and exit
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $_version = "1.0.0";					# Current version number

my $dbh;								# The global database handle
my $dbhCategory;
my $dbhLookup;

my %options;							# The options hash to pass to other modules
my $opt_archive;						# If True, then archive the tokens files after categorizing
my $opt_arch_delete;					# If True, then delete all the token files after categorizing
my $opt_log_file;						# The name of the log file to use
my $opt_tokendir;						# If True, this is the name of the directory holding token files to categorize
my $opt_output_dir;						# Output the caregorized URLs to domains.his files under the out_output_dir directory
my $opt_noname;							# If True then do no URL by name categorization
my $opt_name = 1;						# This is the flip of opt_noname
my $opt_delete;							# If True then delete any token file that doesn't match the opt_category
my $opt_match_delete;					# If True then delete any token file that does match the opt_category
my $opt_verbose;						# If True then show everything going on
my $recategorize_file;					# The full file name to write urls to that need to be recategorized
my $unknown_file;						# The full file name to write urls to that are unknown
my $opt_urls;							# If True then read URLs instead of token files
my $opt_benchmark;						# True if I should benchmark the speed
my $opt_unknown_file;					# If True then save unknown and recateorize urls to files
my $opt_fast_categorize;				# If True then we are running a fast categorize pass
my $opt_lang;							# If set, then delete any token file that does not match language
my $opt_content_dir;					# If set, and debugging turned on, then this is the directory to put .content.txt files into
my $opt_runcount = 0 + 200;				# Maximum number ofdomains to categorize before quiting

my $opt_images = 1;								# If set, then use image analysis as one of the categorization methods
my $max_image_download		= 0 + 10000000;		# The maximum number of bytes of images to download from any given website
my $max_image_count			= 0 + 50;			# The maximum number of images to download from any given site



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
        "a|archive"			=> \$opt_archive,
        "b|benchmark"		=> \$opt_benchmark,
        "c|category=s"		=> \$opt_category,
        "d|delete"			=> \$opt_delete,
        "e|archdelete"		=> \$opt_arch_delete,
		"f|logfile=s"		=> \$opt_log_file,
		"i|input=s"			=> \$opt_input_file,
        "k|keywords"		=> \$opt_show_most_interesting,
        "l|lang=s"			=> \$opt_lang,
        "m|matchdelete"		=> \$opt_match_delete,
        "n|noname"			=> \$opt_noname,         
        "o|output=s"		=> \$opt_output_dir,
        "o|output=s"		=> \$opt_output_dir,
        "r|runcount=i"		=> \$opt_runcount,
        "t|tokendir=s"		=> \$opt_tokendir,
        "u|unknown=s"		=> \$opt_unknown_file,
        "v|verbose"			=> \$opt_verbose,
		"w|wizard"			=> \$opt_wizard,
		"x|xxx"				=> \$opt_debug,
		"z|zzz"				=> sub { $opt_fast_categorize = undef; },
        "h|help"			=> \$opt_help
    );


	$SIG{'INT'} = 'INT_handler' if ( ! $opt_debug );

	# Get rid of too big or too small error messages	
    local $SIG{__WARN__} = sub 
		{	warn @_ unless $_[0] =~ m(^.* too (?:big|small)); 
		}; 


    &StdHeader( "Categorize" ) if ( ! $opt_wizard );
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    &UsageError() if ( ( $opt_sensitivity )  &&  ( $opt_sensitivity < 0  ||  $opt_sensitivity > 100 ) );


	$opt_name = undef if ( $opt_noname );
	
	$opt_verbose = 1 if ( $opt_debug );
	
	my $my_pid = &ProcessGetCurrentProcessId();


	mkdir( $log_directory );
	$opt_log_file = "$log_directory\\Categorize-$my_pid.log" if ( ! defined $opt_log_file );
		
	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;

	# Does the opt_logfile include a pathname?  If not, use the current directory
	if ( ! ( $opt_log_file =~ m/\\/ ) )
		{	$opt_log_file = $dir . "\\" . $opt_log_file if ( defined $dir );
		}


    &SetLogFilename( $opt_log_file, undef );
	&lprint( "Logging set to $opt_log_file\n" ) if ( defined $opt_log_file );
	
	&TrapErrors( "$log_directory\\CategorizeErrors-$my_pid.log" ) if ( ! $opt_debug );
	
	if ( $opt_urls )
		{	$opt_tokendir = undef;
		}
	elsif ( ! defined $opt_tokendir )
		{	$opt_tokendir = getcwd;
			$opt_tokendir =~ s#\/#\\#gm;
		}
	
	
	if ( ( $opt_delete )  &&  ( ! $opt_category ) )
		{	lprint "You have to specify the category in order to delete not matching tokens files\n";
			my ( $ok, $msg ) = &EmailError( "You have to specify the category in order to delete not matching tokens files\n", "Categorize", $my_pid );
			exit( 1 );
		}
	
	if ( ( $opt_delete )  &&  ( ! $opt_tokendir ) )
		{	lprint "You have to specify the token file directory in order to delete not matching tokens files\n";
			my ( $ok, $msg ) = &EmailError( "You have to specify the token file directory in order to delete not matching tokens files\n", "Categorize", $my_pid );
			exit( 2 );
		}
	
	if ( ( $opt_match_delete )  &&  ( ! $opt_category ) )
		{	lprint "You have to specify the category in order to delete matching tokens files\n";
			my ( $ok, $msg ) = &EmailError( "You have to specify the category in order to delete matching tokens files\n", "Categorize", $my_pid );
			exit( 3 );
		}
	
	if ( ( $opt_match_delete )  &&  ( ! $opt_tokendir ) )
		{	lprint "You have to specify the token file directory in order to delete matching tokens files\n";
			my ( $ok, $msg ) = &EmailError( "You have to specify the token file directory in order to delete matching tokens files\n", "Categorize", $my_pid );
			exit( 4 );
		}
	
	if ( ( $opt_match_delete )  &&  ( $opt_delete ) )
		{	lprint "You can\'t delete matching and not matching tokens files at the same time\n";
			my ( $ok, $msg ) = &EmailError( "You can\'t delete matching and not matching tokens files at the same time\n", "Categorize", $my_pid );
			exit( 5 );
		}
	
	
    #  If there still is an argument, it must be the input file name
    if ( $ARGV[0] )   
		{	$opt_input_file = shift;  
		}


	# If I have an input file or URLs, then I'm not reading tokens files
	if ( ( $opt_input_file )  &&  ( -e $opt_input_file ) )
		{	$opt_tokendir = undef;
			$opt_urls = undef;
		}
			

    #  Make sure the source number is either customer automatic (4) or Lightspeed Automatic (3)
    $opt_source = 4 if ( $opt_source < 3 || $opt_source > 4 );
	
	
	# If using a tokens directory make sure that it exists
	if ( ( $opt_tokendir )  &&  ( ! -d $opt_tokendir ) )
		{	&lprint( "Token files directory $opt_tokendir does not exist\n" );
			my ( $ok, $msg ) = &EmailError( "Token files directory $opt_tokendir does not exist\n", "Categorize", $my_pid );
			exit( 6 );
		}
		

	# If archiving, make sure there is a tokens directory
	if ( ( $opt_archive )  &&  ( ! defined $opt_tokendir ) )
		{	&lprint( "You can not use the archive option without also setting the tokens file directory\n" );
			my ( $ok, $msg ) = &EmailError( "You can not use the archive option without also setting the tokens file directory\n", "Categorize", $my_pid );
			exit( 7 );
		}
		
		
	# If downloading and categorizing images then make sure there is a tmp directory
	if ( ( $opt_images )  &&  ( ! -d $tmp_directory ) )
		{	&lprint( "You can not use the images option without also setting the temporary file directory\n" );
			my ( $ok, $msg ) = &EmailError( "You can not use the images option without also setting the temporary file directory\n", "Categorize", $my_pid );
			exit( 9 );
		}
		
		
	# If using an output directory make sure that it exists
	if ( ( $opt_output_dir )  &&  ( ! -d $opt_output_dir ) )
		{	&lprint( "Output directory $opt_output_dir does not exist\n" );
			my ( $ok, $msg ) = &EmailError( "Output directory $opt_output_dir does not exist\n", "Categorize", $my_pid );
			exit( 8 );
		}
		

	# Set the content directory to the tokens directory if it isn't defined
	if ( ! defined $opt_content_dir )
		{	$opt_content_dir = $opt_tokendir;
		}


	&lprint( "My process ID (pid) = $my_pid\n" ) if ( defined $my_pid );
	&lprint( "My current directory = $dir\n" ) if ( defined $dir );

	
	&BenchmarkStart() if ( $opt_benchmark );
	
	
	# Set the recategorize and unknown URLs file names if an opt_input or a tokendir file is given
	# Default them to unused if opt_unknown_files is not true
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year = 1900 + $year;
	$mon = $mon + 1;
	
	my $datestr = sprintf( "%04d-%02d-%02d %02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );
	$recategorize_file	= undef;
	$unknown_file		= "unknown.$datestr.urls";

	if ( ( $opt_unknown_file )  &&  ( ( $opt_input_file )  ||  ( $opt_tokendir ) ) )
		{	my $dir = getcwd;
			$dir =~ s#\/#\\#gm;
			
			# Does the $opt_input_file include a pathname?  If not, use the current directory
			$dir = undef if ( ( $opt_input_file )  &&  ( $opt_input_file =~ m/\\/ ) );
			
			# If we are using a token dir, then save the files into into that directory
			$dir = $opt_tokendir if ( $opt_tokendir );
			
			if ( $opt_input_file )
				{	$unknown_file		= "unknown." . $opt_input_file . ".urls";
				}
			else
				{	$unknown_file		= $opt_unknown_file;
				}				
		}

	
	#  Open the database and load all the arrays
	lprint "Opening a connection to the ODBC System DSN \'TrafficRemote\' ...\n";
	$dbh = &ConnectRemoteServer();

	if ( ! $dbh )
		{
lprint "Unable to open the Remote Content database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.
Also add the Category SQL Server as a System DSN named \'TrafficCategory\'
with default database \'Category\'.\n";
			my ( $ok, $msg ) = &EmailError( "Unable to open the Remote Content database", "Categorize", $my_pid );
			exit( 9 );
		}

	lprint "Opening a connection to the ODBC System DSN \'TrafficCategory\' ...\n";

	# Connect to the category database
	$dbhCategory = &CategoryConnect();
	if ( ! $dbhCategory )
		{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";
			my ( $ok, $msg ) = &EmailError( "Unable to open the Remote Category database", "Categorize", $my_pid );
			exit( 10 );
		}
		
	
	lprint "Opening a connection to the ODBC System DSN \'TrafficLookup\' ...\n";

	# Connect to the lookup database
	$dbhLookup = &CategoryLookupConnect();
	if ( ! $dbhLookup )
		{
lprint "Unable to open the Traffic Lookup database.
Run ODBCAD32 and add the Armyxxx platoon leader SQL Server as a System DSN named
\'TrafficLookup\' with default database \'IpmContent\'.\n";
			my ( $ok, $msg ) = &EmailError( "Unable to open the Traffic Lookup database", "Categorize", $my_pid );
			exit( 11 );
		}
		
	
	&BenchmarkTime( "Open Databases" );
	
	my $logfile = &GetLogFilename();
	lprint "Logging to file $logfile\n" if ( $logfile );
	

	&LoadCategories();
	$opt_root_dir = &KeywordsDirectory() if ( ! $opt_root_dir );


	# Should I categorize the URLs locally?
	# Build up the options hash to use to pass to the categorize module
	%options = (
		"database handle"		=> $dbh,
		"root dir"				=> $opt_root_dir,
		"input file"			=> $opt_input_file,
		"show most interesting"	=> $opt_show_most_interesting,
		"sensitivity"			=> $opt_sensitivity,
		"source"				=> $opt_source,
		"category"				=> $opt_category,
		"max tokens"			=> $max_tokens,
		"output dir"			=> $opt_output_dir,
		"name"					=> $opt_name,
		"delete"				=> $opt_delete,
		"matchdelete"			=> $opt_match_delete,
		"runcount"				=> $opt_runcount,
		"verbose"				=> $opt_verbose,
		"recategorizefile"		=> $recategorize_file,
		"unknownfile"			=> $unknown_file,
		"debug"					=> $opt_debug,
		"archive"				=> $opt_archive,
		"archdelete"			=> $opt_arch_delete,
		"fast"					=> $opt_fast_categorize,
		"lang"					=> $opt_lang,
		"contentdir"			=> $opt_content_dir,
		"image"					=> $opt_images,
		"tmp_directory"			=> $tmp_directory,
		"max_image_download"	=> $max_image_download,
		"max_image_count"		=> $max_image_count
		);

	
	&CategorizeOptions( \%options );
	&Categorize( $opt_tokendir );


	#  Close up the databases
	$dbh->disconnect		if ( $dbh );
	$dbh = undef;
	&CategoryClose()		if ( $dbhCategory );
	$dbhCategory = undef;
	&CategoryLookupClose()	if ( $dbhLookup );
	$dbhLookup = undef;

	&BenchmarkTime( "Close Database" );
	
	# Write out an OK file so the the controlling task knows that everything is OK
	my $finished_log_file = "$log_directory\\Categorize-$my_pid.OK";
	open( FINISHED, ">$finished_log_file" );      	   
	print FINISHED "Done\n";
	close( FINISHED );

	&BenchmarkEnd() if ( $opt_benchmark );

	&StdFooter if ( ! $opt_wizard );

   exit( 0 );
}



################################################################################
#
sub INT_handler( $ )
#
#  Interrupt handler
#
################################################################################
{		
	#  Close up the databases
	$dbh->disconnect			if ( $dbh );
	$dbh = undef;
	
	$dbhCategory->disconnect	if ( $dbhCategory );
	$dbhCategory = undef;
	
	$dbhLookup->disconnect		if ( $dbhLookup );
	$dbhLookup = undef;
  
	exit( 253 ); 
}



################################################################################
#
sub TrapErrors( $ )
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = shift;
	
	return( undef ) if ( ! defined $filename );
  
	my $MYLOG;

	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	lprint( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "Categorize";

    bprint "$_[0]\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
.
    &StdFooter;

    exit( 12 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Categorize";

    bprint <<".";
Usage: $me [OPTION(s)] [URLFILE]
Categorizes unknown URLs.
Default is to read unknown URLs directly from the Content database.
Any command argument will be assumed to be the file name of a list of URLs.

  -a, --archive            to archive the tokens files after they have been
                           categorized
  -b, --benchmark          to track benchmark times
  -c, --category=CATNAME   to specify a single category to check
  -d, --delete             to delete any token file that does NOT match CATNAME
  -e, --archdelete         delete instead instead of archiving the token files  
  -f, --logfile            the name of the log file to use - default is 
                           Categorize.log or URLFILE.log
  -h, --help               display this help and exit
  -i, --input=URLFILE      input file of URLs, default is to use tokens files
  -k, --keywords           show the keywords used to categorize each url
  -l, --lang=LANG          to delete any token file that does NOT match language
  -m, --matchdelete        to delete any token file that DOES match CATNAME
  -n, --name               to NOT use URL name categorization
  -o, --output=OUTDIR      to output the categorization results to test files
                           in directory OUTDIR
  -r, --recategorize       to recategorize known URLs
  -s, --sensitivity        keyword sensitivity, 50 default, 100 most aggressive
  -t, --tokendir=TOKENDIR  to categorize token files in directory TOKENDIR
                           default is the current directory
  -u, --unknown            to save unknown and recatorize URLs to files
  -v, --version            display version information and exit
  -z, --zzz                to run in QueueCategorize mode
.
    &StdFooter;

    exit( 13 );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "Categorize";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit( 14 );
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
