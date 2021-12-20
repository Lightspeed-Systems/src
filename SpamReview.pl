################################################################################
#!perl -w
#
# Rob McCarthy's version of extracting URLs, etc from the Spam For Review folder
#
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use MIME::Base64;
use MIME::QuotedPrint;
use HTML::Entities;
use Cwd;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Sys::Hostname;



use Content::ScanUtil;
use Content::File;
use Content::FileUtil;
use Content::Mail;
use Content::SQL;
use Content::Category;
use Content::SpamSummary;
use Content::QueryOS;



# Validate and get the parameters
my $_version = "6.02.0";

my $opt_version;
my $opt_verbose;
my $opt_help;
my $opt_dir;								# Directory to use
my $tokens_dir;								# Directory of the tokens file
my $opt_category;							# Create category directories for known urls
my $opt_files;								# True if I should create domains.hit output files
my $opt_debug;								# Debug mode - leaves created files in place
my $opt_urls;								# True if I should save all URLS in the domains.hit file
my $opt_allfiles;							# True if all files should be analyzed
my $opt_working;							# True if shold delete working files
my $opt_review;								# True if I'm running to normal spam review daily process
my $opt_wizard;								# True if I shouldn't display headers and footers
my $opt_summary_to;							# Set to an individual email address if I'm supposed to send a spam summary to just one person
my $opt_export;								# Set to an individual email address if I'm supposed to export the newest spam summary data for one person
my $opt_no_summary;							# True if I shouldn't send summary messages
my $opt_dns_query;							# True if I should query DNS about unknown URLs IP addresses
my $opt_source = 0 + 4;						# Source number = 4 is default, 3 is Lightspeed
my $opt_no_sql_timeout;						# True if I should not do any SQL sleeping
my $opt_test_spf;							# If True then test all the ham email with SPF
my $opt_incremental;						# If True then just send the spam summary emails
my $opt_matt;								# If True then send a spam summary even if there is no spam to summarize
my %options;								# A hash containing the new options added for version 8.2 of TTC


my $send_summary;							# True if the default is to send the spam summary email
my $send_summary_good_emails = 1;			# True if the default is to include all the good emails in the spam summary
my $global_forward_spam;					# True if the default is to forward spam
my $global_block_spam = 1;					# True if the default is to block spam
my $log_filename = "SpamReview.log";		# The name of the log file to use
my $dbh;									# My database handle for the content database
my $dbhStats;								#  My database handle for the statistics database
my @clues;									# The list of clues about this message
my @data;   								# The data from the spam file - limited to 500 lines - global so that it is easy to get to
my $spam_summary_server;					# If set, this is the hostname or IP address of the server that holds the spam summary information
my $max_bytes = 0 + 2000000;				# The maximum number of bytes to read in a spam file before giving up
my $max_lines = 0 + 20000;					# The maximum number of lines in a spam file to read before giving up
my $create_spam_user_preferences = 1;		# True if I should create the spam user preferences for users that have just gotten spam mail
my $url_ip_counter = 0 + 0;					# The count of ip addresses that I've looked up for URLs
my $archive_path;							# This is the path to the mail archive - if set - read from the Spam Mail blocker properties
my $hostname;								# This is my hostname - used in SPFAnalyze
my $date_format;							# If set, this is the date format in the form m/d/yyyy or d/m/yyyy


# These are the addresses that various Lightspeed programs use to send email messages
my @special_addresses = ( "notspam\@lightspeedsystems\.com", 
						 "spam\@lightspeedsystems\.com", 
						 "blacklist\@lightspeedsystems\.com", 
						 "blockedcontent\@lightspeedsystems.com",
						 "virus\@lightspeedsystems.com",
						 "support\@lightspeedsystems.com",
						 "unknown\@lightspeedsystems.com",
						 "database\@lightspeedsystems.com",
						 "\"spam mail summary\""
						 );  


#  Bayesian global parameters
my $min_frequency = 0 + 20;					# Number of times a token needs to be used before it is considered significant
my $expected_good_to_bad = 0 + 1.15;		# This is the ratio of the expected number of non spams to spams in a normal day of email
my $opt_sensitivity;						# If not set, the expected good to bad ratio will be used
my $opt_show_most_interesting;				# Show the most interesting picks
my $opt_most_interesting_min = 0 + 10;		# Minimum required most interesting
my $opt_most_interesting_max = 0 + 50;		# Maximum allowed most interesting
my $opt_mindev = 0 + 0.1;					# The minimum deviation from 0.5 to make the token interesting enough
my $opt_unknown_token = 0 + 0.41;			# The value to use for a completely unknown token
my $opt_spam_threshold = 0 + 0.80;			# What percentage sure that it's spam
my $pure_spam;								# Probability of a token that only occurs in a spam file
my $pure_notspam;							# Probability of a token that only occurs in a non spam file
my $corpus_file;							# The full file name of the corpus file I used
my $opt_offset = 0 + 0.1;					# The offset from 1 and 0 for pure spam and pure not spam
my %token_spam_rating;						# The spam rating of all the known tokens
my $current_file;							# The name of the current file I am analyzing



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
        "a|allfiles"	=> \$opt_allfiles,
        "c|category"	=> \$opt_category,
        "d|directory=s" => \$opt_dir,
        #"e|export=s"	=> \$opt_export,
        "i|incremental" => \$opt_incremental,	
        "f|files"		=> \$opt_files,
        "k|kkk"			=> \$opt_dns_query,
        "m|matt=s"		=> \$opt_matt,
        "n|nosummary"	=> \$opt_no_summary,
        "p|policy"		=> \$opt_test_spf,
        "r|review"		=> \$opt_review,
        "s|summary=s"	=> \$opt_summary_to,
        "t|timeout"		=> \$opt_no_sql_timeout,
        "u|urls"		=> \$opt_urls,
        "w|wizard"		=> \$opt_wizard,
        "v|verbose"		=> \$opt_verbose,
        "x|xdebug"		=> \$opt_debug,
        "h|help"		=> \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


	$opt_working = 1 if ( $opt_category );
	$opt_summary_to = $opt_matt if ( $opt_matt );
	
	
	# If I'm doing the daily review of hand categoried spam, set all the defaults
	if ( $opt_review )
		{	$opt_allfiles	= 1;
			$opt_working	= 1;
			$opt_urls		= 1;
			$opt_dir		= getcwd();
			$opt_dir		=~ s#\/#\\#gm;
			$opt_files		= 1;
			#$opt_dns_query	= 1;
			$opt_source		= 0 + 3;
		}
		
		
	# What mode am I running in?
	my $filename = shift;
	
	
	# Get the default settings for spam summaries	
	&GetProperties();
	
	# Get the properties from an XML file if SpamPlus is installed
	&GetPropertiesXML();
	
	
	# If no command line, then I am analyzing all the files in the directory
	$opt_files = 1 if ( ! $filename );
	
	
	# Figure out the default directory to use
	my $opt_dir_created;
	if ( ! $opt_dir )
		{	$opt_dir = &DefaultDirectory();
			
			if ( ( $filename )  &&  ( -d $filename ) )
				{	$opt_dir = $filename;
					$filename = undef;
					$opt_files = 1;
				}
			
			# Make sure the directory exists
			if ( ! -d $opt_dir )	
				{	mkdir( $opt_dir );  
					
					$opt_dir_created = 1;
				}
		}

	
	if ( $opt_dir eq "." )
		{	$opt_dir = getcwd;
			$opt_dir =~ s#\/#\\#gm;
		}
		
				
	&lprint( "Do not send spam summary emails\n" ) if ( $opt_no_summary );
	
	
	# Should I create the domains.hit files?	
	$opt_files = 1 if ( ( $filename )  &&  ( -d $filename ) );


	if ( ( ! $opt_files )  &&  ( ! $filename ) )
		{	&lprint( "You must specify a file to analyze on the command line\n" );
			exit( 1 );
		}
		

	if ( ( ! $opt_files )  &&  ( ! -e $filename ) )
		{	&lprint( "Can not find file $filename to analyze\n" );
			exit( 1 );
		}
		
		
	#  Open the Content database
	$dbh = &ConnectServer() or &FatalError("Unable to connect to SQL database\n" );
	LoadCategories();
	
    #  Open the Statistics database
    $dbhStats = &ConnectStatistics() or &FatalError("Unable to connect to Statistics database\n" );

	# Open the Category database if I can
	my $dbhCategory = &CategoryConnect();
	bprint( "Connected to the Category database\n" ) if ( $dbhCategory );
	

	if ( $opt_no_sql_timeout )
		{	SqlSleepOff();
			&lprint( "Turned off all SQL sleeping timeouts\n" );
		}

		
	if ( $opt_test_spf )	
		{	&StdHeader( "SpamReview" ) if ( ! $opt_wizard );
			
			$log_filename = "SpamReviewSPF.log";
			&SetLogFilename( $log_filename, undef );

			&TrapErrors() if ( ! $opt_debug );
			
			&SPFAnalyze( $opt_allfiles, undef );
		}	
	elsif ( ! $opt_files )
		{	$opt_verbose = undef;
			
			#  Calculate the pure spam and pure not spam values
			if ( $opt_offset )
				{
					&Usage() if ( $opt_offset < 0.01  ||  $opt_offset > 0.49 );
					$pure_spam = 1 - $opt_offset;
					$pure_notspam = $opt_offset;
				}


			#  If calculate the opt_sensitivity if not already set
			if ( !$opt_sensitivity )
				{	$opt_sensitivity = 100 * ( ( 1.55 - $expected_good_to_bad ) / .8 );
				}
			else  #  If the sensitivity was set, calc the expected good to bad ratio
				{	$expected_good_to_bad = .75 + ( ( ( 100 - $opt_sensitivity ) * .8 ) / 100 );
				}


			$tokens_dir = &SoftwareDirectory();
			
			&LoadSpamTokens();
			
			&AnalyzeFile( $filename, undef );

			bprint "$_\n" foreach ( @clues );
		}
	elsif ( $opt_summary_to )	# Am I just sending a single summary message to one person?
		{	&StdHeader( "SpamReview" ) if ( ! $opt_wizard );
			&SetLogFilename( $log_filename, undef );

			&TrapErrors() if ( ! $opt_debug );
			
			lprint "Using default directory $opt_dir\n" if ( defined $opt_dir );
			
			# Are there some domains that I need to just send summaries for?
			&SpamSummaryFilteredDomains();
			
			&SpamSingleSummaryMessages( $opt_summary_to, $spam_summary_server, $opt_no_sql_timeout, $send_summary_good_emails, $opt_matt, $date_format, \%options );
		}
#	elsif ( $opt_export )	# Am I just exporting the most recent spam summary data for one person?
#		{	&StdHeader( "SpamReview" ) if ( ! $opt_wizard );
#			&SetLogFilename( $log_filename, undef );
#
#			&TrapErrors() if ( ! $opt_debug );
#			
#			&SpamSummaryUpdate( $opt_export );
#		}
	elsif ( $opt_incremental )
		{	# Just send the spam summary messages
			&StdHeader( "SpamReview" ) if ( ! $opt_wizard );
			&SetLogFilename( $log_filename, undef );

			&TrapErrors() if ( ! $opt_debug );
			
			lprint "Just sending the spam summary messages\n";
			
			lprint "Using default directory $opt_dir\n" if ( defined $opt_dir );
			
			# Are there some domains that I need to just send summaries for?
			&SpamSummaryFilteredDomains();
			
			&CreateSpamUserPreferences( $opt_no_sql_timeout, $send_summary, $global_forward_spam, $global_block_spam ) if ( $create_spam_user_preferences );
			
			&SpamSummaryMessages( $spam_summary_server, $opt_no_sql_timeout, $send_summary, $send_summary_good_emails, $opt_incremental, $date_format, \%options );
		}
	else	# I must be doing the daily processing
		{				
			&StdHeader( "SpamReview" ) if ( ! $opt_wizard );
			&SetLogFilename( $log_filename, undef );

			&TrapErrors() if ( ! $opt_debug );
			
			lprint "Using default directory $opt_dir\n" if ( defined $opt_dir );
			
			if ( ( ! $opt_review )	&&  ( ! $opt_no_summary ) ) # This is all the spam mail summary stuff
				{	# Are there some domains that I need to just send summaries for?
					&SpamSummaryFilteredDomains();

					&CreateSpamUserPreferences( $opt_no_sql_timeout, $send_summary, $global_forward_spam, $global_block_spam ) if ( $create_spam_user_preferences );
			
					&SpamSummaryMessages( $spam_summary_server, $opt_no_sql_timeout, $send_summary, $send_summary_good_emails, $opt_incremental, $date_format, \%options );

					&SpamSummaryPurgeData();
				}
			
				
			# Should I pull spam data out of the statisitics database?
			if ( ! $opt_review )
				{
					&SpamChallengeAnalyze();
					&SpamExtract();
					&SpamInsert();
					&AutowhiteCheck();
					&SPFAnalyze( undef, 1 );
				}
				
				
			lprint "Scanning message file(s) for unique data ...\n";
			lprint "Directory: $opt_dir\n";
			lprint "Create category subdirectories of known urls\n" if ( $opt_category );
			lprint "Verbose mode\n" if ( $opt_verbose );
			lprint "Do not delete working files\n" if ( $opt_working );
			lprint "Debug mode\n" if ( $opt_debug );

			&AnalyzeDir();
		}


	&StdFooter if ( ! $opt_wizard );
	
	# Remove the directory if I created it	
	rmdir( $opt_dir ) if ( $opt_dir_created );

	
	#  Clean up everything and quit
	$dbhStats->disconnect if ( $dbhStats );
	$dbh->disconnect if ( $dbh );
	&CategoryClose();
	
    exit;
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $dir = &SoftwareDirectory();

	my $filename = "$dir\\SpamReviewErrors\.log";

	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	print "Unable to open error log file $filename: $!\n";
		}
		
	&CarpOut( $MYLOG );
   
	lprint( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub GetProperties()
#
#  Get the current properties from the Spam Blocker Object that affect
#  the SpamReview
#
################################################################################
{    my $key;
     my $type;
     my $data;


	#  First date format from the registry
	my $access = &OueryOSRegistryAccess( KEY_READ );
	my $ok = &RegOpenKeyEx( HKEY_CURRENT_USER, "Control Panel\\International", 0, $access, $key );

	if ( $ok )
		{	$ok = &RegQueryValueEx( $key, "sShortDate", [], $type, $data, [] );

			$date_format = lc( $data ) if ( ( $ok )  &&  ( length( $data ) > 0 ) );
			&RegCloseKey( $key );
		}


	#  First get the current config number
	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations", 0, $access, $key );

	return if ( !$ok );
	$ok = &RegQueryValueEx( $key, "Current", [], $type, $data, [] );
	 
	&RegCloseKey( $key );
	
	return if ( !$ok );   
	my $current = &HexToInt( $data );

	my $current_key = sprintf( "%05u", $current );

	my $subkey;
	my $counter;
	
	#  Next go through the current config looking for a Spam Mail Blocker object
	for ( my $i = 1;  $i < 100;  $i++ )
		{	$counter = sprintf( "%05u", $i );

			$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter";

			$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, $access, $key );
			next if ( !$ok );  

			$ok = &RegQueryValueEx( $key, "ProgID", [], $type, $data, [] );  # Blank is the (Default) value

			&RegCloseKey( $key );
			
			next if ( !$data );
			
			last if ( $data =~ m/SpamMailBlockerSvc/ );         
		}

	return if ( ! $data =~ m/SpamMailBlockerSvc/ ); 

	#  Got a Spam Mail Blocker object - now get the spam summary default
	$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter\\Dynamic Properties";

	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, $access, $key );
	return if ( !$ok );  


	$data = undef;
	$send_summary = undef;
    $ok = &RegQueryValueEx( $key, "Send Spam Summary", [], $type, $data, [] );  # Blank is the (Default) value
	$send_summary = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );


	$data = undef;
	$global_forward_spam = undef;
    $ok = &RegQueryValueEx( $key, "Forward Archived Spam", [], $type, $data, [] );  # Blank is the (Default) value
	$global_forward_spam = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );


	$data = undef;
	$global_block_spam = 1;
    $ok = &RegQueryValueEx( $key, "Block Spam", [], $type, $data, [] );  # Blank is the (Default) value
	$global_block_spam = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );


	$data = undef;
	$spam_summary_server = undef;	
    $ok = &RegQueryValueEx( $key, "Spam Summary Server", [], $type, $data, [] );  # Blank is the (Default) value
	$spam_summary_server = $data if ( ( $data )  &&  ( $data ne "\x00" ) );

	$data = undef;
	$create_spam_user_preferences = 1;	
    $ok = &RegQueryValueEx( $key, "Create Spam User Preferences", [], $type, $data, [] );  # Create the spam user preferences value
	$create_spam_user_preferences = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
	
	$data = undef;
	$send_summary_good_emails = undef;	
    $ok = &RegQueryValueEx( $key, "Spam Summary Include Good Email", [], $type, $data, [] );
	$send_summary_good_emails = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );

	$data = undef;
	$archive_path = undef;	
    $ok = &RegQueryValueEx( $key, "Archive Path", [], $type, $data, [] );
	$archive_path = $data if ( ( $ok )  &&  ( $data ) );


	# These are the new spam summary options added in TTC version 8.2
	$data = undef;
    $ok = &RegQueryValueEx( $key, "Spam Summary Include Adult Subject", [], $type, $data, [] );
	$options{ "Spam Summary Include Adult Subject" } = 0 + 1;
	$options{ "Spam Summary Include Adult Subject" } = 0 + 0 if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );

	$data = undef;
    $ok = &RegQueryValueEx( $key, "Spam Summary Include Global Blocklist", [], $type, $data, [] );
	$options{ "Spam Summary Include Global Blocklist" } = 0 + 1;
	$options{ "Spam Summary Include Global Blocklist" } = 0 + 0 if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );

	$data = undef;
    $ok = &RegQueryValueEx( $key, "Spam Summary Include Personal Blocklist", [], $type, $data, [] );
	$options{ "Spam Summary Include Personal Blocklist" } = 0 + 1;
	$options{ "Spam Summary Include Personal Blocklist" } = 0 + 0 if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );

	$data = undef;
    $ok = &RegQueryValueEx( $key, "Spam Summary Include RBL Server", [], $type, $data, [] );
	$options{ "Spam Summary Include RBL Server" } = 0 + 1;
	$options{ "Spam Summary Include RBL Server" } = 0 + 0 if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );

	$data = undef;
    $ok = &RegQueryValueEx( $key, "Spam Summary Include Spam Pattern", [], $type, $data, [] );
	$options{ "Spam Summary Include Spam Pattern" } = 0 + 1;
	$options{ "Spam Summary Include Spam Pattern" } = 0 + 0 if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );

	$data = undef;
    $ok = &RegQueryValueEx( $key, "Spam Summary Include Virus", [], $type, $data, [] );
	$options{ "Spam Summary Include Virus" } = 0 + 1;
	$options{ "Spam Summary Include Virus" } = 0 + 0 if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );


	&RegCloseKey( $key );

	return;
}



################################################################################
#
sub GetPropertiesXML()
#
#  Set the list of filtered domains to send spam summaries to.  This is a property
#  of SpamPlus and is in the SpamPlusProperties.xml file
#
################################################################################
{	my $dir = &SoftwareDirectory . "\\Website\\Reports\\Properties";

	return( undef ) if ( ! -d $dir );
 
	# Does the SpamPlus Properties XML file exist?
	my $fullfilename = $dir . "\\SpamPlusProperties.xml";
	return( undef ) if ( ! -f $fullfilename );
	
	if ( ! open( SPAMPLUSXML, "<$fullfilename" ) )
		{	my $err = $!;
			&lprint( "Error opening $fullfilename: $err\n" );
			return( undef );
		}
		
	
	&lprint( "Reading file $fullfilename to get the Spam Plus properties ...\n" );
	
	
	# Default some stuff
	$global_block_spam = 1;
	$create_spam_user_preferences = 1;
	
	my $TotalTrafficServerHostnameOrIPAddress;
	
	while ( my $line = <SPAMPLUSXML> )
		{	next if ( ! ( $line =~ m/<PropertyType>/ ) );
			chomp( $line );
			$line =~ s/<PropertyType>//;
			$line =~ s/<\/PropertyType>//;
			my $property = $line;
			$property =~ s/^\s+//;
			$property =~ s/\s+$//;
						
			my $value = <SPAMPLUSXML>;
			
			chomp( $value );
						
			$value =~ s/<Value>//;
			$value =~ s/<\/Value>//;
			
			$value =~ s/^\s+//;
			$value =~ s/\s+$//;

			# Is the final value blank?
			next if ( $value eq "" );
			next if ( $value eq "<Value />" );
			
			next if ( ! $property );
			next if ( ! $value );
			
			
			# Is this a property I care about?
			if ( $property eq "SendSpamMailSummaryEmailsToUsers" )
				{	$send_summary = 1 if ( $value =~ m/True/i );
				}
			elsif ( $property eq "AddSpamToSubjectLineAndForward" )
				{	$global_forward_spam = 1 if ( $value =~ m/True/i );
				}
			elsif ( $property eq "BlockAndReportOrReportOnly" )
				{	$global_block_spam = undef if ( $value =~ m/ReportOnly/i );
				}
			elsif ( $property eq "TotalTrafficServerHostnameOrIPAddress" )
				{	# If this property is set it takes precedence over HostnameOfPolicyServer
					$spam_summary_server = $value;
					$TotalTrafficServerHostnameOrIPAddress = $value;
				}
			elsif ( $property eq "HostnameOfPolicyServer" )
				{	$spam_summary_server = $value if ( ! defined $TotalTrafficServerHostnameOrIPAddress );
				}
			elsif ( $property eq "AutomaticallyCreateUserPreferences" )
				{	$create_spam_user_preferences = undef if ( $value =~ m/False/i );
				}
			elsif ( $property eq "IncludeGoodEmailInSpamSummary" )
				{	$send_summary_good_emails = 1 if ( $value =~ m/True/i );
				}
			elsif ( $property eq "MailPath" )
				{	$archive_path = $value;
				}
			# These are the spam summary optins from TTC version 8.2	
			elsif ( $property eq "SpamSummaryIncludeAdultSubject" )
				{	$options{ "Spam Summary Include Adult Subject" } = 0 + 1;
					$options{ "Spam Summary Include Adult Subject" } = 0 + 0 if ( $value =~ m/False/i );
				}
			elsif ( $property eq "SpamSummaryIncludeGlobalBlocklist" )
				{	$options{ "Spam Summary Include Global Blocklist" } = 0 + 1;
					$options{ "Spam Summary Include Global Blocklist" } = 0 + 0 if ( $value =~ m/False/i );
				}
			elsif ( $property eq "SpamSummaryIncludePersonalBlocklist" )
				{	$options{ "Spam Summary Include Personal Blocklist" } = 0 + 1;
					$options{ "Spam Summary Include Personal Blocklist" } = 0 + 0 if ( $value =~ m/False/i );
				}
			elsif ( $property eq "SpamSummaryIncludeDNSBlocklist" )
				{	$options{ "Spam Summary Include RBL Server" } = 0 + 1;
					$options{ "Spam Summary Include RBL Server" } = 0 + 0 if ( $value =~ m/False/i );
				}
			elsif ( $property eq "SpamSummaryIncludeSpamPatterns" )
				{	$options{ "Spam Summary Include Spam Pattern" } = 0 + 1;
					$options{ "Spam Summary Include Spam Pattern" } = 0 + 0 if ( $value =~ m/False/i );
				}
		}
		
	close( SPAMPLUSXML );
	
	
	return( 1 );            
}



################################################################################
#
sub DefaultDirectory()
#
# Return the default directory to use
#
################################################################################
{
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );

    $mon = $mon + 1;
    $year = 1900 + $year;

    #  Grab the previous day
    $mday = $mday - 1;
    if ( $mday == 0 )
		{	$mon = $mon - 1;

			if ( $mon == 0 )
				{	$year = $year - 1;
					$mon = 12;
				}

			$mday = 30;
			$mday = 28 if ( $mon == 2 );
			$mday = 29 if ( ( $mon == 2 )  && ( ( $year % 4 ) == 0 ) );
			$mday = 31 if ( ( $mon == 1 )  ||
                          ( $mon == 3 ) ||
                          ( $mon == 5 ) ||
                          ( $mon == 7 ) ||
                          ( $mon == 8 ) ||
                          ( $mon == 10 ) ||
                          ( $mon == 12 ) );
      }

	my $datestr = sprintf( "%04d%02d%02d", $year, $mon, $mday );
	
	my $dir = &SoftwareDirectory . "\\Mail Archive\\$datestr";
	
	# Did I get the archive path out of the registry?
	$dir = $archive_path . "\\$datestr" if ( $archive_path );
	
	return( $dir );
}



################################################################################
#
sub AnalyzeDir()
#
# Analyze all the files in a given directory
# Create a working directory of .\spam if necessary.
# Remove the working directory and files if it was created
#
################################################################################
{
	my $domain_dir;
	$domain_dir = $opt_dir . "\\spam";
	
	
	# Do I need to create a sub directory?
	my $created_dir;
	if ( ! -d $domain_dir )
		{	lprint "Creating directory $domain_dir ...\n";
			my $cmd = "mkdir \"$domain_dir\"";
			system $cmd;
			$created_dir = 1;
		}
		
		
	my $domain_file = $domain_dir . "\\domains.hit";
	open( DOMAIN, ">$domain_file" ) or &FatalError( "Unable to open domain file $domain_file: $!\n" );
	
	my $errors_file = $domain_dir . "\\domains.error";
	open( ERRORS, ">$errors_file" ) or &FatalError( "Unable to open errors file $errors_file: $!\n" );
	
	my $existing_file = "urls.existing";
	
	# If a SpamReview\spam directory exists on the current drive, put the existing file there in the domains file
	if ( -d "\\SpamReview\\spam" )
		{	$existing_file = "\\SpamReview\\spam\\domains";
		}
	

	# Delete any files held over from a previous run	
	my $tmp_file = $domain_dir . "\\domains";
	unlink( $tmp_file ) if ( ! $opt_debug );
	$tmp_file = $domain_dir . "\\urls";
	unlink( $tmp_file ) if ( ! $opt_debug );
	unlink( "$domain_dir\\$existing_file" ) if ( ( ! $opt_debug )  &&  ( ! $opt_review ) );
			
		
    # Loop through the directory
    my $file_counter = 0;
    my $file;
	

    # Process the directory
	lprint "Processing directory files in $opt_dir ...\n";
    opendir( DIR, $opt_dir );

	while ( $file = readdir( DIR ) )
		{
			# Skip subdirectories
			next if (-d $file);
		
			chomp( $file );
			$file = lc( $file );
			
			if ( ! $opt_allfiles )
				{	# Spam files start with an s 
					next if ( ! ( $file =~ m/^s/ ) );
		 
					# Spam file ends with a .txt
					next if ( ! ( $file =~ m/\.txt$/ ) );
				}
				
			$file_counter++;
			my $full_filename = "$opt_dir\\$file";
			
			&AnalyzeFile( $full_filename, $domain_dir );
		}

    closedir( DIR );
            
	close( DOMAIN );
	close( ERRORS );
	

    lprint( "Found $file_counter files in $opt_dir that matched s\*\.txt\n" ) if ( ! $opt_allfiles );
    lprint( "Found $file_counter files in $opt_dir\n" ) if ( $opt_allfiles );
    lprint( "Looked up $url_ip_counter IP addresses of URLs\n" ) if ( $url_ip_counter );
 

	if ( $file_counter > 0 )
		{	chdir( $domain_dir );

			lprint "Deleting duplicates from domains\.hit\n";
			my $success = &deldups( "domains.hit", "domains.hit" );
			return( undef ) if ( ! $success );
			
			lprint "Converting hits to squidguard format ...\n";
			$success = &hits2squid( $domain_dir );
			return( undef ) if ( ! $success );
					
			chdir( $opt_dir );
			
			#  Open the database
			my $dbh = &ConnectServer() or return( undef );

			&LoadCategories();
			my $category_number = &CategoryNumber( "spam" );
			
			# Import the found urls into the database
			# Import into the spam directory, override errors, use opt_source
			$success = &ImportCategoryFiles( $opt_dir, $dbh, $category_number, "spam", $opt_source, undef, "errors", undef, $existing_file, "Found URL in a spam email" );
			return( undef ) if ( ! $success );
			
			#  Clean up everything and quit
			$dbh->disconnect;
		}
		
		
	# If I had to create a new sub directory, delete everything out of it and remove the directory
	if ( ( $created_dir )  &&  ( ! $opt_working )  &&  ( ! $opt_debug )  &&  ( ! $opt_review ) )
		{	lprint "Removing work files ...\n";
			
			# Delete any files created
			my $tmp_file = $domain_dir . "\\domains";
			unlink( $tmp_file );
			
			$tmp_file = $domain_dir . "\\urls";
			unlink( $tmp_file );
			
			$tmp_file = $domain_dir . "\\domains.hit";
			unlink( $tmp_file );
			
			$tmp_file = $domain_dir . "\\domains.error";
			unlink( $tmp_file );
			
			$tmp_file = $domain_dir . "\\$existing_file";
			unlink( $tmp_file );
			
			# Remove the directory
			lprint "Removing directory $domain_dir ...\n";
			
			my $cmd = "rmdir \"$domain_dir\" \/s \/q";
			system $cmd;
		}
		
		
	return;	
}



################################################################################
#
sub AnalyzeFile ( $$ )
#
#  Given the full path to the file, and the root directory to put the sub directories in
#  analyze the file.  If the directory is undef, don't add to the output files
#
################################################################################
{   my $file	= shift;
    my $dir		= shift;
	
	
	my $email_from;
	my $header_email_from;
	my $email_to;
	my $external_ip_address;
	my $subject;


    #  Load the file into memory
    @data = ();
    if ( ! open( INFILE, "<$file" ) )
		{	&lprint( "Can not open $file: $!\n" );
			return;
		}

	bprint "File: $file\n" if ( $opt_verbose );
	
	
	@clues = ();					# Initialize the clues array
	
	&debug( "AnalyzeFile = $file\n" );
	&AddClue( "File", $file );
	
    my $counter = 0 + 0;			# The count of lines read from this message file
    my $base64;
	my $quoted_printable;			# True if the boundary is encoded as quoted_printable
    my $message_body;				# True if we are inside part of a message body
	my $header = 1;					# True until we hit the message body - which includes multi part bodies
	my $first_line = 1;				# True if we are reading the first line of the file
	my @boundary;					# The list of boundaries
	my $content_description;		# The description of the current content
	my $content_type;				# The content type of the current part
	my $encoding;					# The encoding of the current part
	my $attachment;					# True if this part contains an attachment
	my $attachment_count = 0 + 0;	# The number of attached files
	my @attached_files;				# The names of the attached files
	my $message_files = 0 + 0;		# The count of message files created
	my $total_parts = 0 + 0;		# The count of the number of parts to a multipart message
    my $bytes = 0 + 0;
	my $attach_filename;			# The name of the current attachment
	my $emailto_domain;				# The domain of the current email to recipient
	my %checked_domains;			# A hash of the domain names and urls that I need to check for this email
	
	
    while ( my $line = <INFILE> )
       {	my $len = length( $line );
			next if ( $len > 1000 );  #  Skip long lines

			$bytes += $len;   #  Count the bytes

			$counter++;			# Count the lines
				
				
			# Have I read a lot in already?
 			if ( ( $counter > $max_lines )  ||  ( $bytes > $max_bytes ) )
				{	&lprint( "Not unpacking completely file $file because of size limitations\n" );
					&lprint( "# of lines = $counter, # of bytes = $bytes\n" );
					
					last;
				}


			chomp( $line );


			if ( $header )
				{
					
					#  Am I reading the first line comment by Brock's code?
					if ( ( $first_line )  &&  ( $line =~ m/\(externalipaddress/i ) )
						{	$first_line = undef;
							my $comment = $line;

							$comment =~ s/\(//;
							$comment =~ s/\)//;
			
							# Read additional lines until I get the trailing )
							while ( ( $line )  &&  ( ! ( $line =~ m/\)/ ) ) )
								{	$line = <INFILE>;
									chomp( $line );
									
									# Get rid of leading whitespace
									$line =~ s/^\s+// if ( $line );

									# Get rid of trailing whitespace
									$line =~ s/\s+$// if ( $line );
									
									$comment .= "," . $line if ( $line );
								}

							my @parts = split /\s/, $comment;
							my $part_no = 0;
							foreach ( @parts )
								{	next if ( ! defined $_ );
									my $keyword = lc( $_ );
									
									$part_no++;
									#  Check for a blank value
									next if ( ! $parts[ $part_no ] );
									next if ( index( "emailfrom:emailto:externalipaddress:", lc( $parts[ $part_no ] ) ) != -1 );
								 
									if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
									if ( $keyword eq "emailto:" )            {  $email_to = lc ( $parts[ $part_no ] );  }
									if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
								}

							&AddClue( "From", $email_from );
							
							my @envelope_to = split /\,/, $email_to if ( $email_to );

							&AddClue( "Envelope To", $email_to );
							$emailto_domain = undef;
							my $junk;
							( $junk, $emailto_domain ) = split /\@/, $envelope_to[ 0 ], 2 if ( $envelope_to[ 0 ] );
							$emailto_domain = &CleanUrl( $emailto_domain );
							
							&AddClue( "Email To Domain", $emailto_domain ) if ( defined $emailto_domain );
							&AddClue( "External-IP", $external_ip_address );
							
							my ( $user, $email_domain ) = split /\@/, $email_from if ( $email_from );
							$email_domain = &CleanUrl( $email_domain );
							$checked_domains{ $email_domain } = $email_domain if ( $email_domain );
							# end of first line processing
						}


					#  Consume any comments in the header - to avoid being deceived
					if ( $line =~ m/\(.*\)/ )
						{  $line =~ s/\(.*\)//;
							$line = "\(\)" if ( !$line );  # if nothing left, pad it to be a blank comment
						}
				   
				
					my $lc_line = lc( $line );	# Get a lower case copy of the line to check encoding, etc

				 
					#  Am I setting the Subject line?
					if ( $lc_line =~ m/subject:/ )
						{	my ( $junk, $stuff ) = split /subject:/, $lc_line, 2;
							$subject = $stuff;
							$subject =~ s/^\s//gm;
							$subject =~ s/\s$//gm;
							
							&AddClue( "Subject", $subject );
						}
			 			 
						 
					#  Am I a setting the header email from?
					if ( ( ! defined $header_email_from )  &&  ( $lc_line =~ m/^from:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/from://i;
							
							$header_email_from = $stuff;
							$header_email_from =~ s/^\s//g;
							$header_email_from =~ s/\s$//g;
							
							$header_email_from = &CleanEmail( $header_email_from );
							&AddClue( "header email from", $header_email_from ) if ( $header_email_from );
							
							my ( $user, $email_domain ) = split /\@/, $header_email_from if ( $header_email_from );
							$email_domain = &CleanUrl( $email_domain );
							$checked_domains{ $email_domain } = $email_domain if ( $email_domain );
						}
					 			
								
					#  Am I setting the Content Description?
					if ( $lc_line =~ m/content-description:/ )
						{	my ( $junk, $stuff ) = split /content-description:/, $lc_line, 2;
							$content_description = $stuff;
							$content_description =~ s/^\s//g;
							$content_description =~ s/\s$//g;
							
							&AddClue( "Content-DESC", $content_description );
						}
			 			 
				 
					#  Am I setting the Content Type?
					if ( $lc_line =~ m/content-type:/ )
						{	my ( $junk, $stuff ) = split /content-type:/, $lc_line, 2;
							$content_type = $stuff;
							$content_type =~ s/\s//;
							$content_type =~ s/\;//;
							( $content_type, $junk ) = split /\s/, $content_type, 2;
							
							&AddClue( "CONTENT-TYPE", $content_type );	 
						}
			 
			 
					# Am I setting the encoding?
					if ( $lc_line =~ m/content-transfer-encoding:/ )
						{	my ( $junk, $stuff ) = split /content-transfer-encoding:/, $lc_line, 2;
							$encoding = $stuff;
							$encoding =~ s/\s//;
							$encoding =~ s/\;//;
							( $encoding, $junk ) = split /\s/, $encoding, 2;
							$base64 = undef;
							$quoted_printable = undef;
								 					
							if ( $encoding =~ m/base64/i )
								{	$base64 = 1;
									$message_files++;	# Write this out to a message file
								}
							elsif ( $encoding =~ m/quoted-printable/i )
								{	$quoted_printable = 1;
									$message_files++;	# Write this out to a message file
								}
								
							&AddClue( "ENCODING", $encoding );
						}


					#  Am I a setting the disposition?
					if ( $lc_line =~ m/content-disposition:/ )
						{	my ( $junk, $stuff ) = split /content-disposition:/, $lc_line, 2;
							my $disposition = $stuff;
							$disposition =~ s/\s//;
							$disposition =~ s/\;//;
							
							if ( $lc_line =~ m/attachment/ )
								{	$attachment = 1;
									$attachment_count++;
									&debug( "Content-Disposition: attachment\n" );
								}
								
							&AddClue( "DISPOSITION", $disposition );
						}
					 
					 
					#  Am I a setting the attachment filename?
					if ( $lc_line =~ m/name=/ )
						{   my ( $junk, $stuff ) = split /name=/, $line, 2;
							my ( $junk1, $junk2 );
																
							# Peel off quote marks if they are there
							if ( $stuff =~ m/\"/ )
								{	( $junk1, $attach_filename, $junk2 ) = split /\"/, $stuff, 3;
								}
							else
								{	$attach_filename = $stuff;
								}

							if ( $attach_filename )
								{	push @attached_files, $attach_filename;
									&debug( "Attached file name = $attach_filename\n" );
								}
									
							$attachment = undef;
							&AddClue( "ATTACH-NAME", $attach_filename );
						}


					#  Am I a setting a boundary?
					if ( $lc_line =~ m/boundary=/g )
						{ 
							my $boundary = substr( $line, pos( $lc_line ) );
							$boundary =~ s#\"##g;   #  Get rid of quotes
							$boundary = '--' . $boundary;	#  Add the dash dash
							
							&AddClue( "BOUNDARY", $boundary );
							
							$boundary = quotemeta( $boundary );  #  Backslash any non alpha character
							push @boundary, $boundary;
						}			 
				}  # end of the header processing 
			 
			 
			#  Have I hit a boundary?
			#  I'm in a header if this matches - until I hit a blank line
			foreach ( @boundary )
				{   next if ( ! defined $_ );
				 
					my $boundary = $_;
					
					if ( $line =~ m/^$boundary/ )
						{	$header				= 1;
							$message_body		= undef;
							$base64				= undef;
							$quoted_printable	= undef;
							$encoding			= undef;
							$attachment			= undef;
							$attach_filename	= undef;
						}
			  }  # end of foreach boundary
			 
			 
			#  A blank line or a dot in the header means we are switching to a body
			if ( ( !$line ) || ( $line eq "." ) )
				{	$total_parts++ if ( !$message_body );
					$message_body	= 1;
					$header			= undef;
					$line			= undef;				
				}
		
			 
			next if ( ! $line );  #  Now that it is blank, skip it


			#  If we are in a body, decode any base64 stuff 
			if ( ( $base64 )  &&  ( $message_body ) )  #  Decode if it looks like it matches
             {   
                 my $not_legal = length( $line ) % 4;
				 
				 # Check to see if it really is a base 64 string - these are all the legal characters
				 $not_legal = 1 if ( $line =~ m/[^a-zA-Z0-9\+=\/]/ );

                 if ( !$not_legal )   #  Don't decode if not a multiple of 4 or has illegal characters
                    {	
						$line = decode_base64( $line );					
                    }
             } # end of decoding base64


			#  If we are in a body, and virus_checking is enable, decode any quoted_printable
			if ( ( $quoted_printable )  &&  ( $message_body ) )  #  Decode if it looks like it matches
				{	# At this point I have already chomped any \n
				 
				$line =~ s/[ \t]+\n/\n/g;        # rule #3 (trailing space must be deleted)
				
				my $hard_return;

				# Trim off any soft returns
				if ( $line =~ m/=$/ )
					{	$line =~ s/=+$//;
					}
				else
					{  $hard_return = 1;
					}
					
					
				# Remove any = signs that aren't followed by 2 hexadecimal characters
				pos( $line ) = 0;
				while ( $line =~ /=(..)/g )
					{	my $str = $1;
						my $hex = uc( $str );
						
						my $left = $`;
						my $right = $';
	
						# Are the next 2 characters left hex codes?  If not, dump the = sign
						if ( $hex =~ m/[^0-9A-F]/ )
							{	
								$line = $left . $str . $right;
								pos( $line ) = length( $left );  # Start checking where we left off
							}						
					}
								
									
				# Decode the line - now using MIME module instead of the substitution line
				$line = MIME::QuotedPrint::decode_qp( $line );
				
				$line = $line . "\r\n" if ( $hard_return );	# Add a carriage return line feed if a hard return
             } # end of decoding quoted-printable

		   
			# Should I save this line into the data array for later Bayesian processing?					
			# Should I skip based on content-type?
			# If it matches on one of these content types, don't do the Bayesian stuff on this data
			if ( ( $message_body )  &&  ( $content_type ) )
				{	next if ( $content_type =~ m/pdf/ );
					next if ( $content_type =~ m/x-msdownload/ );
					next if ( $content_type =~ m/octet-stream/ );
					next if ( $content_type =~ m/audio/ );
					next if ( $content_type =~ m/image/ );
					next if ( $content_type =~ m/postscript/ );
					next if ( $content_type =~ m/zip/ );
  				}
						
			# Should I skip based on attached filename?
			# If it matches on one of these file extensions, don't do the Bayesian stuff on this data
			if ( ( $message_body )  &&  ( $attach_filename ) )	
				{	next if ( $attach_filename =~ m/\.exe/ );
					next if ( $attach_filename =~ m/\.com/ );
					next if ( $attach_filename =~ m/\.pcx/ );
					next if ( $attach_filename =~ m/\.dll/ );
					next if ( $attach_filename =~ m/\.jpg/ );
					next if ( $attach_filename =~ m/\.jpeg/ );
					next if ( $attach_filename =~ m/\.ai/ );
					next if ( $attach_filename =~ m/\.scr/ );
					next if ( $attach_filename =~ m/\.zip/ );
					next if ( $attach_filename =~ m/\.gz/ );
					next if ( $attach_filename =~ m/\.ppt/ );
 					next if ( $attach_filename =~ m/\.xls/ );
					next if ( $attach_filename =~ m/\.doc/ );
					next if ( $attach_filename =~ m/\.bmp/ );
					next if ( $attach_filename =~ m/\.pdf/ );
					next if ( $attach_filename =~ m/\.cup/ );
					next if ( $attach_filename =~ m/\.mpg/ );
					next if ( $attach_filename =~ m/\.mpeg/ );
 				}
						
			# Add it to the data array for later Bayesian processing	
			push @data, $line;
			
			
			#  Does it have at least one http://  ?
			while ( $line =~ m/http:\/\// )
				{	my ( $junk, $url ) = split  /http:\/\//, $line, 2;
                    $line = $url;  #  Put what's left into line so that if there is multiple https on the same line we handle it
                    
                    #  Try to clean off as much crap as possible
                    ( $url, $junk ) = split  /http:\/\//, $url, 2 if ( $url );
                    ( $url, $junk ) = split  /\s/, $url, 2 if ( $url );

                    ( $url, $junk ) = split /\?/, $url, 2 if ( $url );
                    ( $url, $junk ) = split /\"/, $url, 2 if ( $url );


					next if ( ! defined $url );
					
					&debug( "Possible URL: $url\n" );
					
                    #  If it has a user id at the front of the url
                    if ( $url =~ m/@/ )
                       {  ( $junk, $url ) = split /\@/, $url, 2;
                       }
				
                    $url = &CleanUrl( $url );
					my $trim_url = &TrimWWW( $url );
					
					next if ( ! defined $trim_url );

					my ( $domain, $url_ext ) = split /\//, $trim_url, 2;
					$domain = &CleanUrl( $domain );
					$checked_domains{ $domain } = $url if ( $domain );
					
					&debug( "Domain: $domain, URL: $url\n" ) if ( $domain );
				}						

			$first_line = undef;
        }

	close( INFILE );
	
	
	# See if I can figure out the emailto_domain here
	if ( ( ! defined $emailto_domain )  &&  ( $email_to ) )
		{	my $junk;
			( $junk, $emailto_domain ) = split /\@/, $email_to;
			$emailto_domain = &CleanUrl( $emailto_domain );
		}
	
		
	while ( my ( $domain, $url ) = each( %checked_domains ) )
		{	next if ( ! defined $domain );

			# Make sure the URL is not the victim's URL
			next if ( ( $emailto_domain )  &&  ( $domain eq $emailto_domain ) );

			&AddDomainClue( $domain, $url, $dir );
		}

	&BayesianAnalyzeFile() if ( ! $opt_files );
	 

	return( 0 );
}



################################################################################
#
sub AddDomainClue( $$$ )
#
#  Given a domain, add it to my domain clues file if it is OK
#
################################################################################
{	my $domain	= shift;
	my $url		= shift;
	my $dir		= shift;

	&debug( "AddDomainClue: Domain: $domain, URL: $url, dir: $dir\n" );

	return( undef ) if ( ! $domain );
	return( undef ) if ( ! $url );
	return( undef ) if ( ! $dir );
	
	
	&SqlSleep() if ( ! $opt_no_sql_timeout );
	
	my $lookupType = &LookupUnknown( $domain, 0 );
	my $category_name;
	my $source_number = 0 + 3;
	
	if ( ! $lookupType )
		{   # bprint "Unknown url $url\n";
			$category_name = "Unknown";
		}
	elsif ( $lookupType == -1 )
		{	bprint "lookup error domain = $domain\n";
			print ERRORS "$domain\n";
		}
	else
		{	&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			my $category_number;
			
			( $category_number, $source_number ) = &FindCategory( $domain, $lookupType );
			$category_name = &CategoryName( $category_number );

			if ( ! $category_name )
				{	$category_name = "lookup error";
					print ERRORS "$domain\n";
				}
		}

	&AddClue( "URL", "$domain - $category_name" );
	
	bprint "Found URL: $domain $category_name\n" if ( $opt_verbose );


	# Should I save it?
	my $save_it = 1;

	$save_it = 1 if ( $opt_urls );
	$save_it = 1 if ( $opt_allfiles );
	
	
	# Try to avoid obvious mistakes ...
	
	my $root_domain = &RootDomain( $domain );
	return( undef ) if ( ! $root_domain );

	my @parts = split /\./, $domain;
	

	# Ignore short domains
	$save_it = undef if ( ( $#parts == 1 )  &&  ( length( $parts[ 0 ] ) < 4 ) );


	# These domains get included in spam a lot, but they aren't spam
	$save_it = undef if ( $root_domain eq "yahoo.com" );
	$save_it = undef if ( $root_domain eq "yimg.com" );
	$save_it = undef if ( $root_domain eq "nypost.com" );
	$save_it = undef if ( $root_domain eq "ebay.com" );
	$save_it = undef if ( $root_domain eq "nytimes.com" );
	$save_it = undef if ( $root_domain eq "microsoft.com" );
	$save_it = undef if ( $root_domain eq "w3.org" );
	$save_it = undef if ( $root_domain eq "akamai.net" );
	$save_it = undef if ( $root_domain eq "apache.org" );
	$save_it = undef if ( $root_domain eq "ebaystatic.com" );
	$save_it = undef if ( $root_domain eq "washingtontimes.com" );

	# These are goverment and education domains
	$save_it = undef if ( $domain =~ m/\.k12\./ );
	$save_it = undef if ( $domain =~ m/\.gov$/ );
	$save_it = undef if ( $domain =~ m/\.mil$/ );
	$save_it = undef if ( $domain =~ m/\.edu$/ );
	$save_it = undef if ( $domain =~ m/\.edu\./ );
	$save_it = undef if ( $domain =~ m/\.gov\./ );
	$save_it = undef if ( $domain =~ m/\.msn\./ );
	$save_it = undef if ( $domain =~ m/\.yahoo\./ );
	$save_it = undef if ( $domain =~ m/\.aol\./ );

	
	# Was it entered by hand?
	$save_it = undef if ( ( 0 + $source_number ) < ( 0 + 3 )  );
	
	if ( ( $opt_files )  &&  ( $save_it ) )
		{	print DOMAIN "$root_domain\n" if ( $root_domain ne $domain );
			print DOMAIN "$domain\n";
				
			# Is this an IP address?
			next if ( &IsIPAddress( $domain ) );
			
			# Lookup all the IP addresses for this url if I'm supposed to lookup DNS, or if it is unknown
			if ( $opt_dns_query )
				{	&lprint( "Querying DNS for $domain ...\n" ) if ( $opt_verbose );
					my @ip_addresses = &URLIPAddresses( $domain );
					
					# If I didn't get any IP addresses, try a www on the front
					my $test_domain = "www." . $domain;
					if ( $#ip_addresses < 0 )
						{	&lprint( "No IP found for $domain so querying DNS for $test_domain ...\n" ) if ( $opt_verbose );
							@ip_addresses = &URLIPAddresses( $test_domain );
						}
					
					&lprint( "Found IP addresses @ip_addresses\n" ) if ( ( $#ip_addresses > - 1 )  &&  ( $opt_verbose ) );
					&lprint( "Found no IP addresses\n" ) if ( ( $#ip_addresses < 0 )  &&  ( $opt_verbose ) );
					
					foreach ( @ip_addresses )
						{	next if ( ! $_ );
							print DOMAIN "$_\n";
							
							$url_ip_counter++;
						}
				}
		}
		
	&SaveKnown( $category_name, $domain, $dir ) if ( ( $lookupType )  &&  ( $opt_files )  &&  ( $opt_category ) );
}



################################################################################
#
sub AddClue($$)
#
#  Given the clue name and the clue, add it to the list of clues about this message
#
################################################################################
{   my $name = shift;
	my $clue = shift;
	
	return if ( ! $clue );
	
	$name = uc( $name );
	$clue =~ s#\"#\\\"#;
	my $line = $name . ": " . "\"" . $clue . "\"";
	
	push @clues, $line;
	
	&debug( "Add Clue: $line\n" );
}



################################################################################
#
sub LoadSpamTokens()
#
#  Load the spam tokens file, transforming the weight by the given parameters
#
################################################################################
{
	my %nonspam_occurrences;		# The count of how many times the token was found in the nonspam files
	my %spam_occurrences;			# The count of how many times the token was found in the spam files
    my $nonspam_files = 0 + 0;
    my $spam_files = 0 + 0;


	$corpus_file = $tokens_dir . "\\localtokens.txt";


	if ( !open( TOKENS, "<$corpus_file" ) )
		{   $corpus_file = $tokens_dir . "\\spamtokens.txt";
            open TOKENS, "<$corpus_file" or &FatalError( "Can not open $corpus_file: $!" );             
		}


	while ( my $line = <TOKENS> )
       {	chomp( $line );
			my ( $token, $weight, $good, $bad ) = split $line;

			next if ( !$token );

			#  Is this token used enough?
			my $frequency = $bad + $good;
			next if ( $frequency < $min_frequency );

			$token_spam_rating{ $token } = 0 + $weight;
			$spam_occurrences{ $token } = 0 + $bad;
			$nonspam_occurrences{ $token } = 0 + $good;

			#  Is this my "the" token that holds the count of spam and nonspam files?
			next if ( $token ne "the" );
 
			$spam_files = 0 + $bad;
			$nonspam_files = 0 + $good;
		}

    close( TOKENS );


    #  Modify the weight based on command line options    
    my  $badlist_messagecount = $spam_files;
    my  $goodlist_messagecount = $nonspam_files;
	foreach ( keys %token_spam_rating )
       {	next if ( !$_ );

			my  $token = $_;
          
			#  Use the same variable names as Paul Graham
			my  $goodcount = 0 + 0;
			my  $badcount = 0 + 0;

			if ( defined( $nonspam_occurrences{ $token } ) )
				{  $goodcount = $nonspam_occurrences{ $token };
				}

			if ( defined ( $spam_occurrences{ $token } ) )
				{  $badcount = $spam_occurrences{ $token };
				}

			#  Is this token used enough to keep?
			my $total = $goodcount + $badcount;
			next if ( $total < $min_frequency );

			# Normalize the goodvalue to account for the sample size and factor in the fudge amount
			my $goodnorm =  $expected_good_to_bad * ( ( $goodcount * $badlist_messagecount ) / $goodlist_messagecount );

			#  Calculate the percentage of the time this token appears in a spam file versus a non spam file
			my $pw = $badcount / ( $goodnorm + $badcount );

			#  Make sure that rare words don't totally drive the calculation wild
			if ( $pw > $pure_spam )
				{  $pw = $pure_spam;
                }

			if ( $pw < $pure_notspam )
                {  $pw = $pure_notspam;
                }

			$token_spam_rating{ $token } = $pw;
		}
}



################################################################################
#
sub BayesianAnalyzeFile()
#
#  Given the data in the array @data, run the Bayesian statistics on it,
#  and return 1 if it is spam, 0 if not.  Also return the Bayesian score
#
################################################################################
{	my @email_tokens;

	&debug( "BayesianAnalyzeFile\n" );

	foreach ( @data )
		{	my $line = $_;

			my @tokens = split( /[^a-zA-Z\d]+/, $line );

			foreach (@tokens)
				{	    
					# Length restriction
					my $length = length;
					next if ($length < 3 || $length > 40);

					# Ignore all-digit tokens
					next if (/^[0-9.]+$/);

					# Ignore tokens that start with a number
					next if ( m/^[0-9]/ );

					push @email_tokens, $_;
				}
		}


    # Rate each token according to how far from 0.5 it is
    my %email_token_spam_rating;
    my %interesting_tokens;
   
    #Keep track of new tokens
    my %new_tokens;


	foreach ( @email_tokens )
		{
			next if (! length $_);

			my $token = lc( $_ );

			my $rating = $opt_unknown_token;

			#  I don't know the token - use the unknown value
			if ( defined( $token_spam_rating{ $token } ) )
				{  $rating = $token_spam_rating{ $token };
				}

			#  Calculate the deviation from neutral
			my $dev = abs( 0.5 - $rating );

			#  Skip it if it isn't important
			next if ( $dev < $opt_mindev );
	
				$email_token_spam_rating{ $token } = $rating;

			$interesting_tokens{ $token } = $dev;
		}

    
    # Show Information
    my $interesting_tokens_count = scalar keys %interesting_tokens;


    # Get number of interesting tokens
    my $most_interesting_count = $interesting_tokens_count > $opt_most_interesting_max ?
        $opt_most_interesting_max : $interesting_tokens_count;

    #  Not enough tokens to judge
    if ( $most_interesting_count < $opt_most_interesting_min )
        {   return( 0 + 0, 0 + 0 );
        }


	# Get the most interesting tokens, which are sorted by decreasing order of interest
	my @most_interesting = (sort { $interesting_tokens{ $b } <=> $interesting_tokens{ $a } } 
            keys %interesting_tokens)[0..$most_interesting_count - 1];


	# Calculate the Bayes probability
	my $prod = 1;
	my $one_minus_prod = 1;

	foreach ( @most_interesting )
		{
			next if ( !defined $_ );
	        next if ( !defined $email_token_spam_rating{ $_ } );

	        $prod *= $email_token_spam_rating{ $_ };
	        $one_minus_prod *= ( 1.0 - $email_token_spam_rating{ $_ } );
		}


	my $probability_of_spam = 0 + 0;
	$probability_of_spam = $prod / ( $prod + $one_minus_prod )
	if ( ( $prod + $one_minus_prod ) > 0 );


	foreach ( @most_interesting )
		{
			next if ( !defined $_ );
			next if ( !defined $email_token_spam_rating{ $_ } );
			&AddClue( "BAYESIAN-TOKEN", "$_ - $email_token_spam_rating{ $_ }" );
		}  # end of foreach most_interesting


     #  Return 1 if I think it is spam, 0 if not
	 my $result = sprintf( "%2.4f", $probability_of_spam );
	 
	 &AddClue( "BAYESIAN-SCORE", $result );
		
     return( 0 + 0 );
}



################################################################################
#
sub SaveKnown($$$)
#
#  Given the category and the url and the directory, save them in a sub directory
#
################################################################################
{   my $category	= shift;
    my $url			= shift;
	my $opt_dir		= shift;
	
	return if ( ! $opt_category );
	return if ( ! $category );
	
    # Open the right file to write the hit urls to
    my $dir = $category;
    $dir = $opt_dir . "\\" . $category if ( $opt_dir );

    my  $cmd;
    my  $filename = "$dir\\domains\.hit";

    #  Can I open an existing file?
    my $err;
    open( OUTPUT, ">>$filename" ) or $err = 1;
    if ( $err )
      {  $cmd = "mkdir \"$dir\"";
         system( $cmd );

         open OUTPUT, ">>$filename" or print "Cannot create output file: $filename,\n$!\n";
     }

    print OUTPUT "$url\n";
    close( OUTPUT );
}



################################################################################
################################################################################
################# Daily Statistics Spam Processing Functions  ##################
################################################################################
################################################################################



my %spam_ip_address;
my %ham_ip_address;
my %ham_domains;
my %spam_domains;
my %spam_rbl;



################################################################################
# 
sub SpamChallengeAnalyze()
#
#  Extract IP addresses from spams that failed the spam challenge test
#
################################################################################
{   
    my $spam_category	= &CategoryNumber( "spam" );
    my $ham_category	= &CategoryNumber( "ham" );

	if ( ! $spam_category )
		{	lprint "Unable to get the category number of the spam category\n";
			return( undef );
		}
		
		
	lprint "Adding IP addresses of spam challenged emails ...\n";


    # Figure out 8 hours ago in SQL time format
	my $old_time = time() - ( 8 * 60 * 60 );
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );

	$year = 1900 + $year;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );

	
    # Figure out 2 days ago in SQL time format
	$old_time = time() - ( 48 * 60 * 60 );
    ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );

	$year = 1900 + $year;
	$mon++;
	my $old_datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
    
	# Get spam that failed the spam challenge
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $str = "SELECT ExternalIpAddress, EmailFrom, EmailTo FROM SpamMailBlocker WITH(NOLOCK) WHERE Status like 'Spam (Realtime Spam Checker) Challenge email sent%' AND [Time] < \'$datestr\' AND [Time] > '$old_datestr' ORDER BY ExternalIpAddress";
    my $sth = $dbhStats->prepare( $str );
	$sth->execute();


	my $last_ip_address = '0.0.0.0';
	my $add_counter = 0 + 0;
	my %comp_hash;
	
	while ( ( ! $dbhStats->err )  &&  (  my ( $ipAddress, $emailFrom, $emailTo ) = $sth->fetchrow_array() ) )
		{
			my $str_ipaddress = &IPToString( $ipAddress );

			$emailTo = &CleanEmail( $emailTo ) if ( defined $emailTo );
				
			$emailFrom = &CleanEmail( $emailFrom ) if ( defined $emailFrom );
			
			
			# Keep track of all the comps to later check to see if they were autowhitelisted
			if ( ( $emailTo )  &&  ( $emailFrom ) )
				{	my $comp = $emailTo . ':' . $emailFrom;
					$comp = lc( $comp );
					
					$comp_hash{ $comp } = $str_ipaddress;
				}
				
			next if ( $str_ipaddress eq $last_ip_address );
			
			
			$last_ip_address = $str_ipaddress;
			
			my $retcode = &AddNewTrans( $str_ipaddress, $spam_category, 0, $opt_source );

			next if ( $retcode != 0 );
			
			$add_counter++;
			
			lprint "$str_ipaddress was used to send spam that was challenged\n";
			
			&CategorySaveDomainReason( $str_ipaddress, "spam", "sent spam that was challenged" );
		}
		
		
	&SqlErrorHandler( $dbhStats );	
	$sth->finish();
	
	lprint "Added $add_counter new spam IP addresses to the database\n";


	lprint "Checking autowhitelist entries to see if any overblocking by spam IP ...\n";
	
	
	my %overblock;
	my $overblock_count = 0 + 0;
	
	while ( my ( $comp, $str_ipaddress ) = each( %comp_hash ) )
		{
			# Check to see if it is already in the list
			$dbh = &SqlErrorCheckHandle( $dbh );
			my $sth = $dbh->prepare( "SELECT Comp from AutoWhiteList WITH(NOLOCK) WHERE Comp = ?" );
			$sth->bind_param( 1, $comp,  DBI::SQL_VARCHAR );
			$sth->execute();
			
			my ( $CompDB ) = $sth->fetchrow_array();
			
			&SqlErrorHandler( $dbh );
			$sth->finish();
			
			# If an autowhite entry is now found, then I must have overblocked something
			if ( $CompDB )
				{	$overblock{ $str_ipaddress } = 1;
					$overblock_count++;	
				}
		}
		
	
	# Return here if I didn't find any overblocks
	if ( ! $overblock_count )
		{	lprint "Did not find any overblocks by spam IP\n";
			return( 0 + 0 ) ;
		}


	my $overblocked_changes = 0 + 0;
	while ( my ( $str_ipaddress, $val ) = each( %overblock ) )
		{
			my ( $catnum, $source ) = &FindCategory( $str_ipaddress, 0 + 6 );
			
			# Don't change the category if the source < 3 or the category isn't spam
			next if ( $source < $opt_source );
			next if ( $catnum != $spam_category );
			
			lprint "Overblocked spam from IP address $str_ipaddress so changing the category to ham\n";
			my $retcode = &UpdateCategory( $str_ipaddress, $ham_category, 0 + 6, $opt_source );
			
			$overblocked_changes++ if ( ! $retcode );
		}
	
	
	lprint "Found $overblock_count overblocks, actually changed $overblocked_changes IP addresses from spam to ham\n";

	return( 0 + 0 );
}



################################################################################
# 
sub SpamExtract()
#
#  Connect to the Statistics database, extract out new ham and spam info
#
################################################################################
{   
	lprint "Extracting spam and ham IP addresses from the statistics database ... \n";

    # Figure out 6 days ago in SQL time format
	my $old_time = time() - ( 6 * 24 * 60 * 60 );
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );

	$year = 1900 + $year;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );


    # Get spam that isn't virus infected
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $str = "SELECT ExternalIpAddress, EmailFrom, Status FROM SpamMailBlocker WITH(NOLOCK) WHERE Status like 'Spam %' AND Status NOT LIKE '%Checker - Virus%' AND [Time] > \'$datestr\'";
    my $sth = $dbhStats->prepare( $str );
    $sth->execute();


	# Is this a lightspeed email server in Bakersfield?  We use good RBL servers, but we can't trust that our customers do ...
	my $lightspeed_hostname;
	my $hostname = lc( hostname );
	
	# Is this one of our hosts?
	if ( $hostname )
		{	$lightspeed_hostname = 1 if ( $hostname =~ m/cleanmail1/i );
			$lightspeed_hostname = 1 if ( $hostname =~ m/cleanmail2/i );
			$lightspeed_hostname = 1 if ( $hostname =~ m/ttc\-62/i );
			$lightspeed_hostname = 1 if ( $hostname =~ m/lscom\.net/i );
		}
		
		
	while ( ( ! $dbhStats->err )  &&  (  my ( $ipAddress, $emailFrom, $status ) = $sth->fetchrow_array() ) )
		{	#&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			$status = lc( $status );
			
			# Is it an RBL IP address at Lightspeed?
			if ( ( $lightspeed_hostname )  &&  ( $status )  &&  ( $status =~ m/rbl ip/i ) )
				{	$spam_rbl{ $ipAddress } = 0 + 1;
				}
			elsif ( ! defined $spam_ip_address{ $ipAddress } )
				{	$spam_ip_address{ $ipAddress } = 0 + 1;
				}
			else
				{	$spam_ip_address{ $ipAddress }++;
				}
				
			my ( $user, $domain ) = split /\@/, $emailFrom, 2;
			next if ( ! defined $domain );
			
			$domain = &CleanUrl( lc( $domain ) );
			next if ( ! defined $domain );
			
			$spam_domains{ $ipAddress } = $domain;
		}

	&SqlErrorHandler( $dbhStats );	
	$sth->finish();


    # Get the list of external ip addresses and domains that have mailed ok stuff
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    $str = "SELECT ExternalIpAddress, EmailFrom FROM SpamMailBlocker WITH(NOLOCK) WHERE Status like 'OK%' AND [Time] > \'$datestr\'";
    $sth = $dbhStats->prepare( $str );
	
    $sth->execute();

     while ( ( ! $dbhStats->err )  &&  (  my ( $ipAddress, $emailFrom ) = $sth->fetchrow_array() ) )
		{	#&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			if ( ! defined $ham_ip_address{ $ipAddress } )
				{	$ham_ip_address{ $ipAddress } = 0 + 1;
				}
			else
				{	$ham_ip_address{ $ipAddress }++;
				}

			next if ( ! defined $emailFrom );
			
			
			my ( $user, $domain ) = split /\@/, $emailFrom, 2;
			next if ( ! $domain );
			
			$domain = &CleanUrl( lc( $domain ) );
			next if ( ! defined $domain );
			
			if ( ! defined $ham_domains{ $ipAddress } )
				{	$ham_domains{ $ipAddress } = $domain;
					next;
				}
				
				
			# Have I seen a different domain from this same IP address?	
			my $existing_domain = $ham_domains{ $ipAddress };
			
			next if ( $domain eq $existing_domain );
			
			my @domains = split /\t/, $existing_domain;
			
			my $match;
			
			foreach ( @domains )
				{	$match = 1 if ( ( $_ )  &&  ( $_ eq $domain ) );
				}
				
			next if ( $match );
			
			my $str_ipaddress = &IPToString( $ipAddress );
					
			push @domains, $domain;
			
			$existing_domain = undef;
			foreach ( @domains )
				{	next if ( ! $_ );
					my $dom = $_;
					
					$existing_domain .= "\t" . $dom if ( $existing_domain );
					$existing_domain = $dom if ( ! $existing_domain );
				}
				
			# Save the list of domains back to the hash	
			$ham_domains{ $ipAddress } = $existing_domain;
			
			lprint "$str_ipaddress has sent mail from domains $existing_domain\n" if ( $opt_verbose );
		}

	&SqlErrorHandler( $dbhStats );	
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub SpamInsert()
#
#  Insert into the Content database the spam and ham info
#
################################################################################
{   my $sth;
	
    my $ham_category	= &CategoryNumber( "ham" );
    my $spam_category	= &CategoryNumber( "spam" );
    my $errors_category = &CategoryNumber( "errors" );

	if ( ( ! $ham_category )  ||  ( ! $spam_category ) )
		{	lprint "Unable to get the category number of the ham and\\or spam categories\n";
			return( undef );
		}

	lprint "Inserting pure ham IP addresses into the content database ... \n";


    #  Add the ham addresses from the pure ham domains
    my $out_counter = 0 + 0;
    my $switch_counter = 0 + 0;
	
    foreach ( keys %ham_ip_address )
       {	
			next if ( ! $_ );
			my $ipaddress = $_;

			# Did I get some spam from here?
			next if ( defined $spam_ip_address{ $ipaddress } );
			
			my $str_ipaddress = &IPToString( $ipaddress );
 
			next if ( ! &IsValidIP( $str_ipaddress ) );
					 
			my $ham = 0 + $ham_ip_address{ $ipaddress };
			
			my $domain = $ham_domains{ $ipaddress };
			$domain = "unknown" if ( ! $domain );
			
			my @domains = split /\t/, $domain;
			
			# Did I multiple domains from this same IP address?
			if ( $#domains > 0 )
				{	lprint "Got multiple domains from $str_ipaddress $domain so ignoring for now\n" if ( $opt_verbose ); 
					next;
				}

			# Did I get enough ham to make a judgement about how hammy it is?
			if ( $ham < ( 0 + 20 ) )
				{	lprint "Only got $ham Ham emails from $str_ipaddress domain $domain so ignoring for now\n" if ( $opt_verbose ); 
					next;
				}
				
			&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			my $retcode = 0 + 0;	
			$retcode = &LookupUnknown( $str_ipaddress, 0 );


            #  If I don't know this address at all, add it to the ham category
            if ( !$retcode )
				{	lprint "Got $ham ham emails from $str_ipaddress domain $domain so adding\n" if ( $opt_verbose );
					$retcode = &AddNewTrans( $str_ipaddress, $ham_category, 0, $opt_source );

					if ( $retcode == 0 )
						{	$out_counter++;
							&CategorySaveDomainReason( $str_ipaddress, "ham", "received $ham good emails in a row without any spam" );
						}
					next;
				}


			my ( $catnum, $source ) = &FindCategory( $str_ipaddress, $retcode );
			
			
			# Figure out if I should switch categories
			my $switch;
			
			$switch = 1 if ( ( $catnum == $spam_category ) ||  ( $catnum == $errors_category ) );
 			my $catname = &CategoryName( $catnum );
			$switch = 1 if ( $catname =~ m/spam/ );
			
			 
			#  If this is already in the database, and I don't need to switch it, so just update the review time
            if ( ! $switch )
				{	&UpdateReviewTime( $str_ipaddress, $retcode );
					next;
				}


            #  At this point it is in the database and I need to switch it if I can and I need to
			#  Only switching it if it is spam, shopping.spam, or errors, with a high source number
			
			# Make sure that the category hasn't already been changed by something else
			if ( $opt_source <= $source )
				{	&UpdateCategory( $str_ipaddress, $ham_category, $retcode, $opt_source );
					
					&lprint( "Switched $str_ipaddress from $catname to ham\n" ) if ( $opt_verbose );
					$switch_counter++;
					
					&CategorySaveDomainReason( $str_ipaddress, "ham", "received $ham good emails in a row without any spam" );
				}
			else
				{	&lprint( "$str_ipaddress has source $source so not overriding $catname\n" ) if ( $opt_verbose );
				}
       }


	lprint "Added $out_counter pure Ham IP Addresses\n" if ( $out_counter > 0 );
	lprint "Switched $switch_counter IP Addresses from Spam to Ham\n" if ( $switch_counter > 0 );


    #  Add the pure RBL spam addresses
	lprint "Adding RBL server spam IP addresses ...\n";
    $out_counter = 0;
	$switch_counter = 0 + 0;


    foreach ( keys %spam_rbl )
       {   &SqlSleep() if ( ! $opt_no_sql_timeout );
		   
			next if ( !$_ );

			my $ipaddress = $_;
			my $str_ipaddress = &IPToString( $ipaddress );
			
			next if ( ! &IsValidIP( $str_ipaddress ) );
			
	   
			my $retcode = 0 + 0;	
			$retcode = &LookupUnknown( $str_ipaddress, 0 );
			
			
            #  If I don't know this address at all, add it to the spam category
            if ( ! $retcode )
				{	
					lprint "$str_ipaddress was marked as spam by an RBL server so adding to spam category\n";
					$retcode = &AddNewTrans( $str_ipaddress, $spam_category, 0, $opt_source );

					$out_counter++ if ( $retcode == 0 );
					
					&CategorySaveDomainReason( $str_ipaddress, "spam", "marked as spam by an RBL server" );
					next;
				}
				
				
			# Is this already in a blocked category?
			if ( $retcode == ( 0 + 3 ) )
				{	&UpdateReviewTime( $str_ipaddress, $retcode );
					next;
				}
			
			
			my ( $catnum, $source ) = &FindCategory( $str_ipaddress, $retcode );
			
			# Is this already in the spam category?
			if ( $catnum == $spam_category )
				{	&UpdateReviewTime( $str_ipaddress, $retcode );
					next;
				}
			
			
            #  If this is already in the database, and allowed, change it
            if ( $retcode > ( 0 + 3 ) )
				{	&SqlSleep() if ( ! $opt_no_sql_timeout );
					
					lprint "$str_ipaddress was marked as spam by an RBL server so changing it to spam category\n";
					
					#  At this point, it is in the database, and allowed
					my $catname = &CategoryName( $catnum );
					
					if ( $opt_source <= $source )
						{	&UpdateCategory( $str_ipaddress, $spam_category, $retcode, $opt_source );
							&lprint( "Switched $str_ipaddress from $catname to spam\n" ) if ( $opt_verbose );
							
							&CategorySaveDomainReason( $str_ipaddress, "spam", "marked as spam by an RBL server" );
						}
					else
						{	&lprint( "$str_ipaddress has source $source so not overriding $catname\n" ) if ( $opt_verbose );
						}
				}
				
            $switch_counter++;
        }


	lprint "Added $out_counter RBL server IP Addresses\n" if ( $out_counter > 0 );
	lprint "Switched $switch_counter RBL server IP Addresses from allowed to spam\n" if ( $switch_counter > 0 );


    #  Add the pure spam addresses
	lprint "Adding pure spam IP addresses ...\n";
    $out_counter = 0;
	$switch_counter = 0 + 0;


    foreach ( keys %spam_ip_address )
       {   &SqlSleep() if ( ! $opt_no_sql_timeout );
		   
			next if ( !$_ );

			my $ipaddress = $_;
			my $str_ipaddress = &IPToString( $ipaddress );
			
			next if ( ! &IsValidIP( $str_ipaddress ) );
			
			# Was there any ham at all - if there was, skip it
			next if ( defined $ham_ip_address{ $ipaddress } );
			
			
			my $spam = 0 + $spam_ip_address{ $ipaddress };
			
			my $domain = $spam_domains{ $ipaddress };
			$domain = "unknown" if ( ! $domain );
			

			# Did I get enough spam to make a judgement about how spammy it is?
			if ( $spam < ( 0 + 50 ) )
				{	lprint "Only got $spam spam emails from $str_ipaddress domain $domain so ignoring for now\n" if ( $opt_verbose ); 
					next;
				}
				
			my $retcode = 0 + 0;	
			$retcode = &LookupUnknown( $str_ipaddress, 0 );
			
			
            #  If I don't know this address at all, add it to the spam category
            if ( ! $retcode )
				{	lprint "Got $spam spam emails from $str_ipaddress $domain so adding as spam\n" if ( $opt_verbose );
					$retcode = &AddNewTrans( $str_ipaddress, $spam_category, 0, $opt_source );

					if ( $retcode == 0 )
						{	$out_counter++;
							&CategorySaveDomainReason( $str_ipaddress, "spam", "received $spam spam emails in a row with no good emails" );
						}
					next;
				}
				
				
			# Is this already in a blocked category?
			if ( $retcode == ( 0 + 3 ) )
				{	&UpdateReviewTime( $str_ipaddress, $retcode );
					next;
				}
			
			
			# Is this already in the spam category?
			my ( $catnum, $source ) = &FindCategory( $str_ipaddress, $retcode );
					
			if ( $catnum == $spam_category )
				{	&UpdateReviewTime( $str_ipaddress, $retcode );
					next;
				}
			
			
            #  If this is already in the database, and allowed, change it
            if ( $retcode > ( 0 + 3 ) )
				{	&SqlSleep() if ( ! $opt_no_sql_timeout );
					
					my $catname = &CategoryName( $catnum );
					
					if ( $opt_source <= $source )
						{	&UpdateCategory( $str_ipaddress, $spam_category, $retcode, $opt_source );
							&lprint( "Switched $str_ipaddress from $catname to spam\n" ) if ( $opt_verbose );
							
							&CategorySaveDomainReason( $str_ipaddress, "spam", "received $spam spam emails in a row with no good emails" );
						}
					else
						{	&lprint( "$str_ipaddress has source $source so not overriding $catname\n" ) if ( $opt_verbose );
						}
				}
				
            $switch_counter++;
        }


	lprint "Added $out_counter pure Spam IP Addresses\n" if ( $out_counter > 0 );
	lprint "Switched $switch_counter IP Addresses from allowed to spam\n" if ( $switch_counter > 0 );


    #  Add the mixed addresses
#	lprint "Analyzing mixed spam and ham IP addresses ...\n";
    $out_counter = 0 + 0;
	$switch_counter = 0 + 0;
	
	lprint "Ignoring all mixed spam and ham addresses for now\n";
	%spam_ip_address = ();
	
	foreach ( keys %spam_ip_address )
		{	next if ( !$_ );
			
			my $ipaddress = $_;
			
			# Was there any ham at all - if not, skip it - I only want mixed spam and ham IP addresses here
			next if ( ! defined $ham_ip_address{ $ipaddress } );
			
			my $ham = $ham_ip_address{ $ipaddress };
			my $spam = $spam_ip_address{ $ipaddress };

			next if ( ! $ham );
			next if ( ! $spam );

			my $str_ipaddress = &IPToString( $ipaddress );
			next if ( ! &IsValidIP( $str_ipaddress ) );


			my $total = $ham + $spam;
			
			my $spam_percentage = 100 * ( $spam / $total );
			$spam_percentage = &Integer( $spam_percentage );
			
			my $spam_domain = $spam_domains{ $ipaddress };
			$spam_domain = "unknown" if ( ! $spam_domain );
			
			my $ham_domain = $ham_domains{ $ipaddress };
			$ham_domain = "unknown" if ( ! $ham_domain );
			
			
			lprint "IP address $str_ipaddress $ham_domain has $ham ham and $spam spam emails - spam $spam_percentage\%\n" if ( $opt_verbose );
			
			
			# Make a decision if the IP address is a spammer
			if ( $total < ( 0 + 5 ) )
				{	lprint "Only got $total total emails so can\'t decide if $str_ipaddress $spam_domain is a spammer\n" if ( $opt_verbose );
					next;
				}
				
			if ( $total > ( 0 + 200 ) )
				{	lprint "Got $total total emails so can\'t decide if $str_ipaddress $spam_domain is a spammer\n" if ( $opt_verbose );
					next;
				}
				
			if ( $spam_domain ne $ham_domain )
				{	lprint "$str_ipaddress has spam domain $spam_domain and ham domain $ham_domain - can\'t decide if a spammer\n" if ( $opt_verbose );
					next;
				}
				
			if ( $spam_percentage < ( 0 + 75 ) )
				{	lprint "Too low a spam percentage to decide that $str_ipaddress $spam_domain is a spammer\n" if ( $opt_verbose );
					next;
				}
				
				
			# Okay - at this point he is a bad guy - so block him	
			lprint "Decided that IP address $str_ipaddress $spam_domain is a spammer\n" if ( $opt_verbose );


			&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			
			my $retcode = 0 + 0;	
			$retcode = &LookupUnknown( $str_ipaddress, 0 );
			
			
            #  If I don't know this address at all, add it to the spam category
            if ( ! $retcode )
				{	lprint "Adding $str_ipaddress as spam\n" if ( $opt_verbose );
					$retcode = &AddNewTrans( $str_ipaddress, $spam_category, 0, $opt_source );

					$out_counter++ if ( $retcode == 0 );
					next;
				}
				
				
			# Is this already in a blocked category?
			if ( $retcode == ( 0 + 3 ) )
				{	&UpdateReviewTime( $str_ipaddress, $retcode );
					next;
				}
			
			
			my ( $catnum, $source ) = &FindCategory( $str_ipaddress, $retcode );
			
			# Is this already in the spam category?
			if ( $catnum == $spam_category )
				{	&UpdateReviewTime( $str_ipaddress, $retcode );
					next;
				}
			
			
            #  If this is already in the database, and allowed, change it
            if ( $retcode > ( 0 + 3 ) )
				{	#  At this point, it is in the database, and allowed
					my $catname = &CategoryName( $catnum );
					
					if ( $opt_source <= $source )
						{	&UpdateCategory( $str_ipaddress, $spam_category, $retcode, $opt_source );
							&lprint( "Switched $str_ipaddress from $catname to spam\n" ) if ( $opt_verbose );
						}
					else
						{	&lprint( "$str_ipaddress has source $source so not overriding $catname\n" ) if ( $opt_verbose );
						}
				}
				
            $switch_counter++;
		}
		
	lprint "Added $out_counter pure mixed IP Addresses to the spam category\n" if ( $out_counter > 0 );
	lprint "Switched $switch_counter mixed IP Addresses from allowed to spam\n" if ( $switch_counter > 0 );
	

    #  Clear out the memory used
    %spam_ip_address	= ();
    %ham_ip_address		= ();
    %ham_domains		= ();
    %spam_domains		= ();
    %spam_rbl			= ();
	
	
	lprint "Cleaning redundant entries in the Auto Grey List table ...\n";
	$dbh = &SqlErrorCheckHandle( $dbh );
	$sth = $dbh->prepare( "DELETE FROM AutoGreyList WHERE Comp IN ( SELECT Comp FROM AutoWhiteList WITH(NOLOCK) )" );
	
	$sth->execute();
	
	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub AutowhiteCheck()
#
#  Go through the autowhite list to see if I am overblocking any domains or IP
#  addresses
#
################################################################################
{
	my $last_time = &GetAutowhiteCheckTime();
	
	my $all = 1 if ( ! $last_time );
	
	&lprint( "Reading auto white list entries to check for overblocking ...\n" ) if ( $all );
	&lprint( "Reading auto white list entries since $last_time to check for overblocking ...\n" ) if ( ! $all );
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "SELECT Comp, TransactionTime FROM AutoWhiteList WITH(NOLOCK)" ) if ( $all );
	$sth = $dbh->prepare( "SELECT Comp, TransactionTime FROM AutoWhiteList WITH(NOLOCK) WHERE TransactionTime > \'$last_time\'" ) if ( ! $all );
	
	$sth->execute();
	
	
	my %from_domains;
	my $counter = 0 + 0;
	while ( my ( $comp, $transaction_time ) = $sth->fetchrow_array() )
		{	&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			last if ( ! defined $comp );
			
			$last_time = $transaction_time if ( ! $last_time );
			$last_time = $transaction_time if ( $last_time lt $transaction_time );
			
			my ( $to, $from ) = split /\:/, $comp, 2;
		   
			next if ( ! $from );
		   
			my ( $user, $domain ) = split /\@/, $from;
		   
			next if ( ! $domain );
		
			my $root = &RootDomain( $domain );
			
			next if ( ! $root );
			
			$counter++;
			if ( $from_domains{ $root } )
				{	$from_domains{ $root }++;
				}
			else
				{	$from_domains{ $root } = 0 + 1;
				}
		}
	   
	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	&lprint( "Read $counter auto white list entries\n" );
			
	
	&lprint( "Looking up auto white list domains ...\n" );
	my $domains = 0 + 0;
	$counter = 0 + 0;	
	my $ip_counter = 0 + 0;
	
	my @keys = sort keys %from_domains;
	my $ham_category = &CategoryNumber( "ham" );
	
	foreach ( @keys )
		{	my $root = $_;
			next if ( ! $root );
			
			$domains++;
			
			my $retcode = &LookupUnknown( $root, 0 );
			next if ( ! $retcode );
			
			my ( $catnum, $source ) = &FindCategory( $root, $retcode );
			my $catname = &CategoryName( $catnum );
			next if ( ! $catname );
			
			# Is it spam?
			my $spam = 1 if ( $catname =~ /spam/i );
						
			# Is the existing source number lower than me?
			next if ( $source < $opt_source );
			
			my $count = $from_domains{ $root };
			
			# If more than 1 person in a day has emailed this root domain, it probably should not
			# be in the spam category
			next if ( ( $count < 2 )  &&  ( ! $all ) );
			
			# If 4 or more people have mailed to this domain since time began then 
			# it probably should not be in the spam category
			next if ( ( $count < 4 )  &&  ( $all ) );
		
			# Change it if my source number allows me to
			$retcode = &UpdateCategory( $root, $ham_category, $retcode, $opt_source );

			if ( ! $retcode )
				{	$counter++;
					&lprint( "Changed $root from $catname to ham\n" );
				}
				
			my $test_domain = "www." . $root;
			&lprint( "Querying DNS for $test_domain ...\n" );
			my @ip_addresses = &URLIPAddresses( $test_domain );
			
			foreach ( @ip_addresses )
				{	next if ( ! defined $_ );
					
					my $ip = $_;
					
					# Change it if my source number allows me to
					$retcode = &UpdateCategory( $root, $ham_category, 0 + 3, $opt_source );
					
					if ( ! $retcode )
						{	$ip_counter++;
							&lprint( "Changed $ip to ham\n" );
						}
				}
		}
	
	&lprint( "Found and corrected $counter overblocked spam root domains using the auto white list\n" ) if ( $counter );
	&lprint( "Found no overblocked spam root domains using the auto white list\n" ) if ( ! $counter );
	
	&lprint( "Found and corrected $ip_counter overblocked spam root IP addresses using the auto white list\n" ) if ( $ip_counter );
	&lprint( "Found no overblocked spam root IP addresses using the auto white list\n" ) if ( ! $ip_counter );
	
	&SetAutowhiteCheckTime( $last_time );
	
	return( 1 );
}



################################################################################
#
sub GetAutowhiteCheckTime()
#
# Return the last time I ran the checked the auto white list
#
################################################################################
{	
	my $key;
	my $type;
	my $data;

	#  Open the main key
	my $access = &OueryOSRegistryAccess( KEY_READ );
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, $access, $key );

	return( undef ) if ( ! $ok );
	
	$ok = &RegQueryValueEx( $key, "Last Autowhite Check", [], $type, $data, [] );
	$data = undef if ( ! $ok );
	 
	&RegCloseKey( $key );
	
	return( $data );
}



################################################################################
#
sub SetAutowhiteCheckTime( $ )
#
# Set the last time I checked the autowhite list
#
################################################################################
{	my $last_time = shift;
	
	return( undef ) if ( ! defined $last_time );
	
	my $key;

	#  Open the main key
	my $access = &OueryOSRegistryAccess( KEY_ALL_ACCESS );
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, $access, $key );

	return( undef ) if ( ! $ok );
	
	$ok = &RegSetValueEx( $key, "Last Autowhite Check", 0, REG_SZ, $last_time );
	 
	&RegCloseKey( $key );
		
	return( $ok );
}



################################################################################
# 
sub SPFAnalyze( $$ )
#
#  Using Sender Policy Framework, analyze the mail
#
################################################################################
{   my $all			= shift;
	my $spam_only	= shift;
	
use Sys::Hostname::Long;

	$hostname = hostname_long();
	return( undef ) if ( ! defined $hostname );

	&SPFAnalyzeSpam( $all, $hostname );
	
	&SPFAnalyzeHam( $all, $hostname ) if ( ! $spam_only );
	
	return( 1 );
}



################################################################################
# 
sub SPFAnalyzeHam( $$ )
#
#  Using Sender Policy Framework, analyze the ham mail from the last day to see if
#  I made any mistakes that SPF can detect
#
################################################################################
{   my $all			= shift;
	my $hostname	= shift;
	
use Content::SPFTest;
	
	lprint "Analyzing the last day\'s ham email using Sender Policy Framework (SPF) ... \n" if ( ! $all );
	lprint "Analyzing all the ham email using Sender Policy Framework (SPF) ... \n" if ( $all );

    # Figure out 1 day ago in SQL time format
	my $old_time = time() - ( 24 * 60 * 60 );
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );

	$year = 1900 + $year;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );

	my %spf_data;
	
	
    # Get ham from today
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $str = "SELECT ExternalIpAddress, EmailFrom FROM SpamMailBlocker WITH(NOLOCK) WHERE Status like \'OK%\' AND [Time] > \'$datestr\'";
	$str = "SELECT ExternalIpAddress, EmailFrom FROM SpamMailBlocker WITH(NOLOCK) WHERE Status like \'OK%\'" if ( $all );	

    my $sth = $dbhStats->prepare( $str );
    $sth->execute();


 	my $total = 0 + 0;
    while ( ( ! $dbhStats->err )  &&  (  my ( $ipAddress, $emailFrom ) = $sth->fetchrow_array() ) )
		{	&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			next if ( ! defined $ipAddress );
			my $str_ipaddress = &IPToString( $ipAddress );
			
			next if ( $str_ipaddress eq "0.0.0.0" );
			
			$emailFrom = &CleanEmail( $emailFrom );
			next if ( ! defined $emailFrom );
			
			$emailFrom = lc( $emailFrom );
			
			# Is it to one of the special email addresses?
			my $special;
			foreach ( @special_addresses )
				{	$special = 1 if ( $_ eq $emailFrom );
				}
			next if ( $special );
			
			my ( $user, $domain ) = split /\@/, $emailFrom, 2;
			next if ( ! defined $domain );
			
			$domain = &CleanUrl( lc( $domain ) );
			next if ( ! defined $domain );
			
			# Keep a record for each unique domain and ip address combination
			my $key = "$domain\t$str_ipaddress";
			$spf_data{ $key } = "$str_ipaddress\t$emailFrom";
			
			$total++;
		}

	&SqlErrorHandler( $dbhStats );	
	$sth->finish();
	
	lprint "Found $total ham email and IP address pairs to check\n";
	
	my $counter = 0 + 0;
	my $unique  = 0 + 0;
	while ( my ( $key, $value ) = each( %spf_data ) )
		{	my ( $str_ipaddress, $emailFrom ) = split /\t/, $value;
			next if ( ! defined $str_ipaddress );
			next if ( ! defined $emailFrom );

			$unique++;
			
			my $result = &SPFTest( $emailFrom, $str_ipaddress, $hostname, $opt_debug );  #  This should return a +1 if it is a forged email_from

			if ( $result == 1 )
				{	my $changed = &ChangeDatabaseIPAddress( $str_ipaddress, 1 );
					if ( $changed )
						{	my ( $user, $domain ) = split /\@/, $emailFrom, 2;
							lprint "$unique\: Set $str_ipaddress to spam because email $emailFrom failed the SPF test\n";
							&CategorySaveDomainReason( $str_ipaddress, "spam", "This IP address failed the SPF test for an email from $emailFrom" );
							$counter++;
						}
				}			
			}
	
	
	lprint "SPF tested $unique email and IP address pairs\n";
	lprint "Set $counter IP addresses to spam\n";
	
	
	return( 1 );
}



# This is the list of domain names that will be checked to see if their IP addresses have crept into the spam category
my @notspamip_list = (
'aol.com',
'msn.com',
'gmail.com',
'hotmail.com',
'yahoo.com',
'inbox.com',
'lycos.com',
'rr.com',
'.rr.com',
'sbcglobal.net',
'charter.net',
'earthlink.net',
'ev1.net',
'prodigy.net',
'juno.com',
'cox.net',
'verizon.net',
'covad.com',
'excite.com',
'microsoft.com',
'netscape.com',
'att.com',
'btinternet.com',
'btconnect.com',
'gtuk.com',
'talk21.com',
'lightspeedsystems.com'
);


				   
################################################################################
# 
sub SPFAnalyzeSpam( $$ )
#
#  Using Sender Policy Framework, analyze the ham mail from the last day to see if
#  I made any mistakes that SPF can detect
#
################################################################################
{   my $all			= shift;
	my $hostname	= shift;
	
use Content::SPFTest;
	
	lprint "Analyzing the last day\'s spam email using Sender Policy Framework (SPF) ... \n" if ( ! $all );
	lprint "Analyzing all the spam email using Sender Policy Framework (SPF) ... \n" if ( $all );

    # Figure out 1 day ago in SQL time format
	my $old_time = time() - ( 24 * 60 * 60 );
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );

	$year = 1900 + $year;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );

	my %spf_data;
	
	
    # Get ham from today
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $str = "SELECT ExternalIpAddress, EmailFrom FROM SpamMailBlocker WITH(NOLOCK) WHERE Status = \'Spam (Content DB IP)\' AND [Time] > \'$datestr\'";
	$str = "SELECT ExternalIpAddress, EmailFrom FROM SpamMailBlocker WITH(NOLOCK) WHERE Status = \'Spam (Content DB IP)\'" if ( $all );	

    my $sth = $dbhStats->prepare( $str );
    $sth->execute();


	my $counter = 0 + 0;
 	my $total = 0 + 0;
    while ( ( ! $dbhStats->err )  &&  (  my ( $ipAddress, $emailFrom ) = $sth->fetchrow_array() ) )
		{	&SqlSleep() if ( ! $opt_no_sql_timeout );
			
			next if ( ! defined $ipAddress );
			my $str_ipaddress = &IPToString( $ipAddress );
			
			next if ( $str_ipaddress eq "0.0.0.0" );
			
			$counter++;
			$emailFrom = &CleanEmail( $emailFrom );
			next if ( ! defined $emailFrom );
			
			$emailFrom = lc( $emailFrom );

			my ( $user, $domain ) = split /\@/, $emailFrom, 2;
			next if ( ! defined $domain );

			$domain = &CleanUrl( lc( $domain ) );
			next if ( ! defined $domain );
			
			# Is it one of the not spam domains?
			my $notspam;
			foreach ( @notspamip_list )
				{	my $notspam_domain = $_;
					next if ( ! defined $notspam_domain );
					
					$notspam = 1 if ( $notspam_domain eq $domain );
					
					# Am I trying to match a domain like bak.rr.com to ".rr.com"?
					next if ( ! ( $notspam_domain =~ m/^\./ ) );
					
					my $quoted = quotemeta( $notspam_domain );
					$notspam = 1 if ( $domain =~ m/$quoted/ );
				}
			
			
			# Is it an education domain?
			$notspam = 1 if ( $domain =~ m/\.k12\./ );
			$notspam = 1 if ( $domain =~ m/\.gov$/ );
			$notspam = 1 if ( $domain =~ m/\.mil$/ );
			$notspam = 1 if ( $domain =~ m/\.edu$/ );
			$notspam = 1 if ( $domain =~ m/\.edu\./ );
			$notspam = 1 if ( $domain =~ m/\.gov\./ );
							 
			next if ( ! $notspam );
			
			# Keep a record for each unique domain and ip address combination
			my $key = "$domain\t$str_ipaddress";
			$spf_data{ $key } = "$str_ipaddress\t$emailFrom";
			
			$total++;
		}

	&SqlErrorHandler( $dbhStats );	
	$sth->finish();
	
	lprint "Found $total spam email and IP address pairs to check out of $counter total\n";
	
	$counter = 0 + 0;
	my $unique  = 0 + 0;
	while ( my ( $key, $value ) = each( %spf_data ) )
		{	my ( $str_ipaddress, $emailFrom ) = split /\t/, $value;
			next if ( ! defined $str_ipaddress );
			next if ( ! defined $emailFrom );

			$unique++;
			
			my $result = &SPFTest( $emailFrom, $str_ipaddress, $hostname, $opt_debug );  #  This should return a +1 if it is a forged email_from

			# Did it pass the SPF test?
			if ( $result == -1 )
				{	my $changed = &ChangeDatabaseIPAddress( $str_ipaddress, undef );
					if ( $changed )
						{	my ( $user, $domain ) = split /\@/, $emailFrom, 2;
							lprint "$unique\: Set $str_ipaddress to ham because email $emailFrom passed the SPF test\n";
							&CategorySaveDomainReason( $str_ipaddress, "ham", "This IP address passed the SPF test for an email from $emailFrom" );
							$counter++;
						}
				}			
			}
	
	
	lprint "SPF tested $unique email and IP address pairs\n";
	lprint "Set $counter IP addresses to ham\n";
		
	return( 1 );
}


  
################################################################################
#
sub ChangeDatabaseIPAddress( $$ )
#
#  Change the category of an IP address to spam or ham
#
################################################################################
{   my $ip_addr = shift;	# The IP address in text format
	my $spam    = shift;	# If true, then add to the spam category.  If undef, then add to ham
	
	return( undef ) if ( ! defined $ip_addr );
	
	return( undef ) if ( ! &IsIPAddress( $ip_addr ) );
	
	my $change_catnum;
	
	my $spam_category			= &CategoryNumber( "spam" );
	my $shopping_spam_category	= &CategoryNumber( "shopping.spam" );
	my $ham_category			= &CategoryNumber( "ham" );
	
	$change_catnum = $spam_category if ( $spam );
	$change_catnum = $ham_category if ( ! $spam );
	
	return( undef ) if ( ! $change_catnum );
	
	my $retcode = &LookupUnknown( $ip_addr, 0 );
			
			
	# If the IP address isn't in the database, just add it and return
	if ( ! $retcode )
		{	&AddNewTrans( $ip_addr, $change_catnum, 0, $opt_source );
			return( 1 );
		}
	
	
	# If it is in the database, is it set by hand, and so can't be changed?
	my ( $catnum, $source )  = &FindCategory( $ip_addr, $retcode );
	return( undef ) if ( $source < ( 0 + 3 ) );
	
	
	# Is it already set to the right thing?
	return( undef ) if ( $catnum == $change_catnum );
	
	
	# If the IP address is spam, it can also work if it is a blocked category or shopping.spam
	return( undef ) if ( ( $spam )  &&  ( &BlockedCategoryNumber( $catnum ) ) );
	return( undef ) if ( ( $spam )  &&  ( $catnum == $shopping_spam_category ) );
	
	
	# If the IP address is really ham only change it if the current category is spam or shopping.spam
	# That is, don't override a porn IP address just because they have SPF right
	return( undef ) if ( ( ! $spam )  &&  ( ( $catnum != $spam_category )  &&  ( $catnum != $shopping_spam_category ) ) );
	
	
	my $ipaddress = &StringToIP( $ip_addr );
	return( undef ) if ( ! $ipaddress );

	$dbh = &SqlErrorCheckHandle( $dbh );
    my $sth = $dbh->prepare( "UPDATE IpmContentIpAddress SET CategoryNumber = $change_catnum, TransactionTime = getutcdate() WHERE IpAddress = ?" );
    $sth->bind_param( 1, $ipaddress,  DBI::SQL_BINARY );
    $sth->execute();
		
	&SqlErrorHandler( $dbh );
	$sth->finish();
		
	return( 1 );
}
	  


my %domain_ip;	# My hash of domains that I have already looked up the IP address for
################################################################################
# 
sub URLIPAddresses( $ )
#
#  Given a URL, return all the IP addresses in DNS for it
#
################################################################################
{	my $url = shift;
	
	my @addresses;
	
	return( @addresses ) if ( ! $url );
	
	my ( $domain, $url_ext ) = split /\//, $url, 2;

	return( @addresses ) if ( ! $domain );
	
	# Is the domain an IP address itself?
	return( @addresses ) if ( &IsIPAddress( $domain ) );
	
	# Have I already looked up this domain?
	return( @addresses ) if ( $domain_ip{ $domain } );
	
	use Net::DNS;
	my $res = Net::DNS::Resolver->new(udp_timeout => 8);
	
		  
	my $query = $res->send( $domain ); 
	return( @addresses ) if ( ! $query );
	
	foreach my $rr ( $query->answer ) 
		{	next unless $rr->type eq "A";
			my $ip = $rr->address;
			
			# Make sure it is a good IP address
			next if ( ! &IsValidIP( $ip ) );
			push @addresses, $ip;
		}

	# Keep a hash of the domains that I have already looked up
	$domain_ip{ $domain } = 1;
	
	return( @addresses );
}



################################################################################
sub Integer( $ )	# Round off to an integer value
################################################################################
{	my $val = shift;
	
	$val =~ s/\,/\./g;	# Get rid of commas
	my $int = 0.5 + $val;
	my $rnd = sprintf( "%.0f", 0 + $int );
	$rnd =~ s/\,/\./g;	# Get rid of commas
	$rnd = 0 + $rnd;
	
	return( $rnd );
}



################################################################################
# 
sub HexToInt( $ )
#
#  Convert a registry hex value to a decimal value
#
################################################################################
{  my $hexstring = shift;

   my $dec = unpack( "CH", $hexstring );
 
   return( $dec );
}



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     bprint( @_ );
}



################################################################################
#
sub Usage()
#
################################################################################
{
    my $me = "SpamReview";

    bprint <<".";
Usage: $me [OPTION(s)] [filename|directory]

The SpamReview utility has 2 modes - file mode or directory mode.

File mode: If the utility is passed a single filename on the command line, it 
will analyze the file for message clues that can be used for defining mail as
spam or ham.

Directory mode: If the utility is passed nothing, or a directory name, it will
analyze all the files in the directory and import the new URLs into the SQL
database.  It assumes that the files it is looking at are spam files if they 
begin with an 's' and end with the extension '.txt'.  The default directory in 
directory mode is the previous day's directory under the the Mail Archive 
directory.

Unless it is run in debug mode, the utility will clean up all of it's working 
files and directories.

There are a couple of command line options:

  -a, --allfiles        analyze all files as spam, not just s*.txt
  -c, --category        create category subdirectories of known urls
  -d, --directory       set the default directory to work in
  -e, --export EMAILTO  to export the newest spam summary data for EMAILTO
  -h, --help            display this help and exit
  -i, --incremental     send just the new spam summary emails 
                        (this is spam received since the last summary email)
  -k, --kkk             Do a DNS lookup of known URLs  
  -m, --matt emailto    send a spam summary even if there is no spam
  -n, --nosummary       do not send any spam summary emails
  -p, --policy          Test the email with SPF
  -r, --review          set the options for daily review mode
  -s, --summary EMAILTO send a spam summary to the EMAILTO address
  -u, --urls            include known and unknown urls in output files
  -x, --xdebug          show debugging messages
  -v, --verbose         display all the found URLs
-
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
    my $me = "SpamReview";

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
