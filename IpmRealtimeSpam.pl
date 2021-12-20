################################################################################
#!perl -w
#
# Rob McCarthy's version of realtime grading spam perl - IpmRealTimeSpam.pl
#
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Pipe;
use Win32::Process;
use MIME::Base64;
use MIME::QuotedPrint;
use File::Copy;
use File::DosGlob;
use Cwd;
use Time::Local;
use Benchmark;
use HTML::Entities;
use Sys::Hostname::Long;


use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Content::ScanFile;
use Content::Mail;
use Content::Process;
use Content::SPFTest;
use Content::SQLVirusUpdate;



#  Global Options
my $opt_filename;								# True if we are reading from a command line
my $opt_version;								# True if we just want to display the version
my $_version = "2.0.0";							# File version number
my $opt_benchmark;								# True if I should benchmark the speed
my %benchtime;									# Hash of benchmark times = key is the name of the benchmark, value is the time
my $opt_help;									# True if we just want to display help
my $opt_summary; 								# Show summary information only
my $opt_copy; 			      					# If set to a directory name, copy spam to that directory
my $opt_debug; 									# True if I should write to a debug log file
my $opt_show_clues;								# True if I should show the clues I am using to figure out if spam
my $opt_working_files;							# True if I should leave the working files without deleting them
my $opt_wizard;									# True if I shouldn't display headers and footers
my $opt_logging = 1;							# True if I should write to a regular log file
my $opt_append_log;								# True if I should append to the log and debug log
my $opt_installed_virus;						# True if I should just display the installed virus scanners, and then exit
my $opt_unlink;									# True if I should unlink (delete) virus infected files
my $opt_spam_dir;								# If set, this is the name of the directory to move spam to
my $opt_remote_database;						# If True then use the remote Content and Statistics databases


# Use options
my $use_bayesian			= 1;				# True if I should use Bayesian statistics
my $use_autowhitelist		= 1;				# True if I should use Auto White List
my $use_autoblacklist;							# True if I should use Auto Black List
my $use_greylist			= 1;				# True if I should use Grey List
my $use_challenge;								# True if I should should use a challenge email
my $use_contentdb			= 1;				# True if I should use Content Database
my $use_proxy				= 1;				# True if I should  do a proxy test on an external IP addresses and unknown URLs
my $use_proxy_dns			= 1;				# True if I should use IpmProxyTest to get IP addresses and test the relationship between domains
my $use_adult_subjects		= 1;				# True if I should block subject lines with Adult subjects
my $use_spam_patterns		= 1;				# True if I should use the spam patterns file
my $use_spf;									# True if I use use SPF to validate the email from address
my $use_virus				= 1;				# True if I should use virus scanning
my $use_user_preferences	= 1;				# True if I should use the user preferences list
my $use_valid_email_to;							# True if I should use the valid email to table
my $use_valid_email_table;						# True if I should use the Content database table "ValidEmailAddresses" to verify to: addresses
my $use_network_reputation	= 1;				# True if I should use network reputation to block spam


# Misc options
my $log_filename = "IpmRealtimeSpam.log";		# The name of the log file to use
my $block_unknown_urls;							# True if I should block emails with unknown urls in them
my $virus_example = 1;							# True if I should make a copy of the virus infected file for the examples directory
my $block_scan_errors;							# True if I should block an email if I have an error virus scanning the file
my $virus_lightspeed_email = "virus\@lightspeedsystems.com";	# This is the email address to mail new virus infected emails to
my $virus_forward = 1;							# True if I should forward virus infected emails to Lightspeed
my $check_forged = 1;							# True if I should check to see if the from address looks like it is forged
my $block_large_messages;						# If non-zero, then block any messages larger than this value in bytes
my $maximum_attachments;						# If non-zero, then block any messages with more than this number of attachments
my $create_clue_file;							# If non-zero, then create a clue file for each spam message


# Special email addresses that will always go through
# These are the addresses that various Lightspeed programs use to send email messages
my @special_addresses = ( "notspam\@lightspeedsystems.com", 
						 "spam\@lightspeedsystems.com", 
						 "blacklist\@lightspeedsystems.com", 
						 "emarketing\@lightspeedsystems.com", 
						 "blockedcontent\@lightspeedsystems.com",
						 "content\@lightspeedsystems.com",
						 "virus\@lightspeedsystems.com",
						 "support\@lightspeedsystems.com",
						 "unknown\@lightspeedsystems.com",
						 "database\@lightspeedsystems.com",
#						 "sales\@lightspeedsystems.com",
						 "tipsandtricks\@lightspeedsystems.com",
						 "\"spam mail summary\""
						 );  


# This is the list of bad file names
my @bad_list = qw( message.zip patch.exe installation1.exe wicked_scr.scr
					eortwkg.exe aijts.exe hctp.scr fumd.exe install2.exe
					bdkatwye.exe ddnjv.exe q549937.exe );

# This is the list of bad extensions of file names	
my $bad_extensions = ".pif.wbt.inf.ini.lnk.scr.vba.vbe.vbs.shs.bat.cmd.dbg.hta.bhx.uue.hqx.b64.cpl.";
			

# Common domains that I don't need to look up ever - quotemeta style
my @common_domains =
(	'\.w3\.org$',
	'^w3\.org$',
	
	'\.microsoft\.com$',
	'^microsoft\.com$',
	
	'^yimg\.com$',
	'\.yimg\.com$',
	
	'^nypost\.com$',
	'\.nypost\.com$',
	
	'^ebay\.com$',
	'\.ebay\.com$',
 
	'^nytimes\.com$',
	'\.nytimes\.com$',
 
	'^akamai\.net$',
	'\.akamai\.net$',
 
	'^ebaystatic\.com$',
	'\.ebaystatic\.com$',
 
	'^yahoo\.com$',
	'\.yahoo\.com$'
);


my %clues;										# The list of clues about the current message, indexed by clue type
my $max_bytes = 0 + 1000000;					# The maximum number of bytes to read in a spam file before giving up
my $max_lines = 0 + 15000;						# The maximum number of lines in a spam file to read before giving up
my $blank_compare = "<blank>";					# The blank string value to compare is spam patterns
my $opt_delete_spam;							# If True then delete any spam files I find
my $opt_delete_ham;								# If True then delete any ham files I find


#  Global variables
my $pipe_check = '\\\\.\\pipe\\SpamCheck';		# The spam pipe name for file names to check
my $pipe_result = '\\\\.\\pipe\\SpamResult';	# The spam pipe name for results from the check
my $PipeCheck;									# The spam pipe object to get the file name to check
my $PipeResult;									# The spam pipe object to return the results

my $dbh;             							# My database handle to the Content Database
my $dbhStat;             						# My database handle to the Statistics Database

my %summary;									# Totals for all the spam reasons
my @data;   									# The data from the spam file - limited to 500 lines - global so that it is easy to get to

my %grey_list;									# My list of grey list addresses - held for about 1 hour
my $grey_next_time;								# This is the next time I'm going to do grey list processing

my $challenge_email_from;						# The email address to issue email challenges from
my $spam_user_preferences_exists;				# True if the spam user preferences tables exists
my $challenge_body;								# The message body of a challenge email
my $challenge_id = "LSMSGCV";					# This is the secret string that I compare to see if an email is a challenge or a challenge response
my $challenge_subject = "$challenge_id: Your message to EMAIL_TO was blocked as spam - please reply to forward it";	# This is the subject line of a spam challenge message
my $challenge_thank_you;						# This is the message body of the thank you email
my $challenge_send_thank_you = 1;				# If True, then send a thank you message if the challenge is passed

my $spam_patterns_next_time;					# This is the next time I'm going to check for new spam patterns
my @spam_patterns;								# The array of spam patterns
my %spam_pattern_names;							# The names of the spam patterns - index is name, value is the row number in the spam_pattern array
my @virus_patterns;								# The array of virus patterns
my %virus_pattern_names;						# The names of the virus patterns - index is name, value is the row number in the virus_pattern array
my $spam_categories_next_time;					# This is the next time I'm going to check for the list of categories

my @adult_subjects;								# List of adult subjects
my @wildcard_email_to;							# List of domains that I accept any valid email to for
my $last_valid_email_to;						# The last email to: that I just looked up

my $proxy_handle;								# Handle to the proxy test file
my $proxy_file = "IpmProxyTest.urls";			# The name of the proxy test file
my $hostname;									# My hostname - used in SPFTest


#  Bayesian global parameters
my $min_frequency = 0 + 20;          			# Number of times a token needs to be used before it is considered significant
my $expected_good_to_bad = 0 + 1.15;           	# This is the ratio of the expected number of non spams to spams in a normal day of email
my $opt_dir;                                    # Directory of the Spam Tokens file
my $opt_sensitivity;                            # If not set, the expected good to bad ratio will be used
my $opt_show_most_interesting;                	# Show the most interesting picks
my $opt_most_interesting_min = 0 + 10;     		# Minimum required most interesting
my $opt_most_interesting_max = 0 + 50;    		# Maximum allowed most interesting
my $opt_mindev = 0 + 0.1;                       # The minimum deviation from 0.5 to make the token interesting enough
my $opt_unknown_token = 0 + 0.41;          		# The value to use for a completely unknown token
my $opt_spam_threshold = 0 + 0.80;	      		# What percentage sure that it's spam
my $pure_spam;			      					# Probability of a token that only occurs in a spam file
my $pure_notspam;	        	      			# Probability of a token that only occurs in a non spam file
my $corpus_file;                                # The full file name of the corpus file I used
my $opt_offset = 0 + 0.1;                       # The offset from 1 and 0 for pure spam and pure not spam
my %token_spam_rating;							# The spam rating of all the known tokens
my $current_file;								# The name of the current file I am analyzing


#  Virus checking parameters
my $opt_no_virus;								# If true then do no virus checking at all
my $opt_virus;									# True if I should only do virus checking
my $opt_no_lightspeed_virus;					# If True then don't use Lightspeed virus scanner
my $opt_lightspeed_virus_update = 1;			# If True the update the virus signatures every hour
my $virus_installed;							# True if the virus checking command is installed
my $virus_signatures_next_time;					# This is the next time I'm going to check for new virus signatures
my $lightspeed_virus_installed;					# True if the Lightspeed virus scanner is installed
my $virus_signature_count;						# The count of active virus signatures loaded for the Lightspeed virus scanner
my $quarantine;									# Directory to quarantine virus infected to
my $virus_temp_file = "IPMVIRUSTEMP.TXT";		# Temp file name to use for the virus report
my $tmp_dir;									# Tmp directory to unpack files to
my $opt_tmp_dir;								# If set, use this directory for unpacking files, and don't delete the files after unpacking
my $opt_password_protected_zip = 1;				# If set then block emails with password protected zip files


# Network Reputation parameters
my @network_reputation;							# The network reputation table in memory


# These are the arrays of virus scan control variables
my @virus_name;									# The name(s) of the virus scanning product
my @virus_path;									# The path(s) to the command line virus scanning program
my @virus_cmd;									# The command(s) to execute	
my @virus_args;									# The virus command line arguments
my @virus_found;								# The text in the report file that indicates a found virus
my @virus_suspected;							# The text in the report file that indicates a suspected virus
my @virus_system;								# 0 if virus scan executed by Win32 Process, 1 if execute by system command
my $unlink_count = 0 + 0;						# The count of virus infected email message that were deleted



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
		"0|remote"			=> \$opt_remote_database,
        "a|aggressive=s"	=> \$opt_sensitivity,
		"b|benchmark"		=> \$opt_benchmark,
        "c|copy=s"			=> \$opt_copy,
        "d|directory=s"		=> \$opt_dir,
        "e|cluefile"		=> \$create_clue_file,
        "f|nolsvirus"		=> \$opt_no_lightspeed_virus,
        "g|novirus"			=> \$opt_no_virus,
        "h|help"			=> \$opt_help,
        "i|interest=s"		=> \$opt_most_interesting_max,
        "j|jjj=s"			=> \$opt_spam_dir,
        "k|kkk"				=> sub { $opt_lightspeed_virus_update = undef; },
        "l|logging"			=> \$opt_logging,
        "m|minimum=s"		=> \$min_frequency,
        "n|nopipe"			=> \$opt_filename,
        "o|offset=s"		=> \$opt_offset,
        "p|policy"			=> \$use_spf,
        "q|quarantine=s"	=> \$quarantine,
        "r|ratio=s"			=> \$expected_good_to_bad,
        "s|summary"			=> \$opt_summary,
		"t|tmp=s"			=> \$opt_tmp_dir,	
        "u|unlink"			=> \$opt_unlink,
        "v|virus"			=> \$opt_virus,
        "w|wizard"			=> \$opt_wizard,
        "x|xxx"				=> \$opt_debug,
        "y|yyy"				=> \$opt_show_clues,
        "z|zzz"				=> \$opt_installed_virus
       );
	   
	   
	&StdHeader( "IpmRealTimeSpam" ) if ( ! $opt_wizard );


	my $start = new Benchmark if ( $opt_benchmark );


	# Don't delete working files if in debug mode
	$opt_working_files = 1 if ( $opt_debug );


    #  Figure out what directory to use
    $opt_dir = &SoftwareDirectory() if ( !$opt_dir );
	$tmp_dir = &TmpDirectory();
	$tmp_dir = $opt_tmp_dir if ( $opt_tmp_dir );

	my $cwd = getcwd();
	$cwd =~ s#\/#\\#gm;
	if ( ( $tmp_dir )  &&  ( $tmp_dir eq '.' ) )
		{	$tmp_dir = $cwd;
		}
	
	# Put the log file in the current directory if keep tmp files
	$log_filename = "$cwd\\IpmRealtimeSpam.log" if ( $opt_tmp_dir );

	&FatalError( "Can not find tmp directory $tmp_dir ...\n" ) if ( ! -d $tmp_dir );


	# Don't delete working files if unpacking to a different tmp dir
	$opt_working_files = 1 if ( $opt_tmp_dir );
	
	
	$opt_append_log = 1 if ( $opt_debug );
	&TrapErrors() if ( ! $opt_filename );
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	

    #  Read the configured properties out of the registry
    &GetProperties();
	
	
	# Do any necessary logging
	$opt_logging = 1 if ( $opt_debug );	
	
	
	&SetLogFilename( $log_filename, $opt_append_log );
	
	
	# Set everyting if command line executed
	if ( $opt_filename )
		{	$use_proxy		= undef;
			$use_proxy_dns	= undef;
		}
	

	# Check the quarantine directory
	if ( $quarantine )
	  {  &oprint( "$quarantine is not a valid directory name for quarantining\n" ) if ( ! -d $quarantine ); 
		 &oprint( "Quarantining virus infected files to $quarantine\n" );
	  }
	  
    if ( $opt_sensitivity )
      {   &Usage() if ( $opt_sensitivity < 0  ||  $opt_sensitivity > 100 );
      }


    &Usage() if ( $expected_good_to_bad < 0.75  ||  $expected_good_to_bad > 1.55 );
    &Usage() if ( $opt_spam_threshold < 0.01  ||  $opt_spam_threshold > 0.99 );
    &Usage() if ( $opt_most_interesting_min < 5  ||  $opt_most_interesting_min > 25 );
    &Usage() if ( $opt_most_interesting_max < $opt_most_interesting_min  ||  $opt_most_interesting_max > 1000 );

    &oprint( "Virus checking only\n" ) if ( $opt_virus );


    # Don't do a summary if getting file name from the pipe
    $opt_summary = undef if ( !$opt_filename );

	if ( ! $opt_remote_database )
		{	$dbh = &ConnectServer() or &FatalError( "Unable to connect to Content SQL database\n" );
			$dbhStat = &ConnectStatistics() or &FatalError( "Unable to connect to Statistics SQL database\n" );
		}
	else
		{	( $dbh, $dbhStat ) = &RemoteDatabases();
print "Run ODBCAD32 and add the remote SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.\n" if ( ! $dbh );
print "Run ODBCAD32 and add the remote SQL Server as a System DSN named
\'RemoteStatistics\' with default database \'IpmStatistics\'.\n" if ( ! $dbhStat );
exit( -1 ) if ( ( ! $dbh )  ||  ( ! $dbhStat ) );
		}
		
    &debug( "Opened databases\n" );


	# Can I use challenge emails to block spam?
	$use_challenge = &ChallengeEmailOK();
	

	# Make sure this table exists before turning on these options
	if ( ! &SqlTableExists( "SpamUserPreferences" ) )
		{	$use_user_preferences = undef;
			&oprint( "SpamUserPreferences table does not exist so turning \'Use Valid Email To\' option off ...\n" ) if ( $use_valid_email_to );
			$use_valid_email_to = undef;
			$spam_user_preferences_exists = undef;
		}
	else
		{	$spam_user_preferences_exists = 1;
		}
		
		
	# Make sure this table exists before turning the use valid email to options on
	$use_valid_email_table = undef;
	if ( ( $use_valid_email_to )  &&  ( &SqlTableExists( "ValidEmailAddresses" ) ) )
		{	$use_valid_email_table = 1;
			&oprint( "ValidEmailAddresses table exists so using it to verify TO: addresses ...\n" )
		}
	
	
	# Make sure this table exists before turning the auto blacklist option on
	if ( ( $use_autoblacklist )  &&  ( ! &SqlTableExists( "AutoBlackList" ) ) )
		{	$use_autoblacklist = undef;
			&oprint( "AutoBlackList table does not exist so turning \'Use AutoBlackList\' option off ...\n" );
		}
	

	# This must be done before trying to load the Lightspeed Virus Scanner to ensure only
	# blocked categories Virus Signatures are exported to the file...    
	&SpamCategories();


	# Check for installed virus scanners
	$virus_installed = &VirusInstalled() if ( ! $opt_no_virus );
	&oprint( "Finished checking for install virus scanners\n" );
	

	#  If all we are doing is scanning for viruses we better have a virus scanner
	if ( ( $opt_virus )  &&  ( !$virus_installed ) )
	  {  &FatalError( "No virus scanners found\n" );	  
	  }
	  
	if ( $virus_installed )
		{   my $counter = 0;
			
			&oprint( "Installed Virus Scanners ...\n" );
			
			foreach ( @virus_name )
				{	&oprint( "Name: $virus_name[ $counter ]\n" );
					&oprint( "Path: $virus_path[ $counter ]\n" );
					$counter++;
				}
				
			&oprint( "Loaded $virus_signature_count Lightspeed virus signatures\n" ) if ( $virus_signature_count );
		}
	else  
		{	&oprint( "No virus scanners installed\n" );
		}

	
	# Is this all I was supposed to do?		
	if ( $opt_installed_virus )	
		{	$dbh->disconnect if ( $dbh );
			$dbhStat->disconnect if ( $dbhStat );

			# Clean up the scan.dll
			&ScanUnloadSignatures();
			
			exit( 0 );
		}

		
	&LoadSpamPatterns() if ( $use_spam_patterns );
	
	&LoadWildcardEmailTo() if ( $use_valid_email_to );
	
	&LoadAdultSubjects() if ( ( $use_adult_subjects )  &&  ( ! $opt_virus ) );

	
	# Read in the network reputation file if it exists
	&ReadNetworkReputation() if ( $use_network_reputation );


    #  Calculate the pure spam and pure not spam values
    if ( $opt_offset )
		{	&Usage() if ( $opt_offset < 0.01  ||  $opt_offset > 0.49 );
			$pure_spam = 1 - $opt_offset;
			$pure_notspam = $opt_offset;
		}


    #  If calculate the opt_sensitivity if not already set
    if ( !$opt_sensitivity )
      {   $opt_sensitivity = 100 * ( ( 1.55 - $expected_good_to_bad ) / .8 );
      }
    else  #  If the sensitivity was set, calc the expected good to bad ratio
      {  $expected_good_to_bad = .75 + ( ( ( 100 - $opt_sensitivity ) * .8 ) / 100 );
      }


    &LoadSpamTokens();


 	#  Show the spam options
	if ( ! $opt_virus )
		{	&oprint( "Program options:\n" );
			
			&oprint( "Summarize results\n" ) if ( $opt_summary );
			
			if ( $use_bayesian )
				{	&oprint( "Use Bayesian statistics\n" );
 					&oprint( "Spam tokens file: $corpus_file\n" );
					&oprint( "Number of spam tokens loaded: ", scalar keys %token_spam_rating, "\n" );
					&oprint( "Bayesian aggression = $opt_sensitivity\n" );
				}
				
			&oprint( "Use grey listing\n" ) if ( $use_greylist );
			&oprint( "Use email address challenge\n" ) if ( $use_challenge );
			&oprint( "Use automatic white list\n" ) if ( $use_autowhitelist );
			&oprint( "Use automatic black list\n" ) if ( $use_autoblacklist );
			&oprint( "Block mail from blocked content database categories\n" ) if ( $use_contentdb );
			&oprint( "Block mail from mail servers that are proxies\n" ) if ( $use_proxy );
			&oprint( "Use DNS to check unknown URLs to block spam\n" ) if ( $use_proxy_dns );
			&oprint( "Do not proxy test mail servers IP addresses\n" ) if ( ! $use_proxy );
			&oprint( "Use spam mail patterns\n" ) if ( $use_spam_patterns );
			&oprint( "Use Sender Policy Framework (SPF) to validate email from addresses\n" ) if ( $use_spf );
			&oprint( "Block virus infected mail\n" ) if ( $use_virus );
			&oprint( "Do not block virus infected mail\n" ) if ( ! $use_virus );
			&oprint( "Do not use Lightspeed virus scanner\n" ) if ( $opt_no_lightspeed_virus );
			&oprint( "Do not do hourly updates of the Lightspeed virus scanner\n" ) if ( ! $opt_lightspeed_virus_update );
			&oprint( "Use User Preferences\n" ) if ( $use_user_preferences );
			&oprint( "Check Email TO: addresses in the User Preferences table\n" ) if ( ( $use_valid_email_to )  &&  ( ! $use_valid_email_table ) );
			&oprint( "Check Email TO: addresses in the ValidEmailAddresses table\n" ) if ( ( $use_valid_email_table )  &&  ( $use_valid_email_table ) );
			&oprint( "Block messages with scan errors\n" ) if ( $block_scan_errors );
			&oprint( "Create a clue file for each message\n" ) if ( $create_clue_file );
			&oprint( "Move spam messages to directory $opt_spam_dir\n" ) if ( $opt_spam_dir );
			&oprint( "Unlink (delete) virus infected files\n" ) if ( $opt_unlink );
			&oprint( "Check for adult subjects in alternate character sets\n" ) if ( $use_adult_subjects );
			&oprint( "Blocking all messages larger than $block_large_messages bytes\n" ) if ( $block_large_messages );
			&oprint( "Blocking all messages with more than $maximum_attachments attachments\n" ) if ( $maximum_attachments );
			&oprint( "Unpack attachments to directory $opt_tmp_dir\n" ) if ( $opt_tmp_dir );
			&oprint( "Move spam files to directory $opt_copy\n" ) if ( $opt_copy );
			&oprint( "Use network reputation\n" ) if ( $use_network_reputation );
			&oprint( "Do not use network reputation\n" ) if ( ! $use_network_reputation );
			
			
			if ( $opt_filename )
				{	&oprint( "Executed from command line:\n" );
					&oprint( "\tCan not check RBL servers\n" );
					&oprint( "\tCan not check IP address resolution\n" );
					&oprint( "\tCan not do grey list processing\n" );
				}
				
			if ( $opt_logging )
				{	$log_filename = &GetLogFilename();
					&oprint( "Log events to $log_filename\n" );
				}
		}
		
		
	if ( $use_spf )
		{	$hostname = hostname_long();
			$hostname = "cleanmail.lightspeedsystems.com" if ( ! defined $hostname );
			&oprint( "Using hostname $hostname for SPF tests\n" );
		}

		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Program startup time" );
			$start = new Benchmark;
		}
		
		
    if ( !$opt_filename )
		{	&debug( "Opening pipes\n" );
		  
			$PipeResult = new Win32::Pipe( $pipe_result, -1 );
			if ( !$PipeResult )
				{   &FatalError( "Can not open Win32 pipe $pipe_result\n" ); 
				}
		   
			&debug( "Opened pipe $pipe_result\n");
		 
			$PipeCheck = new Win32::Pipe( $pipe_check, -1 );
			if ( !$PipeCheck )
				{   &FatalError( "Can not open Win32 pipe $pipe_check\n" ); 
				}
        
			&debug( "Opened pipe $pipe_check\n");
			
			&oprint( "Opened communication pipes ok\n" );
		}


	# Start up my proxy tester if possible
	if ( ( $use_proxy )  ||  ( $use_proxy_dns ) )
		{	my $ok = &StartProxyTest();
			$use_proxy		= undef if ( ! $ok );
			$use_proxy_dns	= undef if ( ! $ok );
		}
		
		
    my $spam_counter = 0;
    my $file_counter = 0;

	if ( ! $opt_filename )
		{	my $done;

 			# Check to see if I missed any Grey List emails
			&CheckGreyList();

			&oprint( "Ready to start processing files ...\n" );
		
			while ( ! $done )	# Main loop - pipe read and timer processing
				{	my ( $filename, $mode ) = &PipeRead();

					if ( ! defined $filename )
						{	$done = -1;  
						}
					else
						{   $file_counter++;
							$spam_counter += &AnalyzeFile( $filename, undef, undef ) if ( $mode eq "A" );
							$spam_counter += &VirusCheckFile( $filename ) if ( $mode eq "V" );
							$spam_counter += &AnalyzeFile( $filename, undef, 1 ) if ( $mode eq "O" );
						}
					   
					&OldGreyList();
							
					&SpamCategories();

					&LoadSpamPatterns() if ( $use_spam_patterns );
					
					&LoadVirusSignatures() if ( $use_virus );
					
					&CheckDatabases( undef );
					
					&SPFCache() if ( $use_spf );
					
					&debug( "bottom of pipe read loop\n" );
				}
		}

	else #  just read the filenames from the command line
		{	my $item;

			foreach $item ( @ARGV )
				{	# Handle wildcards
					if ($item =~ /\*/ || $item =~ /\?/)
						{	$item = "*" if ( $item eq "*.* " );
						   
							# Loop through the globbed names
							my @glob_names = glob( $item );

							foreach ( @glob_names )
								{   $file_counter++;
									   
									my $file = $_;

									# Ignore my own log file
									next if ( $file =~ m/IpmRealtimeSpam\.log$/i );
									
									if ( $opt_virus )  
										{	$spam_counter += &VirusCheckFile( $file );  
										}
									else
										{	my $is_spam += &AnalyzeFile( $file, undef, undef );  
											$spam_counter++ if ( $is_spam );
											&HandleSpam( $file ) if ( $is_spam );
										}
								}
						}  #  end of handle wild cards

					# Handle single entities
					else
						{	# Analyze a directory
							if ( -d $item )
								{	# Process the directory
									opendir( DIR, $item );

									while ( my $file = readdir(DIR) )
										{	# Skip subdirectories
											next if ( -d "$item\\$file" );
											
											# Ignore my own log file
											next if ( $file =~ m/IpmRealtimeSpam\.log$/i );
									
											# Skip clue files
											next if ( $file =~ m/\.clue$/i );
											
											$file_counter++;
											
  											if ( $opt_virus )
												{	$spam_counter += &VirusCheckFile( "$item\\$file" );  
												}
											else  									
												{	my $is_spam += &AnalyzeFile( "$item\\$file", undef, undef );  
													$spam_counter++ if ( $is_spam );
													&HandleSpam( "$item\\$file" ) if ( $is_spam );
												}

										}

									closedir( DIR );
								}
							# Analyze a single file
							else
								{	$file_counter++;
									if ( $opt_virus )  
										{	$spam_counter += &VirusCheckFile( $item );  
										}
									else  									
										{	my $is_spam += &AnalyzeFile( $item, undef, undef );  
											$spam_counter++ if ( $is_spam );
											&HandleSpam( $item ) if ( $is_spam );
										}
								}
						}
				}  #  end of foreach item
		}  #end of else


    &debug( "Normal program close\n" );
	
	
	# Show the totals
	my $ham_total = $file_counter - $spam_counter;

	&oprint( "Final results - $file_counter files, $spam_counter spam, $ham_total not spam\n" );

	my @list = keys %summary;
	foreach ( @list )
		{	my $msg = $_;
			my $count = $summary{ $msg };
			print "$msg: $count files\n";
		}
   
 
     if ( !$opt_filename )
       {  $PipeCheck->Close() if ( $PipeCheck ); 
          $PipeResult->Close() if ( $PipeResult ); 
       }


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Program analyze time" );
		}
		
		
	if ( ( $use_proxy )  ||  ( $use_proxy_dns ) )
		{	&ProxyTest( "quit" );
		}
		
		
	if ( $opt_benchmark )
		{	my @keys = sort keys( %benchtime );
			
			print "\nBenchmarks\n\n";

			foreach ( @keys )
				{	my $key = $_;
					next if ( ! $_ );
					my $val = $benchtime{ $key };

					my $strtime = timestr( $val );

					print "$key: $strtime\n";
				}
		}
		
	print "Unlinked $unlink_count virus infected email messages\n" if ( $unlink_count );
	

	$dbh->disconnect if ( $dbh );
	$dbhStat->disconnect if ( $dbhStat );

	 
	# Clean up the scan.dll
	&ScanUnloadSignatures();


	&StdFooter if ( ( $opt_filename ) && ( ! $opt_wizard ) );


	exit;
}
###################    End of MAIN  ############################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $dir = &SoftwareDirectory();
	my $filename = $dir . "\\IpmRealtimeSpamErrors.log";

	# Delete the errors file if it is getting too big ...
	my $size = -s $filename;
	unlink( $filename) if ( ( $size )  &&  ( $size > 20000 ) );
	
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">>$filename" ) )
		{	&lprint( "Unable to open $filename: $!\n" );  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	&debug( "Fatal error trapping set to file $filename\n" ); 
}



################################################################################
# 
sub RemoteDatabases()
#
#  Find and connect to the remote Content database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbh, $dbhStat ) if ( ( $dbh )  &&  ( $dbhStat ) );
	
	
	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\TrafficRemote", 0, KEY_READ, $key );
	
	my $ok_stat = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\RemoteStatistics", 0, KEY_READ, $key ) if ( $ok )
	
	&RegCloseKey( $key );

	&FatalError( "Unable to connect to Remote IpmContent SQL database\n" ) if ( ! $ok );
	&FatalError( "Unable to connect to Remote IpmStatistics SQL database\n" ) if ( ! $ok_stat );

	return( undef, undef ) if ( ( ! $ok )  ||  ( ! $ok_stat ) );
	
	
	my $dbhRemote = DBI->connect( "DBI:ODBC:TrafficRemote", "IpmContent" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhRemote )
		{	sleep( 10 );
			$dbhRemote = DBI->connect( "DBI:ODBC:TrafficRemote", "IpmContent" );
		}
		
	&FatalError( "Unable to connect to Remote IpmContent SQL database\n" ) if ( ! $dbhRemote );
		
	my $dbhStatRemote = DBI->connect( "DBI:ODBC:RemoteStatistics", "IpmStatistics" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbhStatRemote )
		{	sleep( 10 );
			$dbhStatRemote = DBI->connect( "DBI:ODBC:RemoteStatistics", "IpmStatistics" );
		}
		
	&FatalError( "Unable to connect to Remote IpmStatistics SQL database\n" ) if ( ! $dbhStatRemote );
	
	&SqlSetCurrentDBHandles( $dbhRemote, $dbhStatRemote );
	
	return( $dbhRemote, $dbhStatRemote );
}



my $database_next_time;
################################################################################
#
sub CheckDatabases( $ )
#
#  Check to make sure the database connections are still going
#  The now parameter is to check the realtimespam now rather than later
#
################################################################################
{	my $now = shift;
	
	if ( ( ! $now )  &&  ( $database_next_time ) )
		{  return if ( time() < $database_next_time );  #  Wait a while to do this processing if I have run before
		}

	$database_next_time = 30 + ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so - plus 30 seconds

	&debug( "CheckDatabases\n" );
	
	
	# Did one of the databases have an error?
	my $err = $dbhStat->err;
	if ( $err )
		{	my $errstr = $dbhStat->errstr;
			&oprint( "Statistics SQL database error: $errstr\n" );
			&oprint( "Trying to re-connect to the Statistics database\n" );
			$dbhStat->disconnect;
			$dbhStat = undef;

			$dbhStat = &ConnectStatistics();
			&FatalError( "Unable to re-connect to the Statistics SQL database\n" ) if ( ! $dbhStat );
		}
	
	$err = $dbh->err;
	if ( $err )
		{	my $errstr = $dbh->errstr;
			&oprint( "Content SQL database error: $errstr\n" );
			&oprint( "Trying to re-connect to the Content database\n" );
			$dbh->disconnect;
			$dbh = undef;

			$dbh = &ConnectServer();
			&FatalError( "Unable to re-connect to the Content SQL database\n" ) if ( ! $dbh );
		}
		
	return;
}




################################################################################
# 
sub GetProperties()
#
#  Get the current properties from the Spam Blocker Object that affect
#  the realtime spam program
#
################################################################################
{	my $key;
	my $type;
	my $data;


	#  First get the current config number
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations", 0, KEY_READ, $key );

	return( undef ) if ( ! $ok );
	$ok = &RegQueryValueEx( $key, "Current", [], $type, $data, [] );

	&RegCloseKey( $key );
	
	return( undef ) if ( ! $ok );   
	my $current = &HexToInt( $data );

	my $current_key = sprintf( "%05u", $current );

	my $subkey;
	my $counter;
	#  Next go through the current config looking for a Spam Mail Blocker object
	for ( my $i = 1;  $i < 100;  $i++ )
		{	$counter = sprintf( "%05u", $i );

			$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter";

			$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
			next if ( ! $ok );  

			$data = undef;
			$ok = &RegQueryValueEx( $key, "ProgID", [], $type, $data, [] );  # Blank is the (Default) value
			next if ( ! $data );

			RegCloseKey( $key );

			last if ( $data =~ m/SpamMailBlockerSvc/ );         
		}

	return( undef ) if ( ! ( $data =~ m/SpamMailBlockerSvc/ ) ); 


	# At this point I've got a spam blocker object in this config
	$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter\\Dynamic Properties";
	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
	return( undef )  if ( ! $ok );  
	 

	$data = undef;
	$ok = &RegQueryValueEx( $key, "Enable Statistical Analysis", [], $type, $data, [] );

	if ( $ok )
		{	$use_bayesian = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Bayesian Aggression", [], $type, $data, [] );

	if ( $ok )
		{	$opt_sensitivity = HexToInt( $data ) if ( $data );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Enable Auto Whitelist", [], $type, $data, [] );

	if ( $ok )
		{	$use_autowhitelist = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Enable AutoBlacklist", [], $type, $data, [] );

	if ( $ok )
		{	$use_autoblacklist = 1 if ( $data ne "\x00\x00\x00\x00" );
		}


	# There are 2 possible keys for the enable grey listing - this on is for version 5.0
	$data = undef;
	$ok = &RegQueryValueEx( $key, "Enable Greylisting", [], $type, $data, [] );

	if ( $ok )
		{	$use_greylist = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	# And this one is for 4.0
	$ok = &RegQueryValueEx( $key, "Enable Advanced Techniques", [], $type, $data, [] );

	if ( $ok )
		{	$use_greylist = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Enable Challenge", [], $type, $data, [] );

	if ( $ok )
		{	$use_challenge = 1 if ( $data ne "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Challenge Address", [], $type, $data, [] );

	if ( $ok )
		{	$challenge_email_from = $data if ( $data );
			push @special_addresses, $challenge_email_from if ( defined $challenge_email_from );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Send Successful Challenge Notification", [], $type, $data, [] );

	if ( $ok )
		{	$challenge_send_thank_you = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Blocked Content Categories", [], $type, $data, [] );

	if ( $ok )
		{	$use_contentdb = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Use Spam Patterns", [], $type, $data, [] );

	if ( $ok )
		{	$use_spam_patterns = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Use Network Reputation", [], $type, $data, [] );

	if ( $ok )
		{	$use_network_reputation = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Use SPF", [], $type, $data, [] );

	if ( $ok )
		{	$use_spf = 1 if ( ( defined $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Adult Subjects", [], $type, $data, [] );
	if ( $ok )
		{	$use_adult_subjects = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Virus Infected", [], $type, $data, [] );

	if ( $ok )
		{	$use_virus = undef if ( $data eq "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Scan Errors", [], $type, $data, [] );

	if ( $ok )
		{	$block_scan_errors = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Proxy Check Unknown Servers", [], $type, $data, [] );

	if ( $ok )
		{	$use_proxy = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Use DNS to Check Unknown URLs", [], $type, $data, [] );

	if ( $ok )
		{	$use_proxy_dns = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Realtime Spam Logging", [], $type, $data, [] );

	if ( $ok )
		{	$opt_logging = 1 if ( $data ne "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Use Valid Email To", [], $type, $data, [] );

	if ( $ok )
		{	$use_valid_email_to = undef if ( $data eq "\x00\x00\x00\x00" );
			$use_valid_email_to = 1 if ( $data ne "\x00\x00\x00\x00" );
		}


	$data = undef;
	$ok = &RegQueryValueEx( $key, "Virus Forward", [], $type, $data, [] );

	if ( $ok )
		{	$virus_forward = undef if ( $data eq "\x00\x00\x00\x00" );
			$virus_forward = 1 if ( $data ne "\x00\x00\x00\x00" );
		}

	$data = undef;
	$ok = &RegQueryValueEx( $key, "Maximum Message Size", [], $type, $data, [] );
	$block_large_messages = undef;

	if ( $ok )
		{	if ( $data ne "\x00\x00\x00\x00" )
				{	$block_large_messages = &DWORDToInt( $data );
					$block_large_messages = 0 + $block_large_messages;
				}
		}

	$data = undef;
	$ok = &RegQueryValueEx( $key, "Maximum Attachments", [], $type, $data, [] );

	if ( $ok )
		{	$maximum_attachments = undef if ( $data eq "\x00\x00\x00\x00" );
			$maximum_attachments = &DWORDToInt( $data ) if ( $data ne "\x00\x00\x00\x00" );
		}

	$data = undef;
	$ok = &RegQueryValueEx( $key, "Block Password Protected Zip", [], $type, $data, [] );
	$opt_password_protected_zip = 1;
	if ( $ok )
		{	$opt_password_protected_zip = undef if ( $data eq "\x00\x00\x00\x00" );
		}

	$data = undef;
	$ok = &RegQueryValueEx( $key, "Bad Extensions", [], $type, $data, [] );
	if ( $ok )
		{	# Set the bad extensions list to the registry value if the registry value exists
			$bad_extensions = $data if ( length( $data ) > 0 );
			&oprint( "Set the list of bad extensions to $bad_extensions\n" );
		}

	&RegCloseKey( $key );
	
	return( 1 );
}



################################################################################
# 
sub HexToInt( $ )
#
#  Convert a registry hex value to a decimal value
#
################################################################################
{	my $hexstring = shift;

	return( 0 + 0 ) if ( ! defined $hexstring );
	
	my $dec = unpack( "CH", $hexstring );
 
   return( $dec );
}



################################################################################
# 
sub DWORDToInt( $ )
#
#  Convert a registry hex value to a decimal value
#
################################################################################
{	my $hexstring = shift;

	return( 0 + 0 ) if ( ! defined $hexstring );
	
	my $dec = unpack( "V", $hexstring );
 
   return( $dec );
}



################################################################################
#
sub AnalyzeFile( $$$ )
#
#  Given a file name, return 1 if it is Spam, 0 if OK, -1 if definitely Ham
#  The second option is to check for viruses only
#
################################################################################
{	my $file			= shift;
	my $virus_only		= shift;
	my $overrides_only	= shift;	# Brock's SMB object has already marked it as SPAM
	
	my @attached_files;
	my $retcode;
	my $result;
	my $msg;
	my $email_from;
	my $header_email_from;
	my $email_to;
	my $envelope_email_to;
	my $external_ip_address;
	my $external_ip_address_source;	
	my $external_ip_address_category;
	my $subject;
	my @message_files;	# The list of message files created
	my %base64_data = ();
	my $line_no = 0 + 0;


	my $start = new Benchmark if ( $opt_benchmark );
	
	
	if ( ( ! $opt_summary )  &&  ( $opt_logging ) )
		{	&oprint( "Virus check file: $file\n" ) if ( $virus_only );
			&oprint( "Override check file: $file\n" ) if ( $overrides_only );
			&oprint( "Spam analyze file: $file\n" ) if ( ! defined $virus_only && ! defined $overrides_only);
		}
		
		
    $retcode = 0 + 0;  # Set the retcode to 0 before running any tests
	
    return( $retcode ) if ( !$file );
	
	$current_file = $file;
	
	
    #  Load the file into memory
    @data = ();
    if ( !open SPAM, "<$file" )
	  {   &lprint( "Error opening file $file: $!\n" );
		  
		  $retcode = 0 - 1;
          $msg = "Email file does not exist";
		  $result = "HAM";
      }


	%clues = ();					# Initialize the clues hash
    my $counter = 0 + 0;			# The count of lines read from this message file
    my $base64;						# True if the boundary is encoded as base64
	my $quoted_printable;			# True if the boundary is encoded as quoted_printable
    my $message_body;				# True if we are inside part of a message body
	my $header = 1;					# True until we hit the message body - which includes multi part bodies
	my $first_line = 1;				# True if we are reading the first line of the file
	my @boundary;					# The list of boundaries
	my $content_description;		# The description of the current content
	my $content_type;				# The content type of the current part
	my $set_content_type;			# True if I just set the content type, and may get an attachment name next
	my $encoding;					# The encoding of the current part
	my $attachment;					# True if this part contains an attachment
	my $attachment_count = 0 + 0;	# The number of attached files
	my $total_parts = 0 + 0;		# The count of the number of parts to a multipart message
    my $bytes = 0 + 0;				# The number of bytes read 
	my $attach_filename;			# The name of the current attachment
	my $set_message_file_name;		# True if I have created a message file name for this attachment or content type
	my $skip_content;				# True if this type of content should be skipped for the Bayesian analysis
	my $skip_filename;				# True if this file extension should be skipped for the Bayesian analysis
	my $skip_decode;				# True if this file extension doesn't need to be decoded
	my $to_list;					# The list of to: addresses from the email header
	my $cc_list;					# The list of cc: addresses from the email header
	my $bcc_list;					# The list of bcc: addresses from the email header
	my $partial_line;	            # For decoding of partial lines in quoted-printable.
	my $last_header_type;			# The last header type line I processed - could be to, cc, subject, etc
	my $multi_subject = 0;
	my $multi_to = 0;
	my $multi_cc = 0;
	my $multi_bcc = 0;
	my $tmp_filename;
	
	
	while ( ( $retcode == 0 )  &&  ( my $line = <SPAM> ) )
		{   my $len = length( $line );
			next if ( $len > 1000 );  #  Skip long lines


			$bytes += $len;		# Count the bytes
			$counter++;			# Count the lines
			
			
			# Have I read a lot in already?
 			if ( ( ! $opt_tmp_dir )  &&  ( ( $counter > $max_lines )  ||  ( $bytes > $max_bytes ) ) )
				{	&lprint( "Not unpacking completely file $file because of size limitations\n" );
					&lprint( "# of lines = $counter, # of bytes = $bytes\n" );

					# Dump any base64 data so that we don't try to unpack damaged zip file, for example
					%base64_data = ();
					last;
				}
			
			chomp( $line );
				
				
			# Do any header processing
			if ( $header )
				{	#  Am I reading the first line comment by Brock's code?
					# &debug( "Header: $line\n" );
							
					if ( ( $first_line )  &&  ( $line =~ m/^\(externalipaddress/i ) )
						{   $first_line = undef;

							my $comment = $line;
							
							# Read additional lines until I get the trailing )
							while ( ( $line )  &&  ( ! ( $line =~ m/\)/ ) ) )
								{	$line = <SPAM>;
									chomp( $line );
									
									# Get rid of leading whitespace
									$line =~ s/^\s+// if ( $line );

									# Get rid of trailing whitespace
									$line =~ s/\s+$// if ( $line );
									
									$comment .= "," . $line if ( $line );
								}

							$comment =~ s/\(//;
							$comment =~ s/\)//;
		
							my @parts = split /\s/, $comment;
							my $part_no = 0;
							foreach ( @parts )
								{  $part_no++;
									my $keyword = lc( $_ );
									#  Check for a blank value
									next if ( !$parts[ $part_no ] );
									next if ( index( "emailfrom:emailto:externalipaddress:", lc( $parts[ $part_no ] ) ) != -1 );
									
									if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
									if ( $keyword eq "emailto:" )            {  $envelope_email_to = lc ( $parts[ $part_no ] );  }
									if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
								}
								
							&AddClue( "From", $email_from );
							&AddClue( "Envelope To", $envelope_email_to );
							&AddClue( "External-IP", $external_ip_address );
							
							next;
						}  # end of first line processing

					
					# Is it a multi-line subject, to, or cc?  A line starting with whitespace is a multi line option
					if ( $line =~ m/^\s/ )   
						{	# Trim off the first whitespace
							$line =~ s/^\s//;
							
							# Trim off the last whitespace
							$line =~ s/\s$//g;
							if ( ! defined $last_header_type )	# If it hasn't been set, then don't do anything
								{
								}
							elsif ( $last_header_type eq "subject" )
								{	$subject .= " " . $line;
									$multi_subject = 1;
									next;	# Get the next line of the file
								}
								
							elsif ( $last_header_type eq "to" )
								{	$to_list .= ";" . $line;
									$multi_to = 1;
									next;	# Get the next line of the file
								}
								
							elsif ( $last_header_type eq "cc" )
								{	$cc_list .= ";" . $line;
									$multi_cc = 1;
									next;	# Get the next line of the file
								}
								
							elsif ( $last_header_type eq "bcc" )
								{	$bcc_list .= ";" . $line;
									$multi_bcc = 1;
									next;	# Get the next line of the file
								}
							
						}
						


					my $lc_line = lc( $line );	# Get a lower case copy of the line to check encoding, etc
					my $no_comments = $lc_line;
				

					#  Consume any comments in the header - to avoid being deceived
					#  Do this to the lc variable, to preserver () in other cases
					if ( $no_comments =~ m/\(.*\)/ )
						{  $no_comments =~ s/\(.*\)//;
							$no_comments = "\(\)" if ( !$no_comments );  # if nothing left, pad it to be a blank comment
						}


					# Get rid of leading whitespace
					$no_comments =~ s/^\s//g;
					
					
					# Is this a header type & option?  It is if it contains a ':' with no spaces in the header option
					my ( $header_type, $option ) = split /\:/, $no_comments, 2;
					$last_header_type = $header_type if ( ( defined $option )  &&  ( ! ( $header_type =~ m/\s/ ) ) );
						
						
					#  Am I a setting the to: list?
					if ( ( ! defined $to_list )  &&  ( $no_comments =~ m/^to:/ ) )
						{    my ( $junk, $stuff ) = split /to:/, $lc_line, 2;

							$to_list = $email_to . ";" . $stuff if ( ( $email_to )  &&  ( $stuff ) );
							$to_list = $stuff if ( ( ! $email_to )  &&  ( $stuff ) );
							
							$to_list = &CleanEmailListStr( $to_list );
							&AddClue( "To List", $to_list );
						}	# End of setting the to: list
					 			
								
					#  Am I a setting the CC list?
					if ( ( ! defined $cc_list )  &&  ( $no_comments =~ m/^cc:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/cc://i;
							
							$cc_list = $stuff;
							$cc_list =~ s/^\s//g;
							$cc_list =~ s/\s$//g;
							
							$cc_list = &CleanEmailListStr( $cc_list );
							&AddClue( "CC list", $cc_list );
						}
					 			
								
					#  Am I a setting the BCC list?
					if ( ( ! defined $bcc_list )  &&  ( $no_comments =~ m/^bcc:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/bcc://i;
							
							$bcc_list = $stuff;
							$bcc_list =~ s/^\s//g;
							$bcc_list =~ s/\s$//g;
							
							$bcc_list = &CleanEmailListStr( $bcc_list );
							&AddClue( "BCC list", $bcc_list );
						}
					 		
								
					#  Am I a setting the Subject line?
					if ( ( ! defined $subject )  &&  ( $no_comments =~ m/^subject:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/subject://i;
							
							$subject = $stuff;
							$subject =~ s/^\s//g;
							$subject =~ s/\s$//g;
							
							&AddClue( "Subject", $subject );
						}
					 		
								
					#  Am I a setting the header email from?
					if ( ( ! defined $header_email_from )  &&  ( $no_comments =~ m/^from:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/from://i;
							
							$header_email_from = $stuff;
							$header_email_from =~ s/^\s//g;
							$header_email_from =~ s/\s$//g;
							
							#  Grab anything inside < > as the email address if <> exists
							$header_email_from = $1 if ( $stuff =~ m/\<(.*?)\>/ );

							$header_email_from = &CleanEmail( $header_email_from );
							&AddClue( "header email from", $header_email_from ) if ( $header_email_from );
						}
					 			
								
					#  Am I a setting the Content Description?
					if ( $no_comments =~ m/^content-description:/ )
						{    my ( $junk, $stuff ) = split /content-description:/, $lc_line, 2;
							$content_description = $stuff;
							$content_description =~ s/^\s//g;
							$content_description =~ s/\s$//g;
							&debug( "Content-Description = $content_description\n" ) if ( $content_description );
							
							&AddClue( "Content-DESC", $content_description ) if ( $content_description );
						}
					 			
						
					#  Am I a setting the Content Type?
					if ( $no_comments =~ m/^content-type:/ )
						{    my ( $junk, $stuff ) = split /content-type:/, $lc_line, 2;
							$content_type = $stuff;
							$content_type =~ s/\s//;
							$content_type =~ s/\;//;
							( $content_type, $junk ) = split /\s/, $content_type, 2;
							&debug( "Content-Type = $content_type\n" ) if ( $content_type );
								
							# Is it a partial message?
							if ( ( $content_type )  &&  ( $content_type eq "message/partial" ) )
								{	$retcode = 1;  # Flag it as spam
									$msg = "Partial	message - could contain virus";
									$result = "VIRUS";
								}
							
							if ( $content_type )
								{	$set_content_type = 1;	
									&AddClue( "CONTENT-TYPE", $content_type );
							
									$skip_content = undef;
									
									$skip_content = 1 if ( $content_type =~ m/pdf/ );
									$skip_content = 1 if ( $content_type =~ m/x-msdownload/ );
									$skip_content = 1 if ( $content_type =~ m/octet-stream/ );
									$skip_content = 1 if ( $content_type =~ m/audio/ );
									$skip_content = 1 if ( $content_type =~ m/image/ );
									$skip_content = 1 if ( $content_type =~ m/postscript/ );
									$skip_content = 1 if ( $content_type =~ m/zip/ );
								}
						}
					
					
					#  Am I setting the encoding?
					if ( $no_comments =~ m/^content-transfer-encoding:/ )
						{   &debug( "Content-Transfer-Encoding\n" );
							my ( $junk, $stuff ) = split /content-transfer-encoding:/, $lc_line, 2;
							$encoding = $stuff;
							$encoding =~ s/\s//;
							$encoding =~ s/\;//;
							( $encoding, $junk ) = split /\s/, $encoding, 2;
							$base64 = undef;
							$quoted_printable = undef;
								
							# If I have an encoded section, break it out to it's own file
							if ( $encoding )
								{	if ( $encoding =~ m/base64/i )
										{	$base64 = 1;

											&debug( "base64 encoding\n" );
											my $fileno = $#message_files + 1;
											$tmp_filename = &ScanBuildTmpFilename( $tmp_dir, $file, $fileno, "eml" );
										}
									elsif ( $encoding =~ m/quoted-printable/i )
										{	$quoted_printable = 1;
											
											&debug( "quoted-printable encoding\n" );
											my $fileno = $#message_files + 1;
											$tmp_filename = &ScanBuildTmpFilename( $tmp_dir, $file, $fileno, "txt" );
										}								
									
									$tmp_filename = &CleanFileName( $tmp_filename );
									
									if ( ( $tmp_filename  )  &&  ( ! $set_message_file_name ) )
										{	# Keep a list of the file names used
											
											push @message_files, $tmp_filename;
											$set_message_file_name = 1;
										}
								}			 
								
							&AddClue( "ENCODING", $encoding );
						}


					#  Is it MimeOLE?
					if ( $lc_line =~ m/^x-mimeole/ )
						{   &debug( "X-MimeOLE\n" );
							&AddClue( "X-MimeOLE", "OLE" );
						}


					#  Am I a setting the disposition?
					if ( $no_comments =~ m/^content-disposition:/ )
						{	&debug( "Content-Disposition\n" );
							my ( $junk, $stuff ) = split /content-disposition:/, $lc_line, 2;
							my $disposition = $stuff;
							$disposition =~ s/\s//;
							$disposition =~ s/\;//;
							
							if ( $lc_line =~ m/attachment/ )
								{	$attachment = 1;
									$attachment_count++;
									&debug( "Content-Disposition: attachment\n" );
								}
								
							&AddClue( "DISPOSITION", $disposition ) if ( $disposition );
						}
							
							
						#  Am I a setting the attachment filename, or did I just set the content type?
						if ( ( $attachment || $set_content_type )  &&  ( $no_comments =~ m/name *=/ ) )
							{	my ( $junk, $stuff ) = split /name *=/, $lc_line, 2;
								
								# Split off anything past a ';'
								( $attach_filename, $junk ) = split /;/, $stuff, 2 if ( defined $stuff );
											
								# Peel off quote marks if they are there
								$attach_filename =~ s/\"//g if ( $attach_filename );							

								# Peel off leading or trailing spaces
								$attach_filename =~ s/^\s+// if ( $attach_filename );
								$attach_filename =~ s/\s+$// if ( $attach_filename );
								
								if ( $attach_filename )
									{	push @attached_files, $attach_filename;
																		
										# If I've already set the message file name change it to include the actual attachment name
										my $fileno = $#message_files;
										
										# If I haven't set the message file name for this section, add a new name
										$fileno = $#message_files + 1 if ( ! $set_message_file_name );
										$set_message_file_name = 1;
										
										my $short_name = &CleanShortFileName( $attach_filename );
										
										$tmp_filename = &ScanBuildTmpFilename( $tmp_dir, $file, $fileno, $short_name );
										
										$tmp_filename = &CleanFileName( $tmp_filename );								
										$message_files[ $fileno ] = $tmp_filename if ( $tmp_filename );
										
										&debug( "Attach message file name = $tmp_filename\n" ) if ( $tmp_filename );
									}
								
								$attachment = undef;
								$set_content_type = undef;
								
								if ( $attach_filename )
									{	&AddClue( "ATTACH-NAME", $attach_filename );
								
								
										# Should I skip adding this content for bayesian analysis based on the filename?
										$skip_filename = undef;
										
										$skip_filename = 1 if ( $attach_filename =~ m/\.exe$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.com$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.pcx$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.dll$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.jpg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.jpeg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.ai$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.scr$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.zip$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.gz$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.ppt$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.xls$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.doc$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.bmp$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.pdf$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.cup$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.avi$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.mp3$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.mpg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.mpeg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.dbg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.gif$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.rar$/ );
										
																				
										# Is this the type of file that I don't need to decode since I won't scan for a virus?
										$skip_decode = undef;
										
										$skip_decode = 1 if ( $attach_filename =~ m/\.jpg$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.jpeg$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.pdf$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.ppt$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.bmp$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.avi$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.mp3$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.mpg$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.mpeg$/ );
									}
							}


					#  Am I a setting a boundary?
					if ( $no_comments =~ m/boundary=/g )
						{	$lc_line =~ m/boundary=/g;
							
							my $boundary = substr( $line, pos( $lc_line ) );
							
							if ( ( $boundary )  &&  ( length( $boundary ) > 6 ) )
								{	$boundary =~ s#\"##g;   #  Get rid of quotes
									$boundary = '--' . $boundary;	#  Add the dash dash
									$boundary =~ s/\s+$//;		# Get rid of trailing whitespace	
									
									&debug( "boundary = $boundary\n" );
									&AddClue( "BOUNDARY", $boundary );
									
									$boundary = quotemeta( $boundary );  #  Backslash any non alpha character
									push @boundary, $boundary;
								}
						}			 
				}  # end of the header processing 
					
					
			#  Have I hit a boundary?
			#  I'm in a header if this matches - until I hit a blank line
			foreach ( @boundary )
				{   next if ( ! $_ );
						
					if ( $line =~ m/$_/ )
						{	$header					= 1;
							$message_body			= undef;
							$base64					= undef;
							$quoted_printable		= undef;
							$encoding				= undef;
							$attachment				= undef;
							$set_content_type		= undef;
							$attach_filename		= undef;
							$set_message_file_name	= undef;
							&debug( "Switching to a header\n" );
						}
				}  # end of foreach boundary
					
					
			#  A blank line or a dot in the header means we are switching to a body
			if (  ( $header )  &&  ( ( ! $line )  ||  ( $line eq "." ) ) )
				{  $total_parts++ if ( ! $message_body );
					$message_body	= 1;
					$header			= undef;
					$line			= undef;
					&debug( "Switching to a body\n" );
				}
			
					
			next if ( ! defined $line );  #  Now that it is blank, skip it
			
			
			# If I'm in a body - could this be some sort of enclosed message that is setting a boundary?
			# Well it might be, if the boundary is wrapped in double quotes and long enough
			if ( ( $message_body )  &&
				( ! $skip_decode ) &&
				( $line )  &&
				( $line =~ m/boundary=\"/ ) )
					{	my ( $junk, $boundary ) = split /boundary=/, $line, 2;
						if ( ( $boundary )  &&  ( $boundary =~ m/\"$/ )  &&  ( length( $boundary ) > 12 ) )
							{	$boundary =~ s#\"##g;   #  Get rid of quotes
								$boundary = '--' . $boundary;	#  Add the dash dash
								$boundary =~ s/\s+$//;		# Get rid of trailing whitespace	
								
								&debug( "message body boundary = $boundary\n" );
								&AddClue( "BOUNDARY", $boundary );
								
								$boundary = quotemeta( $boundary );  #  Backslash any non alpha character
								push @boundary, $boundary;
							}
					}			 
			

			# If the message type is rfc/822, the body is an enclosed message
			if ( ( $content_type )  &&  ( $content_type =~ /message\/rfc822/ ) )
					{	$header					= 1;
						$message_body			= undef;
						$base64					= undef;
						$quoted_printable		= undef;
						$encoding				= undef;
						$attachment				= undef;
						$set_content_type		= undef;
						$set_message_file_name	= undef;
					}
			
				
			#  If we are in a body, decode any base64 stuff 
			if ( ( $base64 )  &&  
				( $message_body )  &&  
				( ! $skip_decode )  &&
				( $content_type )  &&
				( $content_type ne "text\/plain" ) )
				{	# Figure out the right filename to save this data to
					my $fileno = $#message_files;
					my $message_filename = $message_files[ $fileno ];
					
					$base64_data{ $message_filename } .= $line if ( $message_filename );
				}

			#  If we are in a body, and virus_checking is enable, decode any quoted_printable
			if ( ( $quoted_printable )  &&  #  Decode if it looks like it matches
				( $message_body ) ) 
				{	# At this point I have already chomped any \n

					$line =~ s/[ \t]+\n/\n/g;        # rule #3 (trailing space must be deleted)
					
					my $hard_return;

					# Trim off any soft returns, wrap lines together to avoid broken URLs...
					if ( $line =~ m/=$/ )
						{	$line =~ s/=+$//;
							$partial_line .= $line;
							next;
						}
					else
						{  # Do not set a hard return if we are merging lines together.
							$hard_return = 1 if (!$partial_line);
						}
						
					
					# We made it to the end of a merged line.  Set it up and let it go!
					if ( $partial_line )
						{	$line = $partial_line . $line;
							$partial_line = undef;
						}
						    
										
					# Decode the line - now using MIME module instead of the substitution line
					$line = MIME::QuotedPrint::decode_qp( $line );
					
					# Save it to a file
					$line = $line . "\r\n" if ( $hard_return );	# Add a carriage return line feed if a hard return
					
					
					# Should I save this to a file for virus scanning?
					if ( ( ! $skip_decode )  &&
						( $virus_installed )  &&
						( $content_type )  &&
						( $content_type ne "text\/plain" ) )
						{	# Figure out the right filename to save this data to
							my $fileno = $#message_files;
							my $message_filename = $message_files[ $fileno ];
							
							&ScanSaveMessageFile( $file, $message_filename, $line );
						}
				} # end of decoding quoted-printable

				
			# Could this be the beginning of a uuencoded file attachment?
			if ( ( $message_body )  &&  ( $line =~ m/^begin 6/ )  &&  ( ! $skip_decode ) )
				{	my $uu_decode = &UUDecode( $file, 1, $tmp_dir );
					push @message_files, $uu_decode if ( defined $uu_decode );
				}
				
				
			# Should I save this line into the data array for later Bayesian processing?					
			# Should I skip based on content-type?
			next if ( ( $message_body )  &&  ( $content_type )  &&  ( $skip_content ) );
						
			# Should I skip based on attached filename?
			# If it matches on one of these file extensions, don't do the Bayesian stuff on this data
			next if ( ( $message_body )  &&  ( $attach_filename )  &&  ( $skip_filename ) );
						
			# Add it to the data array for later Bayesian processing	
			push @data, $line;
			
			$line_no++;
			&debug( "LINE $line_no: $line\n" );
		}  # end of while <SPAM>
		
	close( SPAM );


	# Decode any BASE64-encoded attachments now and save them to the temporary files created earlier.
	# DO NOT CLOSE THE MESSAGE FILES BEFORE DOING THIS!
	my @base64_filelist = keys %base64_data;
	foreach ( @base64_filelist )
		{	my $message_filename = $_;
			
			# Make sure that I've got a filename
			next if ( ! $message_filename );
			
			my $base64_data = $base64_data{ $message_filename };
			
			# Clean out any white space
			$base64_data =~ s/\s//g if ( $base64_data );
			next if ( ! $base64_data );
			
			# Trim off any padding
			$base64_data =~ s/\=+$// if ( $base64_data );
			next if ( ! $base64_data );
			
			# Make sure the base64 padding is right
			my $base64_padding = 4 - length( $base64_data ) % 4;

			my $pad = '=' x $base64_padding if ( $base64_padding );
			$base64_data .= $pad if ( ( $base64_padding )  &&  ( $base64_padding < 4 ) );

			$base64_data = decode_base64( $base64_data );
			
			# Make sure that I've got something to write
			next if ( ! $base64_data );
			
			if ( $opt_debug )
				{	my $len = length( $base64_data );
					&debug( "Writing $len bytes of base64 decoded data to $message_filename ... \n" ); 
				}
				
			# Save the decoded base64 data to the right file name	
			&ScanSaveMessageFile( $file, $message_filename, $base64_data );            
		}


	# Close any message files that were opened
	&ScanCloseMessageFiles();


    # Make sure any email addresses, etc. are legal
	# Clean up the to an cc strings into clean arrays of valid email addresses
	# First make sure that the TO: email address from the SMTP session is in the TO list
	$to_list .= "," . $email_to if ( ( defined $to_list )  &&  ( defined $email_to ) );
	$to_list = $email_to if ( ! defined $to_list );

	# The envelope email to is a list of email addresses, comma delimited
	my @temp_to = split /,/, $envelope_email_to if ( $envelope_email_to );
	my @envelope_to;
	foreach( @temp_to )
		{	my $to = $_;
			$to = &CleanEmail( $to );
			next if ( ! $to );
			push @envelope_to, $to;
		}
		

	# If the envelope_to list is empty then use the to lists from the mail header as the envelope to:
	if ( $#envelope_to == - 1 )
		{	my @to_list		= &CleanEmailList( $to_list );
			my @cc_list		= &CleanEmailList( $cc_list );
			my @bcc_list	= &CleanEmailList( $bcc_list );
			
			@envelope_to = @to_list;
			push @envelope_to, @cc_list;
			push @envelope_to, @bcc_list;
		}		
		
	# See if there are any easy pseudonyms
	# Make a copy of the envelope to without any psuedos
	my @envelope_to_no_pseudo;
	push @envelope_to_no_pseudo, @envelope_to;
	@envelope_to_no_pseudo = &CleanList( @envelope_to_no_pseudo );
	
	my @pseudo_list = &CleanEmailPseudo( @envelope_to );
	push @envelope_to, @pseudo_list;

	# Remove any duplicates
	@envelope_to = &CleanList( @envelope_to );
	
	# The main email to is the first envelope email to:
	$email_to				= $envelope_to[ 0 ];	
	
	
	# Get as good an email from: as possible
	$email_from				= $header_email_from if ( ! defined $email_from );
	my $original_email_from = $email_from;		# Keep track of the original email from - it can be an invalid email address like "Mail Delivery Subsystem"
    $original_email_from	= $header_email_from if ( ! defined $original_email_from );
	$email_from				= &CleanEmail( $email_from );
	
	
    $external_ip_address	= &CleanIp( $external_ip_address );
	

    &debug( "email_to: $email_to\n" ) if ( defined $email_to );
    &debug( "envelope to list: @envelope_to\n" ) if ( $envelope_to[ 0 ] );
    &debug( "envelope to list no pseudo: @envelope_to_no_pseudo\n" ) if ( $envelope_to_no_pseudo[ 0 ] );
    &debug( "email_from: $email_from\n" ) if ( defined $email_from );
    &debug( "header email_from: $header_email_from\n" ) if ( defined $header_email_from );
    &debug( "external_ip_address: $external_ip_address\n" ) if ( defined $external_ip_address );
    &debug( "subject: $subject\n" ) if ( defined $subject );
	
	
    # Add clues for those multi-part items (Subject, CC, TO, BCC )
	&AddClue( "Multi-line Subject", $subject )	if ( $multi_subject );
	&AddClue( "Multi-line To", $to_list )		if ( $multi_to );
	&AddClue( "Multi-line CC", $cc_list )		if ( $multi_cc );
	&AddClue( "Multi-line BCC", $bcc_list )		if ( $multi_bcc );
    
	
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Reading spam file" );
			$start = new Benchmark;
		}
		
		
	&debug( "Total parts of the message = $total_parts\n" );
		   
	
	
#################################################################################
############  Virus or dangerous message checking starts here  ##################
#################################################################################
    
	
	#  Run all the tests in order
	#  $retcode -1 is HAM, 0 if OK, 1 is SPAM, and > 1 is ERRORCODE
						
							
	my $virus_name;	# The name of the last virus found
	
	# Check for viruses in the message files
	if ( ( $retcode == 0 )  &&  ( $#message_files >= 0 )  &&  ( $use_virus ) )
		{   for ( my $i = 0;  $i <= $#message_files;  $i++ )
				{	my $message_file_name = $message_files[ $i ];
					my $uu_decoded = undef;
					
					# If I haven't found a virus yet, keep checking
					if ( ( $retcode == 0 )  &&  ( -e $message_file_name ) )
						{	( $retcode, $virus_name ) = &VirusCheck( $message_file_name );  #  This should return a 1 if there was a virus, 0 if not
						
							if ( $retcode )
								{	$result = "VIRUS";
									$msg = &BuildSpamReason( "Virus Infected", "Virus: $virus_name", $result );								
								}
							else	
								{	# UUDecode it if necessary
									$uu_decoded = &UUDecode( $message_file_name, 1, $tmp_dir );
								}
						}	
						
						
					# Check for the UUDecoded file
					if ( ( $retcode == 0 )  &&  ( $uu_decoded )  &&  ( -e $uu_decoded ) )
						{	( $retcode, $virus_name ) = &VirusCheck( $uu_decoded );  #  This should return a 1 if there was a virus, 0 if not
						
							if ( $retcode )
								{	$result = "VIRUS";
									$msg = &BuildSpamReason( "Virus Infected", "Virus: $virus_name", $result );								
								}
						}

					if ( ( $uu_decoded )  &&  ( -e $uu_decoded )  &&  ( ! $opt_working_files ) )
						{
							unlink( $uu_decoded );
						}
				}
		}
	 

	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Virus message files" );
			$start = new Benchmark;
		}
		
		
	# Check for viruses in the main file
	if ( ( $retcode == 0 )  &&  ( $use_virus ) )
		{	( $retcode, $virus_name ) = &VirusCheck( $file );  #  This should return a 1 if there was a virus, 0 if not
			
			if ( $retcode )
				{	$result = "VIRUS";
					$msg = &BuildSpamReason( "Virus Infected", "Virus: $virus_name", $result );					
				}
		}
		
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Virus main file" );
			$start = new Benchmark;
		}
		
				
	# Check to see if the main file is a zip with dangerous files inside	
	if ( ( $retcode == 0 )  &&  ( $use_virus )  &&  ( &IsZip( $file ) ) )
		{	# ScanUnzipContents doesn't actually unzip the file - it just get the zip contents
			my ( $err_msg, @zip_files ) = &ScanUnzipContents( $tmp_dir, $file, $opt_password_protected_zip );
			$err_msg = &VirusSpam( $err_msg );
			
			
			# Did the unzipping process figure out a virus?
			if ( ( $err_msg )  &&  ( $err_msg =~ m/^Virus infected\: / ) )
				{	$retcode = 0 + 1;
					$virus_name = $err_msg;
					$virus_name =~ s/Virus infected\: //;
					$result = "VIRUS";
					$msg = &BuildSpamReason( "Virus Infected", "Virus: $virus_name", $result );					
				}
			elsif ( $err_msg )
				{	$retcode = 0 + 1;
					$virus_name = "Suspicious damaged zip: $err_msg";
					$result = "VIRUS";
					$msg = &BuildSpamReason( "Virus Infected", "Virus: suspicious damaged zip archive", $result );					
				}
			else	
				{	( $retcode, $attachment ) = &AttachedFilesCheck( @zip_files );  #  This should return a 1 if there was a dangerous attachment
				 
					if ( $retcode )
						{	$result = "VIRUS";
							$virus_name = "$file : $attachment";
							$msg = &BuildSpamReason( "Dangerous Attachment", "Attachment: $attachment", $result );					
						}
				}
		}
		


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Zip Dangerous File Names" );
			$start = new Benchmark;
		}
		
				
	# Check to see if the message files are zip files with dangerous attached files	
	# Or they could be UUencoded files with dangerous files
	if ( ( $retcode == 0 )  &&  ( $use_virus ) )
		{	foreach ( @message_files )
				{	next if ( ! defined $_ );
					
					my $message_file = $_;
					
					&debug( "Message file = $message_file\n" );
					
					# Check to see if the message file is UUencoded itself
					my $uu_decode_file = &UUDecodeFile( $message_file, 1 );

					if ( defined  $uu_decode_file )
						{	my @uu_decode_list;
							push @uu_decode_list, $uu_decode_file;
							
							( $retcode, $attachment ) = &AttachedFilesCheck( @uu_decode_list );  #  This should return a 1 if there was a dangerous attachment
						 
							if ( $retcode )
								{	$result = "VIRUS";
									$attachment = "Unknown" if ( ! $attachment );
									$virus_name = "$message_file : $attachment";
									$msg = &BuildSpamReason( "Dangerous Attachment", "Attachment: $attachment", $result );					
								}
						}
					
					
					# Clean up the uu decoded file if I created it
					if ( ( defined  $uu_decode_file )  &&  ( ! $opt_working_files ) )
						{	unlink( $uu_decode_file );
							next;	
						}
					
					
					next if ( ! &IsZip( $message_file ) );
					
					
					&debug( "Enclosed message file is a zip = $message_file\n" );
					
					# Check any zipped files names
					# ScanUnzipContents doesn't actually unzip the file - it just gets the zip contents
					my ( $err_msg, @zip_files ) = &ScanUnzipContents( $tmp_dir, $message_file, $opt_password_protected_zip );
					$err_msg = &VirusSpam( $err_msg );


					# Did the unzipping process figure out a virus?
					if ( ( $err_msg )  &&  ( $err_msg =~ m/^Virus infected\: / ) )
						{	$retcode = 0 + 1;
							$virus_name = $err_msg;
							$virus_name =~ s/Virus infected\: //;
							$result = "VIRUS";
							$msg = &BuildSpamReason( "Virus Infected", "Virus: $virus_name", $result );					
						}
					elsif ( $err_msg )
						{	$retcode = 0 + 1;
							$virus_name = "Suspicious damaged zip: $err_msg";
							$result = "VIRUS";
							$msg = &BuildSpamReason( "Virus Infected", "Virus: suspicious damaged zip archive", $result );					
						}
					else
						{	( $retcode, $attachment ) = &AttachedFilesCheck( @zip_files );  #  This should return a 1 if there was a dangerous attachment
				 
							if ( $retcode )
								{	$result = "VIRUS";
									$attachment = "Unknown" if ( ! defined $attachment );
									$virus_name = "$message_file : $attachment";
									$msg = &BuildSpamReason( "Dangerous Attachment", "Attachment: $attachment", $result );					
								}
						}
				}
		}

			
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "ZIP & UUDECODE Dangerous file check" );
			$start = new Benchmark;
		}
		

	# Clean up any message files created 
	for ( my $i = 0;  $i <= $#message_files;  $i++ ) 
		{	my $message_file_name = $message_files[ $i ];
			next if ( ! defined $message_file_name );

			unlink( $message_file_name ) if ( ! $opt_working_files );	# Delete the file now that I checked it if I'm not debugging
		}	
		
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Unlink Message Files" );
			$start = new Benchmark;
		}
		

	if ( ( $retcode == 0 )  &&  ( $use_virus ) )
		{	my $attachment;
			
			( $retcode, $attachment ) = &AttachedFilesCheck( @attached_files );  #  This should return a 1 if there was a dangerous attachment
		 
			if ( $retcode )
				{	$result = "VIRUS";
					$attachment = "Unknown" if ( ! $attachment );
					$virus_name = $attachment;
					$msg = &BuildSpamReason( "Dangerous Attachment", "Attachment: $attachment", $result );					
				}
		}

			
	
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Attached Files Check" );
			$start = new Benchmark;
		}
		

	#  Does it match any of our virus patterns?
	if ( ( $retcode == 0 )  &&  ( $use_spam_patterns ) )
		{	my $virus_pattern_name;
			( $retcode, $virus_pattern_name ) = &VirusPatterns();  #  This should return a -+1 if it matches a spam virus pattern

			if ( $retcode )
				{	$result = "VIRUS";
					$msg = &BuildSpamReason( "Spam Virus Pattern", "Name: $virus_pattern_name", $result );							
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Spam Virus Patterns" );
			$start = new Benchmark;
		}
		
		
	#  Is the IP address blocked in the content database?
	my $contentdb_spam_url;
	if ( ( ( $retcode == 0 )  ||  ( $create_clue_file ) )  &&  ( $use_contentdb ) )
		{	my $virus;
			
			( $retcode, $external_ip_address_source, $virus, $external_ip_address_category ) = &ContentIpAddress( $external_ip_address );
					
			if ( ( $retcode )  &&  ( $virus ) )
				{	$result = "VIRUS";
					$msg = &BuildSpamReason( "Content DB IP", "IP Address: $external_ip_address", $result );							
				}
			elsif ( $retcode )
				{	$contentdb_spam_url = $external_ip_address;	# Hold onto the IP address that is spam until I do some other checking
					$retcode = 0 + 0;	# Reset the return code to nothing - for now ...
				}
		}
			

	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Content DB IP" );
			$start = new Benchmark;
		}
		
		
	# Check the Content Database for the email from, and the header email from (if it exists)
	if ( ( ( $retcode == 0 )  ||  ( $create_clue_file ) )  &&  ( $use_contentdb ) )
		{	my $blocked_url;
			my $virus;
			
			( $retcode, $blocked_url, $virus ) = &ContentDBCheck( $email_from, $header_email_from );
		  
			if ( ( $virus )  &&  ( $retcode ) )
				{	$result = "VIRUS";
					$msg = &BuildSpamReason( "Virus or Spyware URL", "Blocked URL: $blocked_url", $result );				
				}
			elsif ( $retcode )	# If it is spam by this test - hold on until later to return this result
				{	$contentdb_spam_url = $blocked_url;	# Hold onto the url that is a spam url until I do some other checking
					$retcode = 0 + 0;	# Reset the return code to nothing - for now ...
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Content DB URL" );
			$start = new Benchmark;
		}
		
		
	# Check the for dangerous URLs 
	# Don't do this check if the message is white listed
    if ( ( $retcode == 0 )  &&  ( ! $virus_only ) )
		{	my $blocked_url;
			( $retcode, $blocked_url ) = &DangerousURLCheck() if ( $use_contentdb );
		  
			if ( $retcode )
				{	$result = "VIRUS";
					$msg = &BuildSpamReason( "Dangerous URL", "Blocked URL: $blocked_url", $result );				
				}		  
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Dangerous URL Check" );
			$start = new Benchmark;
		}
		

	# Did I find a virus? If so, should I put an example into the virus example directory?
	if ( ( $retcode != 0 )  &&  ( $result eq "VIRUS" )  &&  ( $virus_example )  &&  ( ! $opt_filename ) )
		{	&VirusExample( $virus_name, $file );
		}
		

	# Did I find a virus?  If so, should I delete or quarantine the file?
	if ( ( $retcode != 0 )  &&  ( $result eq "VIRUS" ) )
		{	if ( $quarantine )
				{	&QuarantineFile( $file );  
				}
			elsif ( $opt_unlink ) # Delete the file if there was a virus in it
				{	unlink( $file );
					$unlink_count++;					
				}    
		}
	
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Virus Example & Quarantine" );
			$start = new Benchmark;
		}
		

	#  Can I check the email addresses right now?
	#  Is it a message to/from Lightspeed?
	if ( $retcode == 0 )
		{	$retcode += &LightspeedAdmin( $email_from, $subject, @envelope_to_no_pseudo );
			
			if ( $retcode ) 
				{	$msg = "Lightspeed Systems Admin Message";
					$result = "HAM";
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Lightspeed Systems Admin" );
			$start = new Benchmark;
		}
		

	# Am I just checking for viruses?	If so, bail out here  
	return( $retcode, $result, $msg ) if ( $virus_only );



#################################################################################
################  Start of actual spam blocking techniques  #####################
#################################################################################



	if ( ( $retcode == 0 )  &&  ( $use_valid_email_to ) )
		{	$retcode = &ValidEmailTo( @envelope_to );  #  This should return a non-zero if none of email to: addresses are valid
			
			# Was I not able to find any valid email addresses?
			if ( $retcode  )
				{	$result = "SPAM";
					
					$email_to = "blank" if ( ! $email_to );
					
					if ( $use_valid_email_table )
						{	$msg = &BuildSpamReason( "To: addresses not in ValidEmailAddresses table", "To: $email_to", $result );							
						}
					else
						{	$msg = &BuildSpamReason( "To: addresses not in SpamUserPreferences table", "To: $email_to", $result );							
						}
				}
				
			if ( $opt_benchmark )
				{	my $finish = new Benchmark;
					&TimedBenchmark( $start, $finish, "Valid Email TO: Check" );
					$start = new Benchmark;
				}
		}


	#  Should I block this message based on the size of the message?
	if ( ( $retcode == 0 )  &&  ( $block_large_messages ) )
		{	my $size = -s $file;
			
			if ( ( $size )  &&  ( $block_large_messages )  &&  ( $size > $block_large_messages ) )
				{	$retcode = 1;
					$result = "SPAM";
					$msg = &BuildSpamReason( "Message is too large", "Message Size: $size", $result );							
				}
		}
	
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Block Large Messages" );
			$start = new Benchmark;
		}
				
	
	#  Should I block this message because it has too many attachments?
	if ( ( $retcode == 0 )  &&  ( $maximum_attachments ) )
		{	if ( $attachment_count >= $maximum_attachments )
				{	$retcode = 1;
					$result = "SPAM";
					$msg = &BuildSpamReason( "Message has too many attachments", "Attachment count: $attachment_count", $result );							
				}
		}
	
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Too Many Attachments" );
			$start = new Benchmark;
		}
				
	
	#  Is the user preferences set to not block spam?
	my @not_block_spam;	# This is the list of email TO: addresses that are set to not block spam
	if ( ( $retcode == 0 )  &&  ( $use_user_preferences ) )
		{	foreach ( @envelope_to )
				{	my $check_email = $_;
					next if ( ! defined $check_email );
					
					# Ignore the user preferences for special addresses
					next if ( &SpecialAddresses( $check_email ) );
							 
					my $ret = &UserPreferences( $check_email );  #  This should return a -1 if it is listed
			        next if ( ! $ret );
					next if ( $ret != -1 );
					
					# I must have found a match for no spam blocking
					push @not_block_spam, $check_email;
				}
		
			# If all the TO: addresses are set to not block spam, then call it ham
			if ( ( $#not_block_spam > -1 )  &&  ( @not_block_spam == @envelope_to ) )	
				{	$retcode = -1;
					$msg = "User Preferences set to No Spam Block";
					$result = "HAM";
					$retcode = 0 - 1;
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "User Preferences" );
			$start = new Benchmark;
		}
				

	#  Does one or more of the email TO: addresses have this FROM: address on their autowhite list?
	my @autowhite_listed;		# This is the list of TO: addresses that have this from email address autowhite listed
	if ( ( $retcode == 0 )  &&  ( $use_autowhitelist ) )
		{	foreach ( @envelope_to )
				{	my $check_email = $_;
					next if ( ! defined $check_email );
					
					# Don't autowhitelist any email to one of the special addresses
					next if ( &SpecialAddresses( $check_email ) );
					
					my $ret = &AutoWhiteList( $email_from, $check_email );  #  This should return a -1 if it is listed
			        next if ( ! $ret );
					next if ( $ret != -1 );
					
					# I must have found a match for autowhite listed
					push @autowhite_listed, $check_email;
				}
				
			# If all the TO: addresses have this FROM: address autowhite listed, then call it ham
			if ( ( $#autowhite_listed > -1 )  &&  ( @autowhite_listed == @envelope_to ) )	
				{	$msg = "Personally Allowed";
					$result = "HAM";
					$retcode = 0 - 1;
				}
				
			# If the original email TO: has this FROM: address autowhite listed, then also call it ham	
			elsif ( &AlreadyListed( $email_to, \@autowhite_listed ) )
				{	$msg = "Personally Allowed";
					$result = "HAM";
					$retcode = 0 - 1;
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Auto White List" );
			$start = new Benchmark;
		}
		
		
	#  Is it on the auto black list?
	my @autoblack_listed;
	my @not_autoblack_listed;
	if ( ( $retcode == 0 )  &&  ( $use_autoblacklist ) &&  ( ! defined $overrides_only ) )
		{	# Check the to list and the cc list for an auto black list entry
			foreach ( @envelope_to )
				{	my $check_email = $_;
					next if ( ! defined $check_email );
					next if ( &SpecialAddresses( $check_email ) );
					
					my $ret = &AutoBlackList( $email_from, $check_email );  #  This should return a 1 if it is listed, 0 if no autoblack list at all, or -1 if not autoblack listed
			        
					# Is the autoblack list even there?
					next if ( ! $ret );
					
					# If this to: address doesn't have it auto black listed, then keep track with the not_autoblack list
					if ( $ret == -1 )
						{	push @not_autoblack_listed, $check_email;
							next;
						}
					
					# I must have found a match for autoblack listed
					push @autoblack_listed, $check_email;
				}
				
			# If all the TO: addresses have this FROM: address autoblack listed, then call it spam
			if ( ( $#autoblack_listed > -1 )  &&  ( @autoblack_listed == @envelope_to ) )	
				{	$msg = "Personally Blocked By All Recipients";
					$result = "SPAM";
					$retcode = 0 + 1;
				}				
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Auto Black List" );
			$start = new Benchmark;
		}
		
	
	#  Does it match any of our spam patterns?
	if ( ( $retcode == 0 )  &&  ( $use_spam_patterns ) )
		{	my $spam_pattern_name;
			( $retcode, $spam_pattern_name ) = &SpamPatterns();  #  This should return a -1 ham, +1 if spam

			if ( $retcode )
				{	$result = "HAM" if ( $retcode == ( 0 - 1 ) );
					$result = "SPAM" if ( $retcode == ( 0 + 1 ) );
					$msg = &BuildSpamReason( "Spam Pattern", "Name: $spam_pattern_name", $result );							
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Spam Patterns" );
			$start = new Benchmark;
		}
		
		
	#  Does the subject line contain adult phrases?
	if ( $retcode == 0 )
		{	my $adult_phrase;
			
			( $retcode, $adult_phrase ) = &AdultSubject( $subject ) if ( $use_adult_subjects );
			
			if ( $retcode )
				{	$result = "SPAM";
					$msg = &BuildSpamReason( "Adult Subject", "Adult Phrase: $adult_phrase", $result );							
				}
		}			

	
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Adult Subject" );
			$start = new Benchmark;
		}
		
		
	# Did I find a blocked URL earlier when I was looking for virus URLs?	
	if ( ( $retcode == 0 )  &&  ( $use_contentdb )  &&  ( $contentdb_spam_url ) )
		{	$retcode = 0 + 1;	# Mark it as spam now that is has passed the eariler tests
			$result = "SPAM";
			$msg = &BuildSpamReason( "Blocked or Spam URL", "Blocked URL: $contentdb_spam_url", $result );		
		}
		
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "ContentDB Spam Check" );
			$start = new Benchmark;
		}
		
		
	# Check Bayesian analysis	
    if ( $retcode == 0 )
      {   my $bayes_result;
		  ( $retcode, $bayes_result ) = &BayesianAnalyzeFile() if ( $use_bayesian );
		  
		  if ( $retcode )
			{	$result = "SPAM";
				$msg = &BuildSpamReason( "Bayesian Statistics", $bayes_result, $result );				
			}
      }


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Bayesian analysis" );
			$start = new Benchmark;
		}
		
		
	# Does it look like this is a forged administration address?
	if ( ( $retcode == 0 )  &&  ( $check_forged ) )
		{
			$retcode += &CheckForged( $original_email_from, $email_to );
		  
			if ( $retcode )
				{	$result = "SPAM";
					$msg = &BuildSpamReason( "Forged Email From Address", $email_from, $result );				
				}		  
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Forged Email From Address" );
			$start = new Benchmark;
		}
		
		
	# Can I use SPF to decide if the email_from is forged?
	# Don't check SPF if the external IP address source number is 1 or 2
	if ( ( $retcode == 0 )  &&  
		( $use_spf )  &&  
		( ( ! $external_ip_address_source )  ||  ( $external_ip_address_source > 2 ) ) )
		{	my ( $spf_result ) = &SPFTest( $email_from, $external_ip_address, $hostname, $opt_debug );  #  This should return a +1 if it is a forged email_from

			if ( $spf_result == 1 )
				{	$retcode = 0 + 1;
					$result = "SPAM";
					$msg = &BuildSpamReason( "SPF Test", "Email $email_from from $external_ip_address is not valid", $result );							
					my $changed = &ChangeDatabaseIPAddress( $external_ip_address, 1 );
					lprint "Set $external_ip_address to spam because it failed the SPF test\n" if ( $changed );
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "SPF Test" );
			$start = new Benchmark;
		}
		
		
    # Don't do this check if running from the command line
	if ( ( $retcode == 0 )  &&  ( ! $opt_filename )  &&  ( $use_greylist ) && ( ! defined $overrides_only ) )
		{	#  This should return a retcode of greater than 1 if it wants to temp block the email
			$retcode += &AutoGreyList( $email_from, $email_to, $file, $external_ip_address );
		  
			if ( $retcode )
				{	$msg = "Possible spam - temporarily grey listed";
					$result = "GREY";
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Auto Grey List" );
			$start = new Benchmark;
		}
		
 	
	# Is this email from a network with a bad reputation and the IP address is in the database?
	if ( ( $retcode == 0 )  &&  
		( defined $external_ip_address )  &&  
		( $use_network_reputation ) )
		{	my $reputation;
						
			# Only do this check if the external IP address is not in the database,
			# or the external IP address is not a hand entry in the database
			# or the external IP address is not in the ham category
			my $check_reputation = 1;
			$check_reputation = undef if ( ( $external_ip_address_source )  &&  ( $external_ip_address_source < 3 ) );
			$check_reputation = undef if ( ( $external_ip_address_source )  &&  ( $external_ip_address_category == 56 ) );
			
			# If I am still checking reputation, see if I know this IP address as some sort of mail
			if ( ( $check_reputation )  &&  ( $external_ip_address_category ) )
				{	my $catname = &CategoryName( $external_ip_address_category );
					$check_reputation = undef if ( ( $catname )  &&  ( $catname =~ m/mail/i ) );
				}
				
			if ( $check_reputation )
				{	( $retcode, $reputation ) = &NetworkReputation( $external_ip_address );
		  
					if ( $retcode )
						{	$result = "SPAM";
							$msg = &BuildSpamReason( "Bad Network Reputation", $reputation, $result );				
						}	
				}
		}
		
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Network Reputation" );
			$start = new Benchmark;
		}
		
		
    # Don't do this check if running from the command line, or if there is no email_from
	if ( ( $retcode == 0 )  &&  ( $use_challenge ) && ( ! defined $overrides_only ))
		{	#  This should return a retcode of 1 if it wants to block the email
			$retcode += &ChallengeEmail( $email_from, $original_email_from, $file, $subject, @envelope_to_no_pseudo );
		  
			if ( $retcode )
				{	$result = "SPAM";
					
					# Handle the different cases that this could be spam
					if ( ( ! defined $email_from )  ||  ( $email_from =~ m/noreply/ ) )
						{	$msg = &BuildSpamReason( "Challenge email failed", "blank, noreply, or invalid email from: address", $result );
						}
					elsif ( ( $email_from =~ m/^postmaster\@/i )  ||  ( $email_from =~ m/^mailer-daemon\@/i )  ||  ( $email_from =~ m/^bounce\@/i ) )
						{	$msg = &BuildSpamReason( "Challenge email failed", "postmaster, mailer-daemon, or bounce email from: address", $result );
						}
					elsif ( ( defined $email_to )  &&  ( $email_from eq $email_to )  &&  ( $#envelope_to < 1 ) )
						{	$msg = &BuildSpamReason( "Challenge email failed", "from: and to: addresses are the same", $result );
						}
					else
						{	$msg = &BuildSpamReason( "Challenge email sent", "$email_from is unknown so challenging it", $result ) if ( defined $email_from );
							$result = "CHALLENGE";
						}
				}
		}


	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Challenge Email" );
			$start = new Benchmark;
		}
		
 	
	# If the result is spam, but I have some email addresses on the not block list, then
	# go ahead and mark the file as spam, but forward it to the people who had their user 
	# preferences set to not block spam.  Also don't do this if running from a command line
	if ( ( $retcode == 1 )  &&  ( $#not_block_spam > -1 )  &&  ( ! $opt_filename ) )
		{	&lprint( "Emailing spam file $file to not block spam list ...\n" );
			my $ok = &MailFile( $file, $email_from, @not_block_spam );
			&lprint( "Error emailing file\n" ) if ( ! $ok );
		}
	# If the result is HAM, but I've been asked to override, and there are some people who have their
	# user preferences marked to NOT block spam, then go ahead and forward the email to the list of
	# not_block_spam people.
	elsif ( ( $retcode == -1 )  &&  ( $overrides_only )  &&  ( $#not_block_spam > -1 )  &&  ( ! $opt_filename ) )
		{	&lprint( "Emailing spam file $file to not block spam list ...\n" );
			my $ok = &MailFile( $file, $email_from, @not_block_spam );
			&lprint( "Error emailing file\n" ) if ( ! $ok );
		}
		
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Not Block List Mailing" );
			$start = new Benchmark;
		}
		
 	
	# If the result is spam, but I have some email addresses that have autowhited listed this sender
	# go ahead and mark the file as spam, but forward it to the people who had it autowhite listed
	# Don't do this if running from a command line
	if ( ( $retcode == 1 )  &&  ( $#autowhite_listed > -1 )  &&  ( ! $opt_filename ) )
		{	&lprint( "Emailing spam file $file to autowhite list ...\n" );
			my $ok = &MailFile( $file, $email_from, @autowhite_listed );
			&lprint( "Error emailing file\n" ) if ( ! $ok );
		}
		
		
	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Autowhite List Mailing" );
			$start = new Benchmark;
		}
		
 	
	# If the result is NOT spam, but I have some people who have auto black listed the sender, and some
	# people who didn't autoblack list the sender, then mark the email as spam, but forward the mail to the
	# people who did NOT have the sender auto black listed.
	# Don't actually forward the mail if running from a command line
	if ( ( $retcode == 0 )  &&  ( $#autoblack_listed > -1 )  &&  ( $#not_autoblack_listed > -1 ) )
		{	if ( ! $opt_filename )
				{	&lprint( "Emailing file $file to NOT autoblack list @not_autoblack_listed ...\n" );
					my $ok = &MailFile( $file, $email_from, @not_autoblack_listed );
					&lprint( "Error emailing file\n" ) if ( ! $ok );
				}
				
			$retcode = 0 + 1;
			$result = "SPAM";
			$msg = "Personally Blocked By Some Recipients";							
		}

	if ( $opt_benchmark )
		{	my $finish = new Benchmark;
			&TimedBenchmark( $start, $finish, "Autoblack List Mailing" );
			# $start = new Benchmark; Don't need to do a start on the last benchmark
		}
		
 	
	my $ret = &AnalyzeFileConclusion( $file, $result, $msg, $retcode );
	
	return( $ret );	
 }



################################################################################
#
sub ChangeDatabaseIPAddress( $$ )
#
#  Change the category of an IP address to spam
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
		{	&AddNewTrans( $ip_addr, $change_catnum, 0, 3 );
			return( 1 );
		}
	
	
	# If it is in the database, is it set by hand, and so can't be changed?
	my ( $catnum, $source )  = &FindCategory( $ip_addr, $retcode );
	return( undef ) if ( $source < ( 0 + 3 ) );
	
	
	# Is it already set to the right thing?
	return( undef ) if ( $catnum == $change_catnum );
	
	
	# If the IP address is spam, it can also work if it is a blocked spam category
	my $catname = &CategoryName( $catnum );
	return( undef ) if ( ( $spam )  &&  ( $catname )  &&  ( &SpamBlockedCategoryName( $catname ) ) );
	
	
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
	  


################################################################################
#
sub AnalyzeFileConclusion( $$$$ )
#
#  Now that I've got a conclusion - write it out the the correct file and/or pipe
#  Return 0 if not spam, 1 if spam
#
################################################################################
{	my $file	= shift;	# Filename
	my $result	= shift;	# Result could be SPAM, HAM, GREY, VIRUS, or blank
	my $msg		= shift;	# Related message to the result
	my $retcode = shift;	# Retcode is 1 if spam, -1 if ham, 0 if undetermined - which is ham at this point
	
	
    &debug( "AnalyzeFile Conclusion\n" );
	
	
   # If it is spam or ham, should I do something with it?
    if ( $retcode == 1 )
       {	unlink( $file ) if ( $opt_delete_spam );
			&CopyFile( $file ) if ( $opt_copy );
       }
	elsif ( $opt_delete_ham )
		{	unlink( $file );
		}


    if ( $retcode == 0 )  # Set the message to blank and result to OK if retcode is 0
		{	$msg = undef;
			$result = "OK";
		}
	  
	  
    #  Return here if I am just doing a summary of spam and ham
    if ( $opt_summary )
		{   if ( ( $msg )  &&  ( $retcode != 0 ) )
				{   my ( $reason, $specific ) = split /===/, $msg, 2;
				 
					if ( !$summary{ $reason } )
						{  $summary{ $reason } = 0 + 1;
						}
					else  
						{  $summary{ $reason } += 0 + 1;
						}
				}

			return( 0 + 1 ) if ( $retcode > 0 ); 
		  
			return( 0 + 0 );
		}
	
	
    #  Write out the conclusion
    if ( $opt_filename )
		{	&oprint( "Result: $result\n" );
			&oprint( "Reason: $msg\n" ) if ( $msg );
			&debug( "\n" );
			
			&CreateClueFile( $file, $result, $msg, $retcode ) if ( $create_clue_file );
		}
    else
		{   # Log the results
			if ( $opt_debug )
				{	&oprint( "Result: $result\n" );
					&oprint( "Reason: $msg\n" ) if ( $msg );
				}
				
			&PipeWrite( $file, $result, $msg );
		}

    return( 0 + 1 ) if ( $retcode > 0 ); 
	
    return( 0 + 0 );
	
}



################################################################################
#
sub CreateClueFile( $$$$ )
#
#  Create a clue file containing all the data I've gathered about this message file
#
################################################################################
{	my $file	= shift;	# Filename
	my $result	= shift;	# Result could be SPAM, HAM, GREY, VIRUS, or blank
	my $msg		= shift;	# Related message to the result
	my $retcode = shift;	# Retcode is 1 if spam, -1 if ham, 0 if undetermined - which is ham at this point
	
	
	# Don't do anything if I'm not supposed to
	return( undef ) if ( ! $create_clue_file );
	
	
    &debug( "CreateClueFile\n" );
	return( undef ) if ( ! $file );
	
	my @keys = sort keys %clues;
	
	# If I don't have any clues then return
	return( undef ) if ( $#keys < 0 );

	my ( $method, $method_value ) = split /===/, $msg if ( defined $msg );
	
	$method =~ s/\s+$// if ( $method );
	$method_value =~ s/^\s+// if ( $method_value );

	my $str_ip = $clues{ "EXTERNAL-IP" };

	# Clean up the method and method values as much as possible
	if ( defined $method )
		{	$method =~ s/^OK //;
			$method =~ s/^Spam //;
			$method =~ s/\(Realtime Spam Checker\)// if ( $method );
			$method =~ s/\(//g if ( $method );
			$method =~ s/\)//g if ( $method );
			
			$method =~ s/^\s+// if ( $method );
			$method =~ s/\s+$// if ( $method );
			$method = "Spam Pattern" if ( ( $method )  &&  ( $method =~ m/Pattern/ ) );
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Sender / ) )
		{	( $method, $method_value ) = split ' ', $method, 2;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Recipient / ) )
		{	( $method, $method_value ) = split ' ', $method, 2;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Adult Subject / ) )
		{	$method_value = $method;
			$method_value =~ s/^Adult Subject //;
			$method = "Adult Subject";
		}
		
	if ( ( defined $method_value )  &&  ( $method_value =~ m/^Blocked URL\:/ ) )
		{	$method_value =~ s/Blocked URL\://;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Content DB IP/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Unresolvable/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Domain/ ) )
		{	( $method, $method_value ) = split ' ', $method, 2;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^IP/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Auto White Listed/ ) )
		{	$method_value = $clues{ "FROM" };
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^RBL IP/ ) )
		{	$method_value = $str_ip;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Realtime Spam Checker - Virus / ) )
		{	$method =~ s/Realtime Spam Checker - Virus //;
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Spam Pattern/ ) )
		{	$method_value =~ s/Name\: // if ( $method_value );
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Dangerous Attachment/ ) )
		{	$method_value =~ s/Attachment\: // if ( $method_value );
			$method_value =~ s/\s+//g if ( $method_value );
		}
		
	if ( ( defined $method )  &&  ( $method =~ m/^Virus Infected/ ) )
		{	$method_value =~ s/Virus\: // if ( $method_value );
			my $company;
			( $method_value, $company ) = split /\s/, $method_value, 2 if ( $method_value );
		}

	if ( ( defined $method )  &&  ( $method =~ m/^Challenge email sent/ ) )
		{	$method_value =~ s/ is unknown so challenging it// if ( $method_value );
		}


	# Clean up leading and trailing white space		
	$method =~ s/^\s+// if ( $method );
	$method =~ s/\s+$// if ( $method );

	$method_value =~ s/^\s+// if ( $method_value );
	$method_value =~ s/\s+$// if ( $method_value );
		
		
	my $clue_filename = $file . ".clue";
	
	open( CLUE, ">$clue_filename" ) or return( undef );
	
	print CLUE "FILE: $file\n";
	print CLUE "RESULT: $result\n"	if ( $result );
	print CLUE "METHOD: $method\n" if ( $method );
	print CLUE "METHOD VALUE: $method_value\n"	if ( $method_value );
	print CLUE "CLUES:\n";
	
	
	foreach ( @keys )
		{	my $key = $_;
			next if ( ! $key );
			
			my $value = $clues{ $key };
			next if ( ! $value );
			
			my @values = split /\n/, $value;
			
			foreach ( @values )
				{	my $val = $_;
					next if ( ! $val );
					
					print CLUE "$key\t$val\n";
					print "$key\t$val\n" if ( $opt_debug );
				}
		}
		
	close( CLUE );
		
	return( undef );
}



################################################################################
#
sub ValidEmailTo( @ )
#
#  Given the combined list from the envelope and the message header, return 0 if it
#  is ok, 1 if it doesn't contain any valid to: addresses
#
################################################################################
{	my @list = @_;

	# Should I even do this check?
	return( 0 + 0 ) if ( ! $use_valid_email_to );
	
	# It's spam if there is no to list at all
	return( 0 + 1 ) if ( $#list < 0 );
	
	&debug( "ValidEmailTo: combined list = @list\n" );

	# Check each address, and return 0 + 0 if even one is ok
	foreach ( @list )
		{	next if ( ! $_ );
			
			my $to = $_;
			
			next if ( &SpecialAddresses( $to ) );
			
			# Did I just look this guy up the the spam user preferences?
			return( 0 + 0 ) if ( ( $last_valid_email_to )  &&  ( $to eq $last_valid_email_to ) );
			
			
			# Does it match any domain wildcard?
			foreach ( @wildcard_email_to )
				{	next if ( ! $_ );
					
					my $wildcard = lc( $_ );
					
					if ( $to =~ m/$wildcard/ )
						{	&debug( "Matched the email to: address to $wildcard\n" );
							return( 0 + 0 );
						}
				}
				
				
			# If I've gotten to here, check to see if the username exists in the spam user preferences
			my $database_email_address;
			
			
			# Should I use the ValidEmailAddresses table?
			if ( $use_valid_email_table )
				{	$dbh = &SqlErrorCheckHandle( $dbh );
					my $sth = $dbh->prepare( "SELECT Email from ValidEmailAddresses WITH(NOLOCK) WHERE Email = ?" );
					$sth->bind_param( 1, $to,  DBI::SQL_VARCHAR );
					
					$sth->execute();
					
					( $database_email_address ) = $sth->fetchrow_array() if ( ! $dbh->err );
					
					&SqlErrorHandler( $dbh );
					$sth->finish();
					
					&debug( "Found $database_email_address in the ValidEmailAddresses table\n" ) if ( $database_email_address );
				}
			else	# Or use the spam user preferences table
				{	$dbh = &SqlErrorCheckHandle( $dbh );
					my $sth = $dbh->prepare( "SELECT UserName from SpamUserPreferences WITH(NOLOCK) WHERE UserName = ? AND Domain IS NULL" );
					$sth->bind_param( 1, $to,  DBI::SQL_VARCHAR );
					
					$sth->execute();
					
					( $database_email_address ) = $sth->fetchrow_array() if ( ! $dbh->err );
					
					&SqlErrorHandler( $dbh );
					$sth->finish();
					
					&debug( "Found $database_email_address in the SpamUserPreferences table\n" ) if ( $database_email_address );
				}
				
			
			# If I found to to: address in the SpamUserPreference or the ValidEmailAddresses table, 
			# then it is a valid to:
			return( 0 + 0 ) if ( $database_email_address );	
		}


	&debug( "Did not find a valid email to: address\n" );

	# If I got to here, then I never found a match	   
	return( 0 + 1 );
}



################################################################################
#
sub LoadWildcardEmailTo()
#
#  If validating email to addresses, load from the database any domains that I
#  should allow all email tos
#
################################################################################
{	# Empty the list
	@wildcard_email_to = ();
	
	return( undef ) if ( ! &SqlTableExists( "ValidEmailAddresses" ) );
	
	&oprint( "Loading valid email wildcards from the ValidEmailAddresses table ...\n" );

	$use_valid_email_table = 1;
	
	my $str = "SELECT Email FROM ValidEmailAddresses WITH(NOLOCK) WHERE Email like \'%*%\'";

	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( $str );
	
	$sth->execute();

	my $counter = 0 + 0;

	while ( ( ! $dbh->err )  &&  (  my ( $domain ) = $sth->fetchrow_array() ) )
		{	next if ( ! $domain );
            
			next if ( ! $domain );
			$domain = lc( $domain );
			
			my $reg = &ValueToRegExpression( $domain );
            next if ( ! $reg );
			
			push @wildcard_email_to, $reg;
            $counter += 0 + 1.0;
		}

	&SqlErrorHandler( $dbh );
	$sth->finish();

	&oprint( "Loaded $counter valid email wildcards\n" );
	
	return( 1 );
}



################################################################################
#
sub TimedBenchmark( $$$ )
#
#  Given the start time, the finish time, and the key, save the benchmark time
#
################################################################################
{	my $start	= shift;
	my $finish	= shift;
	my $key		= shift;
	
	return if ( ! $opt_benchmark );
	
	my $diff = timediff( $finish, $start );

	my $total = $diff;
	
	if ( defined $benchtime{ $key } )
		{	my $subtotal = $benchtime{ $key };
			$total = Benchmark::timesum( $subtotal, $diff ) ;
		}
		
	$benchtime{ $key } = $total;
}



################################################################################
#
sub BuildSpamReason($$$)
#
#  Given the reason a message is spam, and the specifics, build the msg to return
#
################################################################################
{	my $reason		= shift;
	my $specific	= shift;
	my $result		= shift;
	
	my $msg = $reason;
	
	my $cutoff = 36;
	$cutoff = 28 if ( $result =~ m/VIRUS/ );  # Brock adds the phrase " - Virus" if a virus - which is 8 chars longer
	$cutoff = 36 if ( $opt_filename );
	
	for ( my $i = length( $msg );  $i < $cutoff;  $i++ )
		{  $msg .= " ";
		}
		
	$msg .= "=== " . $specific;
	
	
	# Convert % to dashes
	if ( $msg =~ m/%/ )
		{	$msg =~ s/\%/\-/gm;
		}
		
	return( $msg );			
}



################################################################################
################################################################################
################################################################################
######################  Command Line Only Spam Checking  #######################
################################################################################
################################################################################
################################################################################



################################################################################
#
sub ContentIpAddress( $ )
#
#  Given the external IP address, it is blocked in the content database?
#  Return 0 if it isn't, 1 if it is ...
#  Return the source number if I know it
#  Also return if it is a virus IP address, or not
#  Also return the category number if I know it
#
################################################################################
{	my $ipaddress = shift;

	&debug( "ContentIpAddress check\n" );
	
	return( 0 + 0, undef, undef, 0 + 0 ) if ( ! $ipaddress );
		
	my $retcode = &LookupUnknown( $ipaddress, 0 );
	&AddClue( "IP", $ipaddress );	
	
	
	# Should I check to see if it is a proxy mail server or a blocked IP address?
	if ( ! $retcode )
		{	&ProxyTest( $ipaddress ) if ( $use_proxy );	
			return( 0 + 0, undef, undef, 0 + 0 );
		}
		
					
	# Now get the category name
	my ( $catnum, $source ) = &FindCategory( $ipaddress, $retcode );

	my $catname = &CategoryName( $catnum );
	return( 0 + 0, $source, undef, 0 + 0 ) if ( ! defined $catname );
	&debug( "Category name = $catname, category number = $catnum\n" );
					
	
	# Return virus if it is in a security category
	return( 0 + 1, $source, 1 , $catnum ) if ( ( $retcode > 0 )  &&  ( &VirusCategory( $catname ) ) );
	
	
	#  If it is spam category blocked, return spam 
	if ( &SpamBlockedCategoryName( $catname ) )
		{	&debug( "External IP addresses is in blocked spam category $catname\n" );
			return( 0 + 1, $source, undef, $catnum );	
		}	
	
	# Return OK
	return( 0 + 0, $source, undef, $catnum );			
}
				
				

################################################################################
#
sub LoadAdultSubjects()
#
#  Load the Adult Subjects list into memory
#
################################################################################
{	my $dir = $opt_dir;

	return if ( ! $dir );
	my $filename = $dir . "\\SpamAdultSubjects.txt";

	if ( ! open FILE, "<$filename" )
		{	&lprint( "Error: unable to open $filename: $!\n" );
			return;	
		}

	@adult_subjects = ();
	
	my $counter = 0 + 0;
	while (my $line = <FILE>)
		{	chomp( $line );
			next if ( ! defined $line );
			$line = quotemeta( $line );
			push @adult_subjects, $line;
			
			$counter++;
		}
		
	&lprint( "Loaded $counter different adult subjects\n" );
	
	close FILE;	
}
				
				
################################################################################
#
sub AdultSubject( $ )
#
#  Given the subject line, does it contain an adult subject?
#  Return 0 if it doesn't, 1 if it does ...
#
################################################################################
{	my $subject = shift;

	return( 0 + 0 ) if ( ! $subject );

	&debug( "AdultSubject check subject = $subject\n" );

use HTML::Entities;
	# Could the subject be encoded?
	my $decoded_subject;
	
	# encoded looks like this =?<Character-Set>?<Encoding>?<Encoded-String>?=
	if ( ( $subject =~ m/=\?/ )  &&  ( $subject =~ m/\?=$/ ) )
        {	my $stuff = $subject;
			$stuff =~ s/\?=$//;
			
			my @parts = split /\?/, $stuff;
			
			my $encoded_subject;

			if ( $#parts >= 0 )
				{	$encoded_subject = $parts[ $#parts ];
				}
				

			# Try quoted printable
			my $quoted_printable = &DecodeQuotedPrintable( $encoded_subject );
			&debug( "AdultSubject quoted_printable = $quoted_printable\n" ) if ( $quoted_printable );

			my $base64 = &DecodeBase64( $encoded_subject );
			&debug( "AdultSubject base64 = $base64\n" ) if ( $base64 );

			$decoded_subject = $quoted_printable if ( ( $quoted_printable )  &&  ( $quoted_printable ne $encoded_subject ) );
			$decoded_subject .= $base64 if ( ( $base64 )  &&  ( $base64 ne $encoded_subject ) );
		}

	&debug( "AdultSubject decoded subject = $decoded_subject\n" ) if ( $decoded_subject );
	
	# Do all compares lowercase
	my $compare = lc( $subject );
	my $html_str = decode_entities( $compare );
	
	# Add the html decoded compare if it is different than the original compare
	$compare .= $html_str if ( $html_str ne $compare );
	
	# Add the decoded subject string if it was decoded
	$compare .= lc( $decoded_subject ) if ( $decoded_subject );
	
	# If there are no changes, assume the IpMagic object has done the compares
	return( 0 + 0 ) if ( ( lc( $subject ) eq $compare )  &&  ( ! $opt_filename ) );
	
	study( $compare );
	
	foreach ( @adult_subjects )
		{	my $pattern = $_;
			
			return( 0 + 1, $pattern ) if ( $compare =~ m/$pattern/ );
		}


	return( 0 + 0, undef );			
}
	
	
				
################################################################################
################################################################################
################################################################################
##########################  File Checking Functions  ###########################
################################################################################
################################################################################
################################################################################



################################################################################
#
sub VirusCheckFile( $ )
#
#  Given a file name, return 1 if it is virus infected, 0 if not
#
################################################################################
{   my $file = shift;
	
    my $retcode;
    my $result;
    my $msg;

    $retcode = 0 + 0;  # Set the retcode to 0 before running any tests


    return( $retcode ) if ( ! defined $file );

	
	( $retcode, $result, $msg ) = &AnalyzeFile( $file, 1, undef );
	  

	if ( $retcode == 0 )  # Set the message to blank and result to OK if retcode is still 0
		{	$msg	= undef;
			$result = "OK";
		}
	
			
    #  Return here if I am just doing a summary of spam and ham
    if ( $opt_summary )
      {   if ( $retcode != 0 )
             {   if ( ! $summary{ $msg } )  
					{	$summary{ $msg } = 0 + 1;  
					}
                 else  
					{	$summary{ $msg } += 0 + 1;  
					}
             }

          return( 1 ) if ( $retcode > 0 ); 
          return( 0 );
      }
	

    &debug( "VirusCheckFile Conclusion\n" );
						
	
    #  Write out the conclusion
    if ( $opt_filename )
      {   bprint "Result: $result\n";
          bprint "Reason: $msg\n" if ( $msg );
      }
    else
      {   # Log the results
		  if ( $opt_debug )
			{	&oprint( "Result: $result\n" );
				&oprint( "Reason: $msg\n" ) if ( $msg );
			}
			
		  &PipeWrite( $file, $result, $msg );
      }

    return( 1 ) if ( $retcode > 0 ); 
    return( 0 );
}



################################################################################
#
sub AttachedFilesCheck( @ )
#
#  Check to see if the email has a dangerous attachment - just based on the
#  attachment name
#  Return 1 and the attachment name if a problem, 0 if not
#
################################################################################
{	my @file_list = @_;
	
	foreach ( @file_list )
		{	next if ( ! $_ );
			
			my $filename = lc( $_ );
			
			&debug( "Attached file name = $filename\n" );
			
			foreach ( @bad_list )
				{	next if ( ! defined $_ );
					
					my $pattern = quotemeta( $_ );
					
					if ( $filename =~ m/$pattern/ )
						{	return( 0 + 1, $filename );
						}
				}
			
			# Some dangerous programs get mailed around with variations of these names
			if ( $filename =~ m/\.exe$/ )	
				{	return( 0 + 1, $filename ) if ( $filename =~ m/^details/ );
					return( 0 + 1, $filename ) if ( $filename =~ m/^document/ );
					return( 0 + 1, $filename ) if ( $filename =~ m/^jokes4/ );
					return( 0 + 1, $filename ) if ( $filename =~ m/postcard/ );
				}
			
			my $ext = &FileExtension( $filename );
			
			if ( defined $ext )
				{	my $qext = quotemeta( "." . $ext . "." );
					return( 0 + 1, $filename ) if ( $bad_extensions =~ m/$qext/ );
				}
				
			
			# Look for tabs, newlines, or repeated spaces before an executable extension
			my $whitespace = 1 if ( $filename =~ m/\s{5,}/ );  # Look for 5 or more repeated white spaces before an executable file name
			$whitespace = 1 if ( $filename =~ m/\_{5,}/ );		# Look for 5 or more repeated underscores before an executable file name
			$whitespace = 1 if ( $filename =~ m/\t/ );
			$whitespace = 1 if ( $filename =~ m/\n/ );
			$whitespace = 1 if ( $filename =~ m/\r/ );
			$whitespace = 1 if ( $filename =~ m/\f/ );
			
			if ( ( $whitespace )  &&  ( defined $ext ) )
				{	if ( $ext eq "exe" )
						{	return( 0 + 1, $filename );					
						}
						
					if ( $ext eq "com" )
						{	return( 0 + 1, $filename );					
						}
					
					if ( $ext eq "sys" )
						{	return( 0 + 1, $filename );					
						}						
				}
		}
		
	return( 0 + 0, undef );
}



################################################################################
#
sub LightspeedAdmin( $$@ )
#
#  Check to see if the email from: is some sort of Lightspeed Admin message
#  Return -1 if it is, 0 if not
#
################################################################################
{	my $email_from	= shift;
	my $subject		= shift;
	my @email_to	= @_;
   
	my $original_email_to;
	my $original_email_from;
	my $external_ip_address;


	# If the email isn't from a Lightspeed admin address, then it doesn't need this processing
	return( 0 + 0 ) if ( ! defined $email_from );


	# Now put the first email to: address into a string for comparisons
	my $email_to = $email_to[ 0 ];
	return( 0 + 0 ) if ( ! defined $email_to );
	

	# Could this message be a bouncing challenge email?  A challenge was sent from another TTC box and was bounced back
	# I should be able to tell by the subject line
	if ( ( defined $subject )  &&  ( $use_challenge )  &&  ( $email_to ne $challenge_email_from ) )
		{	return( 0 - 1 ) if ( $subject =~ m/$challenge_id/ );
		}
		
		
	# Is this email to or from one of our special addresses?
	my $special = 0 + 0;
	foreach ( @special_addresses )
		{	next if ( ! defined $_ );
			
			my $special_address = $_;
			
			$special = ( 0 - 1 ) if ( ( defined $email_to )  &&  ( $special_address eq $email_to ) );
			$special = ( 0 - 1 ) if ( $special_address eq $email_from );
		}
		
	return( 0 + 0 ) if ( ! $special );
   
   
	# If this message is to multiple people at Lightspeed, then it is not an admin message
	# A valid Lightspeed message will only be to one person at Lightspeed - but it could be to multiple people in other domains
	if ( $#email_to > 0 )
		{	my $count = 0 + 0;
			foreach ( @email_to )
				{	next if ( ! defined $_ );
					$count++ if ( $_ =~ m/lightspeedsystems/ );
				}
			
			return( 0 + 0 ) if ( $count > 1 );
		}
		
	
	# At this point it is one of our messages
	&debug( "LightspeedAdmin\n" );


	# Is it a challenge response?  I have a lot of tests to make sure that this is so
	if ( ( $use_challenge )  &&  ( $email_to eq lc( $challenge_email_from ) ) )
		{	my $original_to;
			my $valid_response = 1;	# Set this to undef if along the way one of my tests fails
			
			my $look_deeper;
			foreach ( @data )
				{	my $line = $_;
					next if ( ! defined $line );
					
					if ( $line =~ m/Original To:/ )
						{
							my ( $junk, $stuff ) = split /Original To:/, $line, 2;
							$original_to = $stuff;
							$original_to =~ s/\s//g;
							$original_to = &CleanEmail( $original_to );
							
							# Do I need to look deeper on the next line as well?
							$look_deeper = $line if ( ! $original_to );
						}
					elsif ( $look_deeper )
						{	my $both_lines = $look_deeper . $line;
							
							# Split the stuff up on boundaries of < or > and look for a valid email address
							my @possible = split /<|>/, $both_lines;

							foreach ( @possible )
								{	my $possible = $_;
									next if ( ! $possible );
									$original_to = &CleanEmail( $possible );

									last if ( $original_to );
								}

							$look_deeper = undef;	
						}
						
					last if ( $original_to );
				}
				
			
			# A valid challenge response have an original to in the body text
			if ( ! defined $original_to )
				{	&oprint( "Challenge reponse does not have an Original TO: in the body\n" );
					$valid_response = undef;
				}
			
				
			# A valid challenge response will be to just one person
			if ( $#email_to > 0 )
				{	&oprint( "Email to $challenge_email_from has more than one recipient\n" );
					
					my $counter = 0 + 1;
					foreach ( @email_to )
						{	my $challenge_to = $_;
							&oprint( "Challenge recipient $counter: $challenge_to\n" );
							$counter++;
						}
						
					$valid_response = undef;	
				}
			
				
			# Try to make sure that the message isn't some sort of automated bounce message indicating the user doesn't exist
			if ( ( $valid_response )  &&  ( defined $subject ) )
				{	$valid_response = undef if ( $subject =~ m/delivery status/i );
					$valid_response = undef if ( $subject =~ m/failure/i );
					$valid_response = undef if ( $subject =~ m/out of office/i );
					$valid_response = undef if ( $subject =~ m/returned mail/i );
					$valid_response = undef if ( $subject =~ m/user unknown/i );
					$valid_response = undef if ( $subject =~ m/failed/i );
					$valid_response = undef if ( $subject =~ m/daemon/i );
					$valid_response = undef if ( $subject =~ m/bounce/i );
					$valid_response = undef if ( $subject =~ m/undeliver/i );
					
					&oprint( "Challenge response has an invalid subject: $subject\n" ) if ( ! $valid_response );
				}
				
				
			# Do I need to test it further?  Look for the challenge id in the subject or the body
			if ( $valid_response )
				{	my $found_challenge_id;
					
					if ( ( $subject )  &&  ( $subject =~ m/$challenge_id/ ) )
						{	$found_challenge_id = 1;
						}
					else
						{	my $line_counter = 0 + 0;	# Don't look too deep
							foreach ( @data )
								{	my $line = $_;
									next if ( ! $line );
									
									if ( $line =~ m/$challenge_id/ )
										{	$found_challenge_id = 1;
											last;
										}
										
									$line_counter++;
									
									# Bail out early if there is a lot of lines - the real challenge response has about 20 lines
									last if ( $line_counter > 100 );
								}
						}
						
					# If I didn't find the challenge id in the return message, then the odds are that this is just idle spam	
					$valid_response = undef	if ( ! $found_challenge_id );
					
					&oprint( "Challenge response does not have the challenge id: $challenge_id\n" ) if ( ! $valid_response );
				}
				
				
			# If I've tested everything and it passed, then let it fly
			&ChallengeEmailPass( $email_from, $original_to ) if ( $valid_response );
			&oprint( "Email to $challenge_email_from did not match challenge criteria\n" ) if ( ! $valid_response );
		}
		
	# Is it an autoblacklist reply?
	elsif ( $email_from eq "blacklist\@lightspeedsystems.com" )
		{	foreach ( @data )
				{	my $line = $_;
					next if ( ! defined $line );
					
					if ( $line =~ m/Original Sender:/ )
						{
							my ( $junk, $stuff ) = split /Original Sender:/, $line, 2;
							$original_email_from = $stuff;
							$original_email_from =~ s/\s//g;
							$original_email_from = &CleanEmail( $original_email_from );
							
							next if ( ! defined $original_email_to );
							next if ( ! defined $original_email_from );
							
							&debug( "Adding AutoBlack entry from: $original_email_from to: $original_email_to\n" );
							
							&AddAutoBlackEntry( $original_email_from, $original_email_to );
						}
					  
					if ( $line =~ m/Original Recipient\(s\):/ )
						{	my ( $junk, $stuff ) = split /Original Recipient\(s\):/, $line, 2;
							$original_email_to = $stuff;
							$original_email_to =~ s/\s//g;
							$original_email_to = &CleanEmail( $original_email_to );
							
							next if ( ! defined $original_email_to );
							next if ( ! defined $original_email_from );
							
							&debug( "Adding AutoBlack entry from: $original_email_from to: $original_email_to\n" );
							
							&AddAutoBlackEntry( $original_email_from, $original_email_to );
						}
				}
		}	
		
	else	# It might be an autowhitelist reply
		{	foreach ( @data )
				{	my $line = $_;
					next if ( ! $line );
					
					if ( $line =~ m/Original Sender:/ )
						{	my ( $junk, $stuff ) = split /Original Sender:/, $line, 2;
							$original_email_from = $stuff;
							$original_email_from =~ s/\s//g;
							$original_email_from = &CleanEmail( $original_email_from );
							
							next if ( !$original_email_to );
							next if ( !$original_email_from );
							my $comp = $original_email_to . ':' . $original_email_from;
							
							&debug( "Adding AutoWhite entry $comp\n" );
							
							&AddAutoWhiteEntry( $comp );
						}
					  
					if ( $line =~ m/Original Recipient\(s\):/ )
						{	my ( $junk, $stuff ) = split /Original Recipient\(s\):/, $line, 2;
							$original_email_to = $stuff;
							$original_email_to =~ s/\s//g;
							$original_email_to = &CleanEmail( $original_email_to );
							
							next if ( !$original_email_to );
							next if ( !$original_email_from );
							
							my $comp = $original_email_to . ':' . $original_email_from;
							
							&debug( "Adding AutoWhite entry $comp\n" );
							
							&AddAutoWhiteEntry( $comp );
						}
					  
					if ( $line =~ m/External IP Address:/ )
						{	my ( $junk, $stuff ) = split /External IP Address:/, $line, 2;
							$external_ip_address = $stuff;
							$external_ip_address =~ s/\s//g;

							next if ( ! $external_ip_address );
							
							my $retcode = &LookupUnknown( $external_ip_address, 0 );

							next if ( ! $retcode );  #  If the IP address is not in the database, don't add it
							next if ( $retcode > 3 );  # If the ip address is in the database, but allowed, don't change it
							
							my $ham_category = &CategoryNumber( "ham" );
							
							&debug( "Changing External IP Address $external_ip_address to ham category $ham_category\n" );				
							
							# Try to change it to category ham
							&UpdateCategory( $external_ip_address, $ham_category, $retcode, 4 );
						}
				}
		}	

	# Return a -1 - which is processed as a ham
	return( 0 - 1 );
}



################################################################################
################################################################################
################################################################################
########################  Spam Pattern Processing  ##########################
################################################################################
################################################################################
################################################################################



################################################################################
#
sub VirusPatterns()
#
#  Check to see if the current email matches a virus pattern
#  Return 0 if doesn't match anything, or 1 if it matches virus pattern
#
################################################################################
{	&debug( "VirusPatterns\n" );
	
	# At this point I've got an array of clues
	# See if any of the virus patterns match
	
	# Are any virus patterns defined?
	return( 0 + 0, undef ) if ( ! defined $virus_patterns[ 0 ][ 0 ] );
	
	for ( my $i = 0;  $virus_patterns[ $i ][ 0 ];  $i++ )
		{	
			# Does it match all of the pattern?
			my ( $match1, $match2, $match3, $match4 );
			$match1 = &CheckSpamPatterns( $virus_patterns[ $i ][ 2 ], $virus_patterns[ $i ][ 3 ] );			
			$match2 = &CheckSpamPatterns( $virus_patterns[ $i ][ 4 ], $virus_patterns[ $i ][ 5 ] );
			$match3 = &CheckSpamPatterns( $virus_patterns[ $i ][ 6 ], $virus_patterns[ $i ][ 7 ] );
			$match4 = &CheckSpamPatterns( $virus_patterns[ $i ][ 8 ], $virus_patterns[ $i ][ 9 ] );
			
			
			# CheckSpamPatterns returns 1 for a match, but undef for no match.
			my $match_result = $match1;
			
			if ( ( defined $spam_patterns[ $i ][ 3 ] )  &&  ( $spam_patterns[ $i ][ 3 ] =~ m/\\\|$/ ) )
				{	$match_result |= $match2; 
				}
			else
				{	$match_result &= $match2; 
				}
			      
			if ( ( defined $spam_patterns[ $i ][ 5 ] )  &&  ( $spam_patterns[ $i ][ 5 ] =~ m/\\\|$/ ) )
				{	$match_result |= $match3; 
				}
			else
				{	$match_result &= $match3; 
				}  

			if ( ( defined $spam_patterns[ $i ][ 7 ] )  &&  ( $spam_patterns[ $i ][ 7 ] =~ m/\\\|$/ ) )
				{	$match_result |= $match4; 
				}
			else
				{	$match_result &= $match4; 
				}
			    
			    
				# Did I match?  
			if ( $match_result )
				{	my $name = $virus_patterns[ $i ][ 0 ];
					
					my $ret = "$name";
					
					return( 0 + 1, $ret );  # Return a 1 if matches a virus pattern
					return( 0 - 1, $ret );  # Must be ham
				}
		}
		
	return( 0 + 0, undef );
}



################################################################################
#
sub SpamPatterns()
#
#  Check to see if the current email matches a spam pattern
#  Return -1 if it is Ham, 0 if doesn't match anything, or 1 is Spam
#
################################################################################
{	&debug( "SpamPatterns\n" );
	
	# At this point I've got an array of clues
	# See if any of the spam patterns match
	
	# Are any spam patterns defined
	return( 0 + 0, undef ) if ( ! defined $spam_patterns[ 0 ][ 0 ] );
	
	for ( my $i = 0;  $spam_patterns[ $i ][ 0 ];  $i++ )
		{	
			# Does it match all of the patterns?
			my ( $match1, $match2, $match3, $match4 );
			$match1 = &CheckSpamPatterns( $spam_patterns[ $i ][ 2 ], $spam_patterns[ $i ][ 3 ] );			
			$match2 = &CheckSpamPatterns( $spam_patterns[ $i ][ 4 ], $spam_patterns[ $i ][ 5 ] );
			$match3 = &CheckSpamPatterns( $spam_patterns[ $i ][ 6 ], $spam_patterns[ $i ][ 7 ] );
			$match4 = &CheckSpamPatterns( $spam_patterns[ $i ][ 8 ], $spam_patterns[ $i ][ 9 ] );
			
			
			# CheckSpamPatterns returns 1 for a match, but undef for no match.
			my $match_result = $match1;
			
			if ( ( defined $spam_patterns[ $i ][ 3 ] )  &&  ( $spam_patterns[ $i ][ 3 ] =~ m/\\\|$/ ) )
				{	$match_result |= $match2; 
				}
			else
				{	$match_result &= $match2; 
				}
			      
			if ( ( defined $spam_patterns[ $i ][ 5 ] )  &&  ( $spam_patterns[ $i ][ 5 ] =~ m/\\\|$/ ) )
				{	$match_result |= $match3; 
				}
			else
				{	$match_result &= $match3; 
				}  

			if ( ( defined $spam_patterns[ $i ][ 7 ] )  &&  ( $spam_patterns[ $i ][ 7 ] =~ m/\\\|$/ ) )
				{	$match_result |= $match4; 
				}
			else
				{	$match_result &= $match4; 
				}
			    
			    
				# Did I match?  
			if ( $match_result )
				{	my $name = $spam_patterns[ $i ][ 0 ];
					
					my $ret = "$name";
					
					return( 0 + 1, $ret ) if ( $spam_patterns[ $ i ][ 1 ] eq "SPAM" );  # Return a 1 if spam
					return( 0 + 1, $ret ) if ( $spam_patterns[ $ i ][ 1 ] eq "VIRUS" );  # Return a 1 if spam
					return( 0 + 1, $ret ) if ( $spam_patterns[ $ i ][ 1 ] eq "SUSPICIOUS" );  # Return a 1 if spam
					return( 0 - 1, $ret );  # Must be ham
				}
		}
		
	return( 0 + 0, undef );
}



################################################################################
#
sub CheckSpamPatterns( $$ )
#
#  Given the spam pattern type, and the value, does it match the current file?
#  Return True if it does, 0 if not
#
################################################################################
{	my $type	= shift;
	my $value	= shift;
	
	my $match = 0 + 0;
	
	# A blank type is True
	return( 1 ) if ( ( ! defined $type ) || ( !$type ) );
	return( 1 ) if ( ( ! defined $value ) || ( !$value ) );

	# &debug( "CheckSpamPatterns, type = $type, value = $value\n" );
		
	# Make sure the value does not have a trailing OR symbol before the comparison
	# Which is a \| because the value has been run through a quotemeta
	$value =~ s/\\\|$//;

	if ( $type eq "SUBJECT" )
		{	$match = &StrMatch( $clues{ "SUBJECT" }, $value );
		}
	elsif ( $type eq "FROM" )
		{	$match = &StrMatch( $clues{ "FROM" }, $value );
		}
	elsif ( $type eq "TO" )
		{	my $to_list = $clues{ "ENVELOPE TO" };
			my @email_to = split /\,/, $to_list if ( $to_list );
			foreach( @email_to )
				{	next if ( ! defined $_ );
					my $email = lc( $_ );
					$match = &StrMatch( $email, $value );
					last if ( $match );
				}
		}
	elsif ( $type eq "EXTERNAL-IP" )
		{	$match = &StrMatch( $clues{ "EXTERNAL-IP" }, $value );
		}
	elsif ( $type eq "RESOLVED-DOMAIN" )
		{	$match = &StrMatch( $clues{ "RESOLVED-DOMAIN" }, $value );
		}		
	elsif ( $type eq "CONTENT-DESC" )
		{	$match = &StrMatch( $clues{ "CONTENT-DESC" }, $value );
		}
	elsif ( $type eq "CONTENT-TYPE" )
		{	$match = &StrMatch( $clues{ "CONTENT-TYPE" }, $value );
		}
	elsif ( $type eq "ENCODING" )
		{	$match = &StrMatch( $clues{ "ENCODING" }, $value );
		}
	elsif ( $type eq "DISPOSITION" )
		{	$match = &StrMatch( $clues{ "DISPOSITION" }, $value );
		}
	elsif ( $type eq "ATTACH-NAME" )
		{	$match = &StrMatch( $clues{ "ATTACH-NAME" }, $value );
		}
	elsif ( $type eq "URL" )
		{	$match = &StrMatch( $clues{ "URL" }, $value );
		}
	elsif ( $type eq "BODY" )
		{	foreach ( @data )
				{	next if ( ! $_ );
					my $line = $_;
					
					$match = 1 if ( $line =~ m/$value/i );					
					last if ( $match );
				}
		}
	else
		{	&debug( "Unimplemented Spam Pattern Type = $type\n" );		
		}

	# Make sure that I return a '0' and not an undef
	$match = 0 + 0 if ( ! $match );
	
	return( $match );
}



################################################################################
#
sub StrMatch( $$ )
#
#  Given a string, and a string or wildcard string
#  Return True if they match, undef if not
#
################################################################################
{	my $str			= shift;
	my $wildcard	= shift;

	return( undef ) if ( ! $wildcard );
	
	# Am I doing a blank string compare?
	if ( ! defined $str )
		{	return( 1 ) if ( $wildcard eq $blank_compare );
			return( undef );	
		}
		
	# Clean up the string
	$str = lc( $str );
	$str =~ s/^\s//gm;
	$str =~ s/\s$//gm;

	# Was the string just blanks?
	return( undef ) if ( ! $str );
	
	return( $str =~ m/$wildcard/ );
}



################################################################################
#
sub SpamCategories()
#
#  Load in the list of Categories to Allow/Block in the Spam Mail Blocker - 
#  called after every pipe file name read so don't query the table too often
#
################################################################################
{   if ( $spam_categories_next_time )
		{  return if ( time() < $spam_categories_next_time );  #  Wait a while to do this processing if I have run before
		}

	&debug( "SpamCategories\n" );
	
	&LoadSpamCategories();

	$spam_categories_next_time = 20 + ( 20 * 60 ) + time();  #  Setup the next processing time to be in about 20 minutes or so - plus 20 seconds
}



################################################################################
#
sub LoadSpamPatterns()
#
#  Load in any new spam patterns - called after every pipe file name read
#  so don't query the table too often
#
################################################################################
{   # Am I even using spam patterns?

	return( 0 + 0 ) if ( ! $use_spam_patterns );

	if ( $spam_patterns_next_time )
		{  return if ( time() < $spam_patterns_next_time );  #  Wait a while to do this processing if I have run before
		}

	$spam_patterns_next_time = 20 + ( 30 * 60 ) + time();  #  Setup the next processing time to be in 30 minutes or so - plus 20 seconds

	
	&debug( "LoadSpamPatterns\n" );
	
	# Does the table exist?
	return( 0 + 0 ) if ( ! &SqlTableExists( "SpamPatterns" ) );
	
	my $errcat = &ErrorsCategory();
	
	my $str = "SELECT Name, Result, Type1, Value1, Type2, Value2, Type3, Value3, Type4, Value4 from SpamPatterns WITH(NOLOCK) WHERE CategoryNumber <> $errcat";
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( $str );
	
	$sth->execute();

	# Initialize the spam patterns arrays and hashes
	@spam_patterns			= ();
	%spam_pattern_names		= ();
	@virus_patterns			= ();
	%virus_pattern_names	= ();
	
	my $array_ref = $sth->fetchall_arrayref() if ( ! $dbh->err );
	
	if ( ! $dbh->err )
		{	foreach my $row ( @$array_ref )
				{	my ( $name, $result, $type1, $value1, $type2, $value2, $type3, $value3, $type4, $value4 ) = @$row;
					
					# Is this a virus pattern or a spam pattern?
					if ( $result =~ m/virus/i )
						{
							my $count = $#virus_patterns + 1;

							$count = $virus_pattern_names{ $name } if ( $virus_pattern_names{ $name } );
							
							$virus_patterns[ $count ][ 0 ] = $name;
							$virus_patterns[ $count ][ 1 ] = uc( $result );
							
							$virus_patterns[ $count ][ 2 ] = $type1;
							$virus_patterns[ $count ][ 3 ] = &ValueToRegExpression( $value1, $type1 );
							
							$virus_patterns[ $count ][ 4 ] = $type2;
							$virus_patterns[ $count ][ 5 ] = &ValueToRegExpression( $value2, $type2 );

							$virus_patterns[ $count ][ 6 ] = $type3;
							$virus_patterns[ $count ][ 7 ] = &ValueToRegExpression( $value3, $type3 );

							$virus_patterns[ $count ][ 8 ] = $type4;
							$virus_patterns[ $count ][ 9 ] = &ValueToRegExpression( $value4, $type4 );

							$virus_pattern_names{ $name } = $count;
						}
					else
						{	# Figure out the row number of the rule
							my $count = $#spam_patterns + 1;

							$count = $spam_pattern_names{ $name } if ( $spam_pattern_names{ $name } );
							
							$spam_patterns[ $count ][ 0 ] = $name;
							$spam_patterns[ $count ][ 1 ] = uc( $result );
							
							$spam_patterns[ $count ][ 2 ] = $type1;
							$spam_patterns[ $count ][ 3 ] = &ValueToRegExpression( $value1, $type1 );
							
							$spam_patterns[ $count ][ 4 ] = $type2;
							$spam_patterns[ $count ][ 5 ] = &ValueToRegExpression( $value2, $type2 );

							$spam_patterns[ $count ][ 6 ] = $type3;
							$spam_patterns[ $count ][ 7 ] = &ValueToRegExpression( $value3, $type3 );

							$spam_patterns[ $count ][ 8 ] = $type4;
							$spam_patterns[ $count ][ 9 ] = &ValueToRegExpression( $value4, $type4 );

							$spam_pattern_names{ $name } = $count;
						}
				}
		}
		
	&SqlErrorHandler( $dbh );		
	$sth->finish();

	return( 0 + 0 );
}



################################################################################
#
sub ValueToRegExpression( $$ )
#
#  Given a spam pattern value, or a wildcard domain, return the regular expression
#  to use for a string compare
#
################################################################################
{	my $wildcard	= shift;
	my $type		= shift;

	return( undef ) if ( ! defined $wildcard );
	
	# Is it our blank compare?  If so, just return it
	return( $blank_compare ) if ( lc( $wildcard ) eq $blank_compare );
	
	# Is it a regular expression?
	if ( $wildcard =~ m/^\!/ )
		{	$wildcard =~ s/^\!//;
			return( $wildcard );
		}
	
	# Clean up the string	
	$wildcard = lc( $wildcard );
	$wildcard =~ s/^\s//gm;
	$wildcard =~ s/\s$//gm;
	
	
	# Make sure that body compares are always wildcarded
	if ( ( $type )  &&  ( $type eq "BODY" ) )
		{	# get rid of leading or trailing astericks since the BODY type is always a wildcard
			$wildcard =~ s/^\*//g;
			$wildcard =~ s/\*$//g;
			
			$wildcard = lc( $wildcard );
			
			# Now add the astericks back on
			$wildcard = "*" . $wildcard . "*";
		}
		
		
	# Make sure that URL compares leave off the http://, etc, and are lowercase
	if ( ( $type )  &&  ( $type eq "URL" ) )
		{	$wildcard = lc( $wildcard );
			$wildcard =~ s/^http\:\/\///;
			$wildcard =~ s/^ftp\:\/\///;
			$wildcard =~ s/^https\:\/\///;
		}
		
	my $caret;
	# Make sure that EXTERNAL-IP compares start with a caret so that a wildcard of 66.17.15.* does not match 166.17.15.4
	if ( ( $type )  &&  ( $type eq "EXTERNAL-IP" ) )
		{	$caret = 1;
			$wildcard =~ s/^\^//gm;
		}
		
		
	# Is it a straight string compare?  That is no * or ?
	if ( ( ! ( $wildcard =~ m/\*/ ) )  &&  ( ! ( $wildcard =~ m/\?/ ) ) )
		{	$wildcard = quotemeta( $wildcard );
			return( $wildcard );
		}
	
	
	# Is it a wildcard before?
	my $before;
	if ( $wildcard =~ m/^\*/ )
		{	$before = 1;
			$wildcard =~ s/^\*//gm;
		}
	
	# Is it a wildcard after?
	my $after;
	if ( $wildcard =~ m/\*$/ )
		{	$after = 1;
			$wildcard =~ s/\*$//gm;
		}

	# Is there a '*' in the middle?
	my $middle;
	$middle = 1 if ( $wildcard =~ m/\*/ );

	
	$wildcard = quotemeta( $wildcard );

	$wildcard = ".*" . $wildcard if ( $before );
	$wildcard = $wildcard . ".*" if ( $after );
	$wildcard = "^" . $wildcard if ( $caret );
	
	# Substitute . for \? for single character wildcards
	$wildcard =~ s#\\\?#\.#g;
	

	# Was there an '*' in the middle?
	if ( $middle )
		{	$wildcard =~ s/\\\*/\.\*/g;
		}
	
	
	return( $wildcard );
}



################################################################################
#
sub AutoWhiteList( $$ )
#
#  Check to see if the email from, email to is on the white list
#  Return -1 if it is, 0 if not
#
################################################################################
{   my $email_from = shift;
	my $email_to = shift;
	
	# Just return quick if not using the auto white list
	return( 0 + 0 ) if ( ! $use_autowhitelist );
	
	return( 0 + 0 ) if ( ( ! defined $email_from )  ||  ( ! defined $email_to ) );
	
	&debug( "AutoWhiteList check FROM:$email_from TO:$email_to\n" );
	
	my $comp = $email_to . ':' . $email_from;
	
	$dbh = &SqlErrorCheckHandle( $dbh );
    my $sth = $dbh->prepare( "SELECT Comp from AutoWhiteList WITH(NOLOCK) WHERE Comp = ?" );
	
    $sth->bind_param( 1, $comp,  DBI::SQL_VARCHAR );
	
    $sth->execute();
	
    my ( $Comp ) = $sth->fetchrow_array() if ( ! $dbh->err );
	
	&SqlErrorHandler( $dbh );
    $sth->finish();
	
	my $retcode = 0 - 1;  #  Make sure I'm returning an integer
	
	#  Return a -1 if I found a match
	return( $retcode ) if ( $Comp );
	
	return( 0 + 0 );
}



################################################################################
#
sub SpecialAddresses( $ )
#
#  Return True if the given address is one of the special addresses
#  Return undef if not
#
################################################################################
{	my $email_address = shift;
	
	return( undef ) if ( ! defined $email_address );
	
	foreach ( @special_addresses )
		{	next if ( ! defined $_ );
			
			return( 1 ) if ( $_ eq $email_address );
		}
		
	return( undef );
}



################################################################################
#
sub AutoBlackList( $$ )
#
#  Check to see if the email from, email to is on the black list
#  Return 1 if it is, 0 if not, or -1 if I have all the autoblack stuff, but this guy isn't autoblacklisted
#
################################################################################
{   my $email_from	= shift;
	my $email_to	= shift;
	
	# Just return quick if not using the auto black list
	return( 0 + 0 ) if ( ! $use_autoblacklist );
	
	return( 0 + 0 ) if ( ( ! defined $email_from )  ||  ( ! defined $email_to ) );
	
	&debug( "AutoBlackList check FROM:$email_from TO:$email_to\n" );
		
	$dbh = &SqlErrorCheckHandle( $dbh );
    my $sth = $dbh->prepare( "SELECT [From] from AutoBlackList WITH(NOLOCK) WHERE [TO] = ? AND [From] = ?" );
	
    $sth->bind_param( 1, $email_to,  DBI::SQL_VARCHAR );
    $sth->bind_param( 2, $email_from,  DBI::SQL_VARCHAR );
	
    $sth->execute();
	
	my ( $From ) = $sth->fetchrow_array() if ( ! $dbh->err );
	
	&SqlErrorHandler( $dbh );
    $sth->finish();
		
	#  Return a 1 if I found a match
	return( 0 + 1 ) if ( $From );
	
	# Return a -1 if I didn't find a match
	return( 0 - 1 );
}



################################################################################
#
sub UserPreferences( $ )
#
#  Check to see if the email to has set his user preferences to not block spam
#  Return -1 if it is set to not block spam, 0 if I should block spam
#
################################################################################
{   my $email_to = shift;
	
	return( 0 + 0 ) if ( ! defined $email_to );
	return( 0 + 0 ) if ( ! $use_user_preferences );
	
	&debug( "UserPreferences for $email_to\n" );
	
	$dbh = &SqlErrorCheckHandle( $dbh );
    my $sth = $dbh->prepare( "SELECT UserName from SpamUserPreferences WITH(NOLOCK) WHERE UserName = ? AND Domain IS NULL AND BlockSpam = 0 AND AutoCreated = 0" );	
    
	my $qemail_to = &quoteurl( $email_to );
	$sth->bind_param( 1, $qemail_to,  DBI::SQL_VARCHAR );
	
    $sth->execute();

    my ( $UserName ) = $sth->fetchrow_array() if ( ! $dbh->err );
	
	&SqlErrorHandler( $dbh );
    $sth->finish();
		
	#  Return a -1 if I found a match
	if ( $UserName )
		{	$last_valid_email_to = $email_to;
			return( 0 - 1 );
		}
		
	return( 0 + 0 );
}



################################################################################
#
sub CheckForged( $$ )
#
#  Sometimes spammers forge email addresses as if the spam is from an administrative
#  account on the inside of the network.  Return a positive value if it looks
#  like a forged admin address
#
################################################################################
{	my $original_email_from	= shift;
	my $email_to			= shift;	
	
	return( 0 + 0 ) if ( ! defined $original_email_from );
	return( 0 + 0 ) if ( ! defined $email_to );


	# Is this email from the same as the email to, and thus forged?
	# Doing this check can screw up lot of stuff - so it is commented out 
#	return( 0 + 1 ) if ( $original_email_from eq $email_to );
	
	# Check for special original email from addresses
	my $special;
	
	$special = 1 if ( $original_email_from =~ m/^postmaster@/i );
	$special = 1 if ( $original_email_from =~ m/^mailer-daemon@/i );
	$special = 1 if ( $original_email_from =~ m/^noreply@/i );
	$special = 1 if ( $original_email_from =~ m/^bounce@/i );
	
	return( 0 + 0 ) if ( ! $special );
	
	# Now - does this have to email_to domain address?
	my ( $person, $domain ) = split /\@/, $email_to;
	return( 0 + 0 ) if ( ! $domain );
	
	my $quoted = quotemeta( $domain );
	
	return( 0 + 1 ) if ( $original_email_from =~ m/$quoted$/i );
	
	return( 0 + 0 );
}



################################################################################
################################################################################
################################################################################
######################  Network Reputation Subroutines  ########################
################################################################################
################################################################################
################################################################################



################################################################################
# 
sub NetworkReputation( $ )
#
#  Given an IP address in string format, return a positive value and the reputation
#  if it looks like the network is bad, or 0 and undef if the network is OK
#
################################################################################
{	my $ip = shift;

    return( 0 + 0, undef ) if ( ! &IsIPAddress( $ip ) );

	&debug( "NetworkReputation\n" );
	
	my @parts = split /\./, $ip;
	my $class_a = 0 + $parts[ 0 ];
	my $class_b = 0 + $parts[ 1 ];
	
	my $ip_num = unpack( "N", &StringToIP( $ip ) );
	
	my $the_asn = 0 + 0;
	my $the_reputation;

	my $current_val = $network_reputation[ $class_a ][ $class_b ];
	
	# Is there anything at all?
	if ( ! defined $current_val )
		{	&debug( "No network reputation found\n" );
			return( 0 + 0, undef );	
		}
		
	my @vals = split /\t/, $current_val;	

	foreach ( @vals )
		{	my $val = $_;
			next if ( ! defined $val );

			my ( $istart, $iend, $asn, $reputation ) = split /\s/, $val, 4;
			next if ( ! defined $istart );
			next if ( ! defined $iend );
			next if ( ! defined $asn );
			
			$istart		= 0 + $istart;
			$iend		= 0 + $iend;
			
			# Did I find a match?
			if ( ( $ip_num >= $istart )  &&  ( $ip_num <= $iend ) )
				{	$the_asn		= $asn;
					
					# Get rid of the underlines in the reputation
					if ( defined $reputation )
						{	$reputation =~ s/_/ /g;
							$reputation =~ s/\s+$//;
							
							# If the reputation is a number, then it is the spam percentage
							# If it isn't a number, then it is a string describing the bad reputation
							if ( $reputation =~ m/\D/ )
								{	$the_reputation = $reputation;
								}
							else
								{	$the_reputation = "$reputation percent of the mail from AS# $asn is spam"
								}
						}
						
					&debug( "$ip in AS# $asn has a bad network reputation: $the_reputation\n" ) if ( defined $reputation );
					&debug( "$ip in AS# $asn and has a good network reputation\n" ) if ( ! defined $reputation );
					last;
				}
		}

	
	return( 0 + 1, $the_reputation ) if ( defined $the_reputation );
	return( 0 + 0, undef );	
}



################################################################################
# 
sub ReadNetworkReputation( $ )
#
#  Read in the the $network_reputation table (with reputations) from disk
#  Return True if I read the data OK, undef if not
#
################################################################################
{
	my $reputation_file = &SoftwareDirectory() . "\\NetworkReputation.dat";
	
	if ( ! open( REPUTATION, "<$reputation_file" ) )
		{	&lprint( "Error opening network reputation file $reputation_file: $!\n" );
			$use_network_reputation = undef;
			&lprint( "Turning off using network reputation\n" );
			return( undef );
		}
	
	&lprint( "Reading in network reputation file $reputation_file ...\n" );
	
	@network_reputation = ();
	
	my $count = 0 + 0;
	while ( my $line = <REPUTATION> )
		{	my ( $class_a, $class_b, $current_val ) = split /\t/, $line, 3;
			next if ( ! defined $class_a );
			next if ( ! defined $class_b );
			next if ( ! defined $current_val );
			
			$class_a = 0 + $class_a;
			$class_b = 0 + $class_b;
			
			$network_reputation[ $class_a ][ $class_b ] = $current_val;
			$count++;
		}
				
	close( REPUTATION );	
	
	&lprint( "Read in $count different network reputations from $reputation_file\n" );
	
	if ( $count < 1 )
		{	&lprint( "Could not read any data from $reputation_file so turning off using network reputation\n" );
			$use_network_reputation = undef;
		}
		
	return( $count );
}



################################################################################
################################################################################
################################################################################
########################  Challenge Email Processing  ##########################
################################################################################
################################################################################
################################################################################



################################################################################
#
sub ChallengeEmailOK()
#
#  Return True if OK to use the challenge email, or undef if not 
#
################################################################################
{	return( undef ) if ( ! $use_challenge );
	
	if ( $opt_filename )
		{	&lprint( "Can\'t send emails from the command line so turning \'Use Challenge Email\' option off ...\n" );
			return( undef );
		}
	
	
	# Does the challenge email table exist?
	if  ( &SqlTableExists( "SpamChallengeEmail" ) )
		{	&oprint( "SpamChallengeEmail table exists ...\n" );
		}
	else
		{	&lprint( "SpamChallengeEmail table does not exist so turning \'Use Challenge Email\' option off ...\n" );
			return( undef );
		}
	
	
	# Does the challenge email address exist?
	if ( ! defined $challenge_email_from )	
		{	&lprint( "Challenge email address does not exist so turning \'Use Challenge Email\' option off ...\n" );
			return( undef );
		}
		
	
	# Does the challenge template exist?	
	my $file = &SoftwareDirectory . "\\SpamChallenge.txt";
	&lprint( "Loading the challenge email template from $file ...\n" );
						
	if ( open( CHALLENGE, "<$file" ) )
		{	while (my $line = <CHALLENGE>)
				{	next if ( ! defined $line );
					$challenge_body .= $line if ( defined $challenge_body );
					$challenge_body = $line if ( ! defined $challenge_body );
				}
				
			close( CHALLENGE );
		}
	
	if ( ! defined $challenge_body )
		{	&lprint( "Unable to load the challenge email template so turning \'Use Challenge Email\' option off ...\n" );
			return( undef );
		}


	if ( $challenge_send_thank_you )
		{	# Does the challenge thank you template exist?	
			$file = &SoftwareDirectory . "\\SpamChallengeThankYou.txt";
			&lprint( "Loading the challenge email thank you template from $file ...\n" );
								
			if ( open( CHALLENGE, "<$file" ) )
				{	while ( my $line = <CHALLENGE> )
						{	next if ( ! defined $line );
							$challenge_thank_you .= $line if ( defined $challenge_thank_you );
							$challenge_thank_you = $line if ( ! defined $challenge_thank_you );
						}
						
					close( CHALLENGE );
				}
		}
		
	# If I got to here then I am ready to go ...
	return( 1 );
}		
		


################################################################################
#
sub ChallengeEmail( $$$@ )
#
#  Check to see if I should send an email challenge to this email_from
#  Return 0 if it is OK, or 1 if I challenged it
#
################################################################################
{	my $email_from			= shift;
	my $original_email_from	= shift;
	my $file				= shift;
	my $subject				= shift;
	my @envelope_to			= @_;
	
	
	return( 0 + 0 ) if ( ! $use_challenge );
	
	# Give up if I don't have an email to
	return( 0 + 0 ) if ( $#envelope_to < 0 );
	
	
	# Check for special original email from addresses
	if ( defined $original_email_from )
		{	return( 0 + 1 ) if ( $original_email_from =~ m/^postmaster\@/i );
			return( 0 + 1 ) if ( $original_email_from =~ m/^mailer-daemon\@/i );
			return( 0 + 1 ) if ( $original_email_from =~ m/^noreply\@/i );
			return( 0 + 1 ) if ( $original_email_from =~ m/^bounce\@/i );
		}
		
		
	return( 0 + 1 ) if ( ! defined $email_from );	# There must be a valid from: address to challenge

	
	# Is the from: and to: address the same?
	if ( ( $#envelope_to == 0 )  &&  ( $email_from eq $envelope_to[ 0 ] ) )
		{	&oprint( "Challenge email - FROM: and TO: are both $email_from - so rejecting\n" );
			return( 0 + 1 );
		}
		
		
	# Is this email only to one of our special addresses?
	if ( $#envelope_to == 0 )
		{	my $check_email = $envelope_to[ 0 ];
			return( 0 + 0 ) if ( &SpecialAddresses( $check_email ) );
		}
		
	
	# Is this email from one of our special addresses?
	return( 0 + 0 ) if ( &SpecialAddresses( $email_from ) );
		
	
	# Ignore some special addresses - like mailer daemon, etc
	return( 0 + 0 ) if ( $email_from =~ m/^mailer-daemon@/i );
	return( 0 + 0 ) if ( $email_from =~ m/^postmaster@/i );
	
	
	# Ignore some subject lines - like spam mail summary
	return( 0 + 0 ) if ( ( defined $subject )  &&  ( $subject =~ m/^spam mail summary/i ) );
	
	
	# First, check to see if this guy is autowhitelisted - if I haven't already checked this
	#  Is it on the auto white list?
	if ( ! $use_autowhitelist )
		{	foreach ( @envelope_to )
				{	my $check_email = $_;
					next if ( ! defined $check_email );
					
					# Don't autowhitelist any email to one of the special addresses
					next if ( &SpecialAddresses( $check_email ) );
					
					# If the sender is on the to list - reject it
					if ( $email_from eq $check_email )
						{	&oprint( "Challenge email - FROM: and one of the TO: are both $email_from - so rejecting\n" );
							return( 0 + 1 );
						}
						
					if ( &AutoWhiteList( $email_from, $check_email ) )  #  This should return a -1 if it is listed
						{	return( 0 + 0 );	
						}
				}
		}
	
	
	# Pick the best address to challenge from	
	my $challenge_to = $envelope_to[ 0 ];
	
	# Is there a better challenge email address?
	if ( $#envelope_to > 0 )
		{	$challenge_to = &ChallengeEmailAddress( @envelope_to );
		}
	
	
	# If I couldn't pick a good email to, give up
	return( 0 + 0 ) if ( ! defined $challenge_to );
	
		
	# Now see if I have him in the SpamChallengeEmail table already, and he passed
	my $ret = &ChallengeEmailCheck( $email_from, $challenge_to );
	
	
	return( 0 + 0 ) if ( $ret > 0 );	# Ret is positive if he has passed the test onetime
	return( 0 + 1 ) if ( $ret < 0 );	# Ret is negative if I'm testing him right now - so don't flood him with lots of challenges


	# Well, he isn't autowhitelisted, and he hasn't already passed the challenge, then 
	# add him to the SpamChallengeEmail table, send him a challenge email, and fail him
	
	&ChallengeEmailSend( $email_from, $file, $challenge_to );
	
	return( 0 + 1 );	
}



################################################################################
#
sub ChallengeEmailPass( $$ )
#
#  I've received a challenge response. If valid, go ahead and forward the email
#  and add that this guy passed
#
#  Return undef if no challenges waiting
#  Return the count of files emailed if there were challenges
#
################################################################################
{	my $email_from	= shift;
	my $email_to	= shift;

	&oprint( "Received a challenge response FROM: $email_from\n" );

	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "SELECT [File] from SpamChallengeEmail WITH(NOLOCK) WHERE [FROM] = ? AND PASSED = \'0\'" );
	$sth->bind_param( 1, $email_from,  DBI::SQL_VARCHAR );
					
	$sth->execute();
	
	my @list;
	while ( ( ! $dbh->err )  &&  ( my ( $file ) = $sth->fetchrow_array() ) )
		{	push @list, $file if ( defined $file );
		}
		
	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	
	# If no files, then there wasn't a challenge waiting
	if ( $#list < 0 )
		{	&oprint( "No challenges waiting for FROM: $email_from\n" );
			return( undef );	
		}
	
	
	# Now send each of the files
	my $count = 0 + 0;
	foreach ( @list )
		{	my $file = $_;
			next if ( ! defined $file );
						
			if ( ! -e $file )
				{	&oprint( "Challenge email file $file does not exist\n" );
					next;	
				}
				
				
			# Find the ID of the row in the SpamMailBlocker table with this file in it ...
			$dbhStat = &SqlErrorCheckHandle( $dbhStat );
			$sth = $dbhStat->prepare( "SELECT ID, EmailTo FROM SpamMailBlocker WITH(NOLOCK) WHERE MailFile = \'$file\'" );
							
			$sth->execute();

			my ( $id, $to ) = $sth->fetchrow_array();
			
			&SqlErrorHandler( $dbhStat );
			$sth->finish();
			
			if ( ! defined $id )	
				{	&oprint( "SpamMailBlocker ID does not exist for challenge email file $file\n" );
					next;	
				}
			
			
			my @to;
			push @to, $to;	# Put the original to first on the list ...
			
			
			# Get any additional recipients from the SpamMailBlockerRecipients table
			$dbhStat = &SqlErrorCheckHandle( $dbhStat );
			$sth = $dbhStat->prepare( "SELECT EmailTo FROM SpamMailBlockerRecipients WITH(NOLOCK) WHERE ID = \'$id\'" );
							
			$sth->execute();
			
			my $additional_to;
			while ( ( $additional_to ) = $sth->fetchrow_array() )
				{	push @to, $additional_to;
				}
				
			&SqlErrorHandler( $dbhStat );
			$sth->finish();
				
			
			# Now mail the file ...	
			my $ok = &MailFile( $file, $email_from, @to );
			&lprint( "Error mailing passed spam challenge file $file\n" ) if ( ! $ok );
			$count++ if ( $ok );
			
			# Rename the file to ham by changing the first letter of the short file name from 's' to 'h'
			my ( $dir, $short ) = &SplitFileName( $file );
			$short =~ s/^s/h/;
			
			my $fullfile = "$dir\\$short";
			
			
			# Actually rename the file by copying and then deleting
			$ok = copy( $file, $fullfile );
			&lprint( "Error copying passed challenge file from $file to $fullfile: $!\n" ) if ( ! $ok );
			
			# If it copied OK then delete it
			if ( $ok )
				{	unlink( $file );
				}
					
			
			# Update the row in the SpamMailBlocker table so it won't show up in a spam summary report
			$dbhStat = &SqlErrorCheckHandle( $dbhStat );
			$sth = $dbhStat->prepare( "UPDATE SpamMailBlocker Set [Code] = '75', [Status] = \'OK (Realtime Spam Checker) Passed challenge email test\', MailFile = \'$fullfile\' WHERE ID = \'$id\'" );
							
			$sth->execute();

			&SqlErrorHandler( $dbhStat );
			$sth->finish();
		}
	

	&oprint( "Did not mail any passed spam challenge files for $email_from\n" ) if ( ! $count );
	&oprint( "Mailed $count passed spam challenge files for $email_from\n" ) if ( $count );
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	$sth = $dbh->prepare( "UPDATE SpamChallengeEmail SET PASSED = '1', [Time] = getdate() WHERE [FROM] = ?" );
	$sth->bind_param( 1, $email_from,  DBI::SQL_VARCHAR );
					
	$sth->execute();

	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	&ChallengeEmailThankYouSend( $email_from, $email_to );
	
	# Since this guy passed the challenge then also add him to the autowhite list
	my $comp = $email_to . ':' . $email_from;
	&debug( "Adding AutoWhite entry $comp\n" );	
	&AddAutoWhiteEntry( $comp );

	return( $count );
}



################################################################################
#
sub ChallengeEmailSend( $$$ )
#
#  Send a challenge email and add the challenge to the database
#
################################################################################
{	my $email_from	= shift;
	my $file		= shift;
	my $email_to	= shift;

	&oprint( "Sending a challenge email to $email_from ...\n" );
			
	# Save the file name to what the SpamBlocker Object will name it by changing the first letter of the short file name from 'x' to 's'
	my ( $dir, $short ) = &SplitFileName( $file );
	$short =~ s/^x/s/;
	
	my $fullfile = "$dir\\$short";
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	
	my $qemail_from = &quoteurl( $email_from );
	my $qemail_to = &quoteurl( $email_to );
	my $str = "INSERT INTO SpamChallengeEmail ( [FROM], [TO], [File], PASSED ) VALUES ( \'$qemail_from\', \'$qemail_to\', \'$fullfile\', \'0\' )";
	my $sth = $dbh->prepare( $str );
					
	$sth->execute();
	
	if ( $dbh->err )
		{	&lprint( "Error $dbh->err inserting SpamChallenge into the database\n" );
		}
		
	&SqlErrorHandler( $dbh );
	$sth->finish();

	# Get the message body
	my $body = $challenge_body;
	
	
	# Put the specific email fields in
	$body =~ s/CHALLENGE_SUBJECT/$challenge_subject/g;	# The challenge subject contains the $challenge_id
	$body =~ s/EMAIL_FROM/$email_from/g;
	$body =~ s/EMAIL_TO/$email_to/g;
	$body =~ s/EMAIL_CHALLENGE/$challenge_email_from/g;
	$body =~ s/CHALLENGE_ID/$challenge_id/g;
	
	
	# Create a unique filename for the message file
	my $filename = "SpamChallenge-$email_from-";
	
	my $time = time();
	my $date = sprintf( "%d", $time );
 	
	$filename .= $date . ".txt";

	my ( $ret, $errmsg ) = &SMTPMessageFile( $filename, $challenge_email_from, $body, undef, undef, $email_from );
	&oprint( "Error sending a challenge email TO: $email_from, errmsg: $errmsg\n" ) if ( ! $ret );
	
	return( 1 );
}



################################################################################
#
sub ChallengeEmailThankYouSend( $$ )
#
#  Send a thank you message back to the original sender
#
################################################################################
{	my $email_from	= shift;
	my $email_to	= shift;

	return( undef ) if ( ! $challenge_send_thank_you );
	return( undef ) if ( ! defined $challenge_thank_you );
	return( undef ) if ( ! defined $email_from );
	return( undef ) if ( ! defined $email_to );
	
	&oprint( "Sending a challenge email thank you to $email_from ...\n" );
			
	# Get the thank you message body
	my $body = $challenge_thank_you;
	
	
	# Put the specific email fields in
	$body =~ s/EMAIL_FROM/$email_from/g;
	$body =~ s/EMAIL_TO/$email_to/g;
	$body =~ s/EMAIL_CHALLENGE/$challenge_email_from/g;
	$body =~ s/CHALLENGE_ID/$challenge_id/g;
	
	
	# Create a unique filename for the message file
	my $filename = "SpamThankYou-$email_from-";
	
	my $time = time();
	my $date = sprintf( "%d", $time );
 	
	$filename .= $date . ".txt";

	my ( $ret, $errmsg ) = &SMTPMessageFile( $filename, $challenge_email_from, $body, undef, undef, $email_from );
	&oprint( "Error sending a challenge thank you email TO: $email_from, errmsg: $errmsg\n" ) if ( ! $ret );
	
	return( 1 );
}



################################################################################
#
sub ChallengeEmailCheck( $$ )
#
#  Given the from: address of an email, and the best to: address
#  Return 1 if this guy ever passed
#  Return 0 if I've never heard of him or it's been longer than a day since I've challenged him
#  Return -1 if I'm waiting for him right now
#
################################################################################
{	my $email_from	= shift;
	my $email_to	= shift;
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( "SELECT Passed, [Time], [TO] from SpamChallengeEmail WITH(NOLOCK) WHERE [FROM] = ?" );
	$sth->bind_param( 1, $email_from,  DBI::SQL_VARCHAR );
					
	$sth->execute();
	
	my $ret = 0 + 0;
	
	my $done;
	my $newest_time;
	while ( ( ! $dbh->err )  &&  ( ! $done ) )
		{	my ( $passed, $time, $to ) = $sth->fetchrow_array();
			
			# Keep track of the newest time I have for this same to: address
			if ( defined $time )
				{	if ( ( defined $to )  &&  ( $to eq $email_to ) )	# Is the TO: address defined?
						{	$newest_time = $time if ( ! defined $newest_time );
							$newest_time = $time if ( $time gt $newest_time );
						}
					elsif ( ! defined $to )		# If the [TO] address is not defined
						{	$newest_time = $time if ( ! defined $newest_time );
							$newest_time = $time if ( $time gt $newest_time );
						}	
				}
		
			if ( ! defined $passed )	# No more rows to check
				{	$done = 1;
				}
			elsif ( $passed )			# He passed the challenge one time
				{	$ret = 0 + 1;
					$done = 1;
				}
		}
		
		
	&SqlErrorHandler( $dbh );
	$sth->finish();


	# Did he pass the challenge already?  No need to check anything further if he has
	return( $ret ) if ( $ret == ( 0 + 1 ) );
	
	
	# Do I have a recent pending challenge to this guy?
	if ( defined $newest_time )
		{	$ret = 0 - 1;	# Default to the case where I have already sent him a challenge recently (within 1 day)
			
			#  Figure out 1 day ago time in the correct format
			my $yesterday = time() - ( 1 * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $yesterday );
			$year = 1900 + $year;
			$mon = $mon + 1;
			my $expired_time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, $hour, $min, $sec, 0 );

			$ret = ( 0 + 0 ) if ( $newest_time lt $expired_time );	# If it's been longer than 1 day, send him another challenge
		}
		
		
	return( $ret );
}



################################################################################
#
sub ChallengeEmailAddress( @ )
#
#  Given a list of email addresses, pick one to issue a challenge email from
#  Return the email address
#
################################################################################
{	my @envelope_to = @_;
	
	my $challenge_email = $envelope_to[ 0 ];	# Default to the first on the list
	
	# Return the default if the spam user preferences doesn't exist
	return( $challenge_email ) if ( ! $spam_user_preferences_exists );
	
	foreach ( @envelope_to )
		{	next if ( ! defined $_ );
			my $check_email = $_;
			
			$dbh = &SqlErrorCheckHandle( $dbh );
			my $sth = $dbh->prepare( "SELECT UserName, BlockSpam from SpamUserPreferences WITH(NOLOCK) WHERE UserName = ? AND Domain IS NULL" );
			$sth->bind_param( 1, $check_email,  DBI::SQL_VARCHAR );
					
			$sth->execute();
					
			my ( $database_email_address, $block_spam ) = $sth->fetchrow_array() if ( ! $dbh->err );
			$block_spam = 0 + $block_spam if ( $block_spam );	# Make sure the block spam is undef, 0, or 1
			
			&SqlErrorHandler( $dbh );
			$sth->finish();
			
			return( $check_email ) if ( ( defined $database_email_address )  &&  ( $block_spam ) );
		}
		
	return( $challenge_email );
}



################################################################################
################################################################################
################################################################################
########################  Grey List Processing  ################################
################################################################################
################################################################################
################################################################################



################################################################################
#
sub AutoGreyList( $$$$ )
#
#  Check to see if the email from, email to is on the grey list
#  Return 0 if it is OK, 1 if it is on the temp grey list
#
################################################################################
{   my $email_from = shift;
	my $email_to = shift;
	my $file = shift;
	my $external_ip_address = shift;
	
	
	&debug( "AutoGreyList check\n" );

	# Don't bother if I am not using the grey list stuff
	return( 0 + 0 ) if ( ! $use_greylist );

	return( 0 + 0 ) if ( ! defined $email_to );
	return( 0 + 0 ) if ( ( ! defined $email_from )  &&  ( ! defined $external_ip_address ) );
	
	
	# Make sure that it isn't from and to the same address
	return( 0 + 0 ) if ( ( defined $email_from )  &&  ( $email_to eq $email_from ) );
	
	
	# Check in the content database to see if this IP address is in an unblocked category
	if ( defined $external_ip_address )
		{	my $retcode = &LookupUnknown( $external_ip_address, 0 );
			return( 0 ) if ( ( $retcode )  &&  ( $retcode > 3 ) );  # If it is in the database, and allowed, don't do a Grey list on the email
		}
	
	
	my $comp;
	if ( defined $email_from )
		{	$comp = $email_to . ':' . $email_from;  
		}
	else
		{	$comp = $email_to . ':' . $external_ip_address;
		}

	
	# First, look in the database to see if I have seen this one before
	$dbh = &SqlErrorCheckHandle( $dbh );
    my $sth = $dbh->prepare( "SELECT Comp from AutoGreyList WITH(NOLOCK) WHERE Comp = ?" );
    $sth->bind_param( 1, $comp,  DBI::SQL_VARCHAR );
	
    $sth->execute();
		
    my ( $Comp ) = $sth->fetchrow_array() if ( ! $dbh->err );
	
	&SqlErrorHandler( $dbh );
    $sth->finish();

	
	#  Return a 0 if I found a match
	return( 0 + 0 ) if ( $Comp );
	
	my $two_minutes = 2 * 60;   #  2 minutes, expressed in seconds
	
	
	#  Have I seen this one just recently?
	if ( $grey_list{ $comp } )
	  {  #  Has if been over 2 minutes ago since I saw it?
	     if ( time() > ( $two_minutes + $grey_list{ $comp } ) )
		   {   #  Add it to the permanent grey list
			   my $qcomp = &quoteurl( $comp );
			   my $values = "\'" . $qcomp . "\'";
			   
			   $dbh = &SqlErrorCheckHandle( $dbh );
			   $sth = $dbh->prepare( "INSERT INTO AutoGreyList ( Comp ) VALUES ( $values )" );
			   
			   $sth->execute();
			   
			   &SqlErrorHandler( $dbh );
			   $sth->finish();
			   
			   # Delete the old Grey record
			   &DeleteGreyList( $comp );
			   
			   delete $grey_list{ $comp };  #  Delete it from the temp. grey list
			   
			   return( 0 + 0 );  #  Finally let it go through
		   }
		 else  {  return( 0 + 432 );  }  #  It is still on the temp grey list
      }
	  	
	
	#  At this point, I haven't seen this email in the last 8 hours, so add it to the grey list
	#  Add it to the temp grey list
	$grey_list{ $comp } = time();  #  Save the current time
	
	return( 0 + 432 );
}



################################################################################
#
sub OldGreyList()
#
#  Check to see if grey listed emails never re tried
#  If it has gone over 8 hours, then was really spam
#  Only do this processing every 5 minutes or so,
#  just to keep from spinning the process a lot.
#
################################################################################
{   
	
	# Don't bother if I am not using the grey list stuff
	return if ( ! $use_greylist );
	
	
	if ( $grey_next_time )
		{  return if ( time() < $grey_next_time );  #  Wait a while to do this processing if I have run before
		}
	else
		{	$grey_next_time = 10 + ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so - plus 10 seconds
			return;
		}
	  
	&debug( "OldGreyList\n" );
	
	
	$grey_next_time = 10 + ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so - plus 10 seconds

	 	
	my @grey = keys %grey_list;
	
	my $current_time = time();
	my $maximum_processing_time = 20 + $current_time;  # Only process Grey List stuff for 20 seconds at a time
	
	my $additional_time = ( 8 * 60 * 60 );  #  it is 8 hours, or 8 * 60 minutes later than original time
	
	foreach( @grey )
		{   next if ( !$_ );
			my $comp = $_;
			next if ( !$grey_list{ $comp } );
		  
			my $times_up = $additional_time + $grey_list{ $comp };
	
			#  Has enough time gone by?
			if ( $times_up < $current_time )
				{	my $retcode = &AddSpamMailBlocker( $comp );		  
			   
					# Delete the old Grey record
					&DeleteGreyList( $comp );
			   			   
					#  Delete it from the temp. grey list in memory
					delete $grey_list{ $comp };  			   
				}
			
			if ( time() > $maximum_processing_time )
				{	&debug( "maximum time reached so exiting OldGreyList early\n" );
					return;
				}
	  }
	  
	&debug( "exiting OldGreyList\n" );
	  
	return;
}



################################################################################
#
sub CheckGreyList()
#
#  Check to see if if I missed any Grey List emails that should be marked as spam
#  This will happen if I am being restarted a lot
#  If I have missed one, just add it to the grey_list in memory
#
################################################################################
{	&debug( "CheckGreyList\n" );


	# Don't bother if I am not using the grey list stuff
	return( 0 + 0 ) if ( ! $use_greylist );


	#  Calculate the time for 8 hours ago
	my $old_time = time() - ( ( 8 * 60 ) * 60 );  #  This would be over 8 hours ago
   
	#  Figure out 8 hours ago time in the correct format
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );
	$year = 1900 + $year;
	$mon++;
	my $hours_ago = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
   
	
	my $str = "SELECT EmailFrom, EmailTo, [Time], ExternalIpAddress FROM SpamMailBlocker WITH(NOLOCK)  WHERE [Time] > \'$hours_ago\' AND Code = 251";
	$dbhStat = &SqlErrorCheckHandle( $dbhStat );
	my $sth = $dbhStat->prepare( $str );


	if ( ! $sth->execute() )   #  Quit if I get an error here
		{   &oprint( "Error getting Spam Mail Blocker row data for time $hours_ago\n" );
			
			&SqlErrorHandler( $dbhStat );
			$sth->finish();
			
			return( 0 - 1 );
		}

   		
	my $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStat->err );
	
	if ( ! $dbhStat->err )
		{	foreach my $row ( @$array_ref )
				{	my ( $email_to, $email_from, $sql_time, $external_ip_address ) = @$row;
		   
					next if ( !$email_to );  #  Skip it if not to anybody
		   
					if ( ( $email_to )  &&  ( $email_from ) )
						{	my $comp = $email_from . ':' . $email_to;
				
							my $create_time = &SqlTimeToTime( $sql_time );
				
							if ( !exists $grey_list{ $comp } )
								{  $grey_list{ $comp } = $create_time ;  #  Only add it to the list if it doesn't already exist
								}
						} 
				}
		}
	
	&SqlErrorHandler( $dbhStat );
	$sth->finish();
	
	return( 0 + 0 );
}



################################################################################
#
sub SqlTimeToTime( $ )
#  Given a str in the Microsoft SQL datetime format, return an integer in the 
#  system time format - seconds since January 1, 1970
#
################################################################################
{	my $sql_time = shift;
	my $system_time = 0;

    my $year = substr( $sql_time, 0, 4 );
	$year = $year - 1900;
	
    my $mon = substr( $sql_time, 5, 2 );
	$mon = $mon - 1;
	
    my $mday = 0 + substr( $sql_time, 8, 2 );
    my $hour = 0 + substr( $sql_time, 11, 2 );
    my $min = 0 + substr( $sql_time, 14, 2 );
    my $sec = 0 + substr( $sql_time, 17, 2 );
	
	$system_time = timelocal( $sec, $min, $hour, $mday, $mon, $year );
	
	return( $system_time );
}



################################################################################
#
sub DeleteGreyList( $ )
#
#  Given a comp, delete the old entries and the associated files
#  Return 0 if successful, non-zero if not
#  This is called after I've made the Spam Mail Blocker entry into the database
#  Or when I'm cleaning up stray entries
#  Or if the mail has successfully passed the Grey List test
#
################################################################################
{  my $comp = shift;
	
	# Don't bother if I am not using the grey list stuff
	return if ( ! $use_greylist );
	
   return if ( !$comp );
   
   &debug( "DeleteGreyList\n" );
   
   my ( $email_to, $email_from ) = split /:/, $comp, 2;
         
		 
   return if ( !$email_to );
   return if ( !$email_from );
   
   
   my $str = "SELECT MailFile FROM SpamMailBlocker WITH(NOLOCK) WHERE EmailFrom = ? AND EmailTo = ? AND Code = 251";


	# Did I use the from IP address because the email from was blank?
   if ( IsIPAddress( $email_from ) )
     {  $email_from = undef;
     }


	$dbhStat = &SqlErrorCheckHandle( $dbhStat );
   my $sth = $dbhStat->prepare( $str );
   
   $sth->bind_param( 1, $email_from );
   $sth->bind_param( 2, $email_to );
   

   if ( ! $sth->execute() )   #  Quit if I get an error here
     {  &lprint( "Error getting Spam Mail Blocker row data for $comp\n" );	
		 
		&SqlErrorHandler( $dbhStat );	
		$sth->finish();
		
		return( 0 - 1 );
     }		
		
   my $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStat->err );
	 
   # Delete the mail files
   foreach my $row ( @$array_ref )
     {  my ( $mail_file ) = @$row;
		unlink( $mail_file ) if ( $mail_file );
     }
	
	&SqlErrorHandler( $dbhStat );	   
	$sth->finish();
   
   
   # Now delete the grey entries
   $str = "DELETE FROM SpamMailBlocker WHERE EmailFrom = ? AND EmailTo = ? AND Code = 251";
   
   $dbhStat = &SqlErrorCheckHandle( $dbhStat );
   $sth = $dbhStat->prepare( $str );
   
   $sth->bind_param( 1, $email_from );
   $sth->bind_param( 2, $email_to );
   
   if ( !$sth->execute() )   #  Quit if I get an error here
     {   &lprint( "Error deleting Grey entries Spam Mail Blocker row data for $comp\n" );
		 
		 $dbhStat = &SqlErrorCheckHandle( $dbhStat );
		 $sth->finish();
		 
		 return( -1 ); 
     }
	 
	&SqlErrorHandler( $dbhStat ); 
	$sth->finish();
	
	return( 0 );
}



################################################################################
#
sub AddSpamMailBlocker( $ )
#
#  Given a comp, add the entry to the IpmStatistics Spam Mail Blocker database
#  Return 0 if successful, non-zero if not
#
################################################################################
{	my $comp = shift;
	
	# Don't bother if I am not using the grey list stuff
	return if ( ! $use_greylist );
	
	return if ( !$comp );
   
	&debug( "AddSpamMailBlocker\n" );
   
	my ( $email_to, $email_from ) = split /:/, $comp, 2;
     
	my $str = "SELECT ObjectID, InternalIpAddress, InternalPort, ExternalIpAddress, ExternalPort, EmailToDomain, EmailSubject, ResolvedDomain, MailFile FROM SpamMailBlocker WITH(NOLOCK) WHERE EmailFrom = ? AND EmailTo = ? AND Code = 251 ORDER BY ID";

	# Did I actually use the External Ip Address as the email_from?
	if ( &IsIPAddress( $email_from ) )
		{  $str = "SELECT ObjectID, InternalIpAddress, InternalPort, ExternalIpAddress, ExternalPort, EmailToDomain, EmailSubject, ResolvedDomain, MailFile FROM SpamMailBlocker WITH(NOLOCK) WHERE ExternalIpAddress = ? AND EmailTo = ? AND Code = 251 ORDER BY ID";
		}

	$dbhStat = &SqlErrorCheckHandle( $dbhStat );
	my $sth = $dbhStat->prepare( $str );
	
	$sth->bind_param( 1, $email_from );
	$sth->bind_param( 2, $email_to );
   
	if ( !$sth->execute() )   #  Quit if I get an error here
		{	&lprint( "Error getting Spam Mail Blocker row data for $comp\n" );
		 
			&SqlErrorHandler( $dbhStat );	
			$sth->finish();
		 
			return( -1 );		  
		}
				
	my $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStat->err );
	my ( $object_id, $internal_ip_address, $internal_port, $external_ip_address, $external_port, $email_to_domain, $email_subject, $resolved_domain, $mail_file ) = @_;
 
	my $counter = 0 + 0;
   
	if ( ! $dbhStat->err )
		{	foreach my $row ( @$array_ref )
				{  $counter++;
					( $object_id, $internal_ip_address, $internal_port, $external_ip_address, $external_port, $email_to_domain, $email_subject, $resolved_domain, $mail_file ) = @$row;
				}
		}
		
	&SqlErrorHandler( $dbhStat );		   
	$sth->finish();
  
  
	# If nothing returned, just give up 
	if ( $counter == 0 )
		{	# &lprint( "Unable to find Spam Mail Blocker database records for EmailTo: $email_to, EmailFrom: $email_from\n" );
			return( -2 ) 
		}
	 
	my $retcode = 0;
	my $dest;

	#  Check to see if the mail files exists - if so, copy it to the right file name
	if ( ( $mail_file )  &&  ( -e $mail_file ) )
		{	#  Change the destination file name to start with a s instead of a g
			my @parts = split /\\/, $mail_file;
   
			$parts[ $#parts ] =~ s/g/s/;
			foreach ( @parts )
				{  if ( !$dest )  {  $dest = $_;  }
					else  {  $dest = $dest . "\\" . $_;  }
				}
   
   
			# If the destination file is a different name, copy it
			if ( $mail_file ne $dest )
				{  $retcode = copy( $mail_file, $dest ) if ( !-e $dest );  # Copy the file if it doesn't already exist
				}
		}

	
	# Make sure the dest file name has something in it
	$dest = $mail_file if ( ! $dest );
	$dest = " " if ( ! $dest );
	
	$object_id = "" if ( ! $object_id );
	
	my $qinternal_ip_address	= &quoteurl( $internal_ip_address );
	$qinternal_ip_address = "0" if ( ! $qinternal_ip_address );
	
	my $qexternal_ip_address	= &quoteurl( $external_ip_address );
	$qexternal_ip_address = "0" if ( ! $qexternal_ip_address );
	
	my $qemail_from				= &quoteurl( $email_from );
	$qemail_from = "" if ( ! $qemail_from );
	
	my $qemail_to				= &quoteurl( $email_to );
	$qemail_to = "" if ( ! $qemail_to );
	
	my $qemail_subject			= &quoteurl( $email_subject );
	$qemail_subject = "" if ( ! $qemail_subject );
	
	my $qdest					= &quoteurl( $dest );
	$qdest = "" if ( ! $qdest );
	
	my $qinternal_port			= &quoteurl( $internal_port );
	$qinternal_port = "0" if ( ! $qinternal_port );
	
	my $qexternal_port			= &quoteurl( $external_port );
	$qexternal_port = "0" if ( ! $qexternal_port );
	
	my $qemail_to_domain		= &quoteurl( $email_to_domain );
	$qemail_to_domain = "" if ( ! $qemail_to_domain );
	
	my $qresolved_domain		= &quoteurl( $resolved_domain );
	$qresolved_domain = "" if ( ! $qresolved_domain );

	my $code = 0 + 250;
	my $status = "Spam (Realtime Spam Checker) Failed Grey List test";
   
	#  At this point I have all the data I need, so call the stored procedure to add the spam record
	$dbhStat = &SqlErrorCheckHandle( $dbhStat );

	$str = "INSERT INTO SpamMailBlocker ( ObjectId,
        InternalIpAddress, InternalPort, ExternalIpAddress, ExternalPort,
        EmailFrom, EmailTo, EmailToDomain, EmailSubject, ResolvedDomain, Code, Status, 
        MailFile, [Time] ) VALUES
        ( '{00000000-0000-0000-0000-000000000000}', ?, '$qinternal_port', ?,
        '$qexternal_port', '$qemail_from', '$qemail_to', '$qemail_to_domain', 
        '$qemail_subject', '$qresolved_domain', '$code', '$status', '$qdest', getdate() )";


	$sth = $dbhStat->prepare( $str );
	
	# Use a bind param call to set the IP address
    $sth->bind_param( 1, $internal_ip_address,  DBI::SQL_BINARY );
    $sth->bind_param( 2, $external_ip_address,  DBI::SQL_BINARY );
   
   
	if ( ! $sth->execute() )
		{	&lprint( "Error inserting into table SpamMailBlocker: SQL Command = $str\n" );
			$retcode = -1;
		}

	&SqlErrorHandler( $dbhStat ); 
	$sth->finish();

	return( $retcode );
}



################################################################################
################################################################################
################################################################################
##############################  Virus Checking  ################################
################################################################################
################################################################################
################################################################################



################################################################################
#
sub VirusInstalled()
#
#  Test to see if virus checking is installed
#  Return 1 if it is installed, undef if not
#  If installed, set the variables @virus_path, @virus_cmd, @virus_args,
#  and @virus_name.
#
################################################################################
{	my $path;
	
	# Check for Lightspeed Virus Scanning - don't use file integrity checking
	# First, make sure the virus signatures file is current
	if ( ! $opt_no_lightspeed_virus )
		{	if ( $opt_lightspeed_virus_update )
				{	&lprint( "Pulling any new virus signatures from the database ...\n" );
					
					my $changed = &SQLVirusUpdate( $dbh, $opt_debug );
					&lprint( "Got some newer virus signatures from the database\n" ) if ( $changed );
					&lprint( "No newer virus signatures in the database\n" ) if ( ! $changed );
				}
				
			#  Setup the next processing time to be in 60 minutes or so - plus 30 seconds
			$virus_signatures_next_time = 30 + ( 60 * 60 ) + time(); 
			
			&lprint( "Loading Lightspeed virus signatures into memory ...\n" );
			if ( &ScanLoadSignatures( &SoftwareDirectory(), $tmp_dir, undef, $opt_debug, undef, undef ) )
				{	push @virus_path, &SoftwareDirectory();
					push @virus_name, "Lightspeed";
					push @virus_cmd, "scan";	
					push @virus_args, " ";
					push @virus_found, "Infection:";
					push @virus_suspected, "suspicious";
					push @virus_system, 0;
					$lightspeed_virus_installed = 1;
					&lprint( "Finished loading Lightspeed virus signatures into memory\n" );
					
					&ScanSetTempDirectory( &SoftwareDirectory(), $tmp_dir );
				}
		}
		

#	# Check for Kaspersky - this is really slow so commenting out
#	$path = "C:\\Program Files\\Kaspersky Lab\\Kaspersky Anti-Virus 2009\\avp.exe";
#	if ( -e $path )
#		{	push @virus_path, $path;
#			push @virus_name, "Kaspersky";
#			push @virus_cmd, "avp";	
#			push @virus_args, "scan /i0 /fa /R:$virus_temp_file";
#			push @virus_found, "detected";
#			push @virus_suspected, "xxxxxxxxx";
#			push @virus_system, 0;
#		}
	 

	# Check for F-Prot
	$path = "C:\\Program Files\\FSI\\F-Prot\\fpcmd.exe";
	if ( -e $path )
		{	push @virus_path, $path;
			push @virus_name, "F-Prot";
			push @virus_cmd, "fpcmd";	
			push @virus_args, "/ARCHIVE /DUMB /NOBOOT /NOMEM /PACKED /REPORT=$virus_temp_file /SILENT";
			push @virus_found, "Infection:";
			push @virus_suspected, "could be infected";
			push @virus_system, 0;
		}
	 

	# Check for McAfee Virus Scan 
   $path = "C:\\Program Files\\Common Files\\Network Associates\\VirusScan Engine\\4.0.xx\\scan.exe";
   if ( -e $path )
     {  push @virus_path, $path;
		push @virus_name, "McAfee";
        push @virus_cmd, "scan";	
        push @virus_args, "/ALL /NOBOOT /NOBEEP /NOMEM /MIME /REPORT=$virus_temp_file /UNZIP /SILENT";
		push @virus_found, "Found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 0;
    }

   
	# Check for alternate path for McAfee Virus Scan 
   $path = "C:\\Program Files\\Common Files\\Network Associates\\Engine\\scan.exe";
   if ( -e $path )
     {  push @virus_path, $path;
		push @virus_name, "McAfee";
        push @virus_cmd, "scan";	
        push @virus_args, "/ALL /NOBOOT /NOBEEP /NOMEM /MIME /REPORT=$virus_temp_file /UNZIP /SILENT";
		push @virus_found, "Found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 0;
    }

   
   # Check for Norman anti virus
   $path = "C:\\Norman\\NVC\\BIN\\nvcc.exe";
   if ( -e $path )
     {  push @virus_path, $path;
		push @virus_name, "Norman";
        push @virus_cmd, "nvcc";	
        push @virus_args, "/B /C:1 /N /LF:$virus_temp_file /L:1 /U /Q /SB:0";
		push @virus_found, " -> ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 0;
     }
	 

	# Check for Panda Software Anti Virus
   $path = "C:\\Panda\\Pavcl32\\Pavcl.com";
   if ( -e $path )
     {  push @virus_path, $path;
		push @virus_name, "Panda";
        push @virus_cmd, "pavcl";	
        push @virus_args, "/NOM /NOB /CMP /NOS /AEX /AUT";
		push @virus_found, "Found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 1;
    }

   
	# Check for Panda Software Platinum Anti Virus
   $path = "C:\\Program Files\\Panda Software\\Panda Antivirus Platinum\\Pavcl.com";
   if ( -e $path )
     {  # Because I'm using a system command to execute this, I need to put double quotes
		# on the path name because of the embedded spaces in the path name
		push @virus_path, "\"C:\\Program Files\\Panda Software\\Panda Antivirus Platinum\\Pavcl.com\"";
		push @virus_name, "Panda Platinum";
        push @virus_cmd, "pavcl";	
        push @virus_args, "/NOM /NOB /CMP /NOS /AEX /AUT";
		push @virus_found, "Found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 1;
    }

   
   
   # Check the registry for Sophos path for Sophos SAV32CLI
   my $found_sophos;
   $path = &SophosPath();
	if ( ( $path )  &&  ( -e $path ) )
     {  push @virus_path, $path;
		push @virus_name, "Sophos";
        push @virus_cmd, "sav32cli";	
        push @virus_args, "-f -sc -ext=txt -mime -archive -ss -p=$virus_temp_file";
		push @virus_found, "found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 0;
		$found_sophos = 1;
    }
  
   
	# Check for Sophos SAV32CLI
   $path = "C:\\SAV32CLI\\sav32cli.exe";
   if ( ( ! $found_sophos )  &&  ( -e $path ) )
     {  push @virus_path, $path;
		push @virus_name, "Sophos";
        push @virus_cmd, "sav32cli";	
        push @virus_args, "-f -sc -ext=txt -mime -archive -ss -p=$virus_temp_file";
		push @virus_found, "found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 0;
		$found_sophos = 1;
    }

   
	# Check for alternate path for Sophos SAV32CLI
   $path = "C:\\Program Files\\Sophos SWEEP for NT\\sav32cli.exe";
   if ( ( ! $found_sophos )  &&  ( -e $path ) )
     {  push @virus_path, $path;
		push @virus_name, "Sophos";
        push @virus_cmd, "sav32cli";	
        push @virus_args, "-f -sc -ext=txt -mime -archive -ss -p=$virus_temp_file";
		push @virus_found, "found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 0;
		$found_sophos = 1;
    }

   
	# Check for another alternate path for Sophos SAV32CLI
   $path = "C:\\Program Files\\Sophos\\Sophos Anti-Virus\\sav32cli.exe";
   if ( ( ! $found_sophos )  &&  ( -e $path ) )
     {  push @virus_path, $path;
		push @virus_name, "Sophos";
        push @virus_cmd, "sav32cli";	
        push @virus_args, "-f -sc -ext=txt -mime -archive -ss -p=$virus_temp_file";
		push @virus_found, "found ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 0;
		$found_sophos = 1;
    }

   
   # Check for Generic Antivirus
   $path = "\\antivirus\\scan.cmd";
   if ( -e $path )
     {  push @virus_path, $path;
		push @virus_name, "Generic";
        push @virus_cmd, "scan";	
        push @virus_args, " ";
		push @virus_found, " ";
		push @virus_suspected, "xxxxxxx";
		push @virus_system, 1;
     }
	
	 
	# If I found any engines at all, return 1
	return( 1 ) if ( $virus_path[ 0 ] );
	
	return( undef );
}



################################################################################
#
sub SophosPath()
#
#  Check the registry for a path to the Sopos anit-virus package
#  Return the full path the to program, or undef if not found
#
################################################################################
{	my $key;
	my $type;
	my $data;

	#  First open the Sophos key
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Sophos\\SweepNT", 0, KEY_READ, $key );

	return( undef ) if ( ! $ok );
	$ok = &RegQueryValueEx( $key, "Path", [], $type, $data, [] );

	&RegCloseKey( $key );
	
	return( undef ) if ( ! $ok );   
	return( undef ) if ( ! $data );   

	my $path = $data . "\\sav32cli.exe";
	
	return( $path );
}



################################################################################
#
sub LoadVirusSignatures()
#
#  Load in any new virus signatures - called after every pipe file name read
#  so don't query the table too often
#
################################################################################
{	return( undef ) if ( ! $lightspeed_virus_installed );
	return( undef ) if ( ! $opt_lightspeed_virus_update );
	
	if ( $virus_signatures_next_time )
		{  return( 1 ) if ( time() < $virus_signatures_next_time );  #  Wait a while to do this processing if I have run before
		}

	&debug( "LoadVirusSignatures\n" );
	
	# Are there newer signatures available?
	my $changed = &SQLVirusUpdate( $dbh, $opt_debug );
	
	if ( $changed )
		{	my $ret = &ScanReloadSignatures( $opt_dir );
			&oprint( "Error: return code $ret from reloading virus signature\n" ) if ( $ret );
		}
	
	#  Setup the next processing time to be in 4 hours or so - plus 30 seconds	
	$virus_signatures_next_time = 30 + ( 4 * 60 * 60 ) + time();  

	return( 1 );
}



################################################################################
#
sub VirusCheck( $ )
#
#  Check to see if the file is infected
#  Return 1 if it is infected, 0 if not, and the name of the virus found
#  use all the virus engines that are installed
#  This first part makes sure that we are in the right directory
#
################################################################################
{   my $file = shift;
	
	#  Don't do anything if the virus checker isn't installed
	return( 0 + 0, undef ) if ( !$virus_installed );
	
	#  Also don't check my temporary file
	return( 0 + 0, undef ) if ( $file =~ m/$virus_temp_file/ );
		
    return( 0 + 0, undef ) if ( ! $file );

    return( 0 + 0, undef ) if ( ! -e $file );
	
	my $cwd = getcwd();
	$cwd =~ s#\/#\\#gm;

	my ( $subdir, $short_file ) = &SplitFileName( $file );
	
    chdir( $subdir ) if ( $subdir );  # Don't change the directory if it is the current directory
	
	my $retcode;
	my $msg;

	( $retcode, $msg ) =  &VirusCheckSub( $short_file );

    chdir( $cwd );
	
	return( $retcode, $msg );
}



################################################################################
#
sub VirusCheckSub( $ )
#
#  Check to see if the file is infected
#  Return 1 if it is infected, 0 if not
#  use all the virus engines that are installed
#
################################################################################
{   my $file = shift;
	

    #  Loop throught the virus scanners installed
    for ( my $i = 0;  $virus_path[ $i ];  $i++ )
		{	my $vpath = $virus_path[ $i ];
			my $vargs = $virus_args[ $i ];
			my $vcmd  = $virus_cmd[ $i ];
			my $vname = $virus_name[ $i ];
			my $found = $virus_found[ $i ];
			$found = $file if ( $found eq " " );  # Look for the filename if the found is blank
			my $suspected = $virus_suspected[ $i ];
			
            # If it is some sort of DOS command, use system to execute it
			my $use_system = $virus_system[ $i ];
			

			# Return the virus and scanner that found it in $msg, or undef if not found
			my $msg;
			my $file_id;
			
			# If it is the Lightspeed virus scanner, just call the ScanFile function directly
			if ( $vname eq "Lightspeed" )
				{	( $msg, $file_id ) = &ScanFile( $file, 1, 1 );	# Scan by content, and ignore unknown executables

					# Did I have a scan error - probably scanning an encrypted zip file
					$msg = undef if ( ( $msg )  &&  ( $msg =~ m/Scan error/ )  &&  ( ! $block_scan_errors ) );
					$msg = &VirusSpam( $msg );
					
					# If I got a virus infected email - could it be in a spam unblocked category?
					if ( $msg )
						{	my ( $infected_file, $infected_virus, $infected_category ) = &ScanVirusContained();
							
							# Get the category name of the virus infection
							my $catname = &CategoryName( $infected_category );
							
							# Only block viruses in spam categories that are blocked
							$msg = undef if ( ! &SpamBlockedCategoryName( $catname ) );
						}
				}				
            elsif ( $use_system )	# It's a DOS type scanner
				{	unlink( $virus_temp_file );

					my $escaped_file = $file;
					$escaped_file =~ s#\\#\\\\#g;

					my $cmd = "\"$vpath\" $vargs \"$file\" >$virus_temp_file";

					&debug( "Virus DOS cmd: $cmd\n" );
					
					system( $cmd );
					$msg = &VirusMsg( $found, $suspected );

					unlink( $virus_temp_file );
				}				
			else	# It's not the Lightspeed scanner, and it's not a DOS type scanner, so invoke it as a process
				{	my $processObj;
					my $retcode;
					my $cmd = "$vcmd $vargs \"$file\"";
					
					&debug( "Virus process path: $vpath, cmd: $cmd\n" );
					
					if ( !Win32::Process::Create( $processObj, $vpath, $cmd, 0, NORMAL_PRIORITY_CLASS, "." ) )
						{	&lprint( "Error executing virus check program $vpath\n" );
							my $str = Win32::FormatMessage( Win32::GetLastError() );
							&lprint( "$str\n" );
							next;
						}	


					if ( $processObj->Wait( ( 30 * 1000 ) ) )  #  Wait up to 30 seconds
						{	$processObj->GetExitCode( $retcode );
							
							#  virus scanners return an exit code if there was a virus
							$msg = &VirusMsg( $found, $suspected ) if ( $retcode );
								
							unlink( $virus_temp_file );
						}
					else  # Kill it if it's taking too long
						{	$processObj->Kill( 0 );  # Kill the process
							&debug( "Killed the virus scanning process\n" );
							next;
						}
				}	# End of process invoke
							
			
			# Go on to the next virus scanner if I didn't find anything
			next if ( ! $msg );
			
			  														
			# Return the name of the virus found, along with the virus scanner that found it		
			$msg = $msg . " " . $vname;
							
			return( 0 + 1, $msg );
		}	#  End of virus scanner loop


	#  If the file has disappeared, assume it was virus removed by something
    if ( ! -e $file )
		{	my $msg = "Virus detected";
			return( 0 + 1, $msg );
		}


	# return 0, undef if nothing found
	return( 0 + 0, undef );
}



################################################################################
#
sub VirusMsg( $$ )
#
#  Read through the $virus_temp_file file for the message about what virus it is
#
################################################################################
{	my $found = shift;
	my $suspected = shift;
	
	$found = quotemeta( $found );
	$suspected = quotemeta( $suspected );
	
    open TMPTEXT, "<$virus_temp_file" or return( undef );
	
	while ( my $line = <TMPTEXT> )
	  {   next if ( ! defined $line );

		  if ( $line =~ m/$found/ )  # If it matches the found virus text, we have it
		   {  my ( $junk, $infection ) = split /$found/, $line, 2;
			  chomp( $infection );
			  
			  # Clean up any non word characters
			  $infection =~ s/\!//g;  # Get rid of exclaimation marks
			  $infection =~ s/\(//g;  # Get rid of (
			  $infection =~ s/\)//g;  # Get rid of )
			  $infection =~ s/\://g;  # Get rid of :
			  $infection =~ s/virus//g;  # Get rid of the word virus
			  $infection =~ s/^\s+//; # Leading spaces
			  $infection =~ s/\s+$//; # trailing spaces
			  
			  my $msg = "Virus infected";
			  $msg = "$infection" if ( $infection );
			  
			  close TMPTEXT;			  
			  
			  return( $msg );
		   }
		   
		  if ( $line =~ m/$suspected/ )  # If it matches the suspected virus text, we have it
		   {  my $msg = "Unknown virus";
			  
			  close TMPTEXT;
			  			  
			  return( $msg );
		   }		   
      }

    close TMPTEXT;
	
    return( undef );
}



################################################################################
# 
sub VirusExample($$)
#
#  Given the virus message, copy the given file to the example directory
#  if it doesn't already exist
#
################################################################################
{	my $virus_name = shift;
	my $file = shift;

	return( 1 ) if ( ! $virus_forward );
	
	my $dir = &VirusExampleDirectory();
	return( undef ) if ( ! $dir );
	
	my $example_name = $virus_name;
	$example_name = "Unknown" if ( ! defined $virus_name );
	
	$example_name =~ s/Infected//;
	$example_name =~ s/infected//;
	$example_name =~ s/Virus//;
	$example_name =~ s/virus//;
	$example_name =~ s/by//;
	$example_name =~ s/\s+//gm;
	$example_name =~ s/\\/\./gm;
	$example_name =~ s#\/#\.#gm;
	$example_name = &CleanFileName( $example_name );
	
	my $newfile = $dir . "\\" . "$virus_lightspeed_email-" . $example_name . ".txt";

	return if ( -e $newfile );
	
	my $success = copy( $file, $newfile );
	
	lprint( "Error copying virus example file $newfile: $!\n" ) if ( ! $success );
	
	return( undef ) if ( ! $success );
	
	$success = &MailFile( $newfile, "virus\@lightspeedsystems.com", $virus_lightspeed_email );
	
	lprint( "Error mailing virus example file $newfile\n" ) if ( ! $success );
	
	return( $success );
}



################################################################################
# 
sub VirusExampleDirectory()
#
#  Return the directory to put example viruses into
#  Create the directory if necessary
#
################################################################################
{	my $dir;
	
	$dir = $opt_dir;
	
	$dir = $dir . "\\Mail Archive\\Virus Examples";
	
	# If the directory doesn't already exist, try to create it
	if ( ! -d $dir )
		{	$dir = $opt_dir;
			$dir = $dir . "\\Mail Archive";
			mkdir( $dir );
			
			$dir = $dir . "\\Virus Examples";
			
			if ( ! mkdir( $dir ) )
				{	&lprint( "Unable to create virus example directory $dir: $!\n" );
					return( undef );
				}
		}
			
	return( $dir );
}



################################################################################
# 
sub VirusCategory( $ )
#
#  Given a category name, return True if it indicates a virus infected email
#
################################################################################
{	my $catname = shift;
	
	return( undef ) if ( ! $catname );
	return( undef ) if ( $catname eq "security.proxy" );	# Let security.proxy go through
	return( 1 ) if ( $catname =~ m/security/ );				# All the other security catnames are trouble
	
	return( undef );
}



################################################################################
# 
sub VirusSpam( $ )
#
#  Given a virus scan result - should I ignore it for spam purposes?
#  Return undef if I should just ignore it
#
################################################################################
{	my $virus_ret = shift;
	
	return( undef ) if ( ! defined $virus_ret );
	
	# Should I ignore password protected zip files as viruses?
	return( undef ) if ( ( ! $opt_password_protected_zip )  &&  ( $virus_ret =~ m/Encrypted\.Zip/i ) );
	return( undef ) if ( ( ! $opt_password_protected_zip )  &&  ( $virus_ret =~ m/Suspicious encrypted program/i ) );
	
	return( $virus_ret );
}



################################################################################
################################################################################
################################################################################
############################  Spam Content Checking  ###########################
################################################################################
################################################################################
################################################################################



my @embedded_urls;	# This is the list of embedded URLs found in this email
################################################################################
#
sub ContentDBCheck( $$ )
#
#  Look through the data and see if there is any blocked URLs embedded in it
#  Return a positive value and the blocked url if found any
#  Also return if the URL is in a virus category
#
################################################################################
{	my $email_from			= shift;
	my $header_email_from	= shift;
	
	&debug( "ContentDBCheck\n" );

	my %checked_domains;	# This is my hash of domains I've already checked
	@embedded_urls = ();
	
	
	# Check the domain of the email from
	my ( $user, $domain );
	( $user, $domain ) = split /\@/, $email_from, 2 if ( $email_from );
	$domain = &CleanUrlShort( $domain );
	
	
	# Keep track of any spam urls
	my $spam_url;
	
	# Did I get a good domain from the email from?
	my $email_from_domain;
	if ( $domain )
		{	my $retcode = &LookupUnknown( $domain, 0 );
			&AddClue( "DOMAIN", $domain );

			# If not known, test to see if I know the IP address as something I block	
			if ( ! $retcode )
				{	# Should I check to see if the URL is a proxy mail server or a blocked IP address?
					&ProxyTest( $domain ) if ( ( $use_proxy )  ||  ( $use_proxy_dns ) );
					
					# At this point, if I don't know it, call it spam, if block unknown is turned on
					return( 0 + 1, $domain, undef ) if ( ( $block_unknown_urls )  &&  ( ! &OKDomain( $domain ) ) );
				}
			elsif ( $retcode > 0 )
				{	my ( $catnum, $source ) = &FindCategory( $domain, $retcode );
					my $catname = &CategoryName( $catnum ) if ( $catnum );
							
					# Is it a virus category?
					if ( ( $catname )  &&  ( &VirusCategory( $catname) ) )
						{	return( 0 + 1, $domain, 1 );
						}
					
					# If it is known, see if it is spam blocked
					if ( ( $catname )  &&  ( &SpamBlockedCategoryName( $catname ) ) )
						{	&debug( "Email from: domain $domain is in spam blocked category $catname\n" );
							$spam_url = $domain;
						}
				}
				
			$checked_domains{ $domain } = 1;
			$email_from_domain = $domain;
		}
		
	
	$domain = undef;
	( $user, $domain ) = split /\@/, $header_email_from, 2 if ( $header_email_from );
	$domain = &CleanUrlShort( $domain );
	
	
	# Don't check the header email from: domain if I just checked it
	$domain = undef if ( ( $domain )  &&  ( $email_from_domain )  &&  ( $email_from_domain eq $domain ) );
	
	
	# Did I get a good domain from the header email from?
	if ( $domain )
		{	my $retcode = &LookupUnknown( $domain, 0 );
			&AddClue( "DOMAIN", $domain );
			
			# If not known, test to see if I know the IP address as something I block	
			if ( ! $retcode )
				{	# Should I check to see if the URL is a proxy mail server or a blocked IP address?
					&ProxyTest( $domain ) if ( ( $use_proxy )  ||  ( $use_proxy_dns ) );
					
					# At this point, if I don't know it, call it spam, if block unknown is turned on
					return( 0 + 1, $domain, undef ) if ( ( $block_unknown_urls )  &&  ( ! &OKDomain( $domain ) ) );
				}
			elsif ( $retcode > 0 )
				{	my ( $catnum, $source ) = &FindCategory( $domain, $retcode );
					my $catname = &CategoryName( $catnum ) if ( $catnum );
							
					# Is it a virus category?
					if ( ( $catname )  &&  ( &VirusCategory( $catname) ) )
						{	return( 0 + 1, $domain, 1 );
						}
					
					# If it is known, see if it is spam blocked
					if ( ( $catname )  &&  ( &SpamBlockedCategoryName( $catname ) ) )
						{	&debug( "Header email from: domain $domain is in spam blocked category $catname\n" );
							$spam_url = $domain;
						}
				}
								
			$checked_domains{ $domain } = 1;	
		}


	# Now check every line of the email for embedded URLs	
	foreach ( @data )
		{	my $line = $_;

			next if ( ! $line );
			
			#  Check for hrefs to a blocked or ad urls
			#  Added checking for plain www.domain.com type of URLs
			while ( ( $line =~ m/http:\/\// )  ||  ( $line =~ m/http\%3a\/\//i )  ||  ( $line =~ m/www\./ )  ||  ( $line =~ m/href=\"/ ) )
				{   my ( $junk, $url );

					if ( $line =~ m/www\./ )
						{	( $junk, $url ) = split  /www\./, $line, 2;
						}
					elsif ( $line =~ m/http:\/\// )
						{	( $junk, $url ) = split  /http:\/\//, $line, 2;
						}
					elsif ( $line =~ m/http\%3a\/\// )
						{	( $junk, $url ) = split  /http:\/\//, $line, 2;
						}
					else
						{	( $junk, $url ) = split  /href=\"/, $line, 2;
						}

                    $line = $url;  #  Put what's left into line so that if there is multiple https on the same line we handle it
                    
                    #  Try to clean off as much crap as possible
                    ( $url, $junk ) = split  /http:\/\//, $url, 2 if ( $url );
                    ( $url, $junk ) = split  /http\%3a\/\//, $url, 2 if ( ( $url )  &&  ( ! $junk ) );
                    ( $url, $junk ) = split  /\s/, $url, 2 if ( $url );

                    ( $url, $junk ) = split /\?/, $url, 2 if ( $url );
                    ( $url, $junk ) = split /\"/, $url, 2 if ( $url );

                    last if ( ! defined $url );

                    #  If it has a user id at the front of the url
                    if ( $url =~ m/\@/ )
                       {  ( $junk, $url ) = split /\@/, $url, 2 if ( $url );
                       }

                    $url = &CleanUrl( $url );

                    last if ( ! defined $url );
					
					push @embedded_urls, $url;
	
					my ( $domain, $url_ext ) = split /\//, $url, 2;
					
					# Have I just checked this?
					next if ( $checked_domains{ $domain } );
					$checked_domains{ $domain } = 1;
					
					# Is this a common domain?
					next if ( &CommonDomain( $domain ) );
					
					# Add the URL as a clue to check later in the Spam Patterns
					&AddClue( "BODY URL", $url );
					
                    bprint "Embedded URL $url\n" if ( $opt_show_most_interesting || $opt_debug );
                    my $retcode = &LookupUnknown( $domain, 0 );
					
					&AddClue( "BODY DOMAIN", $domain );
					
					
					#  If I don't know the URL maybe I should go ahead and block it
                    if ( ! $retcode )
						{	&debug( "Unknown URL: $url\n" );
							
							# Is the domain probably ok?
							next if ( &OKDomain( $domain ) );
							
							# Should I check to see if the URL is a proxy mail server or a blocked IP address?
							&ProxyTest( $url ) if ( ( $use_proxy )  ||  ( $use_proxy_dns ) );		

							next if ( &IsIPAddress( $domain ) );

							# At this point, if I don't know it, call it spam, if block unknown is turned on
							return( 0 + 1, $url, undef ) if ( $block_unknown_urls );
							
							next;
						}
						
					# Figure out the category	
                    my ( $catnum, $source ) = &FindCategory( $url, $retcode );
					my $catname = &CategoryName( $catnum );
					next if ( ! defined $catname );
					
					&debug( "Category name = $catname, category number = $catnum\n" );
					 
					# Is it a virus category?
					if ( ( $catname )  &&  ( &VirusCategory( $catname) ) )
						{	return( 0 + 1, $url, 1 );
						}
					
					# If it is known, see if it is spam blocked
					if ( ( $catname )  &&  ( &SpamBlockedCategoryName( $catname ) ) )
						{	&debug( "Embedded URL $url is in spam blocked category $catname\n" );
							$spam_url = $url;
						}
				
					last if ( ! $line );
					last if ( ! defined $line );
				}
		}

	return( 0 + 1, $spam_url, undef ) if ( defined $spam_url );
	
    return( 0 + 0, undef, undef );
}



################################################################################
#
sub OKDomain( $ )
#
#  Given an unknown domain, return True if it is probably OK, undef if not
#
################################################################################
{	my $domain = shift;
	
	# These domains are always OK
	return( 1 ) if ( $domain =~ m/\.k12\./ );
	return( 1 ) if ( $domain =~ m/\.gov$/ );
	return( 1 ) if ( $domain =~ m/\.mil$/ );
	return( 1 ) if ( $domain =~ m/\.edu$/ );
	
	return( undef );
}



################################################################################
#
sub CommonDomain( $ )
#
#  Given an unknown domain, return True if it is a common domain, undef if not
#
################################################################################
{	my $domain = shift;
	
	return( undef ) if ( ! defined $domain );
	
	foreach ( @common_domains )
		{	my $qdomain = $_;
			next if ( ! $qdomain );
			
			return( 1 ) if ( $domain =~ m/$qdomain/ );
		}
	
	return( undef );
}



################################################################################
#
sub DangerousURLCheck( $ )
#
#  Look through the embedded URLs and see if any of them look dangerous
#  Return a positive value and the blocked url if found
#
################################################################################
{	&debug( "DangerousURLCheck\n" );
	
	foreach ( @embedded_urls )
		{	next if ( ! defined $_ );
			my $url = lc( $_ );
			my ( $domain, $url_ext ) = split /\//, $url, 2;
			next if ( ! defined $url_ext );
			
			# Ignore URLs that end in .com - this is the Yahoo Mail problem
			next if ( $url_ext =~ m/\.com$/i );
			
			my $dangerous = &AttachedFilesCheck( $url_ext );
			return( 0 + 1, $url ) if ( $dangerous );
		}
		
	return( 0 + 0, undef );	
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
	
	if ( $opt_debug )
		{	&debug( "AddClue: $name $clue\n" );
		}
	elsif ( $opt_show_clues )
		{	&bprint( "AddClue: $name $clue\n" );
		}
	
	# Is it an existing clue, to add to the rest of the clue?
	if ( defined $clues{ $name } )
		{	$clues{ $name } .= "\n$clue";
			return;
		}
		
	$clues{ $name } = $clue;
	
	return;
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


     $corpus_file = $opt_dir . "\\localtokens.txt";


     if ( ! open( TOKENS, "<$corpus_file" ) )
       {   $corpus_file = $opt_dir . "\\spamtokens.txt";
		   
		   # If I can't open either file, log the error, turn off Bayesian, and return
           if ( ! open( TOKENS, "<$corpus_file" ) )
			{	&lprint( "Cannot open $corpus_file: $!\n" );
				&lprint( "Turning off using Bayesian statistics\n" );
				$use_bayesian = undef;
				return( undef );
			}
       }


	while ( my $line = <TOKENS> )
		{	next if ( ! defined $line );   
			chomp( $line );
			my ( $token, $weight, $good, $bad ) = split /\s/, $line;

			next if ( ! defined $token );
			$weight = 0 + 0 if ( ! defined $weight );
			$good	= 0 + 0 if ( ! defined $good );
			$bad	= 0 + 0 if ( ! defined $bad );
			
			next if ( $weight =~ m/[^0-9\.]/ );
			next if ( $good =~ m/[^0-9\.]/ );
			next if ( $bad =~ m/[^0-9\.]/ );
			
			#  Is this token used enough?
			my $frequency = 0 + $bad + $good;
			next if ( $frequency < $min_frequency );

			$token_spam_rating{ $token }	= 0 + $weight;
			$spam_occurrences{ $token }		= 0 + $bad;
			$nonspam_occurrences{ $token }	= 0 + $good;

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
       {      next if ( !$_ );

              my  $token = $_;
          
              #  Use the same variable names as Paul Graham
              my  $goodcount = 0 + 0;
    	my  $badcount = 0 + 0;

              if ( defined( $nonspam_occurrences{ $token } ) )
  	  {  $goodcount = $nonspam_occurrences{ $token };  }

             if ( defined ( $spam_occurrences{ $token } ) )
	  {  $badcount = $spam_occurrences{ $token }; }

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
			next if ( ! $line );
			
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
                     {  $rating = $token_spam_rating{ $token };  }

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


        # Show the most interesting tokens
        if ( ( $opt_show_most_interesting )  &&  ( !$opt_summary ) )
			{
				# Display the results
				my $str = sprintf( "\nFile name $current_file: %s", $probability_of_spam > $opt_spam_threshold ? "SPAM" : "NOT SPAM" );
				bprint "$str\n";

				$str = sprintf( "Spam Probability  %2.2f \% \n", 100 * $probability_of_spam );
				bprint "$str";

				bprint "Total Email Tokens Found (Not Unique): ", scalar @email_tokens, "\n";
				bprint "Interesting Tokens: ", $interesting_tokens_count, "\n";
				$str = sprintf( "   %25s %12s   %12s", "Token", "Rating", "Interest" );
				bprint "$str\n";

				my $token_count = 0;

				foreach ( @most_interesting )
					{
						next if ( !defined $_ );
						next if ( !defined $email_token_spam_rating{ $_ } );

						$str = sprintf( "%2d %25s       %2.4f       %2.4f", $token_count, $_, $email_token_spam_rating{ $_ }, $interesting_tokens{ $_ } );
						bprint "$str\n";

						++$token_count;
					}  # end of foreach most_interesting
			}  #  end of opt_show_most_interesting


     #  Return 1 if I think it is spam, 0 if not
	 my $result = sprintf( "Score: %2.4f", $probability_of_spam );
	 
	 return( 0 + 1, $result ) if ( $probability_of_spam > $opt_spam_threshold );
		
     return( 0 + 0, $result );
}



################################################################################
# 
sub PipeRead()
#
#  Read the next file name to check from the pipe
#  Return the file name and the mode = V is for Virus check, A is for all
#
################################################################################
{
    my $pipe_buffer;
    my $done;
    my $filename;
	my $mode;
    my $buf;

    &debug( "PipeRead\n" );
	
    while ( !$done )
       {   #  Is there a \n in the buffer?  
           if ( ( $pipe_buffer )  &&  ( $pipe_buffer =~ m/\n/ ) )
             {  chomp( $pipe_buffer );
				 
				$filename =~ s/\x0d// if ( $filename );  # make sure that any 0ds are gone
				
				( $filename, $mode ) = split /\t/, $pipe_buffer, 2;
				
				$mode = uc( $mode );
				
				$mode =~ s/\x0d//;
				$mode =~ s/\x0a//;
				
                return( $filename, $mode ) if ( defined $filename );  #  Keep going if an undef filename
             }
           else
             {  $buf = $PipeCheck->Read();

                if ( ! $buf )
                   {   my @errstr = $PipeCheck->Error();
                       if ( $errstr[ 0 ] )
                         {  &debug( "Error reading from Win32 pipe $pipe_check: @errstr\n" );
                            return( undef );  #  Error reading from the pipe, so we must be all done
                         }
                       else
                        {  &debug( "Zero length pipe read buffer with no error\n" );

                           $PipeCheck->Close(); 
                           $PipeCheck = new Win32::Pipe( $pipe_check, -1 );
						   
                           if ( !$PipeCheck )    
                             {   # &FatalError( "Can not reopen Win32 pipe $pipe_check\n" ); 
								 &debug( "Can not reopen Win32 pipe $pipe_check\n" );
								 return( undef, undef );  # This will cause the program to go to a normal shutdown
                             }
							 
                           else {  &debug( "Reopened pipe $pipe_check\n" );  }
                        }
                  }
                 else
                   {  $pipe_buffer = $pipe_buffer . $buf;
                   }
             }
       }

    return( $filename, $mode );   
}



################################################################################
# 
sub PipeWrite( $$$ )
#
#  Write the results of the spam check to the pipe
#  Given the filename and the result
#
################################################################################
{   my $filename = shift;
    my $result = shift;
    my $message = shift;

    &debug( "PipeWrite\n" );
	
     my $str = "$filename\x0d\x0a$result\x0d\x0a";
     $str = $str . "$message\x0d\x0a" if ( $message );

     if ( !$PipeResult->Write( $str ) )
       {   my @errstr = $PipeResult->Error();
           &debug( "Error writing to Win32 pipe $pipe_result: @errstr\n" ) if ( $errstr[ 0 ] );
       }
}



################################################################################
# 
sub ProxyTest( $ )
#
#  Write out to the IpmProxyTest pipe the URL to check
#  Return True if able to write out OK, undef if an error
#
################################################################################
{   my $url = shift;

use Fcntl qw/:flock/;

    &debug( "ProxyTest\n" );
	
	return( undef ) if ( ( ! $use_proxy )  &&  ( ! $use_proxy_dns ) );
	return( undef ) if ( ! $url );


	my $software_dir = &SoftwareDirectory();
	my $full_filename = $software_dir . "\\$proxy_file";

	if ( ! open( $proxy_handle, ">>$full_filename" ) )
		{	&lprint( "Unable to open file $full_filename: $!\n" );
			$proxy_handle = undef;
			return( undef );
		}
		
	flock( $proxy_handle, LOCK_EX | LOCK_NB );
	
	seek( $proxy_handle, 0, 2 );
	
	my $ok = print $proxy_handle "$url\n";
	
	&lprint( "Error writing to $proxy_file: $!\n" ) if ( ! $ok );
		
	close $proxy_handle;
	$proxy_handle = undef;
	
	return( 1 );	
}



################################################################################
# 
sub StartProxyTest( $ )
#
#  Start everything up for testing proxy servers
#  Return OK, or undef if a problem occurred
#
################################################################################
{	&debug( "StartProxyTest\n" );  
	
use Cwd;
use Win32::Process;
use Content::Process;

	$proxy_handle = undef;

	my $old_cwd = getcwd;
	$old_cwd =~ s#\/#\\#gm;
	
	my $software_dir = &SoftwareDirectory();
	
	# Set up the proxy test file
	my $full_filename = $software_dir . "\\$proxy_file";

	# Truncate the proxy test file ...
	if ( ! open( $proxy_handle, ">$full_filename" ) )
		{	&lprint( "Unable to open file $full_filename: $!\n" );
			$proxy_handle = undef;
			return( undef );
		}
	
		
	close $proxy_handle;
	$proxy_handle = undef;
	
	
	chdir( $software_dir );

	$full_filename = $software_dir . "\\IpmProxyTest.exe";
	my $cmd = "IpmProxyTest.exe -e";
	
	
	# Am I only checking IP addresses of URLs to see if the IP address is blocked - and doing no actual proxy test??
	$cmd = "IpmProxyTest.exe -e -g" if ( ! $use_proxy );
	
	
	# Does the file exist?
	if ( ! -e $full_filename )
		{	lprint "IpmProxyTest.exe does not exist in the software directory\n";
			return( undef );
		}
		
		
	my $outgoing_process;	
	my $ok = Win32::Process::Create( $outgoing_process, $full_filename, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	if ( ! $ok )
		{	my $str = Win32::FormatMessage( Win32::GetLastError() );
			lprint( "Unable to create outgoing process $full_filename: $str\n" );
			chdir( $old_cwd );
			
			return( undef );
			
		}
	
	sleep( 2 );
	my $count = 0 + 0;
	while ( ( ! &ProcessRunningName( "IpmProxyTest.exe" ) )  &&  ( $count < 8 ) )
		{	sleep( 1 );
			$count++;
		}
		
	chdir( $old_cwd );

	return( 1 );
}
	
	
		
################################################################################
#
sub CleanEmailListStr( $ )
#
#  Given a string containing email addresses and names, clean up the list
#  and return an string containing all the valid email names
#
################################################################################
{   my $str_list = shift;
	
	return( undef ) if ( ! defined $str_list );
	
	my @list = &CleanEmailList( $str_list );
	
	return( undef ) if ( $#list < 0 );
	
	my $new_str_list;
	foreach( @list )
		{	my $email = $_;
			next if ( ! defined $email );
			
			$new_str_list .= ";" . $email if ( defined $new_str_list );
			$new_str_list = $email if ( ! defined $new_str_list );
		}
		
	return( $new_str_list );
}



################################################################################
#
sub CleanEmailList( $ )
#
#  Given a string containing email addresses and names, clean up the list
#  and return an array containing all the valid email names
#
################################################################################
{   my $str_list = shift;

    my @list = ();

	return( @list ) if ( ! defined $str_list );
	
	# Flip commas to semicolons
	$str_list =~ s/\,/\;/g;

	my @parts = split /\;/, $str_list;
	
	foreach ( @parts )
		{	my $part = $_;
			next if ( ! defined $part );

			# Get rid of anything inside "" - like the person's name "Rob" <rob@lightspeedsystems.com> becomes rob@lightspeedsystems.com
			if ( $part =~ m/\".*\"/ )
				{  $part =~ s/\".*\"//g;
				}
			
			next if ( ! defined $part );
			
			$part =~ s/^\s+//;
			next if ( ! defined $part );
			$part =~ s/\s+$//;
			next if ( ! defined $part );
			
			#  Grab anything inside < > as the email address if <> exists
			$part = $1 if ( $part =~ m/\<(.*?)\>/ );
				
			next if ( ! defined $part );
						
			my $email = lc( $part );

			next if ( length( $email ) == 0 );
			
			$email = &CleanEmail( $email );
			next if ( ! defined $email );
			
			# Look for duplicates
			next if &AlreadyListed( $email, \@list );

			push @list, $email;
		}

    return( @list );
}



################################################################################
#
sub CleanEmailPseudo( @ )
#
#  Given a list of clean email addresses, return a list of any possible pseudonyms
#  for any of the addresses in the original list
#
################################################################################
{	my @list = @_;
	
	my @pseudo_list;
	
	foreach ( @list )
		{	next if ( ! defined $_ );
			
			my ( $email, $domain ) = split /\@/, $_, 2;
			next if ( ! defined $email );
			next if ( ! defined $domain );
			
			my $root = &RootDomain( $domain );
			next if ( ! defined $root );
			next if ( $root eq $domain );
			
			my $pseudo = $email . "\@" . $root;
			push @pseudo_list, $pseudo;
		}
		
	return( @pseudo_list );
}



################################################################################
#
sub CleanList( @ )
#
#  Given a list, return the list with all duplicates removed
#
################################################################################
{	my @list = @_;
	
	my @return_list;
	
	foreach ( @list )
		{	next if ( ! $_ );
			
			my $item = $_;
			
			# Look for duplicates
			next if ( &AlreadyListed( $item, \@return_list ) );

			push @return_list, $item;
		}
		
	return( @return_list );	
}



################################################################################
#
sub AlreadyListed( $$ )
#
#  Return True if the item is already in the array
#
################################################################################
{	my $item = shift;
	my $array_ref = shift;
	
	foreach ( @$array_ref )
		{	return( 1 ) if ( $item eq $_ )
		}
		
	return( undef );
}



################################################################################
#
sub CopyFile( $ )
#
#  Copy or move the given full path file to the $opt_copy directory, return TRUE if it worked, undef if not
#
################################################################################
{   my $src = shift;

    my @parts = split /\\/, $src;

    my $filename = $parts[ $#parts ];
    my $dest = $opt_copy . "\\$filename";

    my $retcode = move( $src, $dest );

    return( $retcode );
}



################################################################################
#
sub QuarantineFile( $ )
#
#  Copy or move the given full path file to the $quarantine directory, return TRUE if it worked, undef if not
#
################################################################################
{   my $src = shift;
   
    my @parts = split /\\/, $src;

    my $filename = $parts[ $#parts ];
    my $dest = $quarantine . "\\$filename";
	
    my $retcode = move( $src, $dest );

    return( $retcode );
}



################################################################################
#
sub HandleSpam( $ )
#
#  Given a spam file, is there something special I should do with it
#
################################################################################
{   my $file = shift;
   
	return if ( ! $opt_spam_dir );
	
    my @parts = split /\\/, $file;

    my $filename = $parts[ $#parts ];
    my $dest = $opt_spam_dir . "\\$filename";
	
    my $retcode = move( $file, $dest );

    return( $retcode );
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

     lprint( @_ );
}



################################################################################
#
sub oprint( @ )
#
#  Print a line of text to STDOUT in normal or HTML format, depending on the CGI enviroment
#  And also print it to the log file if logging is turned on
#
################################################################################
{
	bprint( @_ );
	&PrintLogFile( @_ ) if ( $opt_logging );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmRealtimeSpam";

    bprint <<".";
Usage: $me
Gets filenames from the spam pipe or from the command line
Reads the file and decides if it is spam or not.

Uses "LocalTokens.txt" for the token weights if it exists, otherwise it
uses "SpamTokens.txt".


  -0, --remote         use remote databases TrafficRemote and RemoteStatistics
  -a, --aggressive     percentage value of how aggressive to grade spam
                       0 = low, 100 high, default is 50. 
  -b, --benchmark      track number of seconds spent in each operation
  -c, --copy=directory move any spam files found to the given directory
  -d, --directory      directory of the tokens file
                       default is "\\Software Directory".
  -e, --cluelist       create a clue list file for each message file
  -h, --help           display this help and exit
  -i, --interest       the maximum number of interesting keywords to use
                       default = 50 
  -k, --kkk            do not update virus signatures from the local database
  -n, --nopipe         read file names to check from the command line 
                       instead of program API
  -o, --offset         offset from 1 and 0 for the maximum and mimimum
                       token value,  default is 0.1
  -p, --policy         force using SPF testing
  -q, --quarantine=directory   directory to put virus infected files into
  -r, --ratio          expected ratio of ham to spam, default is 1.15
  -s, --summary        to show summary information only
  -t, --tmp TMPDIR     to use TMPDIR for unpacking attachments
  -u, --unlink         unlink (delete) virus infected files
  -v, --virus          only do virus checking
  -z, --zvirus         display the different virus scanners found on this PC
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
    my $me = "IpmRealtimeSpam";

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
