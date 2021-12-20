################################################################################
#!perl -w
#
# Rob McCarthy's Ipm Spam Forward source code
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use DBI qw(:sql_types);
use DBD::ODBC;
use Unicode::String qw(utf8 latin1 utf16);

use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;

use Fcntl qw(:DEFAULT :flock);
use Net::SMTP::Multipart;
use Cwd;

use Content::File;
use Content::SQL;
use Content::Mail;
use Content::Process;



# Options
my $opt_subject = "===SPAM===:";	# This is default subject line to prepend
my $opt_dir;						# Directory to put debugging error logs
my $opt_help;
my $opt_debug;						# True if debugging
my $opt_version;
my $opt_logging;					# True if I should be logging details about all the messages
my $opt_wizard;						# True if I should't display headers and footers
my $opt_forward;					# True if I should forward the command line file without white listing it
my $opt_to_forward;					# If set, this is the to address to use to send the email to
my $opt_resend;						# If set, this is a command line argument containing the date to resend ham messages



# Globals
my	$_version = "2.0.0";
my	$dbh;
my	$dbhStats;														#  My database handle for the statistics database
my	$current_id;
my	$setcurrentid_next_time;										# The next time to save the current id into the registry - added so that I don't thrash the registry
my	$lightspeed_email_from = "notspam\@lightspeedsystems.com";		# This is the email address to put in the from field for spam messages
my	$lightspeed_email_forward = "forward\@lightspeedsystems.com";	# This is the email address to put in the from field for forwaring messages
my  $lightspeed_mail_server = "mail.lightspeedsystems.com";			# This is the email server to send command line messages to
my	@spam_forward_exceptions = ();									# The list of domains and email addresses to forward spam mail for - if this is empty, forward everything
my	@domains;														# The list of valid domains, if defined
my  $default_spam_forwarding;										# True if we should forward spam by default
my  $send_summary;													# True if the default is to send the spam summary email
my  $use_autowhitelist = 1;											# True if I should use Auto White List
my  $global_forward_spam;											# True if the default is to forward spam
my  $global_block_spam = 1;											# True if the default is to block spam
my	$create_spam_user_preferences = 1;								# True if I should create the spam user preferences for users that have just gotten spam mail
my	$archive_path;													# The path of the mail archive
my  $supervisor_email_address;										# The email address of the supervisor for forwarded or whitlisted emails
my  $unique_event_name	= "IpmSpamForwardUniqueEvent";
my  $unique_event;



# Special email addresses that will always go through
# These are the addresses that various Lightspeed programs use to send email messages
my @special_addresses = ( "notspam\@lightspeedsystems.com", 
						 "spam\@lightspeedsystems.com", 
						 "blacklist\@lightspeedsystems.com", 
						 "emarketing\@lightspeedsystems.com", 
						 "blockedcontent\@lightspeedsystems.com",
						 "virus\@lightspeedsystems.com",
						 "support\@lightspeedsystems.com",
						 "unknown\@lightspeedsystems.com",
						 "database\@lightspeedsystems.com",
						 "sales\@lightspeedsystems.com",
						 "tipsandtricks\@lightspeedsystems.com",
						 "\"spam mail summary\""
						 );  

my $challenge_email_from;						# The email address to issue email challenges from



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
        "d|directory=s" => \$opt_dir,
        "f|forward"		=> \$opt_forward,
        "l|logging"		=> \$opt_logging,
        "r|resend=s"	=> \$opt_resend,
        "t|to=s"		=> \$opt_to_forward,
        "v|version"		=> \$opt_version,
        "w|wizard"		=> \$opt_wizard,
        "x|xdebug"		=> \$opt_debug,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "IpmSpamForward" ) if ( ! $opt_wizard );
	
	my $filename = shift;
		
	&TrapErrors() if ( ! $opt_debug );
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);

	if ( ( $opt_to_forward )  &&  ( ! defined $filename ) )
		{	print "You need to specify a mail file to forward when setting the to: address\n";
			exit( 0 );
		}
		
	# Get the properties out of the registry
	&GetProperties();
	

	# Am I resending ham from a certain date?
	if ( $opt_resend )
		{	# Check to see if I got a valid date
			my $valid = 1;
			my ( $mon, $day, $year ) = split /\//, $opt_resend, 3;
			$valid = undef if ( ! $mon );
			$valid = undef if ( ! $day );
			$valid = undef if ( ! $year );
			
			$valid = undef if ( ( $valid )  &&  ( ( $mon lt "01" )  ||  ( $mon gt "12" ) ) );
			$valid = undef if ( ( $valid )  &&  ( ( $day lt "01" )  ||  ( $day gt "31" ) ) );
			$valid = undef if ( ( $valid )  &&  ( ( $year lt "2000" )  ||  ( $year gt "2100" ) ) );
			
			if ( ! $valid )
				{	print "$opt_resend is not a valid current date in the format \'MM/DD/YYYY\'.";
					exit( 0 );
				}

			#  Open the database
			$dbhStats = &ConnectStatistics() or die "Unable to connect to Statistics database";
			
			&ForwardHam( $opt_resend );			
		}
	# Did I get invoked with a command line filename?
	elsif ( $filename )
		{	&SetLogFilename( "IpmSpamForwardFile.log", undef );
			
			&lprint( "Set logging file to IpmSpamForwardFile.log\n" );
			&debug( "Debugging messages turned on\n" );
			
			&ForwardFile( $filename );
		}
	else # If not, go into service mode
		{	# Kill other copies of IpmSpamForward if they are running
			# Give myself debug privileges
			&ProcessSetDebugPrivilege();

			# Make sure that I'm the only IpmSpamForward program running
			&KillOtherIpmSpamForward();
			
			#  Figure out what directory to use
			$opt_dir = &SoftwareDirectory() if ( !$opt_dir );

			&SetLogFilename( "IpmSpamForward.log", undef );
			&lprint( "Set logging file to IpmSpamForward.log\n" );
			&debug( "Debugging messages turned on\n" );
			
			
			# Load the spam exceptions
			$dbh = &ConnectServer() or die "Unable to connect to Content database";
			
			#  Open the database
			$dbhStats = &ConnectStatistics() or die "Unable to connect to Statistics database";
		
			
			# Load the properties and spam exceptions
			&LoadSpamExceptions();
			
	
			# Show the domains I will forward for
			if ( $domains[ 0 ] )
				{	&lprint( "Forward spam for only the following domains:\n" );
			
					foreach( @domains )
						{	&lprint( "$_\n" );
						}
				}
			else
				{	&lprint( "Forwarding spam for any domain\n" );
				}
		
			# Start forwarding spam
			&SpamForward();

			&SetCurrentID( $current_id, 1 )  if ( $current_id );
		}
	
			
	#  Clean up everything and quit
	$dbhStats->disconnect if ( $dbhStats );
	$dbhStats = undef;
	$dbh->disconnect if ( $dbh );
	$dbh = undef;

   &StdFooter if ( ! $opt_wizard );

exit;
}
################################################################################



################################################################################
# 
sub KillOtherIpmSpamForward()
#
#  Make sure that I'm the only IpmSpamForward program running
#
################################################################################
{	
	# At this point I've been nice - now I'm getting mean
	my $my_pid = &ProcessGetCurrentProcessId();

	my %processes = &ProcessHash();
	
	# Figure out if there are any IpmSpamForward processes running besides myself
	my @process_names	= values %processes;
	my @process_pids	= keys %processes;
	
	my @kill_pids;
	
	my $index = 0 - 1;
	foreach ( @process_names )
		{	$index++;
			
			next if ( ! $_ );
			
			my $name = lc( $_ );
			
			# Is this an IpmSpamForward process?
			next if ( ! ( $name =~ m/ipmspamforward\.exe/ ) );
			
			my $this_pid = $process_pids[ $index ];
			
			next if ( $this_pid eq $my_pid );
	
			push @kill_pids, $this_pid;				 
		}


	print "Found IpmSpamForward processes running, so killing them now ...\n" if ( $kill_pids[ 0 ] );
	
	
	# If I found any, kill them
	foreach ( @kill_pids )
		{	next if ( ! $_ );
			my $kill_pid = $_;
			print "Killing process $kill_pid\n";
			ProcessTerminate( $kill_pid );
		}
		

	# At this point we are all set to go ...
	$unique_event = Win32::Event->new( 1, 0, $unique_event_name );
	if ( ! $unique_event )
		{	print "Unable to stop other IpmSpamForward programs from running\n";
			return( undef );
		}
		
	return( 1 );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename;
	my $dir = &SoftwareDirectory();

	$filename = $dir . "\\IpmSpamForwardErrors.log";
	
	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or &lprint( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	&lprint( "Error logging set to $filename\n" ); 
}



my $database_next_time;
################################################################################
#
sub CheckDatabases()
#
#  Check to make sure the database connections are still going
#
################################################################################
{	
	if ( $database_next_time )
		{  return if ( time() < $database_next_time );  #  Wait a while to do this processing if I have run before
		}

	$database_next_time = 30 + ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so - plus 30 seconds

	&debug( "CheckDatabases\n" );
	
	# Did one of the databases have an error?
	&SqlErrorHandler( $dbhStats );
	&SqlErrorHandler( $dbh );
		
	return;
}




################################################################################
# 
sub LoadSpamExceptions()
#
#  Pull out of the Content database the relevent Spam Exceptions
#  Put into the spam_forward_exceptions table any email that should have
#  spam forwarded
#
################################################################################
{ 
	
	# Initialize the spam forward exceptions array
	@spam_forward_exceptions = ();
	
	
	# If there is a spam exceptions table, use it if spam forwarding is off by default
	if ( ( ! $default_spam_forwarding )  &&  ( &SqlTableExists( "SpamExceptions" ) ) )
		{	my $str = "SELECT Data FROM SpamExceptions WITH(NOLOCK) WHERE Type = \'FORWARD\'";
			$dbh = &SqlErrorCheckHandle( $dbh );
			my $sth = $dbh->prepare( $str );

			if ( !$sth->execute() )   #  Quit if I get an error here
				{   &lprint( "Error getting forwarding Spam exceptions\n" );
				}
	
			my $array_ref = $sth->fetchall_arrayref() if ( ! $dbh->err );

			if ( ! $dbh->err )			
				{	foreach my $row ( @$array_ref )
						{
							my ( $data ) = @$row;
							push @spam_forward_exceptions, $data;
						}
				}
				
			&SqlErrorHandler( $dbh );
			$sth->finish();
		}
	
	
	# If there is a spam user preferences table, use that
	# If we are forwarding spam by default, load the users who don't want spam
	# If we are not forwarding spam by default, load the users who do want spam forwarding
	if ( &SqlTableExists( "SpamUserPreferences" ) )
		{	my $str = "SELECT UserName from SpamUserPreferences WITH(NOLOCK) WHERE Domain IS NULL AND ForwardMail <> 0 AND AutoCreated = 0";			
			$str = "SELECT UserName from SpamUserPreferences WITH(NOLOCK) WHERE Domain IS NULL AND ForwardMail = 0 AND AutoCreated = 0" if ( $default_spam_forwarding );
			
			$dbh = &SqlErrorCheckHandle( $dbh );
			my $sth = $dbh->prepare( $str );

			if ( !$sth->execute() )   #  Quit if I get an error here
				{   &lprint( "Error getting Spam user preferences\n" );
				}
			elsif ( ! $dbh->err )
				{	my $array_ref = $sth->fetchall_arrayref();

					if ( ! $dbh->err )
						{	foreach my $row ( @$array_ref )
								{	my ( $UserName ) = @$row;
									$UserName = lc( $UserName );

									push @spam_forward_exceptions, $UserName;
								}
						}
				}
			
			&SqlErrorHandler( $dbh );	
			$sth->finish();
		}
				
	return( 1 );
}



################################################################################
# 
sub ForwardHam( $ )
#
#  Given a date in the format MM/DD/YYYY, resend all the ham from the day again
#
################################################################################
{	my $date = shift;
	
	my ( $mon, $day, $year ) = split /\//, $date, 3;
	
	my $new_day = $day + 1;
	
	if ( ( $mon == "01" )  &&  ( $new_day > 31 ) )		# Jan
		{	$mon = "02";
			$new_day = 1;
		}
	elsif ( ( $mon == "02" )  &&  ( $new_day > 28 ) )	# Feb
		{	$mon = "03";
			$new_day = 1;
		}
	elsif ( ( $mon == "03" )  &&  ( $new_day > 31 ) )	# March
		{	$mon = "04";
			$new_day = 1;
		}
	elsif ( ( $mon == "04" )  &&  ( $new_day > 30 ) )	# April
		{	$mon = "05";
			$new_day = 1;
		}
	elsif ( ( $mon == "05" )  &&  ( $new_day > 31 ) )	# May
		{	$mon = "06";
			$new_day = 1;
		}
	elsif ( ( $mon == "06" )  &&  ( $new_day > 30 ) )	# June
		{	$mon = "07";
			$new_day = 1;
		}
	elsif ( ( $mon == "07" )  &&  ( $new_day > 31 ) )	# July
		{	$mon = "08";
			$new_day = 1;
		}
	elsif ( ( $mon == "08" )  &&  ( $new_day > 31 ) )	# Aug
		{	$mon = "09";
			$new_day = 1;
		}
	elsif ( ( $mon == "09" )  &&  ( $new_day > 30 ) )	# Sept
		{	$mon = "10";
			$new_day = 1;
		}
	elsif ( ( $mon == "10" )  &&  ( $new_day > 31 ) )	# Oct
		{	$mon = "11";
			$new_day = 1;
		}
	elsif ( ( $mon == "11" )  &&  ( $new_day > 30 ) )	# Nov
		{	$mon = "12";
			$new_day = 1;
		}
	elsif ( ( $mon == "12" )  &&  ( $new_day > 31 ) )	# Dec
		{	$mon = "01";
			$new_day = 1;
			my $new_year = 1 + $year;
			$year = sprintf( "%04d", $new_year );
		}
		
	$day = sprintf( "%02d", $new_day );
	
	my $next_day = "$mon/$day/$year";


    #  First, grab all the extra recipients
	&lprint( "Resending all the ham for the date $date ...\n" );
	
	&lprint( "First finding all the additional recipients ...\n" );
	
    my $str = "SELECT EmailTo, ID FROM SpamMailBlockerRecipients WITH(NOLOCK) WHERE ID > ? ORDER BY ID";
	
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $sth = $dbhStats->prepare( $str );
    $sth->bind_param( 1, $current_id );
	
    if ( ( !$sth->execute() )  ||  ( $dbhStats->err ) )   #  Quit if I get an error here
		{   &lprint( "Error getting Spam Mail recipients\n" );
			
			&SqlErrorHandler( $dbhStats );
			$sth->finish();
			
			return( -2 ) 
		}
		
    my $array_ref = $sth->fetchall_arrayref();
 	my %id_recipients;
	
	foreach my $row ( @$array_ref )
		{	my ( $email_to, $id ) = @$row;
			
			next if ( ! $id );
			
			# Make sure it is a valid email
			$email_to = &CleanEmail( $email_to );
			next if ( ! $email_to );

			my $current = $id_recipients{ $id };
			if ( ! $current )
				{	$id_recipients{ $id } = $email_to;
				}
			else
				{	$current .= ";" . $email_to;
					$id_recipients{ $id } = $current;
				}
		}

		
	&SqlErrorHandler( $dbhStats );
	$sth->finish();
    
	
	&lprint( "Now finding all the ham email for $date ...\n" );
	$str = "SELECT InternalIpAddress, EmailFrom, EmailTo, MailFile, ID FROM SpamMailBlocker WITH(NOLOCK) WHERE [Time] > \'$date\' AND [Time] < \'$next_day\' AND Status like \'OK%\'";


    $dbhStats = &SqlErrorCheckHandle( $dbhStats );
	$sth = $dbhStats->prepare( $str );
	
    if ( ( !$sth->execute() )  ||  ( $dbhStats->err ) )   #  Quit if I get an error here
		{   &lprint( "Error getting Spam Mail Blocker row data\n" );
			
			&SqlErrorHandler( $dbhStats );
			$sth->finish();
			
			return( -1 );
		}
	
			
    $array_ref = $sth->fetchall_arrayref();


	my $counter = 0 + 0;		
	foreach my $row ( @$array_ref )
		{	my ( $internal_ip_address, $email_from, $email_to, $mail_file, $id ) = @$row;
		
			next if ( ! $mail_file );
			next if ( ! $email_to );
			next if ( ! $id );
			
			# If the mail file name starts with x, try if with h
			my ( $dir, $short_file ) = &SplitFileName( $mail_file );
			next if ( ! $dir );
			
			$short_file =~ s/^x/h/;

			$mail_file = "$dir\\$short_file";
			
			if ( ! -e $mail_file )
				{	&lprint( "Mail file $mail_file does not exist!\n" );
					next;		
				}
				
			#  Find all the recipients and stick them into an array @to
			my @to = ();
				
			# Make sure it is a valid email
			$email_to = &CleanEmail( $email_to );
				
			push @to, $email_to if ( $email_to );

			my $current = $id_recipients{ $id };
			my @recipients = split /\;/, $current if ( $current );
			
			push @to, @recipients;
			
			# Did I end up with any valid email addresses to forward to?
			if ( $#to > -1 )
				{	my $ret = &MailFile( $mail_file, $email_from, @to );
				}
			else
				{	&lprint( "Did not find any valid recipients for $mail_file\n" );
				}
				
			$counter++;					  
		}

	&SqlErrorHandler( $dbhStats );
	$sth->finish();

	&lprint( "Forwarded $counter ham emails for $date\n" );
	
	return( 0 );
}



################################################################################
# 
sub ForwardFile( $ )
#
#  Given a spam file, forward it
#  the TO: address can be the original TO;, or a command line $opt_forward TO:
#  or to a supervisor email address if that is configured
#
################################################################################
{   my $filename = shift;
	
	&lprint( "Forwarding spam file $filename\n" );
	
	my $full_filename = &BuildFullFilename( $filename );
	
	if ( ! $full_filename )
		{   &lprint( "Illegal filename $filename\n" );		  
			return( 0 + 1 );
		}
	
	if ( ! -e $full_filename )
		{   &lprint( "Filename $filename does not exist\n" );		  
			return( 0 + 1 );
		}
	
	if ( ! open( SPAM, "<$full_filename" ) )
		{   &lprint( "Error opening file $full_filename: $!\n" );		  
			return( 0 + 1 );
		}


	# Read the fist line of the file - it should be the Lightspeed comment
	my $comment = <SPAM>;
	
	if ( ( ! $comment )  ||
		 ( ! ( $comment =~ m/\(ExternalIpAddress/i ) )  ||
		 ( ! ( $comment =~ m/EmailTo/i ) ) )
		{	&lprint( "$full_filename is not a Lightspeed message file\n" );
			close( SPAM );
			return( -1 );
		}


	# Read additional lines until I get the trailing )
	my $line = $comment;
	while ( ( $line )  &&  ( ! ( $line =~ m/\)/ ) ) )
		{	$line = <SPAM>;
			chomp( $line );
			
			# Get rid of leading whitespace
			$line =~ s/^\s+// if ( $line );

			# Get rid of trailing whitespace
			$line =~ s/\s+$// if ( $line );
									
			$comment .= "," . $line if ( $line );
		}

	
	&lprint( "File $full_filename is a valid Lightspeed message file\n" );
		   
	# First, try to get as much information as possible from the email file itself
	my $email_from;
	my $email_to;
	my $external_ip_address;
	my $subject;
	my $internal_ip_address;

	
	my @parts = split /\s/, $comment;
	my $part_no = 0;
	foreach ( @parts )
		{	$part_no++;
			my $keyword = lc( $_ );
			
			#  Check for a blank value
			next if ( !$parts[ $part_no ] );
			
			next if ( index( "emailfrom:emailto:externalipaddress:internalipaddress:", lc( $parts[ $part_no ] ) ) != -1 );
						 
			if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
			if ( $keyword eq "emailto:" )            {  $email_to = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "internalipaddress:" )  {  $internal_ip_address = lc ( $parts[ $part_no ] );  }
		}
						  

	# Make sure it is a valid email to
	my @envelope_to = split /\,/, $email_to if ( $email_to );
	$email_to = $envelope_to[ 0 ];
	$email_to = &CleanEmail( $email_to );
		
	my $ret;
	
	
	# Forward the file without touching it - except maybe send it to a different user
	
	# Am I supposed to send it to someone different than the original?
	my $original_email_to = lc( $email_to ) if ( $email_to );
	$original_email_to = &CleanEmail( $original_email_to );
	
	# Handle multiple email addresses, separated by a semi-colon
	my @to_recipients = ();
	push @to_recipients, $original_email_to if ( $original_email_to );
	
	if ( $opt_to_forward )
	{	$email_to = lc( $opt_to_forward );
		@to_recipients = split /\;/, $email_to;
	}
	
	my @clean_to_recipients = ();
	foreach my $email (@to_recipients)
	{	
		my $clean_to = &CleanEmail( $email );
		push @clean_to_recipients, $clean_to if ( $clean_to );
	}
	
	my $original_email_from = lc( $email_from ) if ( $email_from );
	$original_email_from = &CleanEmail( $original_email_from );
	
	
	# If I don't have a valid to address, bail out here
	if ( $#clean_to_recipients < 0 )
		{	&lprint( "No valid TO: address for filename $full_filename\n" );
			close( SPAM );
			return( undef );
		}
		

	# FIX!!! For now we do not want to change the "from" address, because multi-recipient e-mails
	# that are forwarded fall into this check and will cause responses to come to us (forward@lightspeedsystems.com)
	# If I am sending it to someone new, put the return email from the lightspeed email address
	#$email_from = $lightspeed_email_forward if ( ( $email_to )  &&  ( $original_email_to )  && 	
	
	# Do I have a supervisor email address?	
	if ( $supervisor_email_address )
		{	$email_from = $email_to;
			$email_to = $supervisor_email_address;
			&lprint( "Forwarding spam file: $full_filename\n" );
			&lprint( "Forwarding to supervisor email address: $email_to\n" );
			&lprint( "Forwarding from original email TO: address: $email_from\n" ) if ( $email_from );
			&lprint( "Original email FROM: address: $original_email_from\n" ) if ( $original_email_from );
		}
	else
		{	&lprint( "Forwarding spam file: $full_filename\n" );
			&lprint( "Forwarding to email address(es): @clean_to_recipients\n" );
			&lprint( "Forwarding from email address: $email_from\n" ) if ( $email_from );
		}
		
	
	# Let the SMTP relay server pick the host to go to - it may be rewritten using the MX in the SMTPRelay properties
	my $host = undef;
	
	
	&lprint( "Forwarding to SMTP server: $host\n" ) if ( $host );
	
	my ( $dir, $short_file ) = &SplitFileName( $full_filename );
	$short_file = "f" . $short_file;


	# I need to read the whole file into the msg variable
	my $header = 1;	# True if I'm reading the header
	
	# Use blank as the email from is there isn't one
	$email_from = "blank" if ( ! $email_from );
	
	# Make up a unique message ID
	my $message_id = sprintf( "%d$email_from", time );


	# Save the entire message - without the comment line - into $msg
	my $msg;
	while (my $line = <SPAM>)
		{	next if ( ! defined $line );
			
			if ( ( $line eq "\n" )  &&  ( $header ) )
				{	$header = undef;
					
					$msg =~ s/\nto:.*/\nTo: $email_to/i if ( undef $opt_to_forward );
					$msg =~ s/\nto:.*/\nTo: $opt_to_forward/i if ( $opt_to_forward );
					
					$msg =~ s/\nfrom:.*/\nFrom: $email_from/i;
					$msg =~ s/\nmessage-id:.*/\nMessage-Id: $message_id/i;
					$msg =~ s/\ndelivered-to:.*//i;
					&lprint( "Rewrote message header for new TO:, FROM:, and Message ID\n" );
				}
			$msg .= $line if ( $msg );
			$msg = $line if ( ! defined $msg );
		}
		
	close( SPAM );
	
	
	# Send the message to the original user as if nothing has happened
	my $errmsg;
	( $ret, $errmsg ) = &SMTPMessageFile( $short_file, $email_from, $msg, $host, undef, @clean_to_recipients );	
	&lprint( "Error from SMTPMessageFile: $errmsg\n" ) if ( ( ! $ret )  &&  ( $errmsg ) ); 
			
			
	# Do I need to whitelist it?	
	if ( ( ! $opt_forward )  &&  ( ! $supervisor_email_address )  &&  ( $use_autowhitelist ) )
		{	# Open the database if it isn't already opened
			my $already_opened = 1 if ( $dbh );
			$dbh = &ConnectServer() if ( ! $dbh );
			&lprint( "Error adding entry to autowhitelist, could not connect to DB.\n" ) if (! $dbh );
			
			# Build the comp for auto whitelisting with each email_to and email_from
			foreach my $recipient (@clean_to_recipients)
			{	my $comp;
				$comp = $recipient . ':' . $email_from if ( ( $recipient )  &&  ( $email_from ) );
	
				if ( $dbh )
					{	$ret = &AddAutoWhiteEntry( $comp );
						&lprint( "Added $comp to autowhitelist ok\n" ) if ( $ret );
						&lprint( "Error adding $comp to autowhitelist\n" ) if ( ! $ret );
					}
			}

			if ( ! $already_opened )
				{	$dbh->disconnect if ( $dbh );
					$dbh = undef;
				}
		}		
		
	return( $ret );
}



################################################################################
# 
sub BuildFullFilename( $ )
#
#  Given a filename, do some simple checks to make sure that it isn't some kind of hacker
#
################################################################################
{	my $filename = shift;
	
	return( undef ) if ( ! defined $filename );
	
	# Change slashes to backslashes
	$filename =~ s#/#\\#gm;
	
	# Does the name contain .. ?
	return( undef ) if ( $filename =~ m/\.\./ );

	# Does the name contain .\ ?
	return( undef ) if ( $filename =~ m/\.\\/ );

	# Does the name end in .txt ?
	return( undef ) if ( ! ( $filename =~ m/\.txt$/i ) );

	# Is the name a directory?
	return( undef ) if ( -d $filename );
			
	# Is the name a normal file?
	return( $filename ) if ( -f $filename );
	
	return( undef );
}



################################################################################
# 
sub SMTPFileForward()
#
#  Send the spam error message if invoked by the command line
#  Given a file name, Subject line to prepend, SMTP server IP address, From: Address and To: address, 
#  email the file
#  Return True if I actually forwarded the email, undef if not, -1 if error
#
################################################################################
{   my $external_ip_address	= shift;
    my $subject				= shift;
    my $host_ipaddress		= shift;
    my $email_from			= shift;
	my $reason				= shift;
	my $email_to			= shift;
    my $to					= shift;
	

    #  This can fail with a bad error if the host isn't there, so wrap it with an eval
	&debug( "Connecting to email host $host_ipaddress\n" );
	
    my $smtp;
    eval {  $smtp = Net::SMTP::Multipart->new( $host_ipaddress );  };

    if ( !$smtp )
      {  &lprint( "Unable to connect to SMTP server at $host_ipaddress\n" );
         return( -1 );
      }

	&logprint( "Connected ok to email host $host_ipaddress\n" );


    &logprint( "\nForwarding spam error mail ...\n" );
    &logprint( "From: $email_from\n" );
    &logprint( "To: $to\n" );
	&logprint( "Subject: $subject\n" );
    
	
    $smtp->Header( To   => $to,
				   Subj => $subject,
				   From => $lightspeed_email_from );

   
    #  Get the multipart boundary
	my $b = $smtp->bound;

    $smtp->datasend( sprintf"\n--%s\n",$b );       
	$smtp->datasend( "Content-Type: text/plain;\n" );
	$smtp->datasend( "	charset=\"us-ascii\"\n" );
	$smtp->datasend( "Content-Transfer-Encoding: quoted-printable\n\n" );

    my $text;
	
	
    $smtp->datasend( "=20\n\n" );
	
    $reason =~ s#Reason: #The reason it was detected as spam is: #;
	
	$text = "This email was originally detected as spam and was blocked by Lightspeed Systems\.  $reason\.";
	
    $smtp->datasend( $text );
    $smtp->datasend( "=20\n\n" );

	$text = "Later it was decided by someone \(probably you\) that it is not actually spam\.  This email contains clues to avoid blocking messages like this in the future\.  Thank you for helping us bo a better job of blocking spam\.";
    $smtp->datasend( $text );
    $smtp->datasend( "=20\n\n" );
	
	
    if ( $email_from )
	  {  $text = "Original Sender: $email_from";
		 $smtp->datasend( $text );
         $smtp->datasend( "=20\n\n" );
	  }
	  
	if ( $external_ip_address )
	  {  $text = "External IP Address: $external_ip_address";
		 $smtp->datasend( $text );
         $smtp->datasend( "=20\n\n" );
      }
	  
	$text = "Original Recipient(s): $email_to";
	$smtp->datasend( $text );
    $smtp->datasend( "=20\n\n" );	  
	  
    $smtp->End;


    &logprint( "Done forwarding spam error email\n" );
	
    return( 1 );
}



################################################################################
# 
sub SpamForward()
#
#  Loop through the Statistics database, pulling new spam mails, and forwarding them
#  This is the main process pool of the Spam Forward program when running as a service
#
################################################################################
{   
    my $done;
    $current_id = &GetCurrentID();
	
	# Check for new spam exceptions about every 20 minutes or so
	my $exception_time = ( 20 * 60 ) + time();
	
    while ( !$done )
       {    #  Get the newest spam in the archive
            #  First, grab all the extra recipients
            my $str = "SELECT EmailTo, ID FROM SpamMailBlockerRecipients WITH(NOLOCK) WHERE ID > ? ORDER BY ID";
			
			$dbhStats = &SqlErrorCheckHandle( $dbhStats );
            my $sth = $dbhStats->prepare( $str );
            $sth->bind_param( 1, $current_id );
			
            if ( !$sth->execute() )   #  Quit if I get an error here
				{   &lprint( "Error getting Spam Mail recipients\n" );
					
					&SqlErrorHandler( $dbhStats );
					$sth->finish();
					
					return( -2 ) 
				}
				
            my @email_to = ();
            my $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStats->err );
            my $email_to_max = 0;
			
			if ( ! $dbhStats->err )
				{	foreach my $row ( @$array_ref )
						{	my ( $email_to, $id ) = @$row;
								
							# Make sure it is a valid email
							$email_to = &CleanEmail( $email_to );
							next if ( ! $email_to );
							next if ( ! &IsDomainOK( $email_to ) );
								
							$email_to[ $email_to_max ][ 0 ] = 0 + $id;
							$email_to[ $email_to_max ][ 1 ] = $email_to;
							$email_to_max++;
						}
				}
				
			&SqlErrorHandler( $dbhStats );
			$sth->finish();


            $str = "SELECT ExternalIpAddress, InternalIpAddress, EmailFrom, EmailTo, EmailSubject, MailFile, ID, Status FROM SpamMailBlocker WITH(NOLOCK) WHERE ID > ? ORDER BY ID";
            $dbhStats = &SqlErrorCheckHandle( $dbhStats );
			$sth = $dbhStats->prepare( $str );
            $sth->bind_param( 1, $current_id );
			
            if ( !$sth->execute() )   #  Quit if I get an error here
				{   &lprint( "Error getting Spam Mail Blocker row data\n" );
					
					&SqlErrorHandler( $dbhStats );
					$sth->finish();
					
					return( -1 );
				}
				
            $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStats->err );

            my $counter = 0 + 0;
			
            my $email_to_pos = 0;
			
			if ( ! $dbhStats->err )
				{	foreach my $row ( @$array_ref )
						{	my ( $external_ip_address, $internal_ip_address, $email_from, $email_to, $email_subject, $mail_file, $id, $status ) = @$row;
						
							# Is this email OK?  It is if the status line starts with OK
							next if ( $status =~ m/^OK/ );
									   							   
							# Is this email Spam?  It is if the status line starts with spam
							next if ( ! ( $status =~ m/^Spam/ ) );
									   							   
							#  Build the new subject line                      
							my $new_subject = $opt_subject . $email_subject;

							my $external_ipaddress_str = IPToString( $external_ip_address );
							my $host_ipaddress = IPToString( $internal_ip_address );


							#  Find all the recipients and stick them into an array @to
							my @to = ();
							  
							# Make sure it is a valid email
								$email_to = &CleanEmail( $email_to );
								$email_to = undef if ( ! &IsDomainOK( $email_to ) );
								
							push @to, $email_to if ( $email_to );

							my $i;
							for ( $i = $email_to_pos;  $i < $email_to_max;  $i++ )
								{   push( @to, $email_to[ $i ][ 1 ] ) if ( $email_to[ $i ][ 0 ] == ( 0 + $id ) );
									last if ( $email_to[ $i ][ 0 ] > ( 0 + $id ) );
								}

							$email_to_pos = $i;
							my $reason = "Reason: $status";

							#  Save my current position
							$current_id = $id;
							&SetCurrentID( $current_id, undef );
							  
							# Did I end up with any valid email addresses to forward to?
							if ( $to[ 0 ] )
								{	my $ret = &SMTPForward( $external_ipaddress_str, $mail_file, $new_subject, $host_ipaddress, $email_from, $reason, -1, @to  );
								}
								
							$counter++;					  
					}
				}

			&SqlErrorHandler( $dbhStats );
			$sth->finish();


             #  If I didn't get anything to forward, go to sleep for a minute
             if ( ! $counter )
				{	sleep( 60 );
				}
			
			
			# Make sure the databases are connected ok
			&CheckDatabases();
			
			
			# If it has gone on for long enough	
			if ( $exception_time < time() )
				{	&LoadSpamExceptions();
					
					# Check for new entries to the auto white list
					&AddAutoWhiteList() if ( $use_autowhitelist );
					
					# Create a spam user preference for any new spam users by checking outgoing mail
					&CreateSpamUserPreferences();
					
					# Check for new spam exceptions about every 20 minutes or so
					$exception_time = ( 20 * 60 ) + time();
				}
       }

    return( 0 );
}



################################################################################
# 
sub SMTPForward()
#
#  Given a file name, Subject line to prepend, SMTP server IP address, From: Addresss and To: addresses, 
#  email the file
#  Return True if I actually forwarded the email, undef if not, -1 if error
#
################################################################################
{   my $external_ip_address	= shift;
	my $filename			= shift;
    my $subject				= shift;
    my $host_ipaddress		= shift;
    my $email_from			= shift;
	my $reason				= shift;
	my $attachment			= shift;   #  True if I should include the original file as an attachment
    my @to					= @_;
	

	# Should I forward this at all?
	my $forward = $default_spam_forwarding;
	

	# Is there a spam forward exception that matches at least one of the recepients?
	if ( ! $forward )
		{	# Build up a list of recepients that match the exceptions
			my @new_to;
			
			foreach ( @to )
				{	my $to = $_;
			
					foreach ( @spam_forward_exceptions )
						{	my $exception = $_;

							# I can have an exception for an entire domain.  The way to tell is that domain exceptions don't have a '@' in them
							my $domain_exception;
							$domain_exception = 1 if ( ! ( $exception =~ m/\@/ ) );
							
							# If the domain exception is containted inside the to: address, forward it
							if ( ( $domain_exception )  &&  ( index( $to, $exception ) != -1 ) )
								{	$forward = 1;
									
									# Since there is an exception that matches, forward the mail to this recepient
									push @new_to, $to;
								}
								
							# Otherwise it has to match exactly
							elsif ( $to eq $exception )
								{	$forward = 1;
									
									# Since there is an exception that matches, forward the mail to this recepient
									push @new_to, $to;
								}
						}
				}
			
			# Replace the old list with this new clean list
			@to = @new_to;
		}
	else	# I am forwarding, but does one or more of the to's have forwarding turned off?
		{
			my @new_to;
			
			foreach ( @to )
				{	my $to = $_;
			
					my $to_forward = 1;
					
					foreach ( @spam_forward_exceptions )
						{	my $exception = $_;
					
							# I can have an exception for an entire domain.  The way to tell is that domain exceptions don't have a '@' in them
							my $domain_exception;
							$domain_exception = 1 if ( ! ( $exception =~ m/\@/ ) );
							
							# If the domain exception is containted inside the to: address, don't forward it
							if ( ( $domain_exception )  &&  ( index( $to, $exception ) != -1 ) )
								{	$to_forward = undef;
								}
							elsif ( $to eq $exception )
								{	$to_forward = undef;
								}
						}
						
					push @new_to, $to if ( $to_forward );
				}
			
			# Replace the old list with this new clean list
			@to = @new_to;
			
			# If I didn't have any valid to's, turn off all forwarding
			$forward = undef if ( ! $to[ 0 ] );
		}
	
	
	if ( ! $forward )
		{	&debug( "Not forwarding this email\n" );
			return( undef );
		}


	# Build the message to send
	my ( $header, $b ) = &MailHeader( $lightspeed_email_from, $subject, @to );

	my $message = $header;
	my $mx = $host_ipaddress;
	

    &logprint( "\nForwarding spam mail ...\n" );
	&logprint( "File: $filename\n" );
    &logprint( "From: $email_from\n" );
    &logprint( "To: @to\n" );
	&logprint( "Subject: $subject\n" );
    
   
	# Buid up a text message as the first part of the multipart
    $message .= sprintf"\n--%s\n",$b;       
	$message .= "Content-Type: text/plain;\n";
	$message .= "	charset=\"us-ascii\"\n";
	$message .= "Content-Transfer-Encoding: quoted-printable\n\n";

	
    $message .= "=20\n\n";
	
    my $text;
	
    $reason =~ s#Reason: #The reason it was detected as spam is: #;
	
	$text = "This email was detected as spam and was blocked by Lightspeed Systems\. It has been forwarded to you by the automated spam forwarding system\.  $reason\.";
	
	$message .= $text . "=20\n\n";
	

	$text = "If you do not want email from the original sender to be marked as spam in the future just reply to this message\.  By replying you will add the original sender to your personal approved sender list, and help us refine our spam blocking\.";
	$message .= $text . "=20\n\n";
	
	
	if ( $email_from )
		{	$text = "Original Sender: $email_from";
			$message .= $text . "=20\n\n";
		}
	  
	if ( $external_ip_address )
		{	$text = "External IP Address: $external_ip_address";
			$message .= $text . "=20\n\n";
		}
	  
	$text = "Original Recipient(s): @to";
	$message .= $text . "=20\n\n";
     

	# Does the file exist?
 	my $file_exists = 1;
	$file_exists = undef if ( ! -r $filename );


    # Check to see if virus or worm
	$reason = lc( $reason );	
	my $infected;	
	$infected = 1 if ( $reason =~ m/infected/ );
	$infected = 1 if ( $reason =~ m/virus/ );
	$infected = 1 if ( $reason =~ m/worm/ );
	$infected = 1 if ( $reason =~ m/trojan/ );
	
	
    if ( $infected )
		{	$text = "I am unable to include the original email as an attachment because it contained a dangerous virus\.";
			$message .= $text . "=20\n\n";
		}
	
	
	# Send the original email as an attachment file if I can
	if ( ( !$infected )  &&  ( $file_exists )  &&  ( $attachment ) )
      {  $message .= sprintf"\n--%s\n",$b;
		  
     	 $message .= "Content-Type: message/rfc822\n";
	     $message .= "Content-Transfer-Encoding: 7bit\n\n";
   
         open INFILE, "<$filename";
	  	 while ( my $line = <INFILE> )
		   {  $message .= $line if ( defined $line );
           }
		 close INFILE;
	  }
	  
	  
	# Use the original filename as part of the new filename  
	my ( $dir, $file ) = &SplitFileName( $filename );
	
	
	my ( $ok, $errmsg ) = &SMTPMessageFile( $file, $lightspeed_email_from, $message, $mx, undef, @to );

    &lprint( "Added email to spool directory\n" ) if ( $ok );
    &lprint( "Error adding email to spool directory: $errmsg\n" ) if ( ! $ok );
	
    return( 1 );
}



################################################################################
# 
sub SetCurrentID( $$ )
#
#  Save the current ID in the registry
#
################################################################################
{   my $current_id = shift;
	my $force = shift;	# True if I should force a save
    my $key;


	if ( ! $force )  # If I'm not forcing a save, then save the current id every 5 minutes of so, so that I don't thrash the registry
		{	if ( $setcurrentid_next_time )
				{  return if ( time() < $setcurrentid_next_time );  #  Wait a while to do this processing if I have run before
				}
			else
				{	$setcurrentid_next_time = ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so - plus 10 seconds
					return;
				}
				
			$setcurrentid_next_time = ( 5 * 60 ) + time();  #  Setup the next processing time to be in 5 minutes or so - plus 10 seconds	
		}
		
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_WRITE, $key );
	RegSetValueEx( $key, "Last Spam Forward ID", 0,  REG_SZ, $current_id ) if ( $ok );
	RegCloseKey( $key ) if ( $ok );

	return;
}



################################################################################
# 
sub GetCurrentID()
#
#  Get the current ID in the registry - if it isn't in the registry, get the largest
#  in the database
#
################################################################################
{	my $key;
	my $type;
	my $data;

	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

	$ok = RegQueryValueEx( $key, "Last Spam Forward ID", [], $type, $data, [] ) if ( $ok );
	
	RegCloseKey( $key ) if ( $ok );
	
	my $current_id = 0;

	if ( $ok )
		{	$current_id = $data;
			return( $current_id );
		}
	
	my $str = "SELECT MAX(ID) AS MaxID FROM SpamMailBlocker WITH(NOLOCK)";
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
	my $sth = $dbhStats->prepare( $str );
	
	if ( !$sth->execute() )
		{   # Must be nothing in the database
			&SqlErrorHandler( $dbhStats );
			$sth->finish();
			
			return( 0 );
		}
				
    ( $current_id ) = $sth->fetchrow_array() if ( ! $dbhStats->err );
	
	&SqlErrorHandler( $dbhStats );
    $sth->finish();

	return( 0 ) if ( ! $current_id );

	return( $current_id );
}



################################################################################
# 
sub GetProperties()
#
#  Get the current properties from the Spam Blocker Object that affect
#  the IpmSpamForward
#
################################################################################
{	my $key;
	my $type;
	my $data;


	# Should I turn on extended logging?
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

	return if ( !$ok );
	$ok = RegQueryValueEx( $key, "Logging", [], $type, $data, [] );
	$opt_logging = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );

	RegCloseKey( $key );
		
		
	# Set the default for spam forwarding - to off
	$default_spam_forwarding = undef;
	@domains = ();
	
	
	#  First get the current config number
	$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations", 0, KEY_READ, $key );

	return if ( !$ok );
	$ok = RegQueryValueEx( $key, "Current", [], $type, $data, [] );

	return if ( !$ok );   
	
	RegCloseKey( $key );
	
	my $current = &HexToInt( $data );

	my $current_key = sprintf( "%05u", $current );

	my $subkey;
	my $counter;
	
	#  Next go through the current config looking for a Spam Mail Blocker object
	for ( my $i = 1;  $i < 100;  $i++ )
		{	$counter = sprintf( "%05u", $i );

			$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter";

			$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
			next if ( !$ok );  

			$ok = RegQueryValueEx( $key, "ProgID", [], $type, $data, [] );  # Blank is the (Default) value

			RegCloseKey( $key );
			
			next if ( !$data );

			last if ( $data =~ m/SpamMailBlockerSvc/ );         
		}

	return if ( ! $data =~ m/SpamMailBlockerSvc/ ); 


	# At this point I've got a spam blocker object in this config
	$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter\\Dynamic Properties";

	$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
	return if ( !$ok );  


	$data = undef;
	$ok = RegQueryValueEx( $key, "Enable Auto Whitelist", [], $type, $data, [] );
	$use_autowhitelist = 1;
	if ( $ok )
		{	$use_autowhitelist = undef if ( $data eq "\x00\x00\x00\x00" );
		}
		
	$ok = RegQueryValueEx( $key, "Forward Archived Spam", [], $type, $data, [] );
	$default_spam_forwarding = 1 if ( ( $ok )  &&  ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );
	
			
	$data = undef;
	$send_summary = undef;
    $ok = RegQueryValueEx( $key, "Send Spam Summary", [], $type, $data, [] );  # Blank is the (Default) value
	$send_summary = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );


	$data = undef;
	$global_forward_spam = undef;
    $ok = RegQueryValueEx( $key, "Forward Archived Spam", [], $type, $data, [] );  # Blank is the (Default) value
	$global_forward_spam = 1 if ( ( $data )  &&  ( $data ne "\x00\x00\x00\x00" ) );


	$data = undef;
	$global_block_spam = 1;
    $ok = RegQueryValueEx( $key, "Block Spam", [], $type, $data, [] );  # Blank is the (Default) value
	$global_block_spam = undef if ( ( $data )  &&  ( $data eq "\x00\x00\x00\x00" ) );


	$data = undef;
	$archive_path = undef;
    $ok = RegQueryValueEx( $key, "Archive Path", [], $type, $data, [] );  # C:\Program Files\Lightspeed Systems\Traffic\Mail Archive
	$archive_path = $data if ( ( $ok )  &&  ( $data ) );
	$archive_path =~ s/\x00//g if ( $archive_path );
	

	$data = undef;
	$ok = RegQueryValueEx( $key, "Challenge Address", [], $type, $data, [] );

	if ( $ok )
		{	$challenge_email_from = $data if ( $data );
			push @special_addresses, $challenge_email_from if ( defined $challenge_email_from );
		}


	$data = undef;
	$create_spam_user_preferences = 1;	
    $ok = RegQueryValueEx( $key, "Create Spam User Preferences", [], $type, $data, [] );
	$create_spam_user_preferences = undef if ( ( $ok )  &&  ( $data eq "\x00\x00\x00\x00" ) );

	$create_spam_user_preferences = undef if ( ! &SqlTableExists( "SpamUserPreferences" ) );


	# I'm done with this key so close it
	RegCloseKey( $key );


	# Is there a supervisor email address or addresses?
#	$data = undef;
#	$supervisor_email_address = undef;	
#	$ok = RegQueryValueEx( $key, "Supervisor Email Address", [], $type, $data, [] );
#	$supervisor_email_address = $data if ( ( $ok )  &&  ( $data ) );


     #  Next go through the current config's Spam Mail Blocker object loading any relay domains that are configured
     for ( my $i = 0;  $i < 255;  $i++ )
		{	my $subcounter = sprintf( "%05u", $i );

			$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter\\Dynamic Properties\\Relay Domains\\$subcounter";

			$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
			next if ( !$ok );  

    		$ok = RegQueryValueEx( $key, "Name", [], $type, $data, [] );  # Blank is the (Default) value
			
			RegCloseKey( $key );
			
			next if ( !$data );

			my $name = lc( $data );
						
			push @domains, $name;	
		}


	return;
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
sub IsDomainOK($)
#  
#  Given an email address, return TRUE is it is one of our domains, undef if not
#
################################################################################
{	my $email_to = shift;
	
	# Bland emails are never valid
	return( undef ) if ( ! $email_to );
	
	# Just return OK if there are no domains listed in the registry
	return( 1 ) if ( ! $domains[ 0 ] );
	
	my ( $name, $edomain ) = split /\@/, $email_to, 2;
	
	return( undef ) if ( ! $edomain );
	
	$edomain = lc( $edomain );
	
	# Search through the list of domains making sure they are ok
	foreach ( @domains )
		{	return( 1 ) if ( $edomain eq $_ );
		}
		
	return( undef );
}



################################################################################
################################################################################
################################################################################
########################  Auto White List Processing  ##########################
################################################################################
################################################################################
################################################################################



################################################################################
#
sub AddAutoWhiteList()
#
#  Check to see if there any any AutoWhiteList entries that I should make
#  That have happened in the last 20 minutes or so
#
################################################################################
{   my @comp_list;
	
	return if ( ! $use_autowhitelist );
	
    &debug( "AddAutoWhiteList\n" );
	
	my ( $newest_time, $newest_time_spamblocker_table ) = &GetNewestTime();
	
	my $timestr = "\'" . $newest_time . "\'";  # Put the date string in the right format for SQL

    # Get the list of outgoing emails that have been recently added ...
    $dbhStats = &SqlErrorCheckHandle( $dbhStats );
	my $sth = $dbhStats->prepare( "SELECT EmailTo, EmailFrom, EmailSubject, Time FROM TrafficClassEmail WITH(NOLOCK) where Incoming = 0 and Time >= $timestr" );
    $sth->execute();

    my $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStats->err );

	if ( ! $dbhStats->err )
		{	foreach my $row ( @$array_ref )
				{	my ( $email_to, $email_from, $email_subject, $time ) = @$row;
							
					$email_subject = lc( $email_subject );
					
							
					# Check to see if the subject line indicates that we shouldn't auto white list
					next if ( $email_subject =~ m/out of office autoreply/ );
					next if ( $email_subject =~ m/undeliverable/ );
					next if ( $email_subject =~ m/failure notice/ );
					next if ( $email_subject =~ m/delivery status/ );
					next if ( $email_subject =~ m/delivery failed/ );
					next if ( $email_subject =~ m/returned mail/ );
							
							
					$email_to = &CleanEmail( $email_to ) if ( defined $email_to );
					next if ( ! defined $email_to );
					
					$email_from = &CleanEmail( $email_from ) if ( defined $email_from );
					next if ( ! defined $email_from );
					
					next if ( $email_to =~ m/spam\@lightspeedsystems\.com/ );
					next if ( $email_from =~ m/spam\@lightspeedsystems\.com/ );
					
					next if ( $email_to eq $email_from );
					
					# Don't bother creating autowhitelist entries for my special addresses
					my $skip;
					foreach ( @special_addresses )
						{	$skip = 1 if ( $_ eq $email_from );
							$skip = 1 if ( $_ eq $email_to );
						}
						
					next if ( $skip );	
						
					my $comp = $email_from . ':' . $email_to;  #  This is backwards because if is from the perspective of going out, not coming in
					push @comp_list, $comp;
							 
					# Keep track of the newest time
					$newest_time = $time if ( $time gt $newest_time );
				}
		}
		
		
	&SqlErrorHandler( $dbhStats );  
	$sth->finish();
	
	
    # Get the list of outgoing emails that have been recently added into the SpamMailBlocker table
    $dbhStats = &SqlErrorCheckHandle( $dbhStats );
	$sth = $dbhStats->prepare( "SELECT ID, EmailTo, EmailFrom, EmailSubject, Time, [Status] FROM SpamMailBlocker WITH(NOLOCK) WHERE [Time] >= \'$newest_time_spamblocker_table\'" );
    $sth->execute();

    $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStats->err );

	my %id;	# Keep a hash of the unique IDs so that I can get additional recipients
	if ( ! $dbhStats->err )
		{	foreach my $row ( @$array_ref )
				{	my ( $id, $email_to, $email_from, $email_subject, $time, $status ) = @$row;
							
					# Keep track of the newest time
					$newest_time_spamblocker_table = $time if ( ( defined $time )  &&  ( $time gt $newest_time_spamblocker_table ) );

					# Ignore anything but outbound mail
					next if ( ! $status );
					next if ( ! ( $status =~ m/OK \(Outbound Email\)/i ) );
							 
					$email_subject = lc( $email_subject );
					
							
					# Check to see if the subject line indicates that we shouldn't auto white list
					next if ( $email_subject =~ m/out of office autoreply/ );
					next if ( $email_subject =~ m/undeliverable/ );
					next if ( $email_subject =~ m/failure notice/ );
					next if ( $email_subject =~ m/delivery status/ );
					next if ( $email_subject =~ m/delivery failed/ );
					next if ( $email_subject =~ m/returned mail/ );
							
							
					$email_to = &CleanEmail( $email_to ) if ( defined $email_to );
					next if ( ! defined $email_to );
					
					$email_from = &CleanEmail( $email_from ) if ( defined $email_from );
					next if ( ! defined $email_from );
					
					next if ( $email_to =~ m/spam\@lightspeedsystems\.com/ );
					next if ( $email_from =~ m/spam\@lightspeedsystems\.com/ );
					
					
					next if ( $email_to eq $email_from );

					# Don't bother creating autowhitelist entries for my special addresses
					my $skip;
					foreach ( @special_addresses )
						{	$skip = 1 if ( $_ eq $email_from );
							$skip = 1 if ( $_ eq $email_to );
						}
						
					next if ( $skip );	
						
					my $comp = $email_from . ':' . $email_to;  #  This is backwards because if is from the perspective of going out, not coming in
					push @comp_list, $comp;
						
					# Keep track of the IDs so that I can pick up additional recipients		 
					$id{ $id } = $email_from;
			}
		}
		
		
	&SqlErrorHandler( $dbhStats );  
	$sth->finish();
	
	
	# Look for additional recipients
	while ( my ( $id, $email_from ) = each( %id ) )
		{	next if ( ! $id );
			next if ( ! $email_from );
			
			$sth = $dbhStats->prepare( "SELECT EmailTo FROM SpamMailBlocker WITH(NOLOCK) WHERE ID = \'$id\'" );
		    $sth->execute();

			$array_ref = $sth->fetchall_arrayref() if ( ! $dbhStats->err );

			if ( ! $dbhStats->err )
				{	foreach my $row ( @$array_ref )
						{	my ( $email_to ) = @$row;
							
							next if ( $email_from eq $email_to );
							
							my $comp = $email_from . ':' . $email_to;  #  This is backwards because if is from the perspective of going out, not coming in
							push @comp_list, $comp;
						}
				}
		}		
		
		
    #  Add the new Auto White List entries
    foreach ( @comp_list )
       {	next if ( !$_ );
			my $comp = $_;
		   
			&AddAutoWhiteEntry( $comp );
       }
	   
	&SetNewestTime( $newest_time, $newest_time_spamblocker_table );
}



################################################################################
# 
sub SetNewestTime( $$ )
#
#  Save newest time from the AddAutoWhiteList subroutine
#
################################################################################
{   my $newest_time						= shift;
	my $newest_time_spamblocker_table	= shift;
	
    my $key;

	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_WRITE, $key );
	
	&RegSetValueEx( $key, "Last AddAutoWhiteList Time", 0,  REG_SZ, $newest_time ) if ( $ok );
	&RegSetValueEx( $key, "Last AddAutoWhiteList SpamBlocker Time", 0,  REG_SZ, $newest_time_spamblocker_table ) if ( $ok );
	
	&RegCloseKey( $key );
	
	return;
}



################################################################################
# 
sub GetNewestTime()
#
#  Get the last newest time for the AddAutoWhiteList subroutine
#
################################################################################
{	my $key;
	my $type;
	my $data;

	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

	$ok = &RegQueryValueEx( $key, "Last AddAutoWhiteList Time", [], $type, $data, [] ) if ( $ok );

	my $newest_time;

	$newest_time = $data if ( $ok );
	 
	$ok = &RegQueryValueEx( $key, "Last AddAutoWhiteList SpamBlocker Time", [], $type, $data, [] ) if ( $ok );

	my $newest_time_spamblocker_table;

	$newest_time_spamblocker_table = $data if ( $ok );
	 
	&RegCloseKey( $key );

	# Did I find both times in the registry?  If not then default them
	if ( ( ! $newest_time )  ||  ( ! $newest_time_spamblocker_table ) )
		{	# Default the time to 20 minutes ago
			my $time_20 = time - ( 20 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $time_20 );
			$year += 1900;
			$mon++;
			
			my $date_str = sprintf( "%04d-%02d-%02d %02d:%02d:00", $year, $mon, $mday, $hour, $min );

			$newest_time = $date_str if ( ! $newest_time );
			$newest_time_spamblocker_table = $date_str if ( ! $newest_time_spamblocker_table );
		}
		
	return( $newest_time, $newest_time_spamblocker_table );
}



################################################################################
#
sub CreateSpamUserPreferences()
#
# Set up User Preferences for any spam mail receipients that aren't in the database
# This function if different than the one in Spam Review
#
################################################################################
{
	&debug( "CreateSpamUserPreferences\n" );
	
	# Am I supposed to create these user preferences?
	return( undef ) if ( ! $create_spam_user_preferences );
	
	# Don't do shit if the table doesn't exist
	if ( ! &SqlTableExists( "SpamUserPreferences" ) )
		{	lprint( "Spam User Preferences table does not exist in the Content database\n" );
			return;	
		}

	&debug( "Creating spam user preferences for new users based on outgoing emails\n" );
		   
	my $newest_time = &GetUserPreferenceNewestTime;
					
	my $timestr = "\'" . $newest_time . "\'";  # Put the date string in the right format for SQL

    # Get the list of outgoing emails that have been recently added ...
	$dbhStats = &SqlErrorCheckHandle( $dbhStats );
    my $sth = $dbhStats->prepare( "SELECT EmailTo, EmailSubject, Time FROM TrafficClassEmail WITH(NOLOCK) where Incoming = 1 and Time >= $timestr" );
    $sth->execute();

    my $array_ref = $sth->fetchall_arrayref() if ( ! $dbhStats->err );


	# This is the list of emails sent out from the TTC server since the last time this function was run
	my %email_to;
	
	if ( ! $dbhStats->err )
		{	foreach my $row ( @$array_ref )
			{
				my ( $email_to, $email_subject, $time ) = @$row;
				
				$email_subject = lc( $email_subject );
				
				# Check to see if the subject line indicates that we shouldn't create a spam user preference
				next if ( $email_subject =~ m/out of office autoreply/ );
				next if ( $email_subject =~ m/undelive/ );
				next if ( $email_subject =~ m/mail delivery failure notice/ );
				next if ( $email_subject =~ m/mail delivery failure notice/ );
				next if ( $email_subject =~ m/failure notice/ );
				next if ( $email_subject =~ m/daemon/ );
				next if ( $email_subject =~ m/bounce/ );
						
				$email_to = &CleanEmail( $email_to ) if ( defined $email_to );
					 
				# Keep track of the newest time
				$newest_time = $time if ( $time gt $newest_time );
				
				next if ( ! defined $email_to );
				
				# Just make one record for each unique address
				$email_to{ $email_to } = 0;
			}
		}
		
		
	&SqlErrorHandler( $dbhStats );  
	$sth->finish();
	
	
	# Now I've got the list of email froms, make sure that they have a user preferences record
	my @email_to = keys %email_to;


	my @no_password;	# This is the list of email_to with no user preference column
	
	foreach ( @email_to )
		{	my $email_to = $_;
			next if ( ! $email_to );
			
			my ( $username, $password  ) = &GetUserPreferences( $email_to );
			
			# Remember, valid usernames can have no passwords ...
			push @no_password, $email_to if ( ! $username );
		}


	&debug( "Creating user preference records for $#no_password new users\n" ) if ( $#no_password > 0 );
	
	
	# Now I have the list of user preference records that need to be created in @no_password
	foreach ( @no_password )
		{	next if ( ! $_ );
			my $email_to = $_;
			
			my $password = &RandomPassword( $email_to );
			
			# Set this user to send the summary if the default is to send the summary
			my $user_send_summary = 0 + 0;
			$user_send_summary = 0 + 1 if ( $send_summary );
			
			my $forward_mail = 0 + 0;
			$forward_mail = 0 + 1 if ( $global_forward_spam );
			
			my $block_spam = 0 + 1;
			$block_spam = 0 + 0 if ( ! $global_block_spam );
			
			# Set the auto create field to true so that I know that I built it
			my $auto_create = 0 + 1;
			
			&SetUserPreferences( $email_to, $password, $user_send_summary, $forward_mail, $block_spam, $auto_create );
		}
	
	
	# Save the time back into the registry	
	&SetUserPreferenceNewestTime( $newest_time );	
}



################################################################################
# 
sub SetUserPreferenceNewestTime( $ )
#
#  Save newest time from the CreateuserPreference
#
################################################################################
{   my $newest_time = shift;
    my $key;

	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_WRITE, $key );
	RegSetValueEx( $key, "Last Create User Preference Time", 0,  REG_SZ, $newest_time ) if ( $ok );
	RegCloseKey( $key );
	
	return;
}



################################################################################
# 
sub GetUserPreferenceNewestTime()
#
#  Get the last newest time for the CreateuserPreference
#
################################################################################
{	my $key;
	my $type;
	my $data;

	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service", 0, KEY_READ, $key );

	$ok = RegQueryValueEx( $key, "Last Create User Preference Time", [], $type, $data, [] ) if ( $ok );

	my $newest_time = '2003-06-01 12:00:00';

	$newest_time = $data if ( $ok );
	 
	RegCloseKey( $key );
	
	return( $newest_time );
}



################################################################################
#
sub RandomPassword( $ )
#
#  Given the email_to, return a 6 digit random password
#  In the case of sjcoe.net, return the email_to as the password
#
################################################################################
{	my $email_to = shift;
	
	return( $email_to ) if ( $email_to =~ m/\@sjcoe\.net$/ );
	return( $email_to ) if ( $email_to =~ m/\@sjcoe\.k12\.ca\.us$/ );
	return( $email_to ) if ( $email_to =~ m/\@lincolnusd\.k12\.ca\.us$/ );
	return( $email_to ) if ( $email_to =~ m/\@lusd\.net$/ );
	
    # Create arbitrary boundary text
    my ( $i, $n, @chrs );
    $b = "";
    foreach $n (48..57,65..90,97..122) { $chrs[$i++] = chr($n);}
    foreach $n (0..5) {$b .= $chrs[rand($i)];}
	
	$b = lc( $b );
	return( $b );
	
}



################################################################################
#
sub SetUserPreferences( $$$$$$ )
#
#  Create the user preference row with the given column data
#
################################################################################
{	my $email_to			= shift;
	my $password			= shift;
	my $user_send_summary	= shift;
	my $forward_mail		= shift;
	my $block_spam			= shift;
	my $auto_create			= shift;
	
	# &debug( "SetUserPreferences\n" );
	
	
	my $vemail_to			= "\'" . $email_to . "\'";
	my $vpassword			= "\'" . $password . "\'";
	my $vuser_send_summary	= "\'" . $user_send_summary . "\'";
	
	my $vforward_mail		= "\'" . $forward_mail . "\'";
	my $vblock_spam			= "\'" . $block_spam . "\'";
	my $vauto_create		= "\'" . $auto_create . "\'";


    my $str = "INSERT INTO SpamUserPreferences ( UserName, Password, SendSummary, ForwardMail, BlockSpam, AutoCreated ) VALUES ( $vemail_to, $vpassword, $vuser_send_summary, $vforward_mail, $vblock_spam, $vauto_create )";
    $dbh = &SqlErrorCheckHandle( $dbh );
	my $sth = $dbh->prepare( $str );
	
    $sth->execute();
	
	&SqlErrorHandler( $dbh );
    $sth->finish();
}



################################################################################
#
sub GetUserPreferences( $ )
#
#  Check to see if the email to has a user preferences record created
#  Return the the username, password if he does, undef if not
#
################################################################################
{   my $email_to = shift;
	
	# &debug( "GetUserPreferences\n" );
	
	return( undef ) if ( !$email_to );
	
	$dbh = &SqlErrorCheckHandle( $dbh );	
    my $sth = $dbh->prepare( "SELECT Username, Password from SpamUserPreferences WITH(NOLOCK) WHERE UserName = ?" );
    $sth->bind_param( 1, $email_to,  DBI::SQL_VARCHAR );
	
    $sth->execute();
	
    my ( $UserName, $Password ) = $sth->fetchrow_array() if ( ! $dbh->err );
	
	&SqlErrorHandler( $dbh );
    $sth->finish();
		
	#  Return the username, password if I found a match
	return( $UserName, $Password ) if ( $UserName );
	
	return( undef, undef );
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

     &lprint( @_ );
}



################################################################################
#
sub logprint( @ )
#
#  Print a message to the log file if logging is turned on
#
################################################################################
{
     return if ( !$opt_logging );

     &lprint( @_ );
}



################################################################################
# 
sub errstr($)
#  
################################################################################
{
    bprint shift;

    return( -1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "IpmSpamForward";

    bprint "$me\n\n" if (@_);

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
    my $me = "IpmSpamForward";

    bprint <<".";
Usage: $me [OPTION(s)] [message filename]
Forwards spam emails to the original recipient with a rewritten header and
encapsulated message.

If invoked with a message filename, that message file only will be forwarded.

Options
  -d, --dir dirpath        use dirpath rather than the default directory
  -f, --forward            don\'t whitelist From: if forwarding a spam message
  -h, --help               display this help and exit
  -l, --logging            do more extensive logging of events
  -r, --resend MM/DD/YYYY  Resend all the Ham emails from a given day
  -t, --to emailTo         forward a spam message to a different To:
                           (separate addresses with a semi-colon)
  -v, --version            display version information and exit
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
    my $me = "IpmSpamForward";

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
