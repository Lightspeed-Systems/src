################################################################################
#!perl -w
#
# Rob McCarthy's Barracuda Results program
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Cwd;
use Win32API::Registry 0.21 qw( :ALL );



use Content::File;
use Content::Mail;
use Content::SQL;



# Options
my $opt_help;
my $opt_verbose;
my $opt_unlink;		# If True, then unlink any mail file that isn't archived
my $opt_date;		# If set, this is the date to calculate Lightspeed errors for
my $opt_dir;		# If set, this is the directory to look for the Barracuda email files
my $opt_spam_for_review = "H:\\Spam For Review";	# The location of the Spam for Review directory



# Globals
my $barracuda_ip = "10.16.1.47";
my $_version = "1.0.0";
my $original_dir = "E:\\Mail Archive";			# This is the directory that the original statistics was gathered for
my %lightspeed_results;							# A hash of the Lightspeed results - key is "email_from\temail_to\tosubject", value is "$result\t$mailfile"

my $dbhLocalSpam;			# The database handle to the local spam database
my $dbhRemoteStatistics;	# The database handle to the remote statistics database

my @method = ( "Adult Subject", "Auto White Listed", "Bayesian Statistics", "Blocked or Spam URL",
			  "Challenge email failed", "Challenge email sent",
			  "Content DB IP", "Dangerous Attachment", "Dangerous URL", "Domain", "Forged Email From Address",
			  "IP", "IP Lookup Delayed", "IP Lookup Timeout", "IP Lookup Unavailable",
			  "Partial message - could contain virus", "RBL IP SpamCop",
			  "Subject", "Virus Infected", "Virus or Spyware URL",
			  "RBL IP SpamHaus", "Recipient", "Sender", "Spam Pattern", "Unresolvable", "Bad Network Reputation" );



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
        "b|barracuda=s"		=> \$opt_dir,
        "d|date=s"			=> \$opt_date,
        "s|spamdir=s"		=> \$opt_spam_for_review,
        "u|unlink"			=> \$opt_unlink,
        "v|version"			=> \$opt_verbose,
        "h|help"			=> \$opt_help
    );


    &Usage() if ( $opt_help );


	&StdHeader( "Barracuda Results" );
	
	&SetLogFilename( "BarracudaResults.log", undef );
	my $log_filename = &GetLogFilename();
	lprint "Barracuda Results log file set to $log_filename\n";
	lprint "Unlink any mail files that are not archived\n" if ( $opt_unlink );
	lprint "Verbose mode\n" if ( $opt_verbose );
	
	# Make sure the date that I'm working with is valid
	my $valid = &ValidateDate( $opt_date );
	if ( ! $valid )
		{	&lprint( "$opt_date is not a valid date\n" );
			exit( 1 );	
		}
	
	
	# Figure out my starting directory
	my $home_dir = getcwd;
	$home_dir =~ s#\/#\\#gm;
	$opt_dir = $home_dir if ( ! defined $opt_dir );
	
	if ( ! -d $opt_dir )
		{	&lprint( "Unable to find directory $opt_dir\n" );
			exit( 1 );	
		}
	
	if ( ! -d $opt_spam_for_review )
		{	&lprint( "Unable to find directory $opt_spam_for_review\n" );
			exit( 1 );	
		}
	

	$dbhRemoteStatistics = &ConnectRemoteStatistics();
	
	if ( ! $dbhRemoteStatistics )
		{
lprint "Unable to open the Remote Statistics database.
Run ODBCAD32 and add the TTC-62 SQL Server as a System DSN named
\'RemoteStatistics\' with default database \'IpmStatistics\'.\n";

			exit( 1 );
		}
		

	$dbhLocalSpam = &ConnectLocalSpam();
	
	if ( ! $dbhLocalSpam )
		{
lprint "Unable to open the Remote Statistics database.
Run ODBCAD32 and add the SpamArchive SQL Server as a System DSN named
\'Spam\' with default database \'Spam\'.\n";

			exit( 1 );
		}

	&LoadLightspeedResults( $opt_date ) if ( $opt_date );
	
	&CheckOverblocks( $opt_date ) if ( $opt_date );

	&CheckUnderblocks( $opt_date ) if ( $opt_date );
	
	&BarracudaResults();

	&RecalculateSummary( $opt_date ) if ( $opt_date );


	# Close the databases cleanly ...
	$dbhRemoteStatistics->disconnect if ( $dbhRemoteStatistics );
	$dbhRemoteStatistics = undef;

	$dbhLocalSpam->disconnect if ( $dbhLocalSpam );
	$dbhLocalSpam = undef;

	
	&StdFooter();
	
    exit;
}



################################################################################
# 
sub RecalculateSummary( $ )
#
#  Recaculate all the summary information given a specific date
#
################################################################################
{	my $date = shift;
	
	return( undef ) if ( ! $date );
	
	&lprint( "Calculating the summary data for $date ...\n" );
	
	my %errors;
	my %lightspeed_errors;
	
	
	&lprint( "Getting errors from the database for $date ...\n" );
	
	my $str = "SELECT Company, Mailfile, Result, Actual FROM Errors WHERE [Date] = \'$date\'";
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	
	my $err_count			= 0 + 0;
	my $total_spam_errors	= 0 + 0;
	my $total_ham_errors	= 0 + 0;
	my $total_virus_errors	= 0 + 0;
	
	
	# Set the initial values to 0 for the totals
	$errors{ "Barracuda\tBlocked Ham" }		= 0 + 0;
	$errors{ "Barracuda\tMissed Virus" }	= 0 + 0;
	$errors{ "Barracuda\tMissed Spam" }		= 0 + 0;
	$errors{ "Lightspeed\tBlocked Ham" }	= 0 + 0;
	$errors{ "Lightspeed\tMissed Virus" }	= 0 + 0;
	$errors{ "Lightspeed\tMissed Spam" }	= 0 + 0;
	
	
	while ( my ( $company, $mailfile, $result, $actual ) = $sth->fetchrow_array() )
		{	next if ( ! $company );
			next if ( ! $mailfile );
			next if ( ! $result );
			next if ( ! $actual );
			
			
			# Figure out the type of error
			my $error_type;
			
			if ( $actual eq "Ham" )
				{	$error_type = "Blocked Ham";
					$total_ham_errors++;
				}
			elsif ( $actual eq "Virus" )
				{	$error_type = "Missed Virus";
					$total_virus_errors++;
				}
			else	# must be missed spam
				{	$error_type = "Missed Spam";
					$total_spam_errors++;
				}
				
				
			my $key = "$company\t$error_type";
			
			my $count = $errors{ $key };
			$count = 0 + 0 if ( ! $count );
			$count++;
			$errors{ $key } = $count;
			
			$lightspeed_errors{ $mailfile } = $result if ( $company eq "Lightspeed" );
			$err_count++;
		}
		
	$sth->finish();

	&lprint( "Found $err_count total errors on $date\n" );
	

	&lprint( "Getting the methods used for $date ...\n" );


	# Get the methods used to block spam for Lightspeed
	$str = "SELECT Mailfile, Method, Result FROM MailFile WHERE [Date] = \'$date\'";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	
	
	# Initialize the method summary
	my %method_summary = ();
	foreach ( @method )
		{	my $method = $_;
			next if ( ! $method );
			
			$method_summary{ "$method\tHam" }	= 0 + 0;
			$method_summary{ "$method\tSpam" }	= 0 + 0;
		}
		

	# Initialize the error summary
	my %error_summary = ();
	foreach ( @method )
		{	my $method = $_;
			next if ( ! $method );
			
			$error_summary{ "$method\tHam\tSpam" }	= 0 + 0;
			$error_summary{ "$method\tSpam\tHam" }	= 0 + 0;
		}
	
	my $total_mail	= 0 + 0;
	my $total_ham	= 0 + 0;
	my $total_spam	= 0 + 0;
	my $total_virus = 0 + 0;
	
	while ( my ( $mailfile, $method, $result ) = $sth->fetchrow_array() )
		{	next if ( ! $mailfile );
			next if ( ! $method );
			next if ( ! $result );
			
			my $summary_key = "$method\t$result";
			my $count = $method_summary{ $summary_key };
			$count = 0 + 0 if ( ! $count );
			$count++;
			$method_summary{ $summary_key } = $count;
			
			
			# Keep track of totals
			$total_mail++;
			if ( $result eq "Ham" )
				{	$total_ham++;
				}
			elsif ( $result eq "Spam" )
				{	$total_spam++;
				}
			elsif ( $result eq "Virus" )
				{	$total_virus++;
				}
			
			
			# Was this mail file a lightspeed error?  Keep track by method, result, and actual
			if ( defined $lightspeed_errors{ $mailfile } )
				{	my $actual = $result;	# The result in the MailFile table is the actual result 
					$result = $lightspeed_errors{ $mailfile };	# The value in this hash is the result from Lightspeed
					
					next if ( ! $result );
					
					# If these are the same then it doesn't count as an error
					next if ( $actual eq $result );
					
					my $key = "$method\t$result\t$actual";
					my $error_count = $error_summary{ $key };
					$error_count = 0 + 0 if ( ! $error_count );
					$error_count++;
					$error_summary{ $key } = $error_count;
				}
		}
			
	$sth->finish();


	# Get rid of any existing daily totals
	$str = "DELETE FROM DailyTotals WHERE [Date] = \'$date\'";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	# Stick the new daily totals into the database
	$str = "INSERT INTO DailyTotals ( [Date], TotalMail, TotalHam, TotalSpam, TotalVirus )
	VALUES ( \'$date\', \'$total_mail\', \'$total_ham\', \'$total_spam\', \'$total_virus\' )";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	
	
	# Get rid of any existing error summary for this date
	$str = "DELETE FROM ErrorSummary WHERE [Date] = \'$date\'";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	&lprint( "Saving the error summary into the database for $date ...\n" );
	
	# Now insert the new error summary
	while ( my ( $key, $count ) = each( %errors ) )
		{	next if ( ! $key );
			next if ( ! defined $count );
			
			my ( $company, $error_type ) = split /\t/, $key;
			next if ( ! $company );
			next if ( ! $error_type );
			
			# Calculate the various error rates
			my $error_rate			= 0 + 0;
			my $relative_error_rate = 0 + 0;
			
			if ( $error_type eq "Missed Spam" )
				{	$error_rate = 100 * $count / $total_spam if ( $total_spam );
					$relative_error_rate = 100 * $count / $total_spam_errors if ( $total_spam_errors );
				}
			elsif ( $error_type eq "Blocked Ham" )
				{	$error_rate = 100 * $count / $total_ham if ( $total_ham );
					$relative_error_rate = 100 * $count / $total_ham_errors if ( $total_ham_errors );
				}
			elsif ( $error_type eq "Missed Virus" )
				{	$error_rate = 100 * $count / $total_virus if ( $total_virus );
					$relative_error_rate = 100 * $count / $total_virus_errors if ( $total_virus_errors );
				}
			
			
			# Round off the rates	
			$error_rate = sprintf( "%.2f", $error_rate );
			$relative_error_rate = sprintf( "%.2f", $relative_error_rate );

	
			$str = "INSERT INTO ErrorSummary ( Company, ErrorType, Count, ErrorRate, RelativeErrorRate, [Date] )
			VALUES ( \'$company\', \'$error_type\', \'$count\', \'$error_rate\', \'$relative_error_rate\', \'$date\' )";
			
			$sth = $dbhLocalSpam->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
		
		
	# Get rid of any existing method error summary for this date
	$str = "DELETE FROM MethodErrorSummary WHERE [Date] = \'$date\'";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	&lprint( "Saving the method error summary into the database for $date ...\n" );

	# Now insert the new method error summary
	while ( my ( $key, $error_count ) = each( %error_summary ) )
		{	next if ( ! $key );
			
			# For now, ignore 0 counts
			next if ( ! $error_count );
			
			my ( $method, $result, $actual ) = split /\t/, $key;
			next if ( ! $method );
			next if ( ! $result );
			next if ( ! $actual );
			
			$str = "INSERT INTO MethodErrorSummary ( Method, Result, Actual, Count, [Date] )
			VALUES ( \'$method\', \'$result\', \'$actual\', \'$error_count\', \'$date\' )";
			$sth = $dbhLocalSpam->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
		
		
	# Get rid of any existing method summary for this date
	$str = "DELETE FROM MethodSummary WHERE [Date] = \'$date\'";
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	&lprint( "Saving the method summary into the database for $date ...\n" );
	
	# Now insert the new method summary
	while ( my ( $summary_key, $count ) = each( %method_summary ) )
		{	next if ( ! $summary_key );
			
			# For now, ignore 0 counts
			next if ( ! $count );
			
			my( $method, $result ) = split /\t/, $summary_key, 2;
			next if ( ! $method );
			next if ( ! $result );
			
			$str = "INSERT INTO MethodSummary ( Method, Result, Count, [Date] )
			VALUES ( \'$method\', \'$result\', \'$count\', \'$date\' )";
			
			$sth = $dbhLocalSpam->prepare( $str );
			$sth->execute();
			$sth->finish();
		}
		
		
	return( undef );
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
sub LoadLightspeedResults( $ )
#
#  Given a valid date, load the Lightspeed results for that date into memory
#
################################################################################
{	my $date = shift;
	
	return( undef ) if ( ! $date );
	
	&lprint( "Loading the Lightspeed results for $date ...\n" );
		
	my $str = "SELECT MailFile, EmailFrom, EmailTo, Subject, Result FROM MailFile WHERE [Date] = \'$date\'";
	
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	
	%lightspeed_results = ();
	
	my $count = 0 + 0;
	while ( my ( $mailfile, $email_from, $email_to, $subject, $result ) = $sth->fetchrow_array() )
		{	next if ( ! $mailfile );
			next if ( ! $email_to );
			next if ( ! $result );
			
			$email_from = "" if ( ! $email_from );
			$subject	= "" if ( ! $subject );
			
			my $key		= "$email_from\t$email_to\t$subject";
			my $value	= "$result\t$mailfile";
			
			$lightspeed_results{ $key } = $value;
			
			$count++;
		}
		
		
	$sth->finish();
	
	&lprint( "Load $count Lightspeed results for $date\n" );
	
	return( 1 );
}



################################################################################
# 
sub CheckOverblocks( $ )
#
#  Check the remote statistics database and see if there are any new Lightspeed
#  overblocks to record.
#
################################################################################
{	my $date = shift;
	
	return( undef ) if ( ! $date );
	
	&lprint( "Checking Lightspeed overblocks for $date ...\n" );
	
	my $str = "SELECT EmailFrom, EmailTo, EmailSubject FROM SpamMailBlockerOverblocked WHERE [Time] >= \'$date\'";
	
	my $sth = $dbhRemoteStatistics->prepare( $str );
	$sth->execute();

	my %overblocked;
	my $count = 0 + 0;
	while ( my ( $email_from, $email_to, $subject ) = $sth->fetchrow_array() )
		{	next if ( ! $email_to );
			
			$email_from = "" if ( ! $email_from );
			$subject	= "" if ( ! $subject );
			
			my $key		= "$email_from\t$email_to\t$subject";

			# See if I have a matching value from the lightspeed hash
			my $value = $lightspeed_results{ $key };
			next if ( ! $value );
			
			# Have I already corrected this in the database?
			my ( $result, $mailfile ) = split /\t/, $value;
			next if ( ! $mailfile );
			
			next if ( $result eq "Ham" );
			
			# Keep track of what I overblocked
			$overblocked{ $mailfile } = $result;
			
			$count++;
			&lprint( "Lightspeed overblocked file $mailfile ...\n" );
		}
		
	$sth->finish();

	if ( ! $count )
		{	&lprint( "Found no new overblocks for Lightspeed for $date\n" );
			return( 0 + 0 );
		}
		
	
	# Add the errors I found into the database
	while ( my ( $mailfile, $result ) = each ( %overblocked ) )
		{	next if ( ! $mailfile );
			
			&LightspeedError( $mailfile, $result, "Ham" );
		}
	
	&lprint( "Added $count new overblocks for Lightspeed for $date into the database\n" );
	
	return( $count );
}



################################################################################
# 
sub CheckUnderblocks( $ )
#
#  Check the Spam For Review directory and see if there are any new Lightspeed
#  underblocks to record.
#
################################################################################
{	my $date = shift;
	
	return( undef ) if ( ! $date );
	
	# Process the directory
	if ( ! opendir( DIR, $opt_spam_for_review ) )
		{	lprint "Error opening the directory $opt_spam_for_review: $!\n";
			exit( 0 );
		}


	lprint "Starting Lightspeed underblock check in directory $opt_spam_for_review ...\n";


	my %underblocks;
	my $count	= 0 + 0;
	my $errors	= 0 + 0;
	while ( defined( my $file = readdir( DIR ) ) )
		{	next if ( -d $file );

			$count++;
			
			my $file = lc( $file );
			
			my $spam_filename = $opt_spam_for_review . "\\" . $file;
			
			my ( $email_from, $email_to, $subject ) = &AnalyzeSpamForReviewFile( $spam_filename, $date );

			next if ( ! $email_to );
			
			$email_from = "" if ( ! $email_from );
			$subject	= "" if ( ! $subject );
			
			my $key		= "$email_from\t$email_to\t$subject";
			
			my $value = $lightspeed_results{ $key };
			next if ( ! $value );
			
			my ( $result, $mailfile ) = split /\t/, $value;
			
			# Do I have this right already in the database?
			next if ( $result eq "Spam" );
			
			$underblocks{ $mailfile } = $result;
			
			$errors++;
		}
		
	closedir( DIR );
	
	lprint "Analyzed $count spam underblocks from $opt_spam_for_review\n";
	
	if ( ! $errors )
		{	&lprint( "Found no new underblocks for Lightspeed for $date\n" );
			return( 0 + 0 );
		}
		
	
	# Add the errors I found into the database
	while ( my ( $mailfile, $result ) = each ( %underblocks ) )
		{	next if ( ! $mailfile );
			
			&LightspeedError( $mailfile, $result, "Spam" );
		}
	
	&lprint( "Added $errors new underblocks for Lightspeed for $date into the database\n" );
	
	
	return( $count );
}



################################################################################
# 
sub BarracudaResults( $$ )
#
#  Go through the incoming spool directory and process the Barracuda results
#  Return the count of valid Barracuda received emails found
#
################################################################################
{
	# Process the directory
	if ( ! opendir( DIR, $opt_dir ) )
		{	lprint "Error opening the directory $opt_dir: $!\n";
			exit( 0 );
		}


	lprint "Starting Barracuda Results check in directory $opt_dir ...\n";


	my $count = 0 + 0;
	my $errors = 0 + 0;
	while ( defined( my $file = readdir( DIR ) ) )
		{	next if ( -d $file );

			my $file = lc( $file );
			
			# Ignore clue files
			next if ( $file =~ m/\.clue$/i );
			
			my $received_filename = $opt_dir . "\\" . $file;
			
			my $analyze_email = 1 if ( $file =~ m/^i/ );

			if ( ! $analyze_email )
				{	unlink( $received_filename ) if ( $opt_unlink );
					next;	
				}
			
			# Analyze the received Barracuda file and see if I can figure out the
			#original full filename (which should be in the mail header)
			my ( $full_filename, $result ) = &AnalyzeBarracudaFile( $received_filename );
			
			if ( ! $full_filename )
				{	unlink( $received_filename ) if ( $opt_unlink );
					next;	
				}
			
			$count++;

			my $ok = &BarracudaSaveDatabase( $full_filename, $result );
			unlink( $received_filename ) if ( $opt_unlink );
			
			$errors++ if ( $ok );
		}

	closedir( DIR );
	
	lprint "Analyzed $count received Barracuda emails\n";
	lprint "Found $errors Barracuda errors\n";
	
	return( $count );
}



################################################################################
# 
sub LightspeedError( $$$ )
#
#  I found a Lightspeed error so record it into the database
#  Return True if I save the data OK, undef if not
#
################################################################################
{	my $full_filename	= shift;
	my $result			= shift;
	my $actual			= shift;
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $result );
	return( undef ) if ( ! $actual );
	
	my @parts = split /\\/, $full_filename;
	
	my $i = $#parts - 1;
	return( undef ) if ( $i < 0 );
	
	my $date_str = $parts[ $i ];
	return( undef ) if ( ! $date_str );
	return( undef ) if ( length( $date_str ) != 8 );
	
	my $yr		= substr( $date_str, 0, 4 );
	my $mon		= substr( $date_str, 4, 2 );
	my $mday	= substr( $date_str, 6, 2 );
	
	my $date = "$mon/$mday/$yr";
		
	&lprint( "Saving Lightspeed error for file $full_filename ...\n" ) if ( $opt_verbose );

	my $str = "UPDATE MailFile SET Result = \'$actual\' WHERE MailFile = \'$full_filename\'";
	
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	

	# Stick the mail file data into the database
	$str = "INSERT INTO Errors ( MailFile, Company, [Result], [Actual], [Date] ) 
	VALUES ( \'$full_filename\', \'Lightspeed\', \'$result\', \'$actual\', \'$date\' )";
	
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();

	return( 1 );
}



################################################################################
# 
sub BarracudaSaveDatabase( $$ )
#
#  Save the Barracuda results back into the database
#  Return undef if an error, 0 if Barracuda is right, and 1 if Barracuda is wrong
#
################################################################################
{	my $full_filename	= shift;
	my $result			= shift;
	
	return( undef ) if ( ! $full_filename );
	return( undef ) if ( ! $result );

	return( undef ) if ( ! $result );
	
	my @parts = split /\\/, $full_filename;
	
	my $i = $#parts - 1;
	return( undef ) if ( $i < 0 );
	
	my $date_str = $parts[ $i ];
	
	# If this isn't right then it isn't a valid mail file
	return( undef ) if ( ! $date_str );
	return( undef ) if ( length( $date_str ) != 8 );
	
	my $yr		= substr( $date_str, 0, 4 );
	my $mon		= substr( $date_str, 4, 2 );
	my $mday	= substr( $date_str, 6, 2 );
	
	my $date = "$mon/$mday/$yr";
		
		
	&lprint( "Looking up actual results for file $full_filename ...\n" ) if ( $opt_verbose );

	my $str = "SELECT Result FROM MailFile WHERE MailFile = \'$full_filename\'";
	
	my $sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	
	my ( $actual ) = $sth->fetchrow_array();

	$sth->finish();

	# If I don't have an actual result in the database, ignore the mail file
	if ( ! $actual )
		{	&lprint( "No database entry for mail file $full_filename\n" );
			return( undef );	
		}

	
	# Did Barracuda get it right?
	return( 0 + 0 ) if ( $result eq $actual );
	
	
	&lprint( "Saving Barracuda error for file $full_filename ...\n" );

	# Delete any previous entry
	$str = "DELETE FROM Errors Where Mailfile = \'$full_filename\' AND Company = \'Barracuda\'";
	
	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();
	
	
	# Stick the mail file data into the database
	$str = "INSERT INTO Errors ( MailFile, Company, [Result], [Actual], [Date] ) 
	VALUES ( \'$full_filename\', \'Barracuda\', \'$result\', \'$actual\', \'$date\' )";
	

	$sth = $dbhLocalSpam->prepare( $str );
	$sth->execute();
	$sth->finish();

	return( 0 + 1 );
}



################################################################################
# 
sub ConnectRemoteStatistics()
#
#  Find and connect to the remote IpmStatistics database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbhRemoteStatistics ) if ( $dbhRemoteStatistics );
	
	&lprint( "Connecting to the remote Statistics database ...\n" );
	
	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\RemoteStatistics", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	RegCloseKey( $key );
	
	my $dbh = DBI->connect( "DBI:ODBC:RemoteStatistics", "IpmStatistics" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbh )
		{	sleep( 10 );
			$dbh = DBI->connect( "DBI:ODBC:RemoteStatistics", "IpmStatistics" );
		}
			
	return( $dbh );
}



################################################################################
# 
sub ConnectLocalSpam()
#
#  Find and connect to the local Spam database SQL Server, if possible.  
#  Return undef if not possible
#
################################################################################
{   my $key;
    my $type;
    my $data;

	# Am I already connected?
	return( $dbhLocalSpam ) if ( $dbhLocalSpam );
	
	&lprint( "Connecting to the local Spam database ...\n" );
	
	# Now look to see if the ODBC Server is configured
	$data = undef;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\Spam", 0, KEY_READ, $key );
	return( undef ) if ( ! $ok );
	RegCloseKey( $key );
	
	my $dbh = DBI->connect( "DBI:ODBC:Spam", "Spam" );
	
	# If I get an error, sleep for a few seconds and try again
	if ( ! $dbh )
		{	sleep( 10 );
			$dbh = DBI->connect( "DBI:ODBC:Spam", "Spam" );
		}
			
	return( $dbh );
}



################################################################################
# 
sub AnalyzeBarracudaFile( $ )
#
#  Given a received Barracuda file, figure out as much as I can
#  Return the name of the original mail file, or undef if not found
#
################################################################################
{	my $received_filename	= shift;
	
	if ( ! -e $received_filename )
		{	lprint "Filename $received_filename does not exist\n";		  
			return( undef, undef );
		}
	
	
	if ( ! -f $received_filename )
		{	lprint "Filename $received_filename is not a normal file!\n";		  
			return( undef, undef );
		}
	
	
	if ( ! open( SPAM, "<$received_filename" ) )
		{   lprint "Error opening file $received_filename: $!\n";		  
			return( undef, undef );
		}



	my $header = 1;	# True if I'm reading the header
	my $subject;
	my $full_filename;
	
	
	while ( my $line = <SPAM> )
		{	if ( ( $header )  &&  ( $line =~ m/^subject/i ) )
				{	chomp( $line );
					$subject = $line;
				}
			
			if ( ( $header )  &&  ( $line =~ m/^\( Original Filename\: / ) )
				{	chomp( $line );
					$full_filename = $line;
					$full_filename =~ s/\( Original Filename\: //;
					$full_filename =~ s/\)//;
					
					$full_filename =~ s/^\s+// if ( $full_filename );
					$full_filename =~ s/\s+$// if ( $full_filename );
				}
				
			if ( ( $subject )  &&  ( $full_filename ) )
				{	last;
				}
				
			# If I have gone past the header, and I still don't have the information, the quit	
			if ( ( $line eq "\n" )  &&  ( $header ) )
				{	$header = undef;
					last;
				}
		}
		
	close( SPAM );

	if ( ! $full_filename )
		{	&lprint( "Unable to get Barracuda results from $received_filename\n" );
			return( undef, undef );
		}
		
		
	# What were the results?	
	my $result = "Ham";
	
	
	# Barracuda rewrites the subject line with the result of their processing
	if ( defined $subject ) 
		{	$result = "Virus" if ( $subject =~ m/\[QUAR\]/ );
			$result = "Spam" if ( $subject =~ m/\[BULK\]/ );
		}

	&lprint( "Barracuda file $received_filename: Result: $result\n" ) if ( $opt_verbose );
	
	return( $full_filename, $result );
}



################################################################################
# 
sub AnalyzeSpamForReviewFile( $$ )
#
#  Given a received Spam For Review file, figure out as much as I can
#  Return the email from, email to, and subject
#
################################################################################
{	my $received_filename	= shift;
	my $date				= shift;
	
	if ( ! -e $received_filename )
		{	lprint "Filename $received_filename does not exist\n";		  
			return( undef, undef, undef );
		}
	
	
	if ( ! -f $received_filename )
		{	lprint "Filename $received_filename is not a normal file!\n";		  
			return( undef, undef, undef );
		}
	
	
	if ( ! open( SPAM, "<$received_filename" ) )
		{   lprint "Error opening file $received_filename: $!\n";		  
			return( undef, undef, undef );
		}


	# Is the date wrong?  It should be from the same date or later
	# First, rearrange the date to a better format
	my ( $fmon, $fmday, $fyear ) = split /\//, $date;

	$fmon	= sprintf( "%02d", $fmon );
	$fmday	= sprintf( "%02d", $fmday );
	
	my $compare_date = "$fyear$fmon$fmday";
	
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat( $received_filename );	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $mtime );
	$year	= 1900 + $year;
	$mon	= $mon + 1;
	
	$mon	= sprintf( "%02d", $mon );
	$mday	= sprintf( "%02d", $mday );
	
	my $file_date = "$year$mon$mday";

	return( undef, undef, undef ) if ( $file_date lt $compare_date );


	# Start reading the file
	my $header = 1;	# True if I'm reading the header
	my $subject;
	my $email_from;
	my $email_to;
	
	
	while ( my $line = <SPAM> )
		{	if ( ( $header )  &&  ( $line =~ m/^subject\:/i ) )
				{	chomp( $line );
					$subject = $line;
					$subject =~ s/^Subject\: //i;
				}
			
			if ( ( $header )  &&  ( $line =~ m/^from\:/i ) )
				{	chomp( $line );
					$email_from = $line;
					$email_from =~ s/^from\://i;
					$email_from = &CleanEmail( $email_from );
				}
				
			if ( ( $header )  &&  ( $line =~ m/^to\:/i ) )
				{	chomp( $line );
					$email_to = $line;
					$email_to =~ s/^to\://i;
					$email_to = &CleanEmail( $email_to );
				}
				
			if ( ( $subject )  &&  ( $email_from )  &&  ( $email_to ) )
				{	last;
				}
				
			# If I have gone past the header, and I still don't have the information, the quit	
			if ( ( $line eq "\n" )  &&  ( $header ) )
				{	$header = undef;
					last;
				}
		}
		
	close( SPAM );

	# I need to have a least found an email to
	return( undef, undef, undef ) if ( ! $email_to );
	
	# Was it emailed to spam@lightspeedsystems.com?  These don't count
	return( undef, undef, undef ) if ( $email_to eq "spam\@lightspeedsystems.com" );
	
	return( $email_from, $email_to, $subject );
}



#################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... 
Try '$me --help' for more information.
.
    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
Usage: $me [OPTION(s)]  
    
  -b, --barracuda    Directory to find the received Barracuda files
                     default is the current directory
  -d, --date         Date to find any new Lightspeed errors for
  -s, --spamdir      Directory for \"Spam For Review\" files
                     default is \"H:\\Spam For Review\"
  -u, --unlink       Unlink any mail files that aren't archived
  -h, --help         display this help and exit
  -v, --verbose      display verbose information
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
$me $_version
.
    exit;
}


################################################################################

__END__

:endofperl
