################################################################################
#!perl -w
#
# Rob McCarthy's version of extracting URLs, etc from the not Spam For Review folder
#
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;
use Getopt::Long;
use Content::File;
use Content::FileUtil;
use Content::SQL;
use Cwd;
use DBI qw(:sql_types);
use DBD::ODBC;



# Validate and get the parameters
my $_version = "2.0.0";

my $opt_version;
my $opt_verbose;
my $opt_help;
my $opt_dir;		# Directory to use
my $opt_debug;		# Debug mode - leaves created files in place
my $opt_working;	# True if shold delete working files
my $opt_wizard;		# True if I shouldn't display headers and footers
my $dbh;
my %subjects;		# Subject hash - key is subject line, value if the rest of the clues




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
        "d|directory=s" =>\$opt_dir,
        "w|wizard" => \$opt_wizard,
        "v|verbose" => \$opt_verbose,
        "x|xdebug" => \$opt_debug,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	$opt_dir = $cwd if ( !$opt_dir );
	

	#  Open the Content database
	$dbh = &ConnectServer() or &FatalError("Unable to connect to SQL database\n" );
	LoadCategories();
		
	
	&StdHeader( "NotSpamReview" ) if ( ! $opt_wizard );
							
				
	print "Scanning Not Spam message file(s)\n";
	print "Directory $opt_dir\n";


	&AnalyzeDir();
	
	
	&StdFooter if ( ! $opt_wizard );

		
	#  Clean up everything and quit
	$dbh->disconnect if ( $dbh );
		
    exit;
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
		
    # Loop through the directory
    my $file_counter = 0;
    my $file;
	

    # Process the directory
	bprint "Processing directory files ...\n";
    opendir DIR, $opt_dir;

	while ( $file = readdir( DIR ) )
		{
			# Skip subdirectories
			next if (-d $file);
		
			chomp( $file );
			$file = lc( $file );
							
			$file_counter++;
			my $full_filename = "$opt_dir\\$file";

			my $handled = &AnalyzeFile( $full_filename  );
			
			unlink( $full_filename ) if ( $handled );
		}

    closedir DIR;
		
	return;	
}



################################################################################
#
sub AnalyzeFile( $ )
#
# Analyze a given file
# Return undef if if need to be looked at manually, True if it is handled completely
#
################################################################################
{	my $filename = shift;
	
	return( undef ) if ( ! $filename );
	return( undef ) if ( ! -e $filename );
	
	open INPUT, "<$filename" or return( undef );
	
	my $reason;
	my $subject;
	my $url;
	my $sender;
	my $recipient;
	my $ipaddress;
	my $junk;
	my $value;
	
	while (<INPUT>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			$line =~ s/\&nbsp\;/ /g;
			$line =~ s/\. <\/FONT><\/P>/ /g;
			$line =~ s/\=20$/ /;
			$line =~ s/<\/FONT>//g;
			$line =~ s/<BR>//g;
			
			if ( ( $line =~ m/^Subject\:/ )  &&  ( ! $subject ) )
				{	( $junk, $subject ) = split /Subject\: /, $line, 2;
					$subject =~ s/\=\=\=SPAM\=\=\=\:// if ( $subject );
				}
				
			if ( $line =~ m/detected as spam is\:/ )
				{	( $junk, $reason ) = split /is\: /, $line, 2;
					$reason =~ s/\.\=20// if ( $reason );
				}
				
			if ( $line =~ m/Original Sender\:/ )
				{	( $junk, $sender ) = split /er\: /, $line, 2;
					$sender =~ s/\=20// if ( $sender );
					$sender =~ s/\s//g if ( $sender );
				}

			if ( $line =~ m/Original Recipient/ )
				{	( $junk, $recipient ) = split /\: /, $line, 2;
					$recipient =~ s/\=20// if ( $recipient );
					$recipient =~ s/\s//g if ( $recipient );
				}

			if ( $line =~ m/External IP Address/ )
				{	( $junk, $ipaddress ) = split /\: /, $line, 2;
					$ipaddress =~ s/\=20// if ( $ipaddress );
					$ipaddress =~ s/\s//g if ( $ipaddress );
				}

		}
	
	close INPUT;
	
	# If not all the fields are filled out, then this message is something weird and will
	# Have to be looked at manually
	return( undef ) if ( ! $reason );
	return( undef ) if ( ! $recipient );
	return( undef ) if ( ! $ipaddress );
	
	
	# First, process the files that nothing needs to be done ...
	return( 1 ) if ( $reason =~ m/temporarily grey listed/ );
	return( 1 ) if ( $reason =~ m/Bayesian/ );
	return( 1 ) if ( $reason =~ m/Virus Infected/ );
	return( 1 ) if ( $reason =~ m/Virus\)/ );
	return( 1 ) if ( $reason =~ m/Possible dangerous/ );
	return( 1 ) if ( $reason =~ m/Dangerous Attachment/ );
	return( 1 ) if ( $reason =~ m/advertising URL/ );
	return( 1 ) if ( $reason =~ m/Spamhaus/ );
	
	
	# Subject indicating problems
	return( 1 ) if ( $subject =~ m/Undeliverable/ );
	return( 1 ) if ( $subject =~ m/Returned mail/ );
	return( 1 ) if ( $subject =~ m/Spam Mail Summary for/ );
	return( 1 ) if ( $subject =~ m/Returned mail/ );
	return( 1 ) if ( $subject =~ m/Mail Delivery Failure/ );
	return( 1 ) if ( $subject =~ m/failure notice/ );
	return( 1 ) if ( $subject =~ m/Delivery Status Notification/ );
	return( 1 ) if ( $subject =~ m/MailServer Notification/ );


	# Can I get a URL out?
	if ( $reason =~ m/Blocked URL\:/ )
		{	( $junk, $url ) = split /Blocked URL\: /, $reason, 2;
			$url = &CleanUrl( $url );
		}
	
	$subject = $filename if ( ! $subject );
	
	
	# Have I already seen this exact subject?
	return( 1 ) if ( exists $subjects{ $subject } );
	
	
	# Get the reason value if I can
	if ( $reason =~ m/\=\=\=/ )
		{	( $reason, $value ) = split /\=\=\=/, $reason, 2;
			$reason =~ s/^\s+//;
			$reason =~ s/\s$//g;
			$value =~ s/^\s+//;
			$value =~ s/\s$//g;
		}
		
	my %clues;
	$clues{reason}		= $reason;
	$clues{URL}			= $url if ( $url );
	$clues{sender}		= $sender if ( $sender );
	$clues{recipient}	= $recipient;
	$clues{IP}			= $ipaddress;
	$clues{file}		= $filename;
	$clues{vaule}		= $value if ( $value );
	
	$subjects{ $subject } = %clues;
	
	
	print "\n";
	print "Subject:    $subject\n" if ( $subject );
	print "Reason:     $reason\n";
	print "Value:      $value\n" if ( ( $value )  && ( !$url ) );
	print "URL:        $url\n" if ( $url );
	print "Sender:     $sender\n" if ( $sender );
	print "Recipient:  $recipient\n";
	print "IP Address: $ipaddress\n";
	print "\n";

	if ( $reason =~ m/Content DB IP/ )
		{	# has this IP address already been switched
			my $retcode = &LookupUnknown( $ipaddress, 0 );
			return( 1 ) if ( ( $retcode )  &&  ( $retcode ne 3 ) );
			
			my $answer = &AnswerYorN( "Switch $ipaddress to the Ham category?" );
			&SwitchToHam( $ipaddress ) if ( $answer eq "Y" );
		}
		
	elsif ( $reason =~ m/Failed Grey List/ )
		{	my $answer = &AnswerYorN( "Switch $ipaddress to the Ham category?" );
			&SwitchToHam( $ipaddress ) if ( $answer eq "Y" );
		}
		
	elsif ( $reason =~ m/\(Domain\)/ )
		{	my ( $junk, $sender_domain ) = split /\(Domain\) /, $reason, 2;
			
			if ( defined $sender_domain )
				{	$sender_domain =~ s/^\s+//g;
					$sender_domain =~ s/\s$//g;
					$sender_domain =~ s/\.$//;

					my $answer = &AnswerYorN( "Remove $sender_domain from the blacklist?" );
					&RemoveBlacklist( "Domain", $sender_domain ) if ( $answer eq "Y" );
				}
		}
		
	elsif ( $reason =~ m/\(RBL Domain\) Lightspeed Systems/ )
		{	my ( $junk, $sender_domain ) = split /\@/, $sender, 2;
			my $answer = &AnswerYorN( "Add $sender_domain to the RBLErrors list?" );
			&RBLErrors( $sender_domain );
		}
		
	elsif ( $reason =~ m/\(Sender\)/ )
		{	my ( $junk, $sender_value ) = split /\(Sender\) /, $reason, 2;
			
			$sender_value =~ s/^\s+//g;
			$sender_value =~ s/\s$//g;
			$sender_value =~ s/\.$//;
			
			my $answer = &AnswerYorN( "Remove Sender $sender_value from the blacklist?" );
			&RemoveBlacklist( "MAILFROM", $sender_value ) if ( $answer eq "Y" );
		}
		
	elsif ( $reason =~ m/\(IP\)/ )
		{	my $answer = &AnswerYorN( "Remove $ipaddress from the blacklist?" );
			&RemoveBlacklist( "ADDRESS", $ipaddress ) if ( $answer eq "Y" );
		}
		
	elsif ( $reason =~ m/\(Subject\)/ )
		{	my ( $junk, $subject_value ) = split /\(Subject\) /, $reason, 2;
			
			$subject_value =~ s/^\s+//g;
			$subject_value =~ s/\s$//g;
			$subject_value =~ s/\.$//;

			my $answer = &AnswerYorN( "Remove Subject $subject_value from the blacklist?" );
			&RemoveBlacklist( "SUBJECT", $subject_value ) if ( $answer eq "Y" );
		}
		
	elsif ( $url )
		{	my $retcode = &LookupUnknown( $url, 0 );
			return( 1 ) if ( ( $retcode )  &&  ( $retcode gt 3 ) );
			my $answer = &AnswerYorN( "Switch $url to the Ham category?" );
			&SwitchToHam( $url ) if ( $answer eq "Y" );
		}
	
	else
		{	print "I don\'t know what to do with this message\n";
		}
		
	return( 1 );
}



################################################################################
#
sub RBLErrors( $ )
#
# Add value to rblerrors
#
################################################################################
{	my $value = shift;
	
	my $file = &SoftwareDirectory() . "\\RBLErrors.txt";

	open RBL, ">>$file" or die "Error opening file $file: $!\n";
	
	print RBL "$value\n";
	
	close RBL;
}



################################################################################
#
sub RemoveBlacklist( $$ )
#
# Remove a type/value from the blacklist
#
################################################################################
{	my $type = shift;
	my $value = shift;
	
	my $filename = &SoftwareDirectory() . "\\SpamBlacklist.txt";
	
	open FILE, "<$filename" or die "Unable to open file $filename: $!\n";
	
	my %blacklist;
	
	while (<FILE>)
		{	next if ( ! $_ );
			my $line = $_;
			chomp( $line );
			
			my ( $type, $value, $air, $domain ) = split /\t/, $line;

			next if ( ! $value );
			
			my $key = $type . "\t" . $value;
			$key = $key . "\t" . $domain if ( $domain );
			$blacklist{ $key } = $type . "\t" . $value;
		}
		
	close FILE;
	
	my $remove_val = $type . "\t" . $value;
	
		
	my @keys = sort keys %blacklist;
	my $count = 0 + 0;
	
	foreach ( @keys )
		{	next if ( ! $_ );
			my $key = $_;
			my $val = $blacklist{ $key };
			
			if ( $val eq $remove_val )
				{	delete $blacklist{ $key };
					$count++;
				}
		}
	
	
	# If I didn't find any matching, let them know ...
	if ( ! $count )
		{	print "Unable to find $type $value in the blacklist\n";
			return( undef );
		}
	
		
	open FILE, ">$filename" or die "Unable to create file $filename: $!\n";
	
	@keys = ();
	@keys = sort keys %blacklist;

	foreach ( @keys )
		{	next if ( ! $_ );
			my $line = $_;
			
			my ( $type, $value, $domain ) = split /\t/, $line;
			
			next if ( ! $value );
			
			print FILE "$type\t$value\n" if ( ! $domain );
			print FILE "$type\t$value\t\t$domain\n" if ( $domain );
		}
	
	close FILE;

	print "Removed $type $value $count times from the blacklist\n";
}



################################################################################
#
sub SwitchToHam( $ )
#
# Switch a URL to the ham category
#
################################################################################
{	my $url = shift;
	
	my $ham_category = &CategoryNumber( "ham" );
	
    my $retcode = &LookupUnknown( $url, 0 );

    #  Check to see if it is a recategorize that ended up with the same category
    #  Update it if it is not   
    if (  $retcode )
		{	$retcode = &UpdateCategory( $url, $ham_category, $retcode, ( 0 + 2 ) );
			print "Switched $url to the Ham category\n";
		}
	else
		{	my ( $domain, $url_ext ) = split /\//, $url, 2;
			&AddNewTrans( $domain, $ham_category, 0, 2 );
			print "Added $domain to the Ham category\n";
		}
}

	  

################################################################################
#
sub AnswerYorN( $ )
#
# Ask a question and return Y or N in response
#
################################################################################
{	my $question = shift;
	
    print "$question [ Y or N ] ";

	my $done;
	while ( !$done )
		{	my $line = <STDIN>;
			chomp( $line );
            return( "N" ) if ( uc( $line ) eq "N" );
            return( "Y" ) if ( uc( $line ) eq "Y" );
		}
}



################################################################################
#
sub Prompt( $ )
#
# Wait for an enter key to contine
#
################################################################################
{	my $question = shift;
	
    print "$question ";

	my $done;
	while ( !$done )
		{	my $line = <STDIN>;
			return;
		}
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
    my $me = "NotSpamReview";

    bprint <<".";
Usage: $me [OPTION(s)] [filename|directory]


This utility analyzes spam files that were actually decided to be not spam. 

There are a couple of command line options:

  -d, --directory       set the default directory to work in
  -h, --help            display this help and exit
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
    my $me = "NotSpamReview";

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
