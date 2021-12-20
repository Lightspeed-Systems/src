################################################################################
#!perl -w
#
# BlockedContent - Reads blocked content email messages and doublechecks them
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use File::Copy;
use Cwd;
use Content::File;
use Content::SQL;
use Content::Category;



# Options
my $opt_help;
my $opt_version;
my $opt_source_directory;						# This is the directory of token, link, and label files to archive

my $dbh;
my $dbhStats;
my $dbhCategory;

my $_version = "1.0.0";
my $url_list_filename;
my $opt_test;


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
        "s|source=s"		=>	\$opt_source_directory,
        "v|version"			=>	\$opt_version,
        "t|test"			=> \$opt_test,
        "h|help"			=>	\$opt_help
    );

    &StdHeader( "BlockedContent" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


	# Read the command line
	$opt_source_directory = shift if ( ! $opt_source_directory );
	
	
	# If nothing specified, then use the current directory as the source directory
	if ( ( ! $opt_source_directory )  ||  ( $opt_source_directory eq "." ) )
		{	$opt_source_directory = getcwd;
			$opt_source_directory =~ s#\/#\\#gm;	
		}
		
	if ( ! -d $opt_source_directory )
		{	print "Can not find source directory $opt_source_directory\n";
			exit( 0 );
		}

	
	# Set the recategorize and unknown URLs file names if an opt_input or a tokendir file is given
	# Default them to unused if opt_unknown_files is not true
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year = 1900 + $year;
	$mon = $mon + 1;
	
	my $datestr = sprintf( "%04d-%02d-%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );
	$url_list_filename = "BlockedContentSplit.$datestr.urls";
	$url_list_filename =~ s/\s//g;	# Get rid of spaces on the filename - it messes up DumpTokens
	
	print "Creating URLs file $url_list_filename ...\n";
	
	if ( ! $opt_test)
		{	print "Inserting Blocked for Review entries into the Statistics database ...\n";
	
			# Connect to the database
			$dbh = &ConnectServer();
			if ( ! $dbh )
				{	print "Unable to connect to the Content database\n";
					exit( 0 );	
				}
				
			&LoadCategories();
			
		    $dbhStats = &ConnectStatistics();
			if ( ! $dbhStats )
				{	print "Unable to connect to the Statistics database\n";
					exit( 0 );	
				}
		
		
			# Connect to the category database
			$dbhCategory = &CategoryConnect();
			if ( ! $dbhCategory )
				{
					lprint "Unable to open the Remote Category database.
					Run ODBCAD32 and add the Category SQL Server as a System DSN named
					\'TrafficCategory\' with default database \'Category\'.\n";
					exit( 10 );
				}
		}		

	open( URLLIST, ">$url_list_filename" ) or die "Unable to open file $url_list_filename: $!\n";
	
	# Process the source directory
	opendir( DIR, $opt_source_directory );

	my %domains;
	
	my $count = 0 + 0;
	while ( my $file = readdir( DIR ) )
		{	next if ( ! $file );
			
			# Skip subdirectories
			next if (-d $file );
	
			my $lc_file = lc( $file );
			
			lprint "Processing file $file ...\n";
			
			if ( ( ! ( $lc_file =~ m/lscom\.net/i ) )  &&  ( ! ( $lc_file =~ m/smtprelay/ ) ) )
				{	lprint "$file does not match a URL file name\n";
					next;
				}

			my ( $url, $category, $client_ip, $time, $reason, $client_email, $hostname, $client_hostname, $client_username, $referrer ) = &ProcessBlockedURL( "$opt_source_directory\\$file" );
			
			unlink( "$opt_source_directory\\$file" ) if ( ! $opt_test );
			
			next if ( ! defined $url );
			next if ( ! $category );
			
			my $root = &RootDomain( $url );
			$root = &TrimWWW( $url );
			
			next if ( exists $domains{ $root } );
			
			print URLLIST "$root\n";
			
			my $catnum = &CategoryNumber( $category );
			
			$domains{ $root } = 1;

			my $url_type = &UrlType( $url );

			if ($url_type == 1)
				{	$url = &ReverseDomain( $url );
				}
			elsif ($url_type == 2)
				{	$url_type = 3;
				}
			elsif ($url_type == 3)
				{	$url_type = 2;
					
					print "URL type: URL\n";
					  
     				# Get rid of the "www." -- per SH 08/31/2012
     				$url = &TrimWWW( $url );

     				#Remove everything after either a "?" or a "&"
     				my ($good_url, $junk) = split/[?,&]/, $url;
     				$url = $good_url;

     				#Truncate the URL in case it's too big!
     				$url = substr($url, 0, 127);
     				
						# See if this URL has become superfluous
						my ( $host, $host_url ) = split /\//, $url, 2;
						if ( ! length( $host_url ) )
							{
								$url = $host;
								
								if ( &IsIPAddress( $url ) )
									{	$url_type = 3;
									}
								else
									{	$url_type = 1;
										$url = &ReverseDomain( $url );
									}
							}
				}

			my $domain_reason;
			
			if ( ! $opt_test )
				{
					$domain_reason = &CategoryGetDomainReason( $root );
					print "Domain Reason $domain_reason\n" if ( $domain_reason );
				}
			
			$reason				= &quoteurl( $reason )			if ( defined $reason );
			$client_email		= &quoteurl( $client_email )	if ( defined $client_email );
			$hostname			= &quoteurl( $hostname )		if ( defined $hostname );
			$client_hostname	= &quoteurl( $client_hostname ) if ( defined $client_hostname );
			$client_ip			= &quoteurl( $client_ip )		if ( defined $client_ip );
			$client_username	= &quoteurl( $client_username ) if ( defined $client_username );
			$time				= &quoteurl( $time )			if ( defined $time );
			$domain_reason		= &quoteurl( $domain_reason )	if ( defined $domain_reason );
			$referrer			= &quoteurl( $referrer )		if ( defined $referrer );
			
			
			$reason				= "" if ( ! defined $reason );
			$client_email		= "" if ( ! defined $client_email );
			$hostname			= "" if ( ! defined $hostname );
			$client_hostname	= "" if ( ! defined $client_hostname );
			$client_ip			= "" if ( ! defined $client_ip );
			$client_username	= "" if ( ! defined $client_username );
			$time				= "" if ( ! defined $time );
			$domain_reason		= "" if ( ! defined $domain_reason );
			$referrer			= "" if ( ! defined $referrer );
			
			my $str = "INSERT INTO ContentFilteringBlockedForReview (URL, Reason, ReasonForReview, CategoryID, HostName, ClientHost, ClientIP, InSystem, ClientUser, ClientEmail, CategoryReason, Referrer ) 
			VALUES (\'$url\', $url_type, \'$reason\', $catnum, \'$hostname\', \'$client_hostname\', \'$client_ip\', \'$time\', \'$client_username\', \'$client_email\', \'$domain_reason\', \'$referrer\' )";

			if ( ! $opt_test )
				{
					$dbhStats = &SqlErrorCheckHandle( $dbhStats );	
		
					my $sth = $dbhStats->prepare( $str );
					if ( !$sth->execute() )
		               {	print "Error inserting Blocked for review entry:\n";
		                    print "URL: $url, URL_TYPE:$url_type, CATNUM: $catnum, CLIENT_IP: $client_ip, TIME: $time\n";
		               }
		
					&SqlErrorHandler( $dbhStats );
					$sth->finish();

					$count++;
				}
			else
				{
					print "$file\n  URL: $url\n  URL TYPE: $url_type\n  REASON: $reason\n  CATEGORY: $category\n  CLIENT HOSTNAME: $client_hostname\n";
					print "  CLIENTIP: $client_ip\n  TIME: $time\n  CLIENT_USERNAME: $client_username\n  CLIENT EMAIL: $client_email\n  DOMAIN REASON: $domain_reason\n  REFERRER: $referrer\n\n";
				}
		}

	closedir( DIR );

	close( URLLIST );

	if ( $count )
		{	# Split the blocked content file
			my $cmd = "split -s 200 \"$url_list_filename\"";
			print "Split command: $cmd\n";
			
			system $cmd;
		}

	# Delete the file, I am done with it.
  unlink( $url_list_filename );

  if ( ! $opt_test )
  	{
		  
			#  Close up the databases and quit
			$dbh->disconnect if ( $dbh );
			$dbhStats->disconnect if ( $dbhStats );
		
			&CategoryClose()		if ( $dbhCategory );
			$dbhCategory = undef;
  	}
		
	&StdFooter;

    exit;
}



################################################################################
# 
sub ProcessBlockedURL( $ )
#
################################################################################
{	my $full_filename = shift;
	
	return( undef, undef, undef, undef, undef, undef, undef, undef, undef, undef ) if ( ! $full_filename );
	
	return( undef, undef, undef, undef, undef, undef, undef, undef, undef, undef ) if ( ! -e $full_filename );
	
	my $url;
	my $category;
    my $client_ip;
	my $time;
	my $reason;
	my $client_email;
	my $hostname;
	my $client_hostname;
	my $client_username;
	my $referrer;
	
	#print "Processing $full_filename ...\n";
	
	
	# Default the time
 	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year = 1900 + $year;
	$mon = $mon + 1;
	$time = sprintf( "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec );
	
	open( FILE, "<$full_filename" ) or return( undef );
	
	while ( my $line = <FILE> )
       {	chomp( $line );
			next if ( ! length( $line ) );  #  Ignore empty lines
			
			# If it is html emcoded, then clean it up to ordainary text
			$line =~ s/<br>//gi;
			$line =~ s/<a href='//i;
			$line =~ s/<\/a>//i;
			
			my $lc_line = lc( $line );
			
      if ( my $pos = index( $lc_line, 'matched:' ) != -1 )
				{	my ( @parts ) = split/\s/, $line;
					$url = $parts[ $#parts ];
					my $junk;
					
					( $url, $junk ) = split /\'/, $url, 2;
					
					$url = &CleanUrl( $url );
				}

      if ( my $pos = index( $lc_line, 'blocked url:' ) != -1 )
				{	my ( @parts ) = split/\s/, $line;
					$url = $parts[ $#parts ];
					my $junk;
					
					( $url, $junk ) = split /\'/, $url, 2;
					
					$url = &CleanUrl( $url );
				}

			if ( my $pos = index( $lc_line, 'category:' ) != -1 )
				{	my ( @parts ) = split/\s/, $lc_line;
					$category = $parts[ $#parts ];
					$category =~ s/\s+//;
				}
 
			if ( my $pos = index( $lc_line, "server host name:" ) != -1 )
				{	my ( @parts ) = split/host name:/, $lc_line;
					$hostname = $parts[ $#parts ];
					$hostname =~ s/\s+//;
				}
				
			if ( my $pos = index( $lc_line, "client\'s ip address:" ) != -1 )
				{	my ( @parts ) = split/ip address:/, $lc_line;
					$client_ip = $parts[ $#parts ];
					$client_ip =~ s/\s+//;
				}
				
			if ( my $pos = index( $lc_line, "client\'s host name:" ) != -1 )
				{	my ( @parts ) = split/host name:/, $lc_line;
					$client_hostname = $parts[ $#parts ];
					$client_hostname =~ s/\s+//;
				}
				
			if ( my $pos = index( $lc_line, "user name:" ) != -1 )
				{	my ( @parts ) = split/user name:/, $lc_line;
					$client_username = $parts[ $#parts ];
					$client_username =~ s/\s+//;
					$client_username =~ s/\s+$//;
					$client_username = undef if ( $client_username eq "" );
				}
				
			if ( my $pos = index( $lc_line, "reason for review:" ) != -1 )
				{	my ( @parts ) = split/reason for review:/, $lc_line;
					$reason = $parts[ $#parts ];
					$reason =~ s/^\s+//;
					$reason =~ s/\s+$//;
					$reason = undef if ( $reason eq "" );
				}
				
			if ( my $pos = index( $lc_line, "email:" ) != -1 )
				{	my ( @parts ) = split/email:/, $lc_line;
					$client_email = $parts[ $#parts ];
					$client_email =~ s/\s+//;
					$client_email = &CleanEmail( $client_email );
				}
				
			if ( my $pos = index( $lc_line, "referrer:" ) != -1 )
				{	my ( @parts ) = split/referrer:/, $lc_line;
					$referrer = $parts[ $#parts ];
					$referrer =~ s/\s+// if ( $referrer );
					$referrer = &CleanUrl( $referrer );
					
     				# Truncate the referrer in case it's too big!
     				$referrer = substr($referrer, 0, 254) if ( $referrer );		     
				}
	   }

	close( FILE );
	

#	print "URL $url\n"							if ( defined $url );
#	print "Category $category\n"				if ( defined $category );
#	print "Server hostname $hostname\n"			if ( defined $hostname );
#	print "Client IP $client_ip\n"				if ( defined $client_ip );
#	print "Client hostname $client_hostname\n"	if ( defined $client_hostname );
#	print "Client username $client_username\n"	if ( defined $client_username );
#	print "Client email $client_email\n"		if ( defined $client_email );
#	print "Time $time\n"						if ( defined $time );
#	print "Reason $reason\n"					if ( defined $reason );
#	print "Referrer $referrer\n"				if ( defined $referrer );


	return( undef, undef, undef, undef, undef, undef, undef, undef, undef, undef ) if ( ! $category );
	return( undef, undef, undef, undef, undef, undef, undef, undef, undef, undef ) if ( $category eq "local-block" );
	return( undef, undef, undef, undef, undef, undef, undef, undef, undef, undef ) if ( $category eq "spam" );
	
	return( $url, $category, $client_ip, $time, $reason, $client_email, $hostname, $client_hostname, $client_username, $referrer );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "BlockedContent [sourcedir]";
    print <<".";
Usage: $me [OPTION(s)]
    
  -s, --source=SOURCEDIR   source directory of tokens files to archive.
                           Default is the current directory.
  -h, --help               display this help and exit
  -t, --test               test this programs behavior (no data written to DB, files left intact)
  -v, --version            display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "BlockedContent";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
