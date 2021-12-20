################################################################################
#!perl -w
#
# SqlVirusUpdate - import recently discovered websites that contain viruses into
# the Content database.  Also update the Category reason table with the virus name
#
#  Copyright 2007 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long;



use Content::File;
use Content::FileUtil;
use Content::SQL;
use Content::Category;



# Options
my $opt_verbose = 1;                    # If True then be verbose
my $opt_help;
my $opt_source = 0 + 3;
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_existing;						# The name of the file to write existing domains and urls into
my $opt_reason;
my $opt_days = 0 + 365;					# Default to within the last year


my $virus_root					= "Q:\\Virus Archive";		# This is the root directory to put all virus samples into


# Globals
my $_version = "2.0.0";
my $dbh;                              #  My database handle
my $dbhProgram;



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
			"d|day=i"		=> \$opt_days,
			"s|source=i"	=> \$opt_source,
			"v|verbose"		=> sub { if ( $opt_verbose )
										{	$opt_verbose = undef;
										}
									else
										{	$opt_verbose = 1; 
										}
									},
			"w|wizard"		=> \$opt_wizard,
			"h|help"		=> \$opt_help
	    );


    &StdHeader( "SqlVirusUpdate" ) if ( ! $opt_wizard );

    &Usage() if ( $opt_help );


	&SetLogFilename( "SqlVirusUpdate.log", 1 );
	&lprint( "Set logging file to SqlVirusUpdate.log\n" );


	# Map drive Q: if it isn't already mapped
	if ( ! -d $virus_root )
		{	lprint "Mapping drive Q: to \\\\fs06\\Drive-Q ...\n";
			system "net use Q: \\\\fs06\\Drive-Q /USER:LIGHTSPEED\\Rob seeker";
		}

	if ( ! -d $virus_root )
		{	lprint "Unable to find virus root directory $virus_root\n";
			exit( 1 );
		}
		
		
    #  Make sure the source number is numeric
    $opt_source = 0 + $opt_source;
    &Usage() if ( ( $opt_source )  &&  ( $opt_source < 1 || $opt_source > 2000 ) );
    
	
	# Should I only check relatively new Program Links?
	my $datestr;
	if ( ( defined $opt_days )  &&  ( $opt_days ) )
		{	my $time = time - ( $opt_days * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $time );
			$year += 1900;
			$mon++;
			$datestr = sprintf( "%04d-%02d-%02d %02d:%02d:%02d\.%03d", $year, $mon, $mday, $hour, $min, $sec, 0 );
			lprint "Only checking Program Links that have been downloaded since $datestr\n";
		}

		
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
lprint "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 1 );
		}
	lprint "Connected to the Program database\n";	

    #  Open the Ipmcontent database
    $dbh = &ConnectServer() or die;
	lprint "Connected to the local IpmContent database\n";

    &LoadCategories();

	my $dbhCategory = &CategoryConnect();
	lprint "Connected to the Category database\n" if ( $dbhCategory );
	

	# First get all the ProgramLinks that have had viruses discovered
	lprint "Querying the Program database for virus infecteded URLs ...\n";
	
	my $str = "SELECT Programs.FileID, AppName, ProgURL, [Filename], ProgramLink.TransactionTime from ProgramLink, Programs WITH(NOLOCK) 
where Programs.[Filename] like 'q:\\virus archive\\%' 
and Programs.[Filename] not like 'q:\\virus archive\\nettool%'
and Programs.[Filename] not like 'q:\\virus archive\\joke%'
and ProgramLink.FileID = Programs.FileID";

	$str = "SELECT Programs.FileID, AppName, ProgURL, [Filename], ProgramLink.TransactionTime from ProgramLink, Programs WITH(NOLOCK) 
where Programs.[Filename] like 'q:\\virus archive\\%' 
and Programs.[Filename] not like 'q:\\virus archive\\nettool%'
and Programs.[Filename] not like 'q:\\virus archive\\joke%'
and ProgramLink.TransactionTime > '$datestr'
and ProgramLink.FileID = Programs.FileID" if ( defined $datestr );
	

	lprint "SQL Query: $str\n";
	
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();
		
	my $rows = 0 + 0;
	my %domain_virus;
	while ( ( ! $dbhProgram->err )  &&  (  my ( $hex_file_id, $app_name, $prog_url, $filename, $transaction_time ) = $sth->fetchrow_array() ) )
		{	next if ( ! $app_name );
			next if ( ! $prog_url );
			
			# here is the list of stuff that could be in the virus archive, but it isn't a problem
			next if ( $filename =~ m/q\:\\virus archive\\nettool/i );
			next if ( $filename =~ m/q\:\\virus archive\\joke/i );
			
			# Check to make sure the file is still in the virus archive
			if ( ! -f $filename )
				{	lprint "Could not find file $filename\n" if ( $opt_verbose );
					next;
				}
				
			my $domain = &RootDomain( $prog_url );
			next if ( ! $domain );
			
			$rows++;
			
			# Keep a list of all the viruses I have found on this domain
			my $virus_list = $domain_virus{ $domain };
			$virus_list = $virus_list . "\t" . $app_name . " at " . $prog_url if ( $virus_list );
			$virus_list = $app_name . " at " . $prog_url if ( ! $virus_list );
			$domain_virus{ $domain } = $virus_list;
		}

	$sth->finish();

	lprint "Found $rows virus infected program links ...\n";
	
	lprint "Inserting domain categories into the local IpmContent database ...\n";
	my $changed = 0 + 0;
	while ( my ( $domain, $virus_list ) = each( %domain_virus ) )
		{	next if ( ! $domain );
			next if ( ! $virus_list );
			
			my @virus_list = split /\t/, $virus_list;
			
			my $ret = &UpdateVirus( $domain, \@virus_list );
			$changed++ if ( $ret );
		}
		
	lprint "Changed $changed domains\n";
	
	#  Clean up everything and quit
	$dbh->disconnect;
	
	&CategoryClose() if ( $dbhCategory );
	$dbhCategory = undef;
	
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
	
	&StdFooter if ( ! $opt_wizard );

exit;
}
################################################################################



################################################################################
#
sub UpdateVirus( $$ ) 
#
# Given the domain, and the viruses I found, update the databases
#
################################################################################
{	my $domain			= shift;
	my $virus_list_ref	= shift;
	
	# Build up the reason
	my $reason = "Found virus ";
	
	my $count = 0 + 0;
	foreach( @$virus_list_ref )
		{	my $virus_url = $_;
			next if ( ! $virus_url );
			
			$reason = $reason . ", found virus " . $virus_url if ( $count );
			$reason = $reason . $virus_url if ( ! $count );
			
			$count++;
		}
	
	return( 0 + 0 ) if ( ! $count );
	
	if ( $opt_verbose )
		{	lprint "Domain: $domain\n";
			lprint "Reason: $reason\n";
		}
		
	my $category_number = 0 + 63;
	$category_number = 0 + 62 if ( $reason =~ m/spyware/i );
	$category_number = 0 + 62 if ( $reason =~ m/adware/i );
	
	my $ret = &InsertUrlCategory( $domain, $category_number, $opt_source );

	if ( $ret < 0 )
		{	lprint "Unable to override domain $domain\n";
			return( 0 + 0 );
		}
	
	my $category = "security.virus";
	$category = "security.spyware" if ( $category_number == 62 );
	
	&CategorySaveDomainReason( $domain, $category, $reason );
	
	# If I got a retcode of found, update the ReviewTime
	my $retcode = &LookupUnknown( $domain, 0 );
	&UpdateReviewTime( $domain, $retcode ) if ( $retcode );
	
	return( $ret );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlVirusUpdate";

    bprint <<".";
Usage: $me [OPTIONS]

Querys the Program database to find any ProgramLinks that have been discovered
as viruses, then updates the IpmContent database and the Category DomainReason
table, putting the domains into either the security.virus or the 
security.spyware categories.

  -d, --days=NUM           the number of days since downloaded - default is 365
  -s, --source SOURCENUM   source number to use, default is '3'
  -h, --help               display this help and exit
  -v, --verbose            display verbose information
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
    my $me = "SqlImport";

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
