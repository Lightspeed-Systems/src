################################################################################
#!perl -w
#
#  SqlOldest - export out from the domain table the oldest entries for use in 
#  recategorizing
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Content::File;
use Content::SQL;
use DBI qw(:sql_types);
use DBD::ODBC;



my $opt_category;				# Option for categorizing just one category
my $opt_days = 0 + 90;			# Number of days to export older domains by
my $opt_file = "old_domains";	#  The file name if supposed to read unknown urls from a file
my $opt_help;
my $opt_version;
my $opt_wizard;					# True if I shouldn't display headers or footers
my $opt_source;					# If True, the source number to select database to export by
my $opt_new;					# If set, this is the nuber of days newer to export out
my $opt_equal;					# If set, export only sourcenumber equeal to this
my $opt_max;					# If set, this is the maximum number of old domains to export
my $opt_debug;
my $opt_purge;					# If set then purge out non-root domains by setting them to errors



# Globals
my $_version = "2.0.0";
my  $dbh;						#  My database handle



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
        "c|category=s"	=> \$opt_category,
        "d|day=i"		=> \$opt_days,
        "e|equal=i"		=> \$opt_equal,
        "f|file=s"		=> \$opt_file,
        "n|new=i"		=> \$opt_new,
        "m|max=i"		=> \$opt_max,
        "p|purge"		=> \$opt_purge,
        "s|source=i"	=> \$opt_source,
        "v|version"		=> \$opt_version,
		"w|wizard"		=> \$opt_wizard,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "SqlOldest" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	
	&TrapErrors() if ( ! $opt_debug );
	
	&SetLogFilename( ".\\SqlOldest.log", undef );

	$opt_source = undef if ( defined $opt_equal );
	
	$opt_days = undef if ( defined $opt_new );
	
	
	&lprint( "Exporting domains to file $opt_file ... \n" );
	&lprint( "Exporting domains whose transaction and review times are OLDER than $opt_days days ... \n" ) if ( defined $opt_days );
	&lprint( "Exporting domains whose transaction and review times are NEWER than $opt_new days ... \n" ) if ( defined $opt_new );
	&lprint( "Export only category $opt_category ... \n" ) if ( $opt_category );
	&lprint( "Export only entries with source number equal to or greater than $opt_source ... \n" ) if ( defined $opt_source );
	&lprint( "Export only entries with source number equal to $opt_equal ... \n" ) if ( defined $opt_equal );
	&lprint( "Ignoring spam, error, and expired domains ... \n" ) if ( ! $opt_category );
	&lprint( "Only exporting up to $opt_max domains ... \n" ) if ( $opt_max );


	$dbh = &ConnectServer() or die;

	&LoadCategories();

	#  Am I exporting a single category?
	if ( $opt_category )
		{	my  $category_number = &CategoryNumber( $opt_category );
			die "Unable to find category number for category name $opt_category\n"  if ( $category_number == 0 );

			&ExportFile( $category_number, $opt_category );
		}
     else
		{	&ExportFile( undef, undef );
		}


     $dbh->disconnect;

     &StdFooter if ( ! $opt_wizard );

exit;
}

exit;
################################################################################




################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $filename = "SqlOldestErrors.log";
	
	my $MYLOG;
   
	# If the error log is getting really big then delete it
	my $size = -s $filename;
	unlink( $filename ) if ( ( $size )  &&  ( $size > 1000000 ) );

	if ( ! open( $MYLOG, ">>$filename" ) )
		{	&lprint( "Unable to open $filename: $!\n" );  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	&lprint( "Error trapping set to file $filename\n" ); 
}



################################################################################
# 
sub ExportFile( $$ )
#
#  Export out the old data
#
################################################################################
{	my  $category_number = shift;
	my  $category = shift;

	my $time;
	my $datestr;
	
	if ( defined $opt_days )
		{	$time = time - ( $opt_days * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $time );
			$year += 1900;
			$mon++;
			$datestr = sprintf( "%02d/%02d/%04d", $mon, $mday, $year );
		}
		
	my $newer_than;
	
	if ( defined $opt_new )
		{	$time = time - ( $opt_new * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $time );
			$year += 1900;
			$mon++;
			my $newer_datestr = sprintf( "%02d/%02d/%04d", $mon, $mday, $year );
			
			$newer_than = "ReviewTime > \'$newer_datestr\'";
		}
		
	
	my $options;
	
	if ( $opt_source )
		{	$options = " AND SourceNumber >= \'$opt_source\'";
		}


	if ( $opt_equal )
		{	$options = " AND SourceNumber = \'$opt_equal\'";
		}


	# Add the category options
	if ( $category_number )
		{	my $category_options = " AND CategoryNumber = \'$category_number\'";
			$options .= $category_options if ( defined $options );
			$options = $category_options if ( ! defined $options );
		}
		

    open( OUTDOMAINS, ">$opt_file" ) or die "Cannot create output file: $opt_file: \n$!\n";
    &lprint( "Creating file $opt_file ... \n" );


    my $str = "SELECT DomainName, SourceNumber FROM IpmContentDomain WITH(NOLOCK) WHERE ";
	
	# Either $opt_days or $opt_new must be True
	$str = $str . "TransactionTime < \'$datestr\' AND ReviewTime < \'$datestr\'" if ( defined $opt_days );
	$str = $str . $newer_than if ( defined $opt_new );
	
	$str = $str . $options if ( defined $options );

	if ( $opt_max )
		{	$str .= " ORDER by ReviewTime";
		}

	&lprint( "SQL Statement: $str\n" );
    my $sth = $dbh->prepare( $str );
    $sth->execute();

 
	my $count = 0 + 0;
	my $last_domain = "";
	my @purge_list;
    while (  my ( $domain, $source_number  ) = $sth->fetchrow_array() )
        {	$domain = lc( $domain );
			my $reverse_domain = &ReverseDomain( $domain );
			
 			if ( $last_domain eq $reverse_domain )
				{	&lprint( "Error: $reverse_domain (reversed $domain) is duplicated in the database\n" );
				}
					
			$last_domain = $reverse_domain;
			
			
			# Make sure that this is a root domain
			my $root = &RootDomain( $reverse_domain );
			if ( ! $root )
				{	&lprint( "$reverse_domain (reversed $domain) is not a valid domain\n" );
					push @purge_list, $domain if ( ( $opt_purge )  &&  ( $source_number > 2 ) );
					next;	
				}
			
			$source_number = 0 + 3 if ( ! $source_number );
			if ( ( $root ne $reverse_domain )  &&  ( $source_number > 2 ) )
				{	&lprint( "$reverse_domain is not a root domain and has a source number of $source_number\n" );
					push @purge_list, $domain if ( $opt_purge );
					next;
				}
				
            print OUTDOMAINS "$reverse_domain\n";
			
			$count++;
			
			last if ( ( $opt_max )  &&  ( $count >= $opt_max ) );
        }

	$sth->finish();


    $str = "SELECT IPAddress FROM IpmContentIpAddress WITH(NOLOCK) WHERE ";
	
	# Either $opt_days or $opt_new must be True
	$str = $str . "TransactionTime < \'$datestr\' AND ReviewTime < \'$datestr\'" if ( defined $opt_days );
	$str = $str . $newer_than if ( defined $opt_new );
	
	$str = $str . $options if ( $options );

	if ( $opt_max )
		{	$str .= " ORDER by ReviewTime";
		}

	&lprint( "SQL Statement: $str\n" );
    $sth = $dbh->prepare( $str );
    $sth->execute();


	my $ip_count = 0 + 0;
    while (  my ( $ip  ) = $sth->fetchrow_array() )
        {	my $str_ip = &IPToString( $ip );
			
            print OUTDOMAINS "$str_ip\n";
						
			$ip_count++;
			
			last if ( ( $opt_max )  &&  ( ( $count + $ip_count ) >= $opt_max ) );
        }
		
	close( OUTDOMAINS );

	$sth->finish();
	
	&lprint( "Exported $count domains and $ip_count IP addresses\n" );


	if ( $opt_purge )
		{	&lprint( "Purging out the non-root domains ...\n" );
			
			$count = 0 + 0;
			foreach( @purge_list )
				{	my $domain = $_;
					next if ( ! defined $domain );
					
					$str = "DELETE FROM IpmContentDomain WHERE DomainName = '$domain'";
					$sth = $dbh->prepare( $str );
					$sth->execute();
					
					$sth->finish();
					
					$count++;
				}
				
			&lprint( "Done purging $count domains\n" );
		}
		
		
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlOldest";

    bprint <<".";
Usage: $me [exportfile] [OPTION(s)]
Export the oldest domains and IP addresses from the Content Database to a file.
The default export file name is $opt_file.

  -c, --category=name    category name if only one category to export
  -d, --days=NUM         the number of days old - default is 90
  -e, --equal=SRC        to export only source SRC
  -m, --max=NUM          the maximum number of domains to export
  -n, --new=NUM          the number of days newer than
  -f, --file=FILE        file name to export to - default is \'$opt_file\'
  -p, --purge            to move non-root domain entries into errors
  -s, --source=SRC       to export only source SRC or greater - default is 3
  -h, --help             display this help and exit
  -v, --version          display version information and exit
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
    my $me = "SqlOldest";

    bprint <<".";
$me $_version
.
     &StdFooter;

    exit;
}



__END__

:endofperl
