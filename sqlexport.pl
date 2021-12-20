################################################################################
#!perl -w
#
#     SqlExport - Export out of SQL into squid formatted text files
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



my $opt_category;							# Option for exporting just one category
my $opt_dir;								# Directory to put stuff to
my $opt_input_domains	= "domains";		# The file name if supposed to read unknown urls from a file
my $opt_input_urls		= "urls";
my $opt_input_hits		= "hits.urls";
my $opt_input_misses	= "misses.urls";
my $opt_help;
my $opt_version;
my $opt_datestr;							# Optional date to extract from newer from
my $opt_old_datestr;						# Optional date to extract domains, IP, etc older than
my $opt_wizard;								# True if I shouldn't display headers or footers
my $opt_source;								# If True, the source number to select database to export by
my $opt_pattern;							# If set, this is a regular expression that the exported domains and urls must match
my $opt_num;								# If set this is the nuber of days to export newer than



# Globals
my $_version = "2.0.0";
my  $dbh;             #  My database handle



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
        "d|directory=s" => \$opt_dir,
        "n|num=i"		=> \$opt_num,
        "o|old=s"		=> \$opt_old_datestr,
        "p|pattern=s"	=> \$opt_pattern,
        "s|source=s"	=> \$opt_source,
        "t|time=s"		=> \$opt_datestr,
        "v|version"		=> \$opt_version,
		"w|wizard"		=> \$opt_wizard,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "SqlExport" ) if ( ! $opt_wizard );

	&Usage() if ($opt_help);
    &Version() if ($opt_version);


	if ( $opt_num )
		{	my $time = time - ( $opt_num * 24 * 60 * 60 );
			
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $time );
			$year = 1900 + $year;
			$mon = $mon + 1;
			$opt_datestr = sprintf( "%02d/%02d/%04d", $mon, $mday, $year );
		}
		
		
	bprint "Exporting Content SQL database to Squidguard format ... \n";
	bprint "Export only category $opt_category ... \n" if ( $opt_category );
	bprint "Export only entries newer than $opt_num days ... \n" if ( $opt_num );
	bprint "Export only entries newer than $opt_datestr ... \n" if ( $opt_datestr );
	bprint "Export only entries older than $opt_old_datestr ... \n" if ( $opt_old_datestr );
	bprint "Export only entries with source number equal to $opt_source ... \n" if ( $opt_source );
	bprint "Export only entries that match regular expression $opt_pattern ... \n" if ( $opt_pattern );


	$dbh = &ConnectServer() or die;

	&LoadCategories();


	#  Am I exporting a single category?
	if ( $opt_category )
		{	my  $category_number = &CategoryNumber( $opt_category );
			die "Unable to find category number for category name $opt_category\n"  if ( $category_number == 0 );

			&ExportCategoryFiles( $category_number, $opt_category );
       }
	else
		{	my $top = &TopCategoryNumber();

			for ( my $category_number = 1;  $category_number <= $top;  $category_number++ )
				{	my $category = &CategoryName( $category_number );
					next if ( !$category );

					&ExportCategoryFiles( $category_number, $category );
				}
		}


	$dbh->disconnect;

	&StdFooter if ( ! $opt_wizard );

exit;
}

exit;
################################################################################




################################################################################
# 
sub ExportCategoryFiles( $$ )
#
#  Given a category number and name, export out from the SQL database all the squidguard formatted files
#
################################################################################
{	my  $category_number	= shift;
	my  $category			= shift;

	my $dir = $category;
	$dir = $opt_dir . "\\" . $category if ( $opt_dir );

	my $options;
	
	if ( $opt_datestr )
		{	$options = " AND TransactionTime > \'$opt_datestr\'";
		}

	if ( $opt_old_datestr )
		{	$options = " AND TransactionTime < \'$opt_old_datestr\' AND ReviewTime < \'$opt_old_datestr\'";
		}

	if ( $opt_source )
		{	my $source_options = " AND SourceNumber = \'$opt_source\'";
			$options .= $source_options if ( $options );
			$options = $source_options if ( ! $options );
		}

    my  $cmd;
    bprint "Creating category $category files in directory $dir... \n";

    $cmd = "mkdir $dir";
    system( $cmd );

    my  $filename = "$dir\\$opt_input_domains";
    open( OUTDOMAINS, ">$filename" ) or die "Cannot create output file: $filename,\n$!\n";
    bprint "Creating file $filename ... \n";

    my $str = "SELECT IpAddress FROM IpmContentIpAddress WHERE CategoryNumber=$category_number";
	$str = $str . $options if ( $options );

	$str .= " ORDER BY IpAddress";

	print "SQL Statement: $str\n";
    my $sth = $dbh->prepare( $str );
    $sth->execute();

    my $array_ref = $sth->fetchall_arrayref();

	my $last_ip = "";
	foreach my $row ( @$array_ref )
        {	my ( $ipAddress ) = @$row;
            my $str = &IPToString( $ipAddress );
			
			if ( ! $str )
				{	$ipAddress = "undefined" if ( ! $ipAddress );
					print "Error: $ipAddress is not a valid IP address\n";
					next;
				}
				
			# Should I compare it to a pattern?
			if ( defined $opt_pattern )
				{	my $match = 1 if ( $str =~ m/$opt_pattern/ );
					next if ( ! $match );
				}
				
            print OUTDOMAINS "$str\n";
			
			if ( $last_ip eq $str )
				{	$str = "undefined" if ( ! $str );
					print "Error: $str is duplicated in the database\n";
				}
				
			$last_ip = $str;
        }

    $str = "SELECT DomainName FROM IpmContentDomain WHERE CategoryNumber=$category_number";
	$str = $str . $options if ( $options );
	$str .= " ORDER BY DomainName";
	
	print "SQL Statement: $str\n";
	
    $sth = $dbh->prepare( $str );
    $sth->execute();

    $array_ref = $sth->fetchall_arrayref();

	my $last_domain = "";
    foreach my $row ( @$array_ref )
        {	my ( $domain ) = @$row;

            my $reverse_domain = &ReverseDomain( $domain );
			
			# Should I compare it to a pattern?
			if ( defined $opt_pattern )
				{	my $match = 1 if ( $reverse_domain =~ m/$opt_pattern/ );
					next if ( ! $match );
				}
				
            print OUTDOMAINS "$reverse_domain\n";
			
 			if ( $last_domain eq $reverse_domain )
				{	print "Error: $reverse_domain is duplicated in the database\n";
				}
				
			$last_domain = $reverse_domain;
        }

	close( OUTDOMAINS );


    #  Now do the urls ...
    $filename = "$dir\\$opt_input_urls";

    open( OUTURLS, ">$filename" ) or die "Cannot create output file: $filename,\n$!\n";
    bprint "Creating file $filename ... \n";

    $str = "SELECT URL FROM IpmContentURL WHERE CategoryNumber=$category_number ORDER BY URL";
	$str = "SELECT URL FROM IpmContentURL WHERE CategoryNumber=$category_number" . $options . " ORDER BY URL" if ( $options );
	
	print "SQL Statement: $str\n";
	
    $sth = $dbh->prepare( $str );
    $sth->execute();

	$array_ref = $sth->fetchall_arrayref();

	my $last_url = "";
	foreach my $row ( @$array_ref )
		{	my ( $url ) = @$row;
			
			# Should I compare it to a pattern?
			if ( defined $opt_pattern )
				{	my $match = 1 if ( $url =~ m/$opt_pattern/ );
					next if ( ! $match );
				}
				
			print OUTURLS "$url\n";
			
  			if ( $last_url eq $url )
				{	print "Error: $url is duplicated in the database\n";
				}
				
			$last_url = $url;	
		}

    close( OUTURLS );



    #  Now do the hits ...
    $filename = "$dir\\$opt_input_hits";

    open( OUTHITS, ">$filename" ) or die "Cannot create output file: $filename,\n$!\n";
    bprint "Creating file $filename ... \n";

    $str = "SELECT URL FROM IpmContentCategoryHits WHERE CategoryNumber=$category_number ORDER BY URL";
    $sth = $dbh->prepare( $str );
    $sth->execute();

	$array_ref = $sth->fetchall_arrayref();

	foreach my $row ( @$array_ref )
		{	my ( $url ) = @$row;
			print OUTHITS "$url\n";
		}

    close( OUTHITS );


    #  Now do the misses ...
    $filename = "$dir\\$opt_input_misses";

    open( OUTMISSES, ">$filename" ) or die "Cannot create output file: $filename,\n$!\n";
    bprint "Creating file $filename ... \n";

    $str = "SELECT URL FROM IpmContentCategoryMisses WHERE CategoryNumber=$category_number ORDER BY URL";
    $sth = $dbh->prepare( $str );
    $sth->execute();

	$array_ref = $sth->fetchall_arrayref();

	foreach my $row ( @$array_ref )
		{	my ( $url ) = @$row;
			print OUTMISSES "$url\n";
		}

    close( OUTMISSES );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlExport";

    bprint <<".";
Usage: $me [OPTION(s)]
Export domains, urls, hits, and misses from the Content Database to
Squidguard format

  -c, --category=name    category name if only one category to export
  -d, --directory=PATH   to change default files directory
  -n, --num DAYS         to export rows that have changed since DAYS
  -o, --old=mm/dd/yyyy   to export rows that have changed before the time
  -p, --p=PATTERN        to export rows matching regular expression PATTERN
  -s, --source=NUM       to export row with source NUM
  -t, --time=mm/dd/yyyy  to export rows that have changed since the time
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
    my $me = "SqlExport";

    bprint <<".";
$me $_version
.
     &StdFooter;

    exit;
}



__END__

:endofperl
