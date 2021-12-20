################################################################################
#!perl -w
#
#  SqReasonExport - export out from the domain table the oldest entries for use in 
#  recategorizing
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;



use Content::File;
use Content::SQL;
use Content::Category;



# My options
my $opt_category;				# Option for categorizing just one category
my $opt_file = "SqlReasonExport.txt";	#  The file name if supposed to read unknown urls from a file
my $opt_help;
my $opt_version;
my $opt_wizard;					# True if I shouldn't display headers or footers
my $opt_newer;					# If set, export only transaction times newer than this
my $opt_older;					# If set, export only transaction times older than this
my $opt_reason;					# If set, this is category reason
my $opt_hostname;				# If set, export only with the given hostname
my $opt_query;					# If set, use this query to export



# Globals
my	$_version = "2.0.0";
my  $dbh;						#  My database handle
my  $dbhCategory;				#  My database handle to the TrafficCategory database



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
        "f|file=s"		=> \$opt_file,
        "h|hostname=s"	=> \$opt_hostname,
        "r|reason=s"	=> \$opt_reason,
        "o|older=s"		=> \$opt_file,
        "q|query=s"		=> \$opt_query,
        "n|newer=s"		=> \$opt_newer,
        "v|version"		=> \$opt_version,
		"w|wizard"		=> \$opt_wizard,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "SqlReasonExport" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
    &Version() if ($opt_version);

	$dbh = &ConnectServer() or die;

	&LoadCategories();


	lprint "Opening a connection to the ODBC System DSN \'TrafficCategory\' ...\n";


	# Connect to the category database
	$dbhCategory = &CategoryConnect();
	if ( ! $dbhCategory )
		{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";
			exit( 10 );
		}


	my $where_query = $opt_query;
	
	&ReasonExport( $where_query );

	$dbh->disconnect if ( $dbh );
	$dbhCategory->disconnect if ( $dbhCategory );

	&StdFooter if ( ! $opt_wizard );

exit;
}
exit;
################################################################################



################################################################################
#
sub ReasonExport( $ )
#
#  Save the domain, the category, and the reason I categorized it
#
################################################################################
{	my $where_query = shift;
	
	open( FILE, ">$opt_file" ) or die( "Error opening $opt_file: $!\n" );
	
	print "Writing to file $opt_file ...\n";
	
    my $str = "SELECT DomainName from DomainReason WHERE $where_query";

	print "Select statement: $str\n";

    my $sth = $dbhCategory->prepare( $str );
    $sth->execute();

	if ( $dbhCategory->err )
		{	print "Error executing select statement\n";
			return( undef );
		}
		
    my $array_ref = $sth->fetchall_arrayref() ;

	my $count = 0 + 0;
	foreach my $row ( @$array_ref )
		{	my ( $domain ) = @$row;
			next if ( ! defined $domain );
			
			print FILE "$domain\n";
			
			$count++;
		}

	$sth->finish();
	
	close( FILE );
	
	print "Wrote $count domain names to $opt_file\n";
	
	return( $count );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlReasonExport";

    bprint <<".";
Usage: $me [exportfile] [OPTION(s)]
Export the oldest domains from the Content Database to a file.
The default export file name is $opt_file.

  -c, --category=name    category name if only one category to export
  -d, --days=NUM         the number of days old - default is 90
  -e, --equal=SRC        to export only source SRC
  -m, --max=NUM          the maximum number of domains to export
  -n, --new=NUM          the number of days newer than
  -f, --file=FILE        file name to export to - default is \'$opt_file\'
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
    my $me = "SqlReasonExport";

    bprint <<".";
$me $_version
.
     &StdFooter;

    exit;
}



__END__

:endofperl
