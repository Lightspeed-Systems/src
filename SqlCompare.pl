################################################################################
#!perl -w
#
#  SqlCompare - compare the local IpmContent database with another source
#
################################################################################



use strict;
use warnings;



use Getopt::Long;


use Content::File;
use Content::SQL;
use Content::SQLCompare;



my $opt_version;						# Display version # and exit
my $opt_verbose;
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_ignore;							# If set, this is the list of categories to ignore
my $opt_domains_only;					# If True, then only compare domains


my $input_file_name;
my $output_file_name;
my $dbh;								# The global database handle


my $local_company	= "Lightspeed";		# These names are used in the Compare SQL tables
my $remote_company	= "Fast Data";


my %compare_category_rating	=			# A hash of key = compare_category_number, value = compare category rating (S, X, R, PG, G, Errors, Unknown )
(
	1	=>	'Errors',
	2	=>	'Unknown',
	3	=>	'PG',
	10	=>	'G',
	37	=>	'R',
	409	=>	'S',
	426	=>	'R',
	427	=>	'R',
	429	=>	'R',
	438	=>	'R',
	442	=>	'R',
	443	=>	'PG',
	444	=>	'R',
	448	=>	'PG',
	450	=>	'X',
	451	=>	'R',
	457	=>	'R'
);


my %compare_category_name =				# A hash of key = compare_category_number, value = compare category name
(
	1	=>	"errors",
	2	=>	"unknown",
	3	=>	"general",
	10	=>	"Arts and Entertainment" ,
	141	=>	"Science and Technology",
	150	=>	"Nature",
	154	=>	"Social Science",
	18	=>	"Computers and Internet",
	184	=>	"Finance",
	27	=>	"Job Search",
	282	=>	"FYI",
	29	=>	"Shopping",
	37	=>	"Adult",
	382	=>	"Business and Industry",
	409	=>	"Filter Avoidance",
	41	=>	"Games",
	410	=>	"Streaming Media",
	419	=>	"Non-mainstream",
	423	=>	"Lingerie and Swimsuits",
	426	=>	"Tasteless or Obscene",
	427	=>	"Lottery and Sweepstakes",
	429	=>	"Weapons",
	430	=>	"Web Hosting",
	431	=>	"Web-based Email",
	438	=>	"Tattoos",
	439	=>	"Cars and Motorcycles",
	440	=>	"Real Estate",
	441	=>	"Travel",
	442	=>	"Illegal Drugs",
	443	=>	"Alcohol and Tobacco",
	444	=>	"Gambling",
	448	=>	"Sex Ed and Abortion",
	450	=>	"Porn",
	451	=>	"Dating",
	457	=>	"Gay and Lesbian",
	459	=>	"Dining and Drinking",
	48	=>	"Sports and Recreation",
	49	=>	"Health and Nutrition",
	57	=>	"Society and Culture",
	65	=>	"Government and Law",
	9	=>	"Education"
);


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
		"d|domains"			=> \$opt_domains_only,
		"i|ignore=s"		=> \$opt_ignore,
        "v|verbose"			=> \$opt_verbose,
		"w|wizard"			=> \$opt_wizard,
        "h|help"			=> \$opt_help
    );


    &StdHeader( "SqlCompare" ) if ( ! $opt_wizard );
	
    &Usage() if ( ( $opt_help )  ||  ( $opt_version ) );
	
	
    print "Building compare tables\n";
	print "Ignoring category numbers $opt_ignore\n" if ( $opt_ignore );
	print "Only comparing domain tables\n" if ( $opt_domains_only );


	# Get the file names to use
	$input_file_name = shift;
	if ( ! $input_file_name )
		{	&Usage();
			exit();
		}
		
	$output_file_name = shift;
	$output_file_name = "SqlCompare.txt" if ( ! $output_file_name );
	
		
    #  Open the local database
	print "Opening a connection to the local database ...\n";
    $dbh = &ConnectServer() or die;

	print "Loading the local categories ...\n";
    &LoadCategories();


	# Fill out any missing category ratings with 'G'
	while ( my ( $category_number, $category_name ) = each( %compare_category_name ) )
		{	next if ( ! $category_number );
			next if ( exists $compare_category_rating{ $category_number } );
			
			$compare_category_rating{ $category_number } = 'G';
		}


	if ( ! open( INPUT, "<$input_file_name" ) )
		{	print "Error opening $input_file_name: $!\n";
			exit( 0 );
		}

	print "Opened file $input_file_name for input\n";


	&CompareSetup( $dbh, $local_company, $remote_company, \%compare_category_rating, \%compare_category_name, undef );
	
	&SqlCompare();
		
	&CompareClose( $dbh );
	
	close( INPUT );
	
	$dbh->disconnect if ( $dbh );
	
	
	print "Done.\n";

exit;

}
exit;



################################################################################
# 
sub SqlCompare()
#
#  Compare the contents of the 3 main tables in the remote IpmContent database  
#  to the local IpmContent database
#
################################################################################
{
	my $str;
	my $sth;
	my $count	= 0 + 0;
	my $lookup	= 0 + 0;


	if ( ! open( OUTPUT, ">$output_file_name" ) )
		{	print "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	print "Opened file $output_file_name for output\n";
	
	
	while ( my ( $url, $remote_category ) = &CompareNext() )
		{	last if ( ! defined $url );
			next if ( ! $url );
			next if ( ! $remote_category );
			
			if ( ! defined $compare_category_name{ $remote_category } )
				{	print "Undefined name for category number $remote_category\n";
					exit( 1 );
				}
				
			$lookup++;
			
			print "URL: $url, Category: $remote_category\n" if ( $opt_verbose );
			
			# Figure out what the type is
			my $type_name = "Domains";
			$type_name = "URLs" if ( $url =~ m/\// );
			$type_name = "IP addresses" if ( &IsIPAddress( $url ) );
					
			my $type_number = 2;
			$type_number = 1 if ( $type_name eq "Domains" );
			$type_number = 3 if ( $type_name eq "IP addresses" );
			
			my $lookupType = &LookupUnknown( $url, 0 );
			if ( $lookupType )
				{	my ( $category_number, $source_number ) = &FindCategory( $url, $lookupType );
					&CompareSave( $dbh, 2, $url, $category_number, $remote_category );			
					&ShowLookup( $type_name, $count, $lookup );
					next;	
				}
					
			print OUTPUT "$url\n";
					
			$count++;
					
			&ShowCounter( $type_name, $count, $lookup );
		}
	
	close( OUTPUT );	
	
	print "Looked up and compared $lookup URLs\n";
	
	return( 1 );
}



################################################################################
# 
sub CompareNext()
#
#  Return the next URL and category number to compare.  
#  Return undef, undef if all done
#  Return a category of 0 if nothing on this line
#  Do all the parsing of the input file here
#
################################################################################
{
	my $line = <INPUT>;
	
	return( undef, undef ) if ( ! $line );
	
	chomp( $line );
	return( "nothing", 0 ) if ( ! $line );
	
	my ( $url, $category_dis, $junk ) = split /\t/, $line, 3;
	
	return( $url, 0 ) if ( ! $category_dis );
	$url =~ s/^\*\.// if ( $url );
	$url =~ s/\/\*$// if ( $url );
	
	$url = &CleanUrl( $url );
	
	return( "nothing", 0 ) if ( ! $url );
	
	
	# Did it not match anything?  If so, return general
	return( $url, 3 ) if ( $line =~ m/No J\-Space results/ );	
	return( $url, 3 ) if ( $line =~ m/Either relevance/ );
	return( $url, 3 ) if ( $line =~ m/Failed URL request yet at least 3 terms recognized/ );
	return( $url, 3 ) if ( $line =~ m/DISqualified/ );
	return( $url, 3 ) if ( $category_dis =~ m/KW\=/i );
	
	
	# Was it an error of some sort?  If so, return errors
	return( $url, 1 ) if ( $line =~ m/Query Not Specified/ );
	return( $url, 1 ) if ( $line =~ m/Error in reading web page/ );
	
	
	# Is this a definite category?
	if ( $category_dis =~ m/^DIS\=/ )
		{	my $category_number = $category_dis;
			$category_number =~ s/^DIS\=//;
			$category_number = 0 + $category_number;
			
			return( $url, $category_number );
		}
		
	return( "nothing", 0 );
}



################################################################################
# 
sub ShowCounter()
#
#  Show a progress counter 
#
################################################################################
{	my $type	= shift;
	my $count	= shift;
	my $lookup	= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $count ) ||  ( ! $lookup ) );
	
	my $int = 10000 * sprintf( "%d", ( $count / 10000 ) );
	
	return( undef ) if ( $int != $count );
	
	print "Type: $type - looked up $lookup total, found $count missing so far ...\n";
	
	return( 1 );
}



################################################################################
# 
sub ShowLookup()
#
#  Show a lookup progress counter 
#
################################################################################
{	my $type	= shift;
	my $count	= shift;
	my $lookup	= shift;
	
	return( undef ) if ( ( ! $type )  ||  ( ! $count ) ||  ( ! $lookup ) );
	
	my $int = 100000 * sprintf( "%d", ( $lookup / 100000 ) );
	
	return( undef ) if ( $int != $lookup );
	
	print "Type: $type - looked up $lookup total, found $count missing so far ...\n";
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlComapre";

    print <<".";
Syntax: SqlCompare INPUT (OUTPUT)

SqlCompare compares the local IpmContentDatabase to another INPUT source,
and saves any missing entries to OUTPUT.  The default name for OUTPUT is 
SqlCompare.txt.

  -c, --compare      build the summary comparion tables in SQL
  -d, --domains      only compare domains, not IPs and URLs
  -i, --ignore LIST  the list of category numbers to ignore, i.e. 152,153

  -h, --help         show this help
.

    exit( 1 );
}



__END__

:endofperl
