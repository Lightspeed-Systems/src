################################################################################
#!perl -w
#
# Processing new Spam domains once a day
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use DBI qw(:sql_types);
use DBD::ODBC;


use Content::File;
use Content::SQL;


# Options
my $opt_help;
my $opt_version;
my $opt_final_directory		= "G:\\Content\\recategorize";
my $dbh;
my $max_in_memory			= 0 + 100000;	# This is the approximate maximum number of unique domains to hold in memory before dumping to disk
my $output_file_size		= 0 + 100;		# The size of each output file - 200 is roughly the number of domains 1 task can download in 1 hour
my $opt_datestr;		# Optional date to extract from



my $_version = "1.0.0";
my %domains;



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
        "d|dir=s"		=>  \$opt_final_directory,
        "t|time=s"		=>  \$opt_datestr,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );


    &StdHeader( "ProcessSpam" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	if ( ! -d $opt_final_directory )
		{	&FatalError( "Can not find directory $opt_final_directory\n" );
		}
		
		
	print "Opening a connection to the local SQL database ...\n";
	$dbh = &ConnectServer();
	if ( ! $dbh )
		{	print "Unable to connect to the Content database\n";
			exit;	
		}

	print "Using final directory $opt_final_directory ...\n";
	
	&LoadCategories();


	# Figure out the dates to use - start 1 day ago
	my $yesterday = time() - ( 24 * 60 * 60 );
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $yesterday );
	$year = 1900 + $year;
	$mon = $mon + 1;

	if ( ! defined $opt_datestr )
		{	$opt_datestr = sprintf( "%02d\/%02d\/%04d", $mon, $mday, $year );
		}
		
	my $today = time();
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $today );
	$year = 1900 + $year;
	$mon = $mon + 1;
	my $today_str = sprintf( "%02d\/%02d\/%04d", $mon, $mday, $year );
	
	print "Extracting spam domains added since $opt_datestr\n";

		
	my $counter = 0 + 0;
	%domains = ();
	my $spam_category = &CategoryNumber( "spam" );
	
    my $str = "SELECT DomainName FROM IpmContentDomain WHERE CategoryNumber = $spam_category AND TransactionTime > \'$opt_datestr\' AND TransactionTime < \'$today_str\'";	

    my $sth = $dbh->prepare( $str );
    $sth->execute();

    my $array_ref = $sth->fetchall_arrayref();

    foreach my $row ( @$array_ref )
        {	my ( $reverse_domain ) = @$row;
			next if ( ! defined $reverse_domain );
			
            my $domain = &ReverseDomain( $reverse_domain );
			next if ( ! defined $domain );
			
			$domain = &CleanUrl( $domain );
			next if ( ! defined $domain );		
			
			# Compress it to the root
			my $root = &RootDomain( $domain );
			next if ( ! defined $root );
			
			# Is the domain already in the hash?
			next if ( exists $domains{ $root } );
			
			# Add it to my domain hash
			$domains{ $root } = 1;
					
			$counter++;
			
 			# Have I read in a bunch of domains?
			if ( $counter >= $max_in_memory )
				{	
					( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
					$year = 1900 + $year;
					$mon = $mon + 1;
					my $datestr = sprintf( "%04d%02d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );
					
					&DumpDomains( $opt_final_directory, "espamb$datestr" );
					$counter = 0 + 0;
					%domains = ();
				}
        }

		
	# Do I still have some domains in the hash?
	if ( $counter )
		{
			( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
			$year = 1900 + $year;
			$mon = $mon + 1;
			my $datestr = sprintf( "%04d%02d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );
			
			&DumpDomains( $opt_final_directory, "espamc$datestr" );
			$counter = 0 + 0;
			%domains = ();
		}
		
		
	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );

    exit;
}



################################################################################
# 
sub DumpDomains( $$ )
#
################################################################################
{	my $dir		= shift;
	my $file	= shift;
	
	
	print "Dumping out spam domain files to directory $dir ...\n";
	
	# Open the output files
	my $filename = $dir . "\\$file.1.txt";

	open OUTPUT, ">$filename" or die "Cannot create output file $filename: $!\n";
	print "Creating file $filename ...\n";

	my  $file_counter	= 0 + 0;
	my  $file_number	= 0 + 1;

	my @url_list = sort keys %domains;
	
	foreach ( @url_list )
		{	my $new_url = $_;
			print OUTPUT "$new_url\n";
			$file_counter++;;

			if ( $file_counter > $output_file_size )
				{	$file_counter = 0 + 0;
					$file_number++;

                     close OUTPUT;
                     $filename = $dir . "\\$file.$file_number.txt";

                     open OUTPUT, ">$filename" or die "Cannot create output file $filename: $!\n";
                     print "Creating file $filename ...\n";
                 }
         }


    close OUTPUT;
	
	return( 1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "ProcessSpam";

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
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
    my $me = "ProcessSpam";
    print <<".";
Usage: $me [OPTION(s)]
Does the daily processing of new spam domains.

Reads in the new spam domains from SQL.
Spit out the spam domains in up to $output_file_size URL files
into the $opt_final_directory directory so the army
of download servers can chew them up.

Directories used are:
$opt_final_directory

  -d, --dir DIR     the final directory, default is:
                    $opt_final_directory
  -h, --help        display this help and exit
  -v, --version     display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "ProcessSpam";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
