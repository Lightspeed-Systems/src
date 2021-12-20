################################################################################
#!perl -w
#
# Glean - gleans information from the database and related tokens files
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;

use Content::File;
use Content::SQL;
use Content::Archive;



# Options
my $opt_help;
my $opt_version;
my $opt_urls_file;						# This is the file name of the list of urls of tokens files to glean from
my $opt_dest_directory		= 'I:\\Archive';	# This is the root of the archive directory
my $opt_target_dir;						# This is the directory to put the glean data files into
my $opt_no_remote_database;				# If True, then don't use the remote database for anything
my $opt_datestr;		# Optional date to extract from
my $opt_old_datestr;	# Optional date to extract domains, IP, etc older than
my $opt_source;		# If True, the source number to select database to export by
my $filename = "glean.urls";


my $dbh;
my $_version = "1.0.0";



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
        "d|destination=s"	=>	\$opt_dest_directory,
        "f|filename=s"		=>	\$filename,
        "o|old=s"			=>  \$opt_old_datestr,
        "s|source=s"		=>  \$opt_source,
        "t|time=s"			=>  \$opt_datestr,
        "v|version"			=>	\$opt_version,
        "h|help"			=>	\$opt_help
    );
	

    &StdHeader( "Glean" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );

	$dbh = &ConnectServer() or die "Unable to connect to the Content database\n";
	&LoadCategories();

	open( OUTPUT, ">$filename" ) or die "Error opening $filename: $!\n";

	print "Creating file $filename ...\n";
	
	if ( $opt_datestr )
		{	$options = " WHERE TransactionTime > \'$opt_datestr\'";
		}

	if ( $opt_old_datestr )
		{	$options = " WHERE TransactionTime < \'$opt_old_datestr\' AND ReviewTime < \'$opt_old_datestr\'";
		}


    my $str = "SELECT DomainName FROM IpmContentDomain";
	$str = $str . $options if ( $options );
	$str .= " AND CategoryNumber <> 59 AND CategoryNumber <> 30 AND CategoryNumber <> 29 AND CategoryNumber <> 55 AND CategoryNumber <> 56";
	
	print "SELECT: $str\n";
	
    my $sth = $dbh->prepare( $str );
    $sth->execute();

    my $array_ref = $sth->fetchall_arrayref();

	my $counter = 0 + 0;
	my $last_domain = "";
    foreach my $row ( @$array_ref )
        {	my ( $domain ) = @$row;

			$counter++;
			
            my $reverse_domain = &ReverseDomain( $domain );
            print OUTPUT "$reverse_domain\n";
			
 			if ( $last_domain eq $reverse_domain )
				{	print "Error: $reverse_domain is duplicated in the database\n";
				}
				
			$last_domain = $reverse_domain;
        }
	
	close OUTPUT;
	
	print "Output $counter rows\n";
	
	&StdFooter;

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Glean selectarg";
    print <<".";
Usage: $me [OPTION(s)]
Gleans data from the database and tokens files
    
  -d, --dest=ARCHIVEDIR    directory to retrieve the token files from
                           default is $opt_dest_directory
  -h, --help               display this help and exit
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
    my $me = "Glean";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
