################################################################################
#!perl -w

# Rob McCarthy's delknown - read in a list of urls, delete the known urls, and write out the unknown 


# Pragmas
use strict;
use warnings;


use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32API::Registry 0.21 qw( :ALL );


use Content::File;
use Content::SQL;
use Content::Category;


# Options
my $opt_help;
my $opt_version;
my $dbh;								# The global database handle


my $_version = "1.0.0";
my %urls;	# Global hash of urls


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
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	my $input_file	= shift;
	my $output_file = shift;
	
	
	die "You need to enter a file comtaining urls\n" if ( ! defined $input_file );
	
	
	$output_file = $input_file if ( ! defined $output_file );
	
 	if ( ! open( INPUT, "<$input_file" ) )
		{	die ( "Unable to open $input_file: $!\n" );
		}


	print "Opening a connection to the ODBC System DSN \'TrafficRemote\' ...\n";
	$dbh = &ConnectRemoteServer();
	
	if ( ! $dbh )
		{
print "Unable to open the Remote Content database.
Run ODBCAD32 and add the Content SQL Server as a System DSN named
\'TrafficRemote\' with default database \'IpmContent\'.
Also add the Content SQL Server as a System DSN named \'TrafficCategory\'
with default database \'Category\'.\n";

			close INPUT;
			exit( 0 );
		}

	
	print "Deleting known urls from $input_file ...\n";

	%urls = ();
	
	my $counter = 0 + 0;

	while (my $url = <INPUT>)
		{	$url = &CleanUrl( $url );
			next if ( ! defined $url );
			
			$counter++;
			
			if ( ( $counter / 1000 ) == &Integer( $counter / 1000 ) )
				{	print "Read $counter URLs\n";
				}
				
			my $retcode = &LookupUnknown( $url, 0 );
			next if ( $retcode );
			
			$urls{ $url } = 1;
		}
		
		
	close INPUT;
	
	
 	print "\nRead in $counter URLs\n";


	#  Sort the url list
	my @url_list = sort keys %urls;

	my $url_count = $#url_list;

	print "Read $url_count unique URLs total\n";
	print "Creating file $output_file ...\n";
 

 	if ( ! open( OUTPUT, ">$output_file" ) )
		{	die ( "Unable to open $output_file: $!\n" );
		}
		
	foreach ( @url_list )
		{	my $url = $_;
			next if ( ! defined $url );
			
			$url = &CleanUrl( $url );
			next if ( ! defined $url );
			
			if ( ! print( OUTPUT "$url\n" ) )
				{	my $err = $!;
					print "Print error on url $url: $err\n";
					die;
				}
		}

	close OUTPUT;
	
	
	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );

	print "\nDone\n";
    exit;
}



sub Integer( $ )
{	my $val = shift;
	
	my $int = sprintf( "%d", $val );
	$int = 0 + $int;
	
	return( $int );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

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
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
Usage: $me [OPTION(s)] input output
Goes through a list of urls from input and deletes any known URL.
If output is not specified then input will be used for output.
    
  -h, --help         display this help and exit
  -v, --version      display version information and exit
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
