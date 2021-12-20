################################################################################
#!perl -w
#
# Rob McCarthy's Sql Delete - given a list of delete domain names, move any
# existing domains in the Content database into the errors category
#
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long;



use Content::File;
use Content::SQL;



# Options
my $opt_category;                       # Option for categorizing just one category
my $opt_insert;							# True if domains and urls should be inserted without compressing to existing domains or urls
my $opt_override;						# Category to override - for example, ham overrides spam
my $opt_errors_file;					# True if errors should be written to a file
my $opt_misses_file;					# True if misses should be recorded
my $opt_hits_file;						# True if hits should be recorded
my $opt_dir;							# Directory to get stuff from
my $opt_move;							# True if you want to move existing domains, IP address, etc from unblocked categories to the given category
my $opt_help;
my $opt_version;
my $opt_source = 0 + 5;
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_existing;						# The name of the file to write existing domains and urls into
my $opt_reason;




# Globals
my $_version = "2.0.0";
my $dbh;                              #  My database handle



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
	"v|version"		=> \$opt_version,
	"w|wizard"		=> \$opt_wizard,
	"h|help"		=> \$opt_help
    );


    &StdHeader( "SqlDelete" ) if ( ! $opt_wizard );

    &Usage() if ( $opt_help );
	&Version() if ( $opt_version );


     #  Open the database
    $dbh = &ConnectServer() or die;
	&LoadCategories();

	# Get the directory
	$opt_dir = getcwd if ( ! $opt_dir );
	$opt_dir = getcwd if ( $opt_dir eq "." );
	$opt_dir =~ s#\/#\\#;  # Flip slashes to backslashes


	my $file = shift;
	&Usage() if ( ! defined $file );

	
	if ( ! open( FILE, "<$file" ) )
		{	die "Unable to open file $file: $!\n";
		}
		
	
	my $count = 0 + 0;	
	while ( my $line = <FILE> )
		{	chomp( $line );
			next if ( ! defined $line );
			
			my ( $domain, $junk ) = split /\s/, $line, 2;
			next if ( ! defined $domain );
			$domain = &CleanUrl( $domain );
			next if ( ! defined $domain );
			
			my $retcode = &LookupUnknown( $domain, 0 );

			next if ( ! $retcode );
			next if ( $retcode < 1 );
	
			print "Moving $domain to errors ...\n";		
			$retcode = &UpdateCategory( $domain, 7, $retcode, 3 );
			
			$count++;
		}


	close( FILE );

	print "Moved $count domains into the errors category\n";
	
	
	#  Clean up everything and quit
	$dbh->disconnect;
	
	&StdFooter if ( ! $opt_wizard );

exit;
}
################################################################################



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "SqlDelete";

    bprint "$me\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
.
   &StdFooter;

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlDelete";

    bprint <<".";
Usage: $me deletedlist
Given a deletedlist, move existing domains into the errors category

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
    my $me = "SqlDelete";

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
