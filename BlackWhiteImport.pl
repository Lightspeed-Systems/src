################################################################################
#!perl -w
#
# Rob McCarthy's version of importing spam black and white lists into the spam
# patterns table
#
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;
use Getopt::Long;
use Content::File;
use Content::FileUtil;
use Content::SQL;
use Cwd;
use DBI qw(:sql_types);
use DBD::ODBC;



# Validate and get the parameters
my $_version = "2.0.0";

my $opt_version;
my $opt_verbose;
my $opt_help;
my $opt_dir;		# Directory to use
my $opt_debug;		# Debug mode - leaves created files in place
my $opt_working;	# True if shold delete working files
my $opt_wizard;		# True if I shouldn't display headers and footers
my $dbh;
my %subjects;		# Subject hash - key is subject line, value if the rest of the clues




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
        "d|directory=s" =>\$opt_dir,
        "w|wizard" => \$opt_wizard,
        "v|verbose" => \$opt_verbose,
        "x|xdebug" => \$opt_debug,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	$opt_dir = $cwd if ( !$opt_dir );
	

	#  Open the Content database
	$dbh = &ConnectServer() or &FatalError("Unable to connect to SQL database\n" );
	LoadCategories();
		
	
	&StdHeader( "BlackWhiteImport" ) if ( ! $opt_wizard );
							
				
	print "Directory $opt_dir\n";


	&ImportBlacklist();
	&ImportWhitelist();
	
	
	&StdFooter if ( ! $opt_wizard );

		
	#  Clean up everything and quit
	$dbh->disconnect if ( $dbh );
		
    exit;
}




################################################################################
#
sub ImportBlacklist()
#
# Import the blacklist
#
################################################################################
{	
	my $filename = &SoftwareDirectory() . "\\SpamBlacklist.txt";
	
	open FILE, "<$filename" or die "Unable to open file $filename: $!\n";
	
	my %blacklist;
	
	while (<FILE>)
		{	next if ( ! $_ );
			my $line = $_;
			chomp( $line );
			
			my ( $type, $value, $air, $domain ) = split /\t/, $line;

			next if ( ! $value );
			
			my $key = $type . "\t" . $value;
			$key = $key . "\t" . $domain if ( $domain );
			$blacklist{ $key } = $type . "\t" . $value;
		}
		
	close FILE;
	
	
	my @keys = sort keys %blacklist;

}



################################################################################
#
sub ImportWhitelist()
#
# Import the whitelist
#
################################################################################
{	

}



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     bprint( @_ );
}



################################################################################
#
sub Usage()
#
################################################################################
{
    my $me = "BlackWhiteImport";

    bprint <<".";
Usage: $me [OPTION(s)] [filename|directory]


This utility imports spam black and white lists in the spam patterns file. 

There are a couple of command line options:

  -d, --directory       set the default directory to work in
  -h, --help            display this help and exit
  -x, --xdebug          show debugging messages
  -v, --verbose         display all the found URLs
-
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
    my $me = "BlackWhiteImport";

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
