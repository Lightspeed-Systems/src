################################################################################
#!perl -w
#
# Rob McCarthy's Sql Import - import squid guard formatted domains and URLs
# into the Content database
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long;



use Content::File;
use Content::SQL;
use Content::FileUtil;
use Content::Category;



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
my $opt_debug;




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
	"c|category=s"	=> \$opt_category,
	"d|directory=s" => \$opt_dir,
	"e|existing"	=> \$opt_existing,
	"i|insert"		=> \$opt_insert,
	"m|move"		=> \$opt_move,
	"o|override=s"	=> \$opt_override,
	"r|reason=s"	=> \$opt_reason,
	"s|source=i"	=> \$opt_source,
	"v|version"		=> \$opt_version,
	"w|wizard"		=> \$opt_wizard,
	"x|xxx"			=> \$opt_debug,
	"h|help"		=> \$opt_help
    );


    &StdHeader( "SqlImport" ) if ( ! $opt_wizard );

    &Usage()	if ($opt_help);
	&Usage()	if ( $opt_move && ! $opt_category );
	&Version()	if ($opt_version);


    #  Make sure the source number is numeric
    $opt_source = 0 + $opt_source;
    &Usage() if ( ( $opt_source )  &&  ( $opt_source < 1 || $opt_source > 2000 ) );
    
	# Make absolutely sure that an import of source 1 is what they really mean
	if ( $opt_source == 1 )
		{	my $answer = &AnswerYorN( "Are you sure you really want to use source 1?" );
			if ( ( ! $answer )  ||  ( $answer ne "Y" ) )
				{	bprint( "\nDone\n" );
					exit( 0 );	
				}
		}
		
    $opt_category = lc( $opt_category ) if ( $opt_category );
    $opt_override = lc( $opt_override ) if ( $opt_override );

	my $existing = "existing.urls" if ( $opt_existing );
	
    bprint( "Overriding existing domains and urls in category $opt_override\n" ) if ( $opt_override );
    bprint( "Moving existing domains and urls to category $opt_category\n" ) if ( $opt_move );


    #  Open the database
    $dbh = &ConnectServer() or die;

    &LoadCategories();

	my $dbhCategory = &CategoryConnect();
	bprint( "Connected to the Category database\n" ) if ( $dbhCategory );
	

	# Get the directory to import from
	$opt_dir = getcwd if ( ! $opt_dir );
	$opt_dir = getcwd if ( $opt_dir eq "." );
	$opt_dir =~ s#\/#\\#g;  # Flip slashes to backslashes


	#  Am I importing a single category?
	if ( $opt_category )
		{	my  $category_number = &CategoryNumber( $opt_category );
			die "Unable to find category number for category name $opt_category\n"  if ( ! $category_number );

			&ImportCategoryFiles( $opt_dir, $dbh, $category_number, $opt_category, $opt_source, $opt_insert, $opt_override, $opt_move, $existing, $opt_reason );
		}
	else
		{	# Import the categories in category order - useful for importing from the DMOZ database
			my $top = &TopCategoryNumber();

			my @categories;
			
			for ( my $category_number = 1;  $category_number <= $top;  $category_number++ )
				{	my $category = &CategoryName( $category_number );
					next if ( ! defined $category );
					
					push @categories, $category;
				}
				
			my @sorted_categories = &CategorySorted( @categories );
			
			# Now that I have everything sorted in the high priority order, import it
			foreach ( @sorted_categories )
				{	next if ( ! defined $_ );
					my $category = $_;
					
					my $category_number = &CategoryNumber( $category );
					&ImportCategoryFiles( $opt_dir, $dbh, $category_number, $category, $opt_source, $opt_insert, $opt_override, $opt_move, $existing, $opt_reason );
				}
		}


	#  Clean up everything and quit
	$dbh->disconnect;
	&CategoryClose();
	
	&StdFooter if ( ! $opt_wizard );

exit;
}
################################################################################



################################################################################
# 
sub CategorySorted( @ )
#
#  Given a list of category names return it sorted in order
#
################################################################################
{	my @cat_list = @_;
		
	my @sorted = sort CategorySort( @cat_list );

	# Return the highest ranked category 
	return( @sorted );
}



################################################################################
# 
sub CategorySort( $$ )
#
#  Comparing 2 categories - return the perl cmp value
#
################################################################################
{	my $cat1 = shift;
	my $cat2 = shift;
	
	return( 0 ) if ( $cat1 eq $cat2 );
	
	my $top = &TopCategory( $cat1, $cat2 );
	
	return( -1 ) if ( $top eq $cat1 );
	
	return( 1 );
}



################################################################################
#
sub AnswerYorN( $ )
#
# Ask a question and return Y or N in response
#
################################################################################
{	my $question = shift;
	
    print "$question [ Y or N ] ";

	my $done;
	while ( !$done )
		{	my $line = <STDIN>;
			chomp( $line );
            return( "N" ) if ( uc( $line ) eq "N" );
            return( "Y" ) if ( uc( $line ) eq "Y" );
		}
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "SqlImport";

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
    my $me = "SqlImport";

    bprint <<".";
Usage: $me [OPTION(s)]
Imports domains and urls in Squidguard format into the Content database

  -c, --category=name    category to add the domains and urls to
  -d, --directory=PATH   to change default files directory
  -e, --existing         to write out existing domains and urls to the
                         file \'existing.urls\'  
  -h, --help             display this help and exit
  -i, --insert           insert urls, overriding existing urls with the same
                         or higher source number.
  -m, --move             move existing unblocked domains and urls to the 
                         given category
  -o, --override=name    override category - i.e. ham overrides spam
  -r, --reason=\"REASON\"  Add REASON to the Category database
  -s, --source           source number to use on insert, default is 4
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
