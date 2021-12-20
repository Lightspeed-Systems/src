################################################################################
#!perl -w
#
# Rob McCarthy's Keywords Import - import a text file of keywords into the Content Database
# into the Content database
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;

use Getopt::Long;
use Content::File;
use Content::SQL;
use Cwd;



# Options
my $opt_category;                       # Option for categorizing just one category
my $opt_insert;							# True if keywords should be inserted even if they already exist in another category
my $opt_override;						# Category to override - for example, ham overrides spam
my $opt_dir;							# Directory to get stuff from
my $opt_help;
my $opt_version;
my $opt_file;
my $opt_source = 0 + 3;
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_maxcount;						# If set, this is the maximum number of keywords to add
my $opt_keywords_format;				# If True, the input file is in the keywords file format


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
	"f|file=s"		=> \$opt_file,
	"i|insert"		=> \$opt_insert,
	"k|keywords"	=> \$opt_keywords_format,
	"m|maxcount=s"	=> \$opt_maxcount,
	"o|override=s"	=> \$opt_override,
	"s|source=s"	=> \$opt_source,
	"v|version"		=> \$opt_version,
	"w|wizard"		=> \$opt_wizard,
	"h|help"		=> \$opt_help
    );


    &StdHeader( "KeywordsImport" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
	&Version() if ($opt_version);


    #  Make sure the source number is numeric
    $opt_source = 0 + $opt_source;
    &Usage() if ( ( $opt_source )  &&  ( $opt_source < 1 || $opt_source > 2000 ) );
     
	&Usage if ( ! $opt_category );

    $opt_category = lc( $opt_category ) if ( $opt_category );
    $opt_override = lc( $opt_override ) if ( $opt_override );

	$opt_file = shift if ( ! $opt_file );
	&Usage if ( ! $opt_file );
	
	
    #  Open the database
    $dbh = &ConnectServer() or die;

    &LoadCategories();


	# Get the directory to import from
	$opt_dir = getcwd if ( ! $opt_dir );
	$opt_dir = getcwd if ( $opt_dir eq "." );
	$opt_dir =~ s#\/#\\#;  # Flip slashes to backslashes


	my  $category_number = &CategoryNumber( $opt_category );
	die "Unable to find category number for category name $opt_category\n"  if ( $category_number == 0 );

	&ImportCategoryKeywords( $opt_dir, $dbh, $category_number, $opt_source, $opt_insert, $opt_override, $opt_file );

   #  Clean up everything and quit
   $dbh->disconnect;

   &StdFooter if ( ! $opt_wizard );

exit;
}
################################################################################



################################################################################
# 
sub ImportCategoryKeywords( $$$ $$$ $ )
#
#  Given a category number and name, import into the SQL database the 
#  category keywords from the given file
#  
#  Return True if imported ok, undef if a problem
#
################################################################################
{	my $dir				= shift;
	my $dbh				= shift;
	my $category_number = shift;
	
	my $source			= shift;	
	my $opt_insert		= shift;
	my $opt_override	= shift;
	
	my $opt_file		= shift;


	my $category = &CategoryName( $category_number );
	
	my $override_category;
	$override_category = &CategoryNumber( $opt_override ) if ( $opt_override );
	
	
	bprint "Importing category keywords for $category ... \n";
	bprint "Overriding keywords in $opt_override ... \n" if ( $opt_override );


    my $filename = $dir . "\\" . $opt_file;
	$filename = $opt_file if ( $opt_file =~ m/\\/ );
	

    if ( ! open INFILE, "<$filename" )
		{	bprint "Cannot open file $filename: $!\n";
			return( undef );
		}

	my $add_count = 0 + 0;
	my $override_count = 0 + 0;
	
	my $counter = 0 + 0;
	
	while ( <INFILE> )
		{	next if ( ! $_ );
			my $keyword = $_ ;
			chomp( $keyword );
			next if ( !$keyword );               #  Ignore empty lines
			next if $keyword =~ /^\#/;           #  Skip comments
			next if $keyword =~ /^\s*(\#|$)/;
			
			# Clean up whitespaces
			$keyword =~ s/^\s+//;
			$keyword =~ s/\s+$//;
			
			$keyword =~ s/\s+/ /g;
			next if ( ! defined $keyword );
			
			# Am I importing from a Lightspeed keywords file?
			if ( $opt_keywords_format )
				{	my $junk;
					( $keyword, $junk ) = split /\s/, $keyword, 2;
				}
				
			$counter++;
			
			last if ( ( $opt_maxcount )  &&  ( $counter > $opt_maxcount ) );
			
			print "$keyword\n";
			
			my ( $existing_source, $existing_category ) = &KeywordLookup( $keyword );
			
			
			# if it doesn't exist at all, just add it
			if ( ! $existing_source )
				{	my $ret = &KeywordAdd( $keyword, $source, $category_number );
					
					$add_count++ if ( $ret );
					next;
				}
				
			if ( $opt_override )
				{	# Is it my category or the override category?
					next if ( ( $existing_category != $category_number )  &&
							( $existing_category != $override_category ) );
					
					# Is the existing source lower than my source?
					next if ( $existing_source < $source );
					
					my $ret = &KeywordUpdate( $keyword, $source, $category_number );
					
					$override_count++ if ( $ret );
					
					next;
				}
				
			if ( $opt_insert )
				{	# Is the existing source lower than my source?
					next if ( $existing_source < $source );
					
					my $ret = &KeywordUpdate( $keyword, $source, $category_number );
					
					$override_count++ if ( $ret );
				}
		}
	
	close INFILE;
	
	bprint "Added $add_count new keywords\n" if ( $add_count );
	bprint "Overrode $override_count existing keywords\n" if ( $override_count );
	
	return( 1 );	
}



################################################################################
# 
sub KeywordLookup( $ )
#
#  Given a keyword, look it up in the database.  Return undef if not found
#
################################################################################
{	my $keyword = shift;
	
	my $sth = $dbh->prepare( "SELECT SourceNumber, CategoryNumber FROM CategoryKeywords where Keyword = ?" );
	$sth->bind_param( 1, $keyword,  DBI::SQL_VARCHAR );
	$sth->execute();
	my ( $source, $category ) = $sth->fetchrow_array();
	$sth->finish();
	
	return( $source, $category );
}



################################################################################
# 
sub KeywordAdd( $$$ )
#
#  Given a keyword, add it to the database.  Return undef if an error happens
#
################################################################################
{	my $keyword		= shift;
	my $source		= shift;
	my $category	= shift;
	
	my $quoted_keyword = &quoteurl( $keyword );
	
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $str = "INSERT INTO CategoryKeywords ( Keyword, CategoryNumber, SourceNumber ) VALUES ( \'$quoted_keyword\', \'$category\', \'$source\' )";
	my $sth = $dbh->prepare( $str );
	return( undef ) if ( ! $sth->execute() );
	
	&SqlErrorHandler( $dbh );
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub KeywordUpdate( $$$ )
#
#  Given a keyword, update the database.  Return undef if an error happens
#
################################################################################
{	my $keyword		= shift;
	my $source		= shift;
	my $category	= shift;
	
	my $quoted_keyword = &quoteurl( $keyword );

	# Delete the existing keyword
	$dbh = &SqlErrorCheckHandle( $dbh );
	my $str = "DELETE CategoryKeywords WHERE Keyword = \'$quoted_keyword\'";
	my $sth = $dbh->prepare( $str );
	return( undef ) if ( ! $sth->execute() );

	
	my $ret = &KeywordAdd( $keyword, $source, $category );
	
	return( $ret );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "KeywordsImport";

    bprint <<".";
Usage: $me -c category [OPTION(s)] keywords-file

Imports keywords into the Content database

  -c, --category=name    category to add the domains and urls to
  -d, --directory=PATH   to change default files directory
  -h, --help             display this help and exit
  -i, --insert           insert new keywords, over writing any existing
  -o, --override=name    override a specific category - i.e. porn overrides adult
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
    my $me = "KeywordsImport";

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
