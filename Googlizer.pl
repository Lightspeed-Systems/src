################################################################################
#!perl
#
#
#  Rob McCarthy's Googlizer source
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;


use Getopt::Long;
use GoogleSearch;

use DBI qw(:sql_types);
use DBD::ODBC;
use Content::File;
use Content::SQL;



# Options & Defaults
my $def_keyfile = "keywords";

my $opt_max_results = 10;
my $opt_keyword_count = 10;
my $opt_outfile = "googlizer.urls";
my $opt_string;
my $opt_version;
my $opt_help;
my $opt_keywords = 0.0;			# This is non-zero of all we want to do is show what search keywords we would use, without actually doing the search
my $opt_anchor;					# If we want to anchor all of our searches with a word
my $opt_restart = 0.0;			# If restarting a search, this the the search string number to start from
my $opt_category;				# Category to use keywords for
my $dbh;						# The global database handle
my $opt_wizard;					# True if I shouldn't display headers or footers


# Globals
my $spinner = 0;
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
        "c|category=s"		=> \$opt_category,
		"n|number=i"		=> \$opt_keyword_count,
        "m|maxresults=i"	=> \$opt_max_results,
        "o|output=s"		=> \$opt_outfile,
        "s|string=s"		=> \$opt_string,
        "k|keywords"		=> \$opt_keywords,
        "a|anchor=s"		=> \$opt_anchor,
        "r|restart=s"		=> \$opt_restart,
        "v|version"			=> \$opt_version,
        "h|help"			=> \$opt_help
    );


    &StdHeader( "Googlizer" ) if ( ! $opt_wizard );
	
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);

	while ( my $opt = shift )
		{	$opt_string .= " " . $opt if ( defined $opt_string );
			$opt_string = $opt if ( ! defined $opt_string );
		}
		
	print "Searching Google for $opt_string\n" if ( $opt_string );

	if ( ( ! $opt_category )  &&  ( ! $opt_string ) )
		{	print "You have to specify the category to use keywords for.\n";
			exit;
		}
		
		
	#  Open the database and load all the arrays
	print "Opening a connection to the local SQL database ...\n";
	$dbh = &ConnectServer();
	&LoadCategories();


	my $google_key;
	
	if ( open( KEY, "<c:\\perl\\site\\lib\\googlekey.txt" ) )
		{	print "Found googlekey.txt at c:\\perl\\site\\lib\\googlekey.txt\n";
			$google_key = <KEY>;
			chomp( $google_key );
			close KEY;
		}

	elsif ( open( KEY, "<googlekey.txt" ) )
		{	print "Found googlekey.txt in the current directory\n";
			
			$google_key = <KEY>;
			chomp( $google_key );
			close KEY;
		}
	
	else
		{	print "Using the default googlekey\n";
			$google_key = "/fhrQ/RQFHKDpBBtzkJhvOjWrB3jFwyr";
		}
		
		
    # Initialize Google
    my $google = new GoogleSearch( $google_key );


     # Open the output file
     my $OUTFILE;
     if ( ! $opt_keywords )
       {	print "Writing results to $opt_outfile ...\n";
			open $OUTFILE, ">>$opt_outfile" or die "Cannot open outfile \"$opt_outfile\"\n  $!";
       } 
   
     
    # Search using a specified search string
    if ( $opt_string )
		{
			# Do the search
			my $search_string = $opt_string;

			if ( defined $opt_anchor )
				{	$search_string = $opt_string . " " . $opt_anchor;
				}

			print "Search Text: \"$search_string\"\n";
			
			my $results = &Search( $google, $search_string, $OUTFILE );

			print "Total Results: $results\n";
		}

    # Search using the command line phrase
    else
		{
			# Load the keyfile into a hash by frequency
			my $keyfile = &KeywordsDirectory() . "\\$opt_category.keywords";
			
			open KEYFILE, "<$keyfile" or die "Cannot open keywords file \"$keyfile\"\n  $!";

			my %top_keys;

			while (<KEYFILE>)
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					my ( $token, $rating, $freq, $good, $bad ) = split /\s/, $line;
					$top_keys{$token} = 0 + $freq;
				}

			close KEYFILE;


			# Get the interesting items
			my $top_keys_count = scalar keys %top_keys;
			my $keys_count = $opt_keyword_count;

			$keys_count = $top_keys_count if ( $keys_count > $top_keys_count) ;

			my @interesting = ( sort { $top_keys{$b} <=> $top_keys{$a} } keys %top_keys)[0..$keys_count - 1];

			# Search for the interesting items
			my $counter = 0;
			foreach ( @interesting )
				{   $counter += 1;

					if ( $counter < $opt_restart )
						{   print "Skipping Search Test #$counter: $_\n"; 
							next;
						}

					my $search_string = $_;

					if ( defined $opt_anchor )
						{  $search_string = $_ . " " . $opt_anchor;
						}

					print "Search Text #$counter: \"$search_string\"\n";

					# Do the search
					if ( !$opt_keywords )
						{  
							my $result_count = &Search( $google, $search_string, $OUTFILE );     
							print "  $result_count hits         \n";
						}
				}

			if ( !$opt_keywords )
				{  close $OUTFILE;
				}
		}


	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );
	&StdFooter if ( ! $opt_wizard );
	
	exit;
}




################################################################################
#
sub Search ($$$)
#
################################################################################
{
    # Get parameters
    my ( $google, $search_text, $OUTFILE ) = @_;


    # Loop through and get all the reuslts
    my $start = 0;
    my @results;
    my $result_count = 0;
    my $total_results = 0;

    do
    {
        # Get the next results
        @results = &NextSearch($google, $search_text, $start);


        # Dump the results to the output file
		foreach ( @results )
			{	next if ( ! $_ );
				
				my $url = &CleanUrl( $_ );
				
				next if ( ! $url );
				
				my $root = &RootDomain( $url );
				$root = &TrimWWW( $root );
				
				print $OUTFILE "$root\n";
				print $OUTFILE "$url\n" if ( $url ne $root );
			}
        
        $result_count = @results;
        $total_results += $result_count;

        $start += 10;


        # Spin it
        &Spin("  $total_results hits");

    } while ($result_count >= 10 && $total_results < $opt_max_results);

    return $total_results;
}




################################################################################
#
sub NextSearch ($$$)
#
################################################################################
{
    #
    # ** NOTE:  If we print anything here, start it with a "\n" so that it wont 
    # overwrite the last Spin( ) line, since it prints with a "\r".
    #

    # Get parameters
    my ($google, $search_text, $start) = @_;
    if ( ! $google )
	{	print "No google object\n";
		return;
	}

    # Do the search
    my $return = $google->doGoogleSearch
    (
          query => $search_text,
          start => $start,
          maxResults => 10
    )->result();


    if ( ! $return->{'resultElements'} )
      {  print "No results from last search\n";
	 return;
      }


    # Display the results
    my @results;
    my $hit_count = scalar @{ $return->{'resultElements'} };

    if ( ( $hit_count )  &&  ( $return->{'resultElements'} ) )
    {
        print "\nComments: $return->{searchComments}\n" if (length($return->{searchComments}));

        foreach my $entry (@{$return->{'resultElements'}}) 
        {
            push @results, $entry->{URL};
        }
    }


    return @results;
}




################################################################################
#
sub Spin ($)
#
################################################################################
{
    my @chars = ('|', '/', '-', '\\');

    print "$_[0] " if (@_);

    print $chars[$spinner++], "\r";
    $spinner == 4 and $spinner = 0;
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
Usage: $me [OPTION]... KEYWORDS-FILE
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
Usage: $me [OPTION(s)] [search string]
Uses Google to search for the most relevant website for a category
You can specify a search string on the command line, or use
the top keywords in a Content Filter category with the -c option.

  -a, --anchor=word       anchor word to use in every search
  -c, --category=CATNAME  name of the category to use keywords from
  -k, --keywords          just display the top keywords without doing a search
  -n, --number=NUM        number of top keywords to search, default = 10
  -m, --maxresults=NUM    maximum number of results, default = 10
  -o, --output=FILE       output file, default=googlizer.urls
  -r, --restart=NUM       keyword number to start from after restarting a search
  -s, --string=STRING     do google search with STRING instead of top keywords
  -h, --help              display this help and exit
  -v, --version           display version information and exit
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
