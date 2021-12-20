@rem = '--*-Perl-*--
@echo off
if "%OS%" == "Windows_NT" goto WinNT
perl -x -S -T "%0" %1 %2 %3 %4 %5 %6 %7 %8 %9
goto endofperl
:WinNT
perl -x -S -T %0 %*
if NOT "%COMSPEC%" == "%SystemRoot%\system32\cmd.exe" goto endofperl
if %errorlevel% == 9009 echo You do not have Perl in your PATH.
if errorlevel 1 goto script_failed_so_exit_with_non_zero_val 2>nul
goto endofperl
@rem ';

################################################################################
#!perl -w
use strict;


use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Content::File;
use Content::SQL;



# Validate and get the parameters
my $opt_root_dir;
my $opt_show_most_interesting = 1.0;         # Show the most interesting picks
my $opt_sensitivity = 0 + 30;                       # Keyword sensitivity - from 0 to 100, 30 is the default
my $opt_most_interesting_min = 0 + 10;       # Minimum required most interesting
my $opt_most_interesting_max = 0 + 25;      # Maximum allowed most interesting
my $opt_unknown_rating = 0 + 0.49;           # Rating for tokens which were not found
my $opt_hit_threshold = 0 + 0.80;	       # What percentage sure that it's a hit
my $opt_recategorize;                                # True if it should recategorize urls If the url alreadys exists in the database and wasn't set by hand
my $opt_wizard;		# True if I shouldn't display headers or footers



my $pure_hit = 0 + 0.99;		       # Probability of a token that only occurs in a hit file
my $pure_miss =  0 + 0.01;	                     # Probability of a token that only occurs in a miss file
my $tokens_file = "keywords";
my $opt_help;                                            # Show help text
my $opt_version;                                        # Show version info
my $opt_directory;
my $opt_category;
my $_version = "1.0.0";
my @url_tokens;
my %token_hit_rating;
my  $dbh;             #  My database handle



################################################################################
#
#    Main section
#
################################################################################
{

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "c|category=s" => \$opt_category,
        "s|sensitivity=s" =>\$opt_sensitivity,
 	"w|wizard" => \$opt_wizard,
       "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


	&StdHeader( "IpmGradeURL", "TableCGIHeader.html" ) if ( ! $opt_wizard );

	&Usage() if ( $opt_help );
   &Version() if ( $opt_version) ;
   &Usage if ( !defined $ARGV[0] );
   &Usage if ( !$opt_category );

   my $url = shift;

   #  Is this a valid url at all?
   my $cleanurl = &CleanUrl( $url );
   if ( !$cleanurl )
     {   &FatalError( "Illegal url = $url" );
     }


   $dbh = &ConnectServer() or die;
   LoadCategories();

   $opt_root_dir = &KeywordsDirectory() if ( !$opt_root_dir );

   my $retval = &LoadCategoryKeywords( $opt_category );


    bprint "Currently categorized in database as ... \n";
    &SqlQuery( $url );
    bprint "\n";


    #  Do any URL expression or phrase processing
    &LoadExpressions();

    my $category = &ProcessExpressions( $url );

    if ( $category eq "general" )
      {
          $category = &CategorizeByUrlName( $url );

          if ( $category )
            {  bprint( "Categorized the URL by phrase to category $category\n" );
            }
       }


   bprint( "\n" );

   $retval = &TokenizeUrl( $url, \@url_tokens ) if ( $retval == 0 );  #  If there was an error reading the URL, record that


   &AnalyzeTokens() if ( $retval == 0 );

   bprint "\n\n";

   &StdFooter( "TableCGIFooter.html" ) if ( ! $opt_wizard );


exit;
}  #  End of the main



################################################################################
# 
sub SqlQuery( $ )
#
#  Given a url, print out everything about it
#
################################################################################
{   my $url = shift;

     my  ( $domain, $url_ext ) = split /\//, $url, 2;


     my  $lookupType = &LookupUnknown( $url, 0 );
     if ( !$lookupType )
       {   bprint "Unknown url $url\n";
       }
     else 
       {  my ( $category_number, $source_number ) = &FindCategory( $url, $lookupType );
          my $category_name = &CategoryName( $category_number );

          my $blocked = "FALSE";
          $blocked = "TRUE" if ( &BlockedCategory( $category_name ) );

          if ( ( $lookupType == 2 )  ||  ( $lookupType == 5 ) )
             {  bprint "URL: $url, Category $category_number - $category_name, Blocked = $blocked\n";
             }
          elsif ( ( $lookupType == 3 )  ||  ( $lookupType == 6 ) )
             {   bprint "IP Address: $domain, Category $category_number - $category_name, Blocked = $blocked\n";
             }
          else
            {   
                bprint "Domain: $domain, Category $category_number - $category_name, Blocked = $blocked\n";  
            }

          if ( $source_number )                
            {   my $source_name = &SourceName( $source_number );
                bprint "Source # $source_number, $source_name\n"; 
            }
       }
}


################################################################################
#
sub tprint( @ )
#
#  Print a 4 column table - optional 5th parameter is a background color
#
################################################################################
{
 
    if ( !&IsCGI() )
      {
           my $str = sprintf "%10s %20s %15s %15s", $_[ 0 ], $_[ 1 ], $_[ 2 ], $_[ 3 ];
           print "$str\n";
           return;
       }

    if ( $_[ 4 ] )  {  print   "<tr bgcolor=\"$_[ 4 ]\">\n";  }
    else  {  print "<tr>\n";  }
 
    exit if ( !print "<td align=center width=10%>$_[ 0 ]</td>\n" );   
    exit if ( !print "<td align=right width=30%>$_[ 1 ]</td>\n" );   
    exit if ( !print "<td align=right width=20%>$_[ 2 ]</td>\n" );   
    exit if ( !print "<td align=right width=20%>$_[ 3 ]</td>\n</tr>\n" );

    exit if ( !print "</tr>\n" );   
}



################################################################################
#
sub AnalyzeTokens ()
#
################################################################################
{

     # Pull out the type of tokens that we care about
     my @web_tokens;

     foreach( @url_tokens ) 
        {
            # Length restriction
            my $length = length( $_ );
            next if ($length < 3 || $length > 40);

             # Ignore all-digit tokens
             next if (/^[0-9.]+$/);

             push @web_tokens, $_;
        }


    # Rate each token according to how far from 0.5 it is
    my %web_token_hit_rating;
    my %interesting_tokens;
   

    foreach ( @web_tokens )
      {
          next if ( !length $_ );

          my $token = lc;
          my $rating = $opt_unknown_rating;

          if ( $token_hit_rating{ $token } )
            {  $rating = $token_hit_rating{ $token };
            }
		
         $web_token_hit_rating{ $token } = $rating;
         $interesting_tokens{ $token } = abs(0.5 - $rating);
      }

    
    # Show Information
    my $interesting_tokens_count = scalar keys %interesting_tokens;


    # Get number of interesting tokens
    my $most_interesting_count = $interesting_tokens_count > $opt_most_interesting_max ?
        $opt_most_interesting_max : $interesting_tokens_count;

    if ($most_interesting_count >= $opt_most_interesting_min)
    {
        # Get the most interesting tokens, which are sorted by decreasing order of interest
        my @most_interesting = (sort { $interesting_tokens{ $b } <=> $interesting_tokens{ $a } } 
            keys %interesting_tokens)[0..$most_interesting_count - 1];


        # Calculate the Bayes probability
        my $prod = 1;
        my $one_minus_prod = 1;

        foreach ( @most_interesting )
        {
	        next if ( !defined $_ );
	        next if ( !defined $web_token_hit_rating{$_} );

	        $prod *= $web_token_hit_rating{$_};
	        $one_minus_prod *= (1.0 - $web_token_hit_rating{$_});
        }


        my $probability_of_hit = 0;
        $probability_of_hit = $prod / ($prod + $one_minus_prod)
	        if (($prod + $one_minus_prod) > 0);

        # Display the results
        my $str = sprintf "Grade %s\n", $probability_of_hit > $opt_hit_threshold ? "HIT" : "MISS";

        if ( $probability_of_hit > $opt_hit_threshold )
          {  bprint "HIT - matches category\n\n";  }
        else  {  bprint "MISS - does not match category\n\n";  }

        $str = sprintf  "Probability  %2.10f\n", $probability_of_hit;
        bprint "$str";
        bprint "Total Web Tokens (Not Unique): ", scalar @web_tokens, "\n";
        bprint "Interesting Tokens: ", $interesting_tokens_count, "\n";
        bprint "\n";

        # Show the most interesting tokens
        if ($opt_show_most_interesting)
          {  bprint "Most Interesting Tokens\n";

             print "<table border=0 bordercolor=\"#dddddd\" cellspacing=0>\n" if ( &IsCGI() );

             tprint( "Token #", "Keyword", "Value", "Interest", "#eeeeee" );

             my $token_count = 0;

             foreach ( @most_interesting )
              {
                 my $str1 = $token_count + 1;
                 my $str2 = sprintf "%2.4f", $web_token_hit_rating{$_};
                 my $str3 = sprintf "%2.4f", $interesting_tokens{ $_ };
                 tprint( $str1, $_, $str2, $str3 );
                ++$token_count;
              }

            print "</table>\n" if ( &IsCGI() );
         }

    }

    else
    {
        # Display the results
        bprint "NOT ENOUGH KEYWORDS\n";
    }

}



################################################################################
#
sub TokenizeUrl ($\@)
#
################################################################################
{
    # Get the parameters
    my ( $url, $tokens ) = @_;


    # Request the page
    my $url_string = URI::Heuristic::uf_urlstr($url);

    bprint "URL: $url_string\n";

    $| = 1;

    my $ua = LWP::UserAgent->new();
    $ua->agent("Schmozilla/v9.14 Platinum");

    my $req = HTTP::Request->new(GET => $url_string);
    $req->referer("http://wizard.yellowbrick.oz");

    $ua->max_size( 100000 );
    $ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

    # Get the response
    my $response = $ua->request( $req );

    if ($response->is_error())
    {
        bprint "Request Error: ", $response->status_line, "\n";
        my ( $retval, $str ) = split /\s/, $response->status_line, 2;

        return $retval;  #  Return an error code
    }

    if ( $response->content =~ m/Lightspeed Systems Content Filtering/ )
     {  bprint ( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
        return( -1 );
     } 

    # Split the reponse into tokens
    @$tokens = split /[^a-zA-Z\d'$-]+/, $response->content;

    return( 0 );
}



################################################################################
#
sub LoadCategoryKeywords( $ )
#
#  Given a category name, load up the keywords into memory
#
################################################################################
{   my  $new_factor;
 
    # Get the parameters
    my ( $catname ) = shift;

    #  Watch for undefined names - category 0 for instance
    return  if ( !$catname );

    # Load the keyword tokens
    my $keywords_file = $opt_root_dir . '\\' . $catname . '.keywords';

    if ( !open TOKENS, "<$keywords_file" )
      {   bprint "ERROR\n";
          bprint "Unable to read category keywords file\n";
          bprint "Filename: $keywords_file\n";
          return( -1 );
       }

    $new_factor = 2 - ( 1.5 * ( $opt_sensitivity / 100 ) ) if ( $opt_sensitivity );

    my  $count = 0;
    while (my $line = <TOKENS>)
       {  my ( $token, $rating, $freq ) = split / /, $line;
          next  if ( !$token );  #  Watch out for blank lines
          next  if ( !$rating );

          #  Modify the rating based on the opt_sensitivity
          if ( ( $opt_sensitivity )  &&  ( $rating < 1.0 ) )  #  Don't modify 1.0 ratings - which had to be set by hand
            {  my  $g = ( 1 / ( 2 * $rating ) ) - 0.5;
               my  $new_rating = 1 / ( 1 + ( $new_factor * $g ) );  

               #  Check for rationality
               $new_rating = 0.01 if ( $new_rating < 0.01 );
               $new_rating = 0.99 if ( $new_rating > 0.99 );
               $rating = $new_rating;
            }

          $token_hit_rating{ $token } = $rating;
          $count++;
       }

   bprint "Category: $catname\n";
   bprint "Number of keywords in category: $count\n\n";

   close TOKENS;

   return( 0 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmGradeURL";

    bprint <<".";
Usage: $me [OPTION(s)]  URL
Grade a URL against a category to see if it is a HIT or a MISS

  -c, --category=name    category to grade the URL against
  -s, --sensitivity      keyword sensitivity, 0 default, 100 most aggressive
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
    my $me = "IpmGradeURL";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}

################################################################################

exit;
################################################################################

__END__

:endofperl
