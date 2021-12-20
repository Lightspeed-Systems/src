@rem = '--*-Perl-*--
@echo off
if "%OS%" == "Windows_NT" goto WinNT
perl -x -S "%0" %1 %2 %3 %4 %5 %6 %7 %8 %9
goto endofperl
:WinNT
perl -x -S %0 %*
if NOT "%COMSPEC%" == "%SystemRoot%\system32\cmd.exe" goto endofperl
if %errorlevel% == 9009 echo You do not have Perl in your PATH.
if errorlevel 1 goto script_failed_so_exit_with_non_zero_val 2>nul
goto endofperl
@rem ';

################################################################################
#!perl -w
#
# Rob McCarthy's version of grading spam perl - IpmSpamGrade
#
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;


use Getopt::Long;
use Content::File;
use MIME::Base64;



# Validate and get the parameters
my $_version = "2.0.0";
my $min_frequency = 0 + 20;          		# Number of times a token needs to be used before it is considered significant
my $expected_good_to_bad = 0 + 1.15;           	# This is the ratio of the expected number of non spams to spams in a normal day of email

my $opt_version;
my $opt_help;
my $opt_filename;                                     # If defined, the corpus file to use for spam tokens
my $opt_dir;                                             #  Directory of the Spam Tokens file
my $opt_sensitivity;                                   #  If not set, the expected good to bad ratio will be used
my $opt_summary;                                    # If set, just show the summary of the ham and spam
my $opt_show_most_interesting;                # Show the most interesting picks
my $opt_most_interesting_min = 0 + 10;     # Minimum required most interesting
my $opt_most_interesting_max = 0 + 50;    # Maximum allowed most interesting
my $opt_mindev = 0 + 0.1;                        # The minimum deviation from 0.5 to make the token interesting enough
my $opt_unknown_token = 0 + 0.41;          # The value to use for a completely unknown token
my $opt_spam_threshold = 0 + 0.80;	      # What percentage sure that it's spam
my $pure_spam;			      # Probability of a token that only occurs in a spam file
my $pure_notspam;	        	      # Probability of a token that only occurs in a non spam file
my $corpus_file;                                       # The full file name of the corpus file I used
my $opt_offset = 0 + 0.1;                           # The offset from 1 and 0 for pure spam and pure not spam
my $opt_pw;
my $opt_copy; 			      # If set to a directory name, copy spam to that directory
my $opt_nopipe;				#  This is just used so that IpmRealtimeSpam has the same command line args
my $opt_wizard;



my %token_spam_rating;
my %nonspam_occurrences;
my %spam_occurrences;



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
        "a|aggressive=s" =>\$opt_sensitivity,
        "c|copy=s" =>\$opt_copy,
        "d|directory=s" =>\$opt_dir,
        "f|filename=s" =>\$opt_filename,
        "i|interest=s" =>\$opt_most_interesting_max,
        "m|minimum=s" =>\$min_frequency,
        "n|nopipe" =>\$opt_nopipe,
        "o|offset=s" =>\$opt_offset,
        "p|pweight" =>\$opt_pw,
        "r|ratio=s" =>\$expected_good_to_bad,
        "s|summary" =>\$opt_summary,
        "t|tokens" =>\$opt_show_most_interesting,
 	"w|wizard" => \$opt_wizard,
       "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &StdHeader( "IpmGradeSpam" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    if ( $opt_sensitivity )
      {   &Usage() if ( $opt_sensitivity < 0  ||  $opt_sensitivity > 100 );
      }

    &Usage() if ( $expected_good_to_bad < 0.75  ||  $expected_good_to_bad > 1.55 );
    &Usage() if ( $opt_spam_threshold < 0.01  ||  $opt_spam_threshold > 0.99 );
    &Usage() if ( $opt_most_interesting_min < 5  ||  $opt_most_interesting_min > 25 );
    &Usage() if ( $opt_most_interesting_max < $opt_most_interesting_min  ||  $opt_most_interesting_max > 1000 );

    if ( $opt_copy )
      {
           &FatalError( "The copy directory $opt_copy is not valid\n" ) if ( !-d $opt_copy )
      }


    #  Calculate the pure spam and pure not spam values
    if ( $opt_offset )
      {
           &Usage() if ( $opt_offset < 0.01  ||  $opt_offset > 0.49 );
           $pure_spam = 1 - $opt_offset;
           $pure_notspam = $opt_offset;
      }


    #  If calculate the opt_sensitivity if not already set
    if ( !$opt_sensitivity )
      {   $opt_sensitivity = 100 * ( ( 1.55 - $expected_good_to_bad ) / .8 );
      }
    else  #  If the sensitivity was set, calc the expected good to bad ratio
      {  $expected_good_to_bad = .75 + ( ( ( 100 - $opt_sensitivity ) * .8 ) / 100 );
      }


    #  Figure out what directory to use
    $opt_dir = &SoftwareDirectory() if ( !$opt_dir );


    &LoadSpamTokens();


    bprint "Grading email files for spam ... \n";
    # Loop through the remaining parameters, which should all be files to scan
    my $item;
    my $file_counter = 0;
    my $spam_counter = 0;
    foreach $item (@ARGV)
      {
           # Handle wildcards
           if ($item =~ /\*/ || $item =~ /\?/)
             {
                 # Loop through the globbed names
                 my @glob_names = glob $item;

                foreach (@glob_names)
                  {   $file_counter++;
                      $spam_counter += &AnalyzeFile($_);
                 }
            }  #  end of handle wild cards

         # Handle single entities
        else
          {
               # Analyze a directory
               if (-d $item)
                 {
                     # Process the directory
                    opendir DIR, $item;

                    while (my $file = readdir(DIR))
                       {
                           # Skip subdirectories
                           next if (-d $file);

                           $file_counter++;
                           $spam_counter += &AnalyzeFile("$item\\$file");
                      }

                 closedir DIR;
              }

           # Analyze a single file
          else
             {    $file_counter++;
                  $spam_counter += &AnalyzeFile( $item );
             }
       }
   }  #  end of foreach item


    bprint "Parameter values: \n";
    bprint "Minimum Frequency = $min_frequency\n";
    bprint "Agressive scale = $opt_sensitivity\n";
    bprint "Expected Ratio = $expected_good_to_bad\n";
    bprint "Pure spam rating = $pure_spam\n";
    bprint "Pure ham rating = $pure_notspam\n";
    bprint "Spam Level = $opt_spam_threshold\n";
    bprint "Spam Tokens files = $corpus_file\n";
    bprint "Spam Tokens Loaded: ", scalar keys %token_spam_rating, "\n";

    &DumpPw() if ( $opt_pw );

    my $ham_total = $file_counter - $spam_counter;

    bprint( "Final results - $file_counter files, $spam_counter spam, $ham_total not spam\n" );
 
    &StdFooter if ( ! $opt_wizard );

    exit;
}



################################################################################
#
sub LoadSpamTokens()
#
#  Load the spam tokens file, transforming the weight by the given parameters
#
################################################################################
{

    bprint "Loading in the Spam Tokens file ... \n";

    my $nonspam_files = 0 + 0;
    my $spam_files = 0 + 0;


    # Load the spam tokens
    if ( $opt_filename )
       {   $corpus_file = $opt_filename;
           open TOKENS, "<$corpus_file" or &FatalError( "Cannot open $corpus_file\n  $!" );
       }
    else  #  Try to open localtokens.txt - if you can't, open spamtokens.txt
       {   $corpus_file = $opt_dir . "\\localtokens.txt";

           if ( !open TOKENS, "<$corpus_file" )
             {   $corpus_file = $opt_dir . "\\spamtokens.txt";
                  open TOKENS, "<$corpus_file" or &FatalError( "Cannot open $corpus_file\n  $!" );             
             }
       }


    while ( <TOKENS> )
       {      chomp;
	my ( $token, $weight, $good, $bad ) = split;

	next if ( !$token );

               #  Is this token used enough?
               my $frequency = $bad + $good;
               next if ( $frequency < $min_frequency );

	$token_spam_rating{ $token } = 0 + $weight;
	$spam_occurrences{ $token } = 0 + $bad;
	$nonspam_occurrences{ $token } = 0 + $good;

              #  Is this my "the" token that holds the count of spam and nonspam files?
              next if ( $token ne "the" );
 
              $spam_files = 0 + $bad;
              $nonspam_files = 0 + $good;
       }

    close TOKENS;


    #  Modify the weight based on command line options    
    my  $badlist_messagecount = $spam_files;
    my  $goodlist_messagecount = $nonspam_files;
    foreach ( keys %token_spam_rating )
       {      next if ( !$_ );

              my  $token = $_;
          
              #  Use the same variable names as Paul Graham
              my  $goodcount = 0 + 0;
    	my  $badcount =  0 + 0;

              if ( defined( $nonspam_occurrences{ $token } ) )
  	  {  $goodcount = $nonspam_occurrences{ $token };  }

             if ( defined ( $spam_occurrences{ $token } ) )
	  {  $badcount = $spam_occurrences{ $token }; }

              #  Is this token used enough to keep?
              my $total = $goodcount + $badcount;
              next if ( $total < $min_frequency );

	# Normalize the goodvalue to account for the sample size and factor in the fudge amount
	my $goodnorm =  $expected_good_to_bad * ( ( $goodcount * $badlist_messagecount ) / $goodlist_messagecount );

	#  Calculate the percentage of the time this token appears in a spam file versus a non spam file
	my $pw = $badcount / ( $goodnorm + $badcount );

	#  Make sure that rare words don't totally drive the calculation wild
	if ( $pw > $pure_spam )
                {  $pw = $pure_spam;
                }

	if ( $pw < $pure_notspam )
                {  $pw = $pure_notspam;
                }

              $token_spam_rating{ $token } = $pw;
       }
}



################################################################################
#
sub DumpPw()
#
#  dump out to a text file the current token rating
#
################################################################################
{   

    bprint "Dumping actual token weights to file tokens\.txt\n";
    open PWFILE, ">tokens.txt";

    foreach ( sort keys %token_spam_rating )
       {      next if ( !$_ );

               my $token = $_;
               my $weight = 0;
               my $bad = 0;
               my $good = 0;

	$weight = $token_spam_rating{ $token }  if ( defined( $token_spam_rating{ $token } ) );

	$bad = $spam_occurrences{ $token } if ( defined( $spam_occurrences{ $token } ) );

	$good = $nonspam_occurrences{ $token } if ( defined( $nonspam_occurrences{ $token } ) );

               print PWFILE "$token $weight $good $bad\n";
       }

    close PWFILE;

    return( 0 );    
}



################################################################################
#
sub AnalyzeFile( $ )
#
#  Given a file name, return 1 if it is spam, 0 if not
#
################################################################################
{   my $file = shift;
    my $retcode = 0;


    $retcode = &BayesianAnalyzeFile( $file );

    #  if it is spam, should I do something with it?
    if ( $retcode == 1 )
       {
             &CopyFile( $file ) if ( $opt_copy );
       }


    return( 1 ) if ( $retcode == 1 );

    return( 0 );    
}



################################################################################
#
sub BayesianAnalyzeFile( $ )
#
#  Given a file name, run the Bayesian statistics on it, and return 1 if it is spam, 0 if not
#
################################################################################
{   my $file = shift;

    # Load the spam text file
    my @email_tokens;

    open SPAM, "<$file" or &FatalError( "Cannot open $file\n  $!" );

    while (<SPAM>)
    {  my $line = $_;

	    my @tokens = split( /[^a-zA-Z\d]+/, $line );

	    foreach (@tokens)
	    {	    
		    # Length restriction
		    my $length = length;
		    next if ($length < 3 || $length > 40);

		    # Ignore all-digit tokens
		    next if (/^[0-9.]+$/);

                                 # Ignore tokens that start with a number
                                 next if ( m/^[0-9]/ );

		    push @email_tokens, $_;
	    }
    }

    close SPAM;



    # Rate each token according to how far from 0.5 it is
    my %email_token_spam_rating;
    my %interesting_tokens;
   
    #Keep track of new tokens
    my %new_tokens;


    foreach ( @email_tokens )
    {
	    next if (! length $_);

	    my $token = lc( $_ );

                  my $rating = $opt_unknown_token;

                  #  I don't know the token - use the unknown value
	    if ( defined( $token_spam_rating{ $token } ) )
                     {  $rating = $token_spam_rating{ $token };  }

                  #  Calculate the deviation from neutral
	    my $dev = abs( 0.5 - $rating );

                  #  Skip it if it isn't important
                  next if ( $dev < $opt_mindev );
	
                  $email_token_spam_rating{ $token } = $rating;

	    $interesting_tokens{ $token } = $dev;
    }

    
    # Show Information
    my $interesting_tokens_count = scalar keys %interesting_tokens;


    # Get number of interesting tokens
    my $most_interesting_count = $interesting_tokens_count > $opt_most_interesting_max ?
        $opt_most_interesting_max : $interesting_tokens_count;


    if ( $most_interesting_count < $opt_most_interesting_min )
        {   bprint "$file: NOT ENOUGH TOKENS\n" if ( !$opt_summary );
            return( 0 );
        }


        # Get the most interesting tokens, which are sorted by decreasing order of interest
        my @most_interesting = (sort { $interesting_tokens{ $b } <=> $interesting_tokens{ $a } } 
            keys %interesting_tokens)[0..$most_interesting_count - 1];


        # Calculate the Bayes probability
        my $prod = 1;
        my $one_minus_prod = 1;

        foreach ( @most_interesting )
            {
	        next if ( !defined $_ );
	        next if ( !defined $email_token_spam_rating{ $_ } );

	        $prod *= $email_token_spam_rating{ $_ };
	        $one_minus_prod *= ( 1.0 - $email_token_spam_rating{ $_ } );
            }


        my $probability_of_spam = 0;
        $probability_of_spam = $prod / ( $prod + $one_minus_prod )
	        if ( ( $prod + $one_minus_prod ) > 0 );

        # Display the results
        my $str = sprintf( "\nFile name $file: %s", $probability_of_spam > $opt_spam_threshold ? "SPAM" : "NOT SPAM" );
        bprint "$str\n" if ( !$opt_summary );

        $str = sprintf( "Spam Probability  %2.2f\n", 100 * $probability_of_spam );
        bprint "$str" if ( !$opt_summary );

        if ( !$opt_summary )
           {  bprint "Total Email Tokens Found (Not Unique): ", scalar @email_tokens, "\n";
               bprint "Interesting Tokens: ", $interesting_tokens_count, "\n";
           }


        # Show the most interesting tokens
        if ( ( $opt_show_most_interesting )  &&  ( !$opt_summary ) )
           {
               $str = sprintf( "   %25s %12s   %12s", "Token", "Rating", "Interest" );
               bprint "$str\n";

               my $token_count = 0;

              foreach ( @most_interesting )
                 {
	        next if ( !defined $_ );
	        next if ( !defined $email_token_spam_rating{ $_ } );

                     $str = sprintf( "%2d %25s       %2.4f       %2.4f", $token_count, $_, $email_token_spam_rating{ $_ }, $interesting_tokens{ $_ } );
                     bprint "$str\n";

                     ++$token_count;
                }  # end of foreach most_interesting
         }  #  end of opt_show_most_interesting


     #  Return 1 if I think it is spam, 0 if not
     return( 1 ) if ( $probability_of_spam > $opt_spam_threshold );

     return( 0 );
}



################################################################################
#
sub CopyFile( $ )
#
#  Copy the given full path file to the $opt_copy directory, return TRUE if it worked, undef if not
#
################################################################################
{   my $src = shift;

    use File::Copy;

    my @parts = split /\\/, $src;

    my $filename = $parts[ $#parts ];
    my $dest = $opt_copy . "\\$filename";

    my $retcode = move( $src, $dest );

    return( $retcode );
}



################################################################################
#
sub Usage ()
#
################################################################################
{
    my $me = "IpmGradeSpam";

    bprint <<".";
Usage: $me [OPTION(s)] [email file or directory of email files]

Reads email files from disk, tokenizes them, and then applies Bayesian
statistics to calculate if they resemble spam mail.

Uses "LocalTokens.txt" for the token weights if it exists, otherwise it
uses "SpamTokens.txt".


  -a, --aggressive     percentage value of how aggressive to grade spam
                       0 = low, 100 high, default is 50. 
  -c, --copy = directory  move any spam file found to the given directory
  -d, --directory      location of the tokens file
                       default is "\\Software Directory".
  -f, --filename=FILE  to set the spam tokens file name
                       default = "LocalTokens.txt" or "SpamTokens.txt"         
  -h, --help           display this help and exit
  -i, --interest       the maximum number of interesting keywords to use
                       default = 50 
  -o, --offset         offset from 1 and 0 for the maximum and mimimum
                       token value,  default is 0.1
  -p, --pweight        write to file "tokens.txt" the actual weight used
  -r, --ratio          expected ratio of ham to spam, default is 1.15
  -s, --summary        to show summary information only
  -t, --tokens         to show the tokens used to categorize each email
  -v, --version        display version information and exit
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
    my $me = "IpmGradeSpam";

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
