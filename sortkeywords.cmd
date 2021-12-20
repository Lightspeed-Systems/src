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


# Pragmas
#use strict;

use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;


# Constants
my $keywords_file = "keywords";


# Options
my $opt_root_dir = "\\Content\\blacklists";
my  $opt_help;
my  $opt_version;
my  $opt_input_file;


# Globals
my $_version = "1.0.0";



################################################################################
#
MAIN:
#
################################################################################
{
    print ("Sort Keywords command\n" );

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "d|directory=s" => \$opt_root_dir,
        "i|input=s" => \$opt_input_file,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


    # Load the keyword tokens
    my $tokens_file = $keywords_file;

    #  If there still is an argument, it must be the input file name
    if ( $ARGV[0] )   {  $tokens_file = $ARGV[0];  }

    if ( $opt_input_file )  {  $tokens_file = $opt_input_file;  }


    if (!open TOKENS, "<$tokens_file")
    {   print "Unable to read keyword file $tokens_file.\n";
        die;
    }

    my  %token_hit_rating;
    my  %token_freq;
    my  $count = 0;
    while ( <TOKENS> )
    {              chomp;
	    my ( $token, $rating, $freq ) = split / /, $_;
	    $token_hit_rating{ $token } = $rating;
                   $token_freq{ $token } = $freq;
                   $count++;
    }

  close TOKENS;


   open TOKENS, ">$tokens_file" or die "Cannot create keywords file: $tokens_file,\n$!\n";


     foreach $key ( sort { $token_freq{ $b } <=> $token_freq{ $a }  } keys %token_freq )
        {    $token = $key;
             print  TOKENS "$token $token_hit_rating{ $token } $token_freq{ $token }\n"; 
        }

   close TOKENS;

   print "\nDone.\n"
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
Usage: $me [OPTION]... [FILE]
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

#  -u, --url=URL         specify URL instead of using file
    print <<".";
Usage: $me [OPTION(s)] [File of URLs]
Sorts the keywords file by the most representative words.
  -i, --input=FILE       input file of keywords, default is "keywords"
  -h, --help             display this help and exit
  -v, --version          display version information and exit
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
