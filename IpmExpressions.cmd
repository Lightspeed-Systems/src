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
# Rob McCarthy's expressions processing
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
#use strict;
use Getopt::Long;
use Content::File;



# Options
my $opt_help;
my $opt_version;
my $opt_dir;
my  $opt_tmpfile = 'Expressions.tmp';


# Globals
my $_version = "2.0.0";
my @files;
my @expressions;   #  List expressions
my @expressions_category;  #  Matching categories of the expressions



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "IpmExpressions" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    my $url = shift;
    &Usage() if ( !$url );

    &LoadExpressions();

    bprint( "\n" );

    my $category = &ProcessExpressions( $url );

    if ( $category eq "general" )
      {
          $category = &CategorizeByUrlName( $url );

          if ( !$category )
            {  bprint( "Unable to categorize url by expression or phrase\n" );
            }
          else
            {  bprint( "Categorized the URL by phrase to category $category\n" );
            }
      } 

   &StdFooter;

exit;
}
################################################################################



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "IpmExpressions";

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
    my $me = "IpmExpressions";

    bprint <<".";
Usage: $me [OPTION(s)]
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
    my $me = "IpmExpressions";

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
