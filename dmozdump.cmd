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
#!perl

# Pragmas
use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;


# Options
my $opt_version;
my $opt_out_dir;
my $opt_help;


# Globals
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
        "o|output=s" => \$opt_out_dir,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage() if ($opt_help);
    &Version() if ($opt_version);


    LWP::Simple::getstore( 'http://rdf.dmoz.org/rdf/content.rdf.u8.gz', "content.rdf.u8.gz" );

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
Usage: $me [OPTION]... URI
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

#  -f, --file=FILE           dump URLs from input file

    print <<".";
Usage: $me [OPTION(s)] url_list
  -o, --output=PATH     output directory
                        default = input file's directory\\dump
  -h, --help            display this help and exit
  -v, --version         display version information and exit
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
