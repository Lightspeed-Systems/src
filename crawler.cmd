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
use strict;

use Getopt::Long;
use WWW::SimpleRobot;
use URI::Heuristic;


# Options
my $opt_url;
my $opt_depth = 1;
my $opt_input_file;
my $opt_output_file = ".\\domains.unknown";
my $opt_asp = 0.0;
my $opt_suburls = 0.0;
my $current_url;
my $opt_directory_sites = "\\Content\\blacklists\\DirectorySites";


# Version
my $_version = "1.0.0";




################################################################################
#
MAIN:
#
################################################################################
{

    print "Crawler command\n";
 
    # Get the options
    Getopt::Long::Configure("bundling");

    my $opt_version;
    my $opt_help;

    my $option_count = Getopt::Long::GetOptions
    (
        "a|asp" => \$opt_asp,
        "d|depth=s" => \$opt_depth,
        "i|input=s" => \$opt_input_file,
        "o|output=s" => \$opt_output_file,
        "s|suburls" => \$opt_suburls,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);
    if ( !$opt_input_file )  { $opt_input_file = shift } ;
    my $arg = shift;
    if ( $arg )  { $opt_output_file = $arg } ;

   
    open OUTPUT, ">>$opt_output_file" or die "Unable to open output file $opt_output_file\n";


    #  Read in my directory sites that I shouldn't try to crawl
    my @directory;
    my $counter = 0;

    if ( open DIRECTORY, "<$opt_directory_sites" )
      {   while ( <DIRECTORY> )
              {  chomp;
                  next if (!$_);         #  Ignore empty lines
                  next if /^#/;           #  Skip comments
                  next if /^\s*(#|$)/;
                  
                   #  Domain names have one dot, web sites have two dots
                   #  If it just has one dot, add one to the front
                   my @dots = m#\.#g;
                   if ( scalar @dots == 1.0 )  {  $_ = '.' . $_ };
                
                  $directory[ $counter ]  = $_;
                  $counter += 1.0
              }

           close DIRECTORY;
      }


    #  If I can open the $opt_input_file as a file, it must be a file name passed to me, otherwise it's a URL
    open INFILE, "<$opt_input_file" or ( $opt_url = $opt_input_file );


     my  $url;
     my $domain;
     my $url_ext;


     if ( $opt_url )   #  If I have just one URL
       {  # Build the URL string
          $url = URI::Heuristic::uf_urlstr( $opt_url );
          &crawl( $url );
       }
    else  #  If I have a whole list of URLs in a file
       {  while ( $opt_url = <INFILE> )
              {   $_ = $opt_url;
                  chomp;
                  next if (!length);  #  Ignore empty lines
                  next if /^#/;  #  Skip comments
                  next if /^\s*(#|$)/;


                 #  Is it one of my directory sites?
                  #  Split off the domain part ...
                  ( $domain, $url_ext ) = split /\\|\//, $opt_url, 2;
                  my  $matched;
                  foreach ( @directory )
                      {  if ( $domain =~ m#$_# )   {  $matched = $_;  }                            
                      }

                 #  Did I match a directory site?
                 if ( $matched )
                   {  print "Skipping crawling site $opt_url because it matches directory site $matched\n";
                      next;
                   }

                 $url = URI::Heuristic::uf_urlstr( $opt_url );
                 &crawl( $url );
             }
       }

   close OUTPUT;
   close INFILE;

}



################################################################################
#
sub crawl 
#
################################################################################
{
   my  $url = shift;


    # Do the bot
    eval 
    {   print "Crawling URL $url ... \n";

        $current_url = $url;

        my $robot = WWW::SimpleRobot->new(
            URLS            => [ "$url" ],
            #FOLLOW_REGEX    => ".*",
            DEPTH           => $opt_depth,
            TRAVERSAL       => 'depth',
            VISIT_CALLBACK  => \&callback,
        );

        $robot->max_size( 100000 );
        $robot->timeout( 30 );
        $robot->traverse;
    };
}



################################################################################
#
sub callback 
#
################################################################################
{ 
    my ($url, $depth, $html, $links) = @_;

    $_= $url;

    #  Unless asp pages are to be included, ignore them
    if ( ( $opt_asp == 0.0 )  &&  ( /.asp/ ) )  { return; }

    #  Unless sub URLs are specifically requested, they will be ignored
    if ( ( $opt_suburls == 0.0 )  &&  ( /$current_url/ ) )  { return; }

    print STDERR "$url\n";
    print OUTPUT "$url\n";
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
Usage: $me [OPTION]... URL
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
Usage: $me [OPTION(s)] [Input URLs] [Output URLs]
Recursively follows (crawls) links on a single URL, or a list of URLs.

  -a, --asp             include asp pages as well as html, default is no asp
  -d, --depth=NUM       max depth to crawl, default is 1 level
  -i, --input=FILE      List of URLs to crawl.  No default.
  -h, --help            display this help and exit
  -o, --output=FILE     output file to write the crawled URLs to.
                        The default is ".\\domains.unknown"
  -s, --suburls         include sub URLs of the crawled URL.
                        The default is no suburls
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
