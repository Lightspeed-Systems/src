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


# Pragmas
use strict;
use Getopt::Long;
use Content::File;
use Content::SQL;
use DBI qw(:sql_types);
use DBD::ODBC;



my $opt_dir;                                         # Directory to put stuff to
my $opt_output_file = "unknown.urls";    
my $opt_help;
my $opt_version;



# Globals
my $_version = "2.0.0";
my  $dbh;             #  My database handle



################################################################################
#
MAIN:
#
################################################################################
{ 
    print ("SQLExtract\n" );
    print "Extracting domains and urls from the Content database using query commands ... \n";


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "d|directory=s" => \$opt_dir,
        "o|output=s" => \$opt_output_file,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


     #  Build up the command line to issue
     my  $cmd;
     while ( my $arg = shift ) 
       {  if ( !$cmd )  {  $cmd = $arg;  }
          else  {  $cmd = $cmd . " " . $arg;  }
       }

     print "Select Query = $cmd\n";

     $dbh = &ConnectServer() or die;

     &ExtractFile( $cmd );

     $dbh->disconnect;

     print "\nDone\n";
}

exit;
################################################################################




################################################################################
# 
sub ExtractFile( $ )
#
#  Given a WHERE command, extract out from the database matching domains and urls
#
################################################################################
{   my  $cmd = shift;

    my $dir = "\.";
    $dir = $opt_dir if ( $opt_dir );

    my  $filename = "$dir\\$opt_output_file";
    open OUTPUT, ">>$filename" or die "Cannot create output file: $filename,\n$!\n";
    print "Creating file $filename ... \n";

    print "Querying domains ...\n";
    my $str = "SELECT DomainName FROM IpmContentDomain WHERE $cmd";
    my $sth = $dbh->prepare( $str );
    $sth->execute();

    my $array_ref = $sth->fetchall_arrayref();

     foreach my $row ( @$array_ref )
         {
             my ( $reverseDomain ) = @$row;
             my $domain = &ReverseDomain( $reverseDomain );

             #  Should I add a www. to the front of it?

              print OUTPUT "$domain\n";
              $str = "www\." . $domain;
              print OUTPUT "$str\n";
         }


    print "Querying urls ...\n";
    $str = "SELECT URL FROM IpmContentURL WHERE $cmd";
    $sth = $dbh->prepare( $str );
    $sth->execute();

    $array_ref = $sth->fetchall_arrayref();

    foreach my $row ( @$array_ref )
       {
             my ( $url ) = @$row;
             print OUTPUT "$url\n";
       } 

     close  OUTPUT;

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
Usage: $me [OPTION(s)]
Export domains, urls, hits, and misses from the Content Database to Squidguard format

  -c, --category=name    category name if only one category to export
  -d, --directory=PATH   to change default files directory
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



__END__

:endofperl
