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



# Options
my $opt_help;
my $opt_version;
my $opt_wizard;		# True if I shouldn't display headers or footers


my $_version = "1.0.0";
my  $dbh;             #  My database handle



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
        "v|version" => \$opt_version,
	"w|wizard" => \$opt_wizard,
        "h|help" => \$opt_help
    );


    &StdHeader( "SqlQuery" ) if ( $opt_wizard );

     &Usage() if ( $opt_help );
     &Version() if ( $opt_version );

     my $url = shift;

     if ( !$url )
        {   &Usage();
            exit;
        }


     #  Is this a valid url at all?
     my $cleanurl = &CleanUrl( $url );
     if ( !$cleanurl )
       {   &FatalError( "Illegal url = $url" );
       }


     $dbh = &ConnectServer() or die;
     LoadCategories();

     $url = $cleanurl; 

     &SqlQuery( $url );

     $dbh->disconnect;

     &StdFooter if ( $opt_wizard );

exit;
}

exit;
################################################################################



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
       {  print "Lookup Type = $lookupType\n";

	  my ( $category_number, $source_number, $transaction_time, $review_time ) = &FindCategory( $url, $lookupType );
          my $category_name = &CategoryName( $category_number );

          my $blocked = "FALSE";
          $blocked = "TRUE" if ( &BlockedCategory( $category_name ) );

          $category_name = "unknown" if ( !$category_name );
 
          if ( ( $lookupType == 2 )  ||  ( $lookupType == 5 ) )
             {  bprint "URL: $url, Category $category_number - $category_name, Blocked = $blocked, Source = $source_number\n";
             }
          elsif ( ( $lookupType == 3 )  ||  ( $lookupType == 6 ) )
             {   bprint "IP Address: $domain, Category $category_number - $category_name, Blocked = $blocked, Source = $source_number\n";
             }
          else
            {   
                bprint "Domain: $domain, Category $category_number - $category_name, Blocked = $blocked, Source = $source_number\n";  
            }

          if ( $source_number )                
            {   my $source_name = &SourceName( $source_number );
                bprint "Source # $source_number\n"; 
                bprint "Source Name $source_name\n" if ( $source_name ); 
            }
	if ( $transaction_time )
	{	bprint( "Transaction Time = $transaction_time\n" );
	}

	if ( $review_time )
	{	bprint( "Review Time = $review_time\n" );
	}
       }
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "sqlquery";
    bprint <<".";
Usage: $me [OPTION(s)]  URL
Query the Content database about a given URL
    
  -h, --help         display this help and exit
  -v, --version      display version information and exit
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
    my $me = "sqlquery";

    bprint <<".";
$me $_version
.
   &StdFooter;

    exit;
}


__END__

:endofperl
