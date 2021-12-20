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
#
# Rob McCarthy's categorize perl source
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;

use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use DBI qw(:sql_types);
use DBD::ODBC;
use Unicode::String qw(utf8 latin1 utf16);
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Fcntl qw(:DEFAULT :flock);
use Content::File;
use Content::SQL;
use CGI::Carp qw(fatalsToBrowser); 



# Options
my $opt_input_domains = "domains";     #  The file name if supposed to read unknown urls from a file
my $opt_input_urls = "urls";
my $opt_input_hits = "hits.urls";
my $opt_input_misses = "misses.urls";
my $opt_category;                               # Option for categorizing just one category
my $opt_insert;         # True if domains and urls should be inserted without compressing to existing domains or urls
my $opt_errors_file;  #  True if errors should be written to a file
my $opt_misses_file;  # True if misses should be recorded
my $opt_hits_file;       # True if hits should be recorded
my $opt_dir;              # Directory to get stuff from
my $opt_help;
my $opt_version;
my $opt_source = 0 + 5;


# Globals
my $_version = "2.0.0";
my $dbh;                              #  My database handle



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "Spam Databse Update" );

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


    &SpamExtract();

    #  Open the database
    $dbh = &ConnectServer() or die;

    &LoadCategories();

    &SpamInsert();


   #  Clean up everything and quit
   $dbh->disconnect;

   &StdFooter;

exit;
}
################################################################################




################################################################################
# 
sub MXLookup( $ )
#
#  Given a domain name, return the IP Addresses of all the MX records
#
################################################################################
{   my $domain = shift;

     my $output = `nslookup -type=mx $domain`;

     my @addrs;

     my @parts = split /\s/, $output;

     foreach ( @parts )
        {   push @addrs, $_ if ( &IsIPAddress( $_ ) );
        }

    return( @addrs );
}



my @spam_ip_address;
my %ham_domains;
################################################################################
# 
sub SpamExtract()
#
#  Connect to the Statistics database, extract out new ham and spam info
#
################################################################################
{   
    my $dbhStats;

     lprint "Extracting spam and ham IP addresses from the statistics database ... \n";

    #  Open the database
    $dbhStats = &ConnectStatistics() or die;


    my $str = "SELECT ExternalIpAddress FROM SpamMailBlocker WHERE Status like 'Spam %'";
    my $sth = $dbhStats->prepare( $str );
    $sth->execute();

    my $array_ref = $sth->fetchall_arrayref();

    foreach my $row ( @$array_ref )
       {
           my ( $ipAddress ) = @$row;
           push @spam_ip_address, $ipAddress;
       }


    $sth = $dbhStats->prepare( "SELECT EmailTo FROM TrafficClassEmail" );
    $sth->execute();

    $array_ref = $sth->fetchall_arrayref();

    foreach my $row ( @$array_ref )
       {
           my ( $emailTo ) = @$row;
           my ( $junk, $domain ) = split /@/, $emailTo, 2;

           if ( $domain )
             {  $ham_domains{ $domain } = 0;
             }
       }


   #  Clean up everything and quit
   $dbhStats->disconnect;
}



################################################################################
# 
sub SpamInsert()
#
#  Insert into the Content database the spam and ham info
#
################################################################################
{
    my $ham_category =  &CategoryNumber( "ham" );
    my $spam_category =  &CategoryNumber( "spam" );

     lprint "Inserting spam and ham IP addresses into the content database ... \n";


    #  Add the ham addresses
    my $out_counter = 0;
    my $switch_counter = 0;
    foreach ( keys %ham_domains )
       {   next if ( !$_ );

           my $domain = $_;
           my @addrs = &MXLookup( $domain );

           foreach ( @addrs )
              {   next if ( !$_ );
                  my $ipaddress = $_;
                  my $retcode = &LookupUnknown( $ipaddress, 0 );

                  #  If I don't know this address at all, add it to the ham category
                  if ( !$retcode )
                    {    $retcode = &AddNewTrans( $ipaddress, $ham_category, 0, $opt_source );

                          if ( $retcode == 0 )
                            {   $out_counter++;
                                 lprint "Added to database Ham IP Address $ipaddress\n";           
                            }
                         else
                            {  lprint "Error $retcode adding IP address $ipaddress to the database\n";
                            }
                         next;
                    }

                 #  If this is already in the database, and allowed, just skip it
                 next if ( $retcode > 3 );

                 #  At this point, it is in the database, but blocked, so is it in the spam category?
                 my $catnum = &FindCategory( $ipaddress, $retcode );
                 next if ( $catnum != $spam_category );
                 &UpdateCategory( $ipaddress, $ham_category, $retcode, $opt_source );

                 lprint "Switched IP Address $ipaddress from Spam to Ham\n";
                 $switch_counter++;
             }
       }


     lprint "Added $out_counter Ham IP Addresses to the database\n" if ( $out_counter > 0 );
     lprint "Switched $switch_counter IP Addresses from Spam to Ham\n" if ( $switch_counter > 0 );


    #  Add the spam addresses
    $out_counter = 0;
    foreach ( @spam_ip_address )
       {   next if ( !$_ );

           my $ipaddress = &IPToString( $_ );
           my $retcode = &AddNewTrans( $ipaddress, $spam_category, 0, $opt_source );

            if ( $retcode == 0 )
              {   $out_counter++;
                  lprint "Added to database Spam IP Address $ipaddress\n";           
              }
       }

     lprint "Added $out_counter Spam IP Addresses to the database\n" if ( $out_counter > 0 );


    #  Clear out the memory used
    @spam_ip_address = [];
    %ham_domains = ();
}


  
################################################################################
# 
sub ConnectStatistics()
#
#  Find and connect to the SQL Traffic Statistics Server, if possible.  Return undef if not possible
#
################################################################################
{   my  $dbh;
    my  $key;
    my  $type;
    my  $data = 0;
    my $sql_server = "(local)";  #  Default sql server to connect to


    # First, get the SQL server to connect through from the registry
     #  At this point, I couldn't connect, so see if the ODBC DSN is even in the registry
     my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\Content Database", 0, KEY_READ, $key );

     $ok = RegQueryValueEx( $key, "DB Connect Type", [], $type, $data, [] ) if ( $ok );

 
     #  If it is a DB Connect Type 0x02000000, then it is a specified server name - and probably not (local)
     if( $data eq "\x02\x00\x00\x00" )
       {   $data = undef;
           $ok = RegQueryValueEx( $key, "DB Connect Server", [], $type, $data, [] );
           $sql_server = $data if ( $data );
       }


     # Now look to see if the ODBC Server is set to the same thing as sql_server is ...
     $data = undef;
     $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\TrafficStats", 0, KEY_READ, $key );
     $ok = RegQueryValueEx( $key, "Server", [], $type, $data, [] ) if ( $ok );


     #  If everything is set ok, try to connect to it
     if ( ( $data )  &&  ( $data eq $sql_server ) )
       {  #  Try to connect the the ODBC DSN
          $dbh = DBI->connect( "DBI:ODBC:TrafficStats", "IpmStatistics" ); 
          if ( $dbh )
            {  return( $dbh );
            }

          #  At this point, I couldn't connect, so see if the ODBC DSN is even in the registry
          $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\TrafficStats", 0, KEY_READ, $key );

          $ok = RegQueryValueEx( $key, "Server", [], $type, $data, [] ) if ( $ok );

          if ( $ok )
            {   lprint "Found HKEY_LM\\SOFTWARE\\ODBC\\ODBC.INI datasource TrafficStats in registry, but\n";
                lprint "am unable to connect to it.\n";  
                breturn( undef );
            }
        }


     # At this point I know that the ODBC datasource isn't defined, so go ahead and try punching it into the registry myself ...

     lprint "Adding TrafficStats ODBC datasource to the local registry ... \n";

     #  Add the Data Sources entry
     #  Create the key if it isn't there already
     $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\ODBC Data Sources", 0, KEY_WRITE, $key );
     RegSetValueEx( $key, "TrafficStats", 0, REG_SZ, "SQL Server" );


     #  Add the TrafficStats entry
     $key = 0;
     $ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\ODBC\\ODBC.INI\\TrafficStats", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] );

     if ( !$ok )
       {    lprint "Unable to create key HKEY_LM\\SOFTWARE\\ODBC\\ODBC.INI\\TrafficStats in the registry\n";
            return( undef );
       }

     my $systemRoot = Win32::ExpandEnvironmentStrings( "%SystemRoot%" );
     my $driver = $systemRoot . "\\System32\\sqlsrv32.dll";

     RegSetValueEx( $key, "Driver", 0,  REG_SZ, $driver );
     RegSetValueEx( $key, "Description", 0, REG_SZ, "Lightspeed Total Traffic Server SQL database" );
     RegSetValueEx( $key, "Server", 0, REG_SZ, $sql_server );
     RegSetValueEx( $key, "Database", 0, REG_SZ, "IpmStatistics" );
     RegSetValueEx( $key, "LastUser", 0, REG_SZ, "ROB" );
     RegSetValueEx( $key, "Trusted_Connection", 0, REG_SZ, "Yes" );


     #  Try connecting now ...  if I can't, there is nothing I can do about it
     $dbh = DBI->connect( "DBI:ODBC:TrafficStats", "IpmStatistics" ); 

     return( $dbh );
}



################################################################################
# 
sub errstr($)
#  
################################################################################
{
    bprint shift;

    return( -1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "SqlImport";

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
    my $me = "SqlImport";

    bprint <<".";
Usage: $me [OPTION(s)]
Imports domains and urls in Squidguard format into the Content database

  -c, --category=name    category to add the domains and urls to
  -d, --directory=PATH   to change default files directory
  -h, --help             display this help and exit
  -i, --insert           insert new urls without compressing or changing
                         old url categories
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
    my $me = "SqlImport";

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
