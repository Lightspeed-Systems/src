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
# Rob McCarthy's version of extracting IP addresses from ham and spam mails
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

my $opt_version;
my $opt_help;
my $opt_drive;                                              
my $opt_datestr;			#  To be able to put a command line date to download and process
my $opt_extract_only;                    #  True if all I have to do is extract - no other processing
my $drive = "C:";                       #  Default drive letter



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "HamExtract" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "d|drive=s" =>\$opt_drive,
        "e|extract" => \$opt_extract_only,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    $opt_datestr = shift;

    if ( $opt_drive )
      {  $drive = $opt_drive;
      }

    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    print "Extracting only - no other processing\n" if ( $opt_extract_only );

    my $cmd;

if ( !$opt_extract_only )
{
    print "Deleting old ham files ... \n";
    system ( "del $drive\\SpamExtract\\nonspam\\h*" );


    print "Deleting old badham files ... \n";
    system ( "del $drive\\SpamExtract\\badham\\h*" );

    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );

    $mon = $mon + 1;
    $year = 1900 + $year;

    #  Grab the previous day
    $mday = $mday - 1;
    if ( $mday == 0 )
      {  $mon = $mon - 1;

         if ( $mon == 0 )
            {  $year = $year - 1;
               $mon = 12;
            }

         $mday = 30;
         $mday = 28 if ( $mon == 2 );
         $mday = 29 if ( ( $mon == 2 )  && ( ( $year % 4 ) == 0 ) );
         $mday = 31 if ( ( $mon == 1 )  ||
                                 ( $mon == 3 ) ||
                                 ( $mon == 5 ) ||
                                 ( $mon == 7 ) ||
                                 ( $mon == 8 ) ||
                                 ( $mon == 10 ) ||
                                 ( $mon == 12 ) );
      }

    my $datestr = sprintf( "%04d%02d%02d", $year, $mon, $mday );

    $cmd = "call scpnotspam $datestr $drive\\SpamExtract";
    $cmd = "call scpnotspam $opt_datestr $drive\\SpamExtract" if ( $opt_datestr );

    print "$cmd\n";

    system( $cmd );

    print "Smashing header and body files ... \n";
    system( "smash $drive\\SpamExtract\\nonspam" );

    print "Deleting header files ... \n";
    system( "del $drive\\SpamExtract\\nonspam\\q*" );

    print "Deleting body files ... \n";
    system ( "del $drive\\SpamExtract\\nonspam\\d*" );

    print "Deleting any extra files ... \n";
    system ( "del $drive\\SpamExtract\\nonspam\\f*" );
    system ( "del $drive\\SpamExtract\\nonspam\\s*" );
    system ( "del $drive\\SpamExtract\\nonspam\\l*" );

    print "Cleaning the bad ham out ...\n";
    system( "call IpmRealtimeSpam -a 75 -n -c $drive\\SpamExtract\\badham  $drive\\SpamExtract\\nonspam" );

}   # end of if !$opt_extract_only


    print "Deleting the old domains.ham file ... \n";
    system ( "del $drive\\SpamExtract\\domains.ham" );


    open DOMAIN, ">$drive\\SpamExtract\\domains.ham" or &FatalError( "Cannot open $drive\\SpamExtract\\domains.ham: $!\n" );
   
    print "Extracting IP addresses from ham files ...\n";

    # Loop through the remaining parameters, which should all be files to scan
    my $item;
    my $file_counter = 0;
    foreach $item ( "$drive\\SpamExtract\\nonspam" )
      {
           # Handle wildcards
           if ($item =~ /\*/ || $item =~ /\?/)
             {
                 # Loop through the globbed names
                 my @glob_names = glob $item;

                foreach (@glob_names)
                  {   $file_counter++;
                      &AnalyzeFile($_);
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
                           &AnalyzeFile("$item\\$file");
                      }

                 closedir DIR;
              }

           # Analyze a single file
          else
             {    $file_counter++;
                  &AnalyzeFile( $item );
             }
       }
   }  #  end of foreach item


    close  DOMAIN;

    bprint( "Final results - extracted from $file_counter files\n" );
 

    print "Deleting the duplicates in domains.ham ...\n";
    $cmd = "deldups $drive\\SpamExtract\\domains.ham";
    system( $cmd );
    

    &StdFooter;

    exit;
}



################################################################################
#
sub AnalyzeFile ($)
#
################################################################################
{
    # Get the parameters
    my $file = shift;


    open INFILE, "<$file" or &FatalError( "Cannot open $file\n  $!" );


    my $first;    #  TRUE if I have already read the first ip address
    my $bytes = 0;
    while (<INFILE>)
        {    chomp;
             my $line = $_;


                  #  Does it have a $ ip address in the beginning?
	    if  ( ( !$first )  &&  ( $line =~ m/^\$\_/ )  )
                     {    $line =~ s/^\$\_//;
                           my ( $domain, $ipaddress ) = split /\s/, $line, 2;

                           if ( $domain =~ m/\[/ )
                             {  $ipaddress = $domain;
                                 $domain = undef;
                             }
 
                           if ( $line =~ m/may be forged/ )
                             {  $domain = undef;
                             }

                           #  Clean up the IP address
                           if ( $ipaddress )
                             {  $ipaddress =~ s/\[//;
                                $ipaddress =~ s/\]//;
                                my $junk;
                                ( $junk, $ipaddress ) = split( /@/, $ipaddress ) if ( $ipaddress =~ /@/ );
                                ( $ipaddress, $junk ) = split /\s/, $ipaddress, 2;
                             }

                          print DOMAIN "$ipaddress\n" if ( $ipaddress );

                         close INFILE;
                         return( 0 );
                     }

        }

    close INFILE;

     return( 0 );
}



################################################################################
#
sub Usage ()
#
################################################################################
{
    my $me = "HamExtract";

    bprint <<".";
Usage: $me [OPTION(s)] [list of URLs]
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
    my $me = "HamExtract";

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
