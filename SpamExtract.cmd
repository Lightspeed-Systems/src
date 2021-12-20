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
my $opt_debug;
my $opt_datestr;			#  To be able to put a command line date to download and process
my $drive = "C:";                       #  Default drive letter



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "SpamExtract" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "d|drive=s" =>\$opt_drive,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    $opt_datestr = shift;

    if ( $opt_drive )
      {  $drive = $opt_drive;
      }

    &Usage() if ($opt_help);
    &Version() if ($opt_version);

 
    my $cmd;

    my $old_time = time() - ( 6 * 24 * 60 * 60 );   #  Figure out six days ago

    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );

    $mon = $mon + 1;
    $year = 1900 + $year;

    my $datestr = sprintf( "%04d%02d%02d", $year, $mon, $mday ) if ( ! $opt_datestr );

    $datestr = $opt_datestr if ( $opt_datestr );

    print "Extracting spam for date: $datestr\n";

    my $dir = "$drive\\Program Files\\Lightspeed Systems\\Traffic\\Mail Archive\\$datestr";
    print "Archive directory: $dir\n\n";
    


    my $results_dir = "$drive\\Content\\spam";
    my $results_file = $results_dir . "\\domains\.hit";
    my $results_dom = $results_dir . "\\domains";
    my $results_url = $results_dir . "\\urls";


    print "Deleting the old $results_file files ... \n";
    unlink $results_file;
    unlink $results_dom;
    unlink $results_url;


    open DOMAIN, ">$results_file" or &FatalError( "Cannot open $results_file: $!\n" );
   
    print "Extracting IP addresses and URLs from spam files ...\n";


    # Loop through the directory
    my $file_counter = 0;
    my $file;

    # Process the directory
    opendir DIR, $dir;

    while ( $file = readdir( DIR ) )
      {
         # Skip subdirectories
         next if (-d $file);

         my $spam_file = $file =~ m/^s/;
         next if ( !$spam_file );
 
         $file_counter++;
         &AnalyzeFile( "$dir\\$file", undef );
      }

    closedir DIR;
            

    close  DOMAIN;

    bprint( "Final results - extracted from $file_counter files\n" );
 
    chdir( $results_dir );

    $cmd = "hits2squid $results_file";
    system( $cmd );
    

    # Now do all the ham files

    $old_time = time() - ( 1 * 24 * 60 * 60 );   #  Figure out one day ago

    ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old_time );

    $mon = $mon + 1;
    $year = 1900 + $year;

    $datestr = sprintf( "%04d%02d%02d", $year, $mon, $mday ) if ( ! $opt_datestr );

    $datestr = $opt_datestr if ( $opt_datestr );

    print "Extracting ham for date: $datestr\n";

    $dir = "$drive\\Program Files\\Lightspeed Systems\\Traffic\\Mail Archive\\$datestr";
    print "Archive directory: $dir\n\n";
    $results_dir = "$drive\\Content\\ham";
    $results_file = $results_dir . "\\domains\.hit";
    $results_dom = $results_dir . "\\domains";
    $results_url = $results_dir . "\\urls";


    print "Deleting the old $results_file files ... \n";
    unlink $results_file;
    unlink $results_dom;
    unlink $results_url;


    open DOMAIN, ">$results_file" or &FatalError( "Cannot open $results_file: $!\n" );
   
    print "Extracting IP addresses and URLs from ham files ...\n";


    # Loop through the directory
    $file_counter = 0;

    # Process the directory
    opendir DIR, $dir;

    while ( $file = readdir( DIR ) )
      {
         # Skip subdirectories
         next if (-d $file);

         my $ham_file = $file =~ m/^h/;
         next if ( !$ham_file );
 
         $file_counter++;
         &AnalyzeFile( "$dir\\$file", 1 );
      }

    closedir DIR;
            

    close  DOMAIN;

    bprint( "Final results - extracted from $file_counter files\n" );
 
    chdir( $results_dir );

    $cmd = "hits2squid $results_file";
    system( $cmd );
    

    print "Importing into the Content Database ... \n";

    chdir "$drive\\Content";

    my $import_dir = "$drive\\Content";

    $cmd = "sqlimport -d $import_dir -s 6 -c spam";
    system( $cmd );

    $cmd = "sqlimport -d $import_dir -s 6 -c ham -o spam";
    system( $cmd );


    &StdFooter;

    exit;
}



################################################################################
#
sub pause()
#
################################################################################
{
    return  if ( !$opt_debug );
    print "Ready? [ Y or N ]  ";

         my $done;
         while ( !$done )
            {  my $line = <STDIN>;
               chomp( $line );
               exit if ( uc( $line ) eq "N" );
               $done = 1 if ( uc( $line ) eq "Y" );
            }

          print "\n";

}



################################################################################
#
sub AnalyzeFile ($$)
#
################################################################################
{
    # Get the parameters
    my $file = shift;
    my $iponly = shift;

	my $email_from;
	my $email_to;
	my $external_ip_address;
	my $resolved_domain;


    open INFILE, "<$file" or &FatalError( "Cannot open $file\n  $!" );


    my $first_line = 1;
    my $base64;
    my $message_body;
    my $bytes = 0;
    while (<INFILE>)
        {    chomp;
             my $line = $_;
             next if ( !$line );
             my $len = length( $line );

            $bytes += $len;   #  Count the bytes


	    #  Am I reading the first line comment by Brock's code?
	    if ( ( $first_line )  &&  ( $line =~ m/\(.*\)/ ) )
		{   $first_line = undef;
			my $comment = $line;

			$comment =~ s/\(//;
			$comment =~ s/\)//;
	
			my @parts = split /\s/, $comment;
			my $part_no = 0;
			foreach ( @parts )
		          {  $part_no++;
				my $keyword = lc( $_ );
				#  Check for a blank value
				next if ( !$parts[ $part_no ] );
				next if ( index( "emailfrom:emailto:externalipaddress:resolveddomain:", lc( $parts[ $part_no ] ) ) != -1 );
						 
				if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
				if ( $keyword eq "emailto:" )            {  $email_to = lc ( $parts[ $part_no ] );  }
				if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
				if ( $keyword eq "resolveddomain:" )     {  $resolved_domain = lc ( $parts[ $part_no ] );  }
			  }

			print DOMAIN "$external_ip_address\n" if ( $external_ip_address );
			
			return if ( $iponly );			  
		}  # end of first line processing


            #  Am I a setting the encoding?
            if ( m/Content-Transfer-Encoding: / )
             {   $base64 = undef;
                 $base64 = 1 if ( m/base64/ );
                 $message_body = undef;
             }

           if ( ( $base64 )  &&  ( $message_body ) )  #  Decode if it looks like it matches
             {   
                 my $padding = length( $line ) % 4;

                 if ( ( $line )  &&  ( !$padding ) )   #  Don't decode if too small or not a multiple of 4
                    {  $line = decode_base64( $line );
                    }
                 else  {  $base64 = undef;  }
             }

              #  Does it have at least one http://  ?
              while ( $line =~ m/http:\/\// )
                {   my ( $junk, $url ) = split  /http:\/\//, $line, 2;
                    $line = $url;  #  Put what's left into line so that if there is multiple https on the same line we handle it
                    
                    #  Try to clean off as much crap as possible
                    ( $url, $junk ) = split  /http:\/\//, $url, 2 if ( $url );
                    ( $url, $junk ) = split  /\s/, $url, 2 if ( $url );

                    ( $url, $junk ) = split /\?/, $url, 2 if ( $url );
                    ( $url, $junk ) = split /\"/, $url, 2 if ( $url );

                    next if ( !$url );

                    #  If it has a user id at the front of the url
                    if ( $url =~ m/@/ )
                       {  ( $junk, $url ) = split /@/, $url, 2 if ( $url );
                       }

                    $url = &CleanUrl( $url );

                    print DOMAIN "$url\n" if ( $url );
                }

	  $first_line = undef;
	  return if ( $iponly );
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
    my $me = "SpamExtract";

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
    my $me = "SpamExtract";

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
