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
use Content::File;
use Content::SQL;



# Options
my $opt_help;
my $opt_version;
my $opt_input_file = "content.txt";


my $_version = "1.0.0";
my  $dbh;             #  My database handle
my $dbhstats;



################################################################################
#
MAIN:
#
################################################################################
{   print "Blocked Content Formatting command\n";

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "i|input=s" => \$opt_input_file,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


     &Usage() if ( $opt_help );
     &Version() if ( $opt_version );


     if ( !$opt_input_file )
        {   &Usage();
            exit;
        }


     print "Formatting input file $opt_input_file to CONTENT's Blocked for Review Report ... \n";

     open INFILE, "<$opt_input_file" or die "Cannot open input file $opt_input_file: $!\n";


     $dbh = &ConnectServer() or die;
     LoadCategories();
     $dbhstats = &ConnectStatistics() or die;

    my $url;
    my $category;
    my $time = "<none>";
    my $client_ip;

    my %url_list;

    while (<INFILE>)
       {
           chomp;
           next if (!length);  #  Ignore empty lines
           
           my $line = lc( $_ );

           if ( my $pos = index( $line, 'posted at:' ) != -1 )
             {
                 my $pos2 = length('posted at:') + $pos;
                 $time = substr($line, $pos2);
             }

           if ( my $pos = index( $line, 'blocked url:' ) != -1 )
             {   my ( @parts ) = split/\s/, $line;
                 $url = $parts[ $#parts ];
             }

           if ( my $pos = index( $line, 'category:' ) != -1 )
             {   my ( @parts ) = split/\s/, $line;
                 $category = $parts[ $#parts ];
             }
 
           if ( my $pos = index( $line, "ttc server host name:" ) != -1 )
             {   my ( @parts ) = split/\s/, $line;
                 $client_ip = $parts[ $#parts ];

                 next if ( $category eq "local-block" );
                 my  $lookupType = &LookupUnknown( $url, 0 );
                 next if ( !$lookupType );

               my $url_type = &UrlType($url);

			if ($url_type == 1)
			{
			     $url = &ReverseDomain($url);
		     }
			elsif ($url_type == 2)
			{
			     $url_type = 3;
			}
			elsif ($url_type == 3)
			{
			     $url_type = 2;
     		     #Truncate the URL in case it's too big!
     		     $url = substr($url, 0, 127);		     
		     }
               
     		my $catnum = &CategoryNumber($category);
               next if ( !$catnum );
               
     		#reformat time string--there's gotta be a better way??
               (@parts) = split/,/, $time;
               my $time = sprintf("%s%s", $parts[1], $parts[2]);


			my $sth = $dbhstats->prepare( "INSERT INTO ContentFilteringBlockedForReview (URL, Reason, CategoryID, ClientHost, InSystem) VALUES (\'$url\', $url_type, $catnum, \'$client_ip\', \'$time\')" );
               if ( !$sth->execute() )
               {
                    &lprint( "Error inserting Blocked for review entry:\n" );
                    &lprint( "URL: $url, URL_TYPE:$url_type, CATNUM: $catnum, CLIENT_IP: $client_ip, TIME: $time\n" );
               }

               $sth->finish();	
             }
            
       }


     close INFILE;

     $dbh->disconnect;
     $dbhstats->disconnect;
}

exit;
################################################################################



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "BlockedFormat";
    print <<".";
Usage: $me [OPTION(s)] 
Import over-blocked information from a text file, into a Report.
    
  -h, --help                  display this help and exit
  -v, --version               display version information and exit
  -i, --import <input-file>   specify an import file to use, default is content.txt
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "sqlquery";

    print <<".";
$me $_version
.
    exit;
}


__END__

:endofperl
