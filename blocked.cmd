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
my $opt_output_file = "blocked.html";


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
        "o|output=s" => \$opt_output_file,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


     &Usage() if ( $opt_help );
     &Version() if ( $opt_version );



     $dbh = &ConnectServer() or die;
     LoadCategories();
     $dbh->disconnect;


     #  Try to connect the the ODBC DSN for the Statistics database
     # I need to have defined an ODBC connection with the default database of IpmStatistics
     my $statdbh = DBI->connect( "DBI:ODBC:TrafficStatistics", "IpmStatistics" ); 

    die "Unable to open statistics database\n" if ( !$statdbh );

    my $url;
    my $category;

    my %url_list;

     my $sth = $statdbh->prepare( "SELECT CategoryId, Url Allow FROM ContentFiltering" );

     $sth->execute();

     my $array_ref = $sth->fetchall_arrayref();


     foreach my $row ( @$array_ref )
       {
            my ( $category_number, $url ) = @$row;
            my $category_name = &CategoryName( $category_number );

            if ( !$url_list{ $url } )  {  $url_list{ $url } = $category_name;  }              
       }


     $sth->finish();



     open OUTFILE, ">$opt_output_file" or die "Cannot open output file $opt_output_file: $!\n";

     print OUTFILE "<HTML>\n <HEAD></HEAD>\n <BODY>\n";


     my @urls = sort keys %url_list;
     foreach( @urls )
         {  $url = $_;
             $category = $url_list{ $url };
             print OUTFILE "Category: $category  <A HREF=\"http:\/\/$url\" TARGET=\"_blank\">$url<\/A><BR>\n";
         }


     print OUTFILE " </BODY>\n</HTML>\n";

     close OUTFILE;


     $statdbh->disconnect;
}

exit;
################################################################################



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "sqlquery";
    print <<".";
Usage: $me [OPTION(s)]  URL
Query the Content database about a given URL
    
  -h, --help         display this help and exit
  -v, --version      display version information and exit
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
