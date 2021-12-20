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



# Validate and get the parameters
my $_version = "2.0.0";

my $opt_version;
my $opt_help;
my $opt_dir;                                              #  Directory of the Spam Tokens file


################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "Blacklist" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "d|directory=s" =>\$opt_dir,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


    open DOMAIN, ">>domains.hit" or &FatalError( "Cannot open domains.hit\n  $!" );
   

    # Loop through the remaining parameters, which should all be files to scan
    my $item;
    my $file_counter = 0;
    foreach $item (@ARGV)
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

    bprint( "Final results - $file_counter files\n" );
 
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

    my $counter = 0;
    while (<INFILE>)
        {    chomp;
             my $line = $_;
             next if ( !$line );

	    if ( $line=~ m/^Source/ )
                     {    $line =~ s/^\$\_//;
                           my @parts = split /\s/, $line;

                           my $ipaddress = $parts[ $#parts ];

                          next if ( !&IsIPAddress( $ipaddress ) );

                          print DOMAIN "$ipaddress\n" if ( $ipaddress );

                          $counter++;
                     }

        }

    print "Found $counter IP addresses\n" if ( $counter > 0 );

    close INFILE;

     return( 0 );
}



################################################################################
#
sub Usage ()
#
################################################################################
{
    my $me = "Blacklist";

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
    my $me = "Blacklist";

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
