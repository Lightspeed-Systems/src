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
use Content::File;



################################################################################
#
MAIN:
#
################################################################################
{    my $skip_count = shift;

    open INFILE, "<domains.hit" or die "Cannot open input file: $!\n";
    open OUTFILE, ">hits.urls" or die "Cannot open input file: $!\n";
    my $count = 0;
    while (<INFILE>)
       {
           chomp;
           next if (!length);  #  Ignore empty lines

           $count++;
           if ( $count > $skip_count )
             {   # print OUTFILE  "www\.";
                  print OUTFILE "$_\n";
                 $count = 0;
             }
       }

     close INFILE;
     close OUTFILE;

 
    exit;
}





################################################################################

__END__

:endofperl
