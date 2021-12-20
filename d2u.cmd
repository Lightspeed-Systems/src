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

# Rob McCarthy's Dos to Unix to text converter



################################################################################
#
MAIN:
#
################################################################################
{
    my $infile = shift;
    my $outfile = "tmp.txt";

    open INFILE, "<$infile" or die "Cannot open input file $infile: $!\n";
    open OUTFILE, ">$outfile" or die "Cannot open output file $outfile: $!\n";

    while (<INFILE>)
       {
           chomp;
           print OUTFILE "$_";
       }

     close INFILE;
     close OUTFILE;

     rename( $outfile, $infile ) or die "Cannot rename $outfile to $infile: $!\n";

    exit;
}



################################################################################

__END__

:endofperl
