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
# Rob McCarthy's version of grading spam perl - IpmRealTimeSpam.cmd
#
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;


use Fcntl;
use Getopt::Long;


################################################################################
#
MAIN:
#
################################################################################
{

     # Get the options
     my $item = shift;

     if ( !$item )
        {  print "You must enter the directory containing the files to smash\n";
           exit( -1 );
        }

    if ( ! -d $item )
        {  print "You must enter the directory containing the files to smash\n";
           exit( -1 );
        }
       
     print "Smashing files in directory $item\n";

     # Process the directory
     opendir DIR, $item;

     my $file_counter = 0;
     while ( my $file = readdir( DIR ) )
        {
             # Skip subdirectories
             next if (-d $file);

            #  make sure the file name starts with qf
            next if ( !( $file =~ m/^qf/ ) );

            my $dfile = $file;
            $dfile =~ s/^qf/df/;

            my $hfile = $file; 
            $hfile =~ s/qf//;
 
            $file_counter++;
            &SmashFiles( $item, $file, $dfile, $hfile );
        }

     print "Smashed $file_counter files\n";

     exit;
}
###################    End of MAIN  ################################################



################################################################################
#
sub SmashFiles( $$$$ )
#
#  smash 2 files together, making a third file
#
################################################################################
{   my $dir = shift; 
    my $file = shift;
    my $dfile = shift;
    my $hfile = shift;
    my $lines;
    my $nodf;
    my $noqf;

    print "Smashing $file and $dfile into $hfile ...\n";
    open TEMP, ">>$dir\\$hfile";
    open QFTEMP, "<$dir\\$file" or $noqf = -1;
    open DFTEMP, "<$dir\\$dfile" or $nodf = -1;

    my @qf;
    if ( ! $noqf )
      {  while ( <QFTEMP> )
            {  push @qf, $_;  }
      }

    my @df;
    if ( ! $nodf )
      {  while ( <DFTEMP> )
            {  push @df, $_;  }
      }

    close( QFTEMP );
    close( DFTEMP );

    foreach $lines ( @qf )
	{
	print TEMP $lines;
	}
     foreach $lines ( @df )
	{
	print TEMP $lines;
	}

     close(TEMP);
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
