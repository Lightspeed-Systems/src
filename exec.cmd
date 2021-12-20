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

# Rob McCarthy's exec command to execute a command line on every file in a directory


# Pragmas
use strict;
use warnings;


use Getopt::Long;
use File::DosGlob;
use Cwd;


# Options
my $opt_input_file;
my $opt_output_file;
my $opt_help;
my $opt_version;


my $_version = "1.0.0";
my %urls;


################################################################################
#
MAIN:
#
################################################################################
{
     #  Build up the command line to issue
    my  $cmd;
    while ( my $arg = shift ) 
      {  if ( !$cmd )  {  $cmd = $arg;  }
         else  {  $cmd = $cmd . " " . $arg;  }
      }

    if ( ! defined $cmd )
    	{	print "No command to execute\n";
		exit( 0 );
	}

    print "Exec command = $cmd\n";

    my $dir = getcwd;
    $dir =~ s#\/#\\#gm;

  	my $dir_handle;

	print "Reading in file names ...\n";
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";
	my @allfiles = readdir $dir_handle;
	closedir $dir_handle;

	my $counter = 0 + 0;
	foreach( @allfiles )
		{	
			my $file = $_;
			next if ( ! defined $file );

			next if ( $file eq "." );
			next if ( $file eq ".." );

			next if ( -d $file );
	
			$counter++;
			my $system_cmd = "$cmd $file";

			print "Exec command = $system_cmd\n";
			system $system_cmd ;
         		}

	print "Execute $cmd on $counter files\n";
    exit;
}




################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
Try '$me --help' for more information.
.
    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
Usage: $me [OPTION(s)]  source (wildcard allowed) output
Combines lists of URLs into one large list
    
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
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
$me $_version
.
    exit;
}


################################################################################

__END__

:endofperl
