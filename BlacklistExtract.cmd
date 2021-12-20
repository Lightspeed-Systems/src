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
# Rob McCarthy's version of extracting IP addresses from Blacklist messages
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
my $opt_filename = "blacklist\.txt";
my $opt_output = "domains\.hit";



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "BlacklistExtract" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "f|filename=s" =>\$opt_filename,
        "o|output=s" =>\$opt_output,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

 
    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    open DOMAIN, ">$opt_output" or &FatalError( "Cannot open $opt_output: $!\n" );
   
    print "Extracting IP addresses from Blacklist emails ...\n";

    &AnalyzeFile( $opt_filename );
             
    close  DOMAIN;

    print "Created output file $opt_output\n";

    &StdFooter;

    exit;
}



################################################################################
#
sub AnalyzeFile ( $ )
#
################################################################################
{
    	# Get the parameters
    	my $file = shift;

	my $sourceip;
	my $sourcedomain;
	my $emailfromaddress;
	my $subject;


    	open INFILE, "<$file" or &FatalError( "Cannot open $file\n  $!" );


    	my $bytes = 0;
	my $line_counter = 0;
    	while (<INFILE>)
           {    
		chomp;
             	my $line = $_;
             	next if ( !$line );
             	my $len = length( $line );

            	$bytes += $len;   #  Count the bytes


		my $comment = $line;
		$comment =~ s/\s//g;   # crunch the spaces out
		$comment =~ s/\(//;
		$comment =~ s/\)//;

		my @parts = split /\:/, $comment;
		my $part_no = 0;
		foreach ( @parts )
		     {  $part_no++;
			my $keyword = lc( $_ );

			#  Check for a blank value
			next if ( !$parts[ $part_no ] );
			next if ( index( "sourceipsourcedomainemailfromaddresssubject", lc( $parts[ $part_no ] ) ) != -1 );
						 
			if ( $keyword eq "sourceip" )           {  $sourceip = lc( $parts[ $part_no ] );  }
			if ( $keyword eq "sourcedomain" )       {  $sourcedomain = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "emailfromaddress" )   {  $emailfromaddress = lc ( $parts[ $part_no ] );  }
			if ( $keyword eq "subject" )            {  $subject = lc ( $parts[ $part_no ] );  }
		     }

		print DOMAIN "$sourceip\n" if ( $sourceip );
		$line_counter++;
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
    my $me = "BlacklistExtract";

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
    my $me = "BlacklistExtract";

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
