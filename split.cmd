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

# Rob McCarthy's split command to split a list of URLs into file multiple files


# Pragmas
use strict;
use Socket;

use Getopt::Long;
use URI::Heuristic;


use Content::File;



# Options
my $opt_input_file;
my $opt_help;
my $opt_version;
my $opt_numeric;
my $opt_size;


my $_version = "1.0.0";
my @url_list;  #  Urls in list format


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
        "i|input=s" => \$opt_input_file,
        "n|numeric=i" => \$opt_numeric,
        "s|size=i" => \$opt_size,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

    if ( !$opt_input_file )  {  $opt_input_file = shift;  }

    &UsageError("You must specify the input file to split up") unless ( $opt_input_file );

    &UsageError("You must specify how many files or the size of the files to split the input file into")  if ( ( ! $opt_numeric )  &&  ( ! $opt_size ) );


    # Read the URLs
    my  $counter = 0 + 0;
    my  $new_url;


    open( INFILE, "<$opt_input_file" ) or die "Cannot open input file $opt_input_file: $!\n";
    print "Reading file $opt_input_file\n";

    while ( my $line = <INFILE> )
 	{	chomp( $line );
           	next if ( ! length( $line ) );  #  Ignore empty lines
           	next if $line =~ m/^#/;  #  Skip comments
           	next if $line =~ m/^\s*(#|$)/;

		$new_url = $line;

 		next if ( ! defined $new_url );
		
 		$counter++;
		push @url_list, $new_url;
       }

     close( INFILE );

     print "Read in a total of $counter URLs from file $opt_input_file\n";


     my  $urls_per_file;

     if ( $opt_numeric )
     	{	$urls_per_file = $counter / $opt_numeric;
	}
     else
	{	$urls_per_file = $opt_size;
		$opt_numeric = $counter / $opt_size;

		my $int_numeric = int( $opt_numeric );

		   #  Round it up one if it isn't even
    		 $opt_numeric = 1.0 + $int_numeric if ( $opt_numeric != $int_numeric );
	}

	my $int_per_file = int( $urls_per_file );

     #  Round it up one if it isn't even
     $urls_per_file = 1.0 + $int_per_file if ( $urls_per_file != $int_per_file );

	print "Splitting file $opt_input_file into $opt_numeric files of approx. $urls_per_file URLs each\n";
 

	# Open the output files
	my  $filename = $opt_input_file . ".1";

	open( OUTPUT, ">$filename" ) or die "Cannot create output file: filename,\n$!\n";
	print "Creating file $filename\n";

      	my $file_counter = 0 + 0;
      	my $file_number = 0 + 1;

	my $last_root;
	foreach ( @url_list )
         {	$new_url = $_;
		next if ( ! defined $new_url );

		my $root = &RootDomain( $new_url );
		next if ( ! defined $root );	

		print OUTPUT "$new_url\n";
               
		$file_counter++;

		# Make sure that urls with the same root domain end up in the same file

		next if ( ( defined $last_root )  &&  ( $root eq $last_root ) );

		$last_root = $root;

              	if ( $file_counter >= $urls_per_file )
                 {   $file_counter = 0 + 0;
                     $file_number++;

                     close( OUTPUT );
                     $filename = $opt_input_file . ".$file_number";

                     open( OUTPUT, ">$filename" ) or die "Cannot create output file: filename: $!\n";
                     print "Creating file $filename\n";
                 }
         }


    close( OUTPUT );

	print "Done.\n";

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
Usage: $me [OPTION(s)]  input-file
Splits a large file of URLs into multiple files that are approx. the same size
    
  -n, --number       number of files to split into
  -s, --size         size of files to split into
  -i, --input=FILE   input file to split up
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
