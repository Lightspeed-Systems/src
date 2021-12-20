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
use warnings;


use Getopt::Long;
use File::DosGlob;
use Content::File;


# Options
my $opt_input_file;
my $opt_output_file;
my $opt_help;
my $opt_version;


my $_version = "1.0.0";
my %urls;
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
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	die "You need to enter at least 2 file names to combine root domains\n" if ( $#ARGV < 1 );

	my @input;
    	while ( my $file = shift )
		{	push @input, $file;
			$opt_output_file = $file;
		}


	print "Combining root domains in files";

 
	my $file_counter = 0 + 0;
	foreach ( @input )
		{	my $item = $_;
			next if ( ! $item );

               		 # Handle wildcards
                		 if ( $item =~ /\*/ || $item =~ /\?/ )
                   			{	$item = "*" if ( $item eq "*.*" );

                       				# Loop through the globbed names
                      				 my @glob_names = glob( $item );

                       				foreach ( @glob_names )
                           					{	$file_counter++;
							   
							my $file = $_;
							&ReadFile( $file );
						}
                           			}
			else
				{	$file_counter++;
					&ReadFile( $item );
				}
                     	}


 
     	#  Sort the url list
     	@url_list = sort( keys %urls );

	print "\nCreating file $opt_output_file ...\n";
 
 	open( OUTPUT, ">$opt_output_file" ) or die ( "Unable to open $opt_output_file: $!\n" );

      	foreach ( @url_list )
         		{
              			my $new_url = $_;
               		print OUTPUT "$new_url\n";
          		}

    	close OUTPUT;

	print "\nDone\n";
    exit;
}




################################################################################
# 
sub ReadFile( $ )
#
################################################################################
{
	my $file = shift;

	return( 1 ) if ( ( $file eq $opt_output_file )  &&  ( ! -e $opt_output_file ) );

	print " $file";

	open( FILE, "<$file" ) or die( "Unable to open file $file: $!\n" );
   
	while (<FILE>)
		{
           			chomp;
           			next if (!length);  #  Ignore empty lines
           			next if /^#/;  #  Skip comments
  
           			my $new_url = $_;

			$new_url = &CleanUrl( $new_url );
			next if ( ! $new_url );

			my $root = &RootDomain( $new_url );

			next if ( ! $root );

			my $trim = &TrimWWW( $root );
			next if ( ! $trim );

			$urls{ $trim } = 1;
		}

	close FILE;

	return( 1 );
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
