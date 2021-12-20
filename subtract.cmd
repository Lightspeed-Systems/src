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

# Rob McCarthy's subtract command to subtract a file of URLs from another file of URLs


# Pragmas
use strict;
use Socket;

use Getopt::Long;
use URI::Heuristic;


# Options
my $opt_help;
my $opt_version;
my $source_file;
my $subtract_file;
my $remainder_file;
my $intersection_file;


my $_version = "1.0.0";
my %urls;
my %dom;
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

    # Read the URLs
    my  $counter = 0;
    my  $new_url;

    my  $source_file = shift;
    my  $subtract_file = shift;
    my  $remainder_file = shift;
    my  $intersection_file = shift;

    &Usage() if ( !$remainder_file );     

    open INFILE, "<$subtract_file" or die "Cannot open subtract file $subtract_file: $!\n";
    print "Reading subtract file $subtract_file\n";

    while ( my $line = <INFILE> )
       {
          chomp( $line );
          next if ( ! length( $line ) );  #  Ignore empty lines
          next if $line =~ m/^#/;  #  Skip comments
          next if $line =~ m/^\s*(#|$)/;

          $counter++;
 	my $junk;
          ( $new_url, $junk ) = split /\t/, $line, 2;

          &insert_url( $new_url );
      }

    close( INFILE );

    print "Read in $counter URLs from subtract file $subtract_file\n";


    # Open the remainder file
    open( OUTPUT, ">$remainder_file" ) or die "Cannot create remainder file: $remainder_file,\n$!\n";

    # Open the intersect file - if I am supposed to
    if ( $intersection_file )
    	{	open( INTERSECT, ">$intersection_file" ) or die "Cannot create intersect file: $intersection_file,\n$!\n";
	}

    # Open the source file
    open( INFILE, "<$source_file" ) or die "Cannot open source file $source_file: $!\n";
    print "Reading source file $source_file\n";


    $counter  = 0.0;
    my  $remainder_count = 0 + 0;
    my  $intersect_count = 0 + 0;

    while ( my $line = <INFILE> )
       {
          chomp( $line );
          next if ( ! length( $line ) );  #  Ignore empty lines
          next if $line =~ m/^#/;  #  Skip comments
          next if $line =~ m/^\s*(#|$)/;

          $counter++;
 
  	my $junk;
          ( $new_url, $junk ) = split /\t/, $line, 2;


          # Do I already know this exact URL?
          if ( ! exists( $urls{ $new_url } ) )
            {  print OUTPUT "$new_url\n";
               $remainder_count++;
            }
          else
            {  print INTERSECT "$new_url\n" if ( $intersection_file );
               $intersect_count++;
            }
      }

    close ( INFILE );
    close ( OUTPUT );
    close ( INTERSECT ) if ( $intersection_file );

    print "Read in $counter URLs from source file $source_file\n";
    print "Created remainder file $remainder_file with $remainder_count URLs total.\n";
    print "Found $intersect_count URLs that intersected.\n";

    exit;
}




################################################################################
# 
sub insert_url
#
################################################################################
{
    my $url = shift;

    my $domain;
    my $url_ext;
    my $old_url_ext;
    my $old_url;

    $url = lc( URI::Heuristic::uf_urlstr( $url ) ); 

     #  Clean off the http:// and the trailing /
     $url =~ s#^http:\/\/##im;
     $url =~ s#\/$##m;


     # Do I already know this exact URL?
     if ( exists( $urls{ $url } ) )
       {   $urls{ $url } += 1.0;   # If so, just count it and move on 
            return;
       }

     # Do I already know another URL from this domain?
     ( $domain, $url_ext ) = split /\\|\//, $url, 2;

     if ( exists( $dom{ $domain } ) )  #  Ok - I've seen this domain before
       {  $old_url_ext = $dom{ $domain };

          #  Build back the url I already have
          $old_url = $domain;
          if ( $old_url_ext )
            {  $old_url = $domain . "\/" . $old_url_ext;  } 

           # Is it already a root domain, i.e. old_url_ext is unititalized?
           if ( !$old_url_ext )
              {  $urls{ $old_url } += 1.0; 
                  return;
              }

           # Is the new URL a root domain, i.e. url_ext is unititalized?
           if ( !$url_ext )
             {  #  Create the new key                
                $urls{ $url } = $urls{ $old_url } + 1.0; 

                 #  Delete the old key
                delete $urls{ $old_url };
               
                #  Set the domain value to the new url_ext
                $dom{ $domain } = $url_ext;
                return;
             }

           # Could the old url ext be a higher level than the new url ext?
           #  The old url ext should be contained in the new url ext
           #  So just ignore the new url
           if ( index( $url_ext,  $old_url_ext, 0 ) != -1 )
             {  $urls{ $old_url } += 1.0; 
                 return;
             } 

           # Could the new url ext be a higher level than the old url ext?
           if ( index( $old_url_ext, $url_ext, 0 ) != -1 )
             {   #  If so, then throw away the old_url and keep the new one
                # Create the new key
                $urls{ $url } = $urls{ $old_url } + 1.0; 

                 #  Delete the old key
                delete $urls{ $old_url };

                #  Set the domain value to the new url_ext
                 $dom{ $domain } = $url_ext;
                 return; 
             }

       }  # End of if domain exists


    #  Otherwise, add it to the list
    $urls{ $url } = 1.0;
    $dom{ $domain } = $url_ext;
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
Usage: $me source_file subtract_file remainder_file [intersect_file]
Subtract a list of URLs from source list of URLs,
creating a remainder list of URLs.  If specified, the
intersection of the two files will also be created.
    
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
