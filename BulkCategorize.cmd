@rem = '--*-Perl-*--
@echo off
if "%OS%" == "Windows_NT" goto WinNT
perl -x -S -T "%0" %1 %2 %3 %4 %5 %6 %7 %8 %9
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

# Rob McCarthy's split command categorize all the urls in all the files in a given directory


# Pragmas
use strict;
use Socket;
use Errno qw(EAGAIN);
use Getopt::Long;


# Options
my $opt_help;
my $opt_version;
my $opt_child = 4;   #  How many child tasks to launch to categorize a lot of urls
my  $opt_tmpfile = 'BulkCategorize.tmp';
my $opt_cat = " ";


my $_version = "1.0.0";
my @files;




################################################################################
#
MAIN:
#
################################################################################
{

    while ( my $opt = shift )
        {  $opt_cat = $opt_cat . $opt . " ";
        }


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "c|child=s" => \$opt_child,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


   push ( @ARGV, '.\\' ) if ( !$ARGV[ 0 ] );




   #  Get rid of any temp files ...
   unlink( $opt_tmpfile );
   for ( my $i = 1;  $i < 20;  $i++ )
      {   my $filename = $opt_tmpfile . ".$i";
          unlink( $filename );
      } 

   my  $item;
   my  $file;

   # Loop through the remaining parameters, which should all be files to bulk categorize
   foreach ( @ARGV )
     {   $item = $_;
         # Handle wildcards
         if ($item =~ /\*/ || $item =~ /\?/)
           {
               # Loop through the globbed names
               my @glob_names = glob $item;

               foreach (@glob_names)
                 {
                    &AddFile($_);
                }
          }

       # Handle single entities
       else
         {
             # Analyze a directory
             if (-d $item)
               {
                   # Process the directory
                  opendir DIR, $item;

                  while ( $file = readdir( DIR ) )
                     {
                         # Skip subdirectories
                         next if (-d $file);

                         if ( $item eq  '.\\' )  {  &AddFile( $file );  } 
                         else {  &AddFile( "$item\\$file" );  }
                     }

                 closedir DIR;
              }

           # Analyze a single file
           else
             {
                &AddFile( $item );
             }
       }  # end of single entities
   }  #  end of foreach $item


    print STDERR "Joining all the files ... \n";
    my @args;
    push( @args, "join" );
    foreach ( @files )  {  push( @args, $_ ) };
    push( @args, $opt_tmpfile );

    system( @args );
 
    # Now run the deldups command with the right arguments
    my $cmd = "deldups $opt_tmpfile";
    system( $cmd );

    if ( $opt_child > 1 )
      {
          print "Spawing child processes ... \n";

          # Now split the temp file up into the right number of part
          $cmd = "split -n $opt_child $opt_tmpfile";
          system( $cmd );

          my  $pid;
          for ( my $i = 0;  $i < $opt_child;  $i++ )
             {  #  Now fork off my child processes
                FORK:{
                       if ( $pid = fork )  {  next;  }

                       elsif ( defined $pid )
                         {  print "Launching IpmCategorize ... \n";
                            my  $file_num = $i + 1;
                            $cmd = 'IpmCategorize -p -n 3 ' . $opt_cat . $opt_tmpfile . ".$file_num";

                            exec $cmd;
                         }

                       elsif ( $! == EAGAIN )  {  sleep 5;  redo FORK;  }

                       else  { die "Can't fork: $!\n";  }

                }  # end of FORK
             }  # end of for loop
          exit;
      }


    # Now run the IpmCategorize command with the right arguments
    $cmd = "IpmCategorize -p -n 3 $opt_cat $opt_tmpfile";
    system( $cmd );


   #  Get rid of any temp files ...
   unlink( $opt_tmpfile );
   for ( my $i = 1;  $i < 20;  $i++ )
      {   my $filename = $opt_tmpfile . ".$i";
          unlink( $filename );
      } 


    exit;
}



################################################################################
# 
sub AddFile( $ )
#
################################################################################
{
    my  $file = shift;

    push  @files, $file;
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "BulkCategorize";

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
    my $me = "BulkCategorize";
    print <<".";
Usage: $me [OPTION(s)]  input-file
Splits a large file of URLs into multiple files that are approx. the same size
    
  -c, --child       number of child tasks to process the unknown urls
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
    my $me = "BulkCategorize";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
