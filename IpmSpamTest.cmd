@rem = '--*-Perl-*--
@echo off
if "%OS%" == "Windows_NT" goto WinNT
perl -x -S -T "%0" %1 %2 %3 %4 %5 %6 %7 %8 %9
goto endofperl
:WinNT
perl -x -S -T %0 %*
if NOT "%COMSPEC%" == "%SystemRoot%\system32\cmd.exe" goto endofperl
if %errorlevel% == 9009 echo You do not have Perl in your PATH.
if errorlevel 1 goto script_failed_so_exit_with_non_zero_val 2>nul
goto endofperl
@rem ';

################################################################################
#!perl -w
#
# Rob McCarthy's categorize perl source
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;

use Getopt::Long;
use Net::SMTP;



# Options
my  $opt_subject = "===SPAM===: ";    #  This is default subject line to prepend
my $opt_help;
my $opt_version;
my $subject = "Test email";
my $host_ipaddress = '10.16.50.1';
my $email_from = 'rob@lightspeedsystems.com';
my $to = 'rob@lightspeedsystems.com';
my $reason = "This is my reason for blocking this email";
my $count = 1;


# Globals
my $_version = "2.0.0";



################################################################################
#
MAIN:
#
################################################################################
{
    print( "IpmSpamTest\n" );

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "a|address=s" =>\$host_ipaddress,
        "c|count=s" =>\$count,
        "f|from=s" =>\$email_from,
        "s|subject=s" =>\$subject,
        "t|to=s" =>\$to,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    chomp( $host_ipaddress );

    print "Target host ip address = $host_ipaddress\n";

    # Loop through the remaining parameters, which should all be files to scan

    my $file_counter = 0;
    my $item;

    my @files;
    while ( my $temp = shift )
      {  push @files, $temp;
      }


    foreach $item ( @files )
      {
           # Handle wildcards
           if ($item =~ /\*/ || $item =~ /\?/)
             {
                 # Loop through the globbed names
                 my @glob_names = glob $item;

                foreach ( @glob_names )
                  {   $file_counter++;
			my $mailfile = $_;
		      for ( my $i = 0;  $i < $count;  $i++ )
                      	{	&SendFile( $mailfile );
			}
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
                           for ( my $i = 0;  $i < $count;  $i++ )
                      		{	&SendFile( $file );
				}
                      }

                 closedir DIR;
              }

           # Analyze a single file
          else
             {    $file_counter++;
		  my $mailfile = $item;
                  for ( my $i = 0;  $i < $count;  $i++ )
                      	{	&SendFile( $mailfile );
			}
             }
       }
   }  #  end of foreach item


   print "\nDone.\n";

exit;
}
################################################################################




################################################################################
# 
sub SendFile( $ )
#
#  Given a file name
#  email the file
#
################################################################################
{   my $filename = shift;

    &SMTPForward( $filename, $subject, $host_ipaddress, $email_from, $reason, $to  );    #  Try to open the file.  If I can't, just return
    
    return( 0 );
}



################################################################################
# 
sub SMTPForward( $$$$$$ )
#
#  Given a file name, Subject line to prepend, SMTP server IP address, From: Addresss and To: addresses, 
#  email the file
#
################################################################################
{   my $filename = shift;
    my $subject = shift;
    my $host_ipaddress = shift;
    my $email_from = shift;
	my $reason = shift;
    my @to = @_;
	
	#  Just return if the spam file doesn't exist or can't be read
	if ( ! -r $filename )
	  { print( "Can not read file $filename\n" );
		return( -1 );	  
	  }

    #  This can fail with a bad error if the host isn't there, so wrap it with an eval
    my $smtp;
    eval {  $smtp = Net::SMTP->new( $host_ipaddress );  };

    if ( !$smtp )
      {  print( "Unable to connect to SMTP server at $host_ipaddress\n" );
         return( -1 );
      }

    my $domain = $smtp->domain;
    print "SMTP host domain = $domain\n";


    my $to_list;
    foreach ( @to )
      {  $to_list = ( $to_list . ";" . $_ ) if ( $to_list );
         $to_list = $_ if ( !$to_list );
      }


    print( "\nForwarding spam mail ...\n" );
    print( "File: $filename\n" );
    print( "From: $email_from\n" );
    print( "To: $to_list\n" );
    

    $smtp->mail( $email_from );	
    $smtp->to( $to_list );

    $smtp->data();
    open INFILE, "<$filename" or return( -2 );

    my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat INFILE;
    print "File size = $size bytes\n";

    while ( <INFILE> )
          {  $smtp->datasend( $_ );
          }
    close INFILE;
    $smtp->dataend();


    $smtp->quit;

    print( "Done forwarding email\n" );
	
    return( 0 );
}



################################################################################
# 
sub errstr($)
#  
################################################################################
{
    print shift;

    return( -1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "IpmSpamTest";

    print "$me\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
.
   &StdFooter;

    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmSpamTest";

    print <<".";
Usage: $me [OPTION(s)]
Sends test smtp emails to the server

  -a, --address        SMTP host name or address to send to
  -f, --from           from email address
  -s, --subject        subject line to send
  -t, --to             email address to mail to
  -h, --help           display this help and exit
  -v, --version        display version information and exit
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
    my $me = "IpmSpamTest";

    print <<".";
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
