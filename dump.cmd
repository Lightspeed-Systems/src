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
use warnings;
use strict;



use LWP::UserAgent;
use LWP::ConnCache;




################################################################################
#
MAIN:
#
################################################################################
{
	my $url = shift;
	die "You must enter url\n" if ( ! defined $url );

	my $cache = LWP::ConnCache->new;
	$cache->total_capacity( 1 );

	my $ua = LWP::UserAgent->new( );
	$ua->agent("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50215)");
			
	#$ua->max_size( 250000 );	# Read up to 250k
	$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

	$ua->conn_cache( $cache );
		
    	$url = "http:\/\/" . $url if ( ! ( $url =~ m/^http/ ) );

    	$| = 1;
	

 	my $response = $ua->get( $url );


    	if ( $response->is_error() )
		{	print "Request Error: ", $response->status_line, "\n";
			print "Unable to read URL $url\n";
			
			die;
		}

	my $content = $response->content;
	
	
	print "$content\n";
 

     exit( 0 );
}




__END__

:endofperl
