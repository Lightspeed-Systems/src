################################################################################
#!perl -w
#
# Rob McCarthy's StopBadware - Screen scrape URLs from the StopBadware.org website
# 
# Copyright 2007 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use HTTP::Request;
use HTTP::Response;
use LWP::ConnCache;
use LWP;
use LWP::Simple;
use LWP::UserAgent;


use Content::File;



my $_version = "1.00.00";
my $opt_debug;
my $opt_version;
my $opt_verbose;
my $opt_wizard;
my $opt_help;
my $opt_file = "StopBadware.txt";
my $opt_search_origin;



my $ua;		# The user agent for reuse
my $cache;	# The connection cache for reuse
my @urls;	# The array of URLS that I found



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
		"f|file=s"		=> \$opt_file,
		"s|sorigin=i"	=> \$opt_search_origin,
		"v|verbose"		=> \$opt_verbose,
		"w|wizard"		=> \$opt_wizard,
		"h|help"		=> \$opt_help,
		"x|xxxdebug"	=> \$opt_debug
    );


    &StdHeader( "StopBadware Utility" ) if ( ! $opt_wizard );
	
    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );
	
	&TrapErrors();

	
	print "Writing output URLs to $opt_file ...\n";
	print "Using search origin $opt_search_origin ...\n" if ( $opt_search_origin );
	
	my $mode = ">";
	$mode = ">>" if ( $opt_search_origin );
	
	if ( ! open( OUTPUT, "$mode$opt_file" ) )
		{	print "Error opening $opt_file: $!\n";
			exit( 0 );
		}


	my $done;
	my $search_origin = $opt_search_origin;
	$search_origin = 0 + 0 if ( ! $search_origin );
	
	my $total = 0 + 0;

	
	if ( ! $opt_search_origin )	
		{	$total = &FirstPage();
			$done = 1 if ( ! $total );
		}

	my $error_count = 0 + 0;
	
	while ( ! $done )
		{
			my $count = &PostForm( $search_origin );
			
			$search_origin += $count if ( $count );
			
			if ( ! defined $count )	# There must have been an error
				{	$error_count++;
					
					if ( $error_count > 10 )
						{	print "$error_count errors in a row so quitting ...\n";
							$done = 1;
						}
					else
						{	print "Had an error, so waiting for 10 seconds ...\n" if ( $error_count == 1 );
							print "Had $error_count errors in a row, so waiting for another 10 seconds ...\n" if ( $error_count == 1 );
							sleep( 10 );
						}
				}
			elsif ( ! $count )
				{	$done = 1;
					$error_count = 0 + 0;
				}
			else
				{	$total += $count;
					$error_count = 0 + 0;
				}
		}
	
	close( OUTPUT );
	
	print "Found $total badware links\n" if ( $total );
	
	&StdFooter();
	
    exit;
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = "StopBadwareErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	print "Error logging set to $filename\n"; 
}



################################################################################
# 
sub FirstPage()
#
#  Get the first page of the StopBadware.org URLs
#  Return the count of URLs found
#
################################################################################
{	
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}

	$| = 1;

	if ( ! $ua )
		{	$ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 1000000 );
			$ua->timeout( 5 * 60 );  #  Wait for a long time

			$ua->conn_cache( $cache );
		}

	my $url = "http://www.stopbadware.org/home/reportsearch?searchtext=searchfulllist";

	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $ua->request( $req );

	if ( $response->is_error() )
		{	my $error = $response->status_line;
			print "Request error: $error\n";
			my ( $retval, $str ) = split /\s/, $error, 2;

			return( undef );  #  Return that an error happened
		}

	my $content = $response->content;

	my $count = &ParseContent( \$content );

	return( $count );	
}



################################################################################
# 
sub PostForm( $ )
#
#  Get a page of StopBadware.ord URLs
#  Return the count of URLs found - or undef if an error
#
################################################################################
{	my $search_origin = shift;
	
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}

	$| = 1;

	if ( ! $ua )
		{	$ua = LWP::UserAgent->new();
			$ua->agent("Schmozilla/v9.14 Platinum");

			$ua->max_size( 1000000 );
			$ua->timeout( 5 * 60 );  #  Wait for a long time

			$ua->conn_cache( $cache );
		}

	my $url = "http://www.stopbadware.org/home/reportsearch";
		

	print "Searching for more URLs: search origin $search_origin ...\n";
	
	my $response = $ua->post(
		$url,
		[	'searchtext'	=> 'searchfulllist',
			'searchorigin'	=> $search_origin,
			'commit'		=> 'Next'
		],
	'Content_Type' => 'form-data' );
	
	
	my $ok = $response->is_success();
	my $status = $response->status_line;
	my $content = $response->content;

	if ( ! $ok )
		{	print "Error: $status\n";

			#print "Content: $content\n";
			
			return( undef );
		}
	
	my $count = &ParseContent( \$content );
	
	return( $count );
}



my $last_url;	# The last page of URLs first URL - used to stop getting duplicates
################################################################################
# 
sub ParseContent( $ )
#
#  Given a reference to some content, parse it for URLs
#  Return the count of URLs found
#
################################################################################
{	my $content_ref = shift;
	
	my @lines = split /\n/, $$content_ref;

	my $count = 0 + 0;
	my $line_count = 0 + 0;	
	
	my $first_url;
	
	foreach ( @lines )
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );

			$line_count++;
			
			$line =~ s/\s/ /g;
			
			# Is this line one of the searchrows?
			next if ( ! ( $line =~ m/\"searchrow\"/ ) );

			print "Line: $line\n" if ( $opt_verbose );
			
			my ( $crap, $url ) = split /reportname\=/, $line, 2;
			next if ( ! $url );

			( $url, $crap ) = split /\%2F\" target\=\"\_blank\"/, $url, 2;
			next if ( ! $url );
			
			( $url, $crap ) = split /\<\/a\>/, $url, 2;
			next if ( ! $url );
			
			# Reverse out any escaped % signs
			$url =~ s/\%25/\%/g;

			# Reverse out any escaped /
			$url =~ s/\%2f/\//gi;

			( $url, $crap ) = split /\/\"\>\(/, $url, 2;
			next if ( ! $url );
			
			( $url, $crap ) = split /\/\&amp\;reportident/, $url, 2;
			next if ( ! $url );

			print "URL: $url\n" if ( $opt_verbose );
			
			push @urls, $url;
			
			print OUTPUT "$url\n";
			
			$count++;
			
			if ( ! $first_url )
				{	$first_url = $url;
					print "First URL: $first_url\n";
					
					if ( ( $last_url )  &&  ( $first_url eq $last_url ) )
						{	print "This search origin is a duplicate page\n";
							return( 0 + 0 );
						}
				}
		}
	
	print "Found $count more URLs\n";
	
	$last_url = $first_url;
	
	return( $count );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "StopBadware Utility";

    print <<".";
Usage: $me

Downloads virus and spyware URLs from the StopBadware.org website.

  -f, --file FILE        file name to write results to,
                         default is StopBadware.txt
  -s, --search           search origin to use when restarting
  -h, --help             show this help text
  -v, --verbose          verbose mode
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
    my $me = "StopBadware";

    print <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################

__END__

:endofperl
