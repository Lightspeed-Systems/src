################################################################################
#!perl -w
#
# Rob McCarthy's spider perl source
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;


use Getopt::Long;
use Net::DNS;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use Content::File;



# Options
my $opt_depth = 0 + 1;					# Depth to spider - default is 1 level
my $opt_input_file;     				# The file name to read the urls to spider
my $opt_output_file;     				# The file name to write the urls found out to
my $opt_version;
my $opt_help;							# Display help and exit
my $opt_wizard;							# True if I shouldn't display headers or footers
my $opt_debug;							# True if debugging
my $_version = "1.0.0";					# Current version number
my $url_counter = 0 + 1;



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
        "d|depth=s"			=> \$opt_depth,         
		"i|input=s"			=> \$opt_input_file,
        "o|output=s"		=> \$opt_output_file,
        "v|version"			=> \$opt_version,
		"w|wizard"			=> \$opt_wizard,
		"x|xxx"				=> \$opt_debug,
        "h|help"			=> \$opt_help
    );


	# Default the log file name based on the input file name and the current directory
    #  If there still is an argument, it must be the input file name
    if ( $ARGV[0] )   
		{	$opt_input_file = shift;  
		}

    if ( $ARGV[0] )   
		{	$opt_output_file = shift;  
		}

	$opt_depth = 0 + $opt_depth;
	
    &StdHeader( "Spider" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	
	
	&Spider( $opt_input_file, $opt_output_file, $opt_depth );


	&StdFooter if ( ! $opt_wizard );

   exit;
}



################################################################################
# 
sub Spider( $$$ )
#
#  Given the inputfile, outputfile, and depth, read all the linked urls
#
################################################################################
{	my $input_file	= shift;
	my $output_file = shift;
	my $depth		= shift;
	
	
	if ( ! open( INPUT, "<$input_file" ) )
		{	print "Unable to open input file $input_file: $!\n";
			return( undef );	
		}
		
	if ( ! open( OUTPUT, ">$output_file" ) )
		{	print "Unable to open output file $output_file: $!\n";
			return( undef );	
		}
		
		
	while (<INPUT>)
		{	chomp;
			next if ( ! $_ );
		
			my $url = $_;
			$url = &CleanUrl( $url );
			next if ( ! $url );
			
			my @linked_urls = &LinkedUrls( $url );
			
			foreach ( @linked_urls )
				{	next if ( ! $_ );
					print "Found URL $_\n";
					print OUTPUT "$_\n";
				}
				
			# Now recursively go down levels lower than 1
			for ( my $level = 0 + 1;  $level < $depth;  $level++ )
				{	my @level_links;
					
					foreach ( @linked_urls )
						{	my $url = $_;
							$url = &CleanUrl( $url );
							next if ( ! $url );
							
							my @links = &LinkedUrls( $url );
							push @level_links, @links;
						}
					
					foreach ( @level_links )
						{	next if ( ! $_ );
							print "Found URL $_\n";
							print OUTPUT "$_\n";
						}
						
					@linked_urls = 	@level_links;
				}
		}
	
	close OUTPUT;
	
	close INPUT;
	
	return( 1 );
}



################################################################################
# 
sub LinkedUrls( $ )
#
# Given a URL, return a list of the urls that it links to
#
################################################################################
{	my $url = shift;
	
	my @linked_urls;

	my @addresses = &URLIPAddresses( $url );
	
	
	# If I couldn't find any IP addresses, don't bother reading the URL
	return( @linked_urls ) if ( $#addresses < 0 );

	print "Reading URL # $url_counter - $url ...\n";
	$url_counter++;
	
	my $content;
	my $errmsg;
	
	( $content, $errmsg ) = &ReadUrl( $url );
	
	# If I didn't read any content there aren't going to be any URLs
	return( @linked_urls ) if ( ! $content );
	
	my $root = &RootDomain( $url );
	
	
	# Get any site and linked urls from this content
	my %link_urls;
	my %site_urls;
	
	&UrlsContent( $content, $root, \%site_urls, \%link_urls );

	@linked_urls = sort keys %link_urls;
	
	return( @linked_urls );
}



################################################################################
# 
sub URLIPAddresses( $ )
#
#  Given a URL, return all the IP addresses in DNS for it
#
################################################################################
{	my $url = shift;
	
	my @addresses;
	
	return( @addresses ) if ( ! $url );
	
	my ( $domain, $url_ext ) = split /\//, $url, 2;

	return( @addresses ) if ( ! $domain );
	
	# Is the domain an IP address itself?
	return( @addresses ) if ( &IsIPAddress( $domain ) );
	
use Net::DNS;
	my $res = Net::DNS::Resolver->new;
	
	# Wait for 8 seconds for a response
	$res->tcp_timeout( 8 );
	$res->udp_timeout( 8 );
	
	&lprint( "Querying DNS for $domain ...\n" );
	
	my $query = $res->search( $domain ); 
	if ( ! $query )
		{	my $error = $res->errorstring;
			$error = "Unknown error" if ( ! $error );
			
			# Does this domain or host exist at all?
			my $nonexisiting_domain;
			$nonexisiting_domain = 1 if ( $error eq "NXDOMAIN" );
			
			$error = "nonexisting hostname or domain" if ( $nonexisiting_domain );				
			&lprint( "DNS Query failed: $error\n" );
			
			return( @addresses );
		}
		
	foreach my $rr ( $query->answer ) 
		{	next unless $rr->type eq "A";
			my $ip = $rr->address;

			# Make sure it is a good IP address
			next if ( ! &IsValidIP( $ip ) );
			push @addresses, $ip;
		}
		
	return( @addresses );	
}



################################################################################
#
sub UrlsContent( $$ )
#
# Given the content of a url, and the root domain I am checking
# return the hash of valid site urls and linked urls
#
################################################################################
{	my $content		= shift;
	my $root		= shift;
	my $site_urls	= shift;	# These are urls that on in the same domain
	my $link_urls	= shift;	# These are other urls contained in the content
	
	
	my @data = split /\>/, $content;
	
	
	# Now check every line for URLs
	# Make a hash of all linked urls, and a hash of same site urls	
	foreach ( @data )
		{	my $line = $_;
	
			next if ( ! $line );
			
		     #  Check for hrefs
             if ( $line =~ m/href=\"/ )
                {   my ( $junk, $hurl );
					
					# Does this URL have quotes around it?
					my $quoted = 1 if ( $line =~ m/href=\"/ );
					
					( $junk, $hurl ) = split  /href=/, $line, 2;
					next if ( ! $hurl );
					
					# If it is a quoted URL, trim off the quotes and convert spaces to %20
					if ( $quoted )	
						{	$hurl =~ s/\"//;
							next if ( ! $hurl );
					
							( $hurl, $junk ) = split/\"/, $hurl, 2;
							next if ( ! $hurl );
							
							$hurl =~ s/ /\%20/g;
						}
						
					( $hurl, $junk ) = split/\s/, $hurl, 2;
					
					next if ( ! $hurl );
					
					# Is this a relative URL?
					if ( ! ( $hurl =~ m/http:\/\// ) )
						{	$hurl = $root . $hurl;
						}
						
					$hurl = &CleanUrl( $hurl );

                    next if ( ! $hurl );

					my $root_domain = &RootDomain( $hurl );

					if ( $root eq $root_domain )
						{	$$site_urls{ $hurl } = 1;
						}
					else
						{	$$link_urls{ $hurl } = 1;
						}
				}
		}
	
	
	return( 1 );
}



################################################################################
#
sub ReadUrl( $ )
#
# Given a url, return the content, or undef and an error message
#
################################################################################
{	my $url = shift;
	
    # put the URL into the format http://url
    my $url_string = "http:\/\/" . $url;

    $| = 1;

    my $ua = LWP::UserAgent->new();
    $ua->agent("Schmozilla/v9.14 Platinum");

    $ua->max_size( 100000 );
    $ua->timeout( 15 );  #  Go ahead and wait for 15 seconds

    my $req = HTTP::Request->new( GET => $url_string );
    #$req->referer("http://wizard.yellowbrick.oz");


    # Get the response
    my $response = $ua->request( $req );

    if ( $response->is_error() )
		{	lprint "Request Error: ", $response->status_line, "\n";
			my $errmsg = $response->status_line;
			return( undef, $errmsg );
		}

	my $content = $response->content;
	if ( $content =~ m/Lightspeed Systems Content Filtering/ )
		{	lprint ( "Error reading URL - redirected to Lightspeed Systems Access Denied web page\n" );
			return( undef, "Redirected to Lightspeed Systems Access Denied web page" );
		}
		
	return( $content, undef );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Spider";

    bprint <<".";
Usage: $me [OPTION(s)] inputfile outputfile
Given a file with a list of urls, this utility outputs any linked urls

  -d, --depth=NUM        the number of levels to spider down, default is 1
  -h, --help             display this help and exit
  -v, --version          display version information and exit
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
    my $me = "Spider";

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
