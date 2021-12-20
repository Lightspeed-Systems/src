################################################################################
#!perl -w
#
# Rob McCarthy's NetTrekker - Screen scrape URLs from the NetTrekker website
# 
# Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use HTTP::Request;
use HTTP::Response;
use HTTP::Cookies;
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
my $opt_content;		# If true, then save all the http content to NetTrekkerContent.txt
my $opt_max = 0 + 10;	# If set, this is the maximum number of NetTrekker URLs to read
my $opt_reload;
my $opt_all_reload;
my $opt_linkid;


my $ua;		# The user agent for reuse
my $cache;	# The connection cache for reuse


my %site_urls;		# This is a hash of urls found on NetTrekker with the root domain nettrekker.com - key is url, val is the number of bytes read
my %link_urls;		# This is a hash of urls found on NetTrekker with the toot domain <> nettrekker.com - key is url, val is number of bytes read
my %link_ids;		# This is a hash of NetTrekker link id urls as the key, val is the tabbed urls that were found
my @link_id_base;	# This is a array of the base URLs found from a NetTrekker link id, and the NetTreker link id URL it came from
my @link_domain;	# This is an array of domains that were screen scraped off of NetTrekker in the format they use for links



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
		"a|allreload"	=> \$opt_all_reload,
		"c|content"		=> \$opt_content,
		"l|linkid"		=> \$opt_linkid,
		"m|max=i"		=> \$opt_max,
		"r|reload"		=> \$opt_reload,
		"v|verbose"		=> \$opt_verbose,
		"w|wizard"		=> \$opt_wizard,
		"h|help"		=> \$opt_help,
		"x|xxxdebug"	=> \$opt_debug
    );


    &StdHeader( "NetTrekker Utility" ) if ( ! $opt_wizard );

	
    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );
	
	&TrapErrors();

    &SetLogFilename( ".\\NetTrekker.log", undef );


	# Load the initial URLs to crawl
	if ( ( $opt_reload )  ||  ( $opt_all_reload ) )
		{	&NetTrekkerLoad( $opt_all_reload );
		}
	else
		{	# Put the initial URL to start crawling from into the site URLs
			$site_urls{ "school.nettrekker.com/subject/" } = 0 + 0;

#test url for LinkID
#$site_urls{ "school.nettrekker.com/redirecter/?link_id=290966" } = 0 + 0;

			# Delete any existing data
			unlink( "NetTrekkerContent.txt" );
			unlink( "NetTrekkerLink.txt" );
			unlink( "NetTrekkerLinkID.txt" );
			unlink( "NetTrekkerLinkBase.txt" );
		}
	
	
	if ( $opt_content )
		{	open( CONTENT, ">>NetTrekkerContent.txt" ) or die( "Error opening NetTrekkerContent.txt: $!\n" );
			lprint "Writing HTTP content to NetTrekkerContent.txt ...\n";
		}
		
	
	my $ok = &NetTrekkerLogin( "lightspeed", "trial" );
	
	die "Unable to login correctly\n" if ( ! $ok );
	

	# Are there URLs that I need to ignore?
	my $ignore_count = 0 + 0;
	if ( open( NETIGNORE, "<NetTrekkerIgnore.txt" ) )
		{	while ( my $line = <NETIGNORE> )
				{	chomp( $line );
					next if ( ! $line );
					$line =~ s/^http\:\/\///;
					
					$site_urls{ $line } = 1;
					$ignore_count++;
				}
				
			close( NETIGNORE );
		}
		
	lprint( "Loaded $ignore_count URLs to ignore from NetTrekkerIgnore.txt ...\n" ) if ( $ignore_count );

	
	# Start crawling
	lprint "Starting crawling ...\n";
	&NetTrekkerCrawl();
	lprint "Finished crawling ...\n";
	
	
	close( CONTENT ) if ( $opt_content );
	
	
	# Dump out what I've learned
	&NetTrekkerDump();
	
	
	&StdFooter();
	
    exit;
}



################################################################################
# 
sub NetTrekkerLoad( $ )
#
#  Load from disk everything that I've learned
#
################################################################################
{	my $all = shift;	# True if I am supposed to reload everything into memory
	
	if ( open( SITE, "<NetTrekkerSite.txt" ) )
		{	my $count = 0 + 0;
			while ( my $line = <SITE> )
				{	chomp( $line );
					next if ( ! $line );
					my ( $key, $val ) = split /\t/, $line, 2;
					
					$val = 0 + $val if ( $val );
					$val = 0 + 0 if ( ! $val );
					
					$site_urls{ $key } = $val;
					$count++;
				}
				
			close( SITE );
			
			lprint "Loaded $count site URLs from NetTrekker.txt\n";
		}
		

	# If I am not supposed to reload everything then I am done right here	
	return( 1 ) if ( ! $all );
	
	
	if ( open( LINK, "<NetTrekkerLink.txt" ) )
		{	while ( my $line = <LINK> )
				{	chomp( $line );
					next if ( ! $line );
					my ( $key, $val ) = split /\t/, $line, 2;
					
					$val = 0 + $val if ( $val );
					$val = 0 + 0 if ( ! $val );
					
					$link_urls{ $key } = $val;
				}
				
			close( LINK );
		}
	

	# Keys start the line, val urls start with a tab
	if ( open( LINKID, "<NetTrekkerLinkID.txt" ) )
		{	my $key;
			my $val;
			
			while ( my $line = <LINKID> )
				{	chomp( $line );
					next if ( ! $line );
					
					# If the line doesn't start with a tab, then it is a key
					if ( ! ( $line =~ m/^\t/ ) )
						{	# Save the last key/val pair
							$link_ids{ $key } = $val if ( $key );
							
							$key = $line;
							$val = undef;
						}
					else	# It must be a val URL
						{	# Trim the tab off the front of the line
							$line =~ s/^\t//;
							
							$val .= "\t" . $line if ( $val );
							$val = $line if ( ! $val );
						}
				}
			
			# Save the last key/val pair
			$link_ids{ $key } = $val if ( $key );
			
			close( LINKID );
		}


	if ( open( LINKBASE, "<NetTrekkerLinkBase.txt" ) )
		{	
			while ( my $line = <LINKBASE> )
				{	chomp( $line );
					next if ( ! $line );
					
					push @link_id_base, $line;
				}
				
			close( LINKBASE );
		}
		
		
	if ( open( LINKDOMAIN, "<NetTrekkerLinkDomain.txt" ) )
		{	
			while ( my $line = <LINKDOMAIN> )
				{	chomp( $line );
					next if ( ! $line );
					
					push @link_domain, $line;
				}
				
			close( LINKDOMAIN );
		}
		
	return( 1 );
}



################################################################################
# 
sub NetTrekkerDump()
#
#  Dump to disk everything that I've learned
#
################################################################################
{
	open( SITE, ">NetTrekkerSite.txt" ) or die "Error opening file NetTrekkerSite.txt: $!\n";
	
	my @keys = sort keys %site_urls;
	
	foreach ( @keys )
		{	my $key = $_;
			next if ( ! defined $key );
			
			my $val = $site_urls{ $key };
			next if ( ! defined $val );
			
			print SITE "$key\t$val\n";
		}		
	close( SITE );
	
	
	open( LINK, ">>NetTrekkerLink.txt" ) or die "Error opening file NetTrekkerLink.txt: $!\n";
	
	@keys = sort keys %link_urls;
	
	foreach ( @keys )
		{	my $key = $_;
			next if ( ! defined $key );
			
			print LINK "$key\n";
		}		
	close( LINK );


	open( LINKID, ">>NetTrekkerLinkID.txt" ) or die "Error opening file NetTrekkerLinkID.txt: $!\n";
	
	@keys = sort keys %link_ids;
	
	# Write out each Link ID URL, and then on tabbed lines the URLS found from that Link ID
	foreach ( @keys )
		{	my $key = $_;
			next if ( ! defined $key );
			
			my $val = $link_ids{ $key };
			next if ( ! defined $val );
			
			print LINKID "$key\n";
			
			my @urls = split /\t/, $val;
			
			foreach ( @urls )
				{	print LINKID "\t$_\n";
				}
		}
		
	close( LINKID );

	
	open( LINKBASE, ">>NetTrekkerLinkBase.txt" ) or die "Error opening file NetTrekkerLinkBase.txt: $!\n";
	foreach ( @link_id_base )
		{	print LINKBASE "$_\n";
		}	
	close( LINKBASE );


	open( LINKDOMAIN, ">>NetTrekkerLinkDomain.txt" ) or die "Error opening file NetTrekkerLinkDomain.txt: $!\n";
	foreach ( @link_domain )
		{	print LINKDOMAIN "$_\n";
		}	
	close( LINKDOMAIN );

	return( 1 );
}



################################################################################
# 
sub NetTrekkerCrawl()
#
#  Crawl the NetTrekker website
#
################################################################################
{	
	my $done;
	my $total_urls = 0 + 0;
	
	while ( ! $done )
		{	my $url_count	= 0 + 0;
			my $count		= 0 + 0;
			
			while ( my ( $url, $bytes ) = each( %site_urls ) )
				{	# Ignore some URLs
					next if ( ! defined $url );
					
					# Ignore some URLs because they don't have any URLs in their content
					next if ( $url =~ m/\.gif$/i );
					next if ( $url =~ m/\.jpg$/i );
					
					# I think that these URLs don't matter
					next if ( $url =~ m/deadlink/i );
					
					# I think that these URLs don't matter
					next if ( $url =~ m/timeline/i );
					
					# I think that these URLs don't matter
					next if ( $url =~ m/index\.epl/i );
					
					# Ignore results URLs because these URLs can also be found by subject
					next if ( $url =~ m/results/i );
					
					# These types of URLs are duplicates
					next if ( $url =~ m/\&dict\=1$/i );
					
					# Have I already read this URL?
					next if ( $bytes );
					
					# Am I supposed to only look at link IDs?
					next if ( ( $opt_linkid )  &&  ( ! ( $url =~ m/\?link_id\=/i ) ) );
					next if ( ( $opt_linkid )  &&  ( ! ( $url =~ m/redirecter/i ) ) );
					
					my $ok = &NetTrekkerURL( $url, $total_urls );
					
					$url_count++ if ( $ok );
					$count++;	
					$total_urls++;
					
					last if ( ( $opt_max )  &&  ( $opt_max <= $total_urls ) );
				}
				
			$done = 1 if ( ! $url_count );
			$done = 1 if ( ( $opt_max )  &&  ( $opt_max <= $total_urls ) );
		}
	
	
	if ( ( $opt_max )  &&  ( $opt_max <= $total_urls ) )
		{	lprint "Reached the max URLs to read of $opt_max\n";
		}
	else
		{	lprint "Ran out of URLs to read\n";
		}
		
	return( 1 );
}	



################################################################################
# 
sub NetTrekkerURL( $$ )
#
#  Given a netTrekker URL, grab the content and extract all the URLs
#  Return the bytes read, or undef if an error
#
################################################################################
{	my $url			= shift;
	my $total_urls	= shift;
	
	
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}
	
    # put the URL into the format http://url
    my $url_string = $url;
    $url_string = "http:\/\/" . $url if ( ! ( $url =~ m/^http/ ) );

    $| = 1;


	if ( ! defined $ua )
		{	$ua = LWP::UserAgent->new( protocols_forbidden => ['https'] );
			#$ua->agent("Schmozilla/v9.14 Platinum");
			$ua->agent("Mozilla/4.0 (compatible; MSIE 7.0;Windows NT 5.1;.NET CLR 1.1.4322;.NET CLR 2.0.50727;.NET CLR 3.0.04506.30)");
			$ua->cookie_jar( HTTP::Cookies->new( file => "$ENV{HOME}/.cookies.txt") );
			
			# The max size if commented out because some websites give a 416 error when given this parameter
			$ua->max_size( 250000 );	# Read up to 250k
			$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds

			$ua->conn_cache( $cache );
		}
		

	lprint "Reading URL # $total_urls: $url_string ...\n";
	
	
	my $response = $ua->get( $url_string );
 	lprint "Got the GET response ...\n" if ( $opt_debug );


	# Is this a link ID?  If so, then keep track.  I can tell if the root domain of the base URL is not nettrekker.com
	my $link_id;

	
	my $content		= $response->content;
	my $base		= $response->base;
	$base			= $url_string if ( ! defined $base );
	my $base_url	= &CleanUrl( $base );
	
	
	# Did I get a different root domain from the base?  I might have if NetTrekker is doing a redirect
	my $root_base = &RootDomain( $base_url ) if ( $base_url );

	
	if ( ( $root_base )  &&  ( $root_base ne "nettrekker.com" ) )			
		{	lprint "Base URL: $base_url\n";
			
			# This is a NetTrekker link id that linked to a website other than nettrekker
			$link_id = 1 if ( $url =~ m/\?link_id\=/ );	
			push @link_id_base, "$base_url\t$url" if ( $link_id );
			
			$link_urls{ $base_url } = 0 + 0 if ( ! defined $link_urls{ $base_url } );
		}


	my $errmsg;

    if ( $response->is_error() )
		{	$errmsg = $response->status_line;
			$errmsg = "Unknown error" if ( ! defined $errmsg );
			lprint "Unable to read URL $url_string: $errmsg\n";
			return( undef );
		}

	if ( ( ! defined $content )  &&  ( ! defined $errmsg ) )
		{	my $errmsg = $response->status_line;
			$errmsg = "Unknown error" if ( ! defined $errmsg );
			return( undef );
		}


	# Should I save this content to disk?
	if ( $opt_content )
		{	print CONTENT "=== URL: $url ==>\n";
			print CONTENT "=== Link ID ==>\n" if ( $link_id );
			print CONTENT "=== Base: $base ==>\n\n";
			print CONTENT $content;
			print CONTENT "\n\n\n";	
		}


	# Parse out any URLs I can from this content
	if ( ! $link_id )
		{	lprint "Getting URLs from URL Content $url, base $base ...\n";
			&UrlsContent( $content, $base, "nettrekker.com", \%site_urls, \%link_urls, undef );
		}
	else
		{	my %ids;
			
			lprint "Getting URLs from Link ID URL Content $url, base $base ...\n";
			
			&UrlsContent( $content, $base, "nettrekker.com", \%site_urls, \%link_urls, \%ids );
			
			# Get the list of URLs found sorted
			my @links = sort keys %ids;
			
			# Add the base URL in
			my $data = $base_url;
			
			# Now add each url I found
			foreach ( @links )
				{	my $link = $_;
					next if ( ! defined $link );
					
					$data .= "\t" . $link;
				}
				
			$link_ids{ $url } = $data if ( $data );
		}
		
	my $bytes = length( $content );
	lprint "Read $bytes bytes from $url\n";
	
	# Keep track that I read this url
	$site_urls{ $url } = $bytes;
				
	return( $bytes );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = "NetTrekkerErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	print "Error logging set to $filename\n"; 
}



################################################################################
# 
sub NetTrekkerLogin( $$ )
#
#  Login to NetTrekker
#
################################################################################
{	my $username = shift;
	my $password = shift;
	
	
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}

	$| = 1;

	if ( ! $ua )
		{	$ua = LWP::UserAgent->new();
			$ua->agent( "Mozilla/4.0 (compatible; MSIE 7.0;Windows NT 5.1;.NET CLR 1.1.4322;.NET CLR 2.0.50727;.NET CLR 3.0.04506.30)" );
			$ua->cookie_jar( HTTP::Cookies->new( file => "nettrekker.cookies.txt") );
			
			$ua->max_size( 1000000 );
			$ua->timeout( 5 * 60 );  #  Wait for a long time

			$ua->conn_cache( $cache );
		}


	my $url = "http://school.nettrekker.com/LOGIN";
		

	lprint "Logging into NetTrekker ...\n";
	
	my $response = $ua->post(
		$url,
		[	'credential_0'	=> $username,
			'credential_1'	=> $password,
			'destination'	=> "http://school.nettrekker.com",
			'submit.x'		=> '30',
			'submit.y'		=> '8'
		],
	'Content_Type' => 'application/x-www-form-urlencoded' );
	
	
	my $ok = $response->is_success();
	my $status = $response->status_line;
	my $content = $response->content;

	lprint "Login status = $status\n";


	if ( $opt_content )
		{	print CONTENT "=== URL: $url ==>\n\n";
			print CONTENT $content;
			print CONTENT "\n";
		}
		

	if ( ! $ok )
		{	lprint "Error: $status\n";
			
			# A 302 error is the normal error
			return( 1 ) if ( $status =~ m/302/ );
			return( undef );
		}
	

	return( 1 );
}



################################################################################
#
sub UrlsContent( $$$ $$$ )
#
# Given the content of a url, and the root domain I am checking
# return the hash of valid site urls and linked urls
#
################################################################################
{	my $content			= shift;	# This is the HTML content
	my $base			= shift;	# The base URI that I read the content from
	my $root			= shift;	# Root domain of the URL that I am downloading
	
	my $site_urls		= shift;	# A ref to a hash of urls that on in the same domain
	my $link_urls		= shift;	# A ref to a hash of other urls contained in the content
	my $link_ids		= shift;	# A ref to a hash of other urls contained in the content if a link id url

use HTML::LinkExtor;


	return( undef ) if ( ! defined $content );
	return( undef ) if ( ! defined $base );
	
	
	# Don't bother with PDFs
	return( undef ) if ( $base =~ m/\.pdf$/i );
	return( undef ) if ( $content =~ m/^\%PDF\-1\./ );
	
	
	my $original_url = &CleanUrl( $base );
	return( undef ) if ( ! defined $original_url );
	

	lprint "Looking for hrefs in base URI $base ...\n";


	# Make sure I have the base url	in the right url hash
	my $root_domain = &RootDomain( $original_url );
	my $bytes = length( $content );
	
	if ( $root eq $root_domain )
		{	$$site_urls{ $original_url } = $bytes if ( ! defined $$site_urls{ $original_url } );
		}
	else
		{	$$link_urls{ $original_url } = $bytes if ( ! defined $$link_urls{ $original_url } );
		}
		
		
	my $parser = HTML::LinkExtor->new( undef, $base );
	return( undef ) if ( ! defined $parser );
	
	$parser->parse( $content )->eof;


	my @links = $parser->links;
	
	foreach ( @links )
		{	next if ( ! defined $_ );
			my $linkarray = $_;
			
			my @element = @$linkarray;
			my $elt_type = shift @element;	# element type

			# The element array now contains attribute name and value pairs - we don't care about the name, so dump it
			foreach ( @element )
				{	next if ( ! defined $_ );
					my $hurl = $_;

					# Only hang onto the elements that are http
					next if ( ! ( $hurl =~ m/^http/ ) );
								
					$hurl = &CleanUrl( $hurl ) if ( defined $hurl );
					next if ( ! defined $hurl );
					
					$root_domain = &RootDomain( $hurl );
					next if ( ! defined $root_domain );
					
					$hurl = &ChopUrl( $hurl );
					
					lprint "UrlsContent found URL: $hurl\n" if ( $opt_debug );
					
					if ( $root eq $root_domain )
						{	$$site_urls{ $hurl } = 0 + 0 if ( ! defined $$site_urls{ $hurl } );
						}
					else
						{	$$link_urls{ $hurl } = 0 + 0 if ( ! defined $$link_urls{ $hurl } );
							$$link_ids{ $hurl }	= 0 + 0 if ( defined $link_ids );
						}
				} # end if foreach element
		}
	
	
	# Look for meta http refresh in the document - indicates a page that should be loaded after a refresh amount of time
	my @parts = split /meta http-equiv="refresh"/, $content;
	
	$parts[ 0 ] = undef;	# Ignore the first part
	foreach ( @parts )
		{	next if ( ! defined $_ );
			my $part = $_;

			lprint "meta http-equiv=\"refresh\" found!\n";
			my $hurl = &URLParseRefresh( $original_url, $part );
			
			if ( ! $hurl )
				{	lprint "ERROR: Unable to parse the meta refresh url from this: $part\n";
					next;
				}
				
			lprint "UrlsContent meta refresh URL: $hurl\n";

			my $root_domain = &RootDomain( $hurl );
			next if ( ! defined $root_domain );
			
			$hurl = &ChopUrl( $hurl );
			
			if ( $root eq $root_domain )
				{	$$site_urls{ $hurl } = 0 + 0 if ( ! defined $$site_urls{ $hurl } );
				}
			else
				{	$$link_urls{ $hurl } = 0 + 0 if ( ! defined $$link_urls{ $hurl } );
					$$link_ids{ $hurl }	= 0 + 0 if ( defined $link_ids );
				}
		}


	# Now check for embedded http:// somewhere in the content
	@parts = split /http:\/\//, $content;
	$parts[ 0 ] = undef;	# Ignore the first part
	
	foreach ( @parts )
		{	next if ( ! defined $_ );
			my $part = $_;
			my ( $hurl, $junk ) = split /"/, $part, 2;
			( $hurl, $junk ) = split /'/, $hurl, 2 if ( $hurl );
			( $hurl, $junk ) = split /\n/, $hurl, 2 if ( $hurl );
			( $hurl, $junk ) = split /\)/, $hurl, 2 if ( $hurl );
			( $hurl, $junk ) = split /\</, $hurl, 2 if ( $hurl );
			( $hurl, $junk ) = split /\>/, $hurl, 2 if ( $hurl );
			( $hurl, $junk ) = split /\?/, $hurl, 2 if ( $hurl );	
			next if ( ! $hurl );
			
			# Ignore text/css pages
			next if ( $hurl =~ m/text\/css/i );
			
			$hurl = &CleanUrl( $hurl );
			next if ( ! defined $hurl );
			
			my $root_domain = &RootDomain( $hurl );
			next if ( ! defined $root_domain );
			
			# NetTrekker puts '...' into urls that it is trying to hide
			if ( $hurl =~ m/\.\.\./ )
				{	push @link_domain, $root_domain;
					next;
				}
			
			lprint "UrlsContent embedded URL: $hurl\n" if ( $opt_debug );
			
			$hurl = &ChopUrl( $hurl );
			
			if ( $root eq $root_domain )
				{	$$site_urls{ $hurl } = 0 + 0 if ( ! defined $$site_urls{ $hurl } );
				}
			else
				{	$$link_urls{ $hurl } = 0 + 0 if ( ! defined $$link_urls{ $hurl } );
					$$link_ids{ $hurl }	= 0 + 0 if ( defined $link_ids );
				}
		}
		
		
	# Now check for valid domain names in the content
	$content =~ s#http\:\/\/#\n#ig;
	@parts = split /[\\\s\(\)\[\]\{\}\'\"\<\>\n]+/, $content;
	
	foreach ( @parts )
		{	next if ( ! defined $_ );
			my $hurl = $_;

			# Get rid of leading and trailing periods
			$hurl =~ s/^\.+//;
			$hurl =~ s/\.+$//;

			# Now see if there is a period inside what remains - if not, it can't be a valid domain or IP address
			next if ( ! ( $hurl =~ m/\./ ) );
			
			# Get rid of leading and trailing slashes
			$hurl =~ s/^\/+//;
			$hurl =~ s/\/+$//;
			
			$hurl = &CleanUrl( $hurl );
			next if ( ! defined $hurl );
			
			lprint "UrlsContent content URL: $hurl\n" if ( $opt_debug );
			
			my $root_domain = &RootDomain( $hurl );
			next if ( ! defined $root_domain );
			
			$hurl = &ChopUrl( $hurl );
			
			if ( $root eq $root_domain )
				{	$$site_urls{ $hurl } = 0 + 0 if ( ! defined $$site_urls{ $hurl } );
				}
			else
				{	$$link_urls{ $hurl } = 0 + 0 if ( ! defined $$link_urls{ $hurl } );
					$$link_ids{ $hurl }	= 0 + 0 if ( defined $link_ids );
				}
		}
		
		
	return( 1 );
}



################################################################################
#
sub URLParseRefresh( $$ )
#
# Given the original url, and the url portion of an http meta "refresh",
# parse out and return the url to refresh on.  Return undef if I can't figure
# it out.
#
################################################################################
{	my $original_url	= shift;
	my $part			= shift;
	
	return( undef ) if ( ! ( $part =~ m/URL=/i ) );
	
	my ( $junk, $url_part ) = split /URL=/, $part, 2;
	
	( $junk, $url_part ) = split /url=/, $part, 2 if ( ! $url_part );

	my $hurl = $url_part;
	$hurl =~ s/^\s+//	if ( $hurl );

	$hurl =~ s/^\"//	if ( $hurl );	# Trim off any leading double quotes
	
	$hurl =~ s/^\s+//	if ( $hurl );
	
	return( undef ) if ( ! defined $hurl );
	
	( $hurl, $junk ) = split /\"/, $hurl, 2;	# Drop anything after a trailing double quote
	
	$hurl =~ s/^\s+//;		

	$hurl = &FullyQualifiedUrl( $original_url, $hurl );
	
	return( $hurl );
}



################################################################################
#
sub ChopUrl( $ )
#
# Given a URL, chop off anything that starts with ...
# This is a weird thing that Net Trekker does
#
################################################################################
{	my $original_url = shift;

	return( $original_url ) if ( ! ( $original_url =~ m/\.\.\./ ) );
	
	my ( $url, $junk ) = split /\.\.\./, $original_url, 2;

	$url =~ s/\/+$// if ( $url );
	
	my $trim_url = &TrimUrl( $url );
	
	return( $url ) if ( ! defined $trim_url );
	
	return( $trim_url );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "NetTrekker Utility";

    print <<".";
Usage: $me

Crawl the NetTrekker website.  This utility creates five files:

NetTrekkerLink.txt: URLS found on NetTrekker.com linking to a different site
NetTrekkerLinkBase.txt: Base URL and the NetTrekker LinkID URL that loaded it
NetTrekkerLinkDomain.txt: URLs found in the NetTrekker link format
NetTrekkerLinkID.txt: NetTrekkerLinkID URLs and the associated URLS
NetTrekkerSite.txt: URLs found on NetTrekker.com linking to NetTrekker

Other options:

  -a, --allreload        Reload all the exising data files and restart
  -c, --content          Save all the URL content to NetTrekkerContent.txt
  -l, --linkid           Only crawl Link ID URLs
  -m, --max MAX          The maximum number of NetTrekker URLs to read before
                         quitting - default is $opt_max
  -r, --restart          Restart using existing NetTrekker site URLs only
  -v, --verbose          verbose mode

  -h, --help             show this help text
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
    my $me = "NetTrekker";

    print <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################

__END__

:endofperl
