################################################################################
#!perl -w
#
#  Alexa - Query the Alexa Web Services site
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Content::File;
use LWP::UserAgent;
use LWP::ConnCache;
use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);
use MIME::Base64;
use URI;
use URI::QueryParam;
use Cwd;



my $opt_help;
my $opt_version;
my $opt_wizard;					# True if I shouldn't display headers or footers
my $opt_debug;
my $opt_count = 0 + 10;
my $opt_file;
my $opt_restart;
my $opt_operation;
my $opt_query;
my $opt_url;
my $opt_verbose;


my $aws_access_key_id	= "1T0PMS0QCYG8VVJWGN02";
my $secret_access_key	= "6voG6+uFkiJ1an8w96dGvGae1fscrJQwozSOtMhZ";	
my $aws_version			= "2007-03-15";


my $_version		= "1.0.0";
my $curdir;



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
        "c|count=i"		=> \$opt_count,
        "f|file=s"		=> \$opt_file,
        "o|operation=s"	=> \$opt_operation,
        "q|query=s"		=> \$opt_query,
        "r|restart=i"	=> \$opt_restart,
        "u|url=s"		=> \$opt_url,
        "v|verbose"		=> \$opt_verbose,
        "x|xdebug"		=> \$opt_debug,
		"w|wizard"		=> \$opt_wizard,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "Alexa" ) if ( ! $opt_wizard );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );
	
	$curdir = getcwd;
	$curdir =~ s#\/#\\#gm;

	$opt_operation = shift if ( ! defined $opt_operation );
	&Usage() if ( ! defined $opt_operation );
	
	
	if ( ( $opt_file )  &&  ( ! ( $opt_file =~ m/\\/ ) ) )
		{	$opt_file = $curdir . "\\" . $opt_file;
		}
	

	$opt_operation = lc( $opt_operation );
	
	if ( $opt_operation =~ m/search/ )
		{	$opt_query = shift if ( ! defined $opt_query );
			&Usage() if ( ! defined $opt_query );
			
			if ( -f $opt_query )
				{	print "Search queries in file $opt_query ...\n";
					
					if ( ! open( URLFILE, "<$opt_query" ) )
						{	print "Error opening file $opt_query: $!\n";
							exit( 0 );
						}
					
					my $count = 0 + 0;	
					while ( my $line = <URLFILE> )
						{	chomp( $line );
							next if ( ! $line );
							
							my $query = $line;
							
							$query =~ s/^\s+//;
							next if ( ! $query );
							
							$query =~ s/\s+$//;
							next if ( ! $query );
							
							$count++;
							
							print "Search query #$count $query ...\n";
							&AlexaSearch( $query, $opt_count, $opt_file, $opt_restart );
						}
						
					close( URLFILE );
				}
			else
				{	print "Search query $opt_query ...\n";
					&AlexaSearch( $opt_query, $opt_count, $opt_file, $opt_restart );
				}
		}
	elsif ( $opt_operation =~ m/webmap/ )
		{	$opt_url = shift if ( ! defined $opt_url );
			&Usage() if ( ! defined $opt_url );
			
			if ( -f $opt_url )
				{	print "Web map for URLs in file $opt_url ...\n";
					
					if ( ! open( URLFILE, "<$opt_url" ) )
						{	print "Error opening file $opt_url: $!\n";
							exit( 0 );
						}
					
					my $count = 0 + 0;	
					while ( my $line = <URLFILE> )
						{	chomp( $line );
							next if ( ! $line );
							
							my $url = &CleanUrl( $line );
							next if ( ! $url );
							
							$count++;
							
							print "Web map for URL #$count: $url ...\n";
							&AlexaWebMap( $url, $opt_file, $opt_count );
						}
						
					close( URLFILE );
				}
			else
				{	print "Web map for URL: $opt_url ...\n";
					&AlexaWebMap( $opt_url, $opt_file, $opt_count );
				}
		}
	elsif ( $opt_operation =~ m/rank/ )
		{	$opt_url = shift if ( ! defined $opt_url );
			&Usage() if ( ! defined $opt_url );
			
			if ( -f $opt_url )
				{	print "Web rank for URLs in file $opt_url ...\n";
					
					if ( ! open( URLFILE, "<$opt_url" ) )
						{	print "Error opening file $opt_url: $!\n";
							exit( 0 );
						}
					
					my $count = 0 + 0;	
					while ( my $line = <URLFILE> )
						{	chomp( $line );
							next if ( ! $line );
							
							my $url = &CleanUrl( $line );
							next if ( ! $url );
							
							$count++;
							
							print "Web rank for URL #$count: $url ...\n";
							&AlexaWebRank( $url, $opt_file );
						}
						
					close( URLFILE );
				}
			else
				{	print "Web rank for URL: $opt_url ...\n";
					&AlexaWebRank( $opt_url, $opt_file );
				}
		}
	else
		{	print "Illegal operation = $opt_operation\n";
		}
		
		
	&StdFooter if ( ! $opt_wizard );

exit( 0 );
}



################################################################################
# 
sub AlexaUrlInfo( $ )
#
#  Do an Alexa web services url_info query
#
################################################################################
{	my $url_info = shift;

	my $response_group = 'RelatedLinks,Categories,AdultContent,Language,Keywords';
 
	my %params = 
		(	Url				=> $url_info,
			ResponseGroup	=> $response_group		  
		);

 	my $response = &AlexaResponse( "UrlInfo", \%params );

		
}



################################################################################
# 
sub AlexaSearch( $$$ )
#
#  Do an Alexa web services search query and return the results
#
################################################################################
{	my $query	= shift;
	my $count	= shift;
	my $file	= shift;
	my $restart	= shift;
	
use XML::Parser;
use XML::DOM;
use XML::DOM::BagOfTricks;

	my $per_page = 0 + 200;		# This is the number of results per page of search	
	
	
	# Open the file to write results to if I am supposed to
	if ( defined $file )
		{	if ( ! open( FILE, ">$file" ) )
				{	print "Error opening $file: $!\n";
					return( undef );
				}
		}
			
	my $page_number = 0 + 1;
	$page_number = $restart if ( defined $restart );
	
	
	my %params = 
		(	ResponseGroup				=> "Results",	
			Query						=> $query,			
			MaxNumberOfDocumentsPerPage	=> $per_page,
			Unique						=> "site",
			PageNumber					=> $page_number
		);


	print "Searching for results page number $page_number ...\n";		
 	my $response = &AlexaResponse( "Search", \%params );
	return( undef ) if ( ! defined $response );

	# Split the responses into clean lines
	$response =~ s/\>\</\>\n\</g;
	
	my @lines = split /\n/, $response;

	my @urls = &AlexaParse( \@lines, "Url" );
	
	my $results_count = $#urls + 1;

	foreach ( @urls )
		{	my $result_url = $_;
			next if ( ! $result_url );
			
			print "$result_url\n" if ( ( ! defined $file )  ||  ( $opt_verbose ) );
			print FILE "$result_url\n" if ( defined $file );
		}


	# If I asked for the default number of results, or not a full page of results came back, then return here	
	if ( ( $count <= $results_count )  ||  ( $results_count < $per_page ) )
		{	close( FILE ) if ( defined $file );
			print "Found $results_count total\n";
			return( $results_count );	
		}


	#  Get the rest of the results
	$page_number++;
	while ( ( defined $response )  &&  ( $results_count < $count ) )
		{	$params{ PageNumber } = $page_number;

			print "Searching for results page number $page_number ...\n";
			
 			$response = &AlexaResponse( "Search", \%params );
			last if ( ! $response );
			
			# Split the responses into clean lines
			$response =~ s/\>\</\>\n\</g;

			my @lines = split /\n/, $response;

			my @urls = &AlexaParse( \@lines, "Url" );
			
			foreach ( @urls )
				{	my $result_url = $_;
					next if ( ! $result_url );
					
					print "$result_url\n" if ( ( ! defined $file )  ||  ( $opt_verbose ) );
					print FILE "$result_url\n" if ( defined $file );
				}
				
			$results_count += $#urls + 1;
			$page_number++;		
			
			# Have I run out of results?
			last if ( $#urls < 0 );
		}
	
	close( FILE ) if ( defined $file );
	
	print "Found $results_count results total\n";
	
	return( $results_count );
}



################################################################################
# 
sub AlexaWebMap( $$$ )
#
#  Do an Alexa web services map query and return the results
#
################################################################################
{	my $url			= shift;
	my $file		= shift;
	my $max_count	= shift;
	
use XML::Parser;
use XML::DOM;
use XML::DOM::BagOfTricks;

	
	# Open the file to write results to if I am supposed to
	if ( defined $file )
		{	if ( ! open( FILE, ">>$file" ) )
				{	print "Error opening $file: $!\n";
					return( undef );
				}
		}
			
	
	my %params = 
		(	Url				=> $url,
			ResponseGroup	=> "SitesLinkingIn",
			Count			=> 20
		);


	my $page_number = 0 + 1;
	
	print "Searching for results page number $page_number ...\n";		
 	my $response = &AlexaResponse( "SitesLinkingIn", \%params );
	return( undef ) if ( ! defined $response );

	# Split the responses into clean lines
	$response =~ s/\>\</\>\n\</g;
	
	my @lines = split /\n/, $response;
	
	my @urls = &AlexaParse( \@lines, "aws:Url" );
	
	my $results_count = $#urls + 1;

	foreach ( @urls )
		{	my $result_url = $_;
			next if ( ! $result_url );
			
			print "$result_url\n" if ( ( ! defined $file )  ||  ( $opt_verbose ) );
			print FILE "$result_url\n" if ( defined $file );
		}


	# If I asked for the default number of results, or not a full page of results came back, then return here	
	if ( ( $max_count <= $results_count )  ||  ( $results_count < 20 ) )
		{	close( FILE ) if ( defined $file );
			print "Found $results_count total\n";
			return( $results_count );	
		}


	#  Get the rest of the results
	$page_number++;
	my $start = 0 + 20;
	
	while ( ( defined $response )  &&  ( $results_count < $max_count ) )
		{	$params{ Start } = $start;

			print "Searching for results page number $page_number ...\n";
			
 			$response = &AlexaResponse( "SitesLinkingIn", \%params );
			last if ( ! $response );
			
			# Split the responses into clean lines
			$response =~ s/\>\</\>\n\</g;

			my @lines = split /\n/, $response;

			my @urls = &AlexaParse( \@lines, "aws:Url" );
			
			foreach ( @urls )
				{	my $result_url = $_;
					next if ( ! $result_url );
					
					print "$result_url\n" if ( ( ! defined $file )  ||  ( $opt_verbose ) );
					print FILE "$result_url\n" if ( defined $file );
				}
				
			$results_count += $#urls + 1;
			$start += $#urls + 1;
			
			$page_number++;		
			
			# Have I run out of results?
			last if ( $#urls < 0 );
		}
	
	close( FILE ) if ( defined $file );
	
	print "Found $results_count results total\n";
	
	return( $results_count );	
}



################################################################################
# 
sub AlexaWebRank( $$ )
#
#  Do an Alexa web services web rank query and return the results
#
################################################################################
{	my $url		= shift;
	my $file	= shift;
	
use XML::Parser;
use XML::DOM;
use XML::DOM::BagOfTricks;

	
	# Open the file to write results to if I am supposed to
	if ( defined $file )
		{	if ( ! open( FILE, ">>$file" ) )
				{	print "Error opening $file: $!\n";
					return( undef );
				}
		}
			
	
	my %params = 
		(	Url				=> $url,
			ResponseGroup	=> "RelatedLinks,Categories,Rank,ContactInfo,AdultContent,Keywords"
		);


	my $response = &AlexaResponse( "UrlInfo", \%params );
	return( undef ) if ( ! defined $response );

	print "Alexa Response:\n$response\n" if ( $opt_debug );
	
	my @lines = split /\n/, $response;
	
	my @related_links	= &AlexaParse( \@lines, "aws:RelatedLink" );
	my @rank			= &AlexaParse( \@lines, "aws:Rank" );
	my @contact_info	= &AlexaParse( \@lines, "aws:ContactInfo" );
	my @adult_content	= &AlexaParse( \@lines, "aws:AdultContent" );
	my @keywords		= &AlexaParse( \@lines, "aws:Keywords" );
	my @categories		= &AlexaParse( \@lines, "aws:Categories" );
	
	print "URL: $url\n";
	print "related links =\n";
	foreach ( @related_links )
		{	my $line = $_;
			next if ( ! $line );
			
			print "$line\n";
		}
		
	print "rank = @rank\n";
	
	print "contact info =\n";
	foreach ( @contact_info )
		{	my $line = $_;
			next if ( ! $line );
			
			print "$line\n";
		}
		
	print "adult content = @adult_content\n";
	
	print "keywords =\n";
	foreach ( @keywords )
		{	my $line = $_;
			next if ( ! $line );
			
			print "$line\n";
		}
		
	print "categories =\n";
	foreach ( @categories )
		{	my $line = $_;
			next if ( ! $line );
			
			print "$line\n";
		}
	
	if ( defined $file )
		{	print FILE "URL: $url\n";
			print FILE "related links =\n";
			foreach ( @related_links )
				{	my $line = $_;
					next if ( ! $line );
					
					print FILE "$line\n";
				}
				
			print FILE "rank = @rank\n";
			
			print FILE "contact info =\n";
			foreach ( @contact_info )
				{	my $line = $_;
					next if ( ! $line );
					
					print FILE "$line\n";
				}
				
			print FILE "adult content = @adult_content\n";
			
			print FILE "keywords =\n";
			foreach ( @keywords )
				{	my $line = $_;
					next if ( ! $line );
					
					print FILE "$line\n";
				}
				
			print FILE "categories =\n";
			foreach ( @categories )
				{	my $line = $_;
					next if ( ! $line );
					
					print FILE "$line\n";
				}
		}
	
	close( FILE ) if ( defined $file );
	
	return( 0 + 1 );	
}



################################################################################
# 
sub AlexaParse( $$ )
#
#  Given an Alexa response, parse it for the give node value
#
################################################################################
{	my $lines_ref = shift;
	my $node = shift;
	
	my @values;
	
	return( @values ) if ( ! defined $lines_ref );
	
	my $qstart = quotemeta( "<$node>" );
	my $qend = quotemeta( "</$node>" );


	my $started;
	foreach ( @$lines_ref )
		{	my $line = $_;
			next if ( ! defined $line );

			$line =~ s/^\s+//;
			next if ( ! defined $line );
			
			if ( ! $started )
				{	$started = 1 if ( $line =~ m/$qstart/ );
				}
				
			if ( $started )
				{	if ( $line =~ m/$qend/ )
						{	$started = undef;
						}

					my $value = $1 if ( $line =~ m/\>(.*?)\</ );
					
					if ( $value )
						{	my $label = $1 if ( $line =~ m/\<aws\:(.*?)\>/ );
							
							if ( $label )
								{	my $qlabel = quotemeta( $label );
									$label = undef if ( $node =~ m/$qlabel/ );
								}
							
							$value = $label . ":" . $value if ( $label );
							push @values, $value if ( $value );
						}
				}
		}
		
	return( @values );
}



my $cache;
my $ua;
################################################################################
# 
sub AlexaResponse( $$ )
#
#  Given the parameters to an Alexa Web Service, make a request and return the
#  response.
#
################################################################################
{	my $operation	= shift;
	my $params_ref	= shift;

	return( undef ) if ( ! defined $operation );
	
use Digest::HMAC_SHA1 qw( hmac_sha1 hmac_sha1_hex );
use MIME::Base64;
use URI;
use URI::QueryParam;

	if ( ! defined $ua )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
			$ua = LWP::UserAgent->new( );
			$ua->agent("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50215)");
			$ua->timeout( 30 );  #  Go ahead and wait for 30 seconds
			$ua->conn_cache( $cache );
		}

	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime( time() );
	$year += 1900;
	$mon += 1;
	
	my $timestamp = sprintf( "%04d-%02d-%02dT%02d:%02d:%02d.000Z", $year, $mon, $mday, $hour, $min, $sec );
	my $concat = $operation . $timestamp;

	my $hmac = encode_base64( hmac_sha1( $concat, $secret_access_key ) );
	chop $hmac;	
	my $signature = $hmac;

	$| = 1;
	
	my $uri;
	
	if ( $operation =~ m/search/i )
		{	$uri = URI->new( 'http://wsearch.amazonaws.com/' );
		}
	else
		{	$uri = URI->new( 'http://awis.amazonaws.com/' );
		}

 
	$uri->query_param( "AWSAccessKeyId", $aws_access_key_id );
	$uri->query_param( "Timestamp", $timestamp );
	$uri->query_param( "Signature", $signature );
	
	if ( $operation =~ m/search/i )
		{	$uri->query_param( "Version", $aws_version );
		}
		
	$uri->query_param( "Action", $operation );
	
	# Add the rest of the parameters
	my %params = %$params_ref;
	
	while ( my ( $param, $value ) = each( %params ) )
		{	$uri->query_param( $param, $value );
		}
		
	if ( ( $opt_debug )  ||  ( $opt_verbose ) )
		{	my $uri_lines = $uri;
			$uri_lines =~ s#\&#\n\&#g;
			$uri_lines =~ s#\?#\n\?#g;

			print "\nuri lines = $uri_lines\n";
		}

 	my $response = $ua->get( $uri );

	if ( ! defined $response )
		{	print "Request Error: undefined response\n";
			return( undef );	
		}
		
	my $content = $response->content;		
	
	if ( ! defined $content )
		{	print "Request Error: undefined content\n";
			return( undef );	
		}
		
	if ( $opt_debug )
		{	my $formatted_content = $content;
			$formatted_content =~ s#><#>\n<#g;
			print "\nURL Response:\n$formatted_content\n";
		}
		
	if ( $response->is_error() )
		{	print "Request Error: ", $response->status_line, "\n";
			print "Unable to read URI $uri\n";
			return( undef );
		}

	# If I got an internal error - retry the query again one time
	if ( $content =~ m/Internal Error/ )
		{	print "Request Error: Internal Error: Retrying request ...\n";
			$response = $ua->get( $uri );
			
			$content = $response->content;
			
			if ( $opt_debug )
				{	my $formatted_content = $content;
					$formatted_content =~ s#><#>\n<#g;
					print "\nURL Response:\n$formatted_content\n";
				}
		}
		
	return( $content );
}


################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Alexa";

    print <<".";
Usage: $me operation value
Runs an Alexa web query.
Operation can be either \'search\', \'webmap', or \'rank\'.
Value is either the search query, the webmap URL, the rank URL, or a file 
containing search queries, webmap URLs, or rank URLs.

  -c, --count COUNT      maximum cout of search queries to return
  -f, --file FILE        file name to write results to, default is screen
  -o, --operation OP     operation type - either rank, search, or webmap
  -q, --query QUERY      search engine query to execute
  -r, --restart RESTART  page number to restart from
  -u, --url  URL         URL to get a WebMap or rank for
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
    my $me = "Alexa";

    print <<".";
$me $_version
.
    &StdFooter;

    exit;
}


################################################################################

__END__

:endofperl
