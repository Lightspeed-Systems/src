################################################################################
#!perl -w
#
#  Rob McCarthy's DDBTest source code
#  Test the Lightspeed Distributed Database with UDP
#  Copyright 2012 Lightspeed Systems Corp.
#
################################################################################


use warnings;
use strict;


use Getopt::Long;
use IO::Handle;
use IO::Socket;
use Cwd;
use Benchmark;
use Sys::Hostname;
use Net::DNS;

use Content::File;



my $opt_help;					# True if I should just display the help and exit
my $opt_debug;		 			# If True then don't over write existing files
my $opt_verbose;				# True if I should use verbose messages


my $_version = "1.0.0";

#my $server_ip		= "69.84.207.180";	# This is the external master DDB IP address in Bakersfield
my $server_ip		= "10.16.46.228";	# This is one of the four internal master DDB IP addresses in Bakersfield




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
        "i|ip=s"		=> \$server_ip,
        "v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help,
        "x|xxx"			=> \$opt_debug
    );

		
	print "Distributed Database Test Utility server IP $server_ip\n";
	
    &Usage() if ($opt_help);
		
	my $test_domain = shift;
	&Usage() if ( ! defined $test_domain );
	
	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;


	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );
					
	&DDBTest( $test_domain );
	
	print "Done\n";

exit;
}
################################################################################



my $id;	# This is the ID counter that is used to keep requests and responses tied together
my $socket;
my $port_no;			# This is the port number that the DDB protocol uses
################################################################################
# 
sub DDBTest( $ )
#
#  Given a domain, query the DDB server and print the result
#
################################################################################
{	my $test_domain = shift;
	
	
	my $counter = 0 + 0;

	
	$id = 0 + 0 if ( ! $id );
	$id++;	# Increment the ID
	
	
	# Make sure the socket is open
	if ( ! defined $socket )
		{	$port_no = 0 + 1311 if ( ! $port_no );	# This is the port number that the DDB protocol uses
			print "Opening UDP socket IP $server_ip port $port_no ...\n";
			$socket = IO::Socket::INET->new( Proto => 'udp', PeerAddr => $server_ip, PeerPort => $port_no, Timeout => 10 );
			die "Unable to open socket: $!\n" if ( ! defined $socket );
		}
								
	
	print "Checking category for $test_domain ...\n";						
	my $category = &DDBQueryAsync( $socket, $test_domain, $id );
	print "Found category $category\n" if ( $category );
	print "Error getting category\n" if ( ! $category );	
				
	print "Shutting down socket ...\n";
	$socket->shutdown( 2 );
							
	return( $category );
}



my %query;						# A hash of outstanding queries
################################################################################
# 
sub DDBQueryAsync( $$$ )
#
#  Given a socket and a domain, URL, or IP address name, a DDB server for the
#  category.  Return undef if an error, or the Lightspeed category number if OK.
#
# Request packet for getting the category of a domain called “domain.com”
# 0x00 0x00 | for a length of 0 – but later I fill with the overall length of the entire request, which in this case is 2 + 2 + 2 + 4 +2 + 2 + 2 + 2 + 10 = 22, or 0x00 0x16
# 0x00 0x01 | for a version of 1
# 0x00 0x14 | lookup code – in this case 0x14 for LOOKUP_URL, as opposed to 0x15 for LOOKUP_IP, or 0x16 for LOOKUP_IPv6
# 0x00 0x00 0x00 0x09 | the ID # – in this case “9” – but it is just a number, usually sequential, used to keep the requests and replies straight
# 0x00 0x10 | The length of the options part of the request packet, in this case 2 + 2 + 2 + 2 + 10 = 16 - you have include the length field itself
# 0x00 0x01 | for the # of options – in this case 1 for a domain, but 2 for a URL
# 0x00 0x02 | for OPT_HOST value of 2. This could be 1 for OPT_URL
# 0x00 0x0a | for the length of the string “domain.com”, i.e. 10
# domain.com | the string containing the domain name I am trying to look up as ascii, NOT padded to a round number of bytes
#
# If I am requesting a URL, I put the two byte length of the URL, the URL itself, and then the two byte length of the domain, and
# the domain itself into the options part of the request packet
#
################################################################################
{	my $socket	= shift;
	my $lookup	= shift;	# This is what I am looking up - could be a domain, a URL, or an IP
	my $id		= shift;
	
	return( undef ) if ( ! defined $lookup );
	
	my $domain;
	my $url;
	my $ip;
	
	my $type	= &UrlType( $lookup );
	$url		= $lookup if ( $type == 0 + 3 );
	$ip			= $lookup if ( $type == 0 + 2 );
	$domain		= $lookup if ( $type == 0 + 1 );
	
	
	# First build the options part of the request
	my $options_part;
	my $lookup_type;
	
	if ( defined $domain )
		{	$lookup_type = 0x14;
			my $domain_length = length( $domain );
			my $option_length = 8 + $domain_length;
			
			# Pack in the option length, the # of options (1), the OPT_HOST value of 2, the length of the domain name string, and the domain name
			$options_part = pack( "nnnn", $option_length, 1, 2, $domain_length ) . $domain;
		}
	elsif ( defined $ip )
		{	$lookup_type = 0x15;
			
			# For an IP lookup I just have to pack the IP address
			$options_part = &StringToIP( $ip );
		}
	else	# has to be a URL
		{	$lookup_type = 0x14;
		}
	
	
	# Calculate the overall request length
	my $request_length = 10 + length( $options_part );
	
	# Build up the request with request length, version, lookup type, ID, and options
	my $request = pack( "nnnN", $request_length, 1, $lookup_type, $id ) . $options_part;
	

	if ( $opt_debug )
		{	my $request_size = length( $request );
			print "Request size: $request_size\n";
			print "Request ID: $id\n";
			
			if ( defined $domain )
				{	print "Request Domain: $domain\n";
				}
			elsif ( defined $ip )
				{	print "Request IP: $ip\n";
				}
			else
				{	print "Request URL: $url\n";
				}
				
			my $hex = &HexPrint( $request );
			print "Full Request (Hex): $hex\n" if ( $hex );
			
		}
	

	# Keep track of the query
	$query{ $id } = $lookup;

	
	print $socket $request;

	my $resp_lookup;
	my $category;
	
	while ( ! $resp_lookup )
		{	( $resp_lookup, $category ) = &DDBResponseAsync( $socket, $id );
			last if ( ! defined $category );			
		}	
		
	return( $category );
}



################################################################################
# 
sub HexPrint( $ )
#
################################################################################
{	my $val = shift;
	
	return( undef ) if ( ! defined $val );
	
	my @chars = split //, $val;

	my $str;
	foreach ( @chars )
		{	my $ch = $_;
			next if ( ! defined $ch );
			
			my $hex = &StrToHex( $ch );
			next if ( ! defined $hex );
			
			$str .= " " . $hex if ( defined $str );
			$str = $hex if ( ! defined $str );
		}

	return( $str );
}



################################################################################
# 
sub DDBResponseAsync( $$ )
#
#  Given a socket, return the url and the Lightspeed category if a response is waiting.
#  Return (undef, 1) if nothing is there, return (undef, undef) if an error
#
################################################################################
{	my $socket	= shift;
	my $resp_id	= shift;	# This is the ID of the response that i am looking for

	# Is it ready for reading?	
	my $rin ="";
	my $rout;
	vec( $rin, fileno( $socket ), 1 ) = 1;
	return( undef, 1 ) if ( select( $rout=$rin, undef, undef, 0 ) == 0 );

	my $data_len;
	
	my $num_read = 0 + 0;
	while ( ! $num_read )
		{	$num_read = read( $socket, $data_len, 2 );
			return( undef, 1 ) if ( ! defined $num_read );
		}
	
	print "Response read length: $num_read\n" if ( $opt_debug );
	
	my $response_len = unpack( "n", $data_len );
	print "Response length: $response_len\n" if ( $opt_debug );

	my $data;
	$num_read = read( $socket, $data, $response_len - 2 );
	
	my $response = $data_len . $data;
	
	if ( $opt_debug )
		{	my $hex = &HexPrint( $response );
			print "Response (Hex): $hex\n" if ( $hex );
		}
		
	# The response header is the first 10 bytes
	my $response_header  = substr( $response, 0, 10 );

	# Unpack the header
	my ( $resp_len, $version, $code, $rec_id  ) = unpack( "nnnN", $response_header );

	if ( $opt_debug )
		{	print "Response header length: $resp_len\n";
			print "Response version: $version\n";
			print "Header code: $code\n";
			print "Received ID: $rec_id\n";
		}
	
	
	# Is this the right ID?
	# Sometimes UDP packets will echo around the place
	if ( $resp_id != $rec_id )
		{	print "Received ID $rec_id, looking for response ID of $resp_id\n";
			
			# Just return that nothing is there
			return( undef, 1 );
		}
	
	
	if ( ( $code & 0x8000 ) == 0 )
		{	print "Missing response bit\n";
			return( undef, 1 );
		}
		
		
	# Turn off the response bit
	$code -= 0x8000;
	printf( "Returned code = 0x%02x\n", $code ) if ( $opt_debug );
	
	my $categoryNumber;
	
	
	if ( $code == 0x14 )	# It is a returned URL lookup
		{	my $len = $response_len - 10;
			my $response_value  = substr( $response, 10, $len );
			if ( ! defined $response_value )
				{	print "Got a undefined response value\n";
					return( undef, undef );
				}
			
			my $value_length = length( $response_value );
			print "Response value length: $value_length\n" if ( $opt_debug );
			
			if ( $value_length < 6 )
				{	print "Got a weird value length of $value_length\n";
					return( undef, undef );
				}
			
			my ( $category_num, $ttl, $options_length, $options_num ) = unpack( "nNnn", $response_value );
			
			$categoryNumber = $category_num;
			
			if ( $opt_debug )
				{	print "Response Lightspeed category number $categoryNumber\n";
					print "Response ttl $ttl\n";
					print "Response options length $options_length\n";
					print "Response options num $options_num\n";
				}
				
			$len = $response_len - 20;
			my $option_value  = substr( $response, 20, $len );

			my ( $opt, $opt_len ) = unpack( "nn", $option_value );
			
			if ( $opt_debug )
				{	print "opt = $opt\n";
					print "opt len = $opt_len\n";
				}
				
			if ( $opt == 3 )  # Then it is a domain name
				{	$len = length( $option_value ) - 4;
					my $domain = substr( $option_value, 4, $opt_len );
					
					print "Returned domain name = $domain\n" if ( $opt_debug );
				}
		}
	elsif ( $code == 0x15 )	# It is a returned IP address lookup
		{	my $len = $response_len - 10;
			my $response_value  = substr( $response, 10, $len );
			if ( ! defined $response_value )
				{	print "Got a undefined response value\n";
					return( undef, undef );
				}
			
			my $value_length = length( $response_value );
			print "Response value length: $value_length\n" if ( $opt_debug );
			
			if ( $value_length < 6 )
				{	print "Got a weird value length of $value_length\n";
					return( undef, undef );
				}
			
			my ( $category_num, $ttl ) = unpack( "nN", $response_value );
			
			$categoryNumber = $category_num;
			
			if ( $opt_debug )
				{	print "Response Lightspeed category number $categoryNumber\n";
					print "Response ttl $ttl\n";
				}
		}
	else
		{	printf( "Unknown response return code = 0x%02x\n", $code );
			return( undef, undef );
		}
		
		
	my $look = $query{ $id };
	
	# Delete the query from the hash
	delete $query{ $id };

	return( $look, $categoryNumber );
}



################################################################################
# 
sub URLIPAddresses( $ )
#
#  Given a URL, return the hostname and all the IP addresses in DNS for it
#
################################################################################
{	my $url = shift;

	my $host;
	my @addresses;
	
	return( undef, @addresses ) if ( ! defined $url );
	
	my ( $domain, $url_ext ) = split /\//, $url, 2;
	$host = $domain;  # Default the host name to the domain name

	return( undef, @addresses ) if ( ! $domain );
	
	
	# Is the domain an IP address itself?  If so, return the IP address as both the host name and in the addresses array
	if ( &IsIPAddress( $domain ) )
		{	push @addresses, $domain;
			return( $domain, @addresses ) ;
		}
		
		
	my $res = Net::DNS::Resolver->new;
	
	# Wait for 16 seconds for a response
	$res->tcp_timeout( 16 );
	$res->udp_timeout( 16 );
	
	print "Querying DNS for $domain ...\n";
	my $query = $res->search( $domain ); 
	
	my $www_domain = "www.$domain" if ( ! ( $domain =~ m/^www\./ ) );
	if ( ( ! $query )  &&  ( $www_domain ) )
		{	$host = $www_domain;
	
			print "Querying DNS for $www_domain ...\n";
			$query = $res->search( $www_domain );
			$host = $www_domain;
		}
	
	if ( ! $query )
		{	my $error = $res->errorstring;
			$error = "Unknown error" if ( ! $error );
			
			# Does this domain or host exist at all?
			my $nonexisiting_domain;
			$nonexisiting_domain = 1 if ( $error eq "NXDOMAIN" );
			
			$error = "nonexisting hostname or domain: $domain and $www_domain" if ( $nonexisiting_domain );				
			print "DNS Query failed: $error\n";
			
			return( undef, @addresses );
		}
		
	foreach my $rr ( $query->answer ) 
		{	next unless $rr->type eq "A";
			my $ip = $rr->address;

			# Make sure it is a good IP address
			next if ( ! &IsValidIP( $ip ) );
			
			print "Found IP address $ip for $host\n";
			
			push @addresses, $ip;
		}
	
	if ( $#addresses < 0 )
		{	print "No valid IP addresses found for $domain\n";
			return( undef, @addresses );
		}
			
	return( $host, @addresses );	
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
#
sub TrapErrors( $$ )
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename base on the mode I'm running in
	my $filename = "DDTestErrors.log";
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	print( "Unable to open $filename for error logging: $!\n" ); 
			return;
		}
		
	&CarpOut( $MYLOG );
   
	print( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "DDBTest";

    print <<".";
Usage: $me TestDomain [OPTION(s)]
Test the Lightspeed Distributed Database server using UDP
The only required argument is the domain name to test

Options:
  -i, --ip IP_ADDR        the IP address of the DDBTest server
                          default is \"$server_ip\"
  -h, --help              display this help and exit
  -v, --version           display version information and exit 
.
   &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl

