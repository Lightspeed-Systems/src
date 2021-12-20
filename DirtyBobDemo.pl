################################################################################
#!perl -w
#
# Rob McCarthy's DirtyBobDemo for TTC 6.0  11/12/2005
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use HTTP::Request;
use LWP::Simple;
use LWP::UserAgent;
use Cwd;
use Content::File;

use Net::MSN;


# Options
my $opt_help;
my $opt_version;
my $opt_wizard;
my $opt_bob;
my $_version = "1.0.0";
my $client;
my $client_connected;



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
        "b|bob"		=> \$opt_bob,
        "w|wizard"	=> \$opt_wizard,
        "v|version" => \$opt_version,
        "h|help"	=> \$opt_help
		);


	&StdHeader( "DirtyBobDemo" ) if ( ! $opt_wizard );
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;  # Flip slashes to backslashes
	

	my $done;
	
	while ( ! $done )
		{	print "\nRunning the Dirty Bob demo ...\n";
			
			if ( $opt_bob )
				{	&SendMessageMSN( 'bobdirt@lightspeedsystems.com', 'dirtybob', 'rob@lightspeedsystems.com', "Hi Rob!" );
				}
			else
				{	&SendMessageMSN( 'rob@lightspeedsystems.com', 'robby3', 'bobdirt@lightspeedsystems.com', "Hi Bob - do you wanna get in trouble!" );
				}

die;

			&DownloadWebpage( "www.google.com/search?hl=en&ned=us&q=naked+little+girls&btnmeta%3Dsearch%3Dsearch=Search+the+Web" );
			&DownloadWebpage( "images.google.com/images?q=bikini&hl=en&btnG=Search+Images" );
			&DownloadWebpage( "www.google.com/search?hl=en&ned=us&q=hot+bikini+models&btnmeta%3Dsearch%3Dsearch=Search+the+Web" );

			&DownloadWebpage( "www.weeklybikini.com" );
			&DownloadWebpage( "www.microkitten.com" );

			my $hours	= 0 + 8;
			my $seconds = 60 * 60 * $hours;
			
			print "\nSleeping for $hours hours before running the demo downloads again ...\n";
			sleep( $seconds );
		}
		
		
    &StdFooter if ( ! $opt_wizard );
	
	exit;
}



################################################################################
#
sub SendMessageMSN( $$$$ )
#
# Send a message to another user on MSN messenger
#
################################################################################
{	my $handle			= shift;
	my $password		= shift;
	my $target_handle	= shift;
	my $message			= shift;


	print "Trying to send a MSN message to $target_handle ...\n";
	
my $LogFile = './msn-client.log';
unlink( $LogFile );

	$client = new Net::MSN(
  Debug           =>  1,
  Debug_Lvl       =>  3,
  Debug_STDERR    =>  1,
  Debug_LogCaller =>  1,
  Debug_LogTime   =>  1,
  Debug_LogLvl    =>  1,
  Debug_Log       =>  $LogFile );


	if ( ! defined $client )
		{	print "Unable to create MSN Messenger service client\n";
			return( undef );
		}
		
		
	$client->set_event(
		on_connect => \&on_connect,
		on_status  => \&on_status,
		on_answer  => \&on_answer,
		on_message => \&on_message,
		on_join    => \&on_join,
		on_bye     => \&on_bye,
		auth_add   => \&auth_add
		);


	my $ok = $client->connect( $handle, $password );
	if ( ! $ok )
		{	print "Unable to connect to MSN Messenger service\n";
			return( undef );
		}
		

	my $target_connected;
	my $message_started = 0 + 0;
	my $message_sent;
	my $error;
	my $loop_count = 0 + 0;
	while ( ( ! $message_sent )  &&  ( ! $error ) )
		{	$client->check_event();
#sleep( 1 );
			
			if ( ( $client_connected )  &&  ( ! $target_connected ) )
				{	# Is the target already connected?
#$client->buddyaddfl( $target_handle, $target_handle );					
#$client->check_event();
#my $online = $client->is_buddy_online( $target_handle );
#&log_print( "buddy is online\n" ) if ( defined $online );

					my $sb = $client->get_SB( $target_handle );
					
					if ( ! $sb )
						{		
#print "calling buddy add\n";							
#$client->buddyadd( $target_handle, $target_handle );
#&log_print( "Calling $target_handle ...\n" );
#							my $target_online = $client->call( $target_handle );
#							if ( ! $target_online )
#								{	
#&log_print( "$target_handle is not online now\n" );
									#$error = 1;	
#								}
#							else
#								{	&log_print( "Called $target_handle OK\n" );
#									$target_called = 1;
#								}
						}
					
					if ( $sb )
						{	&log_print( "$target_handle is now connected\n" );
							$target_connected = 1;
						}
				}
				
			if ( ( $client_connected )  &&  ( $target_connected )  &&  ( ! $message_started ) )
				{
#&log_print( "Checking for a MSN session handle ...\n" );
					my $sb = $client->get_SB( $target_handle );
					
					if ( $sb )
						{	&log_print( "Sarting to send message now ...\n" );
							$sb->sendmsg( $message );
							$message_started = 0 + 1;
						}
					else
						{	&log_print( "No MSN session handle yet ...\n" );
						}
				}
				
			$message_started++ if ( $message_started );
			$message_sent = 1 if ( $message_started > 10 );
			
#			$loop_count++;
			
			if ( $loop_count > 2 * 60 )
				{	print "2 minutes has gone by and still unable to connect to $target_handle, so quitting\n";
					$error = 1;
				}
		}
	
	$client->disconnect();
	$client_connected = undef;

	print "Message sent\n" if ( $message_sent );
	
	return( $message_sent );
}



sub on_connect 
{	print( "Connected to MSN @ $client->{_Host}:$client->{Port}\n" );
	print( "Connected as: $client->{Handle}\n" );
	$client_connected = 1;
}



sub on_status 
{
print "on_status\n";
  # FIXME
}



sub on_message 
{	my ( $sb, $chandle, $friendly, $message ) = @_;

	print $chandle . " says: ". $message. "\n";
  
	if ($message =~ /^reply/i)
		{	$sb->sendmsg('yes, what would you like?');
		}
	else
		{	$sb->sendmsg( "Did you say this: \"$message\"?");
		}
}



sub on_bye 
{	my ($chandle) = @_;

	print( "$chandle has left the conversation (switch board)\n");
}



sub on_join 
{	my ( $sb, $chandle, $friendly ) = @_;

	print( "$chandle has joined the conversation (switch board)\n" );
}



sub on_answer 
{	my $sb = shift;
	
print "on_answer\n";
#print "Answer() called with parameters:\n";
#print "   " . join(", ", @_), "\n";
}



sub auth_add 
{	my ($chandle, $friendly) = @_;

	print( "Received authorisation request to add $chandle\n" );

	return 1;
}



sub log_print
{
	print "log print: ";
	print @_;
	return if ( ! defined $client );
	$client->{_Log}( @_, 3);
}



################################################################################
#
sub DownloadWebpage( $ )
#
# Given a url, download and return the content, or undef and an error message
#
################################################################################
{	my $url = shift;
	
    # put the URL into the format http://url
    my $url_string = "http:\/\/" . $url;

	print "Downloading web page $url_string ...\n";
	
    $| = 1;

    my $ua = LWP::UserAgent->new();
    $ua->agent("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50215)");

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
		
	return( $content, undef );
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
Usage: $me [OPTION(s)]  [input-file]
    
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
