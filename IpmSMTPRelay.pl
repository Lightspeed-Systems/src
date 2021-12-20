################################################################################
#!perl -w
#
# Rob McCarthy's IpmSMTPRelay source code
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;
use Content::File;
use Content::Relay;
use Content::Mail;
use Content::ClientNoWait;

use Errno qw(EROFS ESHUTDOWN EPROTONOSUPPORT ENFILE ENOLCK
	EADDRINUSE ECONNABORTED EBADF EDEADLK ENOTDIR EINVAL ENOTTY EXDEV
	ELOOP ECONNREFUSED EISCONN EFBIG ECONNRESET EPFNOSUPPORT ENOENT
	EDISCON EWOULDBLOCK EDOM EMSGSIZE EDESTADDRREQ ENOTSOCK EIO ENOSPC
	EINPROGRESS ENOBUFS ERANGE EADDRNOTAVAIL EAFNOSUPPORT ENOSYS EINTR
	EHOSTDOWN EREMOTE EILSEQ ENOMEM ENOTCONN ENETUNREACH EPIPE ESTALE
	EDQUOT EUSERS EOPNOTSUPP ESPIPE EALREADY EMFILE ENAMETOOLONG EACCES
	ENOEXEC EISDIR EPROCLIM EBUSY E2BIG EPERM EEXIST ETOOMANYREFS
	ESOCKTNOSUPPORT ETIMEDOUT ENXIO ESRCH ENODEV EFAULT EAGAIN EMLINK
	EDEADLOCK ENOPROTOOPT ECHILD ENETDOWN EHOSTUNREACH EPROTOTYPE
	ENETRESET ENOTEMPTY);

use Fcntl qw(:DEFAULT :flock);
use Getopt::Long;
use IO::Poll qw(POLLIN POLLOUT POLLERR POLLHUP );
use IO::Socket;
use IO::Select;
use IO::SessionSet;
use IO::LineBufferedSet;
use IO::LineBufferedSessionData;
use Net::DNS;
use Net::SMTP;
use Net::SMTP::Server;
use Net::SMTP::Server::Relay;
use Sys::Hostname;
use Net::Domain qw(hostfqdn); 
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;
use Win32::EventLog;
use Win32::Process;
use Win32::File;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging;				# True if I should log to the file IpmCache.log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_receive;				# True if I should receive emails only - don't send them back out
my $opt_send;					# True if I should send emails only - don't receive any
my $opt_open;					# True if running as an open relay server
my $opt_host;					# True if I should just return my hostname that I am listening to
my $opt_empty;					# True if I should send everyting in the spool directory and then quit once it is empty
my $opt_wizard;					# True if run from a Wizard dialog
my $opt_child;					# True if the sub processes should die if the events don't exist
my $opt_skip_errors;			# True if any sending errors should be immediately skipped without retrying
my $smtp_active = 1;			# False if the Active value in the SMTP Relay registry is set to 0
my $_version = "1.0.0";



# Process control global variables
my $outgoing_event_name			= "IpmSTMPRelayOutgoingEvent";
my $incoming_event_name			= "IpmSTMPRelayIncomingEvent";
my $monitor_unique_event_name	= "IpmSTMPRelayMonitorUniqueEvent";
my $outgoing_unique_event_name	= "IpmSTMPRelayOutgoingUniqueEvent";
my $incoming_unique_event_name	= "IpmSTMPRelayIncomingUniqueEvent";
my $incoming_pid;				# The child process id
my $outgoing_pid;				# The child process id
my $child_task;					# True if I am a child task, false if not



# Variables used globally by all processes
my $myipaddress;				# The IP address I am listening on
my $myhostname;					# My hostname - displayed for information purposes



# Incoming global variables
my $max_incoming_queue_size = 0 + 48;	# The maximum size of the incoming queue
my @clients;					# The list of active client connections
my $spool;						# The directory to put messages into - shared by incoming and outgoing
my $incoming_spool;				# The directory to put incoming messages into - usually the same as spool
my $session_set;				# LineBufferedSet control variable
my %client_hostname;			# Hash of client hostnames - done to speed up incoming connections


# Outgoing global variables
my $max_outgoing_queue_size = 0 + 12;	# The maximum size of the outgoing queue
my @outgoing;					# The list of outgoing sessions with FROM, TO, and MSG, etc
my @outgoing_errors;			# The list of files that had outgoing errors - file names, number of retries, next retry time, error message
my %mail_exchangers;			# The list of mail exchanges, indexed by domain name, value is the server name
my %best_mx;					# If an entry exists, it is the mx server that last worked best, indexed by the mx1 server
my %mx2;						# Backup mx2 server list, indexed by the mx1 server
my %mx3;						# Backup mx3 server list, indexed by the mx1 server
my %disclaimer;					# My outgoing disclaimer message, indexed by domain name
my $poll;						# The poll event list main variable
my $check_spool_next_time = 0;  # The next time that I should check the spool directory	
my @last_directory_list;		# The last directory listing I read from the spool directory
my @bad_outgoing_files;			# This is a list of outgoing spool files that I was unable to delete
my @error_retries = ( 1, 2, 10, 60, 0 );		# This is the number of minutes to wait before retrying an errored session
my $my_mail_hostname;			# This is the fully qulified domain name of the smtp server used in HELO
my @relay_hold_domains;			# This is the list of domains to have on hold for smtp sending
my $check_spool_idle_time;		# This is the amount of time to wait between checking the spool directory for more stuff



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
		"a|skip"	=> \$opt_skip_errors,
		"c|child"	=> \$opt_child,
        "d|debug"	=> \$opt_debug,
        "e|empty"	=> \$opt_empty,
        "l|logging" => \$opt_logging,
        "n|name"	=> \$opt_host,
        "o|open"	=> \$opt_open,
        "r|receive" => \$opt_receive,
        "s|send"	=> \$opt_send,
        "v|version" => \$opt_version,
        "h|help"	=> \$opt_help,
        "w|wizard"	=> \$opt_wizard,
        "x|xxx"		=> \$opt_debug,
    );


	$opt_send = 1 if ( $opt_empty );
	
	
	if ( $opt_send )
		{	print "IpmSMTPRelay Outgoing process started\n";
		}
	elsif ( $opt_receive )
		{	print "IpmSMTPRelay Incoming process started\n";
		}
	else
		{	print "IpmSMTPRelay Monitor process started\n";
		}
	
	
	$spool = &SpoolDirectory();
	$incoming_spool = $spool;
	
    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	
	&debug( "Debugging messages turned on\n" );
	
	# Should I trap programming errors?
	&TrapErrors( $opt_send, $opt_receive ) if ( ! $opt_debug );
		
	# Figure out my IP address
	$myhostname			= lc( hostname() );
	my $fully_qualified = lc ( &hostfqdn() );
	$myipaddress		= inet_ntoa( ( gethostbyname( $myhostname ) )[ 4 ] );
	
	$my_mail_hostname	= $myhostname;
	if ( ! ( $my_mail_hostname =~ m/\./ ) )
		{	$my_mail_hostname = $fully_qualified;
		}
		

	# Get the properties out of the current configuration
	&GetProperties();


	# If I'm just supposed to show the hostname I can die here
	if ( $opt_host )
		{	print "SMTP relay hostname or IP address: $myipaddress\n";
			print "SMTP relay hostname: $my_mail_hostname\n";
			exit;	
		}

		
	# Load up the domain names and mail exchangers
	my @hostnames;
	@hostnames = &LoadMailExchangers() if ( $smtp_active );
	
	if ( ! $hostnames[ 0 ] )
		{	if ( $opt_receive )
				{	print "Can't receive only if no vaild mail exchangers are defined\n";
					exit;
				}
				
			# Am I relaying for anything at all?
			print "SMTP Relay Service is not active\n" if ( ! $smtp_active );
			print "Not relaying for any domains ...\n";		
		}
	
	
	if ( $#relay_hold_domains < 0 )
		{	&lprint( "There are no current relay on hold domains\n" );
		}
	else
		{	&lprint( "Current relay on hold domains are:\n" );
			foreach ( @relay_hold_domains )
				{	next if ( ! $_ );
					my $on_hold_domain = $_;
					&lprint( "On hold domain: $on_hold_domain\n" );
				}
		}
		
		
	# Get the list of domains that I will relay for
	my @allowed_domains = keys %mail_exchangers;
	&SetDomains( $opt_open, @allowed_domains );
	
	# Get the list of servers that I will accept anything from
	my @allowed_servers = values %mail_exchangers;
	my @servers = values %mx2;
	push @allowed_servers, @servers;
	@servers = values %mx3;
	push @allowed_servers, @servers;
	
	&SetServers( @allowed_servers );


	if ( $opt_send )
		{	&OutgoingProcess();
			exit;
		}
		
	if ( $opt_receive )
		{	&IncomingProcess();
			exit;
		}
		
		
	# Make sure that just one copy of this program is running in monitor mode
	my $unique_event = Win32::Event->open( $monitor_unique_event_name );
	if ( $unique_event )
		{	print "Another copy of IpmSMTPRelay monitor process is already running, so exiting now ...\n";
			exit( 0 );
		}

	$unique_event = Win32::Event->new( 1, 1, $monitor_unique_event_name );


	# Make sure that just one copy of this program is running in incoming mode
	my $incoming_unique_event = Win32::Event->open( $incoming_unique_event_name );
	if ( $incoming_unique_event )
		{	print "Another IpmSMTPRelay incoming process is already running, so exiting now ...\n";
			exit( 0 );
		}
		
		
	# Make sure that just one copy of this program is running in outgoing mode
	my $outgoing_unique_event = Win32::Event->open( $outgoing_unique_event_name );
	if ( $outgoing_unique_event )
		{	print "Another IpmSMTPRelay outgoing process is already running, so exiting now ...\n";
			exit( 0 );
		}
		
		
	&SetLogFilename( 'IpmSMTPRelay.log', $opt_debug );
	
	
	# Create the events to monitor the child tasks
	my $inevent;
	if ( $hostnames[ 0 ] )
		{	$inevent = Win32::Event->new( 1, 1, $incoming_event_name );
			$inevent->set;
		}
		
	my $outevent = Win32::Event->new( 1, 1, $outgoing_event_name );
	$outevent->set;
	
	
	my $path = &SoftwareDirectory();
	&lprint( "Software path set to $path\n" );
	
	
	#  Create to the outgoing process on it's own	
	&lprint( "Creating the outgoing process ...\n" );
	my $outgoing_process;	
	$path = $path . "\\IpmSMTPRelay.exe";
	my $cmd = "IpmSMTPRelay -s -c";
	$cmd .= " -x" if ( $opt_debug );
	my $ok = Win32::Process::Create( $outgoing_process, $path, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
	if ( ! $ok )
			{	my $str = Win32::FormatMessage( Win32::GetLastError() );
				&FatalError( "Unable to create outgoing process $path: $str\n" );
			}	
			

	# Should I create the incoming SMTP mail task?
	my $incoming_process;
	
	if ( $hostnames[ 0 ] )
		{	&lprint( "Creating the incoming process ...\n" );
			
			my $cmd = "IpmSMTPRelay -r -c";
			$cmd .= " -x" if ( $opt_debug );

			$ok = Win32::Process::Create( $incoming_process, $path, $cmd, 0, NORMAL_PRIORITY_CLASS, "." );
			if ( ! $ok )
				{	my $str = Win32::FormatMessage( Win32::GetLastError() );
					$outgoing_process->Kill( 0 );
					&FatalError( "Unable to create incoming process $path: $str\n" );
				}					
		}

	

	# Loop forever waiting for a big problem
	my $ret;
	my $done;
    while ( ! $done )    
		{	sleep( 30 );
			
			# Handle the outgoing process event
			$ret = $outevent->wait( 60000 );
			
			if ( ( ! $ret )  ||  ( $ret == -1 ) )
				{	&lprint( "IpmSMTPRelay outgoing process has stopped responding\n" );
					last;
				}
			else
				{	$outevent->reset;
					&debug( "Monitor Process: Outgoing process is alive\n" );
				}
				
			# Handle the incoming process event
			if ( $inevent )
				{	$ret = $inevent->wait( 60000 );
			
					if ( ( ! $ret )  ||  ( $ret == -1 ) )
						{	&lprint( "IpmSMTPRelay incoming process has stopped responding\n" );
							last;
						}
					else
						{	$inevent->reset;
							&debug( "Monitor Process: Incoming process is alive\n" );
						}				
				}
				
			# &debug( "bottom of main loop\n" );
		}
	
	&lprint( "Killing the child processes and terminating the monitor process\n" );
	$outgoing_process->Kill( 0 ) if ( $outgoing_process );
	$incoming_process->Kill( 0 ) if ( $incoming_process );
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
################################################################################
#########################   INCOMING SUBROUTINES   #############################
################################################################################
################################################################################



################################################################################
# 
sub IncomingProcess()
#
#  Process incoming SMTP clients
#
################################################################################
{
	&debug( "Incoming Process\n" );
	

	# Make sure that just one copy of this program is running in incoming mode
	my $unique_event = Win32::Event->open( $incoming_unique_event_name );
	if ( $unique_event )
		{	print "Another incoming process is already running, so exiting now ...\n";
			exit( 0 );
		}

	$unique_event = Win32::Event->new( 1, 1, $incoming_unique_event_name );
	
		
	# Do any necessary logging
	&SetLogFilename( 'IpmSMTPRelayIncoming.log', $opt_debug );
	my $logfile = &GetLogFilename();
	print "Incoming log file set to $logfile\n";
	
	my $server = new Net::SMTP::Server( "$myipaddress" ) ||  &ChildFatalError( "Unable to handle client connection: $!\n" );
	my $listen_socket = $server->{SOCK};
	
	$session_set = IO::LineBufferedSet->new( $listen_socket );
	
	@clients = ();
	
	&lprint( "Incoming process started ok\n" );
	&lprint( "SMTP relay hostname or IP address: $myipaddress\n" );
	&lprint( "SMTP relay hostname: $my_mail_hostname\n" );
	&lprint( "Working incoming spool directory set to $incoming_spool\n" );
	
	# Show the domains that I'm relaying for
	ShowMailExchangers();
			
	&debug( "Started incoming processing loop\n" );	
	
	my $next_time = 2 + time();
	my $sleep_counter = 0 + 0;
	
	while ( 1 )
		{	
			# Only signal the parent process about every 2 seconds
			my $current_time = time();
			if ( $next_time < $current_time )
				{	if ( $opt_child )
						{	my $loopevent = Win32::Event->open( $incoming_event_name );
							if ( ! $loopevent )
								{	&lprint( "Incoming Process: monitor process has disappeared - exiting now\n" );
									exit( 0 );
								}
							# Signal the inevent
							$loopevent->set;
							# &debug( "Incoming Process: signaled the monitor process\n" );
						}
						
					$next_time = 2 + $current_time;
					
					# Check for timeouts
					my $timeout = $current_time - 90;  # Give up if we haven't received anything for 90 seconds
	
					for ( my $i = 0;  $i <= $#clients;  $i++ )
						{	my $time = 0 + $clients[ $i ]->{TIME};
			
							next if ( $time > $timeout );  # If it hasn't gone 90 seconds, skip it
			
							my $delete_session = $clients[ $i ]->{SESSION};
			
							&lprint( "Client message timed out\n" );
							&DeleteClient( $delete_session );				
						}	
				}
				
				
			# Release memory if nothing is going on
			undef( @clients ) if ( $#clients == -1 );
	
			my $new_accepts			= 0 + 0;
			my $processed_clients	= 0 + 0;

#			my @ready = $session_set->waitforread( 2 );

			my @ready;
			eval {	@ready = $session_set->wait( 0 ); };

			if ( $ready[ 0 ] )
				{	foreach ( @ready )
						{	my $session = $_;
							next if ( ! $session );
							
							my $client = &client_session( $session );
		
							# If I don't have a client defined, it must be someone new
							if ( ! $client )
								{	&IncomingProcessAccepts( $session );
									$new_accepts++;
								}
							else
								{	&IncomingProcessClients( $session );
									$processed_clients++;
								}
						}
						
					$sleep_counter = 0 + 0;	
				}
			elsif ( $sleep_counter > 10 )
				{	&debug( "incoming sleeping\n" );
					sleep( 1 );
				}
			else
				{	$sleep_counter++;
				}
		}	# End of process loop

}	# End of Incoming Process



################################################################################
# 
sub client_session( $ )
#
#  Given a session, return the related client record or undef if I couldn't find it
#
################################################################################
{	my $session = shift;
	
	return( undef ) if ( ! defined $session );
	
	for ( my $i = 0;  $i <= $#clients;  $i++ )
		{	my $list_session = $clients[ $i ]->{SESSION};
			
			if ( $list_session eq $session )
				{	my $client = $clients[ $i ]->{CLIENT};
					return( $client );
				}
		}
		
	return( undef );		
}


################################################################################
# 
sub client_session_no( $ )
#
#  Given a session, return the related client record number, or undef
#
################################################################################
{	my $session = shift;
	
	return( undef ) if ( ! $session );
	
	for ( my $i = 0;  $i <= $#clients;  $i++ )
		{	my $list_session = $clients[ $i ]->{SESSION};
			return( $i ) if ( $list_session eq $session );
		}

	&debug( "client session no session = $session\n" );

	return( undef );		
}



################################################################################
# 
sub IncomingProcessAccepts( $ )
#
#  Process incoming SMTP clients accepts
#  Return non-zero if something happened
#
################################################################################
{	my $session = shift;
	
	&debug( "IncomingProcessAccepts, session = $session\n" );
	
	if ( $session )
		{	# Check that we haven't exceeded the queue size
			my $no_clients = $#clients + 1;
			&debug( "no_clients = $no_clients\n" );
			
			if ( $no_clients > $max_incoming_queue_size )
				{	&lprint( "Maximum incoming queue size reached - not accepting new clients\n" );
					&IncomingCloseSession( $session );

					&debug( "exiting IncomingProcessAccepts\n" );	
					return( 1 );	
				}
			
			
			# Create an SMTP server client
			&debug( "Creating a new SMTP server client ...\n" );
			my $client = new Content::ClientNoWait( $session->handle );


			if ( $client )
				{	&debug( "Getting client peername ...\n" );
					my $session_no = $#clients + 1;
					
					# Figure out the IP Address of the remote client
					my $str_ip;
					my $sock = $session->handle;

					
					my $remote_addr		= getpeername( $session->handle );
					my ($port, $ip)		= sockaddr_in( $remote_addr ) if ( $remote_addr );
					
					my $client_hostname;
					
					$str_ip = inet_ntoa( $ip ) if ( $ip );				
					
					if ( defined $str_ip )
						{	# Do I have a cached copy of this?
							$client_hostname = $client_hostname{ $str_ip };
							
							if ( ! defined $client_hostname )
								{	&debug( "Getting client hostname for ip $str_ip ...\n" );
									
									$client_hostname = gethostbyaddr( $ip, AF_INET );
									$client_hostname = "Unknown" if ( ! defined $client_hostname );
									$client_hostname{ $str_ip } = $client_hostname;
								}
						}
						
					$str_ip = "Unknown" if ( ! defined $str_ip );
					
					&lprint( "New client session_no = $session_no, IP address = $str_ip\n" );
						
					$clients[ $session_no ]->{CLIENT}	= $client;
					$clients[ $session_no ]->{SESSION}	= $session;
					$clients[ $session_no ]->{TIME}		= time();					
					$clients[ $session_no ]->{IP}		= $str_ip;
					$clients[ $session_no ]->{HOSTNAME}	= $client_hostname;
					$clients[ $session_no ]->{HANDLE}	= undef;
					$clients[ $session_no ]->{FILE}		= undef;
					$clients[ $session_no ]->{TO}		= undef;
					
					&debug( "created a client $client to handle the connection\n" );
				}
			else
				{	&lprint( "Error creating a no wait client: $!\n" );
				}
		}	
	else 
		{	&lprint( "Error accepting a connection: $!\n" );
		}

	&debug( "exiting IncomingProcessAccepts\n" );
	
	return( 1 );
}



################################################################################
# 
sub IncomingProcessClients( $ )
#
#  Process incoming SMTP client sessions
#
################################################################################
{	my $session = shift;
	
	&debug( "IncomingProcessClients\n" );
							
	# Get the client object reference
	my $client = &client_session( $session );
	
	if ( ! defined $client )
		{	&lprint( "No client defined for session $session\n" );
			&debug( "exiting IncomingProcessClients\n" );

			return;
		}
		
	my $session_no = &client_session_no( $session );
	if ( ! defined $session_no )
		{	&lprint( "Undefined session_no in IncomingProcessClients\n" );
			&debug( "exiting IncomingProcessClients\n" );

			return;
		}

	my $line;
	my $bytes;
	
	# Are we reading data??
	if ( defined $client->{DATA} )
		{	&debug( "data getlines\n" );
			$bytes = $session->getlines( $line );
			&PartialMessage( $session, $line ) if ( defined $line );
		}
	else
		{	&debug( "getline\n" );
			# Get the line of input
			$bytes = $session->getline( $line );
		}

	if ( ! defined $bytes )	# The session has ended
		{
			&debug( "Client session ended prematurely with an I/O error: $!\n" );
			&DeleteClient( $session, undef );
			&debug( "exiting IncomingProcessClients\n" );

			return;
		}
	
	# bytes will be 0 if the remote session closed down
	if ( ! $bytes )		
		{	&debug( "Client not connected anymore\n" );	
			&DeleteClient( $session, undef );
			&debug( "exiting IncomingProcessClients\n" );
			
			return;
		}

	# If something was read
	while ($bytes > 0)
		{
			$bytes = 0;
			
			my $ret = $client->process_line( $session, $line );
			
			if ( ! defined $ret )
				{
					&debug( "error processing client connection\n" );
					
					my $error = $client->{ERROR};
					&lprint( "Message received with an error: $error\n" ) if ( $error );
						
					&DeleteClient( $session, undef );
				}
				
			elsif ( $ret == 2 )  # end of message received
				{
					&debug( "got the client message ok\n" );
        
					my $ok = &SaveMessage( $session, $line );
					&debug( "Got an error in SaveMessage\n" ) if ( ! $ok );
				}
				
			elsif ( $ret == 1 )	# Quit command received
				{	&debug( "got a QUIT command\n" );
					&DeleteClient( $session, 1 );
				}
				
			else  # if the ret is 0 - more processing
				{
					# &debug( "more processing required\n" );
					$clients[ $session_no ]->{TIME} = time();
				}
		}

	&debug( "exiting IncomingProcessClients\n" );
	
	return;
}



################################################################################
# 
sub DeleteClient( $ )
#
#  Given a session, delete the client objects in the arrays
#
################################################################################
{	my $session = shift;
	my $success = shift;
	
	if ( ! defined $session )
		{	&lprint( "Undefined session in DeleteClient\n" );
			return;	
		}
		
	&debug( "delete client session = $session\n" );

	my $session_no = &client_session_no( $session );
	if ( ! defined $session_no )
		{	&lprint( "Undefined session_no in DeleteClient\n" );
			return;
		}
	
	&debug( "delete client session_no = $session_no\n" );
	

	&IncomingCloseSession( $session );	
	
	
	# Close the client
	my $client = &client_session( $session );
	
	if ( $client )
		{	$client->end_message();
			$client->close;
		}
	$client = undef;
	
	
	# Close the client file handle if I opened it
	close( $clients[ $session_no ]->{HANDLE} ) if ( $clients[ $session_no ]->{HANDLE} );
	
	# If we didn't close this session cleanly, then we're going to delete the file...
	if ( ! defined $success )
		{	&lprint( "Session # $session_no did not close cleanly\n" );
			&lprint( "Session # $session_no - deleting message file ...\n" );
			unlink( $clients[ $session_no ]->{FILE} ) if ( defined $clients[ $session_no ]->{FILE} );
		}
	
	$clients[ $session_no ]->{HANDLE} = undef;
	
	# Clean up the clients record
	$clients[ $session_no ]->{CLIENT}	= undef;
	$clients[ $session_no ]->{SESSION}	= undef;
	$clients[ $session_no ]->{TIME}		= undef;
	$clients[ $session_no ]->{IP}		= undef;
	$clients[ $session_no ]->{HOSTNAME}	= undef;
	$clients[ $session_no ]->{HANDLE}	= undef;
	$clients[ $session_no ]->{FILE}		= undef;
	$clients[ $session_no ]->{TO}		= undef;
	$clients[ $session_no ]				= undef;
	
	
	# Splice the session out of the list
	splice( @clients, $session_no, 1 );

	my $client_count = $#clients + 1;

	&debug( "Deleted client - current clients = $client_count\n" );
}



################################################################################
# 
sub IncomingCloseSession( $ )
#
#  Close the session - either the message ended, or we have too many connections
#
################################################################################
{	my $session = shift;
	
	&debug( "IncomingCloseSession\n" );

	if ( ! defined $session )
		{	&debug( "Undefined session in IncomingCloseSession\n" );
			
			return;	
		}
		
	my $ok = 1;
	
	# Close the session set handle
	my $session_handle = $session_set->to_handle( $session );
	$session_set->delete( $session );
	eval{	$session->close;	};
	if ( $@ )
		{	&lprint( "Error closing session $session, $@\n" );
			$ok = undef;
		}
		
	close $session_handle;	
	$session_handle = undef;
	
	&debug( "exiting IncomingCloseSession\n" );
	
	return( $ok );
}



################################################################################
# 
sub PartialMessage( $$ )
#
#  One of the clients has sent part of the message, but not all
#  Return True is everything ok, undef if not
#
################################################################################
{	my $session		= shift;
	my $msg_data	= shift;
	                 
	if ( ! defined $msg_data )
		{	&lprint( "PartialMessage: Undefined data\n" );
			return( undef );	                   
		}
		                 
	if ( ! defined $session )
		{	&lprint( "PartialMessage: Undefined session\n" );
			return( undef );	
		}
	
	&debug( "PartialMessage\n" );

	# Fix-up the line data...

  # RFC 821 compliance.
  $msg_data =~ s/^\.\./\./;
  $msg_data =~ s/\r\n\.\./\./;
	
	# remove the trailing "EOM" marker, if present.
	$msg_data =~ s/^\.\r\n$//;
	$msg_data =~ s/\r\n\.\r\n$//;
	
	
	# Get the client object reference
	my $client = &client_session( $session );
	
	if ( ! $client )
		{	&lprint( "PartialMessage: Could not find the client object for this session = $session\n" );
			return( undef );
		}
	
		
	my $session_no = &client_session_no( $session );
	
	if ( ! defined $session_no )
		{	&debug( "Trying to save a message for a client that does not exist\n" );
			return( undef );
		}


	my $str_ip = $clients[ $session_no ]->{IP};

	my $from = $client->{FROM};

	$from = &CleanEmail( $from );
	
	my @to;	
	my $to_list;
	foreach my $target ( @{ $client->{TO} } )
		{	$target = &CleanEmail( $target );	
			next if ( ! $target );
			
			$target = &AllowedEmailTo( $from, $target, $str_ip ) if ( ! $opt_open );
			next if ( ! $target );
			&debug( "Clean target TO = $target\n" );
			
			# If the TO: address is clean, and it matches an allowed domain, take it
			push @to, $target;
			$to_list .= ";" if ( $to_list );
			$to_list .= $target;
		}
		
		
	# Is there a valid to email address after being checked?
	if ( ! $to[ 0 ] )
		{	&lprint( "Message received without a valid from and/or to address\n" );
			&lprint( "Message from: $from\n" )  if ( $from );
			&lprint( "Message to @to\n" ) if ( $to[ 0 ] );
			return( undef );
		}
	
	
	# Was there an error?
	my $error = $client->{ERROR};
	
	
	if ( $error )
		{	&lprint( "Message received with an error: $error\n" );
			&lprint( "Mail IP address $str_ip\n" )  if ( $str_ip );
			&lprint( "Message from $from\n" ) if ( $from );
			&lprint( "Message to @to\n" ) if ( $to[ 0 ] );			
			return( undef );
		}


	# Have I opened a file handle for this session?
	my $handle = $clients[ $session_no ]->{HANDLE};
	
	
	# If the handle isn't opened yet - I better open it now
	if ( ! $handle )
		{	my $temp = 	&GetTempFile( $session );
			my $filename = $incoming_spool . "\\i" . $temp;

			&debug( "Creating message file $filename\n" );	

			if ( ! sysopen( $handle, $filename, O_WRONLY | O_CREAT | O_TRUNC ) )
				{	&debug( "Could not open file $filename: $!\n" );
					return( undef );
				}
					
			if ( ! flock( $handle, LOCK_EX | LOCK_NB ) )
				{	&debug( "Could not lock exclusively file $filename: $!\n" );
					close $handle;
					return( undef );
				}
				
				
			# Save the handle in the client record
			$clients[ $session_no ]->{HANDLE} = $handle;
		
			# Save the filename in the client record
			$clients[ $session_no ]->{FILE} = $filename;
		
			# Save the to_list in the client record
			$clients[ $session_no ]->{TO} = $to_list;

		
			# Ok, now dump the message header stuff out ...
			# Put a signature string as the first part of the file
			print $handle ( "MESSAGE FILE\n" );
			
			if ( $str_ip )
				{	print $handle ( "IP:\n" );
					print $handle ( "$str_ip\n" );
				}
				
			
			if ( $from )	
				{	print $handle ( "FROM:\n" );
					print $handle ( "$from\n" );
				}
			
				
			if ( @to )	
				{	print $handle ( "TO:\n" );
					
					foreach( @to )
						{	print $handle ( "$_\n" );
						}
				}
				
			print $handle ( "MSG:\n" );
			
			
			# Now print out the received header information for SMTP relay
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
			
			my @days = qw( Sun Mon Tue Wed Thu Fri Sat );
			my $day_str = $days[ $wday ];
			my @months = qw( Jan Feb Mar Apr May Jun July Aug Sept Nov Dec );
			my $mon_str = $months[ $mon ];
			my $timestr = sprintf( "%02d:%02d:%02d -0000", $hour, $min, $sec );
			$year = 1900 + $year;
			my $datestr = "$day_str, $mday $mon_str $year $timestr";
			
			$str_ip = "0.0.0.0" if ( ! defined $str_ip );
			my $client_hostname = $clients[ $session_no ]->{HOSTNAME};
			$client_hostname = $str_ip if ( ! defined $client_hostname );
			$client_hostname = $str_ip if ( ( $client_hostname )  &&  ( $client_hostname eq "Unknown" ) );
			
			print $handle "Received: from $client_hostname ([$str_ip]) by $my_mail_hostname with SMTP; $datestr\n";
			
			&debug( "Finished opening incoming message file & writing header\n" );
		}
		
	
	# Get the message into a local variable	
	
	my $len = length( $msg_data );	
 	print $handle ( $msg_data );
	
	&debug( "Partial message written for session_no = $session_no, length = $len\n" );
	
	return( 1 );
}



################################################################################
# 
sub SaveMessage( $$ )
#
#  One of the clients has completed with a successful message
#  Return True if I saved it ok, undef if not
#
################################################################################
{	my $session = shift;
	my $line	= shift;
	
	return if ( ! defined $session );
	
	&debug( "SaveMessage\n" );
	
	# Call partial message to save the last bit of data
	my $ok = &PartialMessage( $session, $line ) if ( defined $line );
	if ( ! $ok )
		{	&debug( "Error return from PartialMessage\n" );
			return( undef );	
		}
	
	# Get the client object reference
	my $client = &client_session( $session );
	
	if ( ! $client )
		{	&debug( "Could not find the client object for this session = $session\n" );
			return( undef );
		}
	
	my $session_no = &client_session_no( $session );
	
	if ( ! defined $session_no )
		{	&debug( "Trying to save a message for a client that does not exist\n" );
			return( undef );
		}

	
	my $handle = $clients[ $session_no ]->{HANDLE};
	my $from = $client->{FROM};
	$from = &CleanEmail( $from );
	
	
	# Am I supposed to add a disclaimer message for this domain?
	my $disclaimer = &DisclaimerMessage( $from );
	if ( ( $disclaimer )  &&  ( $handle ) )
		{	
			print $handle ( "$disclaimer" );
		}
		
		
	close $handle if ( $handle );
	$clients[ $session_no ]->{HANDLE} = undef;
	
	
	# Pull this stuff out just so I can display it
	my $filename		= $clients[ $session_no ]->{FILE};
	my $str_ip			= $clients[ $session_no ]->{IP};
	my $client_hostname	= $clients[ $session_no ]->{HOSTNAME};
	my $to				= $clients[ $session_no ]->{TO};
	
	
	&lprint( "Message received ok\n" );
	&lprint( "Received from IP address $str_ip\n" )			if ( defined $str_ip );
	&lprint( "Received from hostname $client_hostname\n" )	if ( defined $client_hostname );
	&lprint( "Message File $filename\n" )					if ( defined $filename );
	&lprint( "Message from $from\n" )						if ( defined $from );
	&lprint( "Message to $to\n" )							if ( defined$to );

	return( 1 );
}



################################################################################
# 
sub GetTempFile( $ )
#
#  Give a session, return a full path temporary file name
#  If the session number is a 0, make something up
#
################################################################################
{	my $session = shift;
	
	use Time::HiRes qw(gettimeofday);
	
	my $client_no;
	
	$client_no = &client_session_no( $session ) if ( $session );

	if ( ! defined $client_no )  # Just get a number from somewhere
		{	$client_no = 9999 - ( time() % 1000 );
		}
		
	my $client = sprintf( "%04s", $client_no );

	my ( $seconds , $milliseconds ) = gettimeofday;
	$milliseconds = sprintf ( "%06s",$milliseconds );

	$seconds = sprintf ( "%010s",$seconds );
	
	my $UID = $seconds . $milliseconds;

	my $filename = $client . $UID . "\.txt";

	return( $filename );
}



################################################################################
# 
sub DisclaimerMessage( $$ )
#  Given a from email address, and the message, return a disclaimer message
#  if required.  Return undef if not required
#
################################################################################
{	my $from	= shift;
	my $msg		= shift;
	
	return( undef ) if ( ! $from );
	
	my ( $junk, $domain ) = split /\@/, $from, 2;
	
	return( undef ) if ( ! $domain );
	
	my $disclaimer = $disclaimer{ $domain };
	
	return( undef ) if ( ! $disclaimer );
	
	# Find the boundary marker
	my $boundary;
	$boundary = $1 if ( $msg =~ m/boundary=(.*)\n/ );
	
	if ( $boundary )
		{	$boundary =~ s#\"##g;   #  Get rid of quotes
			$boundary = '--' . $boundary;	#  Add the dash dash
		}
	
	my $insert_text = "\n\n";

	$insert_text .= $boundary . "\nContent-Type: text/plain;\n\tcharset=\"us-ascii\"\nContent-Transfer-Encoding: quoted-printable\n\n" if ( $boundary );
	$insert_text .= "$disclaimer\n";

	return( $insert_text );
}



################################################################################
################################################################################
#########################   OUTGOING SUBROUTINES   #############################
################################################################################
################################################################################



################################################################################
# 
sub OutgoingProcess()
#
#  Process outcoming connections to SMTP servers
#
################################################################################
{	
	&debug( "Outgoing Process\n" );
	
	# Make sure that just one copy of this program is running in incoming mode
	my $unique_event = Win32::Event->open( $outgoing_unique_event_name );
	if ( $unique_event )
		{	print "Another outgoing process is already running, so exiting now ...\n";
			exit( 0 );
		}

	$unique_event = Win32::Event->new( 1, 1, $outgoing_unique_event_name );
	
		
	# Do any necessary logging
	&SetLogFilename( 'IpmSMTPRelayOutgoing.log', $opt_debug );
	my $logfile = &GetLogFilename();
	&lprint( "Outgoing log file set to $logfile\n" );
	&lprint( "Working spool directory set to $spool\n" );
	
	
	$poll = IO::Poll->new() or &ChildFatalError( "Can't create IO::Poll object, $!\n" );
				

	# Figure out what time it is, and the current hour
	my $next_time = time();
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $next_time );
	my $current_hour = $hour;
	
	
	# Keep track if the outgoing sockets get stuck for an extended amount of time
	my $sockets_stuck;
	
	&lprint( "Outgoing process started ok\n" );
	&lprint( "SMTP relay hostname or IP address: $myipaddress\n" );
	&lprint( "SMTP relay hostname: $my_mail_hostname\n" );

			
	while ( 1 )		# Start of infinite loop
		{	my $work = 0 + 0;
	
			# Only signal the parent process about every 2 seconds
			my $current_time = time();
			if ( $next_time < $current_time )
				{	if ( ( $opt_child )  &&  ( ! $sockets_stuck ) )
						{	my $loopevent = Win32::Event->open( $outgoing_event_name );
							if ( ! $loopevent )
								{	&lprint( "Outgoing Process: monitor process has disappeared - exiting now\n" );
									exit( 0 );
								}
								
							# Signal the inevent
							$loopevent->set;
							# &debug( "Outgoing Process: signaled the monitor process\n" );
						}
						
					$next_time = 2 + $current_time;	
					
					# Report that we are stuck if that is going on
					if ( $sockets_stuck )
						{	my $count = $#outgoing + 1;
							&lprint( "The outgoing SMTP sockets are stuck with $count outgoing open sessions\n" ); 							
						}
						
					# Set the stuck flag so that if something resets it in the next couple of seconds,
					# we will know
					$sockets_stuck = 1;
					
					
					# Should I dump the best mx's and try the original mx's again?
					# Dump them every hour
					my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $current_time );
					%best_mx = () if ( $current_hour ne $hour );
					$current_hour = $hour;
				}
				

			# Are there any new files in the spool directory?
			$work += &CheckSpoolDirectory();
			

			# Are there new sessions waiting to be opened?
			&debug( "Checking for new sessions waiting to be opened ...\n" );
			for ( my $i = 0;  $i <= $#outgoing;  $i++ )
				{	$work += &OutgoingOpenSession( $i );
					
					# Have I taken too long here?
					my $current_time = time();
					if ( $next_time < $current_time )
						{	&debug( "Taking too long on OutgoingOpenSession, session_no $i\n" );
							$work++;
							$i = ( 1 + $#outgoing );	
						}
				}
				
				
				
			# The sockets aren't stuck if there is nothing going on
			$sockets_stuck = undef if ( $#outgoing == -1 );
			
			if ( ( $#outgoing == -1 )  &&  ( $#outgoing_errors == -1 ) )
				{	&debug( "Nothing is going on ...\n" );
				}
			
			
			# Release memory if nothing is going on
			undef( @outgoing ) if ( $#outgoing == -1 );
			undef( @outgoing_errors ) if ( $#outgoing_errors == -1 );
			
			
			my $written_sockets = 0;
			&debug( "Checking for handle events ...\n" );
			my $events = $poll->poll( 2 );	# Returns how many handles had events, or -1 if an error
			
			if ( $events > 0 )
				{	&debug( "Had $events polling events\n" );
					
					my @sockets = $poll->handles( POLLOUT | POLLERR );	# Returns which handles had these events
					foreach ( @sockets )
						{	my $socket = $_;
							
							$work += &OutgoingMessages( $socket );
							$written_sockets++;
							
							# Have I taken too long here?
							$current_time = time();
							if ( $next_time < $current_time )
								{	&debug( "Taking too long on OutgoingMessages\n" );
									$work++;
									last;
								}
						}
						
					# The sockets aren't stuck if I was able to write some data
					$sockets_stuck = undef if ( $written_sockets );
					&debug( "Wrote data on $written_sockets sockets\n" ) if ( $written_sockets );
				}
			elsif ( $events < 0 )
				{	&lprint( "Polling error: $!\n" );
					sleep( 2 );
				}
			else
				{	&debug( "Waiting 2 seconds for more events ...\n" );
					sleep( 2 );
				}
		}	# end of infinite loop
}



################################################################################
# 
sub OutgoingMessages( $ )
#
#  Write out the rest of the message to the remote server - no blocking allowed
#  A socket poll event has happened to even get to this situation
#
################################################################################
{	my $client = shift;	# The socket is the SMTP client created in OutgoingOpenSession
	
	&debug( "OutgoingMessages, client = $client\n" );

	# Figure out the session number
	my $session_no;
	for ( my $i = 0;  $i <= $#outgoing;  $i++ )
		{	my $outgoing_socket = $outgoing[ $i ]->{SOCKET};
			next if ( ! $outgoing_socket );
			$session_no = $i if ( $outgoing_socket eq $client );
		}
	
	
	# Have a got a session for this client?
	if ( ! defined $session_no )
		{	&lprint( "Got a socket handle for which there is no matching session, socket = $client\n" );
			return( 0 + 0 );
		}
			
		
	# At this point I'm just writing data to the other SMTP server
	my $win = "";
	my $wout;
	vec( $win, fileno( $client ), 1 ) = 1;
	
	
	# Is it ready for writing?
	if ( select( undef, $wout=$win, undef, 0 ) > 0 )
		{	my $handle = $outgoing[ $session_no ]->{HANDLE};
			my $buf;	# Buffer to read into
			my $bytes = read( $handle, $buf, ( 16 * 1024 ) );


			# Was there an error reading the file?
			if ( ! defined $bytes )
				{	my $file = $outgoing[ $session_no ]->{FILE};
					&MessageError( $session_no, "Error reading file $file: $!", 1 );
					
					# Return work done
					return( 0 + 1 );
				}
				
			# Have I already sent everything?
			elsif ( $bytes == 0 )
				{	# Send the last couple of bytes of the dataend
					my $ok = $client->dataend();
					
					# Flush any data still waiting to go out
					$client->autoflush( 1 );

					if ( ! $ok )
						{	my $code = $client->code();
					
							# A code of 354 is no big deal, but report anything else
							if ( $code ne "354" )
								{	my $message = $client->message();
									$message = "No cmd message" if ( ! defined $message );
									
									# Handle a code of 000
									if ( $code eq "000" )
										{	$message = "Dataend command still pending after 30 seconds\n";
										}
									
									&MessageError( $session_no, "Error writing DATA to session $session_no: $code, cmd message: $message", undef );
								}
						}
						
					# Send the quit message
					$client->quit();	
	
					# Flush any data still waiting to go out
					$client->autoflush( 1 );
					
					&MessageSent( $session_no );
					
					# Return work done
					return( 0 + 1 );
				}
				
			
			# Ok if I go to here then I must have some data in the buf to send ...	
			&debug( "Sending DATA, session_no $session_no, length = $bytes\n" );
			
			
			my $send_ok = $client->datasend( $buf );
			
			if ( ! $send_ok )	# Did I have a problem sending it?
				{	if ( $! == EWOULDBLOCK )
						{	&debug( "EWOULDBLOCK error: $!\n" );
							return( 0 + 1 );
						}
						
					&lprint( "Error writing to socket: $!\n" );
					&MessageError( $session_no, "Error writing to socket: $!", undef );
				
					# Return work done
					return( 0 + 1 );
				}
		}
	else	# I must have received an error event
		{	&MessageError( $session_no, "Polling error on session no = $session_no: $!\n", undef );
		}
		
	# The socket isn't ready for writing right now
	return( 0 + 0 );
}



################################################################################
# 
sub MessageSent( $ )
#
#  The message for the given session number was sent ok
#
################################################################################
{	my $session_no = shift;
	&debug( "MessageSent, session number = $session_no\n" );
	
	$session_no = 0 + $session_no;
	
	my $file	= $outgoing[ $session_no ]->{FILE};
	my $to		= $outgoing[ $session_no ]->{TO};
	my $from	= $outgoing[ $session_no ]->{FROM};
	my $mx		= $outgoing[ $session_no ]->{ACTUAL_MX};
	

	&lprint( "Message TO: $to was sent ok\n" ) if ( defined $to );
			
	my $full_path = $spool . "\\" . $file if ( defined $file );
			
	&debug( "File $full_path\n" )		if ( defined $full_path );
	&debug( "Mail Exchange $mx\n" )		if ( defined $mx );
	&debug( "Message from $from\n" )	if ( $from );
	&debug( "Message to $to\n" )		if ( $to );

		
	# Clear it out of any outgoing errors list and maybe delete the file
	&OutgoingErrorsClose( $file, $session_no, $to, undef );	

	# Close the session, sockets, and clean up all the records
	&OutgoingCloseSession( $session_no );	
}



################################################################################
# 
sub MessageError( $$$ )
#
#  The message for the given session number had a bad error - add it to the current 
#  errors list.  The second parameter is the error message.  The third parameter
#  is if the error was fatal
#
################################################################################
{	my $session_no	= shift;
	my $err_msg		= shift;
	my $fatal		= shift;
	
	&debug( "MessageError\n" );
	
	if ( $opt_skip_errors )
		{	&debug( "Skip on errors is set, so deleting message file\n" );
			$fatal = 1;
		}
	
	my $file		= $outgoing[ $session_no ]->{FILE};
	my $to			= $outgoing[ $session_no ]->{TO};
	my $from		= $outgoing[ $session_no ]->{FROM};
	my $mx			= $outgoing[ $session_no ]->{MX};
	my $actual_mx	= $outgoing[ $session_no ]->{ACTUAL_MX};
	
	
	if ( ! $file )
		{	&debug( "No file name defined for outgoing session # $session_no\n" );
			$file = "Missing File";
		}
		
	
	chomp( $err_msg );
	
	
	my $type = "fatal";
	$type = "retry possible" if ( ! $fatal );
	&lprint( "Message error: $err_msg - type: $type\n" );
	&lprint( "Message error from: $from\n" ) if ( defined $from );
	&lprint( "Message error to: $to\n" ) if ( defined $to );
	&lprint( "Message error file: $file\n" );
	&lprint( "Message error original MX: $mx\n" );
	&lprint( "Message error actual MX: $actual_mx\n" ) if ( $actual_mx ne $mx );
	

	# Update the outgoing errors list
	# See if I already have this file in my outgoing errors list
	my $found = undef;
	for ( my $i = 0;  $i <= $#outgoing_errors;  $i++ )
		{	my $errors_file = $outgoing_errors[ $i ]->{FILE};
			my $errors_to	= $outgoing_errors[ $i ]->{TO};
			
			$found = $i if ( ( $file eq $errors_file )  &&
						    ( $to eq $errors_to ) );
		}
		
	
	# Was it a fatal error?	
	if ( $fatal )
		{	&BounceMessage( $session_no, $err_msg );
			
			# Clean up the outgoing errors list and delete the file
			&OutgoingErrorsClose( $file, $session_no, $to, undef );
		}
	
	elsif ( defined $found )	# I have seen this guy before
		{	# Increment the retry count
			my $retries = $outgoing_errors[ $found ]->{RETRIES};
			$retries++;
			$outgoing_errors[ $found ]->{RETRIES} = $retries;
			
			&debug( "Error retry count = $retries, outgoing errors # $found\n" );
			
			# Save the error message
			$outgoing_errors[ $found ]->{ERRMSG} = $err_msg;

			
			# Have we tried enough times?
			if ( ! $error_retries[ $retries ] )
				{	&lprint( "Giving up on sending message TO: $to after $retries retries\n" );
							
					&BounceMessage( $session_no, "Message file TO: $to was unable to be sent after $retries retries\n" );
			
					# Clean up the outgoing errors list and delete the file
					&OutgoingErrorsClose( $file, $session_no, $to, undef );
				}
			else  # Wait a while longer and retry it
				{	my $etimeout = $error_retries[ $retries ];
					
					$etimeout = 0 + 1 if ( $opt_debug );		# If debugging use a short timeout
					$outgoing_errors[ $found ]->{NEXT} = ( $etimeout * 60 ) + time();	# This is the next time to retry
					
					&lprint( "Error retry $retries for message TO: $to - will retry in $etimeout minutes\n" );
				}
		}
	
	# Is this a SpamChallenge message?  If so, don't give it any error retries since it probaly isn't going anywhere	
	elsif ( $file =~ m/^SpamChallenge/i )
		{	&lprint( "Giving up on sending spam challenge message TO: $to\n" );
					
			&BounceMessage( $session_no, "Message file TO: $to was unable to be sent\n" );
	
			# Clean up the outgoing errors list and delete the file
			&OutgoingErrorsClose( $file, $session_no, $to, undef );
		}
		
	else 	# It is a new error entry - so create it
		{	my $k = $#outgoing_errors + 1;
			$outgoing_errors[ $k ]->{RETRIES}	= 0 + 0;
			
			my $etimeout = $error_retries[ 0 ];
			$etimeout = 0 + 1 if ( $opt_debug );		# If debugging use a short timeout
			$outgoing_errors[ $k ]->{NEXT}		= ( $etimeout * 60 ) + time();	# This is the next time to retry
			
			$outgoing_errors[ $k ]->{FILE}		= $file;
			$outgoing_errors[ $k ]->{ERRMSG}	= $err_msg;
			$outgoing_errors[ $k ]->{TO}		= $to;
			$outgoing_errors[ $k ]->{MX}		= $mx;
			
			&lprint( "First error for message TO: $to - will retry in $etimeout minutes\n" );
		}
		
				
	# Clean up the outgoing session	
	&OutgoingCloseSession( $session_no );
	
	return( 0 + 1 );
}



################################################################################
# 
sub OutgoingErrorsClose( $$$$ )
#
#  Given the error file name, clean up the outgoing_errors entry and delete the file
#  There are 4 ways this function can be called
#  Somebody deleted the message file outside of this program, so give up
#  A fatal error happened, so give up
#  The message was retried enough times, so I give up
#  Or the message file was finally sent ok
#  Anyway it happens, get rid of the entry and delete the file if it is ok
#
################################################################################
{	my $file		= shift;
	my $session_no	= shift;	# This is the session no that is closing, or undef if none
	my $to			= shift;	# This is the to list for this file, or undef if unknown
	my $deleted		= shift;	# True if the file has been delete, so remove it from the errors list no matter what the to: field is
	
	return if ( ! defined $file );
	
	
	if ( ( defined $session_no )  &&  ( defined $to ) )
		{	&debug( "OutgoingErrorsClose file $file, session_no = $session_no, to = $to\n" );
		}
	else
		{	&debug( "OutgoingErrorsClose file $file, undef session_no\n" );
		}
	
	
	# Remove the file from the outgoing errors list if it is there
	for ( my $i = 0;  $i <= $#outgoing_errors;  $i++ )
		{	my $errors_file = $outgoing_errors[ $i ]->{FILE};
			next if ( ! defined $errors_file );
			
			my $errors_to	= $outgoing_errors[ $i ]->{TO};
			$errors_to = "error" if ( ! defined $errors_to );
			
			$to = $errors_to if ( ! defined $to );	# If TO is undefined, then delete away
			$to = $errors_to if ( $deleted );		# If file is deleted, then delete away the errors entry
			
			# If the file name and the TO: match, then I can delete the file
			if ( ( $file eq $errors_file )  &&  ( $to eq $errors_to ) )
				{	$outgoing_errors[ $i ]->{RETRIES}	= undef;
					$outgoing_errors[ $i ]->{NEXT}		= undef;
					$outgoing_errors[ $i ]->{FILE}		= undef;
					$outgoing_errors[ $i ]->{ERRMSG}	= undef;
					$outgoing_errors[ $i ]->{TO}		= undef;
					$outgoing_errors[ $i ]->{MX}		= undef;
					$outgoing_errors[ $i ]				= undef;
									
					splice( @outgoing_errors, $i, 1 );
					
					
					# Should I go ahead and delete the file?
					my $delete_ok;
					
					# If no session was closing, just delete it
					if ( ! defined $session_no )
						{	$delete_ok = 1;
						}
					else	# If another session is still using it, don't delete
						{	$delete_ok = 1;
							for ( my $k = 0;  $k <= $#outgoing;  $k++ )
								{	next if ( $k == $session_no );
									
									my $check_file = $outgoing[ $k ]->{FILE};
									$delete_ok = undef if ( $check_file eq $file );
								}
							
						}
						
					# If nobody else but the closing session is using the file, delete it
					if ( ( $delete_ok )  &&  ( ! $deleted ) )
						{	my $full_file_name = $spool . "\\" . $file;	
							
							if ( defined $session_no )
								{	# Should I close this handle?
									my $handle = $outgoing[ $session_no ]->{HANDLE};
									close( $handle ) if ( $handle );
									$outgoing[ $session_no ]->{HANDLE} = $handle;
								}
								
								
							# Delete the file out of the spool directory
							&DeleteSpoolFile( $full_file_name );
						}
				}
		}
}



################################################################################
# 
sub BounceMessage( $$ )
#  After trying to send a message a bunch of time, or a fatal message error, I give up
#  Now try to bounce the message back
#  The second parameter is the error message that happened
#
################################################################################
{	my $session_no = shift;
	my $err_msg = shift;
	
	use Net::SMTP::Multipart;	
	
	&debug( "BounceMessage\n" );
	
	my $msg = "Unable to deliver message.\n\.\r\n";
		
	my $from = "bounce\@" . $myhostname;
	
	my $mx = $outgoing[ $session_no ]->{IP};
	if ( ! $mx )
		{	&lprint( "No return IP address defined for bounce message so not sending\n" );
			return;
		}
	
	my $to = $outgoing[ $session_no ]->{FROM};
	if ( ! $to )
		{	&lprint( "No TO: defined for bounce message so not sending\n" );
			return;
		}
		
    #  This can fail with a bad error if the host isn't there, so wrap it with an eval
    my $smtp;
    eval {  $smtp = Net::SMTP::Multipart->new( $mx, Hello => $my_mail_hostname, Timeout => 30 );  };

    if ( !$smtp )
		{	&lprint( "Unable to connect to SMTP server at $mx to send bounce message\n" );
			&lprint ( "Caught error: $@\n" );  
			return;
		}


    $smtp->Header( To   => $to,
				   Subj => "Error trying to deliver email message",
				   From => $from );

   
    #  Get the multipart boundary
	my $b = $smtp->bound;

    $smtp->datasend( sprintf"\n--%s\n",$b );       
	$smtp->datasend( "Content-Type: text/plain;\n" );
	$smtp->datasend( "	charset=\"us-ascii\"\n" );
	$smtp->datasend( "Content-Transfer-Encoding: quoted-printable\n\n" );

    my $text;
	
	
    $smtp->datasend( "=20\n\n" );
		
	$text = "SMTP Relay server $myhostname was unable to deliver this message.";
	
    $smtp->datasend( $text );
    $smtp->datasend( "=20\n\n" );

		
    if ( $to )
	  {  $text = "Original Sender: $to";
		 $smtp->datasend( $text );
         $smtp->datasend( "=20\n\n" );
	  }

	  
	my $to_list = $outgoing[ $session_no ]->{TO};
	my @to = split " ", $to_list;
	
	  
	$text = "Original Recipient(s): $to";
	$smtp->datasend( $text );
    $smtp->datasend( "=20\n\n" );
     
	$smtp->dataend;

    $smtp->quit;
}



################################################################################
# 
sub OutgoingCloseSession( $ )
#
#  A session is finished, one way or another, so clean up everything
#
################################################################################
{	my $session_no = shift;
	
	&debug( "OutgoingCloseSession, session no = $session_no\n" );
	
	if ( ! defined $session_no )
		{	&debug( "Bad session_no in OutgoingCloseSession\n" );
			return( undef );	
		}
		
	if ( ! defined $outgoing[ $session_no ] )
		{	&debug( "Undefined session in OutgoingCloseSession\n" );
			return( undef );	
		}
	
	my $file = $outgoing[ $session_no ]->{FILE};
	if ( ! $file )
		{	&debug( "Bad file name in OutgoingCloseSession\n" );
			return( undef );	
		}
		
		
	my $to		= $outgoing[ $session_no ]->{TO};
	my $handle	= $outgoing[ $session_no ]->{HANDLE};
	
	
	# Should I close this handle?
	if ( $handle )
		{	&debug( "Closing file $file\n" );
			close( $handle );
			$outgoing[ $session_no ]->{HANDLE} = $handle;
		}
	

	# Should I delete the file?	
	my $delete_ok = 1;
	
	
	# See if any other outgoing session has this same file in use
	for ( my $i = 0;  $i <= $#outgoing;  $i++ )
		{	next if ( ! $file );
			next if ( $i == $session_no ); # skip my session
			my $check_file = $outgoing[ $i ]->{FILE};
			next if ( ! defined $check_file );
			
			if ( $file eq $check_file )
				{	$delete_ok = undef;
					&debug( "Check: Can not delete file $file because still trying to send to someone else\n" );
				}
		}
			
	
	# See if it is in my errors list at all
	for ( my $i = 0;  $i <= $#outgoing_errors;  $i++ )
		{	next if ( ! $file );
			
			my $errors_file = $outgoing_errors[ $i ]->{FILE};

			if ( $errors_file eq $file )	    
				{	$delete_ok = undef;				
					&debug( "Errors: Can not delete file $file because still trying to send outgoing error\n" );
				}
		}
			
	
	# If the file isn't used in any other outgoing session or is not errored, go ahead and delete it
	if ( ( $delete_ok )  &&  ( $file ) )
		{	my $full_file_name = $spool . "\\" . $file;	
			
			# Delete the file out of the spool directory
			&DeleteSpoolFile( $full_file_name );
		}
	
		
	my $socket = $outgoing[ $session_no ]->{SOCKET};
	
	
	# Should I remove this socket from polling?
	if ( ( defined $socket )  &&  ( defined $outgoing[ $session_no ]->{POLLFD} ) )
		{	
			# Is this IO handle still open?
			my $fileno = fileno( $socket );	# This will return undef if the file is not open
				
			if ( defined $fileno )
				{	&debug( "Removing session $session_no from polling, socket = $socket\n" );
					$poll->remove( $socket ); 
				}
			else
				{	&debug( "Removing file descriptor for session $session_no from polling\n" );
					my $pollfd = $outgoing[ $session_no ]->{POLLFD};
					$poll->removefd( $socket, $pollfd ) if ( defined $pollfd ); 
				}
				
			$outgoing[ $session_no ]->{POLLFD} = undef;
		}
		
		
	# Should I close this socket?
	if ( defined $socket )
		{	&debug( "Closing this session's socket\n" );
			$socket->close;
		}
		
	
	# Clean up the outgoing record
	$outgoing[ $session_no ]->{FILE}		= undef;
	$outgoing[ $session_no ]->{FROM}		= undef;
	$outgoing[ $session_no ]->{TO}			= undef;
	$outgoing[ $session_no ]->{HANDLE}		= undef;
	$outgoing[ $session_no ]->{SOCKET}		= undef;
	$outgoing[ $session_no ]->{MX}			= undef;
	$outgoing[ $session_no ]->{ACTUAL_MX}	= undef;
	$outgoing[ $session_no ]->{POLLFD}		= undef;
	$outgoing[ $session_no ]->{IP}			= undef;
	$outgoing[ $session_no ]				= undef;

					
	# Remove the session entry from the session table
	splice( @outgoing, $session_no, 1 );
}



################################################################################
# 
sub OutgoingOpenSession( $ )
#
#  Given the session_no, open up the session to start sending data ...
#  Open the initial connection socket connection to the remote SMTP server
#  Open and position the file pointer in the message file in the spool directory
#  Return non zero if there was some work done
#
################################################################################
{	my $session_no = shift;
		
	# Is this session already opened?
	return( 0 + 0 ) if ( $outgoing[ $session_no ]->{SOCKET} );
		
	&debug( "OutgoingOpenSession, session number = $session_no\n" );
		
	my $client;
	
	# Is this session defined?
	return( 0 + 0 ) if ( ! defined $outgoing[ $session_no ]->{TO} );
	
    # Loop through the recipient list.
	my $to_list = $outgoing[ $session_no ]->{TO};

	my @to = split " ", $to_list if ( defined $to_list );
	
	
	# Figure out the best mx I can connect to
	my $original_mx = $outgoing[ $session_no ]->{MX};
	
	# Bail out if I don't have an MX
	return( 0 + 0 ) if ( ! defined $original_mx );
	
	# Try mx2 & mx3 if mx1 doesn't work
	my $mx2;
	$mx2 = $mx2{ $original_mx } if ( ( $original_mx )  &&  ( defined $mx2{ $original_mx } ) );
	
	my $mx3;
	$mx3 = $mx3{ $original_mx } if ( ( $original_mx )  &&  ( defined $mx3{ $original_mx } ) );
	
	
	# Build the list of mx's to try
	my @mx;
	
	
	# Are we already using a better mx server?
	# If so, push it on first
	my $mx = undef;
	
	if ( defined $best_mx{ $original_mx } )
		{	$mx = $best_mx{ $original_mx };
			&debug( "Best mx is $mx\n" );
		}
		
	push @mx, $mx if ( defined $mx );
	
	push @mx, $original_mx;
	push @mx, $mx2 if ( defined $mx2 );
	push @mx, $mx3 if ( defined $mx3 );
			
	&debug( "Trying to connect to mail exchange(s) @mx\n" );

	# Wrap this with an eval
	eval {	$client = new Net::SMTP( \@mx, Hello => $my_mail_hostname, Timeout => 30 );	};
	
	# Did I connect to the mx?			
	if ( $client )
		{	$mx = $client->host();
			&lprint( "Connected to mail exchange $mx OK\n" );
		}
	
	&lprint( "Unable to connect to mail exchange(s) @mx\n" ) if ( ! defined $client );
				
	
	# If I don't have a client here, then I was unable to creat a session with any of the mx's
	if ( ! defined $client )	
		{	&MessageError( $session_no, "Unable to connect to mail exchange(s) @mx", 1 );
			return( 0 + 0 );
		}
		
	
	# Save the socket/client now that I've opened it ok
	$outgoing[ $session_no ]->{SOCKET} = $client;

	
	# If the main mx didn't work, save the one that did
	if ( $original_mx ne $mx )
		{	$best_mx{ $original_mx } = $mx;
			&debug( "Saving the best mx $mx that worked for original mx $original_mx\n" );
		}
	
	
	# Save the actual MX in the session record
	$outgoing[ $session_no ]->{ACTUAL_MX} = $mx;
	my $from = $outgoing[ $session_no ]->{FROM};
	my $to	 = $outgoing[ $session_no ]->{TO};
	
	&debug( "Starting to send a message to mail exchange $mx, TO: $to\n" );

	
	my $ok = $client->mail( $from );
	
	my $code;
	my $message;
	
	if ( ! $ok )
		{	$code = $client->code();
			$message = $client->message();			
			$message = "No cmd message" if ( ! defined $message );
			
			$client->quit;
			
			# Handle a code of 000
			if ( $code eq "000" )
				{	$message = "Mail command still pending after 30 seconds\n";
				}
			
			
			# 500 errors and above are fatal
			my $fatal = 1 if ( $code ge "500" );	 	
			&MessageError( $session_no, "Unable to send envelope to mail exchange server $mx, code: $code, cmd message: $message", $fatal );
			
			
			return( 0 + 0 );
		}
	
				
	# Send in my recipients, skipping any bad addresses
	&debug( "Connected session OK, now sending in the recipients ...\n" );
	my @ok_list = $client->to( @to, { SkipBad => 1 } );
			
			
	# Did I have a problem sending this stuff?
	# At least one of the addresses was ok if there is something in this array
	if ( ! $ok_list[ 0 ] )
		{	$client->quit;
			
			&MessageError( $session_no, "According to $mx, none of the TO: addresses are valid", 1 );
			return( 0 + 0 );
		}
	else	# Put the actual TO: into the outgoing session record
		{	$to = undef;
			foreach( @ok_list )
				{	next if ( ! $_ );
					$to .= " " if ( $to );
					$to .= $_;
				}
			$outgoing[ $session_no ]->{TO} = $to;
			
			&debug( "Good TO: addresses $to\n" );
		}
	
	
	# Send the DATA command
	&debug( "Sending the DATA command for session $session_no ...\n" );
	$ok = $client->data();
	$code = $client->code();
	$message = $client->message();
	
	$message = "No cmd message" if ( ! defined $message );
	
	# Handle a code of 000
	if ( $code eq "000" )
		{	$message = "Data command still pending after 30 seconds\n";
		}
	
	if ( ! $ok )
		{	$client->quit;			
			&MessageError( $session_no, "Error sending DATA command to server $mx, code: $code, cmd message: $message", undef );
			return( 0 + 0 );
		}
	

	# Put the socket into non-blocking mode
	&debug( "Going into non-blocking mode ...\n" );
	$client->blocking( 0 );
					
	# Add the new socket to the poll list
	$poll->mask( $client => POLLOUT | POLLERR );
	&debug( "Adding client $client to polling mask\n" );
	
	# Keep track of if I'm polling
	$outgoing[ $session_no ]->{POLLFD} = fileno( $client );
	
	
	# Open the message file and skip down to where the actual message starts
	my $file = $outgoing[ $session_no ]->{FILE};
	my $full_path = $spool . "\\" . $file;
	
	
	&debug( "Opening the message file $file and positioning the file pointer ...\n" );
	my $handle;
	if ( ! sysopen( $handle, $full_path, O_RDONLY ) )
		{	&MessageError( $session_no, "Can not open message file $file: $!\n", 1 );
			return( 0 + 1 );
		}


	# Save the handle			
	$outgoing[ $session_no ]->{HANDLE} = $handle;

	
	if ( ! flock( $handle, LOCK_SH | LOCK_NB ) )
		{	&MessageError( $session_no, "Can not lock shared message file $file: $!\n", 1 );
			return( 0 + 1 );
		}

			
	# Read until I hit MSG:\n
	my $line = " ";
	while ( ( $line )  &&  ( $line ne "MSG:\n" ) )
		{	$line = readline( $handle );
		}

		
	if ( $line ne "MSG:\n" )
		{	&MessageError( $session_no, "No message MSG: defined in file $file\n", 1 );
			return( 0 + 1 );
		}

	# At this point I have a client session created, the message file opened, and the file pointer
	# is sitting right at the start of the message
	
	&debug( "OutgoingOpenSession finished with no errors\n" );
	
	return( 0 + 1 );		
}



################################################################################
# 
sub CheckSpoolDirectory()
#
#  Check to see if there are any new files in the spool directory
#  Return TRUE if there is
#  Add the new files to the outgoing queue
#
################################################################################
{	my $work = 0 + 0;

	# Only run this every couple of seconds - to keep from thrashing the system
	my $current_time = time();
	return( 0 + 0 ) if ( $current_time < $check_spool_next_time );
	
	# Make sure that my idle time is reasonable - should be between 1 and 30 seconds
	$check_spool_idle_time = 0 + 1 if ( ( ! $check_spool_idle_time )  ||  ( $check_spool_idle_time < 1 ) );
	$check_spool_idle_time = 0 + 30 if ( $check_spool_idle_time > 30 );
	
	$check_spool_next_time = $check_spool_idle_time + $current_time;
	
	
	&debug( "CheckSpoolDirectory - check spool idle time = $check_spool_idle_time\n" );
	
	
	&ChildFatalError( "Unable to open spool directory $spool\n" ) if ( ! -d $spool );
	
	# Is the queue already full?
	my $current_outgoing_queue_size = &OutgoingQueueSize();
	if ( $current_outgoing_queue_size >= $max_outgoing_queue_size )
		{	&lprint( "Outgoing queue is full, not scanning Spool directory until queue goes down.\n" );
			return( 0 + 1 );
		}


	# Get the list of file names that I already know about
	&debug( "Building current outgoing file list ...\n" );
	my @file_names;
	for ( my $i = 0;  $i <= $#outgoing;  $i++ )
		{	my $file = $outgoing[ $i ]->{FILE};
			push @file_names, $file if ( defined $file );
		}


	# Rebuild the error names list completely without the outgoing errors that have timed out and are ready
	&debug( "Building current outgoing errors list ...\n" );
	my @error_names = ();
	
	for ( my $i = 0;  $i <= $#outgoing_errors;  $i++ )
		{	my $file = $outgoing_errors[ $i ]->{FILE};
					
			# Add back to the list file names that are still waiting
			my $next_time = $outgoing_errors[ $i ]->{NEXT};
			push @error_names, $file if ( $next_time > $current_time )
		}


	# Read the spool directory for new files entered, return if an error reading it
	return( $work ) if ( ! opendir( DIR, $spool ) );
	
	my @directory_list = ();
	my @summary_list = ();
	my @forward_list = ();
	my @challenge_list = ();
	my @other_list = ();
	
	# Get a listing of files specifically 
	&debug( "Getting spool files in priority order ...\n" );
	
	my $file_counter = 0 + 0;
	while ( my $file = readdir( DIR ) ) 
		{	chomp( $file );
			next if ( ! $file );
			
			$file_counter++;
			
			# Have I already found a bunch of files?
			if ( $file_counter > 200 )
				{	&debug( "Found the maximum of 200 files in the spool directory so quitting the spool priority early\n" );
					last;	
				}
			
			if ( $file =~ m/^summary-/i )
				{	push @summary_list, $file;
				}
			elsif (	$file =~ m/^f/i )
				{	push @forward_list, $file;
				}
			elsif (	$file =~ m/^SpamChallenge-/i )
				{	push @challenge_list, $file;
				}
			else
				{	push @other_list, $file;
				}
		}
		
	closedir( DIR );
	
	&debug( "Found $file_counter files in the spool directory ...\n" );
		   
		
	# Merge all the lists together -- first forwards, then summaries, then other files, and finally challenge requests.
	push @directory_list, @forward_list;
	push @directory_list, @summary_list;
	push @directory_list, @other_list;
	push @directory_list, @challenge_list;
	
	@forward_list = ();
	@summary_list = ();
	@other_list = ();
	@challenge_list = ();
	 	
	# If I have any new files in the spool directory, pause for 2 seconds to let any pending writes complete
	my $new_files;
	
	
	# If I have more files now then I definitely have some new files
	$new_files = 1 if ( $#directory_list > $#last_directory_list );
	
	
	# Do I have the same number of files as before, but the files themselves have changed?
	if ( ( ! $new_files )  &&  ( $#directory_list >= 0 )  &&  ( $#directory_list == $#last_directory_list ) )
		{	$new_files = 1 if ( @directory_list != @last_directory_list );
		}
	
		
	# Did an on hold domain change?
	my $changed = &GetRelayHoldDomains();
	$new_files = 1 if ( $changed );
	
		
	# Do I have less files now, but the files have changed?
	if ( ( ! $new_files )  &&  ( $#directory_list >= 0 )  &&  ( $#directory_list < $#last_directory_list ) )
		{	foreach ( @directory_list )
				{	my $file = $_;
					
					my $match;
					foreach ( @last_directory_list )
						{	if ( $file eq $_ )
								{	$match = 1; 
									last;
								}
						}
					
					if ( ! $match )
						{	$new_files = 1;
							last;	
						}
				}
		}
		
		
	# Pause for 2 seconds to let new files complete
	&debug( "Pausing 2 seconds ...\n" );
	sleep( 2 ) if ( $new_files );

	
	# Keep track of what the directory looked like so I can compare it the next time around
	@last_directory_list = @directory_list;
	
	
	my $file_count = 0 + 0;
	my $on_hold_files = 0 + 0;
	
	foreach ( @directory_list )
		{	my $file = $_;
			next if ( ! defined $file );
			
			my $full_path = $spool . "\\" . $file;
			
			# Skip subdirectories
			next if ( -d $full_path );
			
			# Delete empty files
			if ( ! -s $full_path )
				{	&lprint( "File $full_path is completely empty so deleting ...\n" );
					&DeleteSpoolFile( $full_path );
					next;
				}
			
			$file_count++;
			
			# Test to see if I already have it open
			my $already_open;
			foreach ( @file_names )
				{  $already_open = 1 if ( $file eq $_ );
				}
		
		    if ( $already_open )
				{	#&debug( "$file is already open\n" );
					next;	
				}
			
			
			# Test to see if it is in the errors list
			$already_open = undef;
			foreach ( @error_names )
				{  $already_open = 1 if ( $file eq $_ );
				}
		
		
			# Test to see if it is in the bad outgoing files list
			# If it is, try to delete it again ...
			foreach ( @bad_outgoing_files )
				{	next if ( ! defined $_ );
					
					my $lc_path = lc( $_ );
					if ( lc( $full_path ) eq $lc_path )
						{	$already_open = 1;
							&DeleteSpoolFile( $full_path );
						}
				}
		
		
		    next if ( $already_open );
			
			
			# Test to see if I can open it shared
			my $handle;
			if ( ! sysopen( $handle, $full_path, O_RDONLY ) )
				{	&debug( "Could not open file $full_path: $!\n" );
					next;
				}
					
			# See if I can lock the file exclusively here ...
			# If not, maybe another program is still screwing with the file ...
			if ( ! flock( $handle, LOCK_EX | LOCK_NB ) )
				{	&debug( "Could not lock exclusively file $full_path: $!\n" );
					close $handle;
					next;
				}
			
			
			# Read the first line and make sure it is a message file
			my $line = readline( $handle );
			
			if ( ! defined $line )
				{	&lprint( "File $full_path has a blank first line so deleting ...\n" );
					close $handle;
					
					# Delete the file out of the spool directory
					&DeleteSpoolFile( $full_path );					
					next;
				}
				
			
			if ( $line ne "MESSAGE FILE\n" )
				{	&lprint( "File $full_path is not a message file so deleting ...\n" );
					close $handle;
					
					# Delete the file out of the spool directory
					&DeleteSpoolFile( $full_path );					
					next;
				}
			
			&debug( "Got a new message file: $file\n" );
			
			
			# Get the ip, mx, from and to information from the message file header
			# Delete the file if the format is not right
			my $ip;
			my $forced_mx;
			my $from;
			my @to;
			
			$line = readline( $handle );
			my $bad_header;
			
			while ( ( $line )  &&  ( $line ne "MSG:\n" ) )
				{	if ( $line eq "IP:\n" )
						{	$ip = readline( $handle );
							
							chomp( $ip );
							&debug( "IP = $ip\n" ) if ( $ip );
							$line = readline( $handle );
						}
						
					elsif ( $line eq "MX:\n" )
						{	$forced_mx = readline( $handle );
							
							chomp( $forced_mx );
							&lprint( "Forcing MX to $forced_mx\n" ) if ( $forced_mx );
							$line = readline( $handle );
						}
						
					elsif ( $line eq "FROM:\n" )
						{	$from = readline( $handle );
							
							chomp( $from );
							$from = &CleanEmail( $from );
							&debug( "from = $from\n" ) if ( $from );
							$line = readline( $handle );
						}
						
					elsif ( $line eq "TO:\n" )
						{	$line = readline( $handle );
							
							while ( ( $line )  &&  
								    ( $line ne "MSG:\n" )  &&
									( $line ne "FROM:\n" )  &&
									( $line ne "MX:\n" )  &&
									( $line ne "IP:\n" ) )
								{	my $to = $line;
									chomp( $to );

									$to = &CleanEmail( $to );
									push @to, $to if ( $to );
									
									&debug( "to entry = $to\n" ) if ( $to );
									
									$line = readline( $handle );
								}
								
							&debug( "to array = @to\n" );								
						}
						
					else
						{	&debug( "Bad header line in message file $full_path: $line" );
							$bad_header = 1;
							$line = undef;
						}
				}


			# If there was a bad header, quit
			if ( $bad_header )
				{	&lprint( "Bad message header in file $full_path so deleting it\n" );
					close $handle;

					# Delete the file out of the spool directory
					&DeleteSpoolFile( $full_path );					
					next;	
				}
			
							
			# If there is no to:, quit
			if ( ! $to[ 0 ] )
				{	&lprint( "No TO: defined in message file $full_path so deleting it\n" );
					close $handle;
					
					# Delete the file out of the spool directory
					&DeleteSpoolFile( $full_path );					
					next;	
				}
			
							
			# Read in one line of the message to make sure that there really is a message to send
			$line = readline( $handle );
			
			close $handle;
			
			
			# If there is no msg:, quit
			if ( ! $line )
				{	&lprint( "No actual message in file $full_path so deleting it\n" );
					
					# Delete the file out of the spool directory
					&DeleteSpoolFile( $full_path );					
					next;	
				}
			
			
			# Check to see if the message is on hold because the domain is on hold
			my $on_hold;
			foreach( @relay_hold_domains )
				{	my $hold_domain = $_;
					next if ( ! defined $hold_domain );
					
					my $quoted = quotemeta( $hold_domain );
					foreach( @to )
						{	my $to = $_;
							next if ( ! defined $to );
							
							$on_hold = $hold_domain if ( $to =~ m/$quoted$/ );
						}
				}
				
			# Did I find this file should be on hold?	
			if ( $on_hold )
				{	$on_hold_files++;
					next;
				}


			# Get all the mx records that I have to send to
			# A forced mx record is an email message going to a specific address - no defined domain
			# This could be a bounce message, or a spam forward, or a relay from inside
			my @mx;
			my @mx_pair;
			
			
			# Even if it is a forced MX, if it is going to one of my relay domains, use
			# the mx records for the relay domain instead
			if ( $forced_mx )
				{	my @allowed_domains = keys %mail_exchangers;
					my ( $user, $domain ) = split /\@/, $to[ 0 ], 2;
					$domain = lc( $domain );

					foreach ( @allowed_domains )
						{	next if ( ! $_ );
							$forced_mx = undef if ( $domain eq $_ );
						}
					
						
					push @mx, $forced_mx if ( $forced_mx );
				}
				
				
			if ( ! $forced_mx )
				{	# Get the mx record for each to address
					@mx_pair = &get_mx_list( @to );
					
					# Pull out the list of unique mx's
					@mx = ();
					foreach ( @mx_pair )
						{	next if ( ! $_ );
							my ( $mx, $to ) = split /\s/, $_;
							
							my $match;
							foreach( @mx )
								{	$match = 1 if ( $_ eq $mx );
								}

							push ( @mx, $mx ) if ( ! $match );
						}
				}
				
			
			my $found_mx;
			
			
			# If I have an outgoing_error with this file, use the TO: and MX: from that
			my $error_session;
			for ( my $i = 0;  $i <= $#outgoing_errors;  $i++ )
				{	my $errors_file = $outgoing_errors[ $i ]->{FILE};
					
					# Get the MX to use
					if ( $errors_file eq $file )
						{	$error_session = $i;
							my $mx = $outgoing_errors[ $error_session ]->{MX};
							@mx = ();
							push @mx, $mx;
						}
				}
				
					
			# Create an outgoing session record for each unique mx in the list
			foreach ( @mx )
				{	my $mx = $_;
					next if ( ! defined $mx );
					
					# Make sure that I am not sending to myself
 					if ( ( $mx eq $myipaddress ) || ( $mx eq $myhostname ) )
 						{	&lprint( "Can not relay messages back to myself\n" );
							next;
 						}
						
					my $session_no = $#outgoing + 1;
			
					# Create the new entry in the outgoing queue list
					$outgoing[ $session_no ]->{FILE}		= $file;
					$outgoing[ $session_no ]->{FROM}		= $from;
					
					
					# Build the right to: address list for this mx - spaces between each individual to:
					my $to;
					if ( $forced_mx )	# If a forced mx, then all the to:s go to the same place
						{	$to = $to[ 0 ];
							
							# Add any extra TO: addresses with a space between each one
							for ( my $i = 1;  $to[ $i ];  $i++ )
								{	$to .= " ". $to[ $i ];					
								}
						}
					elsif ( defined $error_session )	# I must be resending an outgoing error is this is true
						{	$to = $outgoing_errors[ $error_session ]->{TO};
							
							&debug( "Starting to resend file $file to $to\n" );
						}
					else	# Go through each mx pair, gathering together all the to:s going to this mx
						{	foreach ( @mx_pair )
								{	next if ( ! $_ );
									
									my ( $pmx, $pto ) = split /\s/, $_;
									
									# If the pmx match, then send this email to this to:
									if ( $mx eq $pmx )
										{	$to .= " " . $pto if ( $to );
											$to = $pto if ( ! $to );
										}
								}
							
						}
					
					
					# At this point $to holds the list of to: addresses, separated by a space, that are
					# going to this mx
					$outgoing[ $session_no ]->{TO}			= $to;
					$outgoing[ $session_no ]->{HANDLE}		= undef;
					$outgoing[ $session_no ]->{SOCKET}		= undef;
					$outgoing[ $session_no ]->{MX}			= $mx; # This is the mx with the lowest preference
					$outgoing[ $session_no ]->{ACTUAL_MX}	= $mx; # This is the actual mx I connected to
					$outgoing[ $session_no ]->{POLLFD}		= undef;  # This will be the client socket file descriptor that I'm polling on, if I've started to poll
					$outgoing[ $session_no ]->{TO}			= $to;
					
					# I use this IP address for bounced messages only
					$outgoing[ $session_no ]->{IP}			= $ip;
					
					# Flag that something new has happened
					$work = 0 + 1;
					
					$found_mx = 1;
					
					&lprint( "Added message TO: $to to outgoing queue\n" );
				}


			if ( ! $found_mx )
				{	my $str = $to[ 0 ];
					&lprint( "No valid mail exchange(s) found for message TO: $str so deleting message\n" );
					
					# Delete the file out of the spool directory
					&DeleteSpoolFile( $full_path );					
					next;						
				}


			# Check our queue size
			if ( &OutgoingQueueSize() >= $max_outgoing_queue_size )			
				{	&lprint( "Outgoing queue is full, after scanning Spool folder.\n" );
					last;
				}
		}
		


	# If I'm running in empty mode, should I quit?
	if ( ( $opt_empty )  &&  ( $file_count == 0 )  &&  ( $#outgoing < 0 ) )
		{	&lprint( "Spool directory is empty, and everything has been sent, so quitting\n" );
			exit( 0 );
		}
	
	
	# Now check the outgoing_errors list to see that the errored files are still there
	# Remove the outgoing_errors entry if the file has disappeared
	for ( my $i = 0;  $i < $#outgoing_errors;  $i++ )
		{	my $errors_file = $outgoing_errors[ $i ]->{FILE};
			
			my $delete_ok = 1;
			for ( my $k = 0;  $k < $#directory_list;  $k++ )
				{	$delete_ok = undef if ( $directory_list[ $k ] eq $errors_file );
				}


			# If it is ok to get rid of the outgoing errors entry because the file has disappeared
			if ( $delete_ok )
				{	&lprint( "Message file $errors_file was deleted by an outside process\n" );
					&OutgoingErrorsClose( $errors_file, undef, undef, 1 );
				}
		}
		
	
	# If the file_count is 0, then there can't be any bad_outgoing_files left ...
	@bad_outgoing_files = () if ( ! $file_count );
	
	# Where there any files on hold?
	&lprint( "Found $on_hold_files files on hold because of an on hold domain name\n" ) if ( $on_hold_files );

	$check_spool_idle_time += 5 if ( ! $work );

	return( $work );	
}



################################################################################
#
sub OutgoingQueueSize()
#
#  Return the size of the outgoing queue, but don't count errored sessions
#
################################################################################
{
	# Count up the active outgoing sessions - don't count ones that have errors
	my $total_outgoing			= $#outgoing + 1;				# This is the total outgoing sessions
	my $total_outgoing_errors	= $#outgoing_errors + 1;		# This is the total errors
	
	&debug( "OutgoingQueueSize total outgoing = $total_outgoing\n" );
	&debug( "OutgoingQueueSize total outgoing errors = $total_outgoing_errors\n" );
	
	return( $total_outgoing );
}



################################################################################
#
sub get_mx_list( @ )
#
#  Given a list to to: addresses, return the list of mx pairs (mx: to:) records to contact
#
################################################################################
{
	my %mx;
	my @mx_pair;
	
	
    # Loop through the recipient list, finding the mx for each domain in the list
	
	while ( my $target = shift )
		{	my $domain;
			my %domain_mx;
			$target =~ m/@(.*)/;
			
			if ( ! $1 )
				{	&debug( "MX No match for domain separator @ in $target\n" );
					next;
				}
			else
				{	$domain = $1;
				}
			
			if ( ! $domain )
				{	&debug( "MX Domain name is blank for target $target\n" );
					next;
				}
			
			my $mx;
			
			# Have I just now already looked up the mx?
			if ( exists( $domain_mx{ $domain } ) )
				{	$mx = $domain_mx{ $domain };
				}
			# Is it one of my defined mail exchangers?
			elsif ( exists( $mail_exchangers{ $domain } ) )					
				{	$mx = $mail_exchangers{ $domain };
				}
			# Do I need to query DNS to find it?
			else
				{	$mx = &MailExchangers( $domain );
				}
				
			# Did I find one to send to?
			if ( $mx )
				{	$mx{ $mx } = 1;
					$domain_mx{ $domain } = $mx;
					
					my $mx_pair = $mx . " " . $target;
					push @mx_pair, $mx_pair;
				}
			else
				{	&lprint( "Unable to find a mail exchange for domain $domain\n" );	
				}
		}
	
	
	if ( $opt_debug )
		{	print "MX pairs:\n";
			
			foreach ( @mx_pair )
				{	print "$_\n";
				}
		}
		
		
	# Return the mx pairs
	return( @mx_pair );
}



################################################################################
################################################################################
##########################   Utility SUBROUTINES   #############################
################################################################################
################################################################################



################################################################################
# 
sub GetRelayHoldDomains()
#
#  Get the domain list that are supposed to be on hold for SMTP sending
#  Return True if there is a change from the last time this was called
#
################################################################################
{	my $key;
	my $type;
	my $data;
	
	my @new_relay_hold_domains = ();
	
	#  Does the SMTP Relay key exist in the registry?
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay", 0, KEY_READ, $key );
	if ( ! $ok )
		{	@relay_hold_domains= ();	# The key doesn't exist, so there isn't anything in it ...

			$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service",  0, KEY_READ, $key );
			
			if ( ! $ok )
				{	print "TTC is not installed on this machice\n";
					return( 1 );
				}
				
			# Now create my keys
			$ok = &RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] ) if ( $ok );
			&RegCloseKey( $key ) if ( $ok );
			$ok = &RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] ) if ( $ok );
			&RegCloseKey( $key ) if ( $ok );
			$ok = &RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] ) if ( $ok );
			&RegCloseKey( $key ) if ( $ok );
			return( undef );
		}

	# Get the RelayHold domains value to use if defined
	$data = undef;
	my $success = &RegQueryValueEx( $key, "RelayHoldDomains", [], $type, $data, [] );

	if ( ( $success )  &&  ( length( $data ) ) )
		{	$data =~ s/\x00+$//;	# Trim any 00s off the end
			my @tmp = split /\x00/, $data;
			
			# Clean up the list
			foreach ( @tmp )
				{	next if ( ! defined $_ );
					
					my $domain = lc( $_ );
					if ( $_ =~ m/\@/ )
						{	push @new_relay_hold_domains, $domain;
						}
					else
						{	push @new_relay_hold_domains, "\@$domain";
						}
				}
		}
		
	&RegCloseKey( $key );
	
	# Return undef if nothing changed
	return( undef ) if ( @relay_hold_domains eq @new_relay_hold_domains );
	
	@relay_hold_domains = @new_relay_hold_domains;
	
	if ( $#relay_hold_domains < 0 )
		{	&lprint( "There are no current relay on hold domains\n" );
		}
	else
		{	&lprint( "New relay on hold domains have been detected\n" );
			&lprint( "Current on hold domains are:\n" );
			foreach ( @relay_hold_domains )
				{	next if ( ! $_ );
					my $on_hold_domain = $_;
					&lprint( "On hold domain: $on_hold_domain\n" );
				}
		}
		
	return( 1 );
}



################################################################################
# 
sub GetProperties()
#
#  Get the current properties from the Spam Blocker Object that affect
#  the IpmSMTPRelay
#
################################################################################
{	my $key;
	my $type;
	my $data;

	&debug( "GetProperties\n" );
	
	#  Does the SMTP Relay key exist in the registry?
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay", 0, KEY_READ, $key );

	# Get the hostname to use if defined
	if ( $ok )
		{	$data = undef;
			my $success = &RegQueryValueEx( $key, "Hostname", [], $type, $data, [] );

			$myipaddress = $data if ( ( $success )  &&  ( length( $data ) )  &&  ( $data ) );
			$my_mail_hostname = $data if ( ( $success )  &&  ( length( $data ) )  &&  ( $data ) );
		}
		
		
	# Get the Active value to use if defined
	if ( $ok )
		{	$data = undef;
			my $success = &RegQueryValueEx( $key, "Active", [], $type, $data, [] );

			$smtp_active = undef if ( ( $success )  &&  ( length( $data ) )  &&  ( $data eq "\x00\x00\x00\x00" ) );
		}
		
	# Get the RelayHold domains value to use if defined
	@relay_hold_domains = ();
	if ( $ok )
		{	$data = undef;
			my $success = &RegQueryValueEx( $key, "RelayHoldDomains", [], $type, $data, [] );

			if ( ( $success )  &&  ( length( $data ) ) )
				{	$data =~ s/\x00+$//;	# Trim any 00s off the end
					my @tmp = split /\x00/, $data;
					
					# Clean up the list
					foreach ( @tmp )
						{	next if ( ! defined $_ );
							
							my $domain = lc( $_ );
							if ( $_ =~ m/\@/ )
								{	push @relay_hold_domains, $domain;
								}
							else
								{	push @relay_hold_domains, "\@$domain";
								}
						}
				}
		}
		
	if ( $ok )
		{	$data = undef;
			my $success = &RegQueryValueEx( $key, "IncomingSpoolDirectory", [], $type, $data, [] );

			if ( ( $success )  &&  ( length( $data ) ) )
				{	$incoming_spool = $data;
					&lprint( "Set incoming spool directory to $incoming_spool\n" );
				}
		}
		
	&RegCloseKey( $key );

	
	#  Does the SMTP Relay\Relay Domains key exist in the registry?
	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay\\Relay Domains", 0, KEY_READ, $key );

	if ( $ok )
		{	&RegCloseKey( $key );
			
			#  Next go through the SMTP properties getting all the domains to relay for
			for ( my $i = 0;  $i < 255;  $i++ )
				{	my $counter = sprintf( "%05u", $i );

					my $subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay\\Relay Domains\\$counter";
					$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
					next if ( ! $ok );  


					# Get the domain name
					$data = undef;
    				$ok = &RegQueryValueEx( $key, "domain", [], $type, $data, [] );
					next if ( ! length( $data ) );

					my $domain = lc( $data );


					# Get the disclaimer - if defined
					my @lines = undef;
    				$ok = &RegQueryValueEx( $key, "disclaimer", [], $type, $data, [] );

					if ( ( $ok )  &&  ( length( $data ) ) )
						{	$data =~ s/\x00+$//;
							my @lines = split /\x00/, $data;
							for ( my $i = 0;  $lines[ $i ];  $i++ )
								{	$disclaimer{ $domain } .= $lines[ $i ];							
								}
						}

					# Get the first mail exchanger
					$data = undef;
    				$ok = &RegQueryValueEx( $key, "mx1", [], $type, $data, [] );
					next if ( ! length( $data ) );
			
					my $mx1 = lc( $data );
			
					$mail_exchangers{ $domain } = $mx1 if ( $mx1 );

					
					# Get the second mail exchanger, if defined
					$data = undef;
    				$ok = &RegQueryValueEx( $key, "mx2", [], $type, $data, [] );
	
					if ( length( $data ) )
						{	my $mx2 = lc( $data );
							$mx2{ $mx1 } = $mx2 if ( ( $mx1 ) && ( $mx2 ) );			
						}
						

					# Get the third mail exchanger, if defined
					$data = undef;
    				$ok = &RegQueryValueEx( $key, "mx3", [], $type, $data, [] );

					if ( length( $data ) )			
						{	my $mx3 = lc( $data );
							$mx3{ $mx1 } = $mx3 if ( ( $mx1 ) && ( $mx3 ) );
						}
						
					&RegCloseKey( $key );
				}
			
			return;
		}

	return;
}



################################################################################
# 
sub MailExchangers( $ )
#
#  Given a domain, find up to 3 domain exchangers
#  Return the first one, and add the next 2 to the %mx2 and %mx3 hashes
#  Return undef if unable to find any mx
#
################################################################################
{	my $domain = shift;
	
	return( undef ) if ( ! defined $domain );
	
	&lprint( "Querying DNS for MailExchangers (MX) for domain: $domain ...\n" );
	
use Net::DNS;
    my $res = Net::DNS::Resolver->new;

	# Wait for 20 seconds for a response
	$res->tcp_timeout( 20 );
	$res->udp_timeout( 20 );

    my @resolve_mx = mx( $res, $domain );	
	my @mx;
 
	if ( $#resolve_mx >= 0 ) 
		{	&lprint( "Resolved MXs for $domain\n" );
			
			foreach my $rr ( @resolve_mx ) 
				{	push @mx, $rr->exchange;
				}
		}
	else 
		{	my $errstr = $res->errorstring;
			&lprint( "Can't find MX records for $domain: $errstr\n" );
		}
		
 
	# If I couldn't resolve it through NET::DNS, then try calling nslookup
	if ( $#mx < 0 )	
		{	@mx = NSLookup( $domain );
		}

		
	my $mx = $mx[ 0 ];
	my $mx2 = $mx[ 1 ];
	my $mx3 = $mx[ 2 ];
	
	# Did I find more that 1 mx?
	if ( defined $mx )
		{	$mx2{ $mx } = $mx2 if ( defined $mx2 );
			$mx3{ $mx } = $mx3 if ( defined $mx3 );
		}
		
	&lprint( "Found $domain MX = $mx\n" )	if ( defined $mx );
	&lprint( "Found $domain MX2 = $mx2\n" ) if ( defined $mx2 );
	&lprint( "Found $domain MX3 = $mx3\n" ) if ( defined $mx3 );

	&lprint( "Found no MXs for $domain\n" ) if ( ! defined $mx );

	return( $mx );
}



################################################################################
# 
sub NSLookup( $ )
#
#  Given a domain name, return mx list in preference order using nslookup
#
################################################################################
{   my $domain = shift;
	
	&debug( "NSLookup, domain = $domain\n" );

	my @output = `nslookup -retry=3 -timeout=20 -type=mx $domain`;

	my %mx_list;
	my @mx;
	
	my $count = 0 + 0;
	foreach ( @output )
		{	next if ( ! defined $_ );
			if ( m/preference = / )
				{	chomp( $_ );
					my ( $junk, $stuff ) = split /preference = /, $_, 2;
					my ( $preference, $exchanger ) = split /, mail exchanger = /, $stuff, 2;
					$preference = 0 + $preference;
					my $key = ( 100 * $preference ) + $count;
					
					$exchanger = &CleanUrl( $exchanger );
					
					# Is the exchanger a clean address?
					if ( &IsIPAddress( $exchanger ) )
						{	$exchanger = &IsValidIP( $exchanger );
						}
						
					next if ( ! defined $exchanger );
					
					$mx_list{ $key } = $exchanger;
					$count++;					
				}
			elsif ( m/mail addr = / )
				{	chomp( $_ );
					my ( $junk, $exchanger ) = split /mail addr = /, $_, 2;
					my $key = ( 200 ) + $count;
					
					$exchanger = &CleanUrl( $exchanger );

					# Is the exchanger a clean address?
					if ( &IsIPAddress( $exchanger ) )
						{	$exchanger = &IsValidIP( $exchanger );
						}
												
					next if ( ! defined $exchanger );
					
					$mx_list{ $key } = $exchanger;
					$count++;					
				}
		}
	
	
	# Sort numerically by the preference
	sub numerically {$a <=> $b }
	my @order = sort numerically( keys( %mx_list ) );

	my @mx_order;
	
	foreach ( @order )
		{	next if ( ! $_ );
			my $key = $_;
			my $value = $mx_list{ $key } if ( defined $mx_list{ $key } );
			push @mx_order, $value;
		}
	

	# If I didn't find an mx record, guess mail.domain.com
	if ( $#mx_order < 0 )
		{	&lprint( "No answer from DNS for MX for domain $domain so guessing \"mail.$domain\"\n" );
			push @mx_order, "mail.$domain";
		}
		
		
	&debug( "mx_order = @mx_order\n" );

	return( @mx_order );
}



################################################################################
# 
sub LoadMailExchangers()
#
#  Load in the IP addresses of the mail exchangers to SMTP relay for
#
################################################################################
{	&debug( "LoadMailExchangers\n" );
		
	my @hostnames = values %mail_exchangers;
		
	# Keep a list of the IP addresses I've found
	my %mx_address;
	
	foreach ( @hostnames )
		{	my $host = $_;

			next if ( ! $host );
						
			my $mx_ipaddress;
			
			if ( &IsIPAddress( $host ) )
				{	$mx_ipaddress = $host;
				}
			else
				{	my ($name, $aliases, $addrtype, $length, @addrs) = gethostbyname( $host );
					
					if ( $addrs[ 0 ] )
						{	$mx_ipaddress = inet_ntoa( @addrs );
						}
				}
			
			if ( ! $mx_ipaddress )
				{	print( "Unable to find an IP address for relay host name $host\n" );
					
					# Remove the mail exchanger from the list
					my @domains = keys %mail_exchangers;
					foreach ( @domains )
						{	my $domain = $_;
							delete( $mail_exchangers{ $domain } ) if ( $host eq $mail_exchangers{ $domain } );
						}
				}
			else
				{	&debug( "Mail Exchange host name = $host, IP address = $mx_ipaddress\n" );
					$mx_address{ $host } = $mx_ipaddress;
				}	
		}
		
	@hostnames = values %mail_exchangers;	
	return( @hostnames );
}



################################################################################
# 
sub ShowMailExchangers()
#
#  Show the IP addresses of the mail exchangers that I'm relaying for
#
################################################################################
{	&debug( "ShowMailExchangers\n" );
	
		
	# Get the new list of host names, now that I've removed servers that I can't reach
	my @hostnames = values %mail_exchangers;	
	my @domains = keys %mail_exchangers;	
	
	
	if ( $hostnames[ 0 ] )
		{	&lprint( "Relaying for the following domains ...\n" );
			for ( my $i = 0;  $hostnames[ $i ];  $i++ )
				{	my $host = $hostnames[ $i ];
					my $domain = $domains[ $i ];
					
					&lprint( "For domain $domain relaying to host $host\n" );
					
					my $mx2;
					$mx2 = $mx2{ $host } if ( exists( $mx2{ $host } ) );
					&lprint( "Backup mx for domain $domain is $mx2\n" ) if ( $mx2 );
					
					my $mx3;
					$mx3 = $mx3{ $host } if ( exists( $mx3{ $host } ) );
					&lprint( "Second backup mx for domain $domain is $mx3\n" ) if ( $mx3 );					
				}
		}	
}



################################################################################
# 
sub DeleteSpoolFile( $ )
#
#  Given a full path filename, delete the file.  If unable to delete it, add
#  it to the bad_outgoing_files list so that I don't repeatedly try to send it
#
################################################################################
{	my $full_file_name = shift;
	
	return( 1 ) if ( ! defined $full_file_name );
	
	# If the file exists, try to delete it	
	if ( -e $full_file_name )
		{	&debug( "Deleting file $full_file_name\n" );
			my $ok = unlink( $full_file_name );
			&lprint( "Error deleting in DeleteSpoolFile file $full_file_name: $!\n" ) if ( ! $ok );
		}
	
	
	# Check to make sure it deleted ok
	return( 1 ) if ( ! -e $full_file_name );
	
	
	# Maybe the file is read only?  I'll try turning off that file attribute
	# If the file is readonly, turn off that attribute
	my $attrib;
	Win32::File::GetAttributes( $full_file_name, $attrib );
	
	# Is the readonly bit set?  If so, turn it off
	if ( $attrib & READONLY )
		{	$attrib = $attrib - READONLY;
			Win32::File::SetAttributes( $full_file_name, $attrib );
		}


	# Try deleting it again
	my $ok = unlink( $full_file_name );
	&lprint( "Second error deleting in DeleteSpoolFile file $full_file_name: $!\n" ) if ( ! $ok );

	# Check to see if it is gone now ...
	return( 1 ) if ( ! -e $full_file_name );


	&lprint( "Unable to delete spool file $full_file_name\n" );

	
	# If the file still exists after trying to delete it, then add it to the bad_files list	
	# First, make sure that it isn't already in the list
	foreach ( @bad_outgoing_files )
		{	next if ( ! defined $_ );
			my $lc_path = lc( $_ );
			
			return( undef ) if ( $lc_path eq lc( $full_file_name ) );
		}
	
	push @bad_outgoing_files, $full_file_name;
		
	return( undef );		
}



################################################################################
# 
sub HexToInt( $ )
#
#  Convert a registry hex value to a decimal value
#
################################################################################
{  my $hexstring = shift;

   my $dec = unpack( "CH", $hexstring );
 
   return( $dec );
}



################################################################################
#
sub debug( @ )
#
#  Print a line of text to STDOUT in normal or HTML format, depending on the CGI enviroment
#  And also print it to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     bprint( @_ );
}



################################################################################
#
sub ChildFatalError( @ )
#
#  Print any error message, dump the footer info, and exit
#  Added in the application event log
#  And do it correctly if I am a child task
#
################################################################################
{

	&lprint( "ChildFatalError @_\n" );
	

	# Just call the normal fatal error if I am not a child task
	&FatalError( @_ ) if ( ! $child_task );
	
	my $log = Win32::EventLog->new( "IpMagicService" );
	
	if ( $log )
		{	my $msg = $0 . " had a fatal error - ";
			
			my $i = 0;			
			while ( $_[ $i ] )
				{	$msg = $msg . $_[ $i ];
					$i++;
				}
				
			$log->Report( {	EventType	=>	EVENTLOG_INFORMATION_TYPE,
							Category	=>	undef,
							EventID		=>	0x800000D2,
							Data		=>	undef,
							Strings		=>	$msg
						  } );
			
			$log->Close;
		}
		
		
	# Simply die - the parent task will figure it out
	die @_;
	
	exit;
}




################################################################################
#
sub TrapErrors( $$ )
#
#  Setup to Trap Errors
#
################################################################################
{	my $send	= shift;
	my $receive = shift;
	
	# Pick a filename base on the mode I'm running in
	my $filename = &SoftwareDirectory() . "\\IpmSMTPRelay";
	my $ext = "Errors.log";
	$ext = "OutgoingErrors.log" if ( $send );
	$ext = "IncomingErrors.log" if ( $receive );
	$filename .= $ext;

	# Delete the errors file if it is getting too big ...
	my $size = -s $filename;
	unlink( $filename) if ( ( $size )  &&  ( $size > 20000 ) );
	
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">>$filename" ) )
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
    my $me = "IpmSMTPRelay";

    print <<".";
Usage: $me [OPTION(s)]
IpmSMTPRelay accepts client connections, gets the messages, saves them into a
queue, and then forwards the messages onto the next message exchange server.

  -a, --skip     skip on first error any message - no retries
  -d, --debug    display debugging messages
  -e, --empty    send until the spool directory is empty, then quit
  -l, --logging  log incoming and outgoing messages
  -h, --help     display this help and exit
  -n, --name     return the hostname or IP address the server is listening on
  -o, --open     run as an open relay server
  -r, --receive  receive messges only
  -s, --send     send messges only
  -v, --version  display version information and exit
  
Spool Directory: $spool  
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
    my $me = "IpmSMTPRelay";

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

