################################################################################
#!perl -w
#
# Rob McCarthy's IpmArchiveBackup source code
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Cwd;


use LWP;
use LWP::Simple;
use LWP::UserAgent;
use LWP::ConnCache;


use Pack::Process;
use Pack::PackFile;
use Pack::PackUtil;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging = 1;			# True if I should log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_wizard;					# True if run from a Wizard dialog



my @backup_servers;				# The list of backup servers 
my %properties;					# The hash of properties for Mail Archiving
my $browser;					# The user agent browser used for all for post files
my $cache;						# The connection cache for reuse


my $_version = "1.0.0";



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
        "l|logging"		=> \$opt_logging,
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help,
        "w|wizard"		=> \$opt_wizard,
        "x|xxx"			=> \$opt_debug,
    );


    &StdHeader( "IpmArchiveBackup" ) if ( ! $opt_wizard );
	
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	

	# Make sure that I'm the only IpmArchiveBackup program running
	&ProcessSetDebugPrivilege();
	&ProcessKillName( "IpmArchiveBackup.exe" );
	
	
	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
		
		
	&SetLogFilename( 'IpmArchiveBackup.log', $opt_debug ) if ( $opt_logging );
	

	my $ok = &PackUtilGetProperties( \%properties );
	if ( ! $ok )
		{	&lprint( "Error getting properties from registry\n" );
			my $last_err = &IndexLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 0 );
		}
	
			
	my $archive_internal = $properties{ "Archive Internal Mail" };
	my $archive_incoming = $properties{ "Archive Incoming Mail" };
	my $archive_outgoing = $properties{ "Archive Outgoing Mail" };


	my $index_email;
	$index_email = 1 if ( ( $archive_internal )  &&  ( $archive_internal eq "\x01\x00\x00\x00" ) );
	$index_email = 1 if ( ( $archive_incoming )  &&  ( $archive_incoming eq "\x01\x00\x00\x00" ) );
	$index_email = 1 if ( ( $archive_outgoing )  &&  ( $archive_outgoing eq "\x01\x00\x00\x00" ) );


	# Are any email backup servers defined?
	my $email_backup;
	my @backup = ( "Backup Server 1", "Backup Server 2", "Backup Server 3", "Backup Server 4", "Backup Server 5" );
	foreach ( @backup )
		{	my $server = $_;
			my $server_name = $properties{ $server };
			if ( ( $server_name )  &&  ( length( $server_name ) > 1 ) )
				{	$email_backup = 1;
					push @backup_servers, $server_name;
				}
		}
	
	
	$email_backup = undef if ( ! $index_email );
	my $queue_dir = $properties{ "Queue Directory" };
	$email_backup = undef if ( ! $queue_dir );
	
	
	if ( ! $email_backup )
		{	&lprint( "Nothing is configured for IpmArchiveBackup to do\n" );
			&StdFooter;
			exit( 0 );	
		}
		
		
	&lprint( "Starting IpmArchiveBackup normal operation  ...\n" );	
			
			
	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	&IpmArchiveBackup();
		
		
	chdir( $cwd );
	
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
# 
sub IpmArchiveBackup()
#
#  Given a filename, copy it to all of the backup queues
#  Return undef if any problems
#
################################################################################
{	my $queue_dir = $properties{ "Queue Directory" };
	
	return( undef ) if ( ! $queue_dir );
	&PackUtilBuildDirectory( $queue_dir );
	return( undef ) if ( ! -d $queue_dir );
	
	&PackUtilBuildDirectory( "$queue_dir\\Backup" );
	
	foreach ( @backup_servers )
		{	my $server = $_;
			next if ( ! $server );
			
			# Don't copy file to a server named "backup" - this will cause real problems
			next if ( lc( $server ) eq "backup" );
			
			# Test to see if this server supports mail archive backup
			my $backup_supported = &TestArchiving( $server );
			if ( ! $backup_supported )
				{	&lprint( "TTC server $server does not support mail archiving, so ignoring backup files for now ...\n" );
					next;
				}
				
			my $qdir = "$queue_dir\\$server";
			
			&PackUtilBuildDirectory( $qdir );
			
			return( undef ) if ( ! opendir( QUEUE_DIR, $qdir ) );
			
			&lprint( "\nCopying backup file to server $server\n" );
			
			while ( my $file = readdir( QUEUE_DIR ) )
				{	my $full_file = "$qdir\\$file";
					
					next if ( ! -f $full_file );

					my $ok = &BackupFile( $server, $full_file );
					
					if ( $ok )
						{	&lprint( "Copied $full_file\n" );
							unlink( $full_file );
						}
				}
				
			close( QUEUE_DIR );
		}
		
	return( 1 );
}



################################################################################
#
sub TestArchiving( $ )
#
#  Given a server name, test it to see if it supports Mail Archiving
#  Return True if if it does, undef if not
#
################################################################################
{	my $server		= shift;
	

	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}
		
	if ( ! $browser )
		{	$browser = LWP::UserAgent->new();
	
			# Give it a long timeout
			$browser->timeout( 15 * 60 );
			
			$browser->conn_cache( $cache );
		}
		
		
	my $url = "http\:\/\/TTCSERVER\/ArchiveQueue\/Default.aspx";	
	$url =~ s/TTCSERVER/$server/;


	my $req = HTTP::Request->new( GET => $url );
	$req->referer("http://wizard.yellowbrick.oz");


	# Get the response
	my $response = $browser->request( $req );

	
	my $ok = $response->is_success();
	my $status = $response->status_line;
	
	
	return( $ok );
}



################################################################################
#
sub BackupFile( $$ )
#
#  Copy to the server using Jones's aspx page the full filename
#  Return True if copies OK, undef it not
#
################################################################################
{	my $server		= shift;
	my $full_file	= shift;
	
	
	# The post command wants to see a reference to an array instead of a simple string
	my @files = ();
	push @files, "$full_file";


	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}
		
	if ( ! $browser )
		{	$browser = LWP::UserAgent->new();
	
			# Give it a long timeout
			$browser->timeout( 15 * 60 );
			
			$browser->conn_cache( $cache );
		}
		
		
	my $url = "http\:\/\/TTCSERVER\/ArchiveQueue\/PostBackup.aspx";
	$url =~ s/TTCSERVER/$server/;


	my $response = $browser->post(
		$url,
		[	'fileUpload'	=> \@files
		],
	'Content_Type' => 'form-data' );
	
	
	my $ok = $response->is_success();
	my $status = $response->status_line;
	

	if ( ! $ok )
		{	&lprint( "Error copying file $full_file: $status\n" );
		}
		
	return( $ok );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = &SoftwareDirectory() . "\\IpmArchiveBackupErrors.log";
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
    my $me = "IpmArchiveBackup";

    print <<".";
Usage: $me docid email [OPTION(s)]
IpmArchiveBackup sends documents from the local server that have been indexed and
archived over to any backup servers that have been configured with
the Mail Archive properties.

  -h, --help     display this help and exit
  -v, --version  display version information and exit
  
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
    my $me = "IpmArchiveBackup";

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

