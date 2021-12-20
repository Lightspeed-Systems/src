################################################################################
#!perl -w
#
#  Rob McCarthy's Pop3Connecter source code
#  Copyright 2007 Lightspeed Systems Corp.
#
#  http://search.cpan.org/~sdowd/Mail-POP3Client-2.17/POP3Client.pm
#  http://search.cpan.org/~tokuhirom/Net-POP3-SSLWrapper-0.06/lib/Net/POP3/SSLWrapper.pm
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Cwd;
use File::Copy;


use IO::Socket::SSL;
use Mail::POP3Client;


use Pack::Process;
use Pack::PackFile;
use Pack::PackUtil;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging = 1;			# True if I should log
my $opt_debug ;		 			# True if I should write to a debug log file
my $opt_wizard;					# True if run from a Wizard dialog
my $opt_kill;
my $opt_ssl;					# True if I should use SSL
my $opt_timeout = 5 * 60;		# Default to a 5 minute timeout

my $opt_server;					# The server, username, and password to use
my $opt_username;
my $opt_password;
my $opt_dirtest;				# True if all if should do is read the current directory and detect what type
								# of message files I find


my $my_pid;						# The process ID of this process
my %properties;					# The hash containing all the properties from the registry



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
		"a|aaa"			=> \$opt_ssl,
		"d|dirtest"		=> \$opt_dirtest,
		"k|kill"		=> \$opt_kill,
        "l|logging"		=> \$opt_logging,
        "s|server=s"	=> \$opt_server,
        "t|timeout=i"	=> \$opt_timeout,
        "u|username=s"	=> \$opt_username,
        "p|password=s"	=> \$opt_password,
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help,
        "w|wizard"		=> \$opt_wizard,
        "x|xxx"			=> \$opt_debug
    );


    &StdHeader( "Pop3Connecter" ) if ( ! $opt_wizard );
	
 #&SSLTest();
 #die;
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	
	
	# Am I just testing stuff?
	if ( $opt_dirtest )
		{
			&DirTest();
			&StdFooter;
			exit;
		}
	
	
	$opt_server		= shift if ( ! $opt_server );
	$opt_username	= shift if ( ! $opt_username );
	$opt_password	= shift if ( ! $opt_password );
	
	
	&Usage() if ( ( ! $opt_server )  ||  ( ! $opt_username )  ||  ( ! $opt_password ) );
	

	# Make sure that I'm the only Pop3Connecter program running
	if ( $opt_kill )
		{	&ProcessSetDebugPrivilege();
			&ProcessKillName( "Pop3Connecter.exe" );
		}

	
	$my_pid = &ProcessGetCurrentProcessId();
	$my_pid = "1" if ( ! $my_pid );
	
	
	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
			
		
	&SetLogFilename( 'Pop3Connecter.log', $opt_debug ) if ( $opt_logging );
	

	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
		

	my $ok = &PackUtilGetProperties( \%properties );
	if ( ! $ok )
		{	&lprint( "Error getting properties from registry\n" );
			exit( 0 );
		}
		
	my $software_dir = &SoftwareDirectory();
	
	if ( ! -d $software_dir )
		{	&lprint( "Unable to find the software directory $software_dir\n" );
			exit( 0 );
		}

	&lprint( "Using a $opt_timeout second timeout value for connections and data transfers\n" );
	

	# If using SSL - make sure that I can find ssleay32.dll
	if ( ( $opt_ssl )  &&  ( ! &SSLFindDll( ) ) )
		{	&lprint( "Unable to find the Open SSL interface ssleay32.dll\n" );
			exit( 0 );
		}
		
		
	my $pop3dat_file = "$software_dir\\Pop3Connecter-$my_pid.dat";
	if ( ! open( POP3DAT, ">$pop3dat_file" ) )
		{	&lprint( "Error opening file $pop3dat_file: $!\n" );
		}
	
	print POP3DAT "$opt_server\t$opt_username\n";
	
	close( POP3DAT );
	

	&Pop3Connecter( $opt_server, $opt_username, $opt_password, $opt_ssl );
		
	
	unlink( $pop3dat_file );	
	chdir( $cwd );
	
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = &SoftwareDirectory() . "\\Pop3ConnecterErrors.log";
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
sub SSLFindDll()
#
#  Make sure that I can find the Open SSL DLL
#  Return True if I can, undef if not
#
################################################################################
{
	my $dll = "ssleay32.dll";
	
	if ( -f $dll )
		{	&lprint( "Found the Open SSL DDL in the current directory\n" ) if ( $opt_debug );
			return( 1 );
		}
	
	my $path = $ENV{ PATH };
		
	return( undef ) if ( ! $path );
	
	my @parts = split /;/, $path;
	
	foreach ( @parts )
		{	my $part = $_;
			next if ( ! $part );
			next if ( ! -d $part );
			
			my $fullpath = $part . "\\" . $dll;
	
			if ( -f $fullpath )
				{	&lprint( "Found the Open SSL DDL at $fullpath\n" ) if ( $opt_debug );
					return( 1 );
				}
		}
		
	return( undef );
}



################################################################################
#
sub SSLTest()
#
#  Test the SSL stuff
#
################################################################################
{
use Mail::POP3Client;

	my $pop = new Mail::POP3Client( USER => "arrivaltest\@hotmail.com",
			       PASSWORD => "testemail",
			       HOST     => "pop3.live.com",
			       USESSL   => 1,
				   TIMEOUT	=> $opt_timeout
			     );

	print "pop = $pop\n";

	my $msg_number = $pop->Count();
	
	for( my $msgnum = 1; $msgnum <= $msg_number; $msgnum++ )
		{	my $file = "Test 3 tmp $msgnum.txt";
		
			# Open up the file handle to use
			my $file_handle;
			if ( ! open( $file_handle, ">$file" ) )
				{	my $err_msg = $!;
					$err_msg = "undefined" if ( ! $err_msg );
					&lprint( "Error opening file $file: $err_msg\n" );
					last;
				}
				
			my $ok = $pop->RetrieveToFile( $file_handle, $msgnum );
			&lprint( "Error getting message number $msgnum: $!\n" ) if ( ! $ok );
			
			close( $file_handle );

			next if ( ! $ok );
			
			my $delete_ok = $pop->Delete( $msgnum );
			&lprint( "Error marking message number $msgnum for deletion: $!\n" ) if ( ! $delete_ok );
		}

	$pop->Close();



}



################################################################################
# 
sub DirTest( $ )
#
#  Just test all the files in the current directory to see if they are Exchange journalling messages
#
################################################################################
{	
	my $cwd = getcwd;

	my $dir = $cwd;
 	$dir =~ s#\/#\\#gm;
	
	
	my $dir_handle;
	opendir( $dir_handle, $dir ) or die "Unable to open directory $dir: $!\n";

	my $count = 0 + 0;
	while ( my $file = readdir( $dir_handle ) )
		{	
			next if ( ! defined $file );

			next if ( $file eq "." );
			next if ( $file eq ".." );
			next if ( $file =~ m/dirtest\.txt/i );

			$count++;

			my $fullfile = "$dir\\$file";
			my $target = "$dir\\dirtest.txt";
			
			&lprint( "Testing file $file ...\n" );
			&ProcessFile( $fullfile, $target );
		}

	closedir( $dir_handle );
	
	return( 1 );
}



################################################################################
# 
sub Pop3Connecter( $$$$ )
#
#  Given a filename, copy it to all of the backup queues
#  Return undef if any problems
#
################################################################################
{	my $host		= shift;
	my $username	= shift;
	my $password	= shift;
	my $ssl			= shift;	# If TRUE then use SSL
	
	
	return( undef ) if ( ! $host );
	return( undef ) if ( ! $username );


	&lprint( "POP3Connecter arguments: server $host username $username password $password\n" );
	&lprint( "Connecting using SSL port 995\n" ) if ( $ssl );
	&lprint( "Connecting using TCP port 110\n" ) if ( ! $ssl );
	
	&lprint( "Connecting to POP3 server $host ...\n" );
	
	
	my $pop = new Mail::POP3Client( 
				USER		=> $username,
				PASSWORD	=> $password,
				HOST		=> $host,
				USESSL		=> $ssl,
				TIMEOUT		=> $opt_timeout
			     );
		
		
	if ( ! $pop )
		{	&lprint( "Unable to connect to host $host\n" );
			return( undef );
		}
	
	
	# Get the number of messages waiting
	my $msg_number = $pop->Count();
	
	
	# If I have some messages then download them and put them into the queue directory for IpmArchive to process
	if ( ( $msg_number )  &&  ( $msg_number > 0 ) ) 
		{	&lprint( "There are $msg_number messages waiting for username $username\n" );
			
			for( my $msgnum = 1; $msgnum <= $msg_number; $msgnum++ )
				{	my $time = time;
					
					my $file = &TmpFilename( $msgnum, $time );
					
					if ( ! $file )
						{	&lprint( "Error getting tmp filename\n" );
							last;
						}
						
					my $final_file = &QueueFilename( $msgnum, $time );
					if ( ! $final_file )
						{	&lprint( "Error getting final filename\n" );
							last;
						}
					
					&lprint( "Getting message number $msgnum to tmp filename $file ...\n" );
					
					
					# Make sure the directories exists
					my ( $dir, $short_name ) = &SplitFileName( $file );
					&PackUtilBuildDirectory( $dir );
					
					( $dir, $short_name ) = &SplitFileName( $final_file );
					&PackUtilBuildDirectory( $dir );
					
					
					# Open up the file handle to use
					my $file_handle;
					if ( ! open( $file_handle, ">$file" ) )
						{	my $err_msg = $!;
							$err_msg = "undefined" if ( ! $err_msg );
							&lprint( "Error opening file $file: $err_msg\n" );
							last;
						}
						
					my $ok = $pop->RetrieveToFile( $file_handle, $msgnum );
					&lprint( "Error retrieving message number $msgnum\n" ) if ( ! $ok );
					
					close( $file_handle );
					
					
					# Is it OK and does the file exist?
					if ( ( $ok )  &&  ( -s $file ) )
						{	&lprint( "Processing file $file to queue file $final_file ...\n" );
							
							$ok = &ProcessFile( $file, $final_file );
							
							if ( $ok )
								{	&lprint( "Marking message # $msgnum for deletion on $host\n" );
									my $delete_ok = $pop->Delete( $msgnum );
									&lprint( "Error marking message # $msgnum for deletion\n" ) if ( ! $delete_ok );
									
								}
							else
								{	&lprint( "Error processing $file to $final_file\n" );
								}
						}
					else
						{	&lprint( "File $file does not exist\n" ) if ( ! -s $file );
							
							&lprint( "Marking message # $msgnum for deletion on $host\n" );
							my $delete_ok = $pop->Delete( $msgnum );
							&lprint( "Error marking message # $msgnum for deletion\n" ) if ( ! $delete_ok );
						}
				}
		}	
	elsif ( ! defined $msg_number )
		{	&lprint( "Error authenticating the username $username\n" );
		}
	else
		{	&lprint( "No messages for username $username\n" );
		}
	
	
	# Disconnect from the POP3 server
	&lprint( "Disconnecting from $host\n" );
	my $ok = $pop->Close;
	&lprint( "Error disconnecting from $host\n" ) if ( ! $ok );
	
	return( $ok );
}



################################################################################
#
sub ProcessFile( $$ )
#
#  Given an input file of a POP3 message, and the name of the output file
#  to archive, process the file.  Return True if OK, undef if not
#
################################################################################
{	my $input_file	= shift;
	my $output_file = shift;
	
	
	# First, take a look at the input file and see if it is an Exchange style
	# encapsulated message
	return( undef ) if ( ! defined $input_file );
	return( undef ) if ( ! defined $output_file );
	if ( ! -f $input_file )
		{	&lprint( "Can not find file $input_file\n" );
			return( undef );
		}
	
	
	if ( ! open( INPUT, "<$input_file" ) )
		{	my $err = $!;
			$err = "Unknown error" if ( ! $err );
			&lprint( "Error opening $input_file to process: $err\n" );
			return( undef );
		}
	
	
	# Set this to True if it is Exchange 2003 or Exchange 2007
	my $exchange;
	my $passed_exchange2003 = 1;	# Set this flag to undef if the file could not be exchange2003
	my $passed_exchange2007 = 1;	# Set this flag to undef if the file could not be exchange2007
	
	
	my $header = 1;
	my @boundary;
	my $content_class;
	my $content_ident;
	my $part = 0 + 1;
	my $sender;
	my $message_id;
	my $recipients;
	my $line_no = 0 + 1;
	my $content_type;
	my $microsoft_exchange_sender;
	my $part1_message_id;
	my $part_line = 0 + 0;
	
	
	# Could this be a Microsoft Exchange style message?
	my $first_line = <INPUT>;	
	chomp( $first_line );
	my $done; 


	if ( ( $opt_debug )  &&  ( $first_line ) )
		{	&dprint( "Message: Part $part: Line $line_no HEAD: $first_line\n" );
		}
	
	if ( ! $first_line )
		{	&dprint( "This file is not Exchange because the first line is blank\n" );
			$done = 1;	
		}


	while ( ( ! $done )  &&  ( my $line = <INPUT> ) )
		{	chomp( $line );

			$line_no++;
			$part_line++;
			
			
			#  Too many parts to be Exchange?
			if ( $part > 13 )
				{	&dprint( "This file is not Exchange because it has too many message parts\n" );
					last;
				}


			if ( $opt_debug )
				{	my $loc = "HEAD";
					$loc = "BODY" if ( ! $header );
					&dprint( "Message: Part $part:Line $line_no $loc: $line\n" );
				}
				
				
			##############################################################################################################
			#
			#  Header processing
			#
			##############################################################################################################
			if ( $header )
				{	# I need to see a content-class in part 1 if Exchange 2003
					$content_class = 1 if ( ( $part == 1 )  &&  ( $line =~ m/Content\-class\: urn:content\-classes\:message/ ) );
					
					# I need to see a content-ident in part 1 if Exchange 2003
					$content_ident = 1 if ( ( $part == 1 )  &&  ( $line =~ m/Content-Identifier\: ExJournalReport/i ) );
					
					# I need to see a microsoft exchange sender in part 1 if Exchange 2007
					$microsoft_exchange_sender = 1 if ( ( $part == 1 )  &&  ( $line =~ m/Sender\: Microsoft Exchange/i ) );
					
					# I need to see a mmessage ID in part 1 if Exchange 2003 or 2007
					$part1_message_id = 1 if ( ( $part == 1 )  &&  ( $line =~ m/^message-id/i ) );
					
					#  Am I a setting a boundary?
					if ( $line =~ m/boundary=/gi )
						{	my $boundary = substr( $line, pos( $line ) );
							$boundary =~ s#\"##g;   #  Get rid of quotes
							$boundary = '--' . $boundary;	#  Add the dash dash
							$boundary = quotemeta( $boundary );  #  Backslash any non alpha character
							&dprint( "Boundary = $boundary\n" );							
							push @boundary, $boundary;
						}	
						
					#  Am I a setting the Content Type?
					if ( $line =~ m/^content-type:/i )
						{    my ( $junk, $stuff ) = split /\:/, $line, 2;
							$content_type = $stuff;
							$content_type =~ s/\s//;
							$content_type =~ s/\;//;
							( $content_type, $junk ) = split /\s/, $content_type, 2;
						}
				}	# End of header processing
				
				
						
			# Did I find the content class line?
			if ( ( $part > 1 )  &&  ( ! $content_class )  &&  ( $passed_exchange2003 ) )
				{	&dprint( "Not Microsoft Exchange 2003 - No content class line\n" );
					$passed_exchange2003 = undef;
				}
				
				
			#  Have I hit a boundary?
			#  This switches to a header if this matches
			foreach ( @boundary )
				{   my $boundary = $_;
					next if ( ! $boundary );
						
					if ( $line =~ m/$boundary/ )
						{	$header	= 1;
							$part++;
							$part_line = 0 + 0;
							
							&dprint( "Switch to header - boundary $boundary\n" );
						}
				}  # end of foreach boundary
					
					
			#  A blank line or a dot in the header means we are switching to a body
			if (  ( $header )  &&  ( ( ! $line ) || ( $line eq "." ) ) )
				{	$header	= undef;
					$line	= undef;
					$part++;
					$part_line = 0 + 0;
					&dprint( "Switch to body\n" );
				}
			
					
			next if ( ! $line );  #  If the line is now blank, skip it
			
			
			##############################################################################################################
			#
			#  Body processing
			#
			##############################################################################################################
						
			
			# If I have reached the first of part 6 in a body then I need to do the final test to see if this is Exchange 2007
			if ( ( $part == 6 )  &&  ( $part_line == 1 ) )
				{	# Did the file pass all the previous exchange2007 tests?
					if ( ! $passed_exchange2007 )
						{	&dprint( "This file is not exchange 2007\n" );
						}
						
					if ( ( $passed_exchange2007 )  &&  ( ! $part1_message_id ) )
						{	&dprint( "This file is not Exchange 2007 because it does not have a message ID in part 1\n" );
							$passed_exchange2007 = undef;
						}
						
					if ( ( $passed_exchange2007 )  &&  ( ! $microsoft_exchange_sender ) )
						{	&dprint( "This file is not Exchange 2007 because it did not have Microsoft Exchange as the sender in the first header\n" );
							$passed_exchange2007 = undef;
						}
					
					if ( ( $passed_exchange2007 )  &&  ( ! $content_type ) )
						{	&dprint( "This file is not Exchange 2007 because it does not have a content type at all\n" );
							$passed_exchange2007 = undef;
						}
						
					if ( ( $passed_exchange2007 )  &&  ( ! ( $content_type =~ m/message\/rfc822/i ) ) )
						{	&dprint( "This file is not Exchange 2007 because it does not have a content type of message/rfc822\n" );
							$passed_exchange2007 = undef;
						}
						
						
					# Did it pass all the tests for Exchange 2007?	
					if ( $passed_exchange2007 )	
						{	&dprint( "This message is detected as an Exchange 2007 messaging journal message\n" );
							$exchange = 1;
							
							# Am I just testing the file?
							last if ( $opt_dirtest );
							
							# Open the Exchange file and start writing to it
							if ( ! open( EXCHANGE, ">$output_file" ) )
								{	my $err = $!;
									$err = "Unknown error" if ( ! $err );
									&lprint( "Error opening output $output_file to $output_file: $err\n" );
									$exchange = undef;
									
									close( INPUT );
							
									return( undef );
								}
								
							&lprint( "Opened file $output_file to write the message attachment to ...\n" );
						}
					else	# If it didn't pass the Exchange 2007 tests, and it already failed Exchange 2003, then I am all done checking	
						{	last if ( ! $passed_exchange2003 );
						}
				}

				
			# Has this gone past where I should have checked for Exchange 2007?
			if ( ( ! $exchange )  &&  ( $passed_exchange2007 )  &&  ( $part == 6 )  &&  ( $part_line > 1 ) )
				{	&dprint( "This file is not Exchange 2007 because part 5 did not match\n" );
					$passed_exchange2007 = undef;
					last if ( ! $passed_exchange2003 );
				}


			# Does this file have too many parts to be Exchange 2007?
			if ( ( ! $exchange )  &&  ( $passed_exchange2007 )  &&  ( $part > 6 ) )
				{	&dprint( "This file is not Exchange 2007 because it has more than 6 parts\n" );
					$passed_exchange2007 = undef;
					last if ( ! $passed_exchange2003 );
				}


			# Part 4 body should have a sender for Exchange 2007
			if ( ( ! $exchange )  &&  ( $part == 4 ) )
				{	$sender	= 1	if ( $line =~ m/^Sender\:/ );
				}
			
			
			# Did I find what I need in part 4 for exchange 2007? 
			if ( ( ! $exchange )  &&  ( $part > 4 )  &&  ( $passed_exchange2007 ) )
				{	$passed_exchange2007 = undef if ( ! $sender );
					
					if ( ! $passed_exchange2007 )
						{	&dprint( "This file is not Exchange 2007 because it does not match part 4 of an Exchange 2007 file\n" );
						}
				}
			
			
			# Part 6 body should have a sender, message id, and recipients for Exchange 2003
			if ( ( ! $exchange )  &&  ( $part == 6 ) )
				{	$sender		= 1	if ( $line =~ m/^Sender\:/ );
					$message_id = 1 if ( $line =~ m/^Message\-ID\:/ );
					$recipients = 1 if ( $line =~ m/^Recipients\:/ );
				}
			
			
			# Did I find what I need in part 6 for exchange 2003? 
			# Exchange 2007 only has 6 parts, so if I got to here it isn't 2007
			if ( ( ! $exchange )  &&  ( $part > 6 )  &&  ( $passed_exchange2003 ) )
				{	$passed_exchange2003 = undef if ( ! $sender );
					$passed_exchange2003 = undef if ( ! $message_id );
					$passed_exchange2003 = undef if ( ! $recipients );
					
					if ( ! $passed_exchange2003 )
						{	&dprint( "This file is not Exchange 2003 because it does not match part 6 of an Exchange 2003 file\n" );
							last;
						}
				}
			
			
			# Does it really look like Exchange 2003?
			if ( ( ! $exchange )  &&  ( $part == 12 ) )
				{	# Did the file pass all the previous exchange2003 tests?
					if ( ! $passed_exchange2003 )
						{	&dprint( "This file is not exchange 2003\n" );
							last;
						}
						
					if ( ! $part1_message_id )
						{	&dprint( "This file is not Exchange 2003 because it does not have a message ID in part 1\n" );
							last;
						}
					
					if ( ! $message_id )
						{	&dprint( "This file is not Exchange 2003 because it does not have a message ID in part 6\n" );
							last;
						}
					
					if ( ! $content_class )
						{	&dprint( "This file is not Exchange 2003 because it does not have a content class\n" );
							last;
						}
					
					if ( ! $content_ident )
						{	&dprint( "This file is not Exchange 2003 because it does not have a content ident\n" );
							last;
						}
					
					if ( ! $content_type )
						{	&dprint( "This file is not Exchange 2003 because it does not have a content type at all\n" );
							last;
						}
					
					if ( ! ( $content_type =~ m/message\/rfc822/i ) )
						{	&dprint( "This file is not Exchange 2003 because it does not have a content type of message/rfc822\n" );
							last;
						}
					
					if ( ! $first_line )
						{	&dprint( "This file is not Exchange 2003 because it the first line is blank\n" );
							last;
						}
						
					if ( ! ( $first_line =~ m/^Received/ ) )
						{	&dprint( "This file is not Exchange 2003 because it the first line is not a Received:\n" );
							last;
						}
						
						
					# If I got to here then it is Exchange 2003 	
					&dprint( "This message is detected as an Exchange 2003 messaging journal message\n" );
					$exchange = 1;
					
					# Am I just testing the file?
					last if ( $opt_dirtest );
					
					# Open the Exchange file and start writing to it
					if ( ! open( EXCHANGE, ">$output_file" ) )
						{	my $err = $!;
							$err = "Unknown error" if ( ! $err );
							&lprint( "Error opening output $output_file to $output_file: $err\n" );
							$exchange = undef;
							
							close( INPUT );
					
							return( undef );
						}
						
					&lprint( "Opened file $output_file to write the message attachment to ...\n" );
				}
				
								
			# Has too many lines gone past and I haven't figured out if it is Exchange?
			if ( ( ! $exchange )  &&  ( $line_no > 200 ) )
				{	&dprint( "Read $line_no lines and this file does not look like Exchange\n" );
					last;
				}
				
				
			# If it is the 12th part, and it is an Exchange 2003 message, then start writing to disk each line
			if ( ( $exchange )   &&  ( $part == 12 ) )
				{	print EXCHANGE "$line\n";
				}
				
				
			# If it is the 6th part, and it is an Exchange 2007 message, then start writing to disk each line
			if ( ( $exchange )   &&  ( $part == 6 ) )
				{	print EXCHANGE "$line\n";
				}
				
		}
		
	close( INPUT );

	
	&lprint( "$input_file is not Exchange 2003 or 2007 formatted\n" ) if ( ! $exchange );
	&lprint( "$input_file was detected as Exchange 2003\n" ) if ( ( $exchange )  &&  ( $passed_exchange2003 ) );
	&lprint( "$input_file was detected as Exchange 2007\n" ) if ( ( $exchange )  &&  ( $passed_exchange2007 ) );

	
	# Return here if I am just testing	
	return( $exchange ) if ( $opt_dirtest );
	
	
	# If the Exchange flag is set then I have opened a file above and handled everything, so now I just need to close the file and return
	if ( $exchange )
		{	close( EXCHANGE );
			return( 1 );
		}
	
	

	# At this point I know that it is NOT a Microsoft Exchange style message, so all I have to 
	# do is move the file
	
	my $ok = move( $input_file, $output_file );
	
	if ( ! $ok )
		{	my $err = $!;
			$err = "Unknown error" if ( ! $err );
			&lprint( "Error moving $input_file to $output_file: $err\n" );
		}
		
	return( $ok );
}



################################################################################
#
sub TmpFilename( $ )
#
#  Return a tmp filename to use to download messages to
#
################################################################################
{	my $msgnum	= shift;
	my $time	= shift;
	
	my $tmp_dir = &TmpDirectory();
	
	return( undef ) if ( ! $tmp_dir );
	
	my $my_pid = &ProcessGetCurrentProcessId();
	$my_pid = "1" if ( ! $my_pid );
	

	# Use the pid and the msgnum to build a good tmp file
	my $tmp_file = $tmp_dir . "\\Pop3Connecter-$my_pid-$msgnum-$time.eml";

	return( $tmp_file );
}




################################################################################
#
sub QueueFilename( $$ )
#
#  Return the final filename to use for a downloaded message
#
################################################################################
{	my $msgnum	= shift;
	my $time	= shift;
	
	my $queue_dir = $properties{ "Queue Directory" };
	
			
	mkdir( $queue_dir ) if ( ! -d $queue_dir );
	
	return( undef ) if ( ! -d $queue_dir );
	
	# Use the pid and the msgnum to build a good final file
	my $final_file = $queue_dir . "\\Pop3Connecter-$my_pid-$msgnum-$time.eml";

	return( $final_file );
}




################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Return OK if the directory already exists
	return( 1 ) if ( -d $dir );
	
	my @parts = split /\\/, $dir;
	
	my $created_dir;
	foreach ( @parts )
		{	next if ( ! defined $_ );
			
			$created_dir .= "\\" . $_ if ( defined $created_dir );
			$created_dir = $_ if ( ! defined $created_dir );

			if ( ! -d $created_dir )
				{	mkdir( $created_dir );
				}
		}
		
	return( 1 );
}



################################################################################
# 
sub dprint()
#
#	lprint some text if debugging is turned on
#
################################################################################
{	return( undef ) if ( ! $opt_debug );
	
	&lprint( @_ );
			
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Pop3Connecter";

    print <<".";
Usage: $me server username password [OPTION(s)]
Pop3Connecter connects to a POP3 server, downloads any messages for the given
username/password, and then puts the messages in the Queue directory so that
the IpmArchive program will add the messages into the message journal.

  -a             to use SSL to connect to the POP3 server
  -d, --dirtest  to test the files in the current directory to see if
                 they are Exchange 2003 or Exchange 2007 message journaling
  -k, --kill     kill any POP3 Connecter process that are running

  -t, --timeout  time out, default is 600 seconds
  
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
    my $me = "Pop3Connecter";

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

