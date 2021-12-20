################################################################################
#!perl -w
#
#  DirectorySync.pl - Given a list of directories and files, sync them with a 
# list of servers
#  Copyright 2009 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;



use Errno qw(EAGAIN);
use Cwd;
use Getopt::Long();
use File::Copy;
use Win32::File;
use Win32::Event;



use Content::File;
use Content::Mail;



my $opt_help;
my $opt_filename = "DirectorySync.txt";		# The name of the file containing the list of servers, directories, and files
my $opt_drive = "s";						# Drive letter to use for connecting to UNC
my $opt_verbose;							# True if verbose mode
my $opt_minutes = 0 + 5;					# The number of minutes to wait before looping again
my $opt_logging;							# If True then log events to a file
my $opt_debug;


my $event_name = "DirectorySync";
my $cwd;									# If set this is the current working directory
my @email_alert;							# If set - this is the list of email addresses to send alerts to
my $monitor_server = "monitor.lightspeedsystems.com";	# This is the TTC server at Lightspeed to flip email alerts to



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
		"d|drive=s"		=> \$opt_drive,
		"f|file=s"		=> \$opt_filename,
		"l|logging"		=> \$opt_logging,
		"m|minutes=i"	=> \$opt_minutes,
		"v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help,
        "x|xdebug"		=> \$opt_debug
      );



    print( "DirectorySync\n" );
	&Usage() if ( $opt_help );

	if ( $opt_logging )	
		{	&SetLogFilename( ".\\DirectorySync.log", undef );
			&lprint( "Set logging file to DirectorySync.log\n" );
		}


	my $temp = shift;
	$opt_filename = $temp if ( defined $temp );		

	if ( ! -f $opt_filename )
		{	&lprint( "Unable to find DirectorySync command file $opt_filename\n" );
			exit();
		}

	if ( length( $opt_drive ) != 1 )
		{	&lprint( "$opt_drive is not a valid drive letter\n" );
			exit( 1 );
		}
		
	$opt_drive = lc( $opt_drive );
	if ( ! ( $opt_drive =~ m/[d-z]/ ) )
		{	&lprint( "$opt_drive is not a valid drive letter\n" );
			exit( 1 );
		}
	
	
	# Show the options
	&lprint( "Using temporary drive $opt_drive\n" );
	&lprint( "Reading DirectorySync commands from $opt_filename\n" );
	&lprint( "Logging enabled\n" ) if ( $opt_logging );
	&lprint( "Logging disabled\n" ) if ( ! $opt_logging );
	&lprint( "Waiting $opt_minutes minutes between checking directories\n" );
	&lprint( "Verbose mode enabled\n" ) if ( $opt_verbose );
	&lprint( "Verbose mode disabled\n" ) if ( ! $opt_verbose );

		
	
	if ( ! open( INFILE, "<$opt_filename" ) )
		{	&lprint( "Error opening $opt_filename: $!\n" );
			exit( 1 );	
		}
		
	
	my @unc;
	my @path;
	my @file;

	
	my $type;
	while ( my $line = <INFILE> )
		{	chomp( $line );
			next if ( ! $line );
			
			if ( $line =~ m/^unc:/i )
				{	$type = "unc";
					next;
				}
			elsif ( $line =~ m/^path:/i )
				{	$type = "path";
					next;
				}
			elsif ( $line =~ m/^file:/i )
				{	$type = "file";
					next;
				}
			elsif ( $line =~ m/^emailalert:/i )
				{	$type = "emailalert";
					next;
				}
			
			next if ( ! defined $type );
			
			if ( $type eq "unc" )
				{	push @unc, $line;
					&lprint( "UNC $line\n" ) if ( $opt_verbose );
				}
			elsif ( $type eq "path" )
				{	push @path, $line;
					&lprint( "Path $line\n" ) if ( $opt_verbose );
					
					if ( ! -d $line )
						{	&BadError( "Unable to find path $line\n" );
							exit( 1 );	
						}
				}
			elsif ( $type eq "file" )
				{	push @file, $line;
					&lprint( "File $line\n" ) if ( $opt_verbose );
				}
			elsif ( $type eq "emailalert" )
				{	push @email_alert, $line;
					&lprint( "Email Alert $line\n" ) if ( $opt_verbose );
				}
		}
		
	close( INFILE );
	
	
	if ( $#unc < 0 )
		{	&BadError( "No UNC paths defined in $opt_filename\n" );
			exit( 1 );
		}

	if ( $#path < 0 )
		{	&BadError( "No directory paths defined in $opt_filename\n" );
			exit( 1 );
		}

	if ( $#file < 0 )
		{	&BadError(  "No files defined in $opt_filename\n" );
			exit( 1 );
		}
		
		
	$cwd = getcwd;
	$cwd =~ s#\/#\\#g;
	$cwd =~ s/\\$//;   # Trim off a trailing slash
	

	# Show who I am emailing alerts to
	if ( $#email_alert > -1 )
		{	
			my $line = "Emailing Alerts to: ";
			foreach ( @email_alert )
				{	$line .= $_;
					$line .= " ";
				}
			$line .= "\n";
			
			&lprint( $line );
		}
		
		  
	# Get a unique name to use for an event for signalling between the parent and child process
	my $my_pid = &ProcessGetCurrentProcessId();
	$event_name .= "-PID$my_pid";
	
	
	#  Now fork off a child process
	my $pid;
	
	FORK:
		{
			if ( $pid = fork )
				{	&lprint( "Started child process pid $pid\n" ) if ( $opt_verbose ); 
					sleep 10;  # Sleep for 10 seconds to give the child time to get started 
				}

			elsif ( defined $pid )
				{	&lprint( "Child process started\n" );
					goto CONTINUE;
				}

			elsif ( $! == EAGAIN )
				{	sleep 15;
					redo FORK;
				}

			else
				{	&BadError( "Can't fork: $!\n");
				}

		}  # end of FORK


	CONTINUE:


	# The parent process should have the pid defined
	if ( $pid )
		{	&lprint( "Parent process is watching child process pid $pid ...\n" ) if ( $opt_verbose );
			
			my $event = Win32::Event->new( 1, 1, $event_name );
			$event->set;
			
			my $no_change = 0 + 0;
			while ( 1 )
				{	&lprint( "Top of parent loop\n" ) if ( $opt_verbose );
					
					# Handle the outgoing process event - this waits for 60 seconds
					my $ret = $event->wait( 60000 );
					$event->reset;
					
					if ( ( ! $ret )  ||  ( $ret == -1 ) )
						{	$no_change++;
							&lprint( "Child process has not responded for $no_change minutes\n" ) if ( $no_change > 1 );	
							last if ( $no_change >= ( $opt_minutes + 5 ) );
						}
					else
						{	&lprint( "Child process is alive\n" ) if ( $opt_verbose );
							print "Child process is alive\n" if ( ! $opt_verbose );
							
							$no_change = 0 + 0;
						}
						
					if ( $no_change >= ( $opt_minutes + 5 ) )
						{	last;
						}
				}
			
			&BadError( "At least $no_change minutes has gone by without the child DirectorySync responding\n" );	
			&lprint( "Waiting for the child process to finish ...\n" );
			kill( $pid );
			wait;
			
			&lprint( "Waiting 10 seconds for any emails to get delivered ...\n" );
			
			sleep( 10 );
			exit( 0 );
		}
		
	
		
	# This is where the child process starts doing work ...	
	sleep( 20 );  # Wait for the parent process to get going
	&lprint( "Child process has started working ...\n" ) if ( $opt_verbose );
	my $loop_counter = 0 + 0;
	
	while ( 1 )
		{	$loop_counter++;
			
			my $loopevent = Win32::Event->open( $event_name );
			if ( ! $loopevent )
				{	&BadError( "Parent process has disappeared - exiting now\n" );
					exit( 0 );
				}
								
			# Signal the inevent
			&lprint( "Signalling the parent process\n" ) if ( $opt_verbose );
			$loopevent->set;
							
			foreach ( @unc )
				{	my $unc = $_;
					next if ( ! defined $unc );

					# Signal the inevent
					&lprint( "Signalling the parent process\n" ) if ( $opt_verbose );
					$loopevent->set;
					
					&lprint( "\nChecking $unc ...\n" );

					
					# Am I already connected to opt_drive: ?
					if ( -d "$opt_drive:\\" )
						{	system "net use $opt_drive: /delete /y";
						}
						
					if ( -d "$opt_drive:\\" )
						{	&lprint( "Error deleting UNC path $opt_drive:\n" );
							next;
						}
							
					system "net use $opt_drive: $unc";
					
					if ( ! -d "$opt_drive:\\" )
						{	&BadError( "Error connecting to UNC path $unc\n" );
							exit( 1 );
						}
						
					&lprint( "Connected to UNC $unc successfully\n" ) if ( $opt_verbose );	


					foreach ( @path )
						{	my $path = $_;
							next if ( ! defined $path );
							
							# Signal the inevent
							&lprint( "Signalling the parent process\n" ) if ( $opt_verbose );
							$loopevent->set;
					
							if ( ! -d $path )
								{	&BadError( "Error - directory $path not found on UNC path $unc\n" );
									exit( 1 );
								}
								
							foreach ( @file )
								{	my $file = $_;
									next if ( ! defined $file );
									
									my $dest = $path;
									if ( $dest =~ m/^.\:/ )
										{	$dest =~ s/^./$opt_drive/;
										}
									else
										{	if ( $path =~ m/^\\/ )
												{	$dest = "$opt_drive:" . $path;
												}
											else
												{	$dest = "$opt_drive:\\" . $path;
												}
										}
									
									if ( $opt_verbose )	
										{	&lprint( "\nCopyFile UNC: $unc\n" );
											&lprint( "CopyFile Source: $path\n" );
											&lprint( "CopyFile Destination: $dest\n" );
											&lprint( "CopyFile File: $file\n" );
										}
										
									&CopyFile( $path, $dest, $file, $unc );
									
									chdir( $cwd );
								}	# End of checking each file
								
						}	# End of checking each path
						
						
					# Signal the inevent
					&lprint( "Signalling the parent process\n" ) if ( $opt_verbose );
					$loopevent->set;

					# Disconnect from the UNC path	
					if ( -d "$opt_drive:\\" )
						{	system "net use $opt_drive: /delete /y";
						}
						
					if ( -d "$opt_drive:\\" )
						{	&lprint( "Error deleting UNC path $opt_drive:\n" );
							next;
						}
						
					&lprint( "Finished checking $unc\n" );

					sleep( 1 );
				}	# End of checking each UNC
			
			chdir( $cwd );	
						
			&lprint( "Waiting for $opt_minutes minutes before checking again ...\n" );
			for ( my $i = 0 + 0;  $i < $opt_minutes;  $i++ )
				{	# Signal the inevent
					&lprint( "Signalling the parent process\n" ) if ( $opt_verbose );
					$loopevent->set;
					sleep( 60 );
				}
		}	# End of done loop
		
	chdir( $cwd );
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub CopyFile( $$$$ )
#
#  Return True if copied OK, undef if not
#
################################################################################
{	my $src_dir		= shift;
	my $dest_dir	= shift;
	my $file		= shift;	# This could be a wildcard
	my $unc			= shift;
	

	&lprint( "Directory: $src_dir\n" ) if ( $opt_verbose ); 
	
	my $change;			# Set this to True if I am changing anything
	
	
	my @files;
	my @short_files;
	my @dest_files;
	my @short_dest_files;
	
	
	# Make sure that the destination directory exists
	if ( ! &MakeDirectory( $dest_dir ) )
		{	&BadError( "Error on UNC $unc making directory $dest_dir: $!\n" );
			exit( 1 );
		}
		
		
	# Do I have a wildcard specification?
	if ( ( $file =~ m/\*/ )  ||  ( $file =~ m/\?/ ) )
		{	@files = &MyGlob( "$src_dir\\$file" );
			
			foreach ( @files )
				{	my $filename = $_;
					next if ( ! defined $filename );

					my ( $dir, $short ) = &SplitFileName( $filename );
					push @short_files, lc( $short );
					
					&lprint( "Src file: $filename\n" ) if ( $opt_verbose );
				}
			
			@dest_files = &MyGlob( "$dest_dir\\$file" );
			
			foreach ( @dest_files )
				{	my $dest = $_;
					next if ( ! defined $dest );
					
					my ( $dir, $short ) = &SplitFileName( $dest );
					push @short_dest_files, lc( $short );
					
					&lprint( "Dest file: $dest\n" ) if ( $opt_verbose );
				}
		}
	elsif ( -f $file )
		{	push @files, $file;
			my ( $dir, $short ) = &SplitFileName( $file );
			push @short_files, lc( $short );
			
			&lprint( "File: $file\n" ) if ( $opt_verbose );
		}


	
	# Nothing to do because I got no files to copy or delete
	if ( ( $#files < 0 )  &&  ( $#dest_files < 0 ) )
		{	&lprint( "No files to change or delete that match $file\n" );
			return( 1 );
		}


	# Are there any files in the destination I need to delete?
	my @delete_list;
	foreach ( @short_dest_files )
		{	my $short_dest = $_;
			next if ( ! defined $short_dest );
			
			# Make sure that each file in the destination directory has the same name in the source directory
			# If not, then I need to delete it
			my $delete = 1;
			foreach ( @short_files )
				{	my $short = $_;
					$delete = undef if ( $short eq $short_dest );
					last if ( ! $delete );
				}
				
			push @delete_list, $short_dest if ( $delete );	
			
			# Delete any leftover .old files
			my $fullfilename = "$dest_dir\\$short_dest";
			
			my $old = "$fullfilename.old";
			next if ( ! -f $old );
			
			&lprint( "Deleting old file $old ...\n" );
			my $ok = unlink( $old );
			
			&lprint( "Error trying to delete $old: $!\n" ) if ( ! $ok );
			&lprint( "Deleted $old OK\n" ) if ( $ok );
			
			$change = 1;
		}


	# If I got anything in the delete list then I need to delete them here
	foreach ( @delete_list )
		{	my $delete_file = $_;
			next if ( ! defined $delete_file );
			my $fullfilename = "$dest_dir\\$delete_file";
			next if ( ! -f $fullfilename );
			
			&lprint( "Deleting file $fullfilename ...\n" );
			
			# Do a rename and delete in case the file is in use by another process
			my $old = "$fullfilename.old";
			my $ok = 1;
			
			$ok = unlink( $old ) if ( -f $old );
			&lprint( "Error trying to delete old file $old\n" ) if ( ! $ok );
			
			$ok = rename( $fullfilename, $old );
			&lprint( "Error trying to rename $fullfilename to $old: $!\n" ) if ( ! $ok );
			
			$ok = unlink( $old );
			
			# If everything worked right then the file is already gone, and this won't do anything
			# If it didn't work, then this is a last chance
			$ok = unlink( $fullfilename ) if ( -f $fullfilename );	
			
			# If I get an error here then keep going, trusting that I can delete the file later
			&lprint( "Error deleting $fullfilename: $!\n" ) if ( ! $ok );
			&lprint( "Deleted $fullfilename OK\n" ) if ( ( $ok )  &&  ( $opt_verbose ) );
			
			$change = 1;
		}
	
	
	# Nothing to do because I got no files to copy
	if ( $#files < 0 )
		{	&lprint( "No files to copy that match $file\n" );
			return( 1 );
		}


	# OK - at this point I can start copying
	foreach ( @files )
		{	my $src_file = $_;
			next if ( ! defined $src_file );
			
			# Did the source file disappear?
			if ( ! -f $src_file )
				{	&lprint( "Source file $src_file has disappeared!\n" );
					next;
				}
				
			my ( $dir, $short ) = &SplitFileName( $src_file );
			
			my $dest_file = "$dest_dir\\$short";
			
			my $retcode = &FileCompare( $src_file, $dest_file );	
			if ( ! $retcode )
				{	&lprint( "File $dest_file is already the same as $src_file\n" ) if ( $opt_verbose );
					next;
				}
			
			
			$change = 1;
			
			
			# If the dest file file is readonly, turn off that attribute
			my $attrib;
			Win32::File::GetAttributes( $dest_file, $attrib );
			
			# Is the readonly bit set?  If so, turn it off
			if ( $attrib & READONLY )
				{	$attrib = $attrib - READONLY;
					Win32::File::SetAttributes( $dest_file, $attrib );
				}
			
			
			# Use an old file if the target exists
			my $old;
			my $ok = 1;
			if ( -f $dest_file )
				{	$old = "$dest_file.old";
					
					# Delete the old old file if it exists - this isn't a huge problem if it fails
					if ( -f $old )
						{	$ok = unlink( $old );
							if ( ! $ok )
								{	&lprint( "Error on UNC $unc trying to delete $old: $!\n" );
								}
						}
						
					$ok = rename( $dest_file, $old );
					if ( ! $ok )
						{	&BadError( "Error on UNC $unc trying to rename $dest_file to $old: $!\n" );
							exit( 1 );
						}
				}
			
			
			&lprint( "Copying $src_file to $dest_file\n" );	
			
			$ok = copy( $src_file, $dest_file );
			if ( ! $ok )
				{	&BadError( "Error on UNC $unc copying $src_file to $dest_file: $!\n" );
					exit( 1 );
				}
				
			&lprint( "Copied ok\n" ) if ( $retcode );
			
			# If this delete doesn't happen it's not the end of the world
			unlink( $old ) if ( defined $old );
		}


	&lprint( "No changes for $file\n" ) if ( ! $change );


	return( 1 );
}



################################################################################
#
sub FileCompare( $$ )
#
#  Compare 2 files.  If the sizes are different, return TRUE
#  Make sure the the to file isn't newer than the from file ...
#
################################################################################
{	my $from	= shift;
	my $to		= shift;
	
	# Do the files exist?
	return( 1 ) if ( !-e $from );
	return( 1 ) if ( !-e $to );
	
	# Are the file sizes different?	
	my $from_size = -s $from;
	my $to_size = -s $to;

	return( 1 ) if ( $from_size ne $to_size );
		
	# Is the existing file have a different mtime?
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $from;	
	my $from_mtime = 0 + $mtime;

	( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $to;
	my $to_mtime = 0 + $mtime;
	
	# Return if the times are different	
	return( 1 ) if ( $to_mtime != $from_mtime );

	return( undef );
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
		
	# Return OK if the directory now exists
	return( 1 ) if ( -d $dir );
	
	return( undef );
}



################################################################################
# 
sub MyGlob( $ )
#
#  The File::Glob::Windows doesn't work - it screws up the stack, so this is
#  my implementation
#
################################################################################
{	my $filespec = shift;
	
use File::DosGlob;
use Cwd;

	my $curdir;
	
	my ( $dir, $short ) = &SplitFileName( $filespec );
	
	if ( defined $dir )
		{	$curdir = getcwd;
			$curdir =~ s#\/#\\#g;
			$curdir =~ s/\\$//;   # Trim off a trailing slash
			
			chdir( $dir );
		}
		
	my @files = glob( $short );

	return( @files ) if ( ! defined $dir );
	
	chdir( $curdir ) if ( defined $curdir );
	
	my @return;
	
	foreach( @files )
		{	my $file = $_;
			next if ( ! defined $file );
			
			push @return, "$dir\\$file";
		}

	return( @return );
}



################################################################################
# 
sub ProcessGetCurrentProcessId()
#
#  Return the pid of my process, or undef if an error
#
################################################################################
{
use Win32::API;
	
	my $GetCurrentProcessId = new Win32::API( 'kernel32.dll', 'GetCurrentProcessId', '', 'N' );
	return( undef ) if ( ! $GetCurrentProcessId );
	
	my $pid = $GetCurrentProcessId->Call();
	
	return( $pid );
}



################################################################################
# 
sub EmailLogFile( $$$$ )
#
#  Given the file name prefix to use, the subject line, message test, and
#  the log file, email the log file to support@lightspeedsystems.
#
################################################################################
{	my $email_file		= shift;
	my $subject			= shift;
	my $message_text	= shift;
	my $log_file		= shift;	# This could be undefined
	
use MIME::Base64;
	
use Socket;
use Sys::Hostname;
	
	
	# Get a good hostname to use for the local host
	my $host = hostname();
	my $packed_ip = ( gethostbyname( $host ) )[ 4 ];
	my $myipaddress = inet_ntoa( $packed_ip ) if ( defined $packed_ip );
	$myipaddress = "0.0.0.0" if ( ! defined $packed_ip );

	# Default a reasonable hostname for version 5.0 and 5.1 servers 
	my $hostname = $host . " - IP $myipaddress";


	my ( $dir, $short_file  ) = &SplitFileName( $log_file ) if ( defined $log_file );
	$short_file = "none.txt" if ( ! defined $short_file );
	
		
	# Make sure that we are in the current directory	
	chdir( $cwd );
		
		
	# Build up the email message
	my $from = "support\@lightspeedsystems.com";
	
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d.%02d.%02d", $year, $mon, $mday, $hour, $min, $sec );
	my $filestr = sprintf( "%04d%02d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );

	$email_file .= $filestr;
	$email_file .= $email_alert[ 0 ] . ".txt";
	
	$subject = $subject . " from $hostname" if ( $hostname );
	
	# Build the message to send
	my ( $header, $b ) = &MailHeader( $from, $subject, @email_alert );

	my $message = $header;
   
	# Buid up a text message as the first part of the multipart
    $message .= sprintf"\n--%s\n",$b;       
	$message .= "Content-Type: text/plain;\n";
	$message .= "	charset=\"us-ascii\"\n";
	$message .= "Content-Transfer-Encoding: quoted-printable\n\n";
	
    $message .= "=20\n\n";
	
	
	$message .= $message_text . "=20\n\n";
	
	$message .= sprintf"\n--%s\n",$b;
		  
	$message .= "Content-Type: application/text;
	name=\"$short_file\"
Content-Transfer-Encoding: base64
Content-Description: $short_file
Content-Disposition: attachment;
	filename=\"$short_file\"
\n";
	
   
	if ( defined $log_file )
		{	open( LOGFILE, "<$log_file" );
			binmode( LOGFILE );
			
			my $buf;
			my $len = 0 + 57;
			
			while ( read( LOGFILE, $buf, $len ) )
				{	my $outbuf = encode_base64( $buf );
					$message .= "$outbuf";
				}
				
			close( LOGFILE );
		}
		
		
	$message .= sprintf"\n--%s\n",$b;
	$message .= ".\n";
	
	my ( $ok, $msg ) = &PostMessageFile( $monitor_server, "$cwd\\$email_file", $from, $message, undef, undef, @email_alert );

	return( 1 ) if ( $ok );
	
	&lprint( "Error emailing: $msg" );
	
	return( undef );
}



################################################################################
# 
sub BadError( $ )
#
#	A bad error has happened.  Do what I can to report it
#
################################################################################
{	my $error = shift;	# This should be a description of the error
	
	chomp( $error );
	print "Bad Error occurred: $error\n";
	
	&StdFooter;

	if ( $#email_alert < 0 )
		{	print "No email alert addresses configured so exiting here\n";
			exit( 1 );	
		}
	
	my $log_file = &GetLogFilename();
	
	my $ret = &EmailLogFile( "DirectorySync", "Directory Sync Error", "Error Message: $error", $log_file );
	
	sleep( 2 );	# Give the mail meeage a little time
	
	exec( "c:\\content\\bin\\waitfor directorysync" );	
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";

Usage: DirectorySync [options]

This utility keep directories in sync across UNC paths.
DirectorySync uses the file size and the last modified Date Time to determine
if a file has changed.


The format of the SYNCCMD file is:
UNC:
(unc paths to servers and shares - i.e. \\server\c$)
PATH:
(directories to syncronize - no wildcards)
FILE:
(file names to syncronize - may be wilcards like *.htm)
EMAILALERT:
(list of email addresses to mail to if bad errors occur)



Possible options are:

  -d, drive DRIVELETTER   the temporary drive letter to use for copying
                          default drive letter is S:
  -f, --file SYNCCMD      the list of UNC, paths, and files to sync
                          default file is DirectorySync.txt
  -l, --logging           to log events to DirectorySync.log
  -m, --minutes MINUTES   the number of minutes to wait before checking again
                          default is 5 minutes
						  
  -v, --verbose           verbose mode
  -h, --help              print this message and exit

.

exit;
}



################################################################################

__END__

:endofperl
