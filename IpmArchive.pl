################################################################################
#!perl -w
#
# Rob McCarthy's IpmArchive source code
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Win32API::Registry 0.21 qw( :ALL );
use Cwd;
use File::Copy;


use Content::Process;


use Pack::PackFile;
use Pack::PackUtil;
use Pack::PackSQL;
use Pack::Pack;


use Index::IndexEml;
use Index::IndexSql;
use Index::Index;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging = 1;			# True if I should log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_wizard;					# True if run from a Wizard dialog
my $opt_file;					# If True then just index this message
my $opt_dir;					# If True, then index everything in this directory
my $opt_log_continuous;			# If True, then keep writing to the same log files instead of overwriting
my $opt_reindex;				# If True, then reindex all the packed files
my $opt_verbose;
my $opt_month;					# The month to reindex
my $opt_start;					# The starting month to reindex
my $opt_end;					# The ending month to reindex


my @backup_servers;				# The list of backup servers 
my %properties;					# The hash of properties for Mail Archiving

my $_version = "1.0.0";



################################################################################
#
MAIN:
#
################################################################################
{

#my $file  = "no snippet 2.eml";
#my $tmp_dir = "c:\\tmp";
#my $final_file;
#my %clues;
#my @attached_files;
#my @to;
#my ( $index_now, $exception_name, $eml_message_id ) = &IndexEml( $file, $tmp_dir, \$final_file, \%clues, \@attached_files, \@to );

#my $snip = $clues{ "SNIP" };

#print "snip = $snip\n" if ( defined $snip );
#print "no snip\n" if ( ! defined $snip );

#die;


	# Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "d|dir=s"		=> \$opt_dir,
		"e|end=s"		=> \$opt_end,
		"f|file=s"		=> \$opt_file,
        "m|month=s"		=> \$opt_month,
        "l|logging"		=> \$opt_log_continuous,
        "r|reindex"		=> \$opt_reindex,
        "s|start=s"		=> \$opt_start,
        "v|version"		=> \$opt_version,
        "h|help"		=> \$opt_help,
        "w|wizard"		=> \$opt_wizard,
        "x|xxx"			=> \$opt_debug
    );

    &StdHeader( "IpmArchive" ) if ( ! $opt_wizard );
	
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	# Make sure that I'm the only IpmArchive program running
#	&ProcessSetDebugPrivilege();
#	&ProcessKillName( "IpmArchive.exe" );


	
	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
		
		
	&SetLogFilename( 'IpmArchive.log', ( $opt_debug || $opt_log_continuous ) ) if ( $opt_logging );



	# If I'm indexing a file, make sure it exists
	if ( ( $opt_file )  &&  ( ! -e $opt_file ) )
		{	&lprint( "File $opt_file does not exist\n" );
			exit;
		}
		

	# If I'm indexing a directory, make sure it exists
	if ( ( $opt_dir )  &&  ( ! -d $opt_dir ) )
		{	&lprint( "Directory $opt_dir does not exist\n" );
			exit;
		}
		
	
	my @months;	
	if ( $opt_month )
		{	# Check that the month is in the right YYYYMM format
			@months = split /\,/, $opt_month;
			
			foreach( @months )
				{	my $month = $_;
					
					$month =~ s/^\s+//;
					$month =~ s/\s+$//;
					
					$month = &CheckMonth( $month );
					
					exit( -1 ) if ( ! $month );
					
					&lprint( "Reindexing month $month\n" );	
				}
		}


	if ( $opt_start )
		{	# Check that the month is in the right YYYYMM format
			$opt_start = &CheckMonth( $opt_start );
					
			exit( -1 ) if ( ! $opt_start );
					
			&lprint( "Reindexing from starting month $opt_start\n" );	
		}


	if ( $opt_end )
		{	# Check that the month is in the right YYYYMM format
			$opt_end = &CheckMonth( $opt_end );
					
			exit( -1 ) if ( ! $opt_end );
					
			&lprint( "Reindexing with ending month $opt_end\n" );	
		}


	# Start up packing
	my $read_only = 1 if ( ( $opt_month )  ||  ( $opt_start )  ||  ( $opt_end )  ||  ( $opt_reindex ) );
	my $ok = &PackStart( $read_only );
	if ( ! $ok )
		{	&lprint( "Error starting to pack\n" );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 0 );
		}
		

	# Start up indexing
	$ok = &IndexStart();
	if ( ! $ok )
		{	&lprint( "Error starting to index\n" );
			my $last_err = &IndexLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 0 );
		}
		

	$ok = &PackUtilGetProperties( \%properties, 1 );
	if ( ! $ok )
		{	&lprint( "Error getting properties from registry\n" );
			my $last_err = &IndexLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 0 );
		}
	
	
	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	if ( $opt_month )
		{	foreach( @months )
				{	my $month = $_;
					&Reindex( $month );
				}
		}
	elsif ( $opt_start )
		{	&Reindex();
		}
	elsif ( $opt_end )
		{	&Reindex();
		}
	elsif ( $opt_reindex )
		{	&Reindex();
		}
	elsif ( $opt_dir )
		{	&IndexDir( $opt_dir, undef, undef, undef, undef );
		}
	elsif ( $opt_file )	
		{	&lprint( "Indexing $opt_file ...\n" );

			my $fullfile = $opt_file;
			$fullfile = "$cwd\\$opt_file" if ( ! ( $opt_file =~ m/\\/ ) );
					
			my $ok = &Index( $fullfile, undef, undef, undef, undef );
			my $last_err = &IndexLastError();
			&lprint( "$last_err\n" ) if ( ( ! $ok )  &&  ( defined $last_err ) );
		}
	else	# I'm going into normal operating mode
		{
			# First index anything on the command line
			&IndexDirection( "Command line" );
			
			while ( my $file = shift )
				{	&lprint( "Indexing $file ...\n" );

					my $fullfile = $file;
					$fullfile = "$cwd\\$file" if ( ! ( $file =~ m/\\/ ) );
					
					my $ok = &Index( $fullfile, undef, undef, undef, undef );
					my $last_err = &IndexLastError();
					&lprint( "$last_err\n" ) if ( ( ! $ok )  &&  ( defined $last_err ) );
				}
			
			my $archive_internal	= $properties{ "Archive Internal Mail" };
			my $archive_incoming	= $properties{ "Archive Incoming Mail" };
			my $archive_outgoing	= $properties{ "Archive Outgoing Mail" };
			my $archive_im			= $properties{ "Archive IM" };

			my $index_email;
			$index_email = 1 if ( ( $archive_internal )  &&  ( $archive_internal eq "\x01\x00\x00\x00" ) );
			$index_email = 1 if ( ( $archive_incoming )  &&  ( $archive_incoming eq "\x01\x00\x00\x00" ) );
			$index_email = 1 if ( ( $archive_outgoing )  &&  ( $archive_outgoing eq "\x01\x00\x00\x00" ) );

			&lprint( "Starting IpmArchive normal operation  ...\n" ) if ( $index_email );	

			
			# Are any email backup servers defined?
			my $email_backup;
			my @backup = ( "Backup Server 1", "Backup Server 2", "Backup Server 3", "Backup Server 4", "Backup Server 5" );
			foreach ( @backup )
				{	my $server = $_;
					my $server_name = $properties{ $server };
					if ( ( $server_name )  &&  ( length( $server_name ) > 1 ) )
						{	# Clean up the server name
							$server_name =~ s/^http://;
							$server_name =~ s/^\/+//;
							next if ( ! $server_name );
							
							my $junk;
							( $server_name, $junk ) = split /\//, $server_name, 2;
							next if ( ! $server );
							
							$server_name = lc( $server_name );

							$email_backup = 1;
							push @backup_servers, $server_name;
						}
				}
			
			$email_backup = undef if ( ! $index_email );
				
			
			# Should I look for IM?
			if ( ( $archive_im )  &&  ( $archive_im eq "\x01\x00\x00\x00" ) )
				{	&IndexDirection( "Instant Message" );
					&IndexInstantMessages( $email_backup );
				}
				
				
			# Should I check the queue directory for any internal mail?
			if ( ( $archive_internal )  &&  ( $archive_internal eq "\x01\x00\x00\x00" ) )
				{	my $queue_dir = $properties{ "Queue Directory" };
					
					&PackUtilBuildDirectory( $queue_dir ) if ( $queue_dir );
					
					if ( -d $queue_dir )
						{	&lprint( "Indexing internal email ...\n" );
							&IndexDirection( "Internal" );
							&IndexDir( $queue_dir, undef, $email_backup, 1, undef );
						}
				}


			# Should I check for backed up email?
			if ( &ArchiveBackupFiles() )
				{	my $queue_dir = $properties{ "Queue Directory" };
					my $queue_backup_dir = "$queue_dir\\Backup";
					&PackUtilBuildDirectory( $queue_backup_dir );
					
					if ( -d $queue_backup_dir )
						{	&lprint( "Indexing backed up internal email ...\n" );
							&IndexDir( $queue_backup_dir, undef, undef, 1, undef );
						}
				}
				
				
			# Should I look for incoming mail?
			if ( ( $archive_incoming )  &&  ( $archive_incoming eq "\x01\x00\x00\x00" ) )
				{	&IndexDirection( "Incoming" );
					&IndexIncoming( $email_backup );
				}
				
				
			# Should I look for outgoing mail?
			if ( ( $archive_outgoing )  &&  ( $archive_outgoing eq "\x01\x00\x00\x00" ) )
				{	&IndexDirection( "Outgoing" );
					&IndexOutgoing( $email_backup );
				}
		}
		
		
	chdir( $cwd );
	
	
	&IndexStop();
	&PackStop();
	
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
#
sub CheckMonth( $ )
#
#  Return the month if it is in the YYYYMM format, or undef if not
#
################################################################################
{	my $month = shift;
					
	return( undef ) if ( ! $month );
	
	$month =~ s/^\s+//;
	$month =~ s/\s+$//;
	
	my $ok = 1;

	$ok = undef if ( length( $month ) != 6 );
	$ok = undef if ( $month =~ m/\D/ );

	my $mon_str = substr( $month, 4, 2 ) if ( $ok );
	
	if ( ( $ok )  &&  ( $mon_str < "01" ) )
		{	$ok = undef;
		}
	if ( ( $ok )  &&  ( $mon_str > "12" ) )
		{	$ok = undef;
		}
		
	if ( ! $ok )
		{	&lprint( "The specified month for reindexing in not in the format YYYYMM: $month\n" );
			return( undef );	
		}

	return( $month );
}



################################################################################
#
sub IndexInstantMessages( $ )
#
#  Index any IM stored in the database
#
################################################################################
{	my $email_backup = shift;
	
	&lprint( "Indexing instant messages ...\n" );

	my $dbhStat = &PackSqlConnectStatistics();
	
	return( undef ) if ( ! $dbhStat );
	
	# If the table doesn't exist, bail out
	if ( ! &PackSqlStatTableExists( "TrafficClassInstantMsg" ) )
		{	&PackSqlCloseStatistics();
			return( undef );	
		}
	
	my $last_time = &GetLastTime( "Mail Instant Messaging" );
	my $next_time = $last_time;
	
	my ( $last_date, $last_msg_from, $last_msg_to ) = split /\t/, $last_time if ( $last_time );


	$dbhStat = &PackSqlErrorCheckHandle( $dbhStat );
	return( undef ) if ( ! $dbhStat );
	return( undef ) if ( $dbhStat->err );
	
	
	# Get any new instant messages
    my $str = "select [Time], MsgFrom, MsgTo, MsgText from TrafficClassInstantMsg where [Time] > \'$last_date\' order by [Time]" if ( $last_date );
    $str = "select [Time], MsgFrom, MsgTo, MsgText from TrafficClassInstantMsg order by [Time]" if ( ! $last_date );
	
    my $sth = $dbhStat->prepare( $str );
    $sth->execute();
	
	
	my $tmp_dir = &TmpDirectory();
	
	
	# Get each new instant message in the database 
	&lprint( "Indexing new instant messages since $last_date\n" ) if ( $last_date );
	&lprint( "Indexing new instant messages\n" ) if ( ! $last_date );
	
	my $counter = 0 + 0;
	while ( my ( $time, $msg_from, $msg_to, $msg_text ) = $sth->fetchrow_array() )
		{	next if ( ! $time );
			next if ( ! $msg_from );
			next if ( ! $msg_to );
			next if ( ! $msg_to );
			next if ( ! $msg_text );
			
			
			# Is this a repeat of the last message I indexed?
			if ( ( $last_date )  &&  ( $last_msg_from )  &&  ( $last_msg_to ) )
				{	next if ( ( $last_date eq $time )  &&
							  ( $last_msg_from eq $msg_from )  &&
							  ( $last_msg_to eq $msg_to ) );
				}
				
				
			$next_time = "$time\t$msg_from\t$msg_to";
			
			$counter++;
			&lprint( "Indexing IM # $counter: $time FROM: $msg_from, TO: $msg_to ...\n" );


			# Add all the message data into one data string
			my $data = "TIME:$time\n";
			$data .= "FROM:$msg_from\n";
			$data .= "TO:$msg_to\n";
			$data .= "MESSAGE:$msg_text";
			
			
			# Create a temporary file for this message
			my $file = $tmp_dir . "\\IpmArchiveTmp.IM";
			if ( ! open( IMFILE, ">$file" ) )
				{	&lprint( "Error opening file $file: $!\n" );
					return( undef );
				}

			print IMFILE $data;			
			close( IMFILE );
			
			
			# Rename the file to it's fileID name so that it is unique
			my $file_id = &PackUtilFileID( $file );
			next if ( ! $file_id );
			
			my $hex_file_id = &PackFileHexFileID( $file_id );
			my $fullfile = $tmp_dir . "\\$hex_file_id.IM";
			my $ok = rename( $file, $fullfile );
			if ( ! $ok )
				{	&lprint( "Error renaming file $file to $fullfile: $!\n" );
					return( undef );
				}
			
			&lprint( "Created temporary IM file $fullfile ...\n" );
			
			
			my $docid = &IndexTextMessage( $fullfile );
			
			
			# Did I have a problem indexing?  The docid may be null if I've already indexed this message, or
			# it could be null because I had a problem
			if ( ! $docid )
				{	my $last_err = &IndexLastError();
					&lprint( "$last_err\n" ) if ( defined $last_err );
					last if ( defined $last_err );
					$ok = undef;
				}
				
			# Should I copy the file to the backup Queue?
			if ( ( $docid )  &&  ( $email_backup ) )
				{	&BackupQueue( $fullfile );
				}
				
			# Now delete the temporary IM file
			unlink( $fullfile );
		}
		
		
	&PackSqlErrorHandler( $dbhStat );
	$sth->finish();
	
	return( undef ) if ( ! $dbhStat );
	return( undef ) if ( $dbhStat->err );

	&SetLastTime( "Mail Instant Messaging", $next_time ) if ( ( $next_time )  &&  ( $next_time gt $last_time ) );

	&PackSqlCloseStatistics();
	
	return( 1 );
}



################################################################################
#
sub IndexIncoming( $ )
#
#  Index any incoming mail
#
################################################################################
{	my $email_backup = shift;
	
	&lprint( "Indexing incoming mail ...\n" );
	
	my $archive_dir = &GetArchiveDirectory();
	if ( ! $archive_dir )
		{	&lprint( "Unable to find the spam mail blocker archive directory\n" );
			return( undef );
		}

	&PackUtilBuildDirectory( $archive_dir );
	
	if ( ! -d $archive_dir )
		{	&lprint( "Spam mail blocker archive directory $archive_dir does not exist\n" );
			return( undef );
		}
		

	my $last_time = &GetLastTime( "Mail Incoming Time" );
	my $next_time = $last_time;
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $last_time );
	$year = 1900 + $year;
	$mon = $mon + 1;
	
	my $last_dir = sprintf( "%04d%02d%02d", $year, $mon, $mday );
	
	return( undef ) if ( ! opendir( ARCHIVE_DIR, $archive_dir ) );
	
	while ( my $dir = readdir( ARCHIVE_DIR ) )
		{	my $full_dir = "$archive_dir\\$dir";
			
			next if ( ! -d $full_dir );
			
			# If the length of the directory != 8, then it isn't an incoming archive directory
			next if ( length( $dir ) != 8 );
			
			# If the directory names contain characters, then it isn't an incoming archive directory
			next if ( $dir =~ m/\D/ );
			
			# Have I already indexed this directory?
			next if ( $dir lt $last_dir );
			
			my $time = &IndexDir( $full_dir, $last_time, $email_backup, undef, "h" );
			$next_time = $time if ( $time > $next_time );
		}
		
	close( ARCHIVE_DIR );
	
	&SetLastTime( "Mail Incoming Time", $next_time ) if ( ( $next_time )  && ( $next_time > $last_time ) );

	# If there isn't any last time, use the current time
	if ( ( ! $last_time )  &&  ( ! $next_time ) )
		{	my $time = time();
			&SetLastTime( "Mail Incoming Time", $time );
		}
		
	return( 1 );
}



################################################################################
#
sub IndexOutgoing( $ )
#
#  Index any outgoing mail
#
################################################################################
{	my $email_backup = shift;
	
	&lprint( "Indexing outgoing mail ...\n" );
	
	my $archive_dir = &GetArchiveDirectory();
	if ( ! $archive_dir )
		{	&lprint( "Unable to find the email archive directory\n" );
			return( undef );
		}
		
	&PackUtilBuildDirectory( $archive_dir );
	
	if ( ! -d $archive_dir )
		{	&lprint( "Spam mail blocker email $archive_dir does not exist\n" );
			return( undef );
		}
		

	my $last_time = &GetLastTime( "Mail Outgoing Time" );
	my $next_time = $last_time;
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $last_time );
	$year = 1900 + $year;
	$mon = $mon + 1;
	
	my $last_dir = sprintf( "%04d%02d%02d", $year, $mon, $mday );
	
	return( undef ) if ( ! opendir( ARCHIVE_DIR, $archive_dir ) );
	
	while ( my $dir = readdir( ARCHIVE_DIR ) )
		{	my $full_dir = "$archive_dir\\$dir";
			
			next if ( ! -d $full_dir );
			
			# If the length of the directory != 8, then it isn't an incoming archive directory
			next if ( length( $dir ) != 8 );
			
			# If the directory names contain characters, then it isn't an incoming archive directory
			next if ( $dir =~ m/\D/ );
			
			# Have I already indexed this directory?
			next if ( $dir lt $last_dir );

			my $time = &IndexDir( $full_dir, $last_time, $email_backup, undef, "o" );
			$next_time = $time if ( $time > $next_time );
		}
		
	close( ARCHIVE_DIR );
	
	&SetLastTime( "Mail Outgoing Time", $next_time ) if ( ( $next_time )  &&  ( $next_time > $last_time ) );

	# If there isn't any last time, use the current time
	if ( ( ! $last_time )  &&  ( ! $next_time ) )
		{	my $time = time();
			&SetLastTime( "Mail Outgoing Time", $time );
		}
		
	return( 1 );
}



################################################################################
#
sub IndexDir( $$$$$ )
#
#  Index all the files in a directory - return the time of the oldest file indexed
#  if everything went OK
#
################################################################################
{	my $dir				= shift;	# The directory to archive
	my $exceed_time		= shift;	# If set, only index files that are the same or newer than this
	my $email_backup	= shift;	# True if I should copy the files to the backup queue
	my $delete			= shift;	# True if I should delete the original file after archiving and backing it up
	my $first_letter	= shift;	# If set, this is the first letter of matching file - usually "h" or "o"
	
	
	return( undef ) if ( ! $dir );
	return( undef ) if ( ! -d $dir );
	
	&lprint( "Indexing and archiving directory $dir ...\n" );
			
	# Process the directory
	return( undef ) if ( ! opendir( DIR, $dir ) );
	
	my $last_mtime = 0 + 0;
	$last_mtime = $exceed_time if ( $exceed_time );
	
	my $file_counter = 0 + 0;
	my @allfiles = readdir( DIR );
	foreach ( @allfiles )
		{	my $file = $_;
			next if ( ! defined $file );
			
			# Skip metadata files ...
			next if ( $file =~ m/\.metadata$/i );

			my $fullfile = "$dir\\$file";
			
			# Skip subdirectories ...
			next if ( -d $fullfile );

			# Next empty files ...
			next if ( ! -s $fullfile );
			
			my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $fullfile;
			
			# Is this file too old?		
			next if ( ( $exceed_time )  &&  ( $mtime )  &&  ( $mtime < $exceed_time ) );								
					
			# Keep track of the newest time found
			$last_mtime = $mtime if ( ( $mtime )  &&  ( $mtime > $last_mtime ) );
					
			my $docid;
			my $metafile;
			
			# Is the file an IM file?
			if ( $file =~ m/\.IM$/i )
				{	$file_counter++;
					&lprint( "Indexing # $file_counter: $file ...\n" );
					
					$docid = &IndexTextMessage( $fullfile );
					my $last_err = &IndexLastError();
					&lprint( "$last_err\n" ) if ( ( ! $docid )  &&  ( defined $last_err ) );
				}
			else	# Is it an email file?
				{	# Skip spam files
					next if ( ( $file =~ m/^s/i )  &&  ( $file =~ m/\.txt$/i ) );
					
					# Skip virus files
					next if ( ( $file =~ m/^v/i )  &&  ( $file =~ m/\.txt$/i ) );
					
					# Skip temp files
					next if ( ( $file =~ m/^x/i )  &&  ( $file =~ m/\.txt$/i ) );
					
					# Do I need to match the first letter of the file?
					if ( $first_letter )
						{	next if ( ! ( $file =~ m/^$first_letter/i ) );
						}

					$file_counter++;
					&lprint( "Indexing # $file_counter: $file ...\n" );
					
					$docid = &Index( $fullfile, undef, undef, undef, undef );
					my $last_err = &IndexLastError();
					&lprint( "$last_err\n" ) if ( ( ! $docid )  &&  ( defined $last_err ) );
					
					# Figure out if there is a metadata file associated with this email
					$metafile = &PackUtilMetaData( $fullfile );
				}
				
			
			# Should I copy the file and the metadata file to the backup Queue?
			if ( ( $docid )  &&  ( $email_backup ) )
				{	&BackupQueue( $metafile ) if ( $metafile );
					&BackupQueue( $fullfile );
				}
				
				
			# Should I delete the file and the metadata file?
			if ( $delete )
				{	unlink( $fullfile ) if ( $fullfile );
					unlink( $metafile ) if ( $metafile );
				}
		}

	close( DIR );
	
	return( $last_mtime );
}



################################################################################
# 
sub BackupQueue( $ )
#
#  Given a filename, copy it to all of the backup queues
#  Return undef if any problems
#
################################################################################
{	my $fullfile = shift;
	
	next if ( ! $fullfile );
	
	my ( $file_dir, $short_file  ) = &SplitFileName( $fullfile );
	my $queue_dir = $properties{ "Queue Directory" };
	
	return( undef ) if ( ! $queue_dir );
	&PackUtilBuildDirectory( $queue_dir );
	return( undef ) if ( ! -d $queue_dir );
	
	&PackUtilBuildDirectory( "$queue_dir\\Backup" );
	
	foreach ( @backup_servers )
		{	my $server = $_;
			next if ( ! $server );
			
			# Don't copy file to a server named "backup" - this will cause real problems
			next if ( $server eq "backup" );
			
			my $dir = "$queue_dir\\$server";
			
			&PackUtilBuildDirectory( $dir );
			if ( ! -d $dir )
				{	&lprint( "Error creating directory $dir\n" );
					next;
				}
				
			my $backup_file = "$dir\\$short_file";
			
			my $ok = copy( $fullfile, $backup_file );
			
			&lprint( "Error copying $fullfile to $backup_file: $!\n" ) if ( ! $ok );
		}
		
	return( 1 );
}



################################################################################
# 
sub GetArchiveDirectory()
#
#  Return the directory containing incoming email messages
#  Return undef if any problems
#
################################################################################
{	my $key;
	my $type;
	my $data;


	# If I didn't find an archive directory, then default it
	my $archive_path = &SoftwareDirectory() . "\\Mail Archive";
	
	#  First get the current config number
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations", 0, KEY_READ, $key );

	return( $archive_path ) if ( !$ok );
	$ok = &RegQueryValueEx( $key, "Current", [], $type, $data, [] );
	return( $archive_path ) if ( ! $ok );   
	
	&RegCloseKey( $key );
	return( $archive_path ) if ( ! length( $data ) );
	
	my $current = &HexToInt( $data );

	my $current_key = sprintf( "%05u", $current );

	my $subkey;
	my $counter;
	
	
	#  Next go through the current config looking for a Spam Mail Blocker object
	for ( my $i = 1;  $i < 100;  $i++ )
		{	$counter = sprintf( "%05u", $i );

			$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter";

			$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
			next if ( !$ok );  

			$ok = &RegQueryValueEx( $key, "ProgID", [], $type, $data, [] );  # Blank is the (Default) value

			&RegCloseKey( $key );
			
			next if ( ! length( $data ) );
			
			next if ( ! $data );

			last if ( $data =~ m/SpamMailBlockerSvc/ );         
		}

	return( $archive_path ) if ( ! $data =~ m/SpamMailBlockerSvc/ ); 


	# At this point I've got a spam blocker object in this config
	$subkey = "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\$current_key\\$counter\\Dynamic Properties";

	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, $subkey, 0, KEY_READ, $key );
	return( undef ) if ( !$ok );  


	$ok = &RegQueryValueEx( $key, "Archive Path", [], $type, $data, [] );
	$archive_path = $data if ( ( $ok )  &&  ( length( $data ) ) );
	
	$archive_path =~ s/\//\\/g;		# Flip slashes to backslashes
	$archive_path =~ s/\\+$//;		# Trim off any trailing backslashes
			

	# I'm done with this key so close it
	&RegCloseKey( $key );


	return( $archive_path );
}



################################################################################
# 
sub ArchiveBackupFiles( $ )
#
#  Return True if there are backup email files to be archived
#
################################################################################
{	my $queue_dir = $properties{ "Queue Directory" };
	
	return( undef ) if ( ! $queue_dir );
	
	my $queue_backup_dir = "$queue_dir\\Backup";

	return( undef ) if ( ! -d  $queue_backup_dir );
	
	return( undef ) if ( ! opendir( BACKUP_DIR, $queue_backup_dir ) );
	
	my $exists;
	while ( my $file = readdir( BACKUP_DIR ) )
		{	my $full_file = "$queue_backup_dir\\$file";
			
			# Ignore directories
			next if ( -d $full_file );
			
			$exists = 1;
			last;
		}
		
	closedir( BACKUP_DIR );
	
	return( $exists );
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
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = &SoftwareDirectory() . "\\IpmArchiveErrors.log";
	my $MYLOG;

	my $mode = ">";
	$mode = ">>" if ( $opt_log_continuous );
	
	if ( ! open( $MYLOG, "$mode$filename" ) )
		{	print( "Unable to open $filename for error logging: $!\n" ); 
			return;
		}
		
	&CarpOut( $MYLOG );
   
	print( "Error logging set to $filename\n" ); 
}



################################################################################
#
sub GetLastTime( $ )
#
#  Return the last time that I indexed an incoming document
#
################################################################################
{	my $valname = shift;
	
	my $key;
	my $type;
	my $data;
	
	#  Open the main registry key
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\Mail Archive", 0, KEY_READ, $key );

	return( 0 + 0 ) if ( ! $key );
	
	$ok = &RegQueryValueEx( $key, $valname, [], $type, $data, [] );
	
	&RegCloseKey( $key );

	return( 0 + 0 ) if ( ! $ok );
	return( 0 + 0 ) if ( ! length( $data ) );

	return( $data );
}



################################################################################
#
sub SetLastTime( $$ )
#
#  Set the last time that I indexed an incoming document
#
################################################################################
{	my $valname		= shift;
	my $last_time	= shift;
	
	my $key;
	my $type;
	my $data;
	
	#  Open the main registry key
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\Mail Archive", 0, KEY_ALL_ACCESS, $key );

	return( undef ) if ( ! $key );
	
	$ok = &RegSetValueEx( $key, $valname, 0,  REG_SZ, $last_time );
	
	&RegCloseKey( $key );

	return( $ok );	
}



################################################################################
#
sub Reindex( $ )
#
#  Go through all the packed files and reindex all the documents
#
################################################################################
{	my $index_subdir = shift;		# If this is set then just reindex a single subdir

	$index_subdir =~ s/^\s+// if ( defined $index_subdir );
	$index_subdir =~ s/\s+$// if ( defined $index_subdir );


	my $root = &PackUtilDirRoot();
	
	my $last_err = &PackLastError() if ( ! $root );

	if ( defined $last_err )
		{	&lprint( "$last_err\n" );
			return( undef );
		}	

	if ( ! defined $root )
		{	&lprint( "Unable to find the root directory of the archive\n" );
			return( undef );
		}
		
	my $reindex_dir = $root;
	$reindex_dir = $root . "\\" . $index_subdir if ( defined $index_subdir );
	
	
	# Can I find the directory that I am looking for?
	if ( ! -d $reindex_dir )
		{	&lprint( "Unable to find the reindex directory $reindex_dir\n" );
			return( undef );
		}
	
	
	&lprint( "Reindexing packed archive files from directory $reindex_dir ...\n" );
	if ( ! opendir( REINDEX_DIR, $reindex_dir ) )
		{	&lprint( "Error opening directory $reindex_dir: $!\n" );
			return( undef );
		}
	
	my $tmp_dir = &SoftwareDirectory() . "\\Mail Archive\\tmp";
	mkdir( $tmp_dir );
	
	if ( ! -d $tmp_dir )
		{	&lprint( "Unable to find tmp directory $tmp_dir\n" );
			return( undef );
		}

	
	my $total = 0 + 0;
	while ( my $dir = readdir( REINDEX_DIR ) )
		{	next if ( ! defined $dir );
			next if ( $dir eq "." );
			next if ( $dir eq ".." );
			
			my $full_dir = "$reindex_dir\\$dir";
			
			# Could this file be an archive file?
			if ( ! -d $full_dir )
				{	my $packfile = $full_dir;
					
					next if ( ! ( $packfile =~ m/\.dat$/ ) );
					
					my ( $ok, $count ) = &UnpackIndex( $packfile, $tmp_dir );
					$total += $count if ( defined $count );
					
					next;
				}
			
			next if ( ! opendir( SUBDIR, $full_dir ) );

			
			# Could this dir be before my starting directory?
			next if ( ( $opt_start )  &&  ( $dir lt $opt_start ) );

			
			# Could this dir be after my ending directory?
			next if ( ( $opt_end )  &&  ( $dir gt $opt_end ) );


			# If I got to here then this is a subdirectory that I want to reindex
			while ( my $subdir = readdir( SUBDIR ) )
				{	next if ( ! defined $subdir );
					next if ( $subdir eq "." );
					next if ( $subdir eq ".." );
					
					my $packfile = "$full_dir\\$subdir";
					
					next if ( -d $packfile );
					next if ( ! ( $packfile =~ m/\.dat$/ ) );
					
					my ( $ok, $count ) = &UnpackIndex( $packfile, $tmp_dir );
					$total += $count if ( defined $count );
				}
				
			closedir( SUBDIR );
		}
		
	closedir( REINDEX_DIR );
	
	&lprint( "Unpacked and indexed $total files\n" );
			
	return( 1 );
}



################################################################################
#
sub UnpackIndex( $$ )
#
#  Given an archive file, unpack and Index all the files within it
#
################################################################################
{	my $packfile	= shift;
	my $dir			= shift;
	
	&lprint( "Unpacking and reindexing all the files from Lightspeed Archive file $packfile ...\n" );

	my $offset = 0 + 6;
	
	my $size = -s $packfile;
	my $count = 0 + 0;
	my $ok;
	my $ending_offset;
	my $last_err = &PackLastError();
	my $extract_file;
	
	while ( ( ! $last_err )  &&  ( $offset < $size ) )
		{	( $ok, $ending_offset, $extract_file ) = &UnpackOffset( $packfile, $offset, $dir, $opt_debug, $opt_verbose );
			
			if ( ! $ok )
				{	$last_err = &PackLastError();
					&lprint( "Error unpacking $packfile: $last_err\n" ) if ( $last_err );
					&lprint( "Error unpacking $packfile\n" ) if ( ! $last_err );
					
					# Just clear the error and go on ...
					&PackClearLastError();
				}
			
			
			# If I didn't get an extract file then just move on
			if ( ! defined $extract_file )
				{	last if ( ! $ending_offset );
					
					# Update the offset to the next file's offset
					$offset = $ending_offset;

					next;
				}
				
				
			my $fileid = &PackUtilFileID( $extract_file );
			
			&lprint( "Reindexing $extract_file ...\n" );
			my $docid = &Index( $extract_file, undef, $packfile, $offset, $fileid );
			
			# Figure out if there is a metadata file associated with this email
			my $metafile = &PackUtilMetaData( $extract_file );
			
			
			# Delete the files that I just extracted
			unlink( $extract_file );
			unlink( $metafile ) if ( defined $metafile );
			
			
			# Now add the file location into SQL if I got a docid
			if ( defined $docid )
				{	my ( $file_dir, $short_file  ) = &SplitFileName( $packfile );
					$ok = &PackSQLSetLocation( $short_file, $offset, $fileid );
					if ( ! $ok )
						{	$last_err = &PackLastError();
							&lprint( "Error adding the location for DocID $docid in packfile $packfile: $last_err\n" ) if ( $last_err );
							&lprint( "Error adding the location for DocID $docid in packfile $packfile\n" ) if ( ! $last_err );
					
							# Just clear the error and go on ...
							&PackClearLastError();
						}
				}
				

			# Update the offset to the next file's offset
			$offset = $ending_offset;
			
			# Keep count of how many I've done
			$count++ if ( $docid );
		}
	
	&lprint( "Unpacked and reindexed $count files from $packfile\n" );
	
	return( $ok, $count );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmArchive";

    print <<".";
Usage: $me [OPTION(s)]
IpmArchive indexes and archives emails and documents.
In normal operation it indexes and archives files in the Mail Archive directory.
All MONTHs are specified in the format YYYYMM.  	

 -d, --dir DIR         Just index everything in directory DIR
 -e, --end ENDMONTH    Reindex ending with month ENDMONTH
 -f, --file FILE       Just index a single file called FILE
 -l, --logging         Append to existing IpmArchive logs
 -m, --month MONTH     Reindex a single month of packed files
                       You can also enter multiple month separated by commas,
                       i.e. 200612,200701,200702
 -r, --reindex         Reindex all the packed files in the archive directory
 -s, --start STARTMON  Reindex from starting month STARTMON 

 -h, --help            display this help and exit
 -v, --version         display version information and exit
  
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
    my $me = "IpmArchive";

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

