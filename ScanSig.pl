################################################################################
#!perl -w
#
# Rob McCarthy's Virus Scanner Signature source code
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use Content::File;
use Content::ScanUtil;
use Content::ScanMD5;
use Content::ScanFile;
use Content::FileIntegrity;
use Content::FileID;
use Content::SQL;
use Getopt::Long();
use DBI qw(:sql_types);
use DBD::ODBC;



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_wizard;				# True if I shouldn't display headers or footers
my $opt_signature;			# If set, add the virus signature number into the database
my $opt_database;			# True if I should dump out of the database to the the virus signatures file
my $opt_insert;				# True if I should insert the virus signatures file into the database
my $opt_category_num = 0 + 64;	# Category number to use for virus signature
my $opt_category;			# Category name if changing from the default category
my $opt_errors;				# If True, take any discovered viruses in the scan log and change their category in the database to errors
my $opt_text;				# If True, create a text file version of the file integrity file
my $opt_recent;				# If set, only dump virus signatures that are recent
my $opt_source = 0 + 2;		# The source number to use for database inserts


my $tmp_dir;
my $virus_name;				# The virus name to use if creating a signature
my $dbh;					# My database handle
my $_version = '1.00.00';
my $file_no = 0 + 0;		# This is the number of the current file that I am checking
my $test_file_no = 0 + 0;	# This is the number of the file to get the sig out and put into the database



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
			"c|category=s"	=> \$opt_category,
			"d|database"	=> \$opt_database,
			"e|errors"		=> \$opt_errors,
			"f|fileno=s"	=> \$test_file_no,
			"i|insert"		=> \$opt_insert,
			"n|name=s"		=> \$virus_name,
			"m|sig=i"		=> \$opt_signature,
			"r|recent"		=> \$opt_recent,
			"s|source=i"	=> \$opt_source,
			"w|wizard"		=> \$opt_wizard,
			"h|help"		=> \$opt_help,
			"x|xxx"			=> \$opt_debug
       )or die( Usage() );


	&StdHeader( "Lightspeed Virus Scanner Signature utility" ) if ( ! $opt_wizard );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	
	if ( ( $opt_signature )  &&  ( ! $virus_name ) )
		{	print "You have to supply a virus name with the -n switch\n";
			exit( 1 );
		}
		
	
	if ( ( $opt_source < 1 )  ||  ( $opt_source > 1000 ) )
		{	print "$opt_source is not a valid source number\n";
			exit( 1 );
		}
		
	print "Using source $opt_source for all database inserts ...\n";
	
	print "Debugging mode\n" if ( $opt_debug );
	
	$tmp_dir = &TmpDirectory();
	
	my $date;
	if ( $opt_recent )
		{	my $recent_time = time - ( 1 * 7 * 24 * 60 * 60 );
			my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $recent_time );
			$year = 1900 + $year;
			$mon = $mon + 1;
			$date = sprintf( "%04d-%02d-%02d 00:00:00.000", $year, $mon, $mday );
			
			print "Dumping virus signatures newer than $date\n";
			$opt_database = 1;
		}
		
	my $errnum = 0 + 7;
	
	if ( $opt_text )	# Dump the File Integrity file to a text file
		{	#  Open the database
			my ( $count, $msg ) = DumpFileIntegrity( $opt_text );
			if ( ! $count )
				{	print "Error dumping the File Integrity database: $msg\n";
					exit( 0 );
				}
		 	
			print "Dumped $count file integrity IDs to $opt_text\n";
			
			exit;
		}
	

	if ( $opt_database )	# Get the list of active virus signatures and file IDs out of the Content database
		{	#  Open the database
			$dbh = &ConnectServer() or die "Can not connect to the Content database\n";
			&LoadCategories();
			$errnum = &ErrorsCategory();
	
			# Bail out if I couldn't read the categories correctly
			die "Can not read the categories correctly\n" if ( ! $errnum );
	
			# Am I setting the category?
			if ( $opt_category )
				{	$opt_category = lc( $opt_category );
					my $catnum = &CategoryNumber( $opt_category );
					die "Can not find category number for category name $opt_category" if ( ! $catnum );
					$opt_category_num = $catnum;
				}
			else
				{	$opt_category_num = undef;
				}

			my $count = &DatabaseDumpVirusSignatures( $dbh, $date, $opt_category_num );
			
			my $signature_file = &ScanSignatureFile(); 				
			print "Dumped $count signatures to $signature_file\n";
			
			# If there are no virus signatures at all, then delete the file
			if ( ! $count )
				{	print "No virus signatures, so deleting $signature_file ...\n";
					unlink( $signature_file );	
				}

			my $md5_changed = &ScanMD5WriteSignatureFiles( undef, 1 );
			
			print "Dumping File IDs ...\n";
			$count = &DatabaseDumpFileIDs( $dbh, $errnum ) or die "Could not load any file IDs from the content database\n";

			my $id_file = &FileIDFilename();
			print "Dumped $count file IDs to $id_file\n";
			
			#  At this point, I'm done with the database, so clean up everything
			$dbh->disconnect if ( $dbh );		 				
			&StdFooter();
			exit;
		}
	
	
	if ( $opt_errors )	# Get the list of active virus signatures and file IDs out of the Content database
		{	#  Open the database
			$dbh = &ConnectServer() or die "Can not connect to the Content database\n";
			&LoadCategories();
			$errnum = &ErrorsCategory();
	
			&ScanDatabaseVirusErrors( $dbh, $errnum );
			
			#  At this point, I'm done with the database, so clean up everything
			$dbh->disconnect;		 				
			&StdFooter();
			exit;
		}
	
	
	if ( $opt_insert )	# Insert the active virus signatures into the Content database
		{	#  Open the database
			$dbh = &ConnectServer() or die "Can not connect to the Content database\n";
				
			&LoadCategories();
			$errnum = &ErrorsCategory();

			# Am I setting the category?
			if ( $opt_category )
				{	$opt_category = lc( $opt_category );
					my $catnum = &CategoryNumber( $opt_category );
					die "Can not find category number for category name $opt_category" if ( ! $catnum );
					
					$opt_category_num = 0 + $catnum;
					print "Using category $opt_category, category number $opt_category_num ...\n";
				}
				
			my $custom_signature_file = &ScanCustomSignatureFile();

			if ( ! open( FILE, "<$custom_signature_file" ) )
				{	print "No custom virus signature defined\n";
				}
			else
				{	print "Inserting virus signatures from $custom_signature_file into the database ...\n";
					my $insert_count = 0 + 0;
					while ( my $line = <FILE> )
						{	chomp( $line );
							next if ( ! $line );
							
							my ( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = split /\t/, $line, 8;

							$delete = "0" if ( ! $delete );
							$delete = "0" if ( $delete ne "1" );
							
							$virus_name = &CleanVirusName( $virus_name );
							next if ( ! defined $virus_name );
							next if ( ! defined $virus_type );
							next if ( ! defined $category_number );
							
							$sigstart = 0 + $sigstart;
							$sigend = 0 + $sigend;
							
							# Make sure that the signature is not blank
							next if ( ! defined $signature );
							$signature =~ s/^\s+//;
							$signature =~ s/\s+$// if ( defined $signature );
							next if ( ! defined $signature );
							
							my $ok = &ScanDatabaseAddSignature( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, 1, $opt_category_num, $delete );
							$insert_count++ if ( $ok );
						}
						
					print "Inserted $insert_count custom virus signatures into the database\n";
					close( FILE );
				}
				
			#  At this point, I'm done with the database, so clean up everything
			$dbh->disconnect;		 				
			&StdFooter();
			exit;
		}
	
	
	if ( $opt_signature )
		{	#  Open the database
			$dbh = &ConnectServer() or die;
			&LoadCategories();
			$errnum = &ErrorsCategory();
			
			# Am I setting the category?
			if ( $opt_category )
				{	$opt_category = lc( $opt_category );
					my $catnum = &CategoryNumber( $opt_category );
					die "Can not find category number for category name $opt_category" if ( ! $catnum );
					$opt_category_num = $catnum;
				}
		}
		
	
	my $filename = shift;
	$virus_name = &CleanVirusName( $virus_name );
	
	if ( ! $filename )
		{	Usage();
		}
	elsif ( ! ( -e $filename ) )
		{	bprint "$filename does not exist\n";
		}
	else
		{	# Handle the 3 types of files
			if ( &ScanIsMessageFile( $filename ) )
				{	&ScanMessageSignature( $filename );					
				}
			elsif ( -T $filename )
				{	&ScanTextSignature( $filename, undef );					
				}
			else
				{	&ScanBinarySignature( $filename );
				}
		}
	
		
	#  Clean up everything and quit
	if ( $opt_signature )
		{	my $count = &DatabaseDumpVirusSignatures( $dbh, $date, undef );
			
			my $signature_file = &ScanSignatureFile(); 				
			print "Dumped $count signatures to $signature_file\n";
		}	
		
		
	&StdFooter() if ( ! $opt_wizard );

	exit;
}
###################    End of MAIN  ################################################



################################################################################
# 
sub ScanMessageSignature( $ )
#
#	Given a filename, print possible virus signatures
#	First print the filename, then the application signature
#   and then up to 4 different signatures
#
################################################################################
{	my $filename = shift;
	
	&debug( "ScanMessageSignature\n" );
	
	# First, look for any text virus signatures in the message file itself
	&ScanTextSignature( $filename, 1 );
	
	my @attachments = &ScanMessageAttachments( $filename, $tmp_dir, $opt_debug );

	my $count = 1 + $#attachments;
	print "Number of attachments = $count\n" if ( $opt_debug );

	foreach ( @attachments )
		{	my $attach_filename = $_;

			if ( ! ( -e $attach_filename ) )
				{	bprint "$attach_filename does not exist\n";
					next;
				}
				
			if ( -T $attach_filename )
				{	&ScanTextSignature( $attach_filename, undef );					
				}
			else
				{	&ScanBinarySignature( $attach_filename );
				}
			
			my $lc_name = lc( $attach_filename );
			
			if ( $lc_name =~ m/\.zip$/ )
				{	&ScanZipSignature( $attach_filename );
				}
				
			unlink( $attach_filename ) if ( ! $opt_debug );
		}
}



################################################################################
# 
sub ScanZipSignature( $ )
#
#	Given a zip filename, unpack it and look for signatures
#
################################################################################
{	my $zipfile = shift;
	
	my ( $err_msg, @files ) = &ScanUnzipFile( $tmp_dir, $zipfile );
	print "\n$err_msg\n" if ( $err_msg );
	
	my $count = 1 + $#files;
	print "Number of files inside zip file $zipfile = $count\n" if ( $opt_debug );

	foreach ( @files )
		{	my $zip_filename = $_;

			if ( ! ( -e $zip_filename ) )
				{	bprint "$zip_filename does not exist\n";
					next;
				}
				
			if ( -T $zip_filename )
				{	&ScanTextSignature( $zip_filename, undef );					
				}
			else
				{	&ScanBinarySignature( $zip_filename );
				}
			
			# Recursively unzip stuff
			my $lc_name = lc( $zip_filename );
			
			if ( $lc_name =~ m/\.zip$/ )
				{	&ScanZipSignature( $zip_filename );
				}
				
			unlink( $zip_filename ) if ( ! $opt_debug );
		}
}



################################################################################
# 
sub ScanTextSignature( $$ )
#
#	Given a filename, print possible virus signatures
#	First print the filename, then the application signature
#   and then up to 4 different signatures
#
################################################################################
{	my $filename = shift;
	my $message_file = shift;	# True if the file is a Lightspeed Message File
	
	print "Message File: $filename\n" if ( $message_file );


	# Is it uuencoded?
	my $uudecode = &UUDecode( $filename, 1 );	
	if ( $uudecode )
		{	print "UU Encoded file $filename\n";
			
			if ( ! ( -e $uudecode ) )
				{	bprint "$uudecode does not exist\n";
					next;
				}
				
			if ( -T $uudecode )
				{	&ScanTextSignature( $uudecode, undef );					
				}
			else
				{	&ScanBinarySignature( $uudecode );
				}
				
			return;
		}
		
	if ( !open( FILE, "<", $filename ) )
		{	print "Unable to open file $filename, $!\n";
			return;
		}
		
		
	
	my $script;
	my $buff;
	my $size = 0 + 10240;
	my $save;
	
	my $found;
	
	
	my $htmlvbs = "< *script +language *=[\"\' ]*vbs[^>]*>";
	my $htmljs = "< *script +language *=[\"\' ]*jscript[^>]*>";
	my $htmljsalt = "< *script *>";
	#my $htmljs = "< *script[^>]*(language *=[\"\' ]*jscript[\"\']*)*[^>]*>";
	#my $htmlend = "<\/script[^>]*>";
	my $htmlend = "<\/script>";
	
	my $counter = 0;
	my $lastpos = 0 - 1;
	while ( read( FILE, $buff, $size ) )
		{
			$save .= $buff;
			
			my $lc_save = lc( $save );
			# Have I started a script?
			
			
			if ( !$script ) 
				{	$script = "HTMLVBS" if ( $lc_save =~ m/$htmlvbs/os );
					if ( ! $script )
						{	$script = "HTMLJS" if ( $lc_save =~ m/$htmljs/os );
							$script = "HTMLJS" if ( $lc_save =~ m/$htmljsalt/os );
						}
						
					$lastpos = 0 - 1;
					
					if ( $script )
						{	$lastpos = pos $lc_save;
						}
				}


			if ( ( $script )  &&  ( $lastpos > -1 ) )
				{	my $end = index( $lc_save, $htmlend, $lastpos );
					
#print "script = $script\n" if ( $script );					
#print "end = $end\n";
#print "lastpos = $lastpos\n";
#print "lc_save = $lc_save\n";

					if ( $end > $lastpos )
						{	
							my $len = $end - $lastpos;
							
							my $sig = substr( $save, $lastpos, $len );
							
#print "sig = $sig\n";

							# Only get up to 4 sigs
							$counter++;
							return if ( $counter > 4 );
							
							# Print the signature data out
							$file_no++;
							print "\nFile Number: $file_no\n";
							print "Text File: $filename\n";
	
							print "appsig: $script\n";

							$found = 1;
							
							my $pos = 0;
							for ( my $i = 0;  $i < 4;  $i++ )
								{	next if ( length( $sig ) < $pos + 128 );
									next if ( $counter > 4 );
									
									my $smallsig = substr( $sig, $pos, 128 );
# print "smallsig = $smallsig\n";									
									my $hex = &StrToHex( $smallsig );
									print "sig$counter: 0 -1 $hex\n";

									&TestSignature( $counter, $virus_name, $script, 0, -1, $hex );
									
									$counter++;
									$pos += 128;
								}		
						}
				}

			# Have I reached the end of the script?
			if ( $script )
				{	$script = undef if $lc_save=~ m/$htmlend/s;
				}
				
			$save = substr( $buff, ( length( $buff ) / 2 ) );
		}

	print "No signatures found in $filename\n" if ( ! $found );
	
	close FILE;
}



################################################################################
# 
sub ScanBinarySignature( $ )
#
#	Given a filename, print possible virus signatures
#	First print the filename, then the application signature
#   and then up to 4 different signatures
#
################################################################################
{	my $filename = shift;
	
	$file_no++;
	
	print "\nFile Number: $file_no\n";
	print "Binary File: $filename\n";
	my $appsig = &ScanFileAppSignature( $filename );
	my $appsighex;
	
	if ( $appsig )
		{	$appsighex = &StrToHex( $appsig );
			print "appsig: $appsighex\n";
		}
	else
		{	$appsighex = "TEST";
			print "appsig: TEST\n";
		}
		
	my $hex;		
			
	my ( $sig, $sigstart, $sigend ) = &ScanFileSignature( $filename, 1024 );
	$hex = &StrToHex( $sig );
	print "sig1: $sigstart $sigend $hex\n" if ( $sig );
	&TestSignature( 1, $virus_name, $appsighex, $sigstart, $sigend, $hex ) if ( $sig );
	
	
	( $sig, $sigstart, $sigend ) = &ScanFileSignature( $filename, 2048 );
	$hex = &StrToHex( $sig );
	print "sig2: $sigstart $sigend $hex\n" if ( $sig );
	&TestSignature( 2, $virus_name, $appsighex, $sigstart, $sigend, $hex ) if ( $sig );
	
			
	( $sig, $sigstart, $sigend ) = &ScanFileSignature( $filename, 5120 );
	$hex = &StrToHex( $sig );
	print "sig3: $sigstart $sigend $hex\n" if ( $sig );
	&TestSignature( 3, $virus_name, $appsighex, $sigstart, $sigend, $hex ) if ( $sig );
	
			
	( $sig, $sigstart, $sigend ) = &ScanFileSignature( $filename, 10240 );
	$hex = &StrToHex( $sig );
	print "sig4: $sigstart $sigend $hex\n" if ( $sig );	
	&TestSignature( 4, $virus_name, $appsighex, $sigstart, $sigend, $hex ) if ( $sig );
	
	# Is this a zip file?
	&ScanZipSignature( $filename ) if ( $appsighex eq "504b0304" );
}




################################################################################
# 
sub ScanFileSignature( $$ )
#
#	Given a filename, and an offset, return the 64 byte signature at that location
#   also return the starting offset, and the ending offset to check
#
################################################################################
{	my $file = shift;
	my $offset = shift;
				
	open INPUT, "<$file" or &FatalError( "Unable to open file $file: $!\n" );
	binmode( INPUT );

	# Seek from the beginning of the file
	return( undef, 0, 0 ) if ( !seek( INPUT, $offset, 0 ) );
	
	# Read the the file for the signature
	my $sig;
	my $size = 0 + 64;
	if ( !read( INPUT, $sig, $size ) )
		{	close INPUT;
			return( undef, 0, 0 ) 
		}
	
	close INPUT;
	
	return( $sig, $offset, $offset + 1024 );
}



################################################################################
# 
sub TestSignature( $$$$$$ )
#
#	Add a signature to the database
#
################################################################################
{	my $signum = shift;
	my $name = shift;
	my $app_sig = shift;
	my $start_offset = shift;
	my $end_offset = shift;
	my $sig = shift;
	
	return if ( ! $opt_signature );
	
	$signum = 0 + $signum;
	$opt_signature = 0 + $opt_signature;
	
	# Am I supposed to add a signum to the database?
	return if ( $signum != $opt_signature );
	
	# Is this the right file number to add into the database?
	return if ( ( $test_file_no )  && ( $test_file_no != $file_no ) );
	
	$name = &CleanVirusName( $name );
	
	my $type = $app_sig;
	$type = "W32" if ( $app_sig =~ m/^4d5a/ );
	$type = "VBS" if ( $app_sig =~ m/VBS/ );
	$type = "JS" if ( $app_sig =~ m/JS/ );
	$type = "ZIP" if ( $app_sig =~ m/^504b0304/ );
	
	my $category_num = $opt_category_num;
	
	
	# Is this virus already in the database?
	# If so, prompt before overwriting it
	my $sth = $dbh->prepare( "SELECT VirusName FROM VirusSignatures WITH(NOLOCK) where VirusName = ?" );
	$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
	$sth->execute();
	my $existing_virus = $sth->fetchrow_array();

	$sth->finish();
	
	if ( $existing_virus )
		{	my $answer = &AnswerYorN( "\nOverwrite existing virus signature for $virus_name?" );
			
			if ( $answer ne "Y" )
				{	$opt_signature = undef;
					return( undef );
				}
		}
	
	
	# At this point, get rid of any existing virus definitions
	if ( $existing_virus )
		{	print "Deleting existing virus signature for $name ...\n";
	
			$sth = $dbh->prepare( "DELETE FROM VirusSignatures where VirusName = ?" );
			$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
			$sth->execute();
			$sth->finish();
		}
		
		
	my @values;
	
	push @values, "\'" . $name . "\',";				# 0 entry
	push @values, "\'" . $type . "\',";				# 1 entry
	push @values, "\'" . $app_sig . "\',";			# 2 entry
	push @values, "\'" . $start_offset . "\',";		# 3 entry
	push @values, "\'" . $end_offset . "\',";		# 4 entry
	push @values, "\'" . $sig . "\',";				# 5 entry
	push @values, "\'" . $category_num . "\',";		# 6 entry
	push @values, "\'" . $opt_source . "\'";		# 7 entry
	
	
	
	print "Adding virus $name to the database ...\n";
	my $str = "INSERT INTO VirusSignatures ( VirusName, VirusType, appsig, sigstart, sigend, signature, CategoryNumber, SourceNumber ) VALUES ( @values )";

	$sth = $dbh->prepare( $str );

	if ( ! $sth->execute() )
		{	print "Error inserting into database\n";
			print "Virus Name: $name, Type = $type, App Sig: $app_sig\n";
			print "Start Offset: $start_offset, End Offset = $end_offset\n";
			print "Sig: $sig\n\n";
			my $length = length( $sig );
			print "Sig length = $length\n";
		}
	
	print "\n";
	
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub ScanDatabaseAddSignature( $$$$$$$$$ )
#
#	Add a single signature to the database - delete an existing one if it has the
#   same name
#
################################################################################
{	my $name			= shift;
	my $type			= shift;
	my $app_sig			= shift;
	my $start_offset	= shift;
	my $end_offset		= shift;
	my $sig				= shift;
	my $overwrite		= shift;
	my $category_num	= shift;
	my $delete			= shift;
		

	$delete = "0" if ( ! $delete );
	$delete = "0" if ( $delete ne "1" );
	
	
	my $sth;
	# Is this virus already in the database?
	if ( $overwrite )	# If so, get rid of it
		{	$sth = $dbh->prepare( "DELETE FROM VirusSignatures where VirusName = ?" );
			$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
			$sth->execute();
			$sth->finish();
		}
	else	# If it is already there, don't overwrite it - unless it is in the errors category
		{	$sth = $dbh->prepare( "SELECT VirusName, CategoryNumber FROM VirusSignatures WITH(NOLOCK) where VirusName = ?" );
			$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
			$sth->execute();
			my ( $existing_virus, $existing_category_num ) = $sth->fetchrow_array();

			$sth->finish();
			
			$existing_category_num = 0 + $existing_category_num if ( $existing_virus );
			
			# Does it exist, and isn't in the errors category?
			return( undef ) if ( ( $existing_virus )  &&  ( $existing_category_num != 7 ) );
			
			# Delete it if it is in the errors category
			if ( $existing_virus )
				{	$sth = $dbh->prepare( "DELETE FROM VirusSignatures where VirusName = ?" );
					$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
					$sth->execute();
					$sth->finish();	
				}
		}
		
		
	my @values;
	
	push @values, "\'" . $name . "\',";				# 0 entry
	push @values, "\'" . $type . "\',";				# 1 entry
	push @values, "\'" . $app_sig . "\',";			# 2 entry
	push @values, "\'" . $start_offset . "\',";		# 3 entry
	push @values, "\'" . $end_offset . "\',";		# 4 entry
	push @values, "\'" . $sig . "\',";				# 5 entry
	push @values, "\'" . $category_num . "\',";		# 6 entry
	push @values, "\'" . $opt_source . "\',";		# 7 entry
	push @values, "\'" . $delete . "\'";			# 8 entry
	
	
	my $str = "INSERT INTO VirusSignatures ( VirusName, VirusType, appsig, sigstart, sigend, signature, CategoryNumber, SourceNumber, Test ) VALUES ( @values )";

	$sth = $dbh->prepare( $str );

	if ( ! $sth->execute() )
		{	print "Error inserting into database\n";
			print "Virus Name: $name, Type = $type, App Sig: $app_sig\n";
			print "Start Offset: $start_offset, End Offset = $end_offset\n";
			print "Sig: $sig\n\n";
			my $length = length( $sig );
			print "Sig length = $length\n";
		}
	else
		{	print "Inserted $name\n";
		}
		
		
	$sth->finish();
	return( 1 );
}



################################################################################
# 
sub ScanDatabaseVirusErrors( $$ )
#
#	Change any detected viruses to the error category in the database
#	The only argument is the database handle to use, and the error category number
#
################################################################################
{
	my $dbh		= shift;
	my $errnum	= shift;
		
		
	# Return right away if the virus signature table doesn't exist
	return( 0 ) if ( ! &SqlTableExists( "VirusSignatures" ) );
	
	my $filename = &ScanSignatureFile();
	if ( ! open( FILE, ">$filename" ) )
		{	print "Error opening $filename: $!\n";
			return( undef );
		}
	
	
	my $sth = $dbh->prepare( "SELECT VirusName, VirusType, appsig, sigstart, sigend, signature, CategoryNumber, Test FROM VirusSignatures WITH(NOLOCK) where CategoryNumber <> $errnum order by VirusName" );
		
		
	$sth->execute();

	my $array_ref = $sth->fetchall_arrayref();
	my $i = 0 + 0;
	foreach my $row ( @$array_ref )
		{	my ( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = @$row;
			$virus_name = &CleanVirusName( $virus_name );
			$sigstart = 0 + $sigstart;
			$sigend = 0 + $sigend;
			$delete = "0" if ( ! $delete );
			$delete = "0" if ( $delete ne "1" );
			
			# Is the signature a clean one, with no regular expressions?
			next if ( $signature =~ m/[^\da-f]/ );
			
			print FILE "$virus_name\t$virus_type\t$appsig\t$sigstart\t$sigend\t$signature\t$category_number\t$delete\n";
			
			$i++;
		}

	$sth->finish();
	
	close FILE;
	

	return( $i );
	
}



################################################################################
# 
sub DatabaseDumpFileIDs( $$ )
#
#	Dump all the file integrity file IDs from the SQL database into the
#	file integity file
#   Return the count of fileIDs saved to disk
#
################################################################################
{	my $dbh		= shift;
	my $errnum	= shift;
		

	# Return right away if the ApplicationProcesses table doesn't exist
	return( 0 ) if ( ! &SqlTableExists( "ApplicationProcesses" ) );

	# Initialize everything in memory for the file ID files
	&FileIDClear();
	
	
	# Don't dump errors down
	my $str = "SELECT FileID, CategoryNumber, ProgramPermissions, AppName, Recommended, Dangerous, CurrentVersion FROM ApplicationProcesses WITH(NOLOCK) where CategoryNumber <> $errnum";
	my $sth = $dbh->prepare( $str );
	$sth->execute();
	
	my $local_permissions	= 0 + 0;
	my $network_permissions = 0 + 0;
	my $network_active_perm_bit			= 0 + 0x80000000;	# PERM_NET_USE - If this bit is turned on, then the network permissions are the active permissions

	my $id_count = 0 + 0;
	while ( ( ! $dbh->err )  &&  ( my ( $hex_fileID, $category_number, $hex_permissions, $app_name, $recommended, $dangerous, $current_version ) = $sth->fetchrow_array() ) )
		{	next if ( ! $hex_fileID );
			$hex_fileID = lc( $hex_fileID );
			
			my $len = length( $hex_fileID );
			next if ( $len != 56 );
			
			# Make sure that it is hex
			next if ( $hex_fileID =~ m/[^a-f0-9]/ );
					 
			my $fileID = &HexToStr( $hex_fileID );
			
			# Make sure the file ID is ok
			next if ( ! $fileID );
			$len = length( $fileID );
			next if ( $len != 28 );
						
			# Convert the hex string to an integer value
			$network_permissions = &HexToStr( $hex_permissions );
			my $permissions_num = unpack "N", $network_permissions;
			$permissions_num	= 0 + $permissions_num;
				
							
			$category_number	= 0 + 6 if ( ! $category_number );	# Default to business
			$category_number	= 0 + $category_number;
			$local_permissions	= 0 + 0;

			# Make sure that the network permissions are the active permissions
			$permissions_num += $network_active_perm_bit if ( ! ( $permissions_num & $network_active_perm_bit ) );
			
			my $attributes = &PackAttributes( $category_number, $permissions_num, $local_permissions );

			$id_count++ if ( &FileIDAdd( $fileID, $category_number, $permissions_num, $app_name ) );
		}

	$sth->finish();

	# Save the ID table to disk
	my ( $id_saved, $msg ) = &FileIDSave( $opt_debug );
	
	print "Added $id_count file IDs, saved $id_saved file IDs\n" if ( $id_saved );
	print "Error saving file IDs: $msg\n" if ( ! $id_saved );
	
	return( $id_saved );
}



################################################################################
#
sub AnswerYorN( $ )
#
# Ask a question and return Y or N in response
#
################################################################################
{	my $question = shift;
	
    print "$question [ Y or N ] ";

	my $done;
	while ( !$done )
		{	my $line = <STDIN>;
			chomp( $line );
            return( "N" ) if ( uc( $line ) eq "N" );
            return( "Y" ) if ( uc( $line ) eq "Y" );
		}
}



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     print( @_ );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "Scan";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Scansig";


    bprint <<".";

Usage: $me file

Scansig analyzes the given file for possible virus signatures.  If the file
is a message file or a zip archive, it will analyze each file contained in the
message file or zip archive.

Scansig returns the application signature and up to 4 possible virus signatures
for each file found.  It can also optionally add a new virus signature into
the local database and the \"VirusSignatures\" file.

When adding a new signature you should specify what signature number of which
file you want to create as well as the name of the virus.

Example:

scansig w32.mimail.j\@mm -f 1 -m 2 -n W32/Mimail.J\@MM

This example adds a new virus signature in the database from the mail file
called \"w32.mimail.j\@mm\".  It will use the first file found, and the second 
signature, and it will be called \"W32/Mimail.J\@MM\" in the database.

  -c, --category   category name for adding a signature, default is \"virus\" 
                   also used for dumping only virus signatures for a category
  -d, --database   dump the virus signatures and file integrity file IDs from
                   the database to \"VirusSignatures\", \"FileIntegrity\", 
                   and \"FileID.dat\".
  -f, --fileno     the file number to use if adding a signature, default is 1
  -i, --insert     insert the virus signatures from file \"CustomSignatures\"
                   into the database
  -n, --name       the name of the virus to create a signature for
  -m, --sig        signature number to use to add a new signature to the 
                   database and the \"VirusSignatures\" file
  -s, --source NUM the source number to use for all database inserts, default 2				   
				   
  -r, --recent     only dump the virus signatures newer than 1 week
  --version        print version number
  --help           print this message and exit

.
    &StdFooter;

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
