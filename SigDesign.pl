################################################################################
#!perl -w
#
# Rob McCarthy's Sig Design source code
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


my $_version = '8.01.00';


use Getopt::Long();
use Win32;
use Win32::Event;
use DBI qw(:sql_types);
use DBD::ODBC;
use Digest::MD5;
use Win32::Exe;
use Win32::Exe::Resource::Version;
use Cwd;
use Archive::Zip qw( :ERROR_CODES );


use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Content::ScanFile;
use Content::UpdateEvent;
use Content::FileIntegrity;
use Content::FileID;



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_wizard;								# True if I shouldn't display headers or footers
my $opt_signature;							# If set, add the virus signature number into the database
my $opt_delete;								# Set to the name of the virus if deleting
my $opt_category = "security.spyware";		# The name of the category to add
my $opt_category_number = 0 + 62;			# The category number of the virus signature
my $opt_insert;								# True if I should insert the virus signatures file into the database
my $opt_virusfile;							# The optional name of the custom virus file
my $opt_offset = 0 + 0;						# Custom file offset to use
my $opt_length = 0 + 128;					# The length of the signature to create - up to 256 bytes - default is 128
my $opt_prepend = "Spyware.";				# The text to prepend to an automatically named virus
my $opt_type;								# The type of signature
my $opt_merge;								# If True then merge the CustomSignatures and the VirusSignatures file


my %category;								# The category hash containing all the category properties, index is the category number, value are all the properties, tab delimited
my %category_number;						# Hash - index is category name, value is category number


my $tmp_dir;
my $virus_name;								# The virus name to use if creating a signature
my $file_no = 0 + 0;						# This is the number of the current file that I am checking
my %virus_list;								# The hash of the virus signatures
my %custom_virus_list;						# The list of custom virus signatures
my $dbh;									# My database handle
my $signum = 0 + 0;							# The number of the last test signature
my $is_known;								# True if the virus file is known in the FileIntegrity hash



################################################################################
#
MAIN:
#
################################################################################
{	$SIG{'INT'} = 'INT_handler';

     # Get the options
     Getopt::Long::Configure("bundling");

     my $options = Getopt::Long::GetOptions
       (
			"c|category=s"	=> \$opt_category,
			"d|delete=s"	=> \$opt_delete,
			"i|insert"		=> \$opt_insert,
			"l|length=s"	=> \$opt_length,
			"m|merge"		=> \$opt_merge,
			"n|name=s"		=> \$virus_name,
			"o|offset=i"	=> \$opt_offset,
			"p|prepend=s"	=> \$opt_prepend,
			"s|sig=i"		=> \$opt_signature,
			"t|type=s"		=> \$opt_type,
			"v|virus=s"		=> \$opt_virusfile,
			"w|wizard"		=> \$opt_wizard,
			"h|help"		=> \$opt_help,
			"x|xxx"			=> \$opt_debug
       ) or die( Usage() );


	print "Lightspeed Virus Signature Design utility\n" if ( ! $opt_wizard );
	print "Version: $_version\n" if ( ! $opt_wizard );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	
	print "Debugging mode\n" if ( $opt_debug );
	
	$tmp_dir = &TmpDirectory();
	
	my $errnum = 0 + 7;
	
	
	if ( $opt_type )
		{	$opt_type = uc( $opt_type );
			
			die "Invalid signature type.  Must be W32, HTM, ZIP, TXT, MW, JS, or BAT\n" if ( ( $opt_type ne "W32" )  &&
																					( $opt_type ne "HTM" )  &&
																					( $opt_type ne "ZIP" )  &&
																					( $opt_type ne "TXT" )  &&
																					( $opt_type ne "VBS" )  &&
																					( $opt_type ne "PL" )  &&
																					( $opt_type ne "MW" )  &&
																					( $opt_type ne "JS" )  &&
																					( $opt_type ne "BAT" ) );
		}
		
		
	# Make sure the length of the signature is valid	
	$opt_length = 0 + $opt_length;
	if ( ( $opt_length < ( 0 + 32 ) )  ||  ( $opt_length > ( 0 + 256 ) ) )
		{	die "The signature length needs to be between 32 and 256 bytes\n";
		}
		
		
	if ( $opt_delete )
		{	#  Open the database
			my $count = &LoadVirusSignatures();
			if ( ! $count )
				{	die "Unable to load any virus signatures\n";
				}
				
			if ( ! defined $virus_list{ $opt_delete } )
				{	die "No current virus is named $opt_delete\n";
				}
			else
				{	delete $virus_list{ $opt_delete };
					delete $custom_virus_list{ $opt_delete } if ( defined $custom_virus_list{ $opt_delete } );
					
					print "Deleted virus signature $opt_delete\n";
					my $count = &SaveVirusSignatures();
					my $signature_file = &ScanSignatureFile(); 				
					print "Total of $count signatures in $signature_file\n";
					
					exit( 0 );
				}
		}
		

	if ( ( $opt_insert )  ||  ( $opt_virusfile ) ) 	# Insert the active virus signatures into the Content database
		{	# Did I get a command line option for a different file name?
			if ( ( $opt_virusfile )  &&  ( ! -e $opt_virusfile ) )
				{	print "The file $opt_virusfile does not exist\n";
					exit( 1 );
				}
				
			#  Open the database
			$dbh = &ConnectServer() or die "Can not connect to the Content database\n";
				
			my $custom_signature_file = &ScanCustomSignatureFile();
			$custom_signature_file = $opt_virusfile if ( $opt_virusfile );
			
			if ( ! open( FILE, "<$custom_signature_file" ) )
				{	print "Unable to open file $custom_signature_file: $!\n";
				}
			else
				{	print "Inserting virus signatures from $custom_signature_file into the database ...\n";
					my $insert_count = 0 + 0;
					while (<FILE>)
						{	my $line = $_;
							chomp( $line );
							next if ( ! $line );
							
							my ( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = split /\t/, $line, 8;
							
							next if ( ! $virus_type );
							next if ( ! $appsig );
							next if ( ! $signature );
							
							$category_number = 0 + 62 if ( ! $category_number );
							$delete = "0" if ( ! $delete );
							$delete = "0" if ( $delete ne "1" );
							
							$virus_name = &CleanVirusName( $virus_name );
							$sigstart = 0 + $sigstart;
							$sigend = 0 + $sigend;
							
							# Force the category insert to be category 64
							my $ok = &ScanDatabaseAddSignature( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, 1, 64, $delete );
							$insert_count++ if ( $ok );
						}
						
					print "Inserted $insert_count custom virus signatures into the database\n";
					close FILE;
				}
				
			#  At this point, I'm done with the database, so clean up everything
			$dbh->disconnect;		 				
			&StdFooter();
			exit;
		}
	
	
	my $filename = shift;

	
	
	$opt_signature = 0 + $opt_signature if ( $opt_signature );
	die "Invalid signature number $opt_signature\n" if ( ( $opt_signature )  &&  ( $opt_signature < 0 + 1 ) );


	print "Merging the CustomSignatures and VirusSignatures files ...\n" if ( $opt_merge );
	if ( ( $opt_signature )  ||  ( $opt_merge ) )
		{	#  Open the database
			my $count = &LoadVirusSignatures();
			if ( ! $count )
				{	die "Unable to load any virus signatures\n";
				}			
		}
		
	
	#  Clean up everything and quit
	if ( $opt_merge )
		{	my $count = &SaveVirusSignatures();
			my $signature_file = &ScanSignatureFile(); 				
			print "\nTotal of $count signatures in $signature_file\n";
			exit( 0 );
		}	


	if ( $filename )	
		{	# Load in the file integrity and check to make sure we aren't building a signature for a known file	
			my ( $loaded_fileIDs, $msg ) = &LoadFileIntegrity( undef );
			if ( ! defined $loaded_fileIDs )
				{	die "Error loading the file integrity database: $msg\n";
				}

			$is_known = &IsKnownFileIntegrity( $filename );
			
			if ( ( $is_known )  &&  ( $is_known == 1 ) )
				{	print "\n$filename is a known program.\n";
					my $answer = &AnswerYorN( "Are you sure you want a virus signature for this?" );
			
					exit( 1 ) if ( $answer eq "N" );
				}
				
			# Default a virus name to the program name
			if ( ! $virus_name )
				{	my $prog_dir;
					( $prog_dir, $virus_name ) = &SplitFileName( $filename );
					
					$virus_name = $opt_prepend . $virus_name if ( ( $opt_prepend )  &&  ( $virus_name ) );
					$virus_name =~ s/\.exe$// if ( $virus_name );
				}

			$virus_name = &CleanVirusName( $virus_name );
			die "No valid virus name defined\n" if ( ! $virus_name );
			print "\nVirus name = $virus_name\n";
		}
		
		
	if ( $opt_category )
		{	&SigLoadCategories();
			my $catname = lc( $opt_category );
			
			$opt_category_number = $category_number{ $catname };
			
			if ( ! $opt_category_number )
				{	print "Unable to find number for category $catname\n";
					exit( 1 );	
				}
		}
		

	if ( $opt_offset )
		{	print "Use an offset of $opt_offset to look for a signature ...\n";
		}
		
		
	if ( ! $filename )
		{	Usage();
		}
	elsif ( ! ( -f $filename ) )
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
		{	my $count = &SaveVirusSignatures();
			
			if ( ( $is_known )  &&  ( $is_known == 1 ) )
				{	my $file_id = &ApplicationFileID( $filename );
					
					if ( ! $file_id )
						{	print "Unable to calculate the file ID for $filename\n";
							exit;
						}
						
					my ( $removed, $errmsg ) = &DeleteFileID( $file_id );
					
					if ( $removed )
						{	print "Saving the File Integrity database ...\n";
							my ( $ok, $msg ) = &SaveFileIntegrity( undef, undef );
							print "Error: $msg\n" if ( ! $ok );
						}
					elsif ( $errmsg )
						{	print "Error: $errmsg\n";
						}
						
					# If the file ID in the fileID.dat file as well?	
					my ( $app_name, $virus_category, $permissions_num ) = &FileIDAppName( $file_id ) if ( $file_id );
					
					if ( ( $file_id )  &&  ( $app_name ) )
						{	print "Saving the FileID database ...\n";
							my ( $count, $msg ) = &FileIDLoad( undef );
							&FileIDDelete( $file_id );
							( $count, $msg ) = &FileIDSave( undef );
			
							# Clear out any global memory used
							&FileIDClear();
						}
				}
			
			my $signature_file = &ScanSignatureFile(); 				
			print "\nTotal of $count signatures in $signature_file\n";
		}	
		
	exit;
}
###################    End of MAIN  ################################################



################################################################################
#
sub INT_handler( $ )
#
#  Interrupt handler
#
################################################################################
{		  
	exit( 253 ); 
}



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
	
	# Get the current directory
	my $old_dir = getcwd();
	$old_dir =~ s#\/#\\#g;

	# make sure the full path is there
	
	my $fullpath_zipfile = $zipfile;
	
	if ( !( $fullpath_zipfile =~ m/\\/ ) )
		{	$fullpath_zipfile = "$old_dir\\$zipfile";
		}
		
	my $zip = Archive::Zip->new( $fullpath_zipfile );
	
	
	# Check to see if there are encrypted files in the zip archive
	if ( $zip )
		{	my @members		= $zip->members;	

			my $fileno = 0 + 0;
			foreach ( @members )
				{	my $member = $_;
					next if ( ! $member );
					
					my $is_encrypted		= $member->isEncrypted();
					my $filename			= $member->fileName();
					my $uncompressed_size	= $member->uncompressedSize();
					my $compressed_size		= $member->compressedSize();
					my $crc32string			= $member->crc32String();
					my $compression_method	= $member->compressionMethod();

					$fileno++;

					if ( $is_encrypted )
						{	my $sig = "!1:*:$uncompressed_size:$compressed_size:$crc32string:*:$fileno:1";
							&TestSignature( $virus_name, "504b0304", 0, -1, $sig );
							
							if ( ! $opt_signature )
								{	print "\nZip encrypted signature - filename = $filename\n";
									print "Signature $signum: Starting Offset: 0 Ending Offset: -1\n$sig\n";
								}
						}
				}
		}

	return if ( $err_msg );
	
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
							
							if ( ! $opt_signature )
								{	print "\nFile Number: $file_no\n";
									print "Text File: $filename\n";
			
									print "Application Signature: $script\n";
									print "\nSuggested virus signatures:\n";		
								}
								
							$found = 1;
							
							my $pos = 0;
							for ( my $i = 0;  $i < 4;  $i++ )
								{	next if ( length( $sig ) < $pos + 128 );
									next if ( $counter > 4 );
									
									my $smallsig = substr( $sig, $pos, 128 );
# print "smallsig = $smallsig\n";									
									my $hex = &StrToHex( $smallsig );
									
									&TestSignature( $virus_name, "JS", 0, -1, $hex );
									print "\nSignature $signum: Starting Offset: 0 Ending Offset: -1\n$hex\n" if ( ! $opt_signature );

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
	
#	my $exe = Win32::Exe->new( $filename );
#	my @offsets;
#	if ( $exe )
#		{	print "\nPE Section offsets:\n";
#			my @sections = $exe->sections;
#			my $sec_num = 0 + 0;
#			foreach ( @sections )
#				{	my $section = $_;
#					my $offset = $section->FileOffset;
#					push @offsets, $offset;
#					print "Section S$sec_num starting offset $offset\n";
#					$sec_num++;
#				}
#		}

		
	my $appsig = &ScanFileAppSignature( $filename );
	my $appsighex;
	
	if ( $appsig )
		{	$appsighex = &StrToHex( $appsig );
		}
	else
		{	$appsighex = "TXT";
		}


	if ( ! $opt_signature )		
		{	print "\nFile Number: $file_no\n";
			print "Binary File: $filename\n";
			print "Application Signature: $appsighex\n";
			print "\nSuggested virus signatures:\n";		
		}
	
	
	
	my ( $sig, $sigstart, $sigend );	
	my $hex;		
	

	# Figure out an MD5 stype of signature	
	( $sig, $sigstart, $sigend ) = &ScanFileMD5Signature( $filename );
	&TestSignature( $virus_name, $appsighex, $sigstart, $sigend, $sig ) if ( $sig );
	print "\nSignature $signum: MD5 hash\n$sig\n" if ( ( $sig )  &&  ( ! $opt_signature ) );
	
	
	my @start = ( 0 + 0, 0 + 4096, 0 + 4176, 0 + 5120, 0 + 10240 );
	
	for ( my $i = 0 + 1;  $i <= 4;  $i++ )
		{	$sigstart = $start[ $i ];
			
			( $sig, $sigstart, $sigend ) = &ScanFileSignature( $filename, $sigstart );
			$hex = &StrToHex( $sig );
			&TestSignature( $virus_name, $appsighex, $sigstart, $sigend, $hex ) if ( $sig );
			
			if ( ( ! $opt_signature )  &&  ( $sig ) )
				{	my $hex_start = sprintf( "%x", $sigstart );
					my $hex_end = sprintf( "%x", $sigend );
					print "\nSignature $signum: Starting offset: $sigstart ($hex_start H) Ending Offset: $sigend ($hex_end H)\n$hex\n";
					my $text = &ReadableText( $hex );
					print "Text: $text\n";
				}
		}
		
	
	# Should I look at a custom offset?
	if ( $opt_offset )
		{	( $sig, $sigstart, $sigend ) = &ScanFileSignature( $filename, $opt_offset );
			$hex = &StrToHex( $sig );
			&TestSignature( $virus_name, $appsighex, $sigstart, $sigend, $hex ) if ( $sig );

			if ( ( ! $opt_signature )  &&  ( $sig ) )
				{	my $hex_start = sprintf( "%x", $sigstart );
					my $hex_end = sprintf( "%x", $sigend );
					$hex = &StrToHex( $sig );
					print "\nSignature $signum: Starting offset: $sigstart ($hex_start H) Ending Offset: $sigend ($hex_end H) \n$hex\n";
					my $text = &ReadableText( $hex );
					print "Text: $text\n";
				}			
		}
		
		
	# Is this a zip file?
	&ScanZipSignature( $filename ) if ( $appsighex eq "504b0304" );
}



################################################################################
# 
sub ScanFileMD5Signature( $ )
#
#	Given a filename, return the md4 hash signature, or undef if a problem
#
################################################################################
{	my $file = shift;

	if ( ! -e $file )
		{	print "Unable to open file $file for an MD5 signature\n";
			return( undef, 0, 0 );	
		}

	my $size = -s $file;
	
	if ( ! $size )
		{	print "Can not create an MD5 signature for a 0 length file\n";
			return( undef, 0, 0 );	
		}
	
	my $hex_md5 = &ScanFileHexMD5( $file );	
	
	my $sig = "!" . "MD5:$size:$hex_md5";
	
	return( $sig, 0 + 0, 0 - 1 );
}



################################################################################
# 
sub ScanFileSignature( $$ )
#
#	Given a filename, and an offset, return the opt length byte signature at that location
#   also return the starting offset, and the ending offset to check
#
################################################################################
{	my $file	= shift;
	my $offset	= shift;
				
	open INPUT, "<$file" or &FatalError( "Unable to open file $file: $!\n" );
	binmode( INPUT );

	$offset = 0 + $offset;
	
	# Seek from the beginning of the file
	return( undef, 0, 0 ) if ( !seek( INPUT, $offset, 0 ) );

	# Read the the file for the signature
	my $sig;
	my $size = 0 + $opt_length;
	if ( !read( INPUT, $sig, $size ) )
		{	close INPUT;
			return( undef, 0, 0 ) 
		}
	
	close INPUT;
	
	return( $sig, $offset, $offset + $opt_length );
}



################################################################################
# 
sub TestSignature( $$$$$ )
#
#	Add a signature to the custom sig file and to the virusignature file
#
################################################################################
{	my $name		= shift;
	my $appsig		= shift;
	my $sigstart	= shift;
	my $sigend		= shift;
	my $signature	= shift;
	
	$signum++;

	return if ( ! $opt_signature );
	
	$opt_signature = 0 + $opt_signature;
	
	# Am I supposed to add a signum to the database?
	return if ( $signum != $opt_signature );
	
	
	my $category_number = $opt_category_number;
	
	my $delete = "0";
	
	my $virus_type = $appsig;
	$virus_type = "W32" if ( $appsig =~ m/^4d5a/i );
	$virus_type = "VBS" if ( $appsig =~ m/VBS/i );
	$virus_type = "JS" if ( $appsig =~ m/JS/i );
	$virus_type = "ZIP" if ( $appsig =~ m/^504b0304/i );
	$virus_type = "MW" if ( $appsig =~ m/^d0cf/i );
	$virus_type = $opt_type if ( $opt_type );

	
	print "\n";
	print "Adding virus signature: $name\n";
	print "Virus type: $virus_type\n";
	print "Application Signature: $appsig\n";
	print "Category; $opt_category\n";
	print "\n";


	my $hex_start = sprintf( "%x", $sigstart );
	my $hex_end = sprintf( "%x", $sigend );
	
	print "Signature offsets: Starting offset: $sigstart ($hex_start H) Ending Offset: $sigend ($hex_end H)\n";
	print "Hex Signature: $signature\n";
	
	
	# Is this virus already in the database?
	# If so, prompt before overwriting it
	
	if ( defined $virus_list{ $virus_name } )
		{	my $answer = &AnswerYorN( "\nOverwrite existing virus signature for $virus_name?" );
			
			if ( $answer ne "Y" )
				{	$opt_signature = undef;
					exit( 0 );
				}
		}
	
	
	my $line = "$virus_name\t$virus_type\t$appsig\t$sigstart\t$sigend\t$signature\t$category_number\t$delete";		
	$virus_list{ $virus_name } = $line;
	$custom_virus_list{ $virus_name } = $line;
	
	
	return( 1 );
}



################################################################################
#
sub ReadableText( $ )
#
# Convert a hex string to readable text
#
################################################################################
{	my $hex_string = shift;
	
	my $str = &HexToStr( $hex_string );
	
	$str =~ s/[^a-zA-Z0-9\.\-]//gm;

	return( $str );
}



################################################################################
#
sub LoadVirusSignatures()
#
# Load the virus signature hash off of disk
#
################################################################################
{
	# Get the current virus signatures off of disk		
	my $file = &ScanSignatureFile();
	
	&ScanNoReadOnly( $file );
	if ( ! open FILE, "<$file" )
		{	print "Unable to open $file for reading: $!\n";
			return( undef );
		}


	my $count = 0 + 0 ;
	while (<FILE>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			$count++;
			my ( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = split/\t/, $line, 8;
			$category_number = 0 + 63 if ( ! $category_number );
			
			$delete = "0" if ( ! $delete );
			$delete = "0" if ( $delete ne "1" );
			
			$virus_name = &CleanVirusName( $virus_name );
			$virus_list{ $virus_name } = "$virus_name\t$virus_type\t$appsig\t$sigstart\t$sigend\t$signature\t$category_number\t$delete";
		}
		
	close FILE;


	# Merge in any Custom Signatures
	my $customsigfile = &ScanCustomSignatureFile();
			
	# Get the custom virus signatures off of disk
	my $merged_count = 0 + 0;	
	if ( open FILE, "<$customsigfile" )
		{	while (<FILE>)
				{	my $line = $_;
					chomp( $line );
					next if ( ! $line );
					
					my ( $virus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = split/\t/, $line, 8;
					$category_number = 0 + 63 if ( ! $category_number );
					$virus_name = &CleanVirusName( $virus_name );
					next if ( ! $virus_name );
					
					$delete = "0" if ( ! $delete );
					$delete = "0" if ( $delete ne "1" );

					$line = "$virus_name\t$virus_type\t$appsig\t$sigstart\t$sigend\t$signature\t$category_number\t$delete";
					$virus_list{ $virus_name } = $line;
					$custom_virus_list{ $virus_name } = $line;
				
					$merged_count++;
				}
				
			close FILE;
			
			print "Merged $merged_count custom virus signature(s) into the main virus file\n" if ( $merged_count > 0 );
		}

	
	return( $count );
}



################################################################################
#
sub SaveVirusSignatures()
#
# Save the virus signature hash to disk
#
################################################################################
{
	# Write the current virus signatures back to disk		
	my $file = &ScanSignatureFile();
		
	if ( ! open VIRUSFILE, ">$file" )
		{	print "Unable to open $file for writing: $!\n";
			return( undef );	
		}
		
	my $file_nx = &ScanSignatureFileNX();
		
	if ( ! open VIRUSFILENX, ">$file_nx" )
		{	print "Unable to open $file_nx for writing: $!\n";
			return( undef );	
		}
		
	my @keys = sort keys %virus_list;

	my $count = 0 + 0;
	foreach ( @keys )
		{	my $virus_name = $_;
			next if ( ! $virus_name );
			next if ( ! defined $virus_list{ $virus_name } );
			my $line = $virus_list{ $virus_name };
			chomp( $line );
			next if ( ! $line );
			print VIRUSFILE "$line\n";
			
			$count++;
			
			my ( $qvirus_name, $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = split/\t/, $line, 8;
			
			# Only write to the virus nx file signatures that match NX types
			next if ( ! &ScanNXVirusType( $virus_type ) );
			
			print VIRUSFILENX "$line\n";
		}
	
	close VIRUSFILE;
	close VIRUSFILENX;
	
	
	# Write out to disk the new custom signatures
	my $customsigfile = &ScanCustomSignatureFile();
			
	my $merged_count = 0 + 0;
	if ( open FILE, ">$customsigfile" )
		{	my @keys = sort keys %custom_virus_list;
			
			foreach( @keys )
				{	next if ( ! $_ );
					my $virus_name = $_;
					my $line = $custom_virus_list{ $virus_name };
					next if ( ! $line );
					
					print FILE "$line\n";
					$merged_count++;
				}
			
			close FILE;
		}

	print "\nSaved $merged_count custom signature(s) to $customsigfile\n" if ( $merged_count > 0 );

	
	# Signal the security agent if it is running
#	my $ok = &SignalService();
#	print "Signaled the Security Agent service to load the new signatures file\n" if ( $ok );	

	return( $count );
}



################################################################################
#
sub SigLoadCategories()
#
#  Load the categories off disk
#
################################################################################
{
	my $file = &ScanCategoryFile();
	
	if ( ! open FILE, "<$file" )
		{	print "Unable to open categories $file: $!\n";
			return( undef );	
		}
	
			
	my $counter = 0 + 0;	
	while (<FILE>)
		{	my $line = $_;
			chomp( $line );
			next if ( ! $line );
			
			my ( $category_name, $category_number, $allow, $time, $description ) = split /\t/, $line;
			
			# If the allow field isn't true or false, then I need to reload the whole table
			return( 0 ) if ( ! $allow );
			return( 0 ) if ( ( $allow ne "true" )  &&  ( $allow ne "false" ) );
			
			next if ( ! $category_number );
			
			$category_number = 0 + $category_number;
			
			$counter++;
			
			my $val = ( 0 + 0 );
			$val = ( 0 + 1 ) if ( $allow eq "false" );
			
			$category_number = 0 + $category_number;
			
			$category{ $category_number } = $line;
			
			$category_number{ $category_name } = $category_number;
		}
		
	close FILE;
	
	return( $counter );
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
	
	my $source = 0 + 1;
	

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
		{	$sth = $dbh->prepare( "SELECT VirusName, CategoryNumber, Signature FROM VirusSignatures where VirusName = ?" );
			$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
			$sth->execute();
			my ( $existing_virus, $existing_category_num, $existing_sig ) = $sth->fetchrow_array();

			$sth->finish();
			
			$existing_category_num = 0 + $existing_category_num if ( $existing_virus );
			
			
			# Does it already exist, and isn't in the errors category, and the signature is different?
			if ( ( $existing_virus )  &&  ( $existing_category_num != 7 )  &&  ( $sig ne $existing_sig ) )
				{	print "Virus $name is already in the database with a different signature!\n";
					return( undef );
				}
			
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
	push @values, "\'" . $source . "\',";			# 7 entry
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
		{	print "Inserted virus $name\n";
		}
		
		
	$sth->finish();
	
	return( 1 );
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
    my $me = "SigDesign";

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
    my $me = "SigDesign";


    bprint <<".";

Usage: $me file [-n virus_name] [-f fileno] [-s signo] [-d virus_name]

SigDesign analyzes the given file for suggested virus signatures.  If the file
is a message file or a zip archive, it will analyze each file contained in the
message file or zip archive.

SigDesign returns the application signature and up to 5 suggested virus
signatures for each file found.  It can also optionally add a new virus 
signature directly into the \"VirusSignatures\" file for use by the Security 
Agent or the scan utility.

EXAMPLE: sigdesign testfile.exe

This example displays up to 5 suggested virus signatures to use from the file
\"testfile.exe\".

EXAMPLE: sigdesign virus.exe -s 2 -n W32/Mimail.J\@MM

This example adds a new virus signature to the \"VirusSignature\" file from a 
program called \"virus.exe\".  It will use the first file found, and the 
second signature, and the signature will be called \"W32/Mimail.J\@MM\".

Valid signature types are W32, HTM, ZIP, TXT, BAT, JS or MW, VBS, PL.


  -d, --delete virus  delete the virus signature from \"VirusSignatures\"
  -i, --insert        insert the virus signatures from file \"CustomSignatures\"
                      into the Content SQL database, if it is present
  -l, --length num    make the signature num bytes long
  -m, --merge         merge the CustomSignatures and VirusSignatures files
  -n, --name virus    the name of the signature to create
  -o, --offset POS    use an offset of POS to look for a signature
  -s, --sig           signature number to use when creating a signature
  -t, --type STYPE    signature type.
  -v, --virus VFILE   to insert virus signatures from the VFILE into
                      the Content SQL database, if it is present
  -h, --help          print this message and exit
.
    &StdFooter;

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
