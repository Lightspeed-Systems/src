################################################################################
#!perl -w
#
# Rob McCarthy's EmailUnpack.pl source code
#  Copyright 2006 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long();
use Cwd;
use File::Copy;
use Content::ScanUtil;
use MIME::Base64 qw(decode_base64);



use Content::File;



my $opt_dir;
my $opt_help;
my $opt_debug;
my $opt_unlink;
my $opt_verbose;

my $max_bytes = 0 + 10000000;
my $max_lines = 0 + 25000;						# The maximum number of lines in a spam file to read before giving up


my $tmp_dir;



################################################################################
#
MAIN:
#
################################################################################
{
	my $options = Getopt::Long::GetOptions
       (
			"d|dir=s"		=> \$opt_dir,
			"u|unlink"		=> \$opt_unlink,
			"h|help"		=> \$opt_help,
			"v|verbose"		=> \$opt_verbose,
			"x|xxx"			=> \$opt_debug
      );

	&StdHeader( "EmailUnpack" );

    &Usage() if ( $opt_help );	
	
	
	my $temp = shift;
	$opt_dir	= $temp if ( $temp );
	$temp = shift;
	
	
	&Usage() if ( ! $opt_dir );
	&Usage() if ( ! -d $opt_dir );
	
	
	# Use as a tmp directory the directory I am copying the attachments to
	$tmp_dir = $opt_dir;
	
	
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	print "Unpacking attachments from Email files in the current directory to directory $opt_dir ...\n";
	
	
	if ( ! opendir( DIRHANDLE, $cwd ) )
		{	print "Can't open directory $cwd: $!\n";
			return;
		}
	
	print "Checking directory $cwd ...\n" if ( $opt_verbose );
	
	my $counter = 0 + 0;
	for my $item ( readdir( DIRHANDLE ) ) 
		{	( $item =~ /^\.+$/o ) and next;
			
			#$dir_path eq "/" and $dir_path = "";
			my $f;
			if ( $cwd =~ m#\\+$# )
				{	$f = $cwd . $item;
				}
			else
				{	$f = $cwd . "\\" . $item;
				}
			
			
			# If the file is a directory, just skip it
			# If it is a ordinary file, scan it
			next if ( -d $f );
				
			my $file_count = &UnpackFile( $f );
			$counter += $file_count if ( $file_count );
		}
		
	closedir( DIRHANDLE );
	
	print "Copied $counter email attachments\n" if ( $counter );
	print "Copied no email attachments\n" if ( ! $counter );
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
#
sub UnpackFile( $ )
#
#  Given a file, unpack out any email attachments
#  Return the count of the email attachments that are unpacked, or undef if an error
#
################################################################################
{	my $file = shift;

	return( undef ) if ( ! $file );
	return( undef ) if ( ! -f $file );

	my $file_count = 0 + 0;


	my @attached_files;
	my $retcode = 0 + 0;
	my $result;
	my $msg;
	my $email_from;
	my $header_email_from;
	my $email_to;
	my $envelope_email_to;
	my $external_ip_address;
	my $external_ip_address_source;	
	my $external_ip_address_category;
	my $subject;
	my @message_files;	# The list of message files created
	my %base64_data = ();
	my $line_no = 0 + 0;


	
	
    #  Load the file into memory
    my @data = ();
    if ( !open SPAM, "<$file" )
	  {   &lprint( "Error opening file $file: $!\n" );
		  
		  return( undef );
      }


    my $counter = 0 + 0;			# The count of lines read from this message file
    my $base64;						# True if the boundary is encoded as base64
	my $quoted_printable;			# True if the boundary is encoded as quoted_printable
    my $message_body;				# True if we are inside part of a message body
	my $header = 1;					# True until we hit the message body - which includes multi part bodies
	my $first_line = 1;				# True if we are reading the first line of the file
	my @boundary;					# The list of boundaries
	my $content_description;		# The description of the current content
	my $content_type;				# The content type of the current part
	my $set_content_type;			# True if I just set the content type, and may get an attachment name next
	my $encoding;					# The encoding of the current part
	my $attachment;					# True if this part contains an attachment
	my $attachment_count = 0 + 0;	# The number of attached files
	my $total_parts = 0 + 0;		# The count of the number of parts to a multipart message
    my $bytes = 0 + 0;				# The number of bytes read 
	my $attach_filename;			# The name of the current attachment
	my $set_message_file_name;		# True if I have created a message file name for this attachment or content type
	my $skip_content;				# True if this type of content should be skipped for the Bayesian analysis
	my $skip_filename;				# True if this file extension should be skipped for the Bayesian analysis
	my $skip_decode;				# True if this file extension doesn't need to be decoded
	my $to_list;					# The list of to: addresses from the email header
	my $cc_list;					# The list of cc: addresses from the email header
	my $bcc_list;					# The list of bcc: addresses from the email header
	my $partial_line;	            # For decoding of partial lines in quoted-printable.
	my $last_header_type;			# The last header type line I processed - could be to, cc, subject, etc
	my $multi_subject = 0;
	my $multi_to = 0;
	my $multi_cc = 0;
	my $multi_bcc = 0;
	my $tmp_filename;
	
	
	while ( ( $retcode == 0 )  &&  ( my $line = <SPAM> ) )
		{   my $len = length( $line );
			next if ( $len > 1000 );  #  Skip long lines


			$bytes += $len;		# Count the bytes
			$counter++;			# Count the lines
			
			
			# Have I read a lot in already?
 			if ( ( $counter > $max_lines )  ||  ( $bytes > $max_bytes ) )
				{	&lprint( "Not unpacking completely file $file because of size limitations\n" );
					&lprint( "# of lines = $counter, # of bytes = $bytes\n" );

					# Dump any base64 data so that we don't try to unpack damaged zip file, for example
					%base64_data = ();
					last;
				}
			
			chomp( $line );
				
				
			# Do any header processing
			if ( $header )
				{	#  Am I reading the first line comment by Brock's code?
					# &debug( "Header: $line\n" );
							
					if ( ( $first_line )  &&  ( $line =~ m/^\(externalipaddress/i ) )
						{   $first_line = undef;

							my $comment = $line;
							
							# Read additional lines until I get the trailing )
							while ( ( $line )  &&  ( ! ( $line =~ m/\)/ ) ) )
								{	$line = <SPAM>;
									chomp( $line );
									
									# Get rid of leading whitespace
									$line =~ s/^\s+// if ( $line );

									# Get rid of trailing whitespace
									$line =~ s/\s+$// if ( $line );
									
									$comment .= "," . $line if ( $line );
								}

							$comment =~ s/\(//;
							$comment =~ s/\)//;
		
							my @parts = split /\s/, $comment;
							my $part_no = 0;
							foreach ( @parts )
								{  $part_no++;
									my $keyword = lc( $_ );
									#  Check for a blank value
									next if ( !$parts[ $part_no ] );
									next if ( index( "emailfrom:emailto:externalipaddress:", lc( $parts[ $part_no ] ) ) != -1 );
									
									if ( $keyword eq "emailfrom:" )          {  $email_from = lc( $parts[ $part_no ] );  }
									if ( $keyword eq "emailto:" )            {  $envelope_email_to = lc ( $parts[ $part_no ] );  }
									if ( $keyword eq "externalipaddress:" )  {  $external_ip_address = lc ( $parts[ $part_no ] );  }
								}
								
							
							next;
						}  # end of first line processing

					
					# Is it a multi-line subject, to, or cc?  A line starting with whitespace is a multi line option
					if ( $line =~ m/^\s/ )   
						{	# Trim off the first whitespace
							$line =~ s/^\s//;
							
							# Trim off the last whitespace
							$line =~ s/\s$//g;
							if ( ! defined $last_header_type )	# If it hasn't been set, then don't do anything
								{
								}
							elsif ( $last_header_type eq "subject" )
								{	$subject .= " " . $line;
									$multi_subject = 1;
									next;	# Get the next line of the file
								}
								
							elsif ( $last_header_type eq "to" )
								{	$to_list .= ";" . $line;
									$multi_to = 1;
									next;	# Get the next line of the file
								}
								
							elsif ( $last_header_type eq "cc" )
								{	$cc_list .= ";" . $line;
									$multi_cc = 1;
									next;	# Get the next line of the file
								}
								
							elsif ( $last_header_type eq "bcc" )
								{	$bcc_list .= ";" . $line;
									$multi_bcc = 1;
									next;	# Get the next line of the file
								}
							
						}
						


					my $lc_line = lc( $line );	# Get a lower case copy of the line to check encoding, etc
					my $no_comments = $lc_line;
				

					#  Consume any comments in the header - to avoid being deceived
					#  Do this to the lc variable, to preserver () in other cases
					if ( $no_comments =~ m/\(.*\)/ )
						{  $no_comments =~ s/\(.*\)//;
							$no_comments = "\(\)" if ( !$no_comments );  # if nothing left, pad it to be a blank comment
						}


					# Get rid of leading whitespace
					$no_comments =~ s/^\s//g;
					
					
					# Is this a header type & option?  It is if it contains a ':' with no spaces in the header option
					my ( $header_type, $option ) = split /\:/, $no_comments, 2;
					$last_header_type = $header_type if ( ( defined $option )  &&  ( ! ( $header_type =~ m/\s/ ) ) );
						
						
					#  Am I a setting the to: list?
					if ( ( ! defined $to_list )  &&  ( $no_comments =~ m/^to:/ ) )
						{    my ( $junk, $stuff ) = split /to:/, $lc_line, 2;

							$to_list = $email_to . ";" . $stuff if ( ( $email_to )  &&  ( $stuff ) );
							$to_list = $stuff if ( ( ! $email_to )  &&  ( $stuff ) );
							
						}	# End of setting the to: list
					 			
								
					#  Am I a setting the CC list?
					if ( ( ! defined $cc_list )  &&  ( $no_comments =~ m/^cc:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/cc://i;
							
							$cc_list = $stuff;
							$cc_list =~ s/^\s//g;
							$cc_list =~ s/\s$//g;
							
						}
					 			
								
					#  Am I a setting the BCC list?
					if ( ( ! defined $bcc_list )  &&  ( $no_comments =~ m/^bcc:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/bcc://i;
							
							$bcc_list = $stuff;
							$bcc_list =~ s/^\s//g;
							$bcc_list =~ s/\s$//g;
						}
					 		
								
					#  Am I a setting the Subject line?
					if ( ( ! defined $subject )  &&  ( $no_comments =~ m/^subject:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/subject://i;
							
							$subject = $stuff;
							$subject =~ s/^\s//g;
							$subject =~ s/\s$//g;
						}
					 		
								
					#  Am I a setting the header email from?
					if ( ( ! defined $header_email_from )  &&  ( $no_comments =~ m/^from:/ ) )
						{   my $stuff = $line;
							
							$stuff =~ s/from://i;
							
							$header_email_from = $stuff;
							$header_email_from =~ s/^\s//g;
							$header_email_from =~ s/\s$//g;
							
							#  Grab anything inside < > as the email address if <> exists
							$header_email_from = $1 if ( $stuff =~ m/\<(.*?)\>/ );
						}
					 			
								
					#  Am I a setting the Content Description?
					if ( $no_comments =~ m/^content-description:/ )
						{    my ( $junk, $stuff ) = split /content-description:/, $lc_line, 2;
							$content_description = $stuff;
							$content_description =~ s/^\s//g;
							$content_description =~ s/\s$//g;
							&debug( "Content-Description = $content_description\n" ) if ( $content_description );
						}
					 			
						
					#  Am I a setting the Content Type?
					if ( $no_comments =~ m/^content-type:/ )
						{    my ( $junk, $stuff ) = split /content-type:/, $lc_line, 2;
							$content_type = $stuff;
							$content_type =~ s/\s//;
							$content_type =~ s/\;//;
							( $content_type, $junk ) = split /\s/, $content_type, 2;
							&debug( "Content-Type = $content_type\n" ) if ( $content_type );
								
							# Is it a partial message?
							if ( ( $content_type )  &&  ( $content_type eq "message/partial" ) )
								{	$retcode = 1;  # Flag it as spam
									$msg = "Partial	message - could contain virus";
									$result = "VIRUS";
								}
							
							if ( $content_type )
								{	$set_content_type = 1;	
							
									$skip_content = undef;
									
									$skip_content = 1 if ( $content_type =~ m/pdf/ );
									$skip_content = 1 if ( $content_type =~ m/x-msdownload/ );
									$skip_content = 1 if ( $content_type =~ m/octet-stream/ );
									$skip_content = 1 if ( $content_type =~ m/audio/ );
									$skip_content = 1 if ( $content_type =~ m/image/ );
									$skip_content = 1 if ( $content_type =~ m/postscript/ );
									$skip_content = 1 if ( $content_type =~ m/zip/ );
								}
						}
					
					
					#  Am I setting the encoding?
					if ( $no_comments =~ m/^content-transfer-encoding:/ )
						{   &debug( "Content-Transfer-Encoding\n" );
							my ( $junk, $stuff ) = split /content-transfer-encoding:/, $lc_line, 2;
							$encoding = $stuff;
							$encoding =~ s/\s//;
							$encoding =~ s/\;//;
							( $encoding, $junk ) = split /\s/, $encoding, 2;
							$base64 = undef;
							$quoted_printable = undef;
								
							# If I have an encoded section, break it out to it's own file
							if ( $encoding )
								{	if ( $encoding =~ m/base64/i )
										{	$base64 = 1;

											&debug( "base64 encoding\n" );
											my $fileno = $#message_files + 1;
											$tmp_filename = &ScanBuildTmpFilename( $tmp_dir, $file, $fileno, "eml" );
										}
									elsif ( $encoding =~ m/quoted-printable/i )
										{	$quoted_printable = 1;
											
											&debug( "quoted-printable encoding\n" );
											my $fileno = $#message_files + 1;
											$tmp_filename = &ScanBuildTmpFilename( $tmp_dir, $file, $fileno, "txt" );
										}								
									
									$tmp_filename = &CleanFileName( $tmp_filename );
									
									if ( ( $tmp_filename  )  &&  ( ! $set_message_file_name ) )
										{	# Keep a list of the file names used
											
											push @message_files, $tmp_filename;
											$set_message_file_name = 1;
											
											$file_count++;
										}
								}			 
								
						}


					#  Is it MimeOLE?
					if ( $lc_line =~ m/^x-mimeole/ )
						{   &debug( "X-MimeOLE\n" );
						}


					#  Am I a setting the disposition?
					if ( $no_comments =~ m/^content-disposition:/ )
						{	&debug( "Content-Disposition\n" );
							my ( $junk, $stuff ) = split /content-disposition:/, $lc_line, 2;
							my $disposition = $stuff;
							$disposition =~ s/\s//;
							$disposition =~ s/\;//;
							
							if ( $lc_line =~ m/attachment/ )
								{	$attachment = 1;
									$attachment_count++;
									&debug( "Content-Disposition: attachment\n" );
								}								
						}
							
							
						#  Am I a setting the attachment filename, or did I just set the content type?
						if ( ( $attachment || $set_content_type )  &&  ( $no_comments =~ m/name *=/ ) )
							{	my ( $junk, $stuff ) = split /name *=/, $lc_line, 2;
								
								# Split off anything past a ';'
								( $attach_filename, $junk ) = split /;/, $stuff, 2 if ( defined $stuff );
											
								# Peel off quote marks if they are there
								$attach_filename =~ s/\"//g if ( $attach_filename );							

								# Peel off leading or trailing spaces
								$attach_filename =~ s/^\s+// if ( $attach_filename );
								$attach_filename =~ s/\s+$// if ( $attach_filename );
								
								if ( $attach_filename )
									{	push @attached_files, $attach_filename;
																		
										# If I've already set the message file name change it to include the actual attachment name
										my $fileno = $#message_files;
										
										# If I haven't set the message file name for this section, add a new name
										$fileno = $#message_files + 1 if ( ! $set_message_file_name );
										$set_message_file_name = 1;
										
										my $short_name = &CleanShortFileName( $attach_filename );
										
										$tmp_filename = &ScanBuildTmpFilename( $tmp_dir, $file, $fileno, $short_name );
										
										$tmp_filename = &CleanFileName( $tmp_filename );								
										$message_files[ $fileno ] = $tmp_filename if ( $tmp_filename );
										
										&debug( "Attach message file name = $tmp_filename\n" ) if ( $tmp_filename );
									}
								
								$attachment = undef;
								$set_content_type = undef;
								
								if ( $attach_filename )
									{	# Should I skip adding this content for bayesian analysis based on the filename?
										$skip_filename = undef;
										
										$skip_filename = 1 if ( $attach_filename =~ m/\.exe$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.com$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.pcx$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.dll$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.jpg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.jpeg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.ai$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.scr$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.zip$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.gz$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.ppt$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.xls$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.doc$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.bmp$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.pdf$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.cup$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.avi$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.mp3$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.mpg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.mpeg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.dbg$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.gif$/ );
										$skip_filename = 1 if ( $attach_filename =~ m/\.rar$/ );
										
																				
										# Is this the type of file that I don't need to decode since I won't scan for a virus?
										$skip_decode = undef;
										
										$skip_decode = 1 if ( $attach_filename =~ m/\.jpg$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.jpeg$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.pdf$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.ppt$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.bmp$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.avi$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.mp3$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.mpg$/ );
										$skip_decode = 1 if ( $attach_filename =~ m/\.mpeg$/ );
									}
							}


					#  Am I a setting a boundary?
					if ( $no_comments =~ m/boundary=/g )
						{	$lc_line =~ m/boundary=/g;
							
							my $boundary = substr( $line, pos( $lc_line ) );
							
							if ( ( $boundary )  &&  ( length( $boundary ) > 6 ) )
								{	$boundary =~ s#\"##g;   #  Get rid of quotes
									$boundary = '--' . $boundary;	#  Add the dash dash
									$boundary =~ s/\s+$//;		# Get rid of trailing whitespace	
									
									&debug( "boundary = $boundary\n" );
									
									$boundary = quotemeta( $boundary );  #  Backslash any non alpha character
									push @boundary, $boundary;
								}
						}			 
				}  # end of the header processing 
					
					
			#  Have I hit a boundary?
			#  I'm in a header if this matches - until I hit a blank line
			foreach ( @boundary )
				{   next if ( ! $_ );
						
					if ( $line =~ m/$_/ )
						{	$header					= 1;
							$message_body			= undef;
							$base64					= undef;
							$quoted_printable		= undef;
							$encoding				= undef;
							$attachment				= undef;
							$set_content_type		= undef;
							$attach_filename		= undef;
							$set_message_file_name	= undef;
							&debug( "Switching to a header\n" );
						}
				}  # end of foreach boundary
					
					
			#  A blank line or a dot in the header means we are switching to a body
			if (  ( $header )  &&  ( ( ! $line )  ||  ( $line eq "." ) ) )
				{  $total_parts++ if ( ! $message_body );
					$message_body	= 1;
					$header			= undef;
					$line			= undef;
					&debug( "Switching to a body\n" );
				}
			
					
			next if ( ! defined $line );  #  Now that it is blank, skip it
			
			
			# If I'm in a body - could this be some sort of enclosed message that is setting a boundary?
			# Well it might be, if the boundary is wrapped in double quotes and long enough
			if ( ( $message_body )  &&
				( ! $skip_decode ) &&
				( $line )  &&
				( $line =~ m/boundary=\"/ ) )
					{	my ( $junk, $boundary ) = split /boundary=/, $line, 2;
						if ( ( $boundary )  &&  ( $boundary =~ m/\"$/ )  &&  ( length( $boundary ) > 12 ) )
							{	$boundary =~ s#\"##g;   #  Get rid of quotes
								$boundary = '--' . $boundary;	#  Add the dash dash
								$boundary =~ s/\s+$//;		# Get rid of trailing whitespace	
								
								&debug( "message body boundary = $boundary\n" );
								
								$boundary = quotemeta( $boundary );  #  Backslash any non alpha character
								push @boundary, $boundary;
							}
					}			 
			

			# If the message type is rfc/822, the body is an enclosed message
			if ( ( $content_type )  &&  ( $content_type =~ /message\/rfc822/ ) )
					{	$header					= 1;
						$message_body			= undef;
						$base64					= undef;
						$quoted_printable		= undef;
						$encoding				= undef;
						$attachment				= undef;
						$set_content_type		= undef;
						$set_message_file_name	= undef;
					}
			
				
			#  If we are in a body, decode any base64 stuff 
			if ( ( $base64 )  &&  
				( $message_body )  &&  
				( ! $skip_decode )  &&
				( $content_type )  &&
				( $content_type ne "text\/plain" ) )
				{	# Figure out the right filename to save this data to
					my $fileno = $#message_files;
					my $message_filename = $message_files[ $fileno ];
					
					$base64_data{ $message_filename } .= $line if ( $message_filename );
				}

			#  If we are in a body, and virus_checking is enable, decode any quoted_printable
			if ( ( $quoted_printable )  &&  #  Decode if it looks like it matches
				( $message_body ) ) 
				{	# At this point I have already chomped any \n

					$line =~ s/[ \t]+\n/\n/g;        # rule #3 (trailing space must be deleted)
					
					my $hard_return;

					# Trim off any soft returns, wrap lines together to avoid broken URLs...
					if ( $line =~ m/=$/ )
						{	$line =~ s/=+$//;
							$partial_line .= $line;
							next;
						}
					else
						{  # Do not set a hard return if we are merging lines together.
							$hard_return = 1 if (!$partial_line);
						}
						
					
					# We made it to the end of a merged line.  Set it up and let it go!
					if ( $partial_line )
						{	$line = $partial_line . $line;
							$partial_line = undef;
						}
						    
										
					# Decode the line - now using MIME module instead of the substitution line
					$line = MIME::QuotedPrint::decode_qp( $line );
					
					# Save it to a file
					$line = $line . "\r\n" if ( $hard_return );	# Add a carriage return line feed if a hard return
					
					
					# Should I save this to a file for virus scanning?
					if ( ( ! $skip_decode )  &&
						( $content_type )  &&
						( $content_type ne "text\/plain" ) )
						{	# Figure out the right filename to save this data to
							my $fileno = $#message_files;
							my $message_filename = $message_files[ $fileno ];
							
							&ScanSaveMessageFile( $file, $message_filename, $line );
						}
				} # end of decoding quoted-printable

				
			# Could this be the beginning of a uuencoded file attachment?
			if ( ( $message_body )  &&  ( $line =~ m/^begin 6/ )  &&  ( ! $skip_decode ) )
				{	my $uu_decode = &UUDecode( $file, 1, $tmp_dir );
					push @message_files, $uu_decode if ( defined $uu_decode );
					
					$file_count++;
				}
				
				
			# Should I save this line into the data array for later Bayesian processing?					
			# Should I skip based on content-type?
			next if ( ( $message_body )  &&  ( $content_type )  &&  ( $skip_content ) );
						
			# Should I skip based on attached filename?
			# If it matches on one of these file extensions, don't do the Bayesian stuff on this data
			next if ( ( $message_body )  &&  ( $attach_filename )  &&  ( $skip_filename ) );
						
			# Add it to the data array for later Bayesian processing	
			push @data, $line;
			
			$line_no++;
			&debug( "LINE $line_no: $line\n" );
		}  # end of while <SPAM>
		
	close( SPAM );


	# Decode any BASE64-encoded attachments now and save them to the temporary files created earlier.
	# DO NOT CLOSE THE MESSAGE FILES BEFORE DOING THIS!
	my @base64_filelist = keys %base64_data;
	foreach ( @base64_filelist )
		{	my $message_filename = $_;
			
			# Make sure that I've got a filename
			next if ( ! $message_filename );
			
			my $base64_data = $base64_data{ $message_filename };
			
			# Clean out any white space
			$base64_data =~ s/\s//g if ( $base64_data );
			next if ( ! $base64_data );
			
			# Trim off any padding
			$base64_data =~ s/\=+$// if ( $base64_data );
			next if ( ! $base64_data );
			
			# Make sure the base64 padding is right
			my $base64_padding = 4 - length( $base64_data ) % 4;

			my $pad = '=' x $base64_padding if ( $base64_padding );
			$base64_data .= $pad if ( ( $base64_padding )  &&  ( $base64_padding < 4 ) );

			$base64_data = &decode_base64( $base64_data );
			
			# Make sure that I've got something to write
			next if ( ! $base64_data );
			
			if ( $opt_debug )
				{	my $len = length( $base64_data );
					&debug( "Writing $len bytes of base64 decoded data to $message_filename ... \n" ); 
				}
			
			$file_count++;
			
			# Save the decoded base64 data to the right file name	
			&ScanSaveMessageFile( $file, $message_filename, $base64_data );            
		}


	# Close any message files that were opened
	&ScanCloseMessageFiles();

	return( $file_count );
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

     lprint( @_ );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";
Usage: EmailUnpack [options] DIR

Read all the files in the current directory, unpacking the attachments from any
email files to directory DIR.

Possible options are:

  -d, --dir DIR        the directory to copy virus infected files to
  -v, --verbose        Verbose mode
  -u, --unlink         unlink (delete) the original virus infected files
  -h, --help           print this message and exit
.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
