################################################################################
#!perl -w
#
#  Delete files that have the same MD5 hash value
#
#  Copyright 2006 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();
use Digest::MD5;
use Content::File;
use Content::Scanable;
use Content::FileIntegrity;


my $opt_help;
my $opt_subdir;
my $opt_dir;
my $opt_rename;
my $opt_keep;
my $opt_executable;
my $opt_create;
my $opt_hashlist;
my $opt_fileid;


my %md5_hash;


my $unique_total	= 0 + 0;
my $deleted_total	= 0 + 0;
my $renamed_total	= 0 + 0;



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
		"c|create=s"	=> \$opt_create,
		"d|dir=s"		=> \$opt_dir,
		"f|fileid=s"	=> \$opt_fileid,
        "k|keep"		=> \$opt_keep,
		"l|load=s"		=> \$opt_hashlist,
        "h|help"		=> \$opt_help,
		"r|rename"		=> \$opt_rename,
		"x|executable"	=> \$opt_executable,
		"s|subdir"		=> \$opt_subdir
      );


	&Usage() if ( $opt_help );

	print "Delete duplicated files based on their MD5 hashes\n";
	
	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	my $dir = $cwd;
	
	$dir = $opt_dir if ( $opt_dir );
	
	print "Renaming unique files to their MD5 hash name ...\n" if ( $opt_rename );
	print "Renaming executable Win32 to .exe_ ...\n" if ( ( $opt_rename )  &&  ( $opt_executable ) );
	print "Creating a list of all the MD5 hashes found in $opt_create ...\n" if ( $opt_create );
	print "Creating a list of all the file IDs found in $opt_fileid ...\n" if ( $opt_fileid );

	if ( $opt_keep )
		{	print "Keeping duplicated files ...\n";
		}
	else
		{	print "Deleting from directory $dir ...\n" if ( ! $opt_subdir );
			print "Deleting from directory $dir and subdirectories ...\n" if ( $opt_subdir );
		}
		
		
	if ( $opt_create )
		{	open( CREATELIST, ">$opt_create" ) or die "Unable to create file $opt_create: $!\n";
		}
		
	if ( $opt_fileid )
		{	open( FILEIDLIST, ">$opt_fileid" ) or die "Unable to create file $opt_fileid: $!\n";
		}
		
		
	if ( $opt_hashlist )
		{	open( HASHLIST, "<$opt_hashlist" ) or die "Unable to open file $opt_hashlist: $!\n";
			
			my $count = 0 + 0;
			while ( my $line = <HASHLIST> )
				{	chomp( $line );
					next if ( ! $line );
								
					my ( $val, $file ) = split /\t/, $line, 2;
					
					next if ( ! defined $val );
					next if ( length( $val ) != 32 );
					
					my $hex_md5 = lc( $val );
					
					$file = "Undefined" if ( ! defined $file );
					
					$md5_hash{ $hex_md5 } = $file;
					
					$count++;
				}
			close( HASHLIST );
			
			die "Unable to read any valid MD5 hash values from $opt_hashlist\n" if ( $count == 0 );
			
			print "Read $count MD5 hashes from $opt_hashlist\n";
		}


    &DelMD5( $dir );

	chdir( $cwd );
	
	close( CREATELIST ) if ( $opt_create );
	close( FILEIDLIST ) if ( $opt_fileid );
	
	print "Found $unique_total total unique files.\n";
	print "Deleted $deleted_total duplicated files.\n" if ( $deleted_total );
	print "Renamed $renamed_total files to their MD5 hash names.\n" if ( $renamed_total );
	
    exit;
}



################################################################################
# 
sub DelMD5( $ )
#
################################################################################
{	my $dir = shift;

	print "Directory: $dir\n"; 
	chdir "$dir";

	my $dir_handle;
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";

	while ( my $file = readdir $dir_handle )
		{	
			next if ( ! defined $file );

			next if ( $file eq "." );
			next if ( $file eq ".." );

			next if ( ( $opt_create )  &&  ( $file eq $opt_create ) );
			next if ( ( $opt_fileid )  &&  ( $file eq $opt_fileid ) );
			
			my $fullpath = "$dir\\$file";
					
			if ( -f $fullpath )
				{	if ( ! -s $fullpath )
						{	print "Deleting 0 length file $file ...\n";
							unlink( $fullpath );
							next;
						}
				
					open( MD5HANDLE, $fullpath ) or next;
					
					binmode( MD5HANDLE );
					
					my $md5 = Digest::MD5->new;

					$md5->new->addfile( *MD5HANDLE );
					
					my $hex_md5 = $md5->hexdigest;

					close( MD5HANDLE );	
				
					next if ( ! $hex_md5 );
					
					if ( exists $md5_hash{ $hex_md5 } )
						{	my $original_file = $md5_hash{ $hex_md5 };
							
							# Is it the same file - just renamed?
							next if ( $original_file eq $fullpath );
							
							print "$file is a duplicate of $original_file\n";
							next if ( $opt_keep );
							
							# Which of the two duplicated file should I keep?
							# I prefer a file with a good extension
							
							my $original_extension = &FileExtension( $original_file );
							
							if ( $original_extension )
								{	unlink( $fullpath );
									$deleted_total++;
								}
							else	# The original file did not a file extension - does the new one?
								{	my $new_extension = &FileExtension( $fullpath );
									
									# If the new file doesn't have a file extesion either, then just delete it and keep the original file
									if ( ! $new_extension )
										{	unlink( $fullpath );
											$deleted_total++;
										}
									else	# Delete the original file, and rename the new file if I am supposed to
										{	print "Keeping $file and deleting $original_file because of the better file extension\n";

											if ( $opt_rename )
												{	my $renamed;
													my $deleted;
													( $fullpath, $renamed, $deleted ) = &RenameMD5( $fullpath, $hex_md5, $opt_executable );
													next if ( ! $fullpath );
													
													$deleted_total++ if ( $deleted );
													
													# Save the new name in the md5 hash
													$md5_hash{ $hex_md5 } = $fullpath;
												}
											
											# Now delete the original file
											unlink( $original_file );
											$deleted_total++;
										}
								}
						}
					else
						{	# Should I rename this file?
							if ( $opt_rename )
								{	my $renamed;
									my $deleted;
									( $fullpath, $renamed, $deleted ) = &RenameMD5( $fullpath, $hex_md5, $opt_executable );
									next if ( ! $fullpath );
									
									$renamed_total++ if ( $renamed );
									$deleted_total++ if ( $deleted );
								}
							
							# Keep track of the unique files	
							$unique_total++ if ( ! exists $md5_hash{ $hex_md5 } );
							
							$md5_hash{ $hex_md5 } = $fullpath;
							
							print CREATELIST "$hex_md5\t$fullpath\n" if ( $opt_create );
							
							if ( $opt_fileid )
								{	my $file_id = &ApplicationFileID( $file );
									my $hex_file_id = &StrToHex( $file_id ) if ( defined $file_id );
									print FILEIDLIST "$hex_file_id\t$fullpath\n" if ( defined $hex_file_id );
								}
						}
				}
			elsif ( ( -d $fullpath )  &&  ( $opt_subdir ) )
				{	&DelMD5( $fullpath );
					chdir( $dir );
				}
		}


	closedir( $dir_handle );

	return( 0 );
}



################################################################################
# 
sub RenameMD5( $$$ )
#
#  Given a full path filename, rename it to the MD5 file name, and return the new
#  name, and the rename status.  Delete duplicate files. Return undef if an error
#
################################################################################
{	my $fullpath	= shift;
	my $hex_md5		= shift;
	my $executable	= shift;	# If True then rename Win32 programs to .exe
	
	my ( $dir, $shortfile ) = &SplitFileName( $fullpath );
	
	my $ext;
	
	my @parts = split /\./, $shortfile;
	
	# Is there a name extension?
	if ( $#parts > 0 )
		{	$ext = lc( $parts[ $#parts ] );
			$ext .= "_" if ( ! ( $ext =~ m/_$/ ) );
		}

	# Clean up the extension
	if ( $ext )
		{	$ext =~ s/\s+//g;
			$ext = lc( $ext ) if ( $ext );
			$ext = undef if ( ( $ext )  &&  ( $ext eq "_" ) );
		}
		
	if ( $ext )
		{	$ext = undef if ( length( $ext ) > 5 );
			$ext = undef if ( ( $ext )  &&  ( length( $ext ) < 1 ) );
		}
	
	# Should I rename to *.exe?
	if ( $executable )
		{	if ( ( ! $ext )  ||  ( $ext ne "exe_" ) )
				{	my $scanable = &Scanable( $fullpath, 1 );
					$ext = "exe_" if ( ( $scanable )  &&  ( $scanable == 1 ) );
				}
		}
		
	my $new_name = $hex_md5;
	$new_name = $hex_md5 . "." . $ext if ( $ext );
	
	my $full_new_name = $new_name;
	$full_new_name = $dir . "\\" . $new_name;
	
	# Is the file already named the right thing?
	return( $full_new_name, undef, undef ) if ( $full_new_name eq $fullpath );
	
	my $ok = rename( $fullpath, $full_new_name );


	# If renamed ok, return here
	if ( $ok )
		{	return( $full_new_name, 1, undef );
		}
		
		
	# If not ok, was it because the file already exists?
	if ( -f $full_new_name )
		{	rename( $full_new_name, $full_new_name );  # Rename it again to make sure the upper/lowercase is right

			# Is there an upper/lower case problem?
			if ( lc( $fullpath ) eq lc( $full_new_name ) )
				{	return( $full_new_name, 1, undef );
				}
				
			# Get rid of the duplicate	
			unlink( $fullpath );
			return( $full_new_name, undef, 1 );
		}
	
	# If I got to here, then I couldn't rename it at all
	return( $fullpath, undef, undef );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "DelMD5";
	
    print <<".";

Usage: delmd5 [options]

This utility deletes duplicated files by comparing MD5 hashes of the files. 

Possible options are:

  -c, --create HASHLIST    to create a HASHLIST file of 32 hex bytes
  -d, --dir DIR            the directory DIR to start in, default is the current
  -f, --fileid FILEIDLIST  to create a File ID List file of 56 hex bytes
  -k, --keep               to keep the duplicated files
  -l, --load HASHLIST      to load a list of MD5 hashes to delete duplicates of
                           Each line of the HASHLIST file should be 32 hex bytes
  -r, --rename             to rename unique files to their md5 hash name
  -s, --subdir             the check subdirectories
  -x, --executable         to rename Win32 programs to *.exe_

  -h, --help               print this message and exit

.

exit;
}


################################################################################

__END__

:endofperl
