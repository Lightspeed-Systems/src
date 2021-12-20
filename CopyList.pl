################################################################################
#!perl -w
#
#  CopyList.pl - Given a list of files in a text file, copy them to a given directory
#  Copyright 2007 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;



use Cwd;
use Getopt::Long();
use File::Copy;


use Content::File;
use Content::ScanUtil;



my $opt_help;
my $opt_filename;		# The name of the listfile
my $opt_dir;			# This is directory to copy the virus files to
my $opt_debug;
my $opt_unlink;			# True if I should delete the virus infected file after copying it
my $opt_subdir;			# True if I should preserve the subdir structure
my $opt_missfile;
my $opt_root;			# Root directory is doing an MD5 copy
my $opt_md5;			# True if MD5 formatted file
my $opt_verbose;
my %md5_hash;
			


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
		"d|md5"			=> \$opt_md5,
		"f|file=s"		=> \$opt_filename,
		"m|miss=s"		=> \$opt_missfile,
		"r|root=s"		=> \$opt_root,
		"s|subdir"		=> \$opt_subdir,
		"u|unlink"		=> \$opt_unlink,
		"v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help,
        "x|xdebug"		=> \$opt_debug
      );


    &StdHeader( "CopyList" );
	&Usage() if ( $opt_help );


	$opt_filename	= shift;
	$opt_dir		= shift;
			

	&Usage() if ( ( ! $opt_dir )  ||  ( ! $opt_filename ) );

	if ( ! -f $opt_filename )
		{	print "Unable to find list file $opt_filename\n";
			exit();
		}


	# Make sure / is converted to \
	$opt_dir =~ s#\/#\\#g;
	
	# Trim off a trailing \\
	$opt_dir =~ s/\\$//;
	if ( ! -d $opt_dir )
		{	print "Unable to find directory $opt_dir\n";
			exit();
		}


	print "Copying files from $opt_filename to $opt_dir ...\n";
	
	
	if ( ! open( INFILE, "<$opt_filename" ) )
		{	print "Error opening $opt_filename: $!\n";
			exit( 1 );	
		}
		
	
	if ( ( $opt_missfile )  &&  ( ! open( MISSFILE, ">$opt_missfile" ) ) )
		{	print "Error opening $opt_missfile: $!\n";
			exit( 1 );	
		}
		
	
	my @files;
	
	if ( ! $opt_md5 )
		{	while ( my $line = <INFILE> )
				{	chomp( $line );
					next if ( ! $line );
					
					my ( $file, $junk ) = split /\t/, $line;
					next if ( ! $file );
					
					( $file, $junk ) = split /\,/, $line;
					next if ( ! $file );
					
					# Ignore directories
					next if ( -d $file );
					
					if ( -f $file )
						{	push @files, $file;
							print "Found $file\n" if ( $opt_verbose );
							next;
						}
						
					print "Unable to find file $file\n";
					
					print MISSFILE "$file\n" if ( $opt_missfile );
				}
		}
	else
		{	while ( my $line = <INFILE> )
				{	chomp( $line );
					next if ( ! $line );
					
					my ( $file, $junk ) = split /\t/, $line;
					next if ( ! $file );
					
					( $file, $junk ) = split /\,/, $line;
					next if ( ! $file );
					
					my $md5 = $junk;
					next if ( ! $md5 );
					$md5 = lc( $md5 );
					next if ( length( $md5 ) != 32 );
					
					$md5_hash{ $md5 } = "not found";
				}
				
			my $cwd = getcwd;
			$cwd = $opt_root if ( $opt_root );
			$cwd =~ s#\/#\\#g;
			$cwd =~ s/\\$//;   # Trim off a trailing slash
	
			&DirectoryMD5( $cwd );
			
			# Pull the files I found out of the hash
			while ( my( $md5, $file ) = each( %md5_hash ) )
				{	next if ( ! $file );
					
					if ( $file eq "not found" )
						{	print "Unable to find md5 hash $md5\n";
					
							print MISSFILE "$md5\n" if ( $opt_missfile );
						}
					else
						{	push @files, $file;
						}
				}
		}
		
		
	close( INFILE );
	close( MISSFILE ) if ( $opt_missfile );
	
	&CopyList( \@files ) if ( $#files > -1 );
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub DirectoryMD5( $ )
#
################################################################################
{	my $dir = shift;

	print "Directory: $dir\n"; 
	chdir "$dir";

	my $dir_handle;
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";

	while ( my $subdir = readdir $dir_handle )
		{	
			next if ( ! defined $subdir );

			next if ( $subdir eq "." );
			next if ( $subdir eq ".." );

			if ( ! -d $subdir )
				{	my ( $md5, $ext ) = split /\./, $subdir, 2;
					next if ( ! $md5 );
					next if ( length( $md5 ) != 32 );
					$md5 = lc( $md5 );
					next if ( ! exists( $md5_hash{ $md5 } ) );
					
					my $fullfile = "$dir\\$subdir";
					$md5_hash{ $md5 } = $fullfile;		 
				}
			else	
				{	my $fulldir = "$dir\\$subdir";

					&DirectoryMD5( $fulldir );

					chdir( $dir );
				}
         	}


	closedir $dir_handle;

	return( 0 );
}




################################################################################
# 
sub CopyList( $ )
#
#	Copy the files in the filelist hash
#
################################################################################
{	my $files_ref = shift;
	
	print "Copying the files ...\n";
	
	my $copy_count = 0 + 0;
	
	foreach ( @$files_ref )
		{	my $file = $_;
			
			next if ( ! $file );
							
			my ( $dir, $short ) = &SplitFileName( $file );
			
			next if ( ! $short );
			
			
			my $dest_dir = $opt_dir;
			
			
			# Make subdirectories like in the Virus Archive
			if ( $opt_subdir )
				{	$dir =~ s#\/#\\#g;
					my @parts = split /\\/, $dir;

					my $subdir = $parts[ 2 ] if ( $parts[ 2 ] );
					
					for ( my $i = 0 + 3;  $i <= $#parts;  $i++ )
						{	my $part = $parts[ $i ];
							next if ( ! defined $part );
							next if ( $part eq "" );
							
							$subdir .= "\\" . $part if ( defined $subdir );
							$subdir = "\\" . $part if ( ! defined $subdir );
						}
						
					$dest_dir = $opt_dir . "\\$subdir" if ( defined $subdir ); 
					$dest_dir = $opt_dir if ( ! defined $subdir ); 
				}
				

			my $ok = &MakeDirectory( $dest_dir );
			if ( ! $ok )
				{	print "Error making directory $dest_dir: $!\n";
					next;
				}
				
			my $dest = $dest_dir . "\\$short";
			
			# Add an underscore the file destingation filename if it doesn't already have one
			$dest =~ s/\_+$//;
			$dest .= '_' if ( ! ( $dest =~ m/\_$/ ) );
			
			print "Copying $file to $dest ...\n";
			
			$ok = copy( $file, $dest );
			
			if ( ! $ok )
				{	my $err = $^E;
					print "Error copying $file to $dest: $err\n";
					next;	
				}
				
			$copy_count++;		
			unlink( $file ) if ( $opt_unlink );
		}
		
	return( $copy_count );
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
sub Usage
#
################################################################################
{
    print <<".";

Usage: CopyList listfile destdir [options]

This utility copies a list of files to the destination directory.
The listfile should be a text file, tab separated, with the filename in the
first column.

Possible options are:

  -d, --md5               copy an MD5 format list
  -m, --missing MISSFILE  write to MISSFILE the files that don't exist
  -r, --root ROOTDIR      root directory of MD5 format copy
  -s, --subdir            keep the subdirectory structure
  -v, --verbose
  -u, --unlink            delete the file after copying
  -h, --help              print this message and exit

.

exit;
}



################################################################################

__END__

:endofperl
