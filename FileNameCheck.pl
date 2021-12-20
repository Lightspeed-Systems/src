################################################################################
#!perl -w
#
#  FileNameCheck.pl
#
#  A quick little Perl script to check to see if file names in a list of files
#  exist in a subdirectory
#
#  Copyright Lightspeed Systems Inc. 2016
#  Written by Rob McCarthy 4/2/2016
#
################################################################################


use strict;
use warnings;


use Cwd;

use Categorize::File;


my @fileList;				# This is the list of files that have list of files in them
my @list;					# The current list that I am checking
my %list;					# A hash of the current list - key is lc(short file), values are the filenames
my $dir_count = 0 + 0;		# The total number of directories that I checked
my $f_count   = 0 + 0;		# The total number of files I checked
my $opt_verbose	= undef;
my @subdirectory_data_files;		# This is the compare data from the filenames of all the files I found in all of the subdirectories 
my @matched;				# The list of matched files

# Rakefile changelog license install 
my @ignore_list = qw( build.rb main.cpp contents.xcworkspacedata project.pbxproj info.plist configure.ac configure.in .rspec makefile.in makefile.am gemfile version.rb version readme.markdown Rakefile changelog license install .gitignore .git\\index readme.md Makefile .project readme install.rb config.guess config.sub configure readme.txt .classpath project.properties );


################################################################################
#
MAIN:
#
################################################################################
{ 

	my $inputfile = shift;
	
	my $cwd = getcwd();

	$cwd =~ s/\//\\/g;	# Make sure that it is a windows type directory
	
	my $total = 0 + 0;
	if ( defined $inputfile )
		{	push @fileList, $inputfile;
		}
	else 
		{	@fileList = &FileListDir( $cwd );
		}
		
	
	&SetLogFilename( "FileNameCheck.log", undef );
	
	
	my $match_list = $cwd . "\\FileNameMatched.log";

	&lprint( "Writing FileNameCheck results to $match_list ...\n" );


	foreach ( @ignore_list )
		{	my $ignore_it = $_;
			next if ( ! length( $ignore_it ) );
			&lprint( "Ignoring files named $ignore_it\n" );
		}

	
	# Create the empty match list file	
	open( OUTPUT, ">$match_list" ) or die( "Error opening match list file $match_list: $!\n" );
	close( OUTPUT );
	
	my $number_of_filelists = 0 + 0;										   
	foreach( @fileList )
		{	my $file_list = $_;
			
			next if ( ! -s $file_list );

			# Append to the match list file ...
			open( OUTPUT, ">>$match_list" ) or die( "Error opening match list file $match_list: $!\n" );

			$number_of_filelists++;
			
			my $found_count = &Search( $cwd, $file_list );
			lprint "Checked $f_count files in $dir_count directories for the $file_list file list\n";	
			$f_count   = 0 + 0;
			
			lprint "Found $found_count matches for filenames from $file_list\n";
			$total += $found_count;
			close( OUTPUT );
		}
	
	lprint "Found $total filenames matching files from all the $number_of_filelists different file lists\n";	
	
	
	my $match_sorted_list = $cwd . "\\FileNameSorted.log";

	&lprint( "Writing sorted FileNameCheck results to $match_sorted_list ...\n" );
	
	# Create the sorted match list file	
	open( OUTPUT, ">$match_sorted_list" ) or die( "Error opening match sorted list file $match_sorted_list: $!\n" );
	my @sorted = sort( @matched );

	my $repo = "ios_mf";
	my $repo_file = $cwd . "\\" . $repo . ".log";
	
	&lprint( "Opening repo file $repo_file ...\n" );
	open( REPO, ">$repo_file" ) or die( "Error opening repo list file $repo_file: $!\n" );
	
	foreach( @sorted )
		{	my $match = $_;
			print OUTPUT "$match\n";
			
			# Is it the same repo?
			my @parts = split /\t/, $match;
			my $new_repo = $parts[ 0 ];
			$new_repo =~ s/^Repo\: //;
			
			if ( $repo eq $new_repo )
				{	print REPO "$match\n";
					next;
				}
			
			# Close the existing repo file and open a new one
			close( REPO );
			$repo = $new_repo;
			$repo_file = $cwd . "\\" . $repo . ".log";
			
			&lprint( "Opening repo file $repo_file ...\n" );
			open( REPO, ">$repo_file" ) or die( "Error opening repo list file $repo_file: $!\n" );
			
			print REPO "$match\n";
		}
		
	close( OUTPUT );
	close( REPO );

	lprint "Done\n";
	
	&CloseLogFile();
	
	
exit;

}



my $found_count;
my $subdirectories_loaded;	# True if I have already loaded all the filenames from all the subdirectories
################################################################################
#
sub Search( $$ )
#
#  Given a directory and a file containing a list of files to seach for
#  Print the directory that any matching file is found
#
################################################################################
{	my $dir			= shift;
	my $file_list	= shift;	# This is the file name of a file that should have a list of filenames to check for
	
	print "Searching $dir with file list $file_list ...\n";
	
	my $file_handle;
	if ( ! open( $file_handle, "<$file_list" ) )
			{	print( "Error opening $file_list: $!\n" );
				exit;
			}	

	my  $count = 0 + 0;
	@list = ();	# Empty the global list
	%list = ();
	
	while ( my $filename = <$file_handle> )
		{	next if ( ! $filename );

			$filename =~ s/\n//g;
			$filename =~ s/\r//g;
			
			$filename =~ s/\//\\/g;
			
			next if ( ! length( $filename ) );
			
			# Get rid of leading whitespace
			$filename =~ s/^\s+//;
			$filename =~ s/^\t+//;
			
			# Get rid of trailing whitespace
			$filename =~ s/\s+$//;
			$filename =~ s/\t+$//;
			
			next if ( ! length( $filename ) );
			
			$count++;
			
			# Can I ignore it?
			my $ignore_it;
			foreach ( @ignore_list )
				{	my $qignore = quotemeta( $_ );
					$ignore_it = 1 if ( $filename =~ m/$qignore$/i );
				}
			
			next if ( $ignore_it );
			
			push @list, $filename;
			
			my ( $listdir, $listshortfile ) = &SplitFileName( $filename );
			my $lc_listshortfile = lc( $listshortfile );

			# Build up the list hash
			if ( ! defined $list{ $lc_listshortfile } )
				{	$list{ $lc_listshortfile } = $filename;
				}
			else
				{	my $val = $list{ $lc_listshortfile };
					$val = $val . "\t" . $filename;
					
					$list{ $lc_listshortfile } = $val;
				}
				
			print "Added $filename to the global list\n" if ( $opt_verbose );
		}

	close( $file_handle );

	$found_count = 0 + 0;
	lprint "Got $count filenames from $file_list to check ...\n";
	
	
	# If I haven't already read in all the subdirectory data then I have to run it this way once
	if ( ! $subdirectories_loaded )
		{	&lprint( "Loading and checking filenames from subdirectories ...\n");
			my $found = &Subdirectory( $dir, $file_list );
			$subdirectories_loaded = 1;
		}
	else	# I already have everything I need to do the file check in memory
		{	&lprint( "Checking filenames from preloaded subdirectory list ...\n");
			my $found = &SubdirectoryLoaded( $file_list );
		}
		
	return( $found_count );
}



################################################################################
#
sub SubdirectoryLoaded( $ )
#
#  Given a directory, see if the global @list of file names matches anything
#  Print out any matches
#
################################################################################
{	my $file_list	= shift;	# This is the name of the file_list file that I am current checking
	
	print "Checking loaded subdirectories for filenames from $file_list ...\n" if ( $opt_verbose );
	
	my $found	= 0 + 0;
	my $count = 0 + 0;
	foreach( @subdirectory_data_files )
		{	my $data = $_;
			my ( $lc_shortfile, $repo, $path ) = split /\t/, $data;
			
			$f_count++;
			$found = &CheckDataFile( $lc_shortfile, $repo, $path, $file_list );
			$found_count++ if ( $found );
		}
		
	return( $found );	
}



################################################################################
#
sub Subdirectory( $$ )
#
#  Given a directory, see if the global @list of file names matches anything
#  Print out any matches
#
################################################################################
{	my $dir			= shift;	# This is the directory to check
	my $file_list	= shift;	# This is the name of the file_list file that I am current checking
	
	print "Checking subdirectory $dir for filenames from $file_list ...\n" if ( $opt_verbose );
	$dir_count++;
	
 	my $dir_handle;
	if ( ! opendir( $dir_handle, $dir ) )
		{	print "Unable to open directory $dir: $!\n";
		    exit;
		}

	my $found	= 0 + 0;
	while ( my $file = readdir( $dir_handle ) )
		{		next if ( ! defined $file );

				next if ( $file eq "." );
				next if ( $file eq ".." );
				next if ( $file eq ".git" );

				my $path = $dir . "\\" . $file;
				
				# Go recursive on subdirectories
				if ( -d $path )
					{	&Subdirectory( $path, $file_list );
						next;
					}
				
				$f_count++;
				$found = &CheckFile( $path, $file_list );
				$found_count++ if ( $found );
		}

 	closedir( $dir_handle );
	
	return( $found );
}



################################################################################
#
sub CheckDataFile( $$$$ )
#
#  Given the file data, do I have a match?
#  Return true if I found a match
#
################################################################################
{	my $lc_shortfile	= shift;
	my $repo			= shift;
	my $path			= shift;
	my $file_list		= shift;	# This is the name of the file_list file that I am current checking
	
	print "Checking file data from $path to see if it matches anything from $file_list ...\n" if ( $opt_verbose );

	my ( $listdir, $listfile ) = &SplitFileName( $file_list );
	
	# Does the list hash have this lc_shortfile?
	my $val = $list{ $lc_shortfile };
	
	# If not match - then it doesn't match!
	return( undef ) if ( ! defined $val );
	
	my @val_matched = split /\t/, $val;
	
	foreach( @val_matched )
		{	my $list_item = $_;
			my $match = "Repo: $repo\tList: $listfile\tPath: $path\tMatched: $list_item";
			print OUTPUT "$match\n";
					
			push @matched, $match;
		}
		
	return( 1 );
}



################################################################################
#
sub CheckFile( $$ )
#
#  Given a full path of a file, does it match anything in the current @list?
#  Return true if I found a match
#
################################################################################
{	my $path		= shift;
	my $file_list	= shift;	# This is the name of the file_list file that I am current checking
	
	print "Checking file $path to see if it matches anything from $file_list ...\n" if ( $opt_verbose );

	my ( $dir, $shortfile ) = &SplitFileName( $path );
	my $lc_shortfile = lc( $shortfile );

	my ( $listdir, $listfile ) = &SplitFileName( $file_list );
	my @parts = split /\\/, $path;
	my $repo = $parts[ 2 ];
		
	# Keep a the list of the data used so that I only have to do this once
	push @subdirectory_data_files, "$lc_shortfile\t$repo\t$path";
	
	# Does the list hash have this lc_shortfile?
	my $val = $list{ $lc_shortfile };
	
	# If not match - then it doesn't match!
	return( undef ) if ( ! defined $val );
	
	my @val_matched = split /\t/, $val;
	
	foreach( @val_matched )
		{	my $list_item = $_;
			next if ( ! length( $list_item ) );

			my ( $listdir, $listshortfile ) = &SplitFileName( $list_item );
			my $match = "Repo: $repo\tList: $listfile\tPath: $path\tMatched: $list_item";
			print OUTPUT "$match\n";
					
			push @matched, $match;
		}
		
	return( 1 );
}



################################################################################
#
sub FileListDir( $ )
#
#  Look for file list types of files in the current directory
#  Return a list of what I found
#
################################################################################
{	my $dir = shift;

	my @fileList;
	
 
 	my $dir_handle;
	if ( ! opendir( $dir_handle, $dir ) )
		{	print "Unable to open directory $dir: $!\n";
		    exit;
		}


	my $count = 0 + 0;
	while ( my $file = readdir( $dir_handle ) )
		{		next if ( ! defined $file );

				next if ( $file eq "." );
				next if ( $file eq ".." );

				# Does it match a .txt type of file name?
				next if ( ! ( $file =~ m/\.txt$/i ) );
				
				my $file_list = $dir . "\\" . $file;

				# Skip subdirectories
				next if (-d $file_list );
				
				$count++;
				
				push @fileList, $file_list;
				
		}

 	closedir( $dir_handle );

	print "Found $count files that look like lists of files\n";
	
	return( @fileList ); 
}





################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "FileNameCheck";

    print <<".";
Syntax: FileNameCheck [inputfile]

Little program to check to see if file names exist in subdirectories
If inputfile is specified then that will be the only file list checked.
Otherwise, all the *.txt files in the directory will be assumed to be
lists of files to check.

Matches are written to FileNameMatched.log in the currrent directory.

.

    exit( 1 );
}





__END__

:endofperl
