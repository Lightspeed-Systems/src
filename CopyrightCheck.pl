################################################################################
#!perl -w
#
#  CopyrightCheck.pl
#
#  A quick little Perl script to check scan a list of files looking for Copyright
#  notices
#
#  Copyright Lightspeed Systems Inc. 2016
#  Written by Rob McCarthy 4/5/2016
#
################################################################################


use strict;
use warnings;


use Cwd;
use File::Copy;
use Getopt::Long;

use Categorize::File;


my $line_count = 0 + 0;	# Total number of lines printed out to OUTPUT
my $total_lines_read = 0 + 0;
my @filelist;		# The list of file to check if I an scanning by subdirectory
my $dir_count = 0 + 0;
my %found_copyright;		# A hash of the files that I found copyright in
my $opt_verbose;
my $opt_help;


################################################################################
#
MAIN:
#
################################################################################
{ 

	my $inputfile	= shift;
	my $outputfile	= shift;

    # Get the options
    Getopt::Long::Configure("bundling");

	my $outdirectory;
	
    my $options = Getopt::Long::GetOptions
    (
        "c|copy=s"	=> \$outdirectory,
        "v|verbose" => \$opt_verbose,
        "h|help"	=> \$opt_help
    );

	my $cwd = getcwd();
	$cwd =~ s/\//\\/g;	# Make sure that it is a windows type directory
	
	# A dot means the current directory
	$inputfile = $cwd if ( $inputfile eq "." );
	
	
	&Usage() if ( $opt_help );
	&Usage() if ( ! defined $inputfile );
	&Usage() if ( ( ! -s $inputfile )  &&  ( ! -d $inputfile ) );
	&Usage() if ( ! defined $outputfile );
	&Usage() if ( ( defined $outdirectory )  &&  ( ! -d $outdirectory ) );
	
	
	
	# Is the inputfile a file, or a directory?
	if ( -d $inputfile )
		{	&Subdirectory( $inputfile );
			print "Checked $dir_count directories for files\n";
			
			print "Opening $outputfile for copyright output data ...\n";
			open( OUTPUT, ">$outputfile" ) or die "Error opening $outputfile: $!\n";
			
			my $file_count = 0 + 0;
			foreach( @filelist )
				{	my $filename = $_;
					next if ( ! length( $filename ) );
					chomp( $filename );
					next if ( ! length( $filename ) );
					
					next if ( ! -s $filename );
					
					next if ( &IgnoreFile( $filename ) );
					
					&ScanFile( $filename );
					
					$file_count++;
				}
				
			close( OUTPUT );
			
			print "Scanned $file_count file(s) for copyright lines\n";
			print "Checked $total_lines_read lines in total\n";
			print "Found $line_count lines in total with non-Lightspeed copyright notices\n";
		}
	else
		{	print "Opening $inputfile for the list of files to scan ...\n";
	
			open( INPUT, "<$inputfile" ) or die "Error opening $inputfile: $!\n";
			
			print "Opening $outputfile for copyright output data ...\n";
			open( OUTPUT, ">$outputfile" ) or die "Error opening $outputfile: $!\n";
			
			my $file_count = 0 + 0;
			while ( my $filename = <INPUT> )
				{	next if ( ! length( $filename ) );
					chomp( $filename );
					next if ( ! length( $filename ) );
					
					next if ( ! -s $filename );
					
					next if ( &IgnoreFile( $filename ) );
					
					&ScanFile( $filename );
					
					$file_count++;
				}
					
			close( OUTPUT );
			close( INPUT );
			
			print "Scanned $file_count file(s) for copyright lines\n";
			print "Checked $total_lines_read lines in total\n";
			print "Found $line_count lines in total with possible non-Lightspeed copyright notices\n";
		}
	
	if ( ( defined $outdirectory )  &&  ( -d $outdirectory ) )
		{	my @sorted = sort keys %found_copyright;

			foreach( @sorted )
				{	my $filename = $_;
					next if ( ! -s $filename );
					
					my ( $dir, $shortfile ) = &SplitFileName( $filename );
					
					my $dest = $outdirectory . "\\" . $shortfile;
					my $original_dest = $dest;
					
					# Does this destination already exist?
					# If so then interate a counter
					my $found = -f $dest;
					my $num = 1;
					while ( $found )
						{	my $str = sprintf( "%03d", $num );
							$num++;
							$dest = $original_dest . "." . $str;
							$found = -f $dest;
						}
						
					print "Copying $filename to $dest ...\n";
					my $success = copy( $filename, $dest );
				}
		}
		
	print "\nDone\n";
	
exit;

}



################################################################################
#
sub IgnoreFile( $ )
#
#  Return true if I shoud ignore this file
#
################################################################################
{	my $filename		= shift;	# filename to check
	
	return( undef ) if ( ! defined $filename );
	
	# Ignore zip files
	return( 1 ) if ( $filename =~ m/\.zip$/i );
	
	# Ignore .git\hooks\pre-rebase.sample files
	return( 1 ) if ( $filename =~ m/\.git\\hooks\\pre\-rebase\.sample$/i );
	
	return( undef );
}



################################################################################
#
sub Subdirectory( $ )
#
#  Given a directory, see if the global @list of file names matches anything
#  Print out any matches
#
################################################################################
{	my $dir			= shift;	# This is the directory to check
	
	print "Checking directory $dir for files ...\n";
	$dir_count++;
	
 	my $dir_handle;
	if ( ! opendir( $dir_handle, $dir ) )
		{	print "Unable to open directory $dir: $!\n";
		    exit;
		}

	my $file_no = 0 + 0;
	while ( my $file = readdir( $dir_handle ) )
		{		next if ( ! defined $file );

				next if ( $file eq "." );
				next if ( $file eq ".." );
				next if ( $file eq ".git" );

				my $path = $dir . "\\" . $file;
				
				# Go recursive on subdirectories
				if ( -d $path )
					{	&Subdirectory( $path );
						next;
					}
				
				push @filelist, $path;
				$file_no++;
		}

 	closedir( $dir_handle );
	
	print "Found $file_no files in directory $dir\n" if ( $file_no );
	print "Found no files in directory $dir\n" if ( ! $file_no );
	
	return( 1 );
}



################################################################################
#
sub ScanFile( $ )
#
#  Scan a given file for lines with copyright in them
#  Print each copyright line to OUTPUT
#
################################################################################
{	my $filename = shift;

	print "Scanning $filename ...\n";
	
	open( SCANFILE, "<$filename" ) or die "Error opening $filename: $!\n";
	
	my $line_no = 0 + 0;
	my $last_line;
	my $last_line_no;
	my $print_next_line;
	
	while ( my $line = <SCANFILE> )
		{	$line_no++;
			$total_lines_read++;
			
			if ( ! length( $line ) )
				{	$last_line = undef;
					next;
				}
				
			chomp( $line );
			if ( ! length( $line ) )
				{	$last_line = undef;
					next;
				}
						
			if ( $print_next_line )
				{	my $p_line = &PrintLine( $line, undef );
					print OUTPUT "$filename\tLine: $line_no\t$p_line\n" if ( defined $p_line );;
					$print_next_line = undef;
				}
				
			# Look for copyright or for (c) 
			my $match;
			$match = 1 if ( $line =~ m/copyright/i );
			$match = 1 if ( $line =~ m/\(c\)/i );
			
			if ( ! $match )
				{	$last_line_no = $line_no;
					$last_line = $line;
					next;
				}
				
			next if ( ( $line =~ m/lightspeed/i ) );
			
			$found_copyright{ $filename } = 1;
			
			my $p_line = &PrintLine( $last_line, undef );
			print OUTPUT "$filename\tLine: $last_line_no\t$p_line\n" if ( length( $p_line ) );
			
			$p_line = &PrintLine( $line, 1 );
			print OUTPUT "$filename\tLine: $line_no\t$p_line\n";
			
			$print_next_line = 1;
			
			$line_count++;
		}

	print "Checked $line_no lines from $filename\n";
	
	close( SCANFILE );

	return( 1 );
}



################################################################################
#
sub PrintLine( $$ )
#
#  Given a line, return as printable a line as possible
#
################################################################################
{	my $line		= shift;
	my $copyright	= shift;	# True if it is a copyright line
	
	return( undef ) if ( ! defined $line );
	
	my $p_line = $line;
	$p_line =~ s/^\s+//;
	$p_line =~ s/\s+$//;
	
	# Short lines are ok
	return( $p_line ) if ( length( $p_line ) < 80 );
	
	if ( ! $copyright )
		{	$p_line = substr( $p_line, 0, 80 ) if ( length( $p_line ) > 80 );
			
			return( $p_line );
		}
	
	my ( $pre, $post ) = split /copyright/i, $p_line;
	$p_line = "Copyright" . $post;	
	
	$p_line = substr( $p_line, 0, 80 ) if ( length( $p_line ) > 80 );

	return( $p_line );	
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "CopyrightCheck";

    print <<".";
Syntax: CopyrightCheck input outputfile

Given a list of files to check in input, scan each file in the list and 
output any lines with a copyright on them.

If input if a directory, then all the files in that directory and any
subdirectories will be scanned.
.

    exit( 1 );
}



__END__

:endofperl
