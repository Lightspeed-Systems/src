################################################################################
#!perl -w
#
#  FileSizes.pl
#
#  Scan through the subdirectories and calculation files sizes and line counts.
#
#  Copyright Lightspeed Systems Inc. 2016
#  Written by Rob McCarthy 4/5/2016
#
################################################################################


use strict;
use warnings;


use Cwd;
use Categorize::File;


my $line_count = 0 + 0;	# Total number of lines printed out to OUTPUT
my $total_lines_read = 0 + 0;
my $dir_count = 0 + 0;

my %file_type_lines;
my %file_type_sizes;
my %file_type_count;


################################################################################
#
MAIN:
#
################################################################################
{ 
	my $inputdir	= shift;
	my $outputfile	= shift;

	
	&Usage() if ( ! defined $inputdir );
	&Usage() if ( ! -d $inputdir );
	&Usage() if ( ! defined $outputfile );
	
	
	my $cwd = getcwd();

	$cwd =~ s/\//\\/g;	# Make sure that it is a windows type directory
	
	$inputdir = $cwd if ( $inputdir eq "." );

	&Subdirectory( $inputdir );

	print "Checked $dir_count directories for files\n";
	
	print "Opening $outputfile for results ...\n";
	open( OUTPUT, ">$outputfile" ) or die "Error opening $outputfile: $!\n";
		
	my @keys = sort keys %file_type_lines;
	
	my $total_lines = 0 + 0;
	my $total_mb    = 0 + 0;
	my $total_count = 0 + 0;
	
	foreach( @keys )
		{	my $key = $_;
			next if ( ! defined $key );
			
			my $lines = $file_type_lines{ $key };
			my $sizes = $file_type_sizes{ $key };
			my $count = $file_type_count{ $key };
			my $mb = $sizes / ( 1024 * 1024 );
			
			next if ( $count < 11 );
			
			my $text = sprintf( "%16s %5d files\t%6d lines\t%2.2f MB", $key, $count, $lines, $mb );
			
			$total_lines += $lines;
			$total_mb	 += $mb;
			$total_count += $count;
			
			print "$text\n";
			
			print OUTPUT "$text\n";
		}
		
	my $text = sprintf( "%16s %5d files\t%6d lines\t%2.2f MB", "Total", $total_count, $total_lines, $total_mb );
	print "\n$text\n";
	print OUTPUT "\n$text\n";
	
	close( OUTPUT );
				
	print "\nDone\n";
	
exit;

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
	
#	print "Checking directory $dir for files ...\n";
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
				
				next if ( &IgnoreFile( $path ) );
				&CountFile( $path );
				
				$file_no++;
		}

 	closedir( $dir_handle );
	
#	print "Found $file_no files in directory $dir\n" if ( $file_no );
#	print "Found no files in directory $dir\n" if ( ! $file_no );
	
	return( 1 );
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
	
	return( 1 ) if ( $filename =~ m/\.zip$/i );
	return( 1 ) if ( $filename =~ m/\.gz$/i );
	return( 1 ) if ( $filename =~ m/\.bak$/i );
	return( 1 ) if ( $filename =~ m/\.bmp$/i );
	return( 1 ) if ( $filename =~ m/\.img$/i );
	return( 1 ) if ( $filename =~ m/\.bak$/i );
	return( 1 ) if ( $filename =~ m/\.cron$/i );
	return( 1 ) if ( $filename =~ m/\.dmg$/i );
	return( 1 ) if ( $filename =~ m/\.docx$/i );
	return( 1 ) if ( $filename =~ m/\.ico$/i );
	return( 1 ) if ( $filename =~ m/\.log$/i );
	return( 1 ) if ( $filename =~ m/\.pid$/i );
	return( 1 ) if ( $filename =~ m/\.yml$/i );
	return( 1 ) if ( $filename =~ m/\.bat$/i );
	return( 1 ) if ( $filename =~ m/\.cmd$/i );
	return( 1 ) if ( $filename =~ m/\.conf$/i );
	return( 1 ) if ( $filename =~ m/\.gif$/i );
	return( 1 ) if ( $filename =~ m/\.plist$/i );
	return( 1 ) if ( $filename =~ m/\.jpg$/i );
	return( 1 ) if ( $filename =~ m/\.gitignore/i );
	return( 1 ) if ( $filename =~ m/get_request$/i );
	return( 1 ) if ( ( $filename =~ m/application\-/i )  &&  ( $filename =~ m/\.js/i ) );

	# React files
	return( 1 ) if ( $filename =~ m/react\.js$/i );
	return( 1 ) if ( $filename =~ m/react\.min\.js$/i );
	return( 1 ) if ( $filename =~ m/RTCMultiConnection\.min\.js$/i );
	return( 1 ) if ( $filename =~ m/RTCMultiConnection\.js$/i );
	return( 1 ) if ( $filename =~ m/websocket\.js$/i );
	return( 1 ) if ( $filename =~ m/websocket\.min\.js$/i );
	
	return( 1 ) if ( $filename =~ m/base\.js$/i );
	return( 1 ) if ( $filename =~ m/ui\.js$/i );
	return( 1 ) if ( $filename =~ m/winjs\.min\.js$/i );
	return( 1 ) if ( $filename =~ m/winjs\.min\.js\.map$/i );
	return( 1 ) if ( $filename =~ m/winjs\.js$/i );
	
	# Ignore .git\hooks\pre-rebase.sample files
	return( 1 ) if ( $filename =~ m/\.git\\hooks\\pre\-rebase\.sample$/i );
	
	return( undef );
}



################################################################################
#
sub CountFile( $ )
#
################################################################################
{	my $filename = shift;

	# Dont's count empty files
	return( undef ) if ( ! -s $filename );
	
#	print "$filename\n";
	
	open( COUNTFILE, "<$filename" ) or die "Error opening $filename: $!\n";
	
	my $line_no = 0 + 0;
	
	while ( my $line = <COUNTFILE> )
		{	$line_no++;
			$total_lines_read++;
		}
	
	close( COUNTFILE );

	my $ext = &MyFileExtension( $filename );
	
	# Special files
	$ext = "gemfile" if $filename =~ ( m/gemfile$/i );
	$ext = "makefile" if $filename =~ ( m/makefile$/i );
	$ext = "rakefile" if $filename =~ ( m/rakefile$/i );
	$ext = "rails" if $filename =~ ( m/rails$/i );
	$ext = "bundle" if $filename =~ ( m/bundle$/i );
	$ext = "install" if $filename =~ ( m/install$/i );
	$ext = "uninstall" if $filename =~ ( m/uninstall$/i );
	
	$ext = "none" if ( ! defined $ext );
		
	$ext = lc( $ext );
	
	my $size = -s $filename;
	
	if ( $size > ( 1024 * 1024 ) )
		{	print "Ignoring big file $filename $size\n";
			return( undef );
		}
		
	if ( defined $file_type_lines{ $ext } )
		{	my $val = $file_type_lines{ $ext };
			$val = $val + $line_no;
			$file_type_lines{ $ext } = $val;
		}
	else
		{	$file_type_lines{ $ext } = $line_no;
		}
		
		
	if ( defined $file_type_sizes{ $ext } )
		{	my $val = $file_type_sizes{ $ext };
			$val = $val + $size;
			$file_type_sizes{ $ext } = $val;
		}
	else
		{	$file_type_sizes{ $ext } = 0 + $size;
		}
		
		
	if ( defined $file_type_count{ $ext } )
		{	my $val = $file_type_count{ $ext };
			$val = $val + 1;
			$file_type_count{ $ext } = $val;
		}
	else
		{	$file_type_count{ $ext } = 0 + 1;
		}
	
	return( 1 );
}



################################################################################
# 
sub MyFileExtension( $ )
#
#  Given a filename, return the file extension, if any
#
################################################################################
{	my $filename = shift;
	
	return( undef ) if ( ! defined $filename );
	
	my ( $dir, $shortfile ) = &SplitFileName( $filename );
	return( undef ) if ( ! defined $shortfile );
	
	my $ext;
	
	my @parts = split /\./, $shortfile;
	
	# Is there a name extension?
	if ( $#parts > 0 )
		{	$ext = lc( $parts[ $#parts ] );
		}
		
	if ( defined $ext )
		{	$ext = undef if ( length( $ext ) > 16 );
			$ext = undef if ( ( $ext )  &&  ( length( $ext ) < 1 ) );
		}

	return( $ext );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "FileSizes dir output";

    print <<".";
Syntax: FileSizes dir output


All the files in the directory and any subdirectories will be have their lines 
counted and sizes totaled by file extension.
.

    exit( 1 );
}



__END__

:endofperl
