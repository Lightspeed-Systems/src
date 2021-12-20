################################################################################
#!perl -w
#
# StringSearch - search in files for a string.  Upper-lower case, wide character
# insensitive
#
# Rob McCarthy - September 7, 2009
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;



# Options
my $opt_help;
my $opt_verbose;

my $_version = "1.0.0";




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
        "v|verbose"			=>	\$opt_verbose,
        "h|help"			=>	\$opt_help
    );
	

    print "StringSearch\n";


    &Usage() if ( $opt_help );
	
	my $string = shift;
	&Usage() if ( ! $string );


	my $file = shift;
	&Usage() if ( ! $file );
		
	my @files = &Filespec( $file );

	foreach ( @files )
		{	my $fullfile = $_;
			next if ( ! defined $fullfile );
			&StringSearch( $string, $fullfile );
		}
		
	print "\nDone\n";
	
    exit;
}



################################################################################
#
sub StringSearch( $$ )
#
#  Given a sting and a file, print any offsets that contain the string
#
################################################################################
{	my $string		= shift;
	my $fullfile	= shift;

	print "Searching $fullfile ...\n";
	
	my $file_size = -s $fullfile;
	return( undef ) if ( ! $file_size );
	
	return( undef ) if ( ! open( READFILE, "<$fullfile" ) );

	binmode( READFILE );
	
	my $count = 0 + 0;
	
	my $buf;
	my $nbytes = sysread( READFILE, $buf, $file_size, 0 );

	close( READFILE );	
	
	# Do lowercase compares
	$buf = lc( $buf );
	
	# First do a straight compare
	$string = lc( $string );
	
	my $offset = index( $buf, $string, 0 );
	
	# Did I find anything?
	if ( $offset != -1 )
		{	my $hoffset = &HexOffset( $offset );
			print "Found string \"$string\" at $offset or $hoffset\n";
			$count++;
			
			while ( $offset != -1 )
				{	my $position = $offset + length( $string );
					$offset = index( $buf, $string, $position );
					
					if ( $offset != -1 )
						{	$hoffset = &HexOffset( $offset );
							print "Found string \"$string\" at $offset or $hoffset\n";
							$count++;	
						}
				}
		}
		
	# Now look for a wide character
	my @char = split //, $string;

	my $wide_string;

	foreach ( @char )
		{	my $char = $_;
			$wide_string .= $char . "\x00" if ( defined $wide_string );
			$wide_string = $char . "\x00" if ( ! defined $wide_string );
		}

	$offset = index( $buf, $wide_string, 0 );
	
	# Did I find anything?
	if ( $offset != -1 )
		{	my $hoffset = &HexOffset( $offset );
			print "Found wide string \"$string\" at $offset or $hoffset\n";
			
			while ( $offset != -1 )
				{	my $position = $offset + length( $string );
					$offset = index( $buf, $string, $position );
			
					if ( $offset != -1 )
						{	$hoffset = &HexOffset( $offset );
							print "Found wide string \"$string\" at $offset or $hoffset\n";
							$count++;	
						}
				}
		}

	return( $count );
}



################################################################################
#
sub HexOffset( $ )
#
#  Given an offset, return it in hex
#  and match.
#
################################################################################
{	my $offset = shift;
	
	my $hoffset = "0x" . sprintf( "%05x", $offset );
	
	return( $hoffset );
}



################################################################################
#
sub Filespec( $ )
#
#  Given a filespec, that could be wildcarded, return the list of files that exist
#  and match.
#
################################################################################
{	my $file = shift;
	
	my @files;
	
	return( @files ) if ( ! defined $file );
	
	# Do I have a wildcard specification?
	if ( ( $file =~ /\*/ )  ||  ( $file =~ m/\?/ ) )
		{	@files = &MyGlob( $file );
			
			return( @files ) if ( $#files < 0 );
		}
	else	# There could be a list of files separated by ';'
		{	my @list = split /;/, $file;
			foreach ( @list )
				{	my $list = $_;
					next if ( ! $list );
					next if ( ! -s $list );
					
					push @files, $list;
				}
				
			# Quit here if I didn't find anything
			return( @files ) if ( $#files < 0 );
		}
			
	return( @files );
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

	my $cwd;
	
	my ( $dir, $short ) = &SplitFileName( $filespec );

	if ( defined $dir )
		{	$cwd = getcwd;
			$cwd =~ s#\/#\\#g;
			$cwd =~ s/\\$//;   # Trim off a trailing slash
			
			chdir( $dir );
		}
		
	my @files = glob( $short );

	return( @files ) if ( ! defined $dir );

	chdir( $cwd ) if ( defined $cwd );
	
	my @return;
	
	foreach( @files )
		{	my $file = $_;
			next if ( ! defined $file );
			
			my $filename = "$dir\\$file";
			$filename = $dir . $file if ( $dir =~ m/\\$/ );
			
			push @return, $filename;
		}
		
	return( @return );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";
Given a filespec, search for a sting.

Usage: StringSearch String Filespec
    
  -h, --help               display this help and exit
  -v, --version            display version information and exit
.
    exit;
}



################################################################################

__END__

:endofperl
