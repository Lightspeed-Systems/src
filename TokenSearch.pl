################################################################################
#!perl -w
#
# Rob McCarthy's TokenSearch program to search a directory of tokens files
# for a list of wildcard tokens
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use File::DosGlob;


use Content::File;


# Options
my $opt_dir;
my $opt_output_file;
my $opt_token_file;
my $opt_help;
my $opt_version;


my $_version = "1.0.0";
my %tokens;					# A hash of the tokens to look for
my %matched;				# A hash of tokens that I found



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
			"d|dir"			=> \$opt_dir,
			"f|file"		=> \$opt_output_file,
			"t|token"		=> \$opt_token_file,
			"v|version"		=> \$opt_version,
			"h|help"		=> \$opt_help
		);


    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	$opt_token_file		= shift if ( ! defined $opt_token_file );
	$opt_dir			= shift if ( ! defined $opt_dir );
	$opt_output_file	= shift if ( ! defined $opt_output_file );

    &Usage() if ( ! defined $opt_dir );
    &Usage() if ( ! defined $opt_output_file );
    &Usage() if ( ! defined $opt_token_file );


	# Read the wildcard tokens in first
	open( WILDCARD, "<$opt_token_file" ) or die "Unable to open wildcard token list: $!\n";

	print "Reading wildcard tokens from $opt_token_file ...\n";
	
	my $count = 0 + 0;
	while ( my $line = <WILDCARD> )
		{	chomp( $line );
			next if ( ! defined $line );
			my $token = lc( $line );
			
			$token =~ s/\s+$//;
			$token =~ s/\*$//;
			$token =~ s/\s+$//;
			$token =~ s/^\s+//;
			next if ( ! $token );
			
			# Skip any with embedded spaces or numbers
			next if ( $token =~ m/\s/ );
			next if ( $token =~ m/\d/ );
			
			# Skip any with weird characters
			next if ( $token =~ m/[\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]/ );

			$tokens{ $token } = $line;
			
			$count++;
		}

	close( WILDCARD );
	print "Read $count wild card tokens\n";
	

	die "Error opening directory $opt_dir: $!\n" if ( ! opendir( DIR, $opt_dir ) );
	open( OUTPUT, ">$opt_output_file" ) or die "Unable to open output file $opt_output_file: $!\n";
	
	
	my $file_counter = 0 + 0;
	while ( my $file = readdir( DIR ) )
		{	next if ( ! $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );
			
			my $full_file = "$opt_dir\\$file";
			
			# Ignore subdirectories
			next if ( -d $full_file );
			
			# Only look at tokens files
			next if ( ! ( $file =~ m/\.tokens\.txt$/i ) );
			
			&TokenSearch( $full_file );
		}
		

 	print "Read in $file_counter tokens files\n";

	closedir( DIR );
	close( OUTPUT );
	
	my @sort = sort keys %matched;
	
	print "\nMatched Tokens\n";
	foreach ( @sort )
		{	my $token = $_;
			next if ( ! defined $token );
			my $existing_count = $matched{ $token };
			
			print "$token\t$existing_count\n";
		}
		
	print "\nDone\n";
    exit;
}




################################################################################
# 
sub TokenSearch( $ )
#
#  Given a tokens file, search it to see if any of the wildcard tokens exist in it
#
################################################################################
{	my $full_file = shift;

	return( 1 )  if ( ! -f $full_file );

	open( TOKENFILE, "<$full_file" ) or return( undef );

	print "Reading tokens from $full_file ...\n";
	
	my ( $dir, $domain ) = &SplitFileName( $full_file );
	$domain =~ s/\.tokens\.txt//i;
	
	my $count = 0 + 0;
	my @found;
	while ( my $token = <TOKENFILE> )
		{	chomp( $token );
			next if ( ! defined $token );
			$token = lc( $token );
			
			$count++;
			
			my $found = &TokenCompare( $token );
			next if ( ! $found );
			
			push @found, $token;
		}

	close( TOKENFILE );

	print "Read $count tokens from $full_file\n";

	my @sort = sort @found;
	my $total = $#sort + 1;	
	
	if ( $total <= 0 )
		{	print "No matching tokens found for $domain\n";
			return( 0 + 0 );		
		}

	print "Found $total matching tokens for $domain\n";
	print OUTPUT "$domain\t";
	
	foreach ( @sort )
		{	next if ( ! defined $_ );
			print OUTPUT "$_ ";
		}
		
	print OUTPUT "\n";
	
	return( $total );
}



################################################################################
# 
sub TokenCompare( $ )
#
#  Given a token, compare it to the wildcard list to see if it matches
#  Return TRUE if it does, undef it it doesn't
#
################################################################################
{	my $token = shift;
	
	return( undef ) if ( ! defined $token );
	
	if ( exists $tokens{ $token } )
		{	my $existing_count = $matched{ $token };
			
			if ( $existing_count )
				{	$existing_count++;
				}
			else
				{	$existing_count = 0 + 1;
				}
				
			$matched{ $token } = $existing_count;
			
			return( 1 );
		}
	
	return( undef );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me TOKEN_LIST DIR OUTPUT_FILE
Try '$me --help' for more information.
.
    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
Usage: $me TOKEN_LIST DIR OUTPUT_FILE

Given a list of wildcard tokens, searches each domain token file in the
directory DIR, print the domains with matching tokens to the file 
OUTPUT_FILE.
    
  
  -h, --help         display this help and exit
  -v, --version      display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
$me $_version
.
    exit;
}


################################################################################

__END__

:endofperl
