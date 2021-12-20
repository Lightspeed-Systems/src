################################################################################
#!perl -w
#
# Rob McCarthy's IWF Process utility
#  Copyright 2009 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long;
use Content::File;


my $opt_version;	# Display version # and exit
my $opt_help;		# Display help and exit
my $opt_debug;		# True if debugging - main difference is the URLs used
my $version			= "1.00.00";	# Current version number



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
		"v|version"		=> \$opt_version,
		"h|help"		=> \$opt_help,
		"x|xxxdebug"	=> \$opt_debug
    );

	
	&Usage() if ( $opt_help );
	
	my $file = shift;
	
	&Usage() if ( ! $file );
	
	print "Processing IWF file $file ...\n";
	
	if ( ( ! $file )  ||  ( ! -f $file ) )
		{	print "Can not file IWF formatted file $file\n";
			exit;
		}
	
    my $dir = getcwd;
    $dir =~ s#\/#\\#gm;

    &IWFProcess( $dir, $file );
    
	exit;
}



################################################################################
# 
sub IWFProcess( $$ )
#
################################################################################
{	my $dir		= shift;
	my $file	= shift;


	return( undef ) if ( ! defined $dir );
	return( undef ) if ( ! -d $dir );
	
	return( undef ) if ( ! defined $file );
	
	my $fullfile = $dir . "\\" . $file;

	return( undef ) if ( ! -f $fullfile );
	
	
	if ( ! open( IWFFILE, "<$fullfile" )  )
		{	print "Error opening $fullfile: $!\n";
			return( undef );
		}
	
	my $counter = 0 + 0;
	
	my %url_hash;
	while ( my $line = <IWFFILE> )
		{	chomp( $line );
			next if ( ! $line );
			
			$line =~ s/^"+//;
			$line =~ s/"+$//;
			
			my $url = &CleanUrl( $line );
			
			next if ( ! $url );
			
			$url_hash{ $url } = 1;
			$counter++;
		}
	
	close( IWFFILE );

	print "Read $counter valid URLs from $fullfile\n";
	
	exit if ( ! $counter );

	my @sorted = sort keys %url_hash;
	my $iwf_data = "LIGHTSPEEDIWF\n";
	foreach ( @sorted )
		{	my $url = $_;
			next if ( ! $url );
			
			# Add the URL, a tab, and the porn.child category number
			$iwf_data .= $url . "\t94\n";		
		}
		
	# Add an extra line feed at the end
	$iwf_data .= "\n";
	
	
	my $clear_file = $dir . "\\Clear.txt";

	if ( ! open( CLEAR, ">$clear_file" ) )
		{	print "Error opening $clear_file: $!\n";
			return( undef );
		}
		
	print CLEAR $iwf_data;
	
	close( CLEAR );

	
	# This is the secret key used by the Security Agent for these announcments
	my $key = "QWmyxlplyx_0XImfg_;:{o}njk6^78ujiaQASgVMioUNU_uiUIbb_bxp";
	
	my $encrypt = &Encrypt( $iwf_data, $key );
	
	my $cache_file = $dir . "\\ContentCache.dat";
	
	if ( ! open( CACHE, ">$cache_file" ) )
		{	print "Error opening $cache_file: $!\n";
			return( undef );
		}
		
	binmode( CACHE );

	print CACHE $encrypt;
	
	close( CACHE );
	
	print "Created file $cache_file\n";
	
	return( 0 );
}



################################################################################
# 
sub Encrypt( $$ )
#
#	Given a some data and a key, return the encrypted data in hex format
#   Pad out the data with spaces
#
################################################################################
{	my $data = shift;
	my $key = shift;
	
use Crypt::Blowfish_PP;
	return( undef ) if ( ! defined $data );
	return( undef ) if ( ! defined $key );
	
	my $blowfish = Crypt::Blowfish_PP->new( $key );
	return( undef ) if ( ! defined $blowfish );
	
	# The blowfish implemetation takes data in 8 byte chunks so split up stuff
	my $len = length( $data );
	
	my $pad_len = 8 - ( $len % 8 );
	$pad_len = 0 + 0 if ( $pad_len == 8 );
	
	my $pad;
	$pad = "\x20" x $pad_len;
	
	my $chunk_data = $data;
	$chunk_data = $data . $pad if ( $pad_len );
	
	my $chunk_len = length( $chunk_data );
	
	my $bytes = 0 + 0;
	my $encrypt_data;
	
	while ( $bytes < $chunk_len )
		{	my $chunk = substr( $chunk_data, $bytes, 8 );
			my $encrypt = $blowfish->encrypt( $chunk );
			
			if ( defined $encrypt_data )
				{	$encrypt_data .= $encrypt;
				}
			else
				{	$encrypt_data = $encrypt;
				}
				
			$bytes += 8;
		}
	
	
	return( $encrypt_data );
}



################################################################################
# 
sub Decrypt( $$ )
#
#	Given some hex encrpted data and a key, return the original data
#   The original data may be spaced padded to an even 8 bytes
#
################################################################################
{	my $encrypt_data = shift;
	my $key = shift;
	
	return( undef ) if ( ! defined $encrypt_data );
	
	my $encrypt_len = length( $encrypt_data );
	
	# The encrpyt length should be even divisible by 8
	return( undef ) if ( $encrypt_len % 8);
	
	my $blowfish = Crypt::Blowfish_PP->new( $key );
	return( undef ) if ( ! defined $blowfish );
		
	my $bytes = 0 + 0;
	my $chunk_data;
	
	while ( $bytes < $encrypt_len )
		{	my $encrypt = substr( $encrypt_data, $bytes, 8 );
			my $decrypt = $blowfish->decrypt( $encrypt );
			
			if ( defined $chunk_data )
				{	$chunk_data .= $decrypt;
				}
			else
				{	$chunk_data = $decrypt;
				}
				
			$bytes += 8;
		}
	
	return( $chunk_data );
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IWFProcess";

    print <<".";

IWFProcess iwf-file

This utility takes a file in the IWF format and creates a new file in the
Lightspeed ContentCache format.  The new file is always called
"ContentCache.dat".  It also creates a file called Clear.txt that shows the
data as clear text.


  -h, --help             display this help and exit
  -v, --version          display version information and exit
.
    &StdFooter;

    exit( 1 );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "IWFProcess";

    print <<".";
$me version: $version
.
    &StdFooter;

    exit( 1 );
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
