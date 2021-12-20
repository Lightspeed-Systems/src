################################################################################
#!perl -w

# Rob McCarthy's UrlList command to build a list of URLs from the token files in a directory


# Pragmas
use strict;
use warnings;


use Getopt::Long;
use File::DosGlob;
use Content::File;
use Cwd;


# Options
my $opt_help;
my $opt_version;


my $_version = "1.0.0";
my %urls;	# Global hash of urls
my $opt_output_file = "UrlList.txt";



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
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	my $token_directory = getcwd;
	$token_directory =~ s#\/#\\#gm;
			
	if ( ! opendir( DIR, $token_directory ) )
		{	&lprint( "Cannot opendir $token_directory: $!\n" );
			return( undef );
		}
		
	my @files = readdir(DIR);
	closedir(DIR);

	%urls = ();
	

	foreach ( @files )
		{	next if ( ! defined $_ );
			my $short_file = $_;
				
			my $url;	
			if ( $short_file =~ m/\.links\.txt$/i )
				{	$url = $short_file;
					$url =~ s/\.links\.txt$//;
				}
			elsif ( $short_file =~ m/\.labels\.txt$/i )
				{	$url = $short_file;
					$url =~ s/\.labels\.txt$//;
				}
			elsif ( $short_file =~ m/\.tokens\.txt$/i )
				{	$url = $short_file;
					$url =~ s/\.tokens\.txt$//;
				}
			elsif ( $short_file =~ m/\.site\.txt$/i )
				{	$url = $short_file;
					$url =~ s/\.site\.txt$//;
				}
			
			$urls{ $url } = 1 if ( defined $url );
		}


	print "Creating file $opt_output_file ...\n";
 

 	if ( ! open( OUTPUT, ">$opt_output_file" ) )
		{	die ( "Unable to open $opt_output_file: $!\n" );
		}
	

	my @url_list = sort keys %urls;	
	foreach ( @url_list )
		{	my $url = $_;
			next if ( ! defined $url );
			
			$url = &CleanUrl( $url );
			next if ( ! defined $url );
			
#			print "$url\n";

			if ( ! print( OUTPUT "$url\n" ) )
				{	my $err = $!;
					print "Print error on url $url: $err\n";
					die;
				}
		}

	close OUTPUT;

	print "\nDone\n";
    exit;
}




################################################################################
# 
sub ReadFile( $ )
#
################################################################################
{
	my $file = shift;

	return( 1 )  if ( ! -e $file );

	open( URLFILE, "<$file" ) or die( "Unable to open file $file: $!\n" );
   
	my $count = 0 + 0;
	while ( my $line = <URLFILE> )
		{	chomp( $line );
			next if ( ! defined $line );
  
			my $new_url = &CleanUrl( $line );
			next if ( ! defined $new_url );

			$urls{ $new_url } = 1;

# print "new url = $new_url\n";

			$count++;
		}

	close URLFILE;

	print "Read $count URLs from $file\n";

	return( 1 );
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
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
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
Usage: $me [OPTION(s)]  source (wildcard allowed) output
Combines lists of URLs into one large list
    
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
