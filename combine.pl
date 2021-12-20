################################################################################
#!perl -w

# Rob McCarthy's combine command to combine multiple files into one


# Pragmas
use strict;
use warnings;


use Getopt::Long;
use File::DosGlob;
use Content::File;


# Options
my $opt_input_file;
my $opt_output_file;
my $opt_help;
my $opt_version;
my $opt_ip_only;
my $opt_domain_only;


my $_version = "1.0.0";
my %urls;	# Global hash of urls


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
        "i|ip" => \$opt_ip_only,
        "d|domain" => \$opt_domain_only,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	die "You need to enter at least 2 file names to combine\n" if ( $#ARGV < 1 );

	my @input;
    	while ( my $file = shift )
		{	push @input, $file;
			$opt_output_file = $file;
		}


	print "Combining files ...\n";

	%urls = ();
	
	my $file_counter = 0 + 0;
	foreach ( @input )
		{	my $item = $_;
			next if ( ! $item );

			# Handle wildcards
			if ( $item =~ /\*/ || $item =~ /\?/ )
				{	$item = "*" if ( $item eq "*.*" );

					# Loop through the globbed names
					my @glob_names = glob( $item );

					foreach ( @glob_names )
						{	$file_counter++;
							   
							my $file = $_;
							
							next if ( -d $file );
							
							&ReadFile( $file );
						}
				}
			else
				{	next if ( -d $item );
					
					$file_counter++;
					&ReadFile( $item );
				}
			}


 	print "\nRead in $file_counter files\n";

	#  Sort the url list
	my @url_list = sort keys %urls;

	my $url_count = $#url_list;

	print "Read $url_count unique URLs total\n";
	print "Creating file $opt_output_file ...\n";
 

 	if ( ! open( OUTPUT, ">$opt_output_file" ) )
		{	die ( "Unable to open $opt_output_file: $!\n" );
		}
		
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
  
			my ( $url, $junk ) = split /\t/, $line, 2;

			my $new_url = &CleanUrl( $url );
			next if ( ! defined $new_url );

			next if ( ( $opt_ip_only )  &&  ( ! &IsIPAddress( $new_url ) ) );
			next if ( ( $opt_domain_only )  &&  ( &IsIPAddress( $new_url ) ) );
			
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
    
  -i, --ip           only include IP addresses
  -d, --domains      only include domain names (no IPs)
  
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
