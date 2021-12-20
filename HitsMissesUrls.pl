################################################################################
#!perl -w
#
#
# Rob McCarthy's create hits and misses urls files from dumptokens directories
#
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Cwd;


# Options
my $opt_help;
my $opt_version;


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
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

	&Usage() if ( $opt_help );
	&Version() if ( $opt_version );

	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;

	my @urls = &GetUrls( "$cwd\\hits" );
	
	&WriteUrls( "hits.urls", @urls );

	@urls = &GetUrls( "$cwd\\misses" );
	
	&WriteUrls( "misses.urls", @urls );

	print "\nDone\n";

	exit;
}




################################################################################
# 
sub GetUrls( $ )
#
################################################################################
{	my $dir = shift;

 	my @urls;

	return( @urls ) if ( ! -d $dir );

	if ( !opendir( DIRHANDLE, $dir ) )
		{	print "Error opening directory $dir: $!\n";
			return( @urls );
		}

	for my $item ( readdir( DIRHANDLE ) ) 
		{	( $item =~ /^\.+$/o ) and next;
			next if ( ! ( $item =~ m/\.links\.txt$/i ) );

			my $url = lc( $item );
			$url =~ s/\.links\.txt$//;

			push @urls, $url;
		}

	return( @urls );
}



################################################################################
# 
sub WriteUrls( $@ )
#
################################################################################
{	my $file = shift;

 	my @urls = @_;

	open FILE, ">$file" or die "Error opening file $file: $!\n";

	foreach ( @urls )
		{	next if ( ! defined $_ );

			my $url = $_;
			
			print FILE "$url\n";
		}

	close FILE;

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
