################################################################################
#!perl -w

# Rob McCarthy's convert categorized hits domains into Squidguard format


# Pragmas
use strict;

use Getopt::Long;
use URI::Heuristic;
use Content::File;
use Content::FileUtil;
use Cwd;


# Options
my $opt_help;
my $opt_version;
my $opt_wizard;
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
        "w|wizard" => \$opt_wizard,
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

	&StdHeader( "Hits2Squid" ) if ( ! $opt_wizard );
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	my $dir = shift;
	$dir = getcwd if ( ! $dir );
	$dir = getcwd if ( $dir eq "." );
	$dir =~ s#\/#\\#gm;  # Flip slashes to backslashes
	
	&hits2squid( $dir );

    &StdFooter if ( ! $opt_wizard );
	
	exit;
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
Usage: $me [OPTION(s)]  [input-file]
    
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
