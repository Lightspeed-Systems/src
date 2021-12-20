################################################################################
#!perl -w
#
# Rob McCarthy's SAExport utility to export Security Agent text files from
# the Content SQL database
#
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;
use warnings;



use Getopt::Long;


use Content::File;
use Content::UpdateDownload;



my $opt_help;
my $opt_version;
my $opt_wizard;		# True if I shouldn't display headers or footers


# Globals
my $_version = "1.0.0";



# These are various update times



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
		"w|wizard"		=> \$opt_wizard,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "SAExport" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
    &Version() if ($opt_version);

	&SAExport();
	
	&StdFooter if ( ! $opt_wizard );

exit;
}

exit;
################################################################################



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SAExport";

    bprint <<".";
Usage: $me [OPTION(s)]
Export from the Content Database to SecurityAgent format

  -h, --help             display this help and exit
  -v, --version          display version information and exit
.
     &StdFooter;

    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "SAExport";

    bprint <<".";
$me $_version
.
     &StdFooter;

    exit;
}



__END__

:endofperl
