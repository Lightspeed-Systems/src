################################################################################
#!perl -w
#
# Rob McCarthy's IATest source code
#  Copyright 2010 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();


use Content::File;
use Content::ImageAnalyze;



my $opt_help;
my $opt_debug;
my $opt_wizard;						# True if I shouldn't display headers or footers
my $opt_verbose;					# True if we should be chatty
my $opt_file;



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
		"x|xxx"			=> \$opt_debug,
        "h|help"		=> \$opt_help,
		"v|verbose"		=> \$opt_verbose
      );


	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
    &Usage() if ( $opt_help );


	$opt_file = shift if ( ! defined $opt_file );
		
	if ( ( ! defined $opt_file )  ||  ( ! -f $opt_file ) )
		{	print "Can not find input file\n";
			exit( 0 + 1 );
		}
		

	my $ret = &ImageAnalyzeInterface( $opt_debug );
	exit if ( ! $ret );
	
	
	&lprint( "Testing Analyze Image function ...\n" );
	my $msg;
	( $ret, $msg ) = &ImageAnalyze( $opt_file, "c:\\temp" );
	
	if ( ! defined $ret )
		{	&lprint( "No return from Analyze Image function call\n" );
		}
	else
		{	&lprint( "Return from Analyze Image function call = $ret, msg = $msg\n" );
		}
	
	
	&lprint( "Unloading Analyze Image library ...\n" );

	&ImageAnalyzeUnload();
	
	lprint "\nDone\n";
	
	exit( 0 + 0 );
}
###################    End of MAIN  ################################################



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IATest";
	
    print <<".";

Usage: IATest image_file

Test Image Analyze library.

Possible options are:

  -x, --xxx               debug mode
  -v, --verbose           verbose mode
  -h, --help              print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
