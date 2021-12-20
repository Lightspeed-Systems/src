################################################################################
#!perl -w
#
# Rob McCarthy's TKTest - test TK routines
#
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use warnings;
use strict;


use Tk;
require Tk::BrowseEntry;



################################################################################
#
MAIN:
#
################################################################################
{


	my $mw = MainWindow->new(-title => "Security Agent Scan");
	$mw->withdraw(); #<--HERE

	my $response = $mw->messageBox( #-icon => 'questhead',
								-message => 'Ready to do the initial system scan for viruses, spyware, and unknown programs?',
								-title => 'Security Agent Scan',
								-type => 'OKCancel',
								-default => 'ok');


	print "response = $response\n";
	
	
	exit;
}



sub done
{
	print "Done\n";
	exit;
}
		
		




__END__

:endofperl
