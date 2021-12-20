################################################################################
#!perl -w
#
# Rob McCarthy's Disinfect.pl source code
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


my $_version = '8.00.01';


use Content::QueryOS;
use Content::Disinfect;



################################################################################
#
MAIN:
#
################################################################################
{	# This just loads into the DisinfectOptions subroutine that the scan.exe program also uses in Disinfect.pm
	
	my $security_agent_version = &GetSecurityAgentVersion();
	
	if ( ( $security_agent_version )  &&  ( $security_agent_version lt '8.00.00' ) )
		{	# Report the version as the Security Agent version so that the right registry keys are modified for the Service
			# Either IpmSecurityAgent2 or SaFsFilter
			print "Disinfect version $_version, Security Agent version $security_agent_version\n\n";
			
			$_version = $security_agent_version;
		}
	elsif ( $security_agent_version )
		{	print "Disinfect version $_version, Security Agent version $security_agent_version\n\n";
		}
	else
		{	print "Disinfect version $_version, no Security Agent version detected\n\n";
		}
		
	&DisinfectOptions( $_version );
	
	print "\nDone\n";
	
	exit( 0 );
}



################################################################################
#
sub GetSecurityAgentVersion()
#
#  Read out of the registry the SecurityAgent version
#
################################################################################
{
use Win32API::Registry 0.21 qw( :ALL );


	#  See if the key exists
	my $key;
	my $access = &OueryOSRegistryAccess( KEY_READ );
	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, $access, $key );
	
	return( undef ) if ( ! $ok );

	# Make sure that I am not being redirected under a 64 bit Windows OS
	&OueryOSWin64BitRegistry( $key );

	my $data;
	my $type;
	$ok = &RegQueryValueEx( $key, "Software Version", [], $type, $data, [] );

	&RegCloseKey( $key );

	return( undef ) if ( ! $ok );

	my $len = length( $data );
	return( undef ) if ( $len <= 0 );
		
	return( $data )
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
