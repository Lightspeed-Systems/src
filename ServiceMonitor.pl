################################################################################
#!perl -w
#
# Rob McCarthy's ServiceMonitor.pl source code
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long();
use Cwd;

use Win32::Service;


use Content::File;



my $opt_help;
my $opt_debug;
my $opt_verbose;
my $cwd;
		
			
			
################################################################################
#
MAIN:
#
################################################################################
{
	my $options = Getopt::Long::GetOptions
       (
			"h|help"		=> \$opt_help,
			"v|verbose"		=> \$opt_verbose,
			"x|xxx"			=> \$opt_debug
      );
	   
	   
	&StdHeader( "ServiceMonitor" );

	&Usage() if ( $opt_help );


	$cwd = getcwd();
	$cwd =~ s#\/#\\#gm;

	
	
	my $log_filename = ".\\ServiceMonitor.log";		# The name of the log file to use
	&SetLogFilename( $log_filename, undef );
	
	$log_filename = &GetLogFilename();
	
	print "Logging Windows service information to $log_filename ...\n";
	
	&ServiceMonitor();
	
	chdir( $cwd );
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub ServiceMonitor()
#
#	Monitor the services
#
################################################################################
{	
	# Get the initial service hash
	
	my %services;
	
	my $ok = Win32::Service::GetServices( "", \%services );
	
	if ( ! $ok )
		{	print "Error getting services list\n";
			return( undef );
		}
		
	my %service_names;
	my %new_services;
	
	&ServiceNames( \%services, \%service_names, \%new_services );
	
	# Show the infor for each service
	&ServiceInfo( \%service_names );
	
	
	lprint "Looking for new services ...\n";
	
	my $done;
	
	while ( ! $done )
		{	$ok = Win32::Service::GetServices( "", \%services );
			
			if ( ! $ok )
				{	print "Error getting services list\n";
					last;
				}
				
			&ServiceNames( \%services, \%service_names, \%new_services );
			
			my $count = &ServiceInfo( \%new_services );
			
			sleep( 1 ) if ( ! $count );
		}
		
	return( 1 );
}



################################################################################
# 
sub ServiceNames( $$$ )
#
#	Given a hash of description, name, return a hash of name, description, and
#   a hash of the new names and descriptions
#
################################################################################
{	my $services_ref		= shift;
	my $service_name_ref	= shift;
	my $new_services_ref	= shift;
	
	# Set the new services to empty, and then file it with anything new I find
	%$new_services_ref = ();
	
	while ( my ( $description, $name ) = each( %$services_ref ) )
		{	next if ( ! defined $name );
			$description = "Unknown - $name" if ( ! defined $description );
			
			if ( ! defined $$service_name_ref{ $name } )
				{	$$service_name_ref{ $name } = $description;
					$$new_services_ref{ $name } = $description;
				}
		}
	
	return( 1 );	
}



################################################################################
# 
sub ServiceInfo( $ )
#
#	Given a hash of name, description, log all the service status stuff
#   a hash of the new names and descriptions
#
################################################################################
{	my $service_name_ref		= shift;
	
	my @sorted = sort keys %$service_name_ref;
	
	return( undef ) if ( $#sorted < 0 );
	
	my $count = 0 + 0;
	foreach( @sorted )
		{	my $name = $_;
			
			$count++;
			
			next if ( ! defined $name );
			
			my $description = $$service_name_ref{ $name };
			
			next if ( ! defined $name );
			
			lprint "Service: $name\n";
			lprint "\tDescription: $description\n";
			
			my %status;
			my $ok = Win32::Service::GetStatus( "", $name, \%status ); 
			next if ( ! $ok );

			my @keys = sort keys %status;
			
			next if ( $#keys < 0 );
			
			foreach( @keys )
				{	my $key = $_;
					next if ( ! defined $key );
					my $value = $status{ $key };
					
					lprint "\t$key: $value\n";
				}
		}
		
	return( $count );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";
Usage: ServiceMonitor

Monitors the Windows services.  If a new service is added it gathers
all the information possble about the service.
  
  -v, --verbose        verbose mode - extra messages
  -h, --help           print this message and exit
.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
