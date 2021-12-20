################################################################################
#!perl -w
#
# RelayHold - manipulate the SMTPRelay RelayHoldDomains key
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Content::File;
use Win32API::Registry 0.21 qw( :ALL );



# Options
my $opt_help;
my $opt_version;
my $opt_source_directory;
my $opt_remove;
my $opt_clear;
my $opt_add;



my $_version = "1.0.0";


my @relay_hold_domains;			# This is the list of domains to have on hold for smtp sending


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
        "a|add=s"		=>	\$opt_add,
        "c|clear"		=>	\$opt_clear,
        "r|remove=s"	=>	\$opt_remove,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );


    &StdHeader( "RelayHold" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	my $new_domain = shift;
	$new_domain = $opt_add if ( defined $opt_add );
	
	&GetRelayHoldDomains();
	
	
	# Handle the options
	if ( $opt_clear )
		{	@relay_hold_domains = ();
			&SetRelayHoldDomains();
		}
		
	if ( defined $opt_remove )
		{	$opt_remove = "\@" . $opt_remove if ( ! ( $opt_remove =~ m/^\@/ ) );
			
			$opt_remove = lc( $opt_remove );
			
			for ( my $i = 0 + 0;  $i <= $#relay_hold_domains;  $i++ )
				{	$relay_hold_domains[ $i ] = undef if ( $relay_hold_domains[ $i ] eq $opt_remove );	
				}
				
			&SetRelayHoldDomains();
			&GetRelayHoldDomains();
		}
		
	if ( defined $new_domain )
		{	push @relay_hold_domains, lc( $new_domain );
			
			&SetRelayHoldDomains();
			&GetRelayHoldDomains();
		}


	print "Current on hold SMTP relay domains:\n";
			
	foreach ( @relay_hold_domains )
		{	print "$_\n";
		}
	
    exit;
}



################################################################################
# 
sub GetRelayHoldDomains()
#
#  Get the domain list that are supposed to be on hold for SMTP sending
#  Return True if there is a change from the last time this was called
#
################################################################################
{	my $key;
	my $type;
	my $data;
	
	my @new_relay_hold_domains = ();
	
	#  Does the SMTP Relay key exist in the registry?
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay", 0, KEY_READ, $key );
	if ( ! $ok )
		{	@relay_hold_domains= ();	# The key doesn't exist, so there isn't anything in it ...

			$ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service",  0, KEY_READ, $key );
			
			if ( ! $ok )
				{	print "TTC is not installed on this machice\n";
					return( 1 );
				}
				
			# Now create my keys
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] ) if ( $ok );
			RegCloseKey( $key ) if ( $ok );
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] ) if ( $ok );
			RegCloseKey( $key ) if ( $ok );
			$ok = RegCreateKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay", 0, "", REG_OPTION_NON_VOLATILE, KEY_WRITE, [], $key, [] ) if ( $ok );
			RegCloseKey( $key ) if ( $ok );
			return( undef );
		}

	# Get the RelayHold domains value to use if defined
	$data = undef;
	my $success = RegQueryValueEx( $key, "RelayHoldDomains", [], $type, $data, [] );

	if ( ( $success )  &&  ( $data ) )
		{	my @tmp = split /\x00/, $data;
			
			# Clean up the list
			foreach ( @tmp )
				{	next if ( ! defined $_ );
					
					my $domain = lc( $_ );
					if ( $_ =~ m/\@/ )
						{	push @new_relay_hold_domains, $domain;
						}
					else
						{	push @new_relay_hold_domains, "\@$domain";
						}
				}
		}
		
	RegCloseKey( $key );
	
	# Return undef if nothing changed
	return( undef ) if ( @relay_hold_domains eq @new_relay_hold_domains );
	
	@relay_hold_domains = @new_relay_hold_domains;
	
	return( 1 );
}



################################################################################
# 
sub SetRelayHoldDomains()
#
#  Set the domain list that are supposed to be on hold for SMTP sending
#
################################################################################
{	my $key;
	my $type;
	my $data;
	
		
	#  Does the SMTP Relay key exist in the registry?
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\SMTP Relay", 0, KEY_ALL_ACCESS, $key );
	return( undef ) if ( ! $ok );

	# Build a multi_sz out of the list
	$data = undef;

	my @new_list;
	
	foreach ( @relay_hold_domains )
		{	next if ( ! defined $_ );
			
			my $domain = $_;
			$domain = "\@" . $domain if ( ! ( $domain =~ m/^\@/ ) );
			
			# Do I already have this same domain in the list?
			my $match;
			foreach ( @new_list )
				{	$match = 1 if ( $_ eq $domain );
				}
			next if ( $match );
			
			push @new_list, $domain;
			
			$data .= "\x00" . $domain if ( defined $data );
			$data = $domain if ( ! defined $data );
		}

	$data .= "\x00\x00";

	RegSetValueEx( $key, "RelayHoldDomains", 0,  REG_MULTI_SZ, $data );
		
	RegCloseKey( $key );
	
	@relay_hold_domains = @new_list;
	
	return( 1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "RelayHold";

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
    my $me = "RelayHold";
    print <<".";
Usage: $me [OPTION(s)] DOMAIN
Put on hold or remove from on hold domains for the SMTP relay server.
To put a domain on hold use this syntax:
$me DOMAIN

  -a, --add DOMAIN     add DOMAIN to the list of domains on hold
  -c, --clear          clear out all the domains on hold
  -r, --remove DOMAIN  remove DOMAIN from the list of on hold domains  
  -h, --help           display this help and exit
  -v, --version        display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "RelayHold";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
