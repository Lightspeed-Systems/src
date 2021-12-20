################################################################################
#!perl -w
#
# LDAPTest - test LDAP settings for the Security Agent
# Rob McCarthy 7/9/2005
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;


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
	my $ldap_root;
	my $uid_attribute;
	my $group_attribute;
	my $protocol_version;
 
    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "b|basedn=s"	=>	\$ldap_root,
        "g|gid=s"		=>	\$group_attribute,
        "p|protocol=i"	=>	\$protocol_version,
        "u|uid=s"		=>	\$uid_attribute,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	my $username	= shift;
	my $ldap_server = shift;
	my $temp		= shift;
	$ldap_root		= $temp if ( defined $temp );

	&BadError( "User is not defined" )			if ( ! defined $username );
	&BadError( "LDAP Server is not defined" )		if ( ! defined $ldap_server );
	&BadError( "LDAP Base DN is not defined" )	if ( ! defined $ldap_root );
	
	&QueryLDAP( $username, $ldap_server, $ldap_root, $uid_attribute, $group_attribute, $protocol_version );
	
    exit;
}



################################################################################
# 
sub BadError( $ )
#
#	Return the LDAP ou and groups the user belongs in, 
#   given a full user name
#
################################################################################
{	my $err = shift;
	
	print "Error: $err\n";
	
	&Usage();
}



################################################################################
# 
sub QueryLDAP( $$$$$$ )
#
#	Return the LDAP ou and groups the user belongs in, 
#   given a full user name and the rest of the LDAp stuff
#
################################################################################
{	my $username			= shift;	# This needs to be in the form vkane or vkane.technology.administration.disd
	my $ldap_server			= shift;
	my $ldap_root			= shift;
	my $uid_attribute		= shift;
	my $group_attribute		= shift;
	my $protocol_version	= shift;

use Net::LDAP qw(:all);
use Net::LDAP::Entry;

	my $ou;
	my @groups;

	return( $ou, @groups ) if ( ! $username );


	# See if there is a uid attribute
	$uid_attribute = "cn" if ( ! defined $uid_attribute );


	# See if there is a group attribute
	$group_attribute = "groupMembership" if ( ! defined $group_attribute );


	# See if there is a protocol version
	$protocol_version = 0 + 2 if ( ! defined $protocol_version );
	
	# There are only 2 possible values for this - 2 or 3
	$protocol_version = 0 + 3 if ( ( $protocol_version ne 2 )  &&  ( $protocol_version ne 3 ) );


	# Now connect to the ldap server and get all the info out of it
	my $ldap = Net::LDAP->new( $ldap_server, timeout => 30 );

	# If I can't connect, just return undef
	if ( ! $ldap )
		{	print "Unable to connect to LDAP server: $ldap_server using protocol version $protocol_version\n";
			return( $ou, @groups ) ;
		}
		
		
	my $mesg = $ldap->bind( version => $protocol_version );

	if ( ! $mesg )
		{	print "Unable to bind to LDAP server: $ldap_server using protocol version $protocol_version\n";
			return( $ou, @groups );
		}
		
	if ( $mesg->code )
		{	&LDAPerror( $mesg );
			return( $ou, @groups );
		}
	
	$username =~ s/^\.//g;	# Make sure that I don't have leading periods on a username
	my @parts = split /\./, $username;

	my $base;

	# The first part of the username should be the common name that I am looking for
	my $cn = $parts[ 0 ];
	
	# Use the given NDS LDAP Root or LDAP Base DN
	my $o = $ldap_root;


	# Get my base for the ldap query
	#$base = "$uid_attribute=$cn," . $o if ( $o );	# This is the format for Novell LDAP
	$base = $o if ( $o );		# This is the format that works for Jeff Davis
	$base = "$uid_attribute=$cn" if ( ! $o );
	
	my $searchString;
	$searchString = "$uid_attribute=$cn";
	
	
	# Display all the query info so I can try to debug stuff
	print "\nLDAP search parameters ...\n";
	print "\tUser: $username:\n";
	print "\tServer: $ldap_server\n";
	print "\tProtocol Version: $protocol_version\n";
	print "\tUID attribute: $uid_attribute\n";
	print "\tGroup attribute: $group_attribute\n";
	print "\tBase DN: $ldap_root\n" if ( $ldap_root );
	print "\tSearch base: $base\n";
	print "\tSearch string: $searchString\n";
	print "\tSearch attribute: $group_attribute\n";
	print "\tSearch scope: sub\n";
	print "\tTime limit: 10 secs\n\n";
	
	
    my $result = $ldap->search (
        base		=> "$base",
        scope		=> "sub",
		filter		=> "$searchString",
        attrs		=> [ $group_attribute ],
		timelimit	=> 10
        );
	
	if ( ! $result )
		{	print "No results from LDAP server: $ldap_server\n";
			$mesg = $ldap->unbind;  # take down session
			return( $ou, @groups );
		}
	
	# Did I get some sort of LDAP error?
	if ( $result->code )
		{	&LDAPerror( $result );
			$mesg = $ldap->unbind;  # take down session
			return( $ou, @groups );
		}
		
	
	print "LDAP result: received OK\n";
	
	# Go through all the returned entries ( there really should only be one )
	my @entries = $result->entries;

	my $entr;
	my $dn;
	
	my $entry_count = 0 + 0;
	my $group_count = 0 + 0;
	foreach $entr ( @entries )
		{	$entry_count++;
			
			$dn = $entr->dn;
			
			print "\tDN: $dn\n";
			
			$dn = &NovellFormat( $dn );
		
			my $attr;
			my $lc_group_attribute = lc( $group_attribute );
			
			foreach $attr ( sort $entr->attributes )
				{	my $ref = $entr->get_value( $attr, asref => 1 );
					
					my @values= @{$ref};
					
					print "\tattribute $attr\n";
					foreach ( @values )
						{	next if ( ! defined $_ );
							my $value = $_;
							
							print "\t$attr: value $value\n";
						}
						
					my $lc_attr = lc( $attr );
					
					next if ( $lc_attr ne $lc_group_attribute );

					foreach ( @values )
						{	next if ( ! defined $_ );
							my $value = $_;
							
							$value = &NovellFormat( $value );
							
							if ( defined $value )
								{	push @groups, $value;
									$group_count++;
								}
						}
				}
		}


	# Did I get too many entries?
	if ( $entry_count ne 1 )
		{	print "LDAP error - received $entry_count entries back from the LDAP search query\n" if ( $entry_count > 1 );
			print "LDAP error - received no entries back from the LDAP search query\n" if ( $entry_count < 1 );
			$mesg = $ldap->unbind;  # take down session

			return( undef, @groups );
		}


	# Figure out a good OU
	$ou = undef;
	
	# If I got a good DN, just trim off the username from the front of it
	# Beware - there can be stray periods so I'll have to clean them off
	if ( $dn )
		{	$ou = lc( $dn );
			$ou =~ s/^\.//g;
			my $lc_username = lc( $username );
			$ou =~ s/^$lc_username//;
			$ou =~ s/^\.//g;
		}
	

	if ( defined $ou )
		{	print "\tUser OU: $ou\n";
		}
	else
		{	print "\tUser OU: Found no OU\n";
		}
		
	
	if ( ! $group_count )
		{	print "\tUser Group: Found no groups\n";
		}
	else
		{	foreach ( @groups )
				{	print "\tUser Group: $_\n";
				}
			
		}
		
	$mesg = $ldap->unbind;  # take down session
	
	return( $ou, @groups );
}



################################################################################
# 
sub NovellFormat( $ )
#
#	Reformat the Novell string from the form "cn=vkane,ou=technology,o=disd" to the
#   form "vkane.technology.disd"
#
################################################################################
{	my $str	= shift;

	my @parts = split /,/, $str;
	
	my $new_str;
	foreach ( @parts )
		{	next if ( ! $_ );
			my $part = $_;
			
			my ( $att, $val ) = split /=/, $part, 2;
			
			$val = $part if ( ! $val );
			
			$new_str = $new_str . "." . $val if ( $new_str );
			$new_str = $val if ( ! $new_str );
		}
		
	return( $new_str );
}



################################################################################
# 
sub LDAPerror( $ )
#
#  Given an error code from LDAP, print out the error message
#
################################################################################ 
 {
   my ( $mesg ) = @_;
   return if ( ! $mesg );
   
   my $code = $mesg->code;
   return if ( ! defined $code );
   
   print "\nLDAP error\n";   
   my $error_name = $mesg->error_name;
   print "Error name: $error_name\n" if ( defined $error_name );
   
   my $text = $mesg->error_text;
   print "$text\n" if ( defined $text );
 }
 
 

################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "LDAPTest";

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
    my $me = "LDAPTest";
    print <<".";

Usage: $me user ldap_server base_dn

Query an LDAP server for user OU and groups.
Used to test LDAP settings quickly.

Options:
  -b, --basedn     LDAP base DN
  -g, --gid        group attribute name - default is \"groupMembership\"
  -p, --protocol   LDAP protocol version - 2 or 3 - default is 2
  -u, --uid        user attribute name - default is \"cn\"

  -h, --help       display this help and exit
  -v, --version    display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "LDAPTest";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
