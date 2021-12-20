#!/bin/perl -w
use strict;

################################################################################
#
MAIN:
#
################################################################################
{

my $arg = $#ARGV;
print "arg = $arg, @ARGV\n";

if ( $arg != 0 + 0 )
{
	die "usage: ArmySSH hostname where hostname is ARMY-01 to ARMY-60, etc\n";
}

my ( $platoon, $number ) = split /\-/, $ARGV[ 0 ];

$platoon = lc( $platoon );

die "Invalid Army hostname $ARGV[0]\n" if ( ( $platoon ne "army" )  &&  ( $platoon ne "airforce" )  &&  ( $platoon ne "navy" )  &&  ( $platoon ne "marine" ) );

die "Invalid Army hostname $ARGV[0]\n" if ( ! $number );

die "Invalid Army hostname $ARGV[0]\n" if ( $number < 1 );

die "Invalid Army hostname $ARGV[0]\n" if ( $number > 60 );

die "Invalid Army hostname $ARGV[0]\n" if ( ( $platoon eq "navy" )  &&  ( $number > 20 ) );

die "Invalid Army hostname $ARGV[0]\n" if ( ( $platoon eq "marine" )  &&  ( $number > 20 ) );

my $ip;

if ( $platoon eq "army" )
	{	my $last = 29 + $number;
		$ip = "10.16.15.$last";
	}

if ( $platoon eq "airforce" )
	{	my $last = 29 + $number;
		$ip = "10.16.19.$last";
	}

if ( $platoon eq "navy" )
	{	my $last = 29 + $number;
		$ip = "10.16.17.$last";
	}

if ( $platoon eq "marine" )
	{	my $last = 29 + $number;
		$ip = "10.16.18.$last";
	}

print "SSH to $ip ...\n";
chdir( "c:\\ssh" );
system "ssh -i c:\\ssh\\rmccarthy_noc_id_rsa noc\@$ip";
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
