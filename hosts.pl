################################################################################
#!perl -w

use strict;
use warnings;

print "Converting HOSTS file to domains file ...\n";

open( HOSTS, "<HOSTS" ) or die "Unable to open HOSTS file to convert: $!\n";

open( DOMAINS, ">domains" ) or die "Unable to open domains file: $!\n";

while ( my $line = <HOSTS> )
	{	chomp( $line );
		next if ( ! $line );
		next if ( ! ( $line =~ m/^127\.0\.0\.1/ ) );

		my ( $junk, $domain ) = split /127\.0\.0\.1/, $line, 2;

		next if ( ! $domain );

		( $domain, $junk ) = split /\#/, $domain, 2;

		next if ( ! $domain );

		$domain =~ s/^\s+//;
		$domain =~ s/\s+$//;

		print DOMAINS "$domain\n";
	}

close( HOSTS );
close( DOMAINS );
 

exit;

__END__

:endofperl
