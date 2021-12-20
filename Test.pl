################################################################################
#!perl -w
################################################################################



use strict;
use warnings;

use Digest::MD5;
use Crypt::CBC;
use Content::File;



################################################################################
#
MAIN:
#
################################################################################
{
	my $secret		= "SAFARI Montage API Secret Key";
	my $des_secret	= "SAFARI Montage API Secre";	# This is as long as a DES key can be
	my $user		= "DMagenau";
	my $password	= "mypassword";
	
	my $ts = time();
	$ts = "1245086485";

	my $md5_hex = Digest::MD5::md5_hex( $secret . $user . $password . $ts );
print "md5 hex = $md5_hex\n";

	my $cipher = Crypt::CBC->new(	-key			=> $des_secret,
									-cipher			=> 'DES_EDE3',
									-iv				=> '12345678',
									-literal_key	=> 0,
									-padding		=> 'null',
                                    -prepend_iv		=> 0

                            );

	my $ciphertext = $cipher->encrypt( $password );
	my $urlencoded = &UrlFormat( $ciphertext );

	
print "ciphertext url encoded = $urlencoded\n";


	#my $password =mcrypt_cbc(MCRYPT_TRIPLEDES, SECRET, $password, MCRYPT_ENCRYPT, '12345678');
	#$link = "http://ads.ltn.lvc.com/?a=109509&s=00:00:38:00&e=00:01:07:00&d=06735AA&user=" . urlencode($user) . "&pw=" . urlencode($password) . "&ts=" . $ts . "&x=" . $md5;
exit;

}


__END__

:endofperl
