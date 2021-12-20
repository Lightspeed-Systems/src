@rem = '--*-Perl-*--
@echo off
if "%OS%" == "Windows_NT" goto WinNT
perl -x -S "%0" %1 %2 %3 %4 %5 %6 %7 %8 %9
goto endofperl
:WinNT
perl -x -S %0 %*
if NOT "%COMSPEC%" == "%SystemRoot%\system32\cmd.exe" goto endofperl
if %errorlevel% == 9009 echo You do not have Perl in your PATH.
if errorlevel 1 goto script_failed_so_exit_with_non_zero_val 2>nul
goto endofperl
@rem ';


################################################################################
#!perl -w
 
##############################################################
# Run if any of the modules are unavailable
#
# perl -MCPAN -e 'install URI::Escape'
# perl -MCPAN -e 'install LWP::Simple'
# perl -MCPAN -e 'install Digest::HMAC_SHA1'
# perl -MCPAN -e 'install MIME::Base64'
##############################################################
 
use  strict;
use  Digest::HMAC_SHA1 qw(hmac_sha1);
use  URI::Escape;
use  MIME::Base64;
use  LWP::Simple;
 
my $AWS_ACCESS_KEY_ID = "1T0PMS0QCYG8VVJWGN02"; 
my $SECRET_ACCESS_KEY = "6voG6+uFkiJ1an8w96dGvGae1fscrJQwozSOtMhZ";
my $SITE = "http://www.amazon.com";
 
print get (UrlInfo_url());
 
sub UrlInfo_url {
  my $timestamp = generate_timestamp();
  my $signature = calculate_RFC2104_HMAC
       ("AlexaWebInfoServiceUrlInfo$timestamp",
       $SECRET_ACCESS_KEY);

print "timestamp= $timestamp\n";
 
  $timestamp = uri_escape($timestamp);
   $signature = uri_escape($signature);
   
   return "http://awis.amazonaws.com/onca/xml?"
        . "Service=AlexaWebInfoService"
        . "&AWSAccessKeyId=$AWS_ACCESS_KEY_ID"
        . "&Operation=UrlInfo"
        . "&ResponseGroup=Rank"
        . "&Url=$SITE"
        . "&Timestamp=$timestamp"
        . "&Signature=$signature";
}
 
sub calculate_RFC2104_HMAC {
        my ($data, $key) = @_;
        my $hmac = encode_base64(hmac_sha1 ($data, $key));
        chop $hmac;
       
        return $hmac;
}
 
sub generate_timestamp {
        return sprintf("%04d-%02d-%02dT%02d:%02d:%02d.000Z",
                sub { ($_[5]+1900,
                        $_[4]+1,
                        $_[3],
                        $_[2],
                        $_[1],
                        $_[0])
                }->(gmtime(time)));
}



exit;

__END__

:endofperl
