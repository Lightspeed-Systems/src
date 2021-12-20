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

my $file = shift;

if ( ! open( FILE, "<$file" ) )
	{	print "Error opening $file: $!\n";
	}

binmode FILE;

while ( my $line = <FILE> )
	{

		print "$line";

	}

exit;



################################################################################
# 
sub UpdateSACookie( $$ )
#
#	Save to a cookie all the user info
#
################################################################################
{	my $ttc_server = shift;
	my $sa_version = shift;

use HTTP::Cookies::Find;

use HTTP::Cookies::Microsoft;

	my $cookie =
"CheckSA
TTCVALUE
TTCDOMAINPATH
1536
LOEXPIRED
HIEXPIRED
LOMODIFIED
HIMODIFIED
*
";
	
	my $value = "SAVersion=TTCSAVERSION&TTCServer=MYTTCSERVER&PolicyName=TTCPOLICYNAME&PolicyVersion=TTCPOLICYVERSION&LastUpdate=TTCLASTUPDATE&User=TTCUSER&Group=TTCGROUPS&OU=TTCOU&HostName=TTCHOSTNAME";

	my $time = time();

	my ( $lowtime, $hightime ) = &Win32FileTime( $time );
	$cookie =~ s/LOEXPIRED/$lowtime/;
	$cookie =~ s/HIEXPIRED/$hightime/;

	$time = $time + ( 2 * 60 * 60 );
	( $lowtime, $hightime ) = &Win32FileTime( $time );
	$cookie =~ s/LOMODIFIED/$lowtime/;
	$cookie =~ s/HIMODIFIED/$hightime/;


	# Build up the cookie value
	$value =~ s/TTCSAVERSION/$sa_version/ if ( defined $sa_version );
	$value =~ s/TTCSAVERSION// if ( ! defined $sa_version );
	
	
	$value =~ s/MYTTCSERVER/$ttc_server/ if ( defined $ttc_server );
	$value =~ s/MYTTCSERVER// if ( ! defined $ttc_server );
		
	my ( $policy, $version ) = &PolicyGetCurrent();
	
	$value =~ s/TTCPOLICYNAME/$policy/ if ( defined $policy );
	$value =~ s/TTCPOLICYNAME// if ( ! defined $policy );

	$version = 0 if ( $version < 0 );
	$value =~ s/TTCPOLICYVERSION/$version/ if ( defined $version );
	$value =~ s/TTCPOLICYVERSION// if ( ! defined $version );
	
	my $key;
	my $type;
	my $data;
	
	my $datestr;
	my $ok = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\SecurityAgent", 0, KEY_READ, $key );
	$ok = RegQueryValueEx( $key, "Last Complete Update", [], $type, $data, [] ) if ( $ok );
	$datestr = $data if ( ( $ok )  &&  ( $data ) );
	RegCloseKey( $key );

	$value =~ s/TTCLASTUPDATE/$datestr/ if ( defined $datestr );
	$value =~ s/TTCLASTUPDATE// if ( ! defined $datestr );

						  
	my ( $username, $computer_name, $computer_domain, $ou, $comment ) = &UpdateGetUserName();
	
	$value =~ s/TTCUSER/$username/ if ( defined $username );
	$value =~ s/TTCUSER// if ( ! defined $username );

	$value =~ s/TTCOU/$ou/ if ( defined $ou );
	$value =~ s/TTCOU// if ( ! defined $ou );
	
	$value =~ s/TTCHOSTNAME/$computer_name/ if ( defined $computer_name );
	$value =~ s/TTCHOSTNAME// if ( ! defined $computer_name );


	my @groups;
	if ( $username )
		{	@groups = &UpdateGetUserGroups( $username, $computer_name );
		}
		
	my $groups;
	foreach ( @groups )
		{	next if ( ! defined $_ );
			$groups .= "," . $_ if ( defined $groups );
			$groups = $_ if ( ! defined $groups );
		}
				
	$value =~ s/TTCGROUPS/$groups/ if ( defined $groups );
	$value =~ s/TTCGROUPS// if ( ! defined $groups );


	$cookie =~ s/TTCVALUE/$value/;
	

	my $lightspeed_cookie = $cookie;
	$lightspeed_cookie =~ s/TTCDOMAINPATH/sa.lightspeedsystems.com\//;
	
	my $cookie_file = "robtest.txt";
	
	if ( ! open( COOKIE, ">$cookie_file" ) )
		{	
			
		}
	binmode COOKIE;
	
	print COOKIE $lightspeed_cookie;
	
	close COOKIE;

print $lightspeed_cookie;

	return( 1 );
}


################################################################################
# 
sub Win32FileTime( $ )
#
#  Given a time in seconds, convert it to Win32 File Time in a hi, low string
#
################################################################################
{	my $time = shift;
	
	# 0x019db1de 0xd53e8000 is 1970 Jan 01 00:00:00 in Win32 FILETIME
	#
	# 100 nanosecond intervals == 0.1 microsecond intervals
	
	my $filetime_low32_1970 = 0xd53e8000;
	my $filetime_high32_1970 = 0x019db1de;

	my $datenow = (($filetime_high32_1970 * 0x10000) * 0x10000) + $filetime_low32_1970 + ( ( 1000000 * $time ) * 10 );
	
	my $high = ( $datenow / 0x10000 ) / 0x10000;
	$high = sprintf( "%d", $high );
	$high = 0 + $high;
	
	my $low  = $datenow - ( ( $high * 0x10000) * 0x10000);
	
	return( $low, $high );
}







__END__

:endofperl
