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


use Content::File;


my $domain = shift;

exit if ( ! defined $domain );

print "Domain = $domain\n";

my $root = &RootDomain( $domain );

print "Root = $root\n" if ( defined $root );
print "No root\n" if ( ! defined $root );



exit;

__END__

:endofperl
