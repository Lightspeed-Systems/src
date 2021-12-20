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


# Pragmas
use strict;
use warnings;


use Cwd;

my $root;
my $startdir;
my $enddir;
my $level;
my $current_level = 0 + 0;
my $reached_startdir;



################################################################################
#
MAIN:
#
################################################################################
{
    
    #  Build up the command line to issue
    my  $cmd;

    while ( my $arg = shift ) 
      {  
	if ( ! defined $cmd )  
		{	if ( $arg =~ m/^startdir\=/i )
				{	$startdir = $arg;
					$startdir =~ s/^startdir\=//i;
				}
			elsif ( $arg =~ m/^enddir\=/i )
				{	$enddir = $arg;
					$enddir =~ s/^enddir\=//i;
				}
			elsif ( $arg =~ m/^level\=/i )
				{	$level = $arg;
					$level =~ s/^level\=//i;
					if ( $level =~ m/\D/ )
						{	print "Invalid level = $level\n";
							exit( 1 );
						}
				}
			else
				{	$cmd = $arg;
				}  
		}
         else  
		{  $cmd = $cmd . " " . $arg;  
		}
      }


    if ( ! defined $cmd )
    	{	print "No command to execute\n";
		exit( 0 );
	}

    print "Subdir command = $cmd\n";
    print "Start dir = $startdir\n" if ( defined $startdir );
    print "End dir = $enddir\n" if ( defined $enddir );
	print "Subdir max level = $level\n" if ( defined $level );

    my $dir = getcwd;
    $dir =~ s#\/#\\#gm;

    $root = $dir;

    &DirectoryCommand( $dir, $cmd );

     chdir( $dir );
    exit;
}



################################################################################
# 
sub DirectoryCommand( $$ )
#
################################################################################
{	my $dir = shift;
	my $cmd = shift;

	$current_level++;

	if ( lc( $dir ) ne lc( $root ) )
		{	print "Subdir command directory: $dir, current level $current_level\n"; 
			chdir "$dir";
			system( $cmd );
		}

	chdir( $dir );
	my $dir_handle;
	opendir( $dir_handle, "." ) or die "Unable to open current directory $dir: $!\n";

	while ( my $subdir = readdir( $dir_handle ) )
		{	
			next if ( ! defined $subdir );

			next if ( $subdir eq "." );
			next if ( $subdir eq ".." );

			my $fulldir = "$dir\\$subdir";
	
			next if ( ! -d $fulldir );

			# Should I ignore this?
			if ( ( lc( $dir ) eq lc( $root ) )  &&  ( $startdir )   &&  ( ! $reached_startdir ) )
				{	if ( lc( $subdir ) eq lc( $startdir ) )
						{	print "Reached the starting directory $startdir\n";
							&DirectoryCommand( $fulldir, $cmd );
							$reached_startdir = 1;
						}
					else
						{	print "Ignoring $subdir\n";
						}
					next;
				}

			if ( ( lc( $dir ) eq lc( $root ) )  &&  ( $enddir ) )
				{	print "Reached the ending directory $enddir\n";
					last if ( lc( $subdir ) eq lc( $enddir ) );
				}


			# Do I have a level defined?
			if ( $level )
				{	# Only run a directory command if the current level is equal to the defined level
					&DirectoryCommand( $fulldir, $cmd ) if ( $current_level <= $level );
				}
			else
				{	&DirectoryCommand( $fulldir, $cmd );
				}

			chdir( $dir );
         	}


	closedir( $dir_handle );

	$current_level--;

	return( 0 );
}



################################################################################
# 
sub LessThan( $$ )
#
#  Return TRUE if the first string is less than the second string alphabetically
#
################################################################################
{	my $first = shift;
	my $second = shift;

	return( undef ) if ( lc( $first ) eq lc( $second ) );

	my $len = length( $first );
	my $len2 = length( $second );

	$len = $len2 if ( $len2 < $len );

	return( undef ) if ( ! $len );

	my $str1 = lc( substr( $first, 0, $len ) );
	my $str2 = lc( substr( $second, 0, $len ) );

	return( 1 ) if ( $str1 lt $str2 );
	return( undef );
}



################################################################################

__END__

:endofperl
