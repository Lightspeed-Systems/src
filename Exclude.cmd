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





################################################################################
#
MAIN:
#
################################################################################
{
	my $item = shift;
	my $output = shift;

	die "You must enter a file name\n" if ( ! $item );
	die "You must enter an output file name\n" if ( ! $output );

	if ( -f $item )
		{  &Exclude( $item, $output );
		   exit( 0 );
		}


       print "Unable to find file $item\n";

     exit( 0 );
}




sub Exclude( $$ )
{
	my $filename = shift;
	my $output = shift;

	return if ( ! $filename );

	open( INPUT, "<$filename" ) or die( "Unable to open file $filename: $!\n" );
	open( OUTPUT, ">$output" ) or die( "Unable to open file $output: $!\n" );

	my $counter = 0;

	while ( my $line = <INPUT>)
	{	next if ( ! $line );
	
		my ( $fullfile, $junk ) = split /\s/, $line, 2;
		next if ( ! $fullfile );

		my ( $dir, $short ) = &SplitFileName( $fullfile );
			
		next if ( ! $short );

		my ( $name, $ext ) = split /\./, $short;

		next if ( length( $name ) != 8 );

		$name = uc( $name );

		print OUTPUT "$name\n";

		$counter++;
	}

	close( INPUT );
	close( OUTPUT );

	print "$filename has $counter crc32 values\n";

	return( $counter );
}



################################################################################
# 
sub SplitFileName( $ )
#
#  Given a file name, clean it up and return the split directory and filename
#
################################################################################
{	my $filename = shift;

	return( undef, undef ) if ( ! defined $filename );
		
	$filename =~ s#\/#\\#gm;	# Change slashes to backslashes
	
	my @parts = split /\\/, $filename;
	my $dir;

	for ( my $i = 0;  $i < $#parts;  $i++ )
		{	if ( defined $dir )  {  $dir = $dir . "\\" . $parts[ $i ];  }
			else  {  $dir = $parts[ $i ];  }
		}
	
	my $short_file = $parts[ $#parts ];
	
	# Do I have a directory at all?
	return( undef, $short_file ) if ( ! defined $dir ); 
	
	# Tack on a backslash if the original filename started with a backslash(s)
	if ( $filename =~ m/^\\\\/ )
		{	$dir =~ s/^\\+//;
			$dir = "\\\\" . $dir;
		}
	elsif ( $filename =~ m/^\\\\/ )
		{	$dir =~ s/^\\+//;
			$dir = "\\" . $dir;
		}
	
	# If the directory is just a drive letter, add a trailing slash
	if ( ( ! ( $dir =~ m/\\/ ) )  &&  ( length( $dir ) == 2 )  &&  ( $dir =~ m/\:$/ ) )
		{	$dir .= "\\";
		}

	return( $dir, $short_file );
}




__END__

:endofperl
