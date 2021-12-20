################################################################################
#!perl -w
#
# Given a source and a destination file, copy only if the files are different
#
################################################################################



# Pragmas
use strict;

use Content::File;
use Content::QueryOS;
use File::Copy;
use Win32::File;
use Win32API::Registry 0.21 qw( :ALL );
use Cwd;




my $_version = "1.0.0";




################################################################################
#
MAIN:
#
################################################################################
{

	# Setup to handle Win 64 bit operations if running under one of those OSes
	&OueryOSWin64Bit();
	&OueryOSWin64BitFile();
	
	my $source = shift;
	my $target = shift;

	if ( ( ! $source )  ||  ( ! $target ) )
		{	print "usage: source target\n";
		}
	else
		{	&install_copy( $source, $target );
		}

    exit;
}



################################################################################
#
sub install_copy( $$ )
#
#  Copy 2 files if they are different.  Return True if the copy happened
#
################################################################################
{	my $from = shift;
	my $to = shift;
	
	if ( ! $to )
		{	print "To file not defined in copy\n";
			return( undef );
		}
		
	if ( ! $from )
		{	print "From file not defined in copy\n";
			return( undef );
		}
	
	if ( ! -e $from )
		{	lprint( "The from file $from does not exist\n" );
			return( undef );
		}

	my $retcode;	
	$retcode = &FileCompare( $from, $to );
	
	if ( ! $retcode )
		{	print "File $to has not changed\n";
			return( undef );
		}
	
	# If the to: file is readonly, turn off that attribute
	my $attrib;
	
	Win32::File::GetAttributes( $to, $attrib );
	
	# Is the readonly bit set?  If so, turn it off
	if ( $attrib & READONLY )
		{	$attrib = $attrib - READONLY;
			Win32::File::SetAttributes( $to, $attrib );
		}
	
	# Use an old file if the target exists
	my $old;
	if ( -f $to )
		{	$old = "$to.old";
			unlink( $old );
			rename( $to, $old );
		}
	
	print "Copying $from to $to\n";	
	
	$retcode = copy( $from, $to );
	
	print "Error copying $from to $to: $!\n" if ( ! $retcode );
	print "Copied ok\n" if ( $retcode );
	
	unlink( $old ) if ( $old );

	return( $retcode );
}



################################################################################
#
sub FileCompare( $$ )
#
#  Compare 2 files.  If the sizes are different, return TRUE
#  Make sure the the to file isn't newer than the from file ...
#
################################################################################
{	my $from	= shift;
	my $to		= shift;
	
	use File::Compare 'cmp';

	# Do the files exist?
	return( 1 ) if ( !-e $from );
	return( 1 ) if ( !-e $to );
	
	# Is the existing file newer?
	my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $from;	
	my $from_mtime = 0 + $mtime;

	( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat $to;
	my $to_mtime = 0 + $mtime;
	
	if ( $to_mtime > $from_mtime )
		{	&lprint( "The target file $to is newer than then source file $from, so not copying\n" );
			return( undef );
		}

	# Return if the times are different	
	return( 1 ) if ( $to_mtime != $from_mtime );

	# Are the file sizes different?	
	my $from_size = -s $from;
	my $to_size = -s $to;

	return( 1 ) if ( $from_size ne $to_size );
	
	return( 1 ) if cmp( $from, $to );
	
	return( undef );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "FileCategorize";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
