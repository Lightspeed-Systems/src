################################################################################
#!perl -w
#
# Renamer - test program
# 
# Given a command line of this:
#
# renamer first_old_file_name first_new_file_name second_old_file_name second_new_file_name program_to_run
#
# Rename the first file, rename the second file, and optionally, execute the program to run
#
# Example:
#
# rename TTCUpdate.exe TTCUpdate.old TTCUpdate.new TTCUpdate.exe TTCUpdate.exe
#
# This renames the old TTCUpdate program, installs the new TTCUpdate program, and then executes the TTCUpdate program
#
#  Copyright 2004 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;

use Win32;


################################################################################
#
MAIN:
#
################################################################################
{

	print "renamer\n";

	# Get the files to rename

	# Here is the first file
	my $rename1_old_name = shift;
	my $rename1_new_name = shift;

	# Here is the second file to rename
	my $rename2_old_name = shift;
	my $rename2_new_name = shift;


	# Check that all the required names are given
	if ( ( ! $rename1_old_name )  ||
		( ! $rename1_old_name ) ||
		( ! $rename1_old_name ) ||
		( ! $rename1_old_name ) )
		{	print "Usage error\n";
			exit( 6 );
		}
		

	# Here is the optional file to execute after done renaming the file
	my $run_name = shift;


	# Make sure the first old file exists
	if ( ! -e $rename1_old_name )
		{	print "$rename1_old_name does not exist\n";
			exit( 1 );
		} 


	# Blow away the first new name if it already there
	unlink( $rename1_new_name );


	# Rename it
	my $ok = rename( $rename1_old_name, $rename1_new_name );
	if ( ! $ok )
		{	print "Can not rename $rename1_old_name to $rename1_new_name\n";
			exit( 2 );
		}


	# Make sure the second old file exists
	if ( ! -e $rename2_old_name )
		{	print "$rename2_old_name does not exist\n";
			exit( 3 );
		} 


	# Blow away the second new name if it already there
	unlink( $rename2_new_name );


	# Rename it
	my $ok = rename( $rename2_old_name, $rename2_new_name );
	if ( ! $ok )
		{	print "Can not rename $rename2_old_name to $rename2_new_name\n";
			exit( 2 );
		}


	# Do I need to run anything?
	exit( 0 ) if ( ! $run_name );


	if ( ! -e $run_name )
		{	print "$run_name does not exist\n";
			exit( 4 );

		}


	# This exec function replaces the current process with the new process	
	exec "$run_name";


	# Should never get to here
	exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
