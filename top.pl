################################################################################
#!perl -w
################################################################################



use strict;
use warnings;



################################################################################
#
MAIN:
#
################################################################################
{ 
	my $input_file_name = shift;
	
	if ( ( ! $input_file_name )  ||  ( ! -e $input_file_name ) )
		{	&Usage();
			exit( 0 );
		}
	
	my $lines = shift;
	
	if ( ! $lines )
		{	&Usage();
			exit( 0 );
		}
	
	
	my $output_file_name = shift;
	if ( ! $output_file_name )
		{	&Usage();
			exit( 0 );
		}
	
	
	if ( ! open INPUT, "<$input_file_name" )
		{	print "Error opening $input_file_name: $!\n";
			exit( 0 );
		}
		
	print "Opened file $input_file_name for input\n";

	if ( ! open OUTPUT, ">$output_file_name" )
		{	print "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	print "Opened file $output_file_name for output\n";
	
	
	my $in_counter = 0 + 0;
	while ( <INPUT> )
		{	my $txt = $_;
			chomp( $txt );
			
			print OUTPUT "$txt\n";

			$in_counter++;
			
			last if ( $in_counter >= $lines );
		}


	close INPUT;
	close OUTPUT;	
	
	print "Done.\n";

exit;

}

exit;



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "top";

    print <<".";
Syntax: top inputfile #lines outputfile

.

    exit( 1 );
}



__END__

:endofperl
