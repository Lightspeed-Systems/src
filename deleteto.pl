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
	
	my $text = shift;
	
	if ( ! $text )
		{	&Usage();
			exit( 0 );
		}
	
	
	my $meta = quotemeta( $text );

	
	my $output_file_name = shift;
	$output_file_name = $input_file_name if ( ! $output_file_name );
	
	
	if ( ! open INPUT, "<$input_file_name" )
		{	print "Error opening $input_file_name: $!\n";
			exit( 0 );
		}
		

	print "Opened file $input_file_name for input\n";
	
	
	my @lines;
	my $matched;
	my $in_counter = 0 + 0;
	while ( <INPUT> )
		{	my $txt = $_;
			chomp( $txt );
			
			$in_counter++;
			
			if ( $txt =~ m/$meta/ )
				{	$matched = 1;
					@lines = ();
					next;
				}
				
			push @lines, $txt;
		}


	close INPUT;
	
	
	print "Read in $in_counter lines from $input_file_name\n";
	
	
	if ( ( $#lines < 0 )  ||  ( ! $matched ) )
		{	print "Unable to find matching text $text\n";
			exit( 0 );
		}
	
	
	if ( ! open OUTPUT, ">$output_file_name" )
		{	print "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

		
	print "Opened file $output_file_name for output\n";


	my $out_counter = 0 + 0;
	foreach ( @lines )
		{	my $line = $_;
			next if ( ! length( $line ) );
			print OUTPUT "$line\n";
			$out_counter++;
		}
		
	close OUTPUT;
	
	
	print "Wrote out $out_counter lines to $output_file_name\n";

exit;

}

exit;



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "deleteto";

    print <<".";
Syntax: deleteto inputfile matchtest [outputfile]

.

    exit( 1 );
}





__END__

:endofperl
