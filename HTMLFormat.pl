################################################################################
#!perl -w
################################################################################



use strict;
use warnings;


use Content::File;


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
	
	
	my $output_file_name = shift;
	if ( ! $output_file_name )
		{	$output_file_name = $input_file_name . ".html";
		}
	
	
	print "HTML format file $input_file_name\n";
	
	
	if ( ! open INPUT, "<$input_file_name" )
		{	print "Error opening $input_file_name: $!\n";
			exit( 0 );
		}
		
	print "Opened file $input_file_name for input\n";

	my @lines;
	while ( <INPUT> )
		{	my $line = $_;
			chomp( $line );
			
			push @lines, $line;
		}


	close INPUT;


	if ( ! open OUTPUT, ">$output_file_name" )
		{	print "Error opening $output_file_name: $!\n";
			exit( 0 );
		}

	print "Opened file $output_file_name for output\n";
	
	
	print OUTPUT "<HTML>\n <HEAD></HEAD>\n <BODY>\n";
	print OUTPUT "<TABLE>\n";
	

	foreach( @lines )
		{	my $line= $_;
			next if ( ! defined $line );
		 
			my $url = &CleanUrl( $line );
			my $domain = &RootDomain( $url );
			next if ( ! defined $domain );
			
			print OUTPUT "<TR>\n";
			
			print OUTPUT "<TD><A HREF=\"http:\/\/$url\" TARGET=\"_blank\">$url<\/A></TD> <TD><A HREF=\"http:\/\/www.$url\" TARGET=\"_blank\">www.$url<\/A></TD>
						<TD><A HREF=\"http:\/\/archive.lightspeedsystems.com\/archive\/Default.aspx?Domain=$domain\" TARGET=\"_blank\">details<\/A></TD>\n";
			
			print OUTPUT "</TR>\n";
		}



    print OUTPUT " </TABLE>\n";	
    print OUTPUT " </BODY>\n</HTML>\n";

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
Syntax: HTMLFormat inputfile [outputfile]

.

    exit( 1 );
}



__END__

:endofperl
