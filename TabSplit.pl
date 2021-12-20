################################################################################
#!perl -w
#
#  TabSplit.pl
#
#  A quick little Perl script to check to split out one column of a tab separated
#  text file
#
#  Copyright Lightspeed Systems Inc. 2016
#  Written by Rob McCarthy 4/5/2016
#
################################################################################


use strict;
use warnings;


use Cwd;

my %unique;		# Don't duplication column data

################################################################################
#
MAIN:
#
################################################################################
{ 

	my $inputfile	= shift;
	my $outputfile	= shift;
	my $tab_no		= shift;
	my $prefix		= shift;
	
	$tab_no = 0 + 0 if ( ! defined $tab_no );
	$tab_no = 0 + $tab_no;
	
	&Usage() if ( ! defined $inputfile );
	&Usage() if ( ! -s $inputfile );
	&Usage() if ( ! defined $outputfile );
	
	my $cwd = getcwd();

	$cwd =~ s/\//\\/g;	# Make sure that it is a windows type directory
	
	print "Opening $inputfile for text file input ...\n";
	
	open( INPUT, "<$inputfile" ) or die "Error opening $inputfile: $!\n";
	
	print "Opening $outputfile for the split out column data ...\n";
	
	print "Removing column prefix $prefix ...\n" if ( defined $prefix );
	
	open( OUTPUT, ">$outputfile" ) or die "Error opening $outputfile: $!\n";
	
	my $line_count = 0 + 0;
	while ( my $line = <INPUT> )
		{	next if ( ! length( $line ) );
			chomp( $line );
			next if ( ! length( $line ) );
			my @parts = split /\t/, $line;
			
			my $column = $parts[ $tab_no ];
			next if ( ! defined $column );
			
			$column =~ s/^$prefix//i if ( defined $prefix );
			$column =~ s/^\s+//;
			$column =~ s/\s+$//;
			
			# Is the data duplicated?
			next if ( defined $unique{ $column } );
			
			print OUTPUT "$column\n";
			
			$unique{ $column } = 1;
			
			$line_count++;
		}
		
		
	close( OUTPUT );
	close( INPUT );
	print "Wrote $line_count lines to $outputfile\n";
	
	print "\nDone\n";
	
exit;

}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "TabSplit";

    print <<".";
Syntax: TabSplit inputfile outputfile tab_no [prefix]

Take an inputfile text file and split out into outputfile the tabbed
column number. Option [prefix] is to remove any prefix to the column.

.

    exit( 1 );
}



__END__

:endofperl
