################################################################################
#!perl -w
#
# Rob McCarthy's Virus Signature Diff source code
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Content::File;
use Content::ScanUtil;
use Content::ScanFile;


use Getopt::Long();



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_wizard;				# True if I shouldn't display headers or footers
my $opt_test;


my $_version = '1.00.00';



################################################################################
#
MAIN:
#
################################################################################
{

     # Get the options
     Getopt::Long::Configure("bundling");

     my $options = Getopt::Long::GetOptions
       (
			"t|test"		=> \$opt_test,
			"w|wizard"		=> \$opt_wizard,
			"h|help"		=> \$opt_help,
			"x|xxx"			=> \$opt_debug
       )or die( Usage() );


	&StdHeader( "Lightspeed Virus Signature Diff utility" ) if ( ! $opt_wizard );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );
	
	
	print "Ignoring test signatures\n" if ( $opt_test );
	
										 
	my $virus1 = shift;
	my $virus2 = shift;

	&Usage() if ( ( ! $virus1 )  ||  ( ! $virus2 ) );
	&Usage() if ( ( ! -f $virus1 )  ||  ( ! -f $virus2 ) );
	
	my %virus1;
	my %virus2;
	my @diff;
	my $same = 0 + 0;
	
	open( VIRUS1, "<$virus1" ) or die "Error opening $virus1: $!\n";
	open( VIRUS2, "<$virus2" ) or die "Error opening $virus2: $!\n";
	
	my $count = 0 + 0;
	while ( my $line = <VIRUS1> )
		{	chomp( $line );
			next if ( ! $line );
			my ( $virus_name, $signature ) = split /\t/, $line, 2;
			
			$virus_name = lc( $virus_name );
			$signature = lc( $signature );
			
			if ( $opt_test )
				{	# Is this a test signature?
					my ( $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = split/\t/, $signature, 7;
					$category_number = 0 + 0 if ( ! $category_number );
					
					$category_number = 0 + $category_number;
				
					next if ( $category_number == 0 + 64 );
				}
				
			$virus1{ $virus_name } = $signature;
			
			$count++;
		}
	
	close( VIRUS1 );
	
	print "Read $count virus signatures from $virus1\n";
	
	$count = 0 + 0;
	while ( my $line = <VIRUS2> )
		{	chomp( $line );
			next if ( ! $line );
			my ( $virus_name, $signature ) = split /\t/, $line, 2;
			
			$virus_name = lc( $virus_name );
			$signature = lc( $signature );
			
			if ( $opt_test )
				{	# Is this a test signature?
					my ( $virus_type, $appsig, $sigstart, $sigend, $signature, $category_number, $delete ) = split/\t/, $signature, 7;
					$category_number = 0 + 0 if ( ! $category_number );
					
					$category_number = 0 + $category_number;
				
					next if ( $category_number == 0 + 64 );
				}
				
			$count++;
			
			if ( exists $virus1{ $virus_name } )
				{	my $sig1 = $virus1{ $virus_name };
					
					delete $virus1{ $virus_name };
					
					# Are the signatures the same?
					if ( $sig1 eq $signature )
						{	$same++;
						}
					else
						{	my $len1 = length( $sig1 );
							my $len2 = length( $signature );
							
							my $diff_line = "$virus_name\tLength 1: $len1\tLength 2: $len2\n\tFile1: $sig1\n\tFile2: $signature\n";
							push @diff, $diff_line;
						}
				}
			else
				{	$virus2{ $virus_name } = $signature;
				}
		}
	
	close( VIRUS2 );
	
	print "Read $count virus signatures from $virus1\n";
	
	print "\nDifferent signatures ...\n";
	$count = 0 + 0;
	foreach ( @diff )
		{	my $line = $_;
			next if ( ! $line );
			
			print $line;
			
			$count++;
		}
	
	
	print "\nDifferent signatures - name only ...\n";
	foreach ( @diff )
		{	my $line = $_;
			next if ( ! $line );
			
			my ( $virus_name, $junk ) = split /\t/, $line, 2;
						
			print "\'$virus_name\',\n";
		}
	
	
	print "\n$count total different signatures\n" if ( $count );
	print "\nNo signatures are different\n" if ( ! $count );
	
	
	print "\nMissing signatures from $virus1:\n";
	
	$count = 0 + 0;
	while ( my ( $virus_name, $signature ) = each( %virus2 ) )
		{	print "$virus_name\t$signature\n";
			$count++;
		}
		
	print "\nMissing signatures from $virus1 - name only:\n";
	
	while ( my ( $virus_name, $signature ) = each( %virus2 ) )
		{	print "\'$virus_name\',\n";
		}
		
		
	print "\n$count missing signatures from $virus1 that are in $virus2\n" if ( $count );
	print "\nNo signatures are missing from $virus1\n" if ( ! $count );

	
	print "\nMissing signatures from $virus2:\n";
	
	$count = 0 + 0;
	while ( my ( $virus_name, $signature ) = each( %virus1 ) )
		{	print "$virus_name\t$signature\n";
			$count++;
		}
		
		
	print "\nMissing signatures from $virus2 - name only:\n";
	
	while ( my ( $virus_name, $signature ) = each( %virus1 ) )
		{	print "\'$virus_name\',\n";
		}
		
	print "$count missing signatures from $virus2 that are in $virus1\n" if ( $count );
	print "No signatures are missing from $virus2\n" if ( ! $count );
		
	print "\n$same signatures are the same in both files\n";
	
	&StdFooter() if ( ! $opt_wizard );

	exit;
}
###################    End of MAIN  ################################################



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     print( @_ );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "VirusSignatureDiff";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "VirusSignatureDiff";


    bprint <<".";

Usage: $me VirusSignatures1 VirusSignatures2

VirusSignatureDiff compares two VirusSignatures files and prints out the
differences.

  -t, --test       ignore test signatures

  --version        print version number
  --help           print this message and exit

.
    &StdFooter;

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
