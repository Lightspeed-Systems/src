################################################################################
#!perl -w
#
# Rob McCarthy's Virus Import source code
#  Copyright 2003 Lightspeed Systems Corp.
# Import signatures.txt file into the Content Database
#
################################################################################



# Pragmas
use strict;


use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use DBI qw(:sql_types);
use DBD::ODBC;
use Unicode::String qw(utf8 latin1 utf16);
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Fcntl qw(:DEFAULT :flock);
use Content::File;
use Content::SQL;
use Content::Scan;



# Options
my $opt_input_file = "signatures\.txt";     #  The file name containing the text base signatures
my $opt_category_num = 0 + 16;               # Option for categorizing just one category
my $opt_insert;								# True if signatures should override what is already in the database
my $opt_dir;								# Directory to get stuff from - the default is the current directory
my $opt_help;
my $opt_version;
my $opt_source = 0 + 2;
my $opt_end_offset = 0 - 1;					# The maximum size of a file to search through, -1 means everything
my $opt_verbose;




# Globals
my $_version = "1.0.0";
my $dbh;									#  My database handle
my %virus_names;							# List of virus names already inserted



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "VirusImport" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
		"c|category=s" => \$opt_category_num,
        "i|insert" => \$opt_insert,
        "d|directory=s" => \$opt_dir,
        "f|file=s" => \$opt_input_file,
        "s|source=s" => \$opt_source,
        "v|verbose" => \$opt_verbose,
        "h|help" => \$opt_help
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);

    #  Make sure the source number is numeric
    $opt_source = 0 + $opt_source;
    &Usage() if ( ( $opt_source < 1 || $opt_source > 2000 ) );
     
    #  Make sure the source number is numeric
    $opt_category_num = 0 + $opt_category_num;
    &Usage() if ( ( $opt_category_num < 1 || $opt_category_num > 100 ) );

    #  Open the database
    $dbh = &ConnectServer() or die;

	# Suck the file into the database
	&ImportVirusSignatures( $opt_input_file, $opt_category_num, $opt_source );

	#  Clean up everything and quit
	$dbh->disconnect;

	&StdFooter;

exit;
}
################################################################################




################################################################################
# 
sub ImportVirusSignatures( $$$ )
#
#  Given a text file containig virus signatures, import it into SQL
#
################################################################################
{	my $file = shift;
	my $category_num = shift;
	my $source = shift;
	my $out_counter;
	
	
	my $dir = $file;
	
    $dir = $opt_dir . "\\" . $file if ( $opt_dir );	

    bprint "Importing virus signatures from $dir ... \n";

    open FILE, "<$dir" or die( "Cannot open input file $dir: $!\n" );

          
	while ( <FILE> )
		{	next if ( !$_ );
			
			my $line = $_ ;
			chomp( $line );
			next if ( ! $line );
			
			my ( $date, $app_sig, $name, $offset, $sig ) = split /::/, $line, 5;
			
			$name =~ s/\s//gm;
			$app_sig =~ s/\s//gm;
			
			if ( ( ! $app_sig ) || ( ! $name ) || ( ! defined $offset ) || ( ! $sig ) )
				{	print "Bad format in line $line\n";
					next;
				}
			
			if ( defined $virus_names{ $name } )
				{	print "Virus $name is already defined\n";
					next;	
				}
			
			
			# Is this virus already in the database?
			my $sth = $dbh->prepare( "SELECT count (*) FROM VirusSignatures where VirusName = ?" );
			$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
			$sth->execute();
			my ( $count ) = $sth->fetchrow_array();
			$sth->finish();
			
			if ( $count > 0 )
				{	print "Virus $name is already in the database\n";
					next;
				}
			

			$virus_names{ $name } = 1;
			
			# Calculate the starting and ending offsets to check
			my $start_offset = $offset;
			my $end_offset;
			my $second_start;
			
			if ( $start_offset =~ /and/ )
				{
					( $start_offset, $end_offset ) = split /and/, $offset;
					
					$start_offset =~ s/ge//;
					$start_offset =~ s/gt//;
					
					
					$end_offset =~ s/le//;
					$end_offset =~ s/lt//;
					
				}
				
			elsif ( $start_offset =~ m/or/ )
				{	my ( $first, $second ) = split /or/, $start_offset;
					
					$first =~ s/eq//;
					$start_offset = $first;
					$end_offset = $start_offset;
					
					$second =~ s/eq//;
					$second_start = $second;
					$second_start =~ s/\s//gm;
				}
			
			elsif ( $start_offset =~ m/eq/ )
				{	$start_offset =~ s/eq//;
					$end_offset = $start_offset;

				}
			
			elsif ( $start_offset =~ m/gt/ )
				{	$start_offset =~ s/gt//;
					$end_offset = $opt_end_offset;
				}
				
			elsif ( $start_offset =~ m/ge/ )
				{	$start_offset =~ s/ge//;
					$end_offset = $opt_end_offset;
				}
								
			elsif ( $start_offset =~ m/le/ )
				{	$end_offset = $start_offset;
					$end_offset =~ s/le//;
					$start_offset = 0;
				}
				
			elsif ( $start_offset =~ m/lt/ )
				{	$end_offset = $start_offset;
					$end_offset =~ s/lt//;
					$start_offset = 0;
				}
				
			elsif ( $start_offset eq 0 )
				{	$end_offset = $opt_end_offset;
				}
				
				
			# Clean up extra spaces	
			$start_offset =~ s/\s//gm;		
			$end_offset =~ s/\s//gm;
			
			
			$start_offset = 0 + $start_offset;
			
			$end_offset = 0 + $end_offset;
			
			# If the end offset is the same as the start offset, add 1 k to it
			$end_offset += 1024 if ( $end_offset eq $start_offset );
			
			
			# Get the virus type
			my ( $type, $junk ) = split /\//, $name, 2;
			$type = "BackDoor" if ( $name =~ m/BackDoor/ );
			$type = "Worm" if ( $name =~ m/worm/ );
			$type = "Linux" if ( $name =~ m/Linux/ );
			$type = "Dropper" if ( $name =~ m/Dropper/ );
			$type = "Test" if ( $name =~ m/Test/ );
			
#			next if ( $type eq "Linux" );
#			next if ( $type eq "W97" );
#			next if ( $type eq "W95" );
			
			if ( $opt_verbose )
				{	print "Date: $date, Virus Name: $name, Type = $type, App Sig: $app_sig\n";
					print "Original Offset: $offset, Start Offset: $start_offset, End Offset = $end_offset\n";
					print "Sig: $sig\n\n";
				}
				
			my $retcode = 0 + 0;
		
			my @values;
			push @values, "\'" . $name . "\',";				# 0 entry
			push @values, "\'" . $type . "\',";				# 1 entry
			push @values, "\'" . $app_sig . "\',";			# 2 entry
			push @values, "\'" . $start_offset . "\',";		# 3 entry
			push @values, "\'" . $end_offset . "\',";		# 4 entry
			push @values, "\'" . $sig . "\',";				# 5 entry
			push @values, "\'" . $category_num . "\',";		# 6 entry
			push @values, "\'" . $source . "\'";			# 7 entry
			
			
			
			my $str = "INSERT INTO VirusSignatures ( VirusName, VirusType, appsig, sigstart, sigend, signature, CategoryNumber, SourceNumber ) VALUES ( @values )";

			$sth = $dbh->prepare( $str );

			if ( ! $sth->execute() )
				{	print "Error inserting $line into database\n";
					print "Date: $date, Virus Name: $name, Type = $type, App Sig: $app_sig\n";
					print "Original Offset: $offset, Start Offset: $start_offset, End Offset = $end_offset\n";
					print "Sig: $sig\n\n";
					my $length = length( $sig );
					print "Sig length = $length\n";
				}
				
			$sth->finish();
		
			$out_counter++ if ( $retcode == 0 );
			
			
			# If there were 2 starts, just create a new virus with a slightly different name
			if ( $second_start )
				{	# Change the name slightly by adding a .2
					$values[ 0 ] =  "\'" . $name . "\.2\',";
					
					$start_offset = 0 + $second_start;
			
					$end_offset = 0 + $end_offset;
			
					# If the end offset is less than the start offset, add 1 k to it
					$end_offset = ( $start_offset + 1024 ) if ( $end_offset <= $start_offset );
					
					$values[ 3 ] =  "\'" . $start_offset . "\',";
					$values[ 4 ] =  "\'" . $end_offset . "\',";
			
					if ( $opt_verbose )
						{	print "Date: $date, Virus Name: $values[ 0 ], App Sig: $app_sig\n";
							print "Start Offset: $start_offset, End Offset = $end_offset\n";
							print "Sig: $sig\n\n";
						}
					
					my $str = "INSERT INTO VirusSignatures ( VirusName, VirusType, appsig, sigstart, sigend, signature, CategoryNumber, SourceNumber ) VALUES ( @values )";

					my $sth = $dbh->prepare( $str );

					$sth->execute();
					$sth->finish();
		
					$out_counter++ if ( $retcode == 0 );
				}		
		}
		
	close FILE;
	
	bprint "\nAdded $out_counter virus signatures to the database\n" if ( $out_counter );
	bprint "\nAdded no new virus signatures to the database\n" if ( ! $out_counter );

	return( 0 );
}



################################################################################
# 
sub errstr($)
#  
################################################################################
{
    bprint shift;

    return( -1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "VirusImport";

    bprint "$me\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
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
    my $me = "VirusImport";

    bprint <<".";
Usage: $me [OPTION(s)]
Imports virus signatures in text format into the Content database

  -c, --category_num=num    category number to add signatures to
  -d, --directory=PATH   to change default files directory
  -f, --file=FILE   to change default file name from signatures.txt
  -h, --help             display this help and exit
  -i, --insert           insert new urls without compressing or changing
                         old url categories
  -s, --source           source number to use on insert, default is 2
  -v, --version          display version information and exit
.
   &StdFooter;

    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "VirusImport";

    bprint <<".";
$me $_version
.
   &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
