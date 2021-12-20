################################################################################
#!perl -w
#
# Rob McCarthy's LineCompare.pl
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;


use Getopt::Long;


# Options
my $opt_help;
my $opt_version;


my $_version = "1.0.0";
my %urls;
my %dom;
my @url_list;  #  Urls in list format


################################################################################
#
MAIN:
#
################################################################################
{
    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
	(	"v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


    # Get the files to compare
    my  $source_file	= shift;
    my  $subtract_file	= shift;
    my  $add_file = shift;
    my  $missing_file	= shift;


    &Usage() if ( ! $source_file );     
    &Usage() if ( ! $subtract_file );     

	die "Can not find compare1 file $source_file\n"		if ( ! -s $source_file );
	die "Can not find compare2 file $subtract_file\n"	if ( ! -s $subtract_file );
	
	$add_file = $source_file . ".add.txt" if ( ! defined $add_file );
	$missing_file = $source_file . ".miss.txt"	if ( ! defined $missing_file );
	
    open( INFILE, "<$subtract_file" ) or die "Cannot open compare2 file $subtract_file: $!\n";
    print "Reading compare2 file $subtract_file\n";

	my %compare2;
	my $counter = 0 + 0;
    while ( my $line = <INFILE> )
       {	$counter++;
		   
			chomp( $line );
			next if ( ! length( $line ) );  #  Ignore empty lines
			next if $line =~ m/^#/;  #  Skip comments
			$compare2{ $line } = $counter;
      }

    close( INFILE );

    print "Read in $counter lines from compare2 file $subtract_file\n";


    # Open the remainder file
    open( OUTPUT, ">$add_file" ) or die "Cannot create add file: $add_file,\n$!\n";

    # Open the missing file
    open( MISSING, ">$missing_file" ) or die "Cannot create missing file: $missing_file,\n$!\n";


    # Open the source file
    open( INFILE, "<$source_file" ) or die "Cannot open compare1 file $source_file: $!\n";
    print "Reading compare1 file $source_file\n";


    my $counter2  = 0 + 0;
    my $same_count = 0 + 0;
    my $missing_count = 0 + 0;
	my $add_count = 0 + 0;

    while ( my $line = <INFILE> )
       {	$counter2++;
		   
			chomp( $line );
			next if ( ! length( $line ) );  #  Ignore empty lines
			next if $line =~ m/^#/;  #  Skip comments
			
			# Do I already know this exact line?
			if ( exists( $compare2{ $line } ) )
				{	delete $compare2{ $line };
					$same_count++;
					next;
				}
				
			print MISSING "$counter2: $line\n";
			$missing_count++;
      }

    close ( INFILE );
    close ( OUTPUT );
    close ( MISSING );


	
	# Put the add file in line order
	my %line_order;
	
	while ( my ( $line, $line_number ) = each( %compare2 ) )
		{	$line_order{ $line_number } = $line;
		}
		
		
	my @keys = sort keys %line_order;

	open( ADDFILE, ">$add_file" ) or die "Error opening add file $add_file: $!\n";
	
	foreach ( @keys )
		{	my $line_number = $_;
			next if ( ! $line_number );
			my $line = $line_order{ $line_number };
			next if ( ! defined $line );
			print ADDFILE "$line_number:	$line\n";
		}
	
	close( ADDFILE );
	
	
    print "Read in $counter lines from compare1 file $source_file\n";
    print "Created added file $add_file with $add_count lines total.\n";
    print "Created missing file $missing_file with $missing_count lines total.\n";
	print "$same_count lines are the same in both $source_file and $subtract_file\n";

    exit;
}




################################################################################
# 
sub insert_url
#
################################################################################
{
    my $url = shift;

    my $domain;
    my $url_ext;
    my $old_url_ext;
    my $old_url;

    $url = lc( URI::Heuristic::uf_urlstr( $url ) ); 

     #  Clean off the http:// and the trailing /
     $url =~ s#^http:\/\/##im;
     $url =~ s#\/$##m;


     # Do I already know this exact URL?
     if ( exists( $urls{ $url } ) )
       {   $urls{ $url } += 1.0;   # If so, just count it and move on 
            return;
       }

     # Do I already know another URL from this domain?
     ( $domain, $url_ext ) = split /\\|\//, $url, 2;

     if ( exists( $dom{ $domain } ) )  #  Ok - I've seen this domain before
       {  $old_url_ext = $dom{ $domain };

          #  Build back the url I already have
          $old_url = $domain;
          if ( $old_url_ext )
            {  $old_url = $domain . "\/" . $old_url_ext;  } 

           # Is it already a root domain, i.e. old_url_ext is unititalized?
           if ( !$old_url_ext )
              {  $urls{ $old_url } += 1.0; 
                  return;
              }

           # Is the new URL a root domain, i.e. url_ext is unititalized?
           if ( !$url_ext )
             {  #  Create the new key                
                $urls{ $url } = $urls{ $old_url } + 1.0; 

                 #  Delete the old key
                delete $urls{ $old_url };
               
                #  Set the domain value to the new url_ext
                $dom{ $domain } = $url_ext;
                return;
             }

           # Could the old url ext be a higher level than the new url ext?
           #  The old url ext should be contained in the new url ext
           #  So just ignore the new url
           if ( index( $url_ext,  $old_url_ext, 0 ) != -1 )
             {  $urls{ $old_url } += 1.0; 
                 return;
             } 

           # Could the new url ext be a higher level than the old url ext?
           if ( index( $old_url_ext, $url_ext, 0 ) != -1 )
             {   #  If so, then throw away the old_url and keep the new one
                # Create the new key
                $urls{ $url } = $urls{ $old_url } + 1.0; 

                 #  Delete the old key
                delete $urls{ $old_url };

                #  Set the domain value to the new url_ext
                 $dom{ $domain } = $url_ext;
                 return; 
             }

       }  # End of if domain exists


    #  Otherwise, add it to the list
    $urls{ $url } = 1.0;
    $dom{ $domain } = $url_ext;
}




################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print "$_[0]\n\n" if (@_);

    print <<".";
Usage: $me [OPTION]... [HITS-DIR MISSES-DIR]
Try '$me --help' for more information.
.
    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
Usage: LineCompare compare1_file compare2_file add_file missing_file

Compare the two files line by line.
Create a file of the lines added in compare2.  Default is '.add.txt'.
Create a file of the lines missing in compare2.  Default is '.miss.txt'
   
  -h, --help         display this help and exit
  -v, --version      display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    (my $me = $0) =~ s/\.cmd$//;

    print <<".";
$me $_version
.
    exit;
}


################################################################################

__END__

:endofperl
