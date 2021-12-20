################################################################################
#!perl -w
#
# Rob McCarthy's Count source code
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long();
use Cwd;


my $opt_file;
my $opt_help;
my $opt_debug;



################################################################################
#
MAIN:
#
################################################################################
{
	my @files = ( "domains_only", "ip_only" );

	my $options = Getopt::Long::GetOptions
       (
		"f|file=s"		=> \$opt_file,
        "h|help"		=> \$opt_help,
		"x|xxx"			=> \$opt_debug
      );


    &Usage() if ( $opt_help );	
	&Usage() if ( ! defined $opt_file );
	
	
	# Open the results file
	open( RESULTS, ">>$opt_file" ) or die( "Unable to open file $opt_file: $!\n" );
	
	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	my @parts = split /\\/, $cwd;
	
	my $dir_name = $parts[ $#parts ];
	
	my $file_counter = 0;
	my $total = 0 + 0;

	my $results = $dir_name;
	
	foreach ( @files )
		{	next if ( ! defined $_ );
			my $filename = $_;
			
			$file_counter++;
			
			my $full_filename = "$cwd\\$filename";
			
			print "Counting $full_filename ...\n";
			
			my $count = &lines( $full_filename );
			
			$results .= ",$count";
		}
 
	print "Total lines for all files = $total\n";

	print "$results\n";
	print RESULTS "$results\n";
	
	close( RESULTS );
	
	exit( 0 );
}




sub lines( $ )
{
	my $filename = shift;
	return if ( ! $filename );

	open( INPUT, "<$filename" ) or die( "Unable to open file $filename: $!\n" );

	my $counter = 0;

	while (<INPUT>)
	{
	   $counter++;
	}

	close INPUT;

	print "$filename has $counter lines\n";

	return( $counter );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "AppProcess";
	
    print <<".";

Usage: scan [list]
Scan a list of directories and/or files to try to build associations between
and .exe's and the installed applications.

By default it will put all the discovered assocations in a file called
\"AppProcess.txt\".

Possible options are:

  -a, --append          append to the existing file
  -c, --category=cat    set the category name of the applications
  -d, --database        don\'t add the app/process info to the database
  -f, --file=name       change the name of the AppProcess.txt to name
  -i, --insert          insert the app process file into the database
  -n, --name=app        force the application name to app
  -o, --overwrite       overwrite existing file IDs in the database
  -p, --program         show the info for each program found
  -r, --recommended     turn on the recommended bit for each program found
  -u, --update          turn on inherit bit for an update package
  -v, --verbose         show work as it progresses
  -w, --windows         label all the app processes as Windows OS  
  -h, --help            print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
