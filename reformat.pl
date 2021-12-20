################################################################################
#!perl -w
#
# Rob McCarthy's reformat.pl - to reformat F-Prot scan logs into the old format
#
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Content::File;


# Options
my $opt_help;
my $opt_version;
my $opt_debug;


my $_version = "1.0.0";




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
        "v|version" => \$opt_version,
        "h|help" => \$opt_help
    );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	my $src = shift;
	my $dest = shift;

	&Usage() if ( ! $src );
	&Usage() if ( ! -f $src );

	&Usage() if ( ! $dest );

	&Reformat( $src, $dest );

    exit;
}




################################################################################
# 
sub Reformat( $$ )
#
#	Reformat an F-Prot log file into the older F-Prot format
#
################################################################################
{	my $src = shift;
	my $dest = shift;
	
	print "Reading F-Prot log file $src ...\n";
	
	open( OUTPUT, ">$dest" ) or die( "Unable to open file $dest: $!\n" );
	
	open( LOGFILE, "<$src" ) or die( "Unable to open file $src: $!\n" );
	
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			# Trim off leading and trailing whitespace
			$line =~ s/^\s+//;
			next if ( ! $line );
			
			$line =~ s/\s+$//;
			next if ( ! $line );
			
			next if ( $line =~ m/\[Found possible virus\]/i );
			next if ( $line =~ m/\[Found possible worm\]/i );
			next if ( $line =~ m/\[Unscannable\]/i );
			
			# Are there lines to ignore?
			next if ( $line =~ m/could be/i );

			# See if the line contains words indicating a virus
			my $vword;
			$vword = 1 if ( $line =~ m/found virus/i );
			$vword = 1 if ( $line =~ m/found joke/i );
			$vword = 1 if ( $line =~ m/found password stealer/i );
			$vword = 1 if ( $line =~ m/found trojan/i );
			$vword = 1 if ( $line =~ m/found adware/i );
			$vword = 1 if ( $line =~ m/found dialer/i );
			$vword = 1 if ( $line =~ m/found worm/i );
			$vword = 1 if ( $line =~ m/found downloader/i );
			$vword = 1 if ( $line =~ m/found application/i );
			$vword = 1 if ( $line =~ m/found backdoor/i );
			$vword = 1 if ( $line =~ m/found security risk/i );
			$vword = 1 if ( $line =~ m/contains infected objects/i );
			next if ( ! $vword );
			
			my ( $virus, $vfile ) = split />\s/, $line, 2;


			next if ( ! $vfile );
			next if ( ! $virus );
			
			
			# Is there junk on the file name to ignore?
			my $junk;
			( $vfile, $junk ) = split /\-\>/, $vfile;
			next if ( ! $vfile );
			
			# Trim off leading and trailing whitespace
			$vfile =~ s/^\s+//;
			next if ( ! $vfile );
			
			$vfile =~ s/\s+$//;
			next if ( ! $vfile );
			
							
			$virus =~ s/\<//g;
			$virus =~ s/\>//g;
			
			$virus =~ s/, not disinfectable//ig;
			$virus =~ s/, generic//ig;
			$virus =~ s/, damaged//ig;
			$virus =~ s/, unknown//ig;
			$virus =~ s/, dropper//ig;
			$virus =~ s/, source//ig;
			$virus =~ s/, non-working//ig;
			$virus =~ s/, component//ig;
			$virus =~ s/, corrupted//ig;
			$virus =~ s/, remnants//ig;
			
			$virus =~ s/\(exact\)//ig;
			$virus =~ s/\(exact, \)//ig;
			$virus =~ s/\(exact, source\)//ig;
			$virus =~ s/\(exact, non-working\)//ig;
			$virus =~ s/\(exact, non-working, not disinfectable\)//ig;
			$virus =~ s/\(exact, unknown, non-working, not disinfectable\)//ig;
			$virus =~ s/\(exact, unknown, damaged\)//ig;
			$virus =~ s/\(exact, dropper\)//ig;
			$virus =~ s/\(exact, generic\)//ig;
			$virus =~ s/\(exact, dropper, not disinfectable\)//ig;
			$virus =~ s/\(exact, dropper, not disinfectable, generic\)//ig;
			$virus =~ s/\(exact, unknown, not disinfectable, generic\)//ig;
			$virus =~ s/\(non-working, dropper\)//ig;
			$virus =~ s/\(non-working, dropper, not disinfectable, generic\)//ig;
			$virus =~ s/\(exact, unknown\)//ig;
			$virus =~ s/\(exact, damaged\)//ig;
			$virus =~ s/\(exact, damaged, not disinfectable\)//ig;
			$virus =~ s/\(not disinfectable\)//ig;
			$virus =~ s/\(not disinfectable, generic\)//ig;
			$virus =~ s/\(exact, not disinfectable\)//ig;
			$virus =~ s/\(generic, not disinfectable\)//ig;
			$virus =~ s/\(generic, damaged, not disinfectable\)//ig;
			$virus =~ s/\(non-working\)//ig;
			$virus =~ s/\(non-working, not disinfectable\)//ig;
			$virus =~ s/\(dropper\)//ig;
			$virus =~ s/\(dropper, not disinfectable\)//ig;
			$virus =~ s/\(dropper, not disinfectable, generic\)//ig;
			$virus =~ s/\(exact, dropper\)//ig;
			$virus =~ s/\(exact, component\)//ig;
			$virus =~ s/\(generic\)//ig;
			$virus =~ s/\(damaged\)//ig;
			$virus =~ s/\(damaged, not disinfectable\)//ig;
			$virus =~ s/\(damaged, not disinfectable, generic\)//ig;
			$virus =~ s/\(corrupted\)//ig;

			$virus =~ s/\[Found virus\]//i;
			$virus =~ s/\[Found virus tool\]//i;
			$virus =~ s/\[Found trojan\]//i;
			$virus =~ s/\[Found trojan proxy\]//i;
			$virus =~ s/\[Found adware\]//i;
			$virus =~ s/\[Found dialer\]//i;
			$virus =~ s/\[Found worm\]//i;
			$virus =~ s/\[Found downloader\]//i;
			$virus =~ s/\[Found application\]//i;
			$virus =~ s/\[Found backdoor\]//i;
			$virus =~ s/\[Found security risk\]//i;
			$virus =~ s/\[Found password stealer\]//i;
			$virus =~ s/\[Found joke\]//i;
			
			next if ( ! $virus );
			
			my $clean_vname = &CleanVName( $virus );
						
			print "$vfile  Infection: $clean_vname\n";

			print OUTPUT "$vfile  Infection: $clean_vname\n";
		}
		
	close( LOGFILE );									 
	close( OUTPUT );									 

	print "Read $linecount lines from F-Prot log file $src\n";
}



################################################################################
# 
sub CleanVName( $ )
#
#	Given a original virus name, clean up any weird characters and return the result
#
################################################################################
{	my $vname = shift;
	
	return( undef ) if ( ! defined $vname );

	$vname =~ s/\t/ /g;
	$vname =~ s/\n/ /g;
	$vname =~ s/\r/ /g;
	
	$vname =~ s/\"//g;
	$vname =~ s/\'//g;
	$vname =~ s/FOUND//g;
	
	$vname =~ s/^\s+// if ( $vname );
	$vname =~ s/\s+$// if ( $vname );
	
	return( $vname );
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
Usage: $me [OPTION(s)]  source (wildcard allowed) output
Combines lists of URLs into one large list
    
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
