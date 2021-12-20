################################################################################
#!perl -w
#
# LinkCount - summarizes the count of links from DumpTokens links files in the current directory
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;

use Content::File;


# Options
my $opt_help;
my $opt_version;
my $opt_source_directory;								# This is the directory of token, link, and label files to archive
my $_version = "1.0.0";
my %link_count;



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
        "s|source=s"		=>	\$opt_source_directory,
        "v|version"			=>	\$opt_version,
        "h|help"			=>	\$opt_help
    );
	

    #&StdHeader( "LinkCount" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


	# Read the command line
	$opt_source_directory = shift if ( ! $opt_source_directory );
	
	
	# If nothing specified, then use the current directory as the source directory
	if ( ( ! $opt_source_directory )  ||  ( $opt_source_directory eq "." ) )
		{	$opt_source_directory = getcwd;
			$opt_source_directory =~ s#\/#\\#gm;	
		}
		

	if ( ! -d $opt_source_directory )
		{	print "Can not find source directory $opt_source_directory\n";
			exit( 0 );
		}


	#print "Summarizing links from directory $opt_source_directory ...\n";
	
		
	# Process the source directory
	opendir DIR, $opt_source_directory;

	# print "Loading up links files to summarize ...\n";
	my @links_files;
	
	while ( my $file = readdir( DIR ) )
		{	next if ( ! $file );
			
			# Skip subdirectories
			next if (-d $file );
	
			my $dump_file;
			$dump_file = $file if ( $file =~ m/\.links\.txt$/ );
			
			next if ( ! $dump_file );
			
			push @links_files, $dump_file;
 		}

	closedir DIR;


	my $file_count = 0 + 0;
	foreach ( @links_files )
		{	my $link_file = $opt_source_directory . "\\" . $_;
			
			next if ( ! -e $link_file );
			
			next if ( ! open( LINKS, "<$link_file" ) );
			
			$file_count++;
			
			my $line = <LINKS>;
			my $ip = 1;
			my @addresses;
			my %root_links;
			
			while (<LINKS>)
				{	next if ( ! $_ );
					chomp;
					next if ( ! $_ );
					
					$line = $_;
							
					if ( ( $ip )  &&  ( &IsIPAddress( $line ) ) )
						{	push @addresses, $line;
						}
					else
						{	$ip = undef;
							
							# Is it a language definition?
							if ( $line =~ m/^Language\:/ )
								{	my ( $junk, $lang ) = split /\s/, $line, 2;
								}
							# Is it a charset definition?
							elsif ( $line =~ m/^Charset\:/ )
								{	my ( $junk, $charset ) = split /\s/, $line, 2;
								}
							else	# Keep track of the root domain of each link
								{	my ( $url, $read_info ) = split /\t/, $line, 2;
									my $root = &RootDomain( $url );
									next if ( ! defined $root );
									
									$root_links{ $root } = 0 + 1;
								}
						}
				}
				
			close( LINKS );
			
			
			# Merge the root links into the main link count
			while ( my $root = each( %root_links ) )
				{	if ( ! defined $link_count{ $root } )
						{	$link_count{ $root } = 0 + 1;
						}
					else
						{	$link_count{ $root }++;
						}
				}
		}

	#print "Read $file_count links files\n";
	
	my @sort_keys = sort sort_count keys %link_count;
	
	foreach ( @sort_keys )
		{	my $root = $_;
			my $count = $link_count{ $root };
			
			print "$root\t$count\n";
		}
		
	#&StdFooter;

    exit;
}



sub  sort_count	# Return the compare of the counts in decending order
{ 
my $count_a = 0 + $link_count{ $a };
my $count_b = 0 + $link_count{ $b };
$count_b <=> $count_a;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "LinkCount [sourcedir]";
    print <<".";
Usage: $me [OPTION(s)]

Summarizes the count of links from DumpTokens links files in the current directory

  -s, --source=SOURCEDIR   source directory of links files to summarize.
                           Default is the current directory.
  -h, --help               display this help and exit
  -v, --version            display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "LinkCount";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
