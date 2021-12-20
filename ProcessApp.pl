################################################################################
#!perl -w
#
# Process AppProcess.txt files that were emailed to unknown@lightspeedsystems.com
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use DBI qw(:sql_types);
use DBD::ODBC;
use Cwd;
use Archive::Zip qw( :ERROR_CODES );


use Content::File;
use Content::SQL;
use Content::EML;


# Options
my $opt_help;
my $opt_version;
my $opt_source_directory;
my $dbh;
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
        "d|directory=s" =>	\$opt_source_directory,
		"x|xxx"			=>  \$opt_debug,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );


    &StdHeader( "ProcessApp" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	if ( ! $opt_source_directory )
		{   $opt_source_directory = getcwd;
			$opt_source_directory =~ s#\/#\\#gm;
		}
		
	if ( ! -d $opt_source_directory )
		{	&FatalError( "Can not find directory $opt_source_directory\n" );
		}

		
		
	print "Opening a connection to the local SQL database ...\n";
	$dbh = &ConnectServer();
	if ( ! $dbh )
		{	print "Unable to connect to the Content database\n";
			exit;	
		}


	# Process the source directory
	opendir DIR, $opt_source_directory;

	my $file;
	my $counter = 0 + 0;
	
	while ( $file = readdir( DIR ) )
		{
			# Skip subdirectories
			next if (-d $file);
			
			my $src	= $opt_source_directory . "\\" . $file;
			
			# Does the file exist?  It might have been deleted by another task
			next if ( ! -e $src );
					
			print "Processing file $file ...\n";

			$counter++;
			
			my $zipped_file = &EMLUnpack( $file );
			
			next if ( ! $zipped_file );
			
			my $zip = Archive::Zip->new( $zipped_file );
			next if ( ! $zip );
			
			my @members = $zip->memberNames();
			
			my @files;
			foreach ( @members )
				{	my $member = $_;
					
					# Clean up the name and extract out just the filename to use
					my $mem = $member;
					$mem =~ s#\/#\\#g;
					
					# Get the filename extracted
					my @parts = split /\\/, $mem;
					
					my $short_file = "AppProcess.txt";

					my $error_code = $zip->extractMemberWithoutPaths( $member, $short_file );
					
					if ( $error_code != AZ_OK )
						{	print "Scan error: extracting $short_file: $error_code\n";
						}
					else
						{	push @files, $short_file;
						}
				}
		
			unlink ( $zipped_file );
			
			foreach ( @files )
				{	next if ( ! defined $_ );
					my $unpacked_file = $_;
										
					if ( ( -e $unpacked_file )  &&  ( -s $unpacked_file ) )
						{
							system "appprocess -l -i -p -f $unpacked_file";
						}
						
					unlink( $unpacked_file ) if ( ! $opt_debug );
				}
		}  # end of $file = readdir( DIR )

	closedir DIR;
			
	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );

    exit;
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "ProcessApp";

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
    my $me = "ProcessUnknown";
    print <<".";
Usage: $me [OPTION(s)]
Process the unknown program info that was emailed to 
unknown\@lightspeedsystems.com


  -h, --help        display this help and exit
  -v, --version     display version information and exit
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "FileDump";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
