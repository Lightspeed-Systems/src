################################################################################
#!perl -w
#
# Archive - archives downloaded token, link, and label files
#
################################################################################



# Pragmas
use strict;
use warnings;



use Getopt::Long;
use Cwd;

use Content::File;
use Content::Archive;


# Options
my $opt_help;
my $opt_version;
my $opt_source_directory;		# This is the directory of token, link, and label files to archive
my $opt_copy;					# If True, then do a copy, not a move
my $opt_move = 1;				# If True, then do a move, not a copy
my $opt_maxfiles = 0 + 10000;	# This is the maximum number of domains to move in one shot
my $opt_quick;					# If True then copy as quickly as possible
my $opt_zip;					# If True the zip in place tokens files
my $opt_archive;				# If set, this is a domain to show the destingation directory for


my $main_dest_directory			= 'I:\\HashArchive';	# This is the root of the main archive directory
my $backup_dest_directory;								# This is the root of the backup archive directory

my $_version = "1.0.0";
my $fast_copy;					# If set, then do a fast copy without zipping the entire directory



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
        "a|archive=s"		=>	\$opt_archive,
        "b|backup=s"		=>	\$backup_dest_directory,
        "c|copy"			=>	sub {	$opt_copy = 1;	$opt_move = undef; },
        "d|destination=s"	=>	\$main_dest_directory,
        "f|fast"			=>	\$fast_copy,
        "l|limit=i"			=>	\$opt_maxfiles,
        "m|move"			=>	sub {	$opt_copy = undef;	$opt_move = 1; },
        "n|nobackup"		=>	sub {	$backup_dest_directory = undef;	},
        "q|quick"			=>	\$opt_quick,
        "s|source=s"		=>	\$opt_source_directory,
        "z|zip"				=>	\$opt_zip,

        "v|version"			=>	\$opt_version,
        "h|help"			=>	\$opt_help
    );
	

    &StdHeader( "Archive" );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );


	if ( $opt_archive )
		{	my $root = &RootDomain( $opt_archive );
			
			if ( ! $root )
				{	print "$opt_archive is not a valid domain name\n";
				}
			else
				{	my $dest_dir = &DomainDestinationDir( $main_dest_directory, $root );
					print "The archive directory for $opt_archive is $dest_dir\n";
				}
				
			&StdFooter;

			exit;
		}
		
		
	# Read the command line
	$opt_source_directory = shift if ( ! $opt_source_directory );
	
	
	# If nothing specified, then use the current directory as the source directory
	if ( ( ! $opt_source_directory )  ||  ( $opt_source_directory eq "." ) )
		{	$opt_source_directory = getcwd;
			$opt_source_directory =~ s#\/#\\#gm;	
		}
		
	my $str = shift;
	$main_dest_directory = $str if ( $str );


	print "Limit the number of domains to process at one time to $opt_maxfiles\n" if ( $opt_maxfiles );
	
	
	# Am I zipping in place?
	if ( $opt_zip )
		{	&ArchiveZipInPlace( $opt_source_directory );
			&StdFooter;
			exit;
		}
		
		
	# Am I quick copying?
	if ( ( $backup_dest_directory )  &&  ( $opt_quick ) )
		{	print "Quick copying - so not copying to $backup_dest_directory\n"; 
			$backup_dest_directory = undef;
		}
		
	if ( ( $opt_copy )  &&  ( $opt_move ) )
		{	print "You can do a copy or a move, but not both!\n";
			exit( 0 );
		}

	if ( ! -d $opt_source_directory )
		{	print "Can not find source directory $opt_source_directory\n";
			exit( 0 );
		}

	if ( ! -d $main_dest_directory )
		{	print "Can not find archive directory $main_dest_directory\n";
			exit( 0 );
		}

	if ( ( $backup_dest_directory )  &&  ( ! -d $backup_dest_directory ) )
		{	print "Can not find archive directory $backup_dest_directory\n";
			exit( 0 );
		}



	# Figure out if I'm moving or copying
	my $move;
	
	$move = 1 if ( $opt_move );
	$move = undef if ( $opt_copy );


	print "Archiving from directory $opt_source_directory ...\n";
	print "Archive copying tokens file to backup directory $backup_dest_directory ...\n" if ( $backup_dest_directory );
	print "Archive copying tokens file to directory $main_dest_directory ...\n" if ( ! $move );
	print "Archive moving tokens file to directory $main_dest_directory ...\n" if ( $move );
	
		
	# Process the source directory
	opendir( DIR, $opt_source_directory );

	print "Loading up files to archive ...\n";
	my $running_count = 0 + 0;
	
	my %domains;
	while ( my $file = readdir( DIR ) )
		{	next if ( ! $file );
			
			# Skip subdirectories
			next if (-d $file );
	
			# Is this file one of the dump type files?
			$file = lc( $file );
			
			my $dump_file;
			$dump_file = ".tokens.txt"	if ( $file =~ m/\.tokens\.txt$/ );
			$dump_file = ".links.txt"	if ( $file =~ m/\.links\.txt$/ );
			$dump_file = ".labels.txt"	if ( $file =~ m/\.labels\.txt$/ );
			$dump_file = ".site.txt"	if ( $file =~ m/\.site\.txt$/ );
			$dump_file = ".image.zip"	if ( $file =~ m/\.image\.zip$/ );
			$dump_file = ".dump.zip"	if ( $file =~ m/\.dump\.zip$/ );
			
			next if ( ! $dump_file );
			
			my $domain = $file;
			$domain =~ s/$dump_file$//;
			next if ( ! defined $domain );
			
			$domains{ $domain } = 1;
			
			$running_count ++;
			
			if ( ( $opt_maxfiles )  &&  ( $running_count >= $opt_maxfiles ) )
				{	print "Reached the limit of $opt_maxfiles of domains at a time\n";
					print "Doing a fast copy because $opt_maxfiles domains need to archive\n";
					$fast_copy = 0 + 1;
					last;	
				}
		}


	closedir( DIR );


	# Actually archive the dump files
	my @domains = sort keys %domains;

	my $dcount = $#domains + 1;
	
	if ( ! $dcount )
		{	print "Found nothing to archive\n";
			
			&StdFooter;

			exit;
		}
		
	print "Found $dcount unique domain names to archive\n";
	print "Found $running_count unique files to archive\n";
	
	print "Waiting 60 seconds for all copies to finish ...\n";
	sleep( 60 );
	
	if ( $backup_dest_directory )
		{	print "Archive copying to $backup_dest_directory ...\n";
			&Archive( $opt_source_directory, $backup_dest_directory, \@domains, 1, $opt_quick, $fast_copy ) if ( $#domains > -1 );
		}
		
	my $keep = 1 if ( ! $move );

	print "Archive copying to $main_dest_directory ...\n" if ( ! $move );
	print "Archive moving to $main_dest_directory ...\n" if ( $move );

	&Archive( $opt_source_directory, $main_dest_directory, \@domains, $keep, $opt_quick, $fast_copy ) if ( $#domains > -1 );
		
	&StdFooter;

    exit;
}



################################################################################
#
sub ArchiveZipInPlace( $ )
#
#
################################################################################
{	my $source_dir	= shift;
	
	# Process the source directory
	opendir( DIR, $source_dir );

	print "Loading up files to zip in place ...\n";
	my %domains;
	my $running_count = 0 + 0;
	
	while ( my $file = readdir( DIR ) )
		{	next if ( ! $file );
			
			# Skip subdirectories
			next if (-d $file );
	
			# Is this file one of the dump type files?
			$file = lc( $file );
			
			my $dump_file;
			$dump_file = ".tokens.txt"	if ( $file =~ m/\.tokens\.txt$/ );
			$dump_file = ".links.txt"	if ( $file =~ m/\.links\.txt$/ );
			$dump_file = ".labels.txt"	if ( $file =~ m/\.labels\.txt$/ );
			$dump_file = ".site.txt"	if ( $file =~ m/\.site\.txt$/ );
			$dump_file = ".image.zip"	if ( $file =~ m/\.image\.zip$/ );
			
			next if ( ! $dump_file );
			
			my $domain = $file;
			$domain =~ s/$dump_file$//;
			next if ( ! defined $domain );
			
			$running_count++ if ( ! defined $domains{ $domain } );
			$domains{ $domain } = 1;
			
			if ( ( $opt_maxfiles )  &&  ( $running_count >= $opt_maxfiles ) )
				{	print "Reached the limit of $opt_maxfiles of domains at a time\n";
					last;	
				}
 		}

	closedir( DIR );


	# Actually zip the dump files
	my @domains = sort keys %domains;

	my $dcount = $#domains + 1;
	
	if ( ! $dcount )
		{	print "Found nothing to zip in place\n";
			return( undef );
		}
	
	print "Found tokens files for $dcount domains\n";
	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	chdir( $source_dir );


	my $counter = 0 + 0;	
	foreach ( @domains )
		{	next if ( ! defined $_ );
			my $domain = $_;

			$counter++;
			
			my $ok = &ArchiveZip( $source_dir, $domain, $source_dir, $counter );
			next if ( ! $ok );
		}
		
	chdir( $cwd );

	print "Successfully zipped up tokens files from $counter different domains\n";
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "Archive [sourcedir] [archivedir]";
    print <<".";
Usage: $me [OPTION(s)]

    
  -a, --archive DOMAIN     Show the archive directory for the given domain
  -b, --backup=ARCHIVEDIR  backup directory to save the token files to.
  -c, --copy               copy to the archive directory
  -d, --dest=ARCHIVEDIR    root directory to save the token files to.
                           Default is $main_dest_directory
  -l, --limit LIMIT        the limit of number of domains at one time
  -m, --move               move to the archive directory DEFAULT
  -n, --nobackup           to NOT use a backup directory
  -q, --quick              to quick copy files DEFAULT
  -s, --source=SOURCEDIR   source directory of tokens files to archive.
  -z, --zip                zip in place the tokens files
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
    my $me = "Archive";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
