################################################################################
#!perl -w
#
# Rob McCarthy's vdir source code
#  Copyright 2007 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use DBI qw(:sql_types);
use DBD::ODBC;
use Digest::MD5;
use String::CRC32;
use File::Copy;


use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Content::Scanable;
use Content::FileIntegrity;
use Content::Category;



my $opt_help;
my $opt_debug;
my $opt_subdir;						# True if I should scan subdirectories
my $opt_wizard;						# True if I shouldn't display headers or footers
my $opt_verbose;					# True if we should be chatty
my $_version = '1.00.00';
my $opt_nonexecutable;				# If True the calculate file IDs for scanable but non executable files
my $opt_unlink;						# If True then delete any file that is not detected as a virus by any AV package
my $opt_copy;
my $opt_move;
my $opt_ignore;
my $opt_dir;
my $log_company;
my $ignore_log_company;



# Globals
my $dbhProgram;						# Handle to the Program database
my %company_count;					# A count by company of the viruses found
my $total = 0 + 0;					# The total number of files found that are "viruses"
my $copied = 0 + 0;
my $moved = 0 + 0;



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
        "c|copy=s"		=> \$opt_copy,
		"i|ignore=s"	=> \$opt_ignore,
		"m|move=s"		=> \$opt_move,
		"d|dir=s"		=> \$opt_dir,
        "s"				=> \$opt_subdir,
        "h|help"		=> \$opt_help,
		"v|verbose"		=> \$opt_verbose,
		"u|unlink"		=> \$opt_unlink,
		"x|xxx"			=> \$opt_nonexecutable
      );


	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
    &Usage() if ( $opt_help );

	
	my @dir_list;
	
	
	# If no arguments, check the current directory	
	if ( $#ARGV < 0 )
		{	my $temp = getcwd;
			$temp =~ s#\/#\\#gm;
			push @dir_list, $temp;
		}
		
	
	if ( ( $opt_copy )  &&  ( $opt_move ) )
		{	print "You can copy or move, but not both\n";
			exit( 0 + 1 );
		}
		
		
	my $log_type = $opt_move;
	$log_type = $opt_copy if ( $opt_copy );	
	
	
	# Sort out all the log companies
	if ( $log_type )
		{	my @types = split /,/, $log_type;
			foreach ( @types )
				{	my $type = $_;
					next if ( ! $type );
					
					my $company = &CategoryLogCompany( $type );
					
					die "Invalid log type $type\n" if ( ! $company );
					
					$log_company .= ", " . $company if ( $log_company );
					$log_company = $company if ( ! $log_company );
				}
		}

	
	print "Log company = $log_company\n" if ( $log_company );
	
	if ( ( $log_type )  &&  ( ! $log_company ) )
		{	print "Unable to find the log company name for log type $log_type\n";
			exit( 0 + 2 );	
		}

	if ( ( $log_company )  &&  ( ! defined $opt_dir ) )
		{	print "No directory defined to copy or move to\n";
			exit( 0 + 3 );
		}

	if ( ( $log_company )  &&  ( ! -d $opt_dir ) )
		{	print "Can not find directory $opt_dir\n";
			exit( 0 + 4 );
		}
		
		
	print "Copying files detected only by $log_company to directory $opt_dir ...\n" if ( $opt_copy );
	print "Moving files detected only $log_company to directory $opt_dir ...\n" if ( $opt_move );
	
	
	$ignore_log_company = &CategoryLogCompany( $opt_ignore ) if ( $opt_ignore );
	if ( ( $opt_ignore )  &&  ( ! $ignore_log_company ) )
		{	print "Unable to find the log company name for ignore log type $opt_ignore\n";
			exit( 0 + 5 );	
		}

	print "Ignoring detection by $ignore_log_company ...\n" if ( $opt_ignore );

	print "Checking subdirectories ...\n" if ( $opt_subdir );
	
	
	# Read the remaining arguments as files or directories to scan
	while ( my $temp = shift )
		{	if ( $temp eq "\." )
				{	push @dir_list, $cwd;
				}
			else	
				{	# If there are no back slashes, assume it needs a back slash
					$temp = $temp . "\\" if ( ! ( $temp =~ m/\\/ ) );
					$temp =~ s#\/#\\#gm;
					push @dir_list, $temp;
				}
		}
				

				
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 0 + 6 );
		}
	
	
	foreach ( @dir_list )
		{	my $item = $_;
					
			next if ( $item =~ m/^\.$/ );	# Skip dot files
			next if ( $item =~ m/^\.\.$/ );	# Skip dot files
					
			if ( -d $item )
				{	&CheckDir( $item );
				}
			elsif ( -f $item )
				{	&CheckFile( $item );										
				}
		}
	
	
	$dbhProgram->disconnect if ( $dbhProgram );
	$dbhProgram = undef;
	

	print "Total virus count: $total\n";
	print "By company:\n";

	my @sorted = sort keys %company_count;
	
	foreach ( @sorted )
		{	my $company = $_;
			next if ( ! $company );
			my $count = $company_count{ $company };
			next if ( ! $count );
			print "\t$company\t$count\n";
		}
	
	print "Copied $copied files\n" if ( $copied );
	print "Moved $moved files\n" if ( $moved );
	
	exit( 0 + 0 );
}
###################    End of MAIN  ################################################



################################################################################
#
sub CheckDir( $ )
#
#  Check all the files in a given directory
#
################################################################################
{
	my $dir_path = shift;

	unless( -r $dir_path ) 
		{	print "Permission denied at $dir_path\n";
			return;
		}
		
	if ( ! opendir( DIRHANDLE, $dir_path ) )
		{	print "Can't open directory $dir_path: $!\n";
			return;
		}
	
	print "Checking directory $dir_path ...\n" if ( $opt_verbose );
	
	for my $item ( readdir( DIRHANDLE ) ) 
		{	( $item =~ /^\.+$/o ) and next;
			
			#$dir_path eq "/" and $dir_path = "";
			my $f;
			if ( $dir_path =~ m#\\+$# )
				{	$f = $dir_path . $item;
				}
			else
				{	$f = $dir_path . "\\" . $item;
				}
			
			
			# If the file is a directory, call recursively
			# If it is a ordinary file, scan it
			if ( -d $f )
				{	&CheckDir( $f ) if ( $opt_subdir );
					next;
				}
				
			&CheckFile( $f );
		}
		
	closedir( DIRHANDLE );
	
	return;
}



################################################################################
#
sub CheckFile( $ )
#
#  Check a file's version info
#
################################################################################
{	my $file = shift;

	return( undef ) if ( ! $file );
	return( undef ) if ( ! -f $file );

	
	my ( $dir, $short_file ) = &SplitFileName( $file );
	
	
	# Is this the type of file that I can calculate a file ID for?
	my $scan_fileid_type = &ScanableFileID( $file, $opt_nonexecutable );
	
	
	if ( $opt_verbose )
		{	print "\nChecking File: $file\n";
			my $desc = &ScanableDescription( $scan_fileid_type );
			print "Scan Type: $desc\n";
		}
		
		
	return( undef ) if ( ! $scan_fileid_type );
		
		
	# If this isn't an executable program, and I'm not supposed to calc this stuff, then return
	if ( ( $scan_fileid_type != 1 )  &&  ( ! $opt_nonexecutable ) )
		{	print "Ignoring this scan type\n" if ( $opt_verbose );
			return( undef );	
		}
	
	
	my $file_id = &ApplicationFileID( $file );
	
	# If no file id, bag it
	if ( ! $file_id )
		{	print "$file does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}
		
	my $hex_file_id = &StrToHex( $file_id );
	
	print "$file\n" if ( ! $opt_verbose );
	print "File ID: $hex_file_id\n" if ( $opt_verbose );
	
	# Does this file ID already exist in the Programs table in the Program database?
	my $sth;
	$sth = $dbhProgram->prepare( "SELECT VirusName, Company FROM FileIDVirus WHERE FileID = \'$hex_file_id\' ORDER BY Company" );
			
	$sth->execute();

	
	my $count = 0 + 0;
	my $file_log_company;
	my $file_virus_name;
	while ( my ( $virus_name, $company ) = $sth->fetchrow_array() )
		{	next if ( ! defined $company );
			
			next if ( ( $ignore_log_company )  &&  ( $ignore_log_company eq $company ) );
			
			print "\t$company: $virus_name\n";
			$count++;
			
			
			# Do I want to copy this file?
			my $qcompany = quotemeta( $company );
			if ( ( $log_company )  &&  ( $log_company =~ m/$qcompany/i ) )
				{	$file_log_company	= $company;
					$file_virus_name	= $virus_name;
				}
				
			
			if ( ! defined $company_count{ $company } )
				{	$company_count{ $company } = 0 + 1;
				}
			else
				{	$company_count{ $company }++;
				}				
		}
 
	$sth->finish();
	

	# Find any program links where I might have downloaded it
	if ( $opt_verbose )
		{	$sth = $dbhProgram->prepare( "SELECT Website, ProgURL, TransactionTime FROM ProgramLink WHERE FileID = \'$hex_file_id\' ORDER BY Website" );
			
			$sth->execute();

	
			my $url_count = 0 + 0;
			while ( my ( $website, $prog_url, $transaction_time ) = $sth->fetchrow_array() )
				{	next if ( ! $prog_url );
					print "\tFound $website: URL $prog_url\n";
				}
				
			$sth->finish();
		}
		
		
	# Am I supposed to delete non-virus files?
	if ( ( $opt_unlink )  &&  ( ! $count ) )
		{	print "Deleting $file ...\n";
			unlink( $file );
		}
	
	
	# Am I supposed to copy virus files?
	my $qcompany = quotemeta( $file_log_company ) if ( $file_log_company );
	if ( ( $file_log_company )  &&  ( $log_company )  &&  ( $log_company =~ m/$qcompany/i ) )
		{	my ( $dir, $short ) = &SplitFileName( $file );
	
			next if ( ! $short );

			my $clean_virus_name = &CleanVirusName( $file_virus_name );
						
			my $virus_dir = &VirusTypeDir( $clean_virus_name );
			
			my $dest_dir = "$opt_dir\\$virus_dir\\$clean_virus_name";
			
			my $ok = &MakeDirectory( $dest_dir );
			if ( ! $ok )
				{	print "Unable to make directory $dest_dir: $!\n";
					exit( 0 + 7 );	
				}
	
			my $dest = "$dest_dir\\$short";
			
			
			if ( $opt_copy )
				{	print "Copying $file to $dest ...\n";
				}
				
			if ( $opt_move )
				{	print "Moving $file to $dest ...\n";
				}
				
			$ok = copy( $file, $dest );
			
			if ( ! $ok )
				{	print "Error copying $file to $dest: $!\n";
					exit( 0 + 8 );
				}
				
			if ( ! -e $dest )
				{	print "Error copying $file to $dest\n";
					exit( 0 + 9 );
				}
			
			$copied++ if ( $opt_copy );
			$moved++ if ( $opt_move );
			
			unlink( $file ) if ( $opt_move );
		}

	$total++ if ( $count );
	
	return( 1 );
}



################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Return OK if the directory already exists
	return( 1 ) if ( -d $dir );
	
	my @parts = split /\\/, $dir;
	
	my $created_dir;
	foreach ( @parts )
		{	next if ( ! defined $_ );
			
			$created_dir .= "\\" . $_ if ( defined $created_dir );
			$created_dir = $_ if ( ! defined $created_dir );

			if ( ! -d $created_dir )
				{	mkdir( $created_dir );
				}
		}
		
	# Return OK if the directory now exists
	return( 1 ) if ( -d $dir );
	
	return( undef );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "vdir";

    print <<".";
scan $_version
.

    exit;
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "vdir";
	
    print <<".";

Usage: vdir [list]
List directories and/or files and display the files and which
AV company detects the file as a virus.

Logtypes are: AdAware, DrWeb, Clam, ClamScan, F-Prot, F-ProtOld, F-Secure,
Kaspersky, McAfee, NOD32, Norton, NortonExport, SA (Security Agent), Sophos,
TrendMicro, PCCillin, Windefender, AVG, MalwareBytes, and 
Winlog (Windefender Log format)

Possible options are:

  -c, --copy LOGTYPE    copy files that are matched by LOGTYPE
                        (multiple logtypes are supported)
  -d, --dir DIR         directory DIR to copy or move LOGTYPE files to
  -i, --ignore LOGTYPE  ignore matches by LOGTYPE
  -m, --move LOGTYPE    move files that are matched by LOGTYPE
                        (multiple logtypes are supported)
  -s                    display subdirectories recursively
  -u, --unlink          to delete files that are NOT viruses
  -v, --verbose         show file info, program URLs
  -x, --nonexecutable   also display scanable but nonexecutable

  -h, --help            print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
