################################################################################
#!perl -w
#
#  Export from the database a list of virus infected files
#  subject to various search options
#
#  Copyright 2007 Lightspeed Systems Inc. by Rob McCarthy
#
################################################################################



# Pragmas
use strict;
use warnings;



use Cwd;
use Getopt::Long();
use File::Copy;
use DBI qw(:sql_types);
use DBD::ODBC;


use Content::File;
use Content::SQL;
use Content::Category;



my $opt_help;
my $opt_dir;			# This is directory to copy the virus files to
my $opt_logtype;		# This is the type of virus log file I am analyzing
my $opt_filename;		# The is the filename of the virus log file
my $opt_debug;
my $opt_newer;
my $opt_older;
my $opt_verbose;		# True if I should be verbose about what I am doing
my $opt_archive;
my $opt_exclude;		# A file of CRC32 values to exclude
my $opt_unique;			# True if I am only supposed to export unique virus names

my %crc32;				# A hash of crc32 values to exclude
my %unique_virus_name;	# A hash of unique virus names if I am only supposed to export unique viruses


my $dbhProgram;			# Handle to the Program database



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
		"a|archive"		=> \$opt_archive,
		"e|exclude=s"	=> \$opt_exclude,
		"l|logtype=s"	=> \$opt_logtype,
		"n|newer=s"		=> \$opt_newer,
		"o|older=s"		=> \$opt_older,
		"u|unique"		=> \$opt_unique,
        "h|help"		=> \$opt_help,
        "x|xdebug"		=> \$opt_debug
      );


    &StdHeader( "VirusExport" );
	&Usage() if ( $opt_help );


	$opt_filename	= shift;
			

	&Usage() if ( ! $opt_filename );
	
	
	# Check to make sure that I have a valid log file type if it is defined
	my $ok = 1;
	$ok = undef if ( ( defined $opt_logtype )  &&
		( lc( $opt_logtype ) ne "f-prot" )  &&
		( lc( $opt_logtype ) ne "f-protold" )  &&
		( lc( $opt_logtype ) ne "adaware" )  &&
		( lc( $opt_logtype ) ne "drweb" )  &&
		( lc( $opt_logtype ) ne "clam" )  &&
		( lc( $opt_logtype ) ne "clamscan" )  &&
		( lc( $opt_logtype ) ne "mcafee" )  &&
		( lc( $opt_logtype ) ne "norton" )  &&
		( lc( $opt_logtype ) ne "nortonexport" )  &&
		( lc( $opt_logtype ) ne "sophos" )  &&
		( lc( $opt_logtype ) ne "fsecure" )  &&
		( lc( $opt_logtype ) ne "f-secure" )  &&
		( lc( $opt_logtype ) ne "winlog" )  &&
		( ! ( $opt_logtype =~ m/^windefen/i ) )  &&
		( ! ( $opt_logtype =~ m/^kasp/i ) )  &&
		( ! ( $opt_logtype =~ m/^trend/i ) )  &&
		( lc( $opt_logtype ) ne "sa" ) );
					
	if ( ! $ok )
		{	print "Invalid log file type.\n";
			print "Must be AdAware, Clam, DrWeb, F-Prot, F-Secure, Kaspersky,\nMcAfee, Norton, SA, Sophos, TrendMicro, or Windefender.\n";
			exit();	
		}


	if ( $opt_newer )
		{	$ok = &ValidateDate( $opt_newer );
			
			if ( ! $ok )
				{	print "$opt_newer is not a valid date in the format MM/DD/YYY\n";
					exit( 1 );	
				}
		}


	if ( $opt_older )
		{	$ok = &ValidateDate( $opt_older );
			
			if ( ! $ok )
				{	print "$opt_older is not a valid date in the format MM/DD/YYY\n";
					exit( 1 );	
				}
		}


	print "Verifing that the files still exist in the virus archive ...\n";
	
	if ( ! open( LISTFILE, ">$opt_filename" ) )
		{	print "Unable to open file $opt_filename: $!\n";
			
			exit( 1 );
		}
		

	# Do I need to build up a hash of excluded crc32s?
	if ( $opt_exclude )
		{	if ( ! open( EXCLUDE, "<$opt_exclude" ) )
				{	print "Unable to open file $opt_exclude: $!\n";
			
					exit( 1 );
				}
		
			print "Reading exclusion list from $opt_exclude ...\n";
			my $counter = 0 + 0;
			while ( my $line = <EXCLUDE> )
				{	chomp( $line );
					next if ( ! $line );
					my ( $crc32, $junk ) = split /\s/, $line;
					next if ( ! $crc32 );
					
					# Does the crc32 contain a path?
					if ( $crc32 =~ m/\\/ )
						{	my ( $crc32_dir, $crc32_file ) = &SplitFileName( $crc32 ); 
							next if ( ! $crc32_file );
							my $ext;
							
							( $crc32, $ext ) = split /\./, $crc32_file;
							next if ( ! $crc32 );
						}
						
					$crc32 = uc( $crc32 );
					next if ( length( $crc32 ) != 8 );
					
					$crc32{ $crc32 } = 1;
					
					$counter++;
				}
				
			close( EXCLUDE );
			
			print "Read $counter crc32 values to exclude\n";
		}
		

	$dbhProgram = &ConnectRemoteProgram();
	
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			close( LISTFILE );
			exit( 0 );
		}


	# Actually do the work here ...
	&VirusExport();
	
	
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
	close( LISTFILE );
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
#
sub VirusExport()
#
#  Export the data from the Program database
#
################################################################################
{	
	my $str;
	
	if ( ! $opt_logtype )
		{	$str = "SELECT [Filename], Appname, CRC32 FROM Programs";
			$str .= "\nWHERE [Filename] LIKE \'\%virus archive\%\'";
			$str .= "\nAND TransactionTime > \'$opt_newer\'" if ( $opt_newer );
			$str .= "\nAND TransactionTime <= \'$opt_older\'" if ( $opt_older );
			
			$str .= "\nORDER BY [Filename]";
		}
	else
		{	my $log_company = &CategoryLogCompany( $opt_logtype );
			$str = "SELECT [Filename], Appname, CRC32 FROM Programs\nWHERE FileID IN ( SELECT FileID from FileIDVirus WHERE Company = \'$log_company\' )";
			$str .= "\nAND TransactionTime > \'$opt_newer\'" if ( $opt_newer );
			$str .= "\nAND TransactionTime <= \'$opt_older\'" if ( $opt_older );

			$str .= "\nORDER BY [Filename]";
		}
		
	
	print "SELECT Statement:\n$str\n";
	
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();
	my $rows = 0 + $sth->rows;

	my $counter = 0 + 0;
	while ( ( ! $dbhProgram->err )  &&  ( my ( $file, $virus, $crc32 ) = $sth->fetchrow_array() ) )
		{	next if ( ! defined $file );
			next if ( ! defined $virus );
			
			next if ( ( $opt_archive )  &&  ( ! -f $file ) );
			
			next if ( ! ( $file =~ m/virus archive/i ) );
			
			# Do I need only uique viruses?
			if ( $opt_unique )
				{	next if ( exists $unique_virus_name{ $virus } );
					$unique_virus_name{ $virus } = 1;
				}
				
			# Is this crc32 excluded?
			if ( $crc32 )
				{	$crc32 = uc( $crc32 );
					next if ( ( $opt_exclude )  &&  ( exists $crc32{ $crc32 } ) );
				}
			elsif ( $opt_exclude )
				{	$crc32 = &HexCRC32( $file );
					next if ( ! $crc32 );
					$crc32 = uc( $crc32 );
					next if ( exists $crc32{ $crc32 } );
				}
			
			$counter++;
					
			print LISTFILE "$file\t$virus\t$crc32\n";
		}

	$sth->finish();
	
	print "Found $counter rows that matched\n";
	
	return( 1 );
}



################################################################################
# 
sub HexCRC32( $ )
#
#	Given a file name, return the hex CRC-32 hash
#   Return undef if not found
#
################################################################################
{	my $file = shift;
	
use String::CRC32;
  
	open( CRCHANDLE, "<$file" ) or return( undef );
	
    binmode( CRCHANDLE );
	
	my $crc = crc32( *CRCHANDLE );

	close( CRCHANDLE );	
	
	return( undef ) if ( ! defined $crc );
	
	my $hex_crc = uc( sprintf( "%08x", $crc ) );

	return( $hex_crc );
}



################################################################################
# 
sub ValidateDate( $ )
#
#  Check that a date string is valid
#
################################################################################
{	my $date = shift;

	return( 1 ) if ( ! defined $date );
	
	my ( $mon, $mday, $year ) = split /\//, $date;
	
	return( undef ) if ( ! $mon );
	return( undef ) if ( ! $mday );
	return( undef ) if ( ! $year );
	
	return( undef ) if ( $mon =~ m/\D/ );
	return( undef ) if ( $mday =~ m/\D/ );
	return( undef ) if ( $year =~ m/\D/ );


	$mon = 0 + $mon;
	return( undef ) if ( ( $mon < 1 )  ||  ( $mon > 12 ) );
	return( undef ) if ( ( $mday < 1 )  ||  ( $mday > 31 ) );
	return( undef ) if ( ( $year < 2007 )  ||  ( $year > 2100 ) );
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";

Usage: VirusExport listfile [options]

This utility exports outs of the Program database virus information to 
listfile.  The listfile format is Filename [tab] Virus Name.

Logtypes are: AdAware, DrWeb, Clam, F-Prot, F-Secure, Kaspersky, McAfee,
Norton, SA (Security Agent), Sophos, TrendMicro, and Windefender.

Possible options are:

  -a, --archive         to check that the file still exists in the archive
  -e, --exclude EXCLUDE to import of list of CRC32 values from file EXCLUDE
  -l, --logtype LOGTYPE to export only viruses discovered by LOGTYPE
  -n, --newdate DATE    to export only viruses newer than DATE - MM/DD/YYYY
  -o, --olddate DATE    to export only viruses older than DATE - MM/DD/YYYY
  -u, --unique          to export only 1 copy of each virus name
  -h, --help            print this message and exit

.

exit;
}



################################################################################

__END__

:endofperl
