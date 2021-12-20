################################################################################
#!perl -w
#
# Process SQL .eml files that were emailed to database@lightspeedsystems.com
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
use Content::SqlReload;


# Options
my $opt_help;
my $opt_version;
my $opt_source_directory;
my $dbh;
my $dbhStat;
my $opt_debug;



# This is the list of tables to backup and restore local data for
my @tables = qw( VirusSignatures IpmContentCategory ApplicationProcesses BannedProcesses IntrusionRuleSet 
IpmContentCategoryHits IpmContentCategoryMisses IpmContentDomain IpmContentIpAddress IpmContentURL RegistryControl
SpamPatterns DisinfectScripts );



# This is the hash of the unique keys for each of the tables
my %table_key = ( 
'IpmContentCategory'		=> 'CategoryName',
'ApplicationProcesses'		=> 'FileID',
'BannedProcesses'			=> 'Process',
'DisinfectScripts'			=> 'VirusName',
'IntrusionRuleSet'			=> 'Name',
'IpmContentCategoryHits'	=> 'URL',
'IpmContentCategoryMisses'	=> 'URL',
'IpmContentDomain'			=> 'DomainName',
'IpmContentIpAddress'		=> 'IpAddress',
'IpmContentURL'				=> 'URL',
'RegistryControl'			=> '[Key]',
'SpamPatterns'				=> 'Name',
'VirusSignatures'			=> 'VirusName'
);



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


    &StdHeader( "ProcessSQL" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );


	if ( ! $opt_source_directory )
		{   $opt_source_directory = getcwd;
			$opt_source_directory =~ s#\/#\\#gm;
		}
		
	if ( ! -d $opt_source_directory )
		{	&FatalError( "Can not find directory $opt_source_directory\n" );
		}

   &SetLogFilename( "$opt_source_directory\\ProcessSQL.log", undef );
		
		
	&lprint( "Opening a connection to the local SQL database ...\n" );
	$dbh = &ConnectServer();
	if ( ! $dbh )
		{	&lprint( "Unable to connect to the Content database\n" );
			exit;	
		}


	# Process the source directory
	opendir DIR, $opt_source_directory;

	my $file;
	my $counter = 0 + 0;
	my $total = 0 + 0;
	my $file_count = 0 + 0;
	
	while ( $file = readdir( DIR ) )
		{
			# Skip subdirectories
			next if (-d $file);
			
			my $src	= $opt_source_directory . "\\" . $file;
			
			# Does the file exist?  It might have been deleted by another task
			next if ( ! -e $src );

			# Is it an eml file?			
			next if ( ! ( $src =~ m/\.eml$/i ) );
			
#			&lprint( "Processing file $file ...\n" );

			$counter++;
			
			$src =~ m/\((.*?)\)/;
			
			my $server_name = $1;
			
			my ( $junk, $date_crap ) = split /since /, $src, 2;

			my $date;			
			( $date, $junk ) = split /\s/, $date_crap, 2;
			
			if ( ( defined $date )  &&  ( $date =~ m/\_xf8ff/ ) )
				{	$date =~ s/\_xf8ff/\-/g;
					$date =~ s/\_//g;
				}
			
			my ( $junk1, $ip, $junk2 ) = split / - /, $src, 3;

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
					
					my $short_file = $parts[ $#parts ];

#					&lprint( "Extracting file $short_file ...\n" );
					
					my $error_code = $zip->extractMemberWithoutPaths( $member, $short_file );
					
					if ( $error_code != AZ_OK )
						{	&lprint( "Scan error: extracting $short_file: $error_code\n" );
						}
					else
						{	push @files, $short_file;
						}
				}
		
			unlink ( $zipped_file ) if ( ! $opt_debug );
			
#			&RestoreLocal( $opt_source_directory );


			foreach ( @files )
				{	next if ( ! defined $_ );
					my $unpacked_file = $_;
					
					if ( $unpacked_file =~ m/TrafficClassSearchQuery\.sql\.dat/i )										
						{	$file_count++;
							
							my $new_name = $server_name . " - " . $date . " - " . $unpacked_file;
							$new_name = $ip . " - " . $server_name . " - " . $date . " - " . $unpacked_file if ( defined $ip );
							
							rename( $unpacked_file, $new_name );
							
							my $count = &lines( $new_name );
							
							&lprint( "$new_name has $count lines\n" );
							
							$total = $total + $count;
							
							my $ok = &InsertTrafficClassSearch( $new_name, $server_name );
							die if ( ! $ok );
						}
					else
						{	unlink( $unpacked_file ) if ( ! $opt_debug );
						}
				}
			
		}  # end of $file = readdir( DIR )

	closedir DIR;
	
	&lprint( "Total files = $file_count\n" );
	&lprint( "Total lines = $total\n" );
	
	#  Close up the databases and quit
	$dbh->disconnect if ( $dbh );
	$dbhStat->disconnect if ( $dbhStat );

    exit;
}



################################################################################
#
sub InsertTrafficClassSearch( $$ )
#
#  Insert data from text file into SQL
#
################################################################################
{	my $file = shift;
	my $server_name = shift;
	
	$dbhStat = &ConnectStatistics() if ( ! $dbhStat );
	if ( ! $dbhStat )
		{	&lprint( "InsertTrafficClassSearch: Unable to connect to the Statistics database\n" );
			return( undef );
		}
	
	if ( ! open( FILE, "<$file" ) )
		{	&lprint( "Error opening $file: $!\n" );
			return( undef );	
		}


	&lprint( "Inserting file $file into the Statistics database ...\n" );
	
	
	my $format = <FILE>;
	
	$server_name =~ s/\'//g;
	
	my $data_counter = 0 + 0;
	while (<FILE>)
		{	my $line = $_;
			next if ( ! defined $line );
			
			chomp( $line );
			
			my ( $ip, $site, $query_string, $time ) = split /\t/, $line, 4;
			next if ( ! defined $query_string );
			
			my $ip_str = &IPToString( $ip );
			my $host = $server_name . ":" . $ip_str;
			
			$dbhStat = &SqlErrorCheckHandle( $dbhStat );

			return( undef ) if ( ! $dbhStat );
			return( undef ) if ( $dbhStat->err );
			
			$query_string	=~ s/\'//g;
			$site			=~ s/\'//g;
			$query_string	=~ s/\'//g;
			$time			=~ s/\'//g;
			
			my $str = "INSERT INTO TrafficClassSearchQuery ( ObjectId, [Time], IpAddress, UserName, HostName, Site, QueryString )
												VALUES ( '60860001-8521-4816-BABC-D8C3870FC9D0', \'$time\', ?, \'Anon\', \'$host\', \'$site\', \'$query_string\' )";

			my $sth = $dbhStat->prepare( $str );
			$sth->bind_param( 1, $ip, DBI::SQL_BINARY );
			$sth->execute();
					
			$data_counter++ if ( $sth->rows );
		}

	&lprint( "Inserted $data_counter rows\n" );
	
	return( 1 );	
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

	return( $counter );
}



################################################################################
#
sub RestoreLocal( $ )
#
#  Restore the local entries
#
################################################################################
{	my $dir = shift;
	
	$dbh = &ConnectServer() if ( ! $dbh );
	if ( ! $dbh )
		{	&lprint( "RestoreLocal: Unable to connect to the Content database\n" );
			return( undef );
		}
		
	foreach ( @tables )
		{	next if ( ! $_ );
			my $table = $_;
			
			my $lc_table = lc( $table );
			
			
			# Only insert data from the tables that I'm interested in ...
			my $interest;
			$interest = 1 if ( $lc_table eq "ipmcontentdomain" );
			$interest = 1 if ( $lc_table eq "ipmcontentipaddress" );
			next if ( ! $interest );
			
			
			# Open a file to read this data from
			my $handle;
			my $datafile = "$dir\\$table.sql.dat";
			
			if ( ! open $handle, "<$datafile" )
				{	#&lprint( "Unable to open file $datafile: $!\n" );
					next;	
				}
				
			&lprint( "Restoring data from table $table ...\n" );
			
			my @columns = &ReadColumn( $handle, 0 );
			
			# Figure out the number of columns in this table
			my $column_count = $#columns;
			
			if ( ! $columns[ 0 ] )
				{	&lprint( "No column data from data file $datafile\n" );
					close $handle;
					$handle = undef;
					next;	
				}
			
			
			# Find the key column number
			my $key_name = $table_key{ $table };
			
			if ( ! $key_name )
				{	&lprint( "No key defined for table $table\n" );
					close $handle;
					$handle = undef;
					next;	
				}
			
			my $lc_key_name = lc( $key_name );
			my $key_column;	
			my $ipaddress_column;	# If an IpAddress is in the table, I have to do a bind parameter
			my $counter = 0 + 0;
			my $category_column;	# The column number of the "CategoryNumber" column
			
			foreach ( @columns )
				{	next if ( ! $_ );
					
					my $lc_column = lc( $_ );
					
					$key_column = $counter if ( $lc_key_name eq $lc_column );
					$ipaddress_column = $counter if ( "ipaddress" eq $lc_column );
					
					$category_column = $counter if ( "categorynumber" eq $lc_column );
					$counter++;
				}
				

			# Did I find the column that the key is in?
			if ( ! defined $key_column )
				{	&lprint( "No key column found for table $table\n" );
					close $handle;
					$handle = undef;
					next;	
				}
				
				
			# Now insert the local data back into the database
			
			# Build up the column names in the right format for an insert
			my $column_names;
			
			foreach ( @columns )
				{	next if ( ! $_ );
					
					$column_names = $column_names . ", " . $_ if ( $column_names );
					$column_names = $_ if ( ! $column_names );
				}
				
			my $data_counter = 0 + 0;
			
			&lprint( "Starting insert for table $table ...\n" );
			my $done;
			while ( ! $done )
				{	my @column_data = &ReadColumn( $handle, $column_count );

					last if ( ! defined $column_data[ 0 ] );
				
					# Is this column data that I want to insert?
					# For now, I'm only interested in the spam category
					next if ( ( defined $category_column )  &&
							 ( $column_data[ $category_column ] != 55 ) );
							 
					# Delete any row that matches my key
					my $key_value = $column_data[ $key_column ];
					
					# Changed single quotes into double single quotes for the column key
					$key_value =~ s/\'/\'\'/g;

					my $str = "DELETE $table WHERE $key_name = \'$key_value\'";
					
					# Special case for Ip Address
					$str = "DELETE $table WHERE $key_name = ?" if ( $lc_key_name eq "ipaddress" );
						
					$dbh = &SqlErrorCheckHandle( $dbh );

					return( undef ) if ( ! $dbh);
					return( undef ) if ( $dbh->err );
			
					my $sth = $dbh->prepare( $str );
					
					$sth->bind_param( 1, $key_value, DBI::SQL_BINARY ) if ( $lc_key_name eq "ipaddress" );

					$sth->execute();
					
					$dbh = &SqlErrorCheckHandle( $dbh );
					return( undef ) if ( ! $dbh);
					return( undef ) if ( $dbh->err );

					# If no problems, go ahead and insert the row data back in
					my $values;
					$counter = 0 + 0;
					my $ip_address;
					foreach ( @column_data )
						{	next if ( ! defined $_ );
							
							my $data = $_;
							
							# Changed single quotes into double single quotes for each column data
							my $quoted = $data;
							$quoted =~ s/\'/\'\'/g;
							
							my $val = "\'$quoted\'";	# Put single quotes around it
							$val = 'NULL' if ( $data eq 'NULL' );	# Is it an undefined value?
							
							
							# Is it an IP Address column?
							if ( ( defined $ipaddress_column )  &&  ( $counter eq $ipaddress_column ) )
								{	$val = "?" ;
									$ip_address = $data;
								}
								
							$values = $values . ", " . $val if ( $values );
							$values = $val if ( ! $values );
							
							$counter++;
						}

									
					$str = "INSERT INTO $table ( $column_names ) VALUES ( $values )";


					# Special case for IpmContentCategory table
					if ( $lc_table eq "ipmcontentcategory" )
						{	my $category_insert = "set identity_insert IpmContent..IpmContentCategory on " . $str . " set identity_insert IpmContent..IpmContentCategory off";
							$str = $category_insert;
						}
						
						
					$dbh = &SqlErrorCheckHandle( $dbh );


					return( undef ) if ( ! $dbh);
					return( undef ) if ( $dbh->err );
			
					$sth = $dbh->prepare( $str );
					$sth->bind_param( 1, $ip_address, DBI::SQL_BINARY ) if ( defined $ip_address );
					$sth->execute();
					
					$data_counter++;
				}
				
			close $handle;
			$handle = undef;

			
			&lprint( "Restored $data_counter rows of local data for table $table\n" );
		}
		
		
	$dbh->disconnect if ( $dbh );
	$dbh = undef;


	return( 1 );	
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "ProcessSQL";

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
    my $me = "ProcessSQL";
    print <<".";
Usage: $me [OPTION(s)]
Process the database update info that was emailed to 
database\@lightspeedsystems.com


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
