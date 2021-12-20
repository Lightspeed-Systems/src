################################################################################
#!perl -w
#
# Rob McCarthy's Registrycontrol source code
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Cwd;
use Getopt::Long();
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use DBI qw(:sql_types);
use DBD::ODBC;



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_dir;
my $opt_wizard;						# True if I shouldn't display headers or footers
my $opt_append;						# True if it should be appended to the file
my $opt_database;					# True if it shoud inject the file into the database
my $opt_file = "RegistryControl.dat";	# Name of the file to create
my $opt_name;						# Application name to force - mostly used for "Windows" directory
my $opt_verbose;					# True if we should be chatty
my $opt_insert;						# True if I should just insert the appprocess.txt file into the database
my $opt_export;						# True if I should export from the database to the appprocess.txt file
my $opt_quick;						# True if I should calculate the quick file ID
my $opt_category;					# True if I should import/export just a single category name
my $opt_source_num = 0 + 2;			# The source number to use when adding a row
my $opt_category_num = 0 + 6;		# The category number to use when importing
my $_version = '1.00.00';



# Globals
my $dbh;
my $add_counter = 0 + 0;
my $update_counter = 0 + 0;




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
        "a|append"		=> \$opt_append,
		"c|category=s"	=> \$opt_category,
		"d|database"	=> \$opt_database,
		"e|export"		=> \$opt_export,
		"f|file=s"		=> \$opt_file,
        "h|help"		=> \$opt_help,
		"i|insert"		=> \$opt_insert,
		"n|name=s"		=> \$opt_name,
		"s|source=s"	=> \$opt_source_num,
		"v|verbose"		=> \$opt_verbose,
		"x|xxx"			=> \$opt_debug
      );


	$opt_source_num = 0 + $opt_source_num;
	if ( ( $opt_source_num <= 0 )  ||  ( $opt_source_num >= 100 ) )
		{	print "Bad source number = $opt_source_num\n";
			exit( 0 );
		}
	
	print( "Registry Control utility\n" ) if ( ! $opt_wizard );


	
	#  Figure out what directory to use
    my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	$opt_dir = $cwd if ( !$opt_dir );
	
	
    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	
	$dbh = &ConnectServer() or die;
	
	if ( ! &SqlTableExists( "RegistryControl" ) )
		{	print "The RegistryControl table does not exist in the local IpmContent database\n";
			exit;
		}
		
	&LoadCategories();

	
	
	# Am I just supposed to insert the file into the database?
	if ( $opt_insert )
		{	&InsertFile( $opt_file );
			$dbh->disconnect if ( $dbh );
			print "Added $add_counter entries to the RegistryControl table\n";
			print "Updated $update_counter entries to the RegistryControl table\n";

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
	
	
	# Am I just supposed to export database to a file?
	if ( $opt_export )
		{	&ExportFile( $opt_file );
			$dbh->disconnect if ( $dbh );

			&StdFooter if ( ! $opt_wizard );
			exit;
		}
		
	
	$dbh->disconnect if ( $dbh );

	&StdFooter if ( ! $opt_wizard );
	
	exit;
}
###################    End of MAIN  ################################################



################################################################################
# 
sub ExportFile( $ )
#
#	Export the database into a file 
#
################################################################################
{	my $file = shift;
	
	print "Exporting the RegistryControl table to $file\n";
	
	if ( ! open OUTPUT, ">$file" )
		{	print "Unable to open file $file: $!\n";
			return;
		}
		
	my $sth;
	
	$sth = $dbh->prepare( "SELECT [Key], ValName, ValType, ValData, Protected, Monitored, [Set], [Delete], PolicyName, CategoryNumber, SourceNumber FROM RegistryControl WHERE CategoryNumber <> 7 ORDER BY [Key]" );
				
	$sth->execute();
	
	
	my $counter = 0 + 0;
	while ( my ( $key, $valName, $valType, $valData, $protected, $monitored, $set, $delete, $policy_name, $category_number, $source_num ) = $sth->fetchrow_array() )
		{	$counter++;
			
			my $pmode = "0";
			$pmode = "1" if ( $protected eq 1 );
			
			my $mmode = "0";
			$mmode = "1" if ( $monitored eq 1 );
			
			my $smode = "0";
			$smode = "1" if ( $set eq 1 );
			
			my $dmode = "0";
			$dmode = "1" if ( $delete eq 1 );
			
			# Make a mode of the 4 attributes together
			my $mode = $pmode . $mmode . $smode . $dmode;
							
			$valType = "N/A" if ( ! $valType );
			$valData = "N/A" if ( ! $valData );
			$valName = "N/A" if ( ! $valName );
			$policy_name = "N/A" if ( ! $policy_name );
			
			print OUTPUT "$key\t$mode\t$valName\t$valType\t$valData\t$category_number\t$policy_name\n";
		}
		
	$sth->finish();	
		
			
	close OUTPUT;
	
	print "Exported $counter RegistryControl rows\n";
	
	return;
}



################################################################################
# 
sub InsertFile( $ )
#
#	Just insert the app process text file into the database
#
################################################################################
{	my $file = shift;
	
	if ( $opt_category )
		{	my $category_num = $opt_category_num;			
		}
		
	print "Inserting file $file directly into the database\n";
	
	if ( ! open INPUT, "<$file" )
		{	print "Unable to open file $file: $!\n";
			return;
		}
		
		
	while (<INPUT>)
		{	next if ( ! $_ );
			
			my $line = $_;
			chomp( $line );
			
			next if ( ! $line );

			my ( $key, $mode, $valName, $valType, $valData, $category_number, $policy_name ) = split /\t/, $line, 7;

			$valName = undef if ( $valName eq "N/A" );
			$valData = undef if ( $valData eq "N/A" );
			$policy_name = undef if ( $policy_name eq "N/A" );
		
			my $source_num = $opt_source_num;
			
			my $ret;
			$ret = &UpdateRegistryControlTable( $key, $mode, $valName, $valType, $valData, $category_number, $policy_name, $source_num );
		
			next if ( ! defined $ret );
	
			$add_counter++ if ( $ret > 0 );
			$update_counter++ if ( $ret < 0 );
		}
	
	close INPUT;
	
	
	return;
}



################################################################################
# 
sub UpdateRegistryControlTable( $$$$$$$$ )
#
#	Put the new information into the database
#   Return 1 if added, -1 if changed, undef if an error, 0 if no change
#
################################################################################
{	my $key				= shift;
	my $mode			= shift;
	my $valName			= shift;
	my $valType			= shift;
	my $valData			= shift;
	my $category_number	= shift;
	my $policy_name		= shift;
	my $source_num		= shift;
	
	

	my $sth;
	
	if ( ! $valName )
		{	$sth = $dbh->prepare( "SELECT [Key], ValName, CategoryNumber, SourceNumber FROM RegistryControl WHERE [Key] = ? AND ValName IS NULL" );
			
			$sth->bind_param( 1, $key,  DBI::SQL_VARCHAR );
			$sth->execute();
		}
	else	
		{	$sth = $dbh->prepare( "SELECT [Key], ValName, CategoryNumber, SourceNumber FROM RegistryControl WHERE [Key] = ? AND ValName = ?" );
			
			$sth->bind_param( 1, $key,  DBI::SQL_VARCHAR );
			$sth->bind_param( 2, $valName,  DBI::SQL_VARCHAR );
			$sth->execute();
		}
		
	my ( $dKey, $dValName, $dCategoryNumber, $dSourceNumber ) = $sth->fetchrow_array();
	$sth->finish();
	

	# Did I find an existing process?
	my $ret = 0 + 1;
	
	if ( $dKey )
		{	# Am I inserting - in which case, let the existing row stay
			return( 0 + 0 ) if ( $opt_insert );
			
			$dSourceNumber = 0 + $dSourceNumber;
			
			# Was it entered by hand?  If so, don't change it
			return( 0 + 0 ) if ( $dSourceNumber < ( 0 + 3 ) );
			
			# Did anything change?
			return( 0 + 0 ) if ( ( $key eq $dKey )  &&
							( $valName eq $dValName )  &&	
							( $category_number eq $dCategoryNumber ) );
				
			my $str;
			
			if ( ! $valName )
				{	$str = "DELETE RegistryControl WHERE [Key] = ? AND ValName IS NULL";

					$sth = $dbh->prepare( $str );
					$sth->bind_param( 1, $key,  DBI::SQL_VARCHAR );
				}
			else
				{	$str = "DELETE RegistryControl WHERE [Key] = ? AND ValName = ?";

					$sth = $dbh->prepare( $str );
					$sth->bind_param( 1, $key,  DBI::SQL_VARCHAR );
					$sth->bind_param( 2, $valName,  DBI::SQL_VARCHAR );
				}
				
			my $ok = $sth->execute();
			$sth->finish();
			
			return( 0 + 0 ) if ( ! $ok );
			
			$ret = 0 - 1;
		}

	my ( $protected, $monitored, $set, $delete );
	my ( $pmode, $mmode, $smode, $dmode ) = split //, $mode, 4;
	
	$protected = "\'0\'";
	$monitored = "\'0\'";
	$set = "\'0\'";
	$delete = "\'0\'";
	
	$protected = "\'1\'" if ( $pmode eq "1" );
	$monitored = "\'1\'" if ( $mmode eq "1" );
	$set = "\'1\'" if ( $smode eq "1" );
	$delete = "\'1\'" if ( $dmode eq "1" );
	
	
	$key				= "'" . $key . "\'";
	$valName			= "'" . $valName . "\'" if ( $valName );
	$valType			= "'" . $valType . "\'" if ( $valType );
	$valData			= "'" . $valData . "\'" if ( $valData );
	$policy_name		= "'" . $policy_name . "\'" if ( $policy_name );
	$category_number	= "'" . $category_number . "\'";
	$source_num			= "'" . $source_num . "\'";
	
	my $str;
	
	
	if ( ( $valName )  &&  ( $valType )  &&  ( $valData )  &&  ( $policy_name ) )
		{	$str = "INSERT INTO RegistryControl ( [Key], ValName, ValType, ValData, Protected, Monitored, [Set], [Delete], PolicyName, CategoryNumber, SourceNumber )
VALUES ( $key, $valName, $valType, $valData, $protected, $monitored, $set, $delete, $policy_name, $category_number, $source_num )";
		}
		
	elsif ( ( $valName )  &&  ( $valType )  &&  ( $valData )  &&  ( ! $policy_name ) )
		{	$str = "INSERT INTO RegistryControl ( [Key], ValName, ValType, ValData, Protected, Monitored, [Set], [Delete], CategoryNumber, SourceNumber )
VALUES ( $key, $valName, $valType, $valData, $protected, $monitored, $set, $delete, $category_number, $source_num )";
		}
		
	elsif ( ( $valName )  &&  ( $valType )  &&  ( ! $valData )  &&  ( ! $policy_name ) )
		{	$str = "INSERT INTO RegistryControl ( [Key], ValName, ValType, Protected, Monitored, [Set], [Delete], CategoryNumber, SourceNumber )
VALUES ( $key, $valName, $valType, $protected, $monitored, $set, $delete, $category_number, $source_num )";
		}
		
	elsif ( ( ! $valName )  &&  ( $valType )  &&  ( $valData )  &&  ( $policy_name ) )
		{	$str = "INSERT INTO RegistryControl ( [Key], ValType, ValData, Protected, Monitored, [Set], [Delete], PolicyName, CategoryNumber, SourceNumber )
VALUES ( $key, $valType, $valData, $protected, $monitored, $set, $delete, $policy_name, $category_number, $source_num )";
		}
		
	elsif ( ( ! $valName )  &&  ( ! $valType )  &&  ( $valData )  &&  ( $policy_name ) )
		{	$str = "INSERT INTO RegistryControl ( [Key], ValData, Protected, Monitored, [Set], [Delete], PolicyName, CategoryNumber, SourceNumber )
VALUES ( $key, $valData, $protected, $monitored, $set, $delete, $policy_name, $category_number, $source_num )";
		}
		
	elsif ( ( ! $valName )  &&  ( ! $valType )  &&  ( ! $valData )  &&  ( $policy_name ) )
		{	$str = "INSERT INTO RegistryControl ( [Key], ValName, ValType, ValData, Protected, Monitored, [Set], [Delete], PolicyName, CategoryNumber, SourceNumber )
VALUES ( $key, $valName, $valType, $valData, $protected, $monitored, $set, $delete, $policy_name, $category_number, $source_num )";
		}
		
	else
		{	$str = "INSERT INTO RegistryControl ( [Key], Protected, Monitored, [Set], [Delete], CategoryNumber, SourceNumber )
VALUES ( $key, $protected, $monitored, $set, $delete, $category_number, $source_num )";
		}
		
		
	$sth = $dbh->prepare( $str );
	
	my $ok = $sth->execute();
	$sth->finish();


	return( $ret ) if ( $ok );
	
	return( 0 + 0 );
}



################################################################################
#
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     lprint( @_ );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "RegistryControl";

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
    my $me = "RegistryControl";
	
    print <<".";


Possible options are:

  -e, --export          export the RegistryControl data
  -i, --insert          insert the RegistryControl file into the database
  -v, --verbose         show work as it progresses
  -h, --help            print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
