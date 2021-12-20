################################################################################
#!perl -w
#
# Rob McCarthy's ProgramCopy source code
#  Copyright 2010 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Cwd;
use Getopt::Long();
use DBI qw(:sql_types);
use DBD::ODBC;
use File::Copy;


use Content::File;
use Content::SQL;
use Content::ScanUtil;
use Content::Category;



my $opt_help;
my $opt_debug;
my $opt_subdir;						# True if I should not scan subdirectories
my $opt_verbose;					# True if we should be chatty
my $opt_count = 0 + 1;				# The number of copies of each App to get


my $app_name_list;					# This is the text file containing the name of the apps (or viruses) that I want to copy

my $dbhProgram;



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
        "c|count"		=> \$opt_count,
        "h|help"		=> \$opt_help,
		"s|subdir"		=> \$opt_subdir,
		"v|verbose"		=> \$opt_verbose,
		"x|xxx"			=> \$opt_debug
      );


	print( "Lightspeed Program Copy Utility\n" );	
	
	
    &Usage() if ( $opt_help );

	
	my $app_name_list = shift;
	
	if ( ! defined $app_name_list )
		{	print "No app name list text file was defined\n";
			&Usage();
		}
				
	if ( ! -f $app_name_list )
		{	print "Could not find app name text file $app_name_list\n";
			exit( 0 );
		}
		
		
	if ( ! open( APPNAME, "<$app_name_list" ) )
		{	print "Could not open app name text file $app_name_list: $!\n";
			exit( 0 );
		}
	
	
	my $dir = shift;
	if ( ! defined $dir )
		{	print "No target directory was defined\n";
			&Usage();
		}
				
	if ( ! -d $dir )
		{	print "Could not find target directory $dir\n";
			exit( 0 );
		}
	
	
	$dbhProgram = &ConnectRemoteProgram();
	
	if ( ! $dbhProgram )
		{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

			exit( 0 );
		}
			
	
	my $total_count		= 0 + 0;
	my $total_missing	= 0 + 0;
	
	while ( my $line = <APPNAME> )
		{	chomp( $line );
			next if ( ! defined $line );
			
			my $app_name = $line;
			
			my $count = &ProgramCopy( $app_name, $dir );
			
			$total_count += $count if ( $count );
			
			$total_missing++ if ( ! $count );
		}
	
	close( APPNAME );		
	
	print "$total_count files copied or already existing in total\n";
	print "$total_missing missing in total\n";
	
		
	$dbhProgram->disconnect if ( $dbhProgram );
	$dbhProgram = undef;
	
	&StdFooter;
	
	exit;
}
###################    End of MAIN  ################################################



################################################################################
#
sub ProgramCopy( $$ )
#
#  Given a app name and a target directory, copy the apps to the target directory
#
################################################################################
{	my $app_name	= shift;	# This is the app name to copy
	my $dir			= shift;	# This is the directory to copy to
		
		
	# Make sure I have valid data - return undef if I don't
	return( undef ) if ( ! defined $app_name );

	# Make sure I have valid data - return undef if I don't
	return( undef ) if ( ! defined $dir );


	my $str = "SELECT [Filename] FROM Programs WITH(NOLOCK) WHERE [AppName] = \'$app_name\' ORDER BY [TransactionTime]";
	my $sth = $dbhProgram->prepare( $str );
	$sth->execute();
	
	&CategorySQLError( $dbhProgram );

	
	my $count = 0 + 0;

	my $filename;
	while ( ( ! $dbhProgram->err )  &&  (  ( $filename ) = $sth->fetchrow_array() ) )
		{	my ( $tdir, $shortfile ) = &SplitFileName( $filename );
			next if ( ! defined $shortfile );

			next if ( ! -f $filename );
			
			my $subdir = &VirusTypeDir( $app_name );
			next if ( ! defined $subdir );
			
			my $dest_dir = 	$dir . '\\' . $subdir;		

			my $ok = &MakeDirectory( $dest_dir );
			if ( ! $ok )
				{	print "Unable to make directory $dest_dir\n";
					exit( 0 );
				}
				
			my $dest = 	$dest_dir . '\\' . $shortfile;
			
			# Does the target already exist?
			if ( -f $dest )
				{	$count++;
					
					# Have I copied all I need to?
					last if ( $count >= $opt_count );
					
					next;
				}
				
			print "Copying $filename to $dest ...\n";
			my $success = copy( $filename, $dest );
					
			if ( ! $success )
				{	print "File copy error: $!\n";
					print "Source file: $filename\n";
					print "Destination file: $dest\n";
					exit( 0 );
				}
				
			$count++;
			
			# Have I copied all I need to?
			last if ( $count >= $opt_count );
		}
		
	$sth->finish();
	
	print "Found no examples of $app_name\n" if ( ! $count );
	
	return( $count );
}



my $last_dir;	# The last directory that I checked
################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Return OK if I just checked this directory
	return( 1 ) if ( ( $last_dir )  &&  ( $last_dir eq $dir ) );
		
	# Return OK if the directory already exists
	if ( -d $dir )
		{	$last_dir = $dir;
			return( 1 );
		}

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
	
	# Did it create OK?
	return( undef ) if ( ! -d $dir );	
	
	$last_dir = $dir;
	
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{	
    print <<".";

Usage: ProgramCopy AppList TargetDir [options]

Given a list of App Names (or Virus Names) in a text file, copy one or
more versions of the AppName to the target directory. 


Possible options are:

  -c, --count COUNT     the maximum number of each App to copy (1 is default)

  -v, --verbose         Verbose mode
  
  -h, --help            print this message and exit

.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
