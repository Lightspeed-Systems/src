################################################################################
#!perl -w
#
# Rob McCarthy's Clam Virus Database Import source code
#  Copyright 2004 Lightspeed Systems Corp.
# Import clam virus signatures.txt file into the Content Database
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use LWP::Simple;
use LWP::UserAgent;
use URI::Heuristic;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32;
use Win32::OLE::Variant;
use Win32API::Registry 0.21 qw( :ALL );
use Fcntl qw(:DEFAULT :flock);
use Cwd;
use Digest::MD5;




use Content::File;
use Content::SQL;
use Content::ScanUtil;



# Options
my $opt_category_num	= 0 + 64;			# The category number to add to the database - 64 is test
my $opt_category		= "security.test";	# The category name to add signatures to - security.test is 64
my $opt_dir;								# Directory to get stuff from - the default is the current directory
my $opt_help;
my $opt_version;
my $opt_source			= 0 + 2;			
my $opt_verbose;
my $opt_move;								# If true, then move all the test viruses to real viruses
my $opt_debug;
my $opt_no_update;							# If TRUE, then don't actually update the database							



# This is the full file list with the PUA files 
#my @file_list = ( "main.db",  "main.hdb",  "main.mdb",  "main.ndb",  "main.zmd", "main.fp",  "main.hdu",  "main.mdu",  "main.ndu",
#				  "daily.db", "daily.hdb", "daily.mdb", "daily.ndb", "daily.zmd", "daily.fp", "daily.hdu", "daily.mdu", "daily.ndu" );

# This is the file list without the PUA files
my @file_list = ( "main.db",  "main.hdb",  "main.mdb",  "main.ndb",  "main.zmd",  "main.fp",
				  "daily.db", "daily.hdb", "daily.mdb", "daily.ndb", "daily.zmd", "daily.fp"  );


# These files contains lists of virus signatures that should be ignored
my @ignore_files = ( "main.ign", "daily.ign" );


# Globals
my $_version = "1.0.0";
my $dbh;									#  My database handle
my $dbh_existing;							#  My database handle to modify the existing signatures table
my %virus_names;							# List of virus names already inserted
my %virus_line;								# Hash of virus lines MD5 hash value - used to keep uniqueness
my @ignore_list;							# List of virus names to ignore



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "ClamImport" );

# Test signatures
#my ( $name, $sig, $start_offset, $end_offset, $clam_type ) = &ClamSignature( "38912:523ec9d0a81718495aa806efd99d5bf2:PUA.PWTool.Messen", "daily.mdu" );
#print "name: $name\n";
#print "sig: $sig\n";
#print "start_offset: $start_offset\n";
#print "end_offset: $end_offset\n";
#print "clam_type: $clam_type\n" if ( defined $clam_type );
#exit;

    # Get the options
    Getopt::Long::Configure("bundling");

		my $options = Getopt::Long::GetOptions
		(
			"c|category=s"	=> \$opt_category,
			"d|directory=s" => \$opt_dir,
			"m|move"		=> \$opt_move,
			"n|noupdate"	=> \$opt_no_update,
			"s|source=s"	=> \$opt_source,
			"v|verbose"		=> \$opt_verbose,
			"h|help"		=> \$opt_help,
			"x|xxx"			=> \$opt_debug
		);


    &Usage() if ($opt_help);
    &Version() if ($opt_version);
	
	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
    #  Make sure the source number is numeric
    $opt_source = 0 + $opt_source;
    &Usage() if ( ( $opt_source < 1 || $opt_source > 2000 ) );
     
    #  Make sure the category number is numeric
    $opt_category_num = 0 + $opt_category_num;
    &Usage() if ( ( $opt_category_num < 1 || $opt_category_num > 120 ) );


    #  Open the database
    $dbh = &ConnectServer() or die "Unable to open Content database";
	
	$dbh_existing = DBI->connect( "DBI:ODBC:TrafficServer", "IpmContent" ) or die "Unable to open Content database";
	

	&LoadCategories();
	

	if ( $opt_move )
		{	&MoveTestSignatures();
			
			#  Clean up everything and quit
			$dbh->disconnect;
			$dbh = undef;
			
			exit( 0 + 0 );
		}
		
		
	if ( $opt_category )
		{	$opt_category = lc( $opt_category );
			$opt_category_num = &CategoryNumber( $opt_category );

			if ( ! $opt_category_num )
				{	$dbh->disconnect;
					$dbh = undef;
					
					die "Unable to find category number for $opt_category\n";
				}
		}


	&SetLogFilename( "$cwd\\ClamImport.log", $opt_debug );
	&TrapErrors( "$cwd\\ClamImportErrors.log" ) if ( ! $opt_debug );
	

	lprint "Do NOT actually update the database\n" if ( $opt_no_update );
	
	
	# Check to make sure all the files exist - print an error message, and exit with an error ...
	foreach ( @file_list )
		{	next if ( ! $_ );
			my $input_file = $_;
			if ( ! -e $input_file )
				{	lprint "Unable to find Clam database file $input_file\n";
					exit( 0 + 1 );
				}
		}
				
	
	# Set the test bit
	&SetTestBit() if ( ! $opt_no_update );

	
	# The new method is to have an exisitng signatures table - this saves RAM memory
	&UpdateExistingSignatures();
	

	# Load up the ignore list
	foreach ( @ignore_files )
		{	my $ignore_file = $_;
			next if ( ! $ignore_file );
			next if ( ! -f $ignore_file );
			
			open( IGNORE, "<$ignore_file" ) or next;
			
			while ( my $line = <IGNORE> )
				{	chomp( $line );
					next if ( ! $line );
					
					my ( $file, $number, $ignore_virus_name ) = split /\:/, $line, 3;
					
					next if ( ! $file );
					next if ( ! $ignore_virus_name );
					
					my $data = lc( $file ) . "\t" . lc( $ignore_virus_name );
					push @ignore_list, $data;
					
					lprint "Ignoring virus $ignore_virus_name from file $file\n";
				}
				
			close( IGNORE );
		}
	
	
	# Suck the files into the database
	my $added		= 0 + 0;
	my $changed		= 0 + 0;
	my $total		= 0 + 0;
	my $error_total = 0 + 0;
	
	# Do a first pass without changing anything in the database to just figure out if we are going to have signatures
	# changed from the main files to the daily files
	%virus_names = ();
	foreach ( @file_list )
		{	next if ( ! $_ );
			my $input_file = $_;
			next if ( ! -e $input_file );
			
			my $category_num = $opt_category_num;
			$category_num = 0 + 6 if ( $input_file =~ m/\.fp$/i );	# Set the category number to business for Clam's false positive file
			
			# Should I actually update database
			my $update_database = 1;
			$update_database = undef if ( $opt_no_update );
			
			my ( $file_added, $file_changed, $file_total, $error_count ) = &ClamImportVirusSignatures( $input_file, $category_num, $opt_source, $update_database );
			
			$added			+= $file_added		if ( $file_added );
			$changed		+= $file_changed	if ( $file_changed );
			$total			+= $file_total		if ( $file_total );
			$error_total	+= $error_count		if ( $error_count );
		}
		
	
	# Put anything with the test bit still on into the errors category
	&MoveTestBitErrors() if ( ! $opt_no_update );

	
	&lprint( "\n" );
	&lprint( "$added added virus signatures in all the files\n" );
	&lprint( "$changed changed virus signatures in all the files\n" );
	&lprint( "$total total virus signatures in all the files\n" );
	&lprint( "$error_total total errors adding virus signatures in all the files\n" );
	
			
	#  Clean up everything and quit
	$dbh->disconnect if ( $dbh );
	$dbh = undef;

	$dbh_existing->disconnect if ( $dbh_existing );
	$dbh_existing = undef;
	
	
	&StdFooter;

	
exit( 0 + 1 ) if (! $total);
exit( 0 + 0 );
}
################################################################################



################################################################################
#
sub TrapErrors( $ )
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = shift;
	
	return( undef ) if ( ! defined $filename );
	
	my $MYLOG;
	
	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	lprint( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub MoveTestSignatures()
#
#  Move security.test virus signatures
#
################################################################################
{	lprint "Moving security.test virus signatures into the security.virus and security.spyware category ...\n";
	
	my $sth = $dbh->prepare( "UPDATE VirusSignatures set CategoryNumber = 63, TransactionTime = getutcdate() where CategoryNumber = '64'" );
	$sth->execute();
	$sth->finish();
	
	$sth = $dbh->prepare( "UPDATE VirusSignatures set CategoryNumber = 62, TransactionTime = getutcdate() where CategoryNumber = '63' and VirusName like '%spyware%'" );
	$sth->execute();
	$sth->finish();
	
	$sth = $dbh->prepare( "UPDATE VirusSignatures set CategoryNumber = 62, TransactionTime = getutcdate() where CategoryNumber = '63' and VirusName like '%adware%'" );
	$sth->execute();
	$sth->finish();

	$sth = $dbh->prepare( "UPDATE VirusSignatures set CategoryNumber = 62, TransactionTime = getutcdate() where CategoryNumber = '63' and VirusName like '%adtool%'" );
	$sth->execute();
	$sth->finish();

	$sth = $dbh->prepare( "UPDATE VirusSignatures set CategoryNumber = 62, TransactionTime = getutcdate() where CategoryNumber = '63' and VirusName like '%keylog%'" );
	$sth->execute();
	$sth->finish();

	lprint "Getting security.test file IDs ...\n";
	$sth = $dbh->prepare( "SELECT FileID, AppName, Process FROM ApplicationProcesses WITH(NOLOCK) WHERE CategoryNumber = \'64\'" );
	$sth->execute();

	my @data;
	while ( ( ! $dbh->err )  &&  ( my ( $file_id, $app_name, $file ) = $sth->fetchrow_array() ) )
		{	next if ( ! $file_id );
			next if ( ! $app_name );
			next if ( ! $file );
			
			my $data = "$file_id\t$app_name\t$file";
			
			push @data, $data;
		}

	$sth->finish();
	
	my $count = $#data + 1;
	lprint "Found $count file IDs in the security.test category ...\n";


	lprint "Moving $count file IDs to the security.virus category ...\n";
	foreach ( @data )
		{	my $data =$_;
			next if ( ! $data );
			
			my ( $file_id, $app_name, $file ) = split /\t/, $data;
			
			my $category_num = 0 + 63;
			
			my $actual_category_num = &VirusGuessCategory( $file, $category_num, $app_name );

			my $str = "UPDATE ApplicationProcesses set CategoryNumber = \'$actual_category_num\', TransactionTime = getutcdate() WHERE FileID = \'$file_id\'";

			my $sth = $dbh->prepare( $str );
			$sth->execute();
			$sth->finish();	
		}

	lprint "Done moving test signatures and file IDs\n";
	
	return( 1 );
}



################################################################################
# 
sub ClamImportVirusSignatures( $$$ $ )
#
#  Given a text file containig virus signatures, import it into SQL
#
################################################################################
{	my $file				= shift;
	my $category_num		= shift;
	my $source				= shift;
	my $update_database		= shift;
	
	
	my $total_count			= 0 + 0;
	my $added				= 0 + 0;
	my $out_counter			= 0 + 0;
	my $defined_count		= 0 + 0;
	my $database_count		= 0 + 0;
	my $changed_count		= 0 + 0;
	my $not_changing		= 0 + 0;
	my $duplicates			= 0 + 0;
	my $error_count			= 0 + 0;
	
	
	my $catname = &CategoryName( $category_num );
	die "Unable to find category name for category number $category_num\n" if ( ! $catname );

	my $full_path = $file;
	
    $full_path = $opt_dir . "\\" . $file if ( $opt_dir );	

    lprint "\n";
    lprint "Importing clam virus signatures from $full_path to category $catname ... \n";

    if ( ! open( FILE, "<$full_path" ) )
		{	&lprint( "Cannot open input file $full_path: $!\n" );
			return( 0 + 0 );
		}
		
		
	# First, parse through the file to pick unique names
	my %unique;
	while ( my $line = <FILE> )
		{	chomp( $line );
			next if ( ! $line );
			
			my ( $name, $sig, $start_offset, $end_offset, $clam_type ) = &ClamSignature( $line, $file );
			next if ( ! $name );
			
			my $upper_name = uc( $name );
			
			# If I haven't seen it before, then it's ok
			if ( ! defined $virus_names{ $upper_name } )
				{	$virus_names{ $upper_name } = "$file\t$line";
					next;
				}
				
			my $data = $virus_names{ $upper_name };	
			my ( $old_file, $old_line ) = split /\t/, $data;
			
			
			if ( $opt_verbose )
				{	lprint "Virus $name was already defined in file $old_file, now redefined in file $file\n";
					lprint "Old line: $old_line\n";
					lprint "New line: $line\n";
				}
				

			# If this name is already defined then pick another
			my $c = 0 + 0;
			my $new_name = $name;
			my $new_upper = uc( $new_name );
			while ( defined $virus_names{ $new_upper } )
				{	$defined_count++;				
					$c++;
					$new_name = $name . "$c";
					$new_upper = uc( $new_name );
				}
				
			#print "Virus $name is already defined, so using name $new_name\n";
			my $key = "$upper_name\t$sig";
			
			$unique{ $key } = $new_name;
			$virus_names{ $new_upper } = "$file\t$line";
			
			lprint "New virus name: $new_name\n" if ( $opt_verbose );
		}
    
	close( FILE );

	
	# Now open the file again and read through it adding new stuff to the database
    open( FILE, "<$full_path" ) or die( "Cannot open input file $full_path: $!\n" );
	
	while ( my $line = <FILE> )
		{	next if ( ! defined $line );
			
			chomp( $line );
			next if ( ! $line );


			# Make sure that the line is unique by comparing the MD5 hash value to previous values from this or other files
			my $md5 = Digest::MD5->new;
			$md5->add( $line );
			my $md5_digest = $md5->digest;	# This should return a 16 byte digest


			# Is this line unique?
			my $old_file = $virus_line{ $md5_digest } if defined $md5_digest;
			
			if ( defined $old_file )
				{	lprint "Duplicated line from old $old_file in new file $file\n" if ( $opt_verbose );
					next;
				}
			$virus_line{ $md5_digest } = $file;

			
			my $offset = 0 - 1;

			my ( $name, $sig, $start_offset, $end_offset, $clam_type ) = &ClamSignature( $line, $file );

			next if ( ! defined $name );
			
			$total_count++;
			
			# Make sure the sig makes sense
			next if ( ! defined $sig );
			$sig =~ s/\s+//g;	# No whitespace
			next if ( length( $sig ) == 0 );
			next if ( $sig eq "!" );	# A single bang is no good either
			
									
			# Did I have to pick another unique name?
			my $upper_name = uc( $name );
			my $key = "$upper_name\t$sig";
			
			if ( defined $unique{ $key } )
				{	$name = $unique{ $key };
				}
			
			
			# Some clam viruses make no sense for Windows
#			next if ( $name =~ m/^UNIX/i );
#			next if ( $name =~ m/^Unix/i );
#			next if ( $name =~ m/^Linux/i );
			

			# Figure out the Lightspeed type and application signature
			my ( $type, $app_sig ) = &ClamVirusType( $name, $sig, $clam_type );

			
			if ( $opt_verbose )
				{	lprint "Virus Name: $name, Type = $type, App Sig: $app_sig\n";
					lprint "Original Offset: $offset, Start Offset: $start_offset, End Offset = $end_offset\n";
					lprint "Sig: $sig\n";
				}
				
				
			# Is this signature already in the database under a different name?
			my ( $duplicate, $exist_virus_name ) = &ExistingSignature( $sig, $start_offset, $end_offset, $name, $type, $app_sig );

			if ( $duplicate )
				{	lprint "Existing virus $exist_virus_name has duplicated the same signature so ignoring $name\n" if ( $opt_verbose );
					$duplicates++;
					
					# Clear the test bit if it was set
					&ClearTestBit( $exist_virus_name );
					
					next;
				}

			
			# Is this virus name already in the database?  And has it changed?
			my $sth = $dbh->prepare( "SELECT sigstart, sigend, VirusType, signature, CategoryNumber, SourceNumber, Test FROM VirusSignatures WITH(NOLOCK) where VirusName = ?" );
			$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
			$sth->execute();
			my ( $exist_start_offset, $exist_end_offset, $exist_type, $exist_sig, $exist_category_num, $exist_source_num, $test ) = $sth->fetchrow_array();
			$sth->finish();
			
			
			if ( $exist_sig )
				{	# print "Virus $name is already in the database\n";
					my $changed;
					$exist_start_offset = 0 + $exist_start_offset;
					$exist_end_offset	= 0 + $exist_end_offset;
					$exist_source_num	= 0 + $exist_source_num;
					
					$changed = 1 if ( lc( $sig ) ne lc( $exist_sig ) );
					$changed = 1 if ( $start_offset != $exist_start_offset );
					$changed = 1 if ( $end_offset != $exist_end_offset );
					$changed = 1 if ( lc( $type ) ne lc( $exist_type ) );


					# If the existing signature is in the errors category, then it has changed
					$changed = 1 if ( $exist_category_num == 7 );
					
					# Clear the test bit if set
					$test = 0 + $test;
					&ClearTestBit( $name );
					
					$database_count++;
					
					if ( ( $changed )  &&  ( $exist_source_num < 2 ) )
						{	lprint "Virus $name has source number $exist_source_num so not changing ...\n";
							$not_changing++;
							
							next;	
						}
						
					if ( $changed )
						{	lprint "Virus $name has changed\n";
							lprint "Signature changed\n" if ( $sig ne $exist_sig );
							lprint "Start offset changed from $exist_start_offset to $start_offset\n"	if ( $start_offset != $exist_start_offset );
							lprint "End offset changed from $exist_end_offset to $end_offset\n"			if ( $end_offset != $exist_end_offset );
							lprint "Type has changed from $exist_type to $type\n"						if ( $type ne $exist_type );
							lprint "Category has changed from 7 to $category_num\n"						if ( $exist_category_num == 7 );	
						}
						
					if ( ! $changed )
						{	lprint "Virus $name has not changed\n" if ( $opt_verbose );
							next;	
						}
					
					# Am I supposed to make a change to the database?
					next if ( ! $update_database );
					
					lprint "Virus $name is already in the database but has changed so overriding ...\n" if ( $changed );
					
					$sth = $dbh->prepare( "DELETE VirusSignatures where VirusName = ?" );
					$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
					$sth->execute();
					$sth->finish();
					
					$changed_count++;
					
					# Get rid of the entry in the Existing Signatures table
					&DeleteExistingSignature( $exist_sig );
				}
			
			
			lprint "Adding virus signature $name\n";
				

			my $retcode = 0 + 0;
		
			my @values;
			push @values, "\'" . $name . "\',";				# 0 entry
			push @values, "\'" . $type . "\',";				# 1 entry
			push @values, "\'" . $app_sig . "\',";			# 2 entry
			push @values, "\'" . $start_offset . "\',";		# 3 entry
			push @values, "\'" . $end_offset . "\',";		# 4 entry
			push @values, "\'" . $sig . "\',";				# 5 entry
			push @values, "\'" . $category_num . "\',";		# 6 entry
			push @values, "\'" . $source . "\',";			# 7 entry
			push @values, "\'0\'";							# 8 entry - the test bit
			
			
			# Am I supposed to make a change to the database?
			next if ( ! $update_database );
					
			
			my $str = "INSERT INTO VirusSignatures ( VirusName, VirusType, appsig, sigstart, sigend, signature, CategoryNumber, SourceNumber, [Test] ) VALUES ( @values )";

			$sth = $dbh->prepare( $str );

			if ( ! $sth->execute() )
				{	lprint "Error inserting $name into database\n";
					lprint "Date: Virus Name: $name, Type = $type, App Sig: $app_sig\n";
					lprint "Original Offset: $offset, Start Offset: $start_offset, End Offset = $end_offset\n";
					lprint "Category: $category_num\n";
					lprint "Source: $source\n";
					lprint "Sig: $sig\n";
					my $length = length( $sig );
					lprint "Signature length = $length\n";
					$length = length( $name );
					lprint "Name length = $length\n\n";

					my $err	= $dbh->err;
		
					# Get the error message
					my $sql_errmsg = $dbh->errstr;
					$sql_errmsg = "SQL error number = $err" if ( ! $sql_errmsg );
					lprint "SQL Error: $sql_errmsg\n";
					
					lprint "Insert statment: $str\n";
					
					$error_count++;		
					
					$sth->finish();
				}
			else	# Update the existing signatures table
				{	$sth->finish();
					
					my $line = "$name\t$type\t$app_sig\t$start_offset\t$end_offset\t$category_num\t$opt_source";

					&SetExistingSignature( $sig, $line );
					
					$added++;
				}
				
		
			$out_counter++ if ( $retcode == 0 );
		}
		
	close( FILE );
	
	lprint "\n";
	lprint "Found $total_count total signatures\n" if ( $total_count );
	lprint "Added $added virus signatures to the database\n" if ( $added );
	lprint "$defined_count virus signatures were duplicated Clam virus names\n" if ( $defined_count );
	lprint "$database_count virus signatures were already in the database\n" if ( $database_count );
	lprint "$changed_count virus signatures were changed in the database\n" if ( $changed_count );
	lprint "$duplicates virus signatures were duplicated signatures\n" if ( $duplicates );
	lprint "$not_changing virus signatures have source 1 so not changing\n" if ( $not_changing );
	lprint "Added no new virus signatures to the database\n" if ( ! $out_counter );
	lprint "Errors adding $error_count virus signatures to the database\n" if ( $error_count );

	# return how many (if any) signatures were added or modified.
	return( $added, $changed_count, $total_count, $error_count );
}



################################################################################
# 
sub ClamVirusType( $$$ )
#
#  Given a virus signature, start offset, and end offset, return True if it is 
#  already in the database - ignoring signatures in the errors category
#  
################################################################################
{	my $name		= shift;
	my $sig			= shift;
	my $clam_type	= shift;	# This is the clam type from the .ndb files
								# 0 – Any file type
								# 1 – MS EXE file type
								# 2 – MS OLE2 file type
								# 3 – HTML file type
								# 4 – Mail file type
								# 5 – Graphics file type


	
	# Get the virus type
	my $type = "W32";
	$type = "W32"		if ( $name =~ m/Backdoor/i );
	$type = "W32"		if ( $name =~ m/worm/i );
	$type = "W32"		if ( $name =~ m/Dropper/i );
	$type = "W32"		if ( $name =~ m/W32/i );
	$type = "W32"		if ( $name =~ m/WIN32/i );
	$type = "W32"		if ( $name =~ m/WIN95/i );
	$type = "W32"		if ( $name =~ m/Trojan/i );
	$type = "Linux"		if ( $name =~ m/^Linux/i );
	$type = "Linux"		if ( $name =~ m/\.linux\./i );
	$type = "MW"		if ( $name =~ m/WM97/i );
	$type = "MW"		if ( $name =~ m/WM2000/i );
	$type = "MW"		if ( $name =~ m/W97M/i );
	$type = "MW"		if ( $name =~ m/^WM\./i );
	$type = "MW"		if ( $name =~ m/^W97\./i );
	$type = "MW"		if ( $name =~ m/XM2000/i );
	$type = "MW"		if ( $name =~ m/^XM97/i );
	$type = "MW"		if ( $name =~ m/^X97M/i );
	$type = "MW"		if ( $name =~ m/^XM\./i );
	$type = "MW"		if ( $name =~ m/^VBA\./i );
	$type = "VBS"		if ( $name =~ m/^VBS\./i );
	$type = "VBS"		if ( $name =~ m/\.vbs\./i );
	$type = "BAT"		if ( $name =~ m/^BAT\./i );
	$type = "BAT"		if ( $name =~ m/\.bat\./i );
	$type = "ZIP"		if ( $name =~ m/^ZIP\./i );
	$type = "HTM"		if ( $name =~ m/\.htm$/i );
	$type = "HTM"		if ( $name =~ m/^HTML\./i );
	$type = "HTM"		if ( $name =~ m/\.HTML\./i );
	$type = "MAIL"		if ( $name =~ m/\.mail$/i );
	$type = "MAIL"		if ( $name =~ m/\.mail1$/i );
	$type = "MAIL"		if ( $name =~ m/^Email\./i );
	$type = "JPG"		if ( $name =~ m/\.jpg$/i );
	$type = "PL"		if ( $name =~ m/\.perl\./i );
	$type = "HTM"		if ( $name =~ m/^JS\./i );


	# This type depends on the signature not the virus name
	$type = "ZIP"		if ( $sig =~ m/\!ZIP\:/i );
	
	
	# Now that I've tried to guess the type - did Clam tell me what the type actually is?
	$type = "*"		if ( ( defined $clam_type )  &&  ( $clam_type == 0 ) );
	$type = "W32"	if ( ( $clam_type )  &&  ( $clam_type == 1 ) );
	$type = "MW"	if ( ( $clam_type )  &&  ( $clam_type == 2 ) );
	$type = "HTM"	if ( ( $clam_type )  &&  ( $clam_type == 3 ) );
	$type = "MAIL"	if ( ( $clam_type )  &&  ( $clam_type == 4 ) );
	$type = "JPG"	if ( ( $clam_type )  &&  ( $clam_type == 5 ) );
	$type = "Linux"	if ( ( $clam_type )  &&  ( $clam_type == 6 ) );
	$type = "TXT"	if ( ( $clam_type )  &&  ( $clam_type == 7 ) );

	
	# Figure out an app signature
	my $app_sig = "4d5a";  # Default to any windows application
	$app_sig = "JS"					if ( $type eq "JS" );
	$app_sig = "VBS"				if ( $type eq "VBS" );
	$app_sig = "d0cf11e0a1b11ae1"	if ( $type eq "MW" );
	$app_sig = "BAT"				if ( $type eq "BAT" );
	$app_sig = "VBS"				if ( $type eq "VBS" );
	$app_sig = "504b0304"			if ( $type eq "ZIP" );
	$app_sig = "4d5a900003"			if ( $type eq "W32" );
	$app_sig = "4d5a"				if ( $type eq "W95" );
	$app_sig = "HTM"				if ( $type eq "HTM" );
	$app_sig = "TXT"				if ( $type eq "MAIL" );
	$app_sig = "ffd8ff"				if ( $type eq "JPG" );
	$app_sig = "TXT"				if ( $type eq "PL" );

	return( $type, $app_sig );
}



################################################################################
# 
sub UpdateExistingSignatures()
#
#  Update the existing signatures table
#  
################################################################################
{
	lprint "Updating the existing signatures table ...\n";
	
	my $count		= 0 + 0;
	my $added_sig	= 0 + 0;
	my $added_multi = 0 + 0;
	
	my $sth = $dbh->prepare( "SELECT VirusName, VirusType, AppSig, sigstart, sigend, CategoryNumber, Signature, [Test], SourceNumber FROM VirusSignatures WITH(NOLOCK)" );
	$sth->execute();
	
	my ( $exist_virus_name, $exist_virus_type, $exist_app_sig, $exist_start_offset, $exist_end_offset, $exist_category_num, $exist_sig, $test, $source_number );

	while ( ( $exist_virus_name, $exist_virus_type, $exist_app_sig, $exist_start_offset, $exist_end_offset, $exist_category_num, $exist_sig, $test, $source_number ) = $sth->fetchrow_array() )
		{	my $line = "$exist_virus_name\t$exist_virus_type\t$exist_app_sig\t$exist_start_offset\t$exist_end_offset\t$exist_category_num\t$source_number";
		

			# Lookup lowercase because the sig column is not case sensitive
			my $lc_exist_sig = lc( $exist_sig );

			# Make sure that the signature is unique by comparing the MD5 hash value to previous values from this or other files
			my $md5 = Digest::MD5->new;
			$md5->add( $lc_exist_sig );
			my $md5_hex = $md5->hexdigest;	# This should return a 32 byte digest

			
			my $sth_existing = $dbh_existing->prepare( "SELECT [Data] FROM ExistingSignatures WITH(NOLOCK) WHERE [MD5] = \'$md5_hex\'" );
			$sth_existing->execute();
	
			my ( $data ) = $sth_existing->fetchrow_array();

			$sth_existing->finish();


			# If the signature doesn't exist then I need to add it

			if ( ! defined $data )
				{	$added_sig++;
					lprint "Adding virus $exist_virus_name to the ExistingSignatures table ...\n" if ( $opt_verbose );
							
					&AddExistingSignature( $exist_sig, $line );
				}
			else	# It could be a multiply defined signature - so gotta check that
				{	my $found;
					
					my @lines = split /\n/, $data;
					
					foreach( @lines )
						{	my $check_line = $_;
							$found = 1 if ( $line eq $check_line );
						}
				  
					if ( ! $found )
						{	$added_sig++;
							$added_multi++;
							
							$data .= "\n" . $line;
							
							lprint "Found a multiply defined signature $exist_virus_name\n";
							
							&SetExistingSignature( $exist_sig, $data );
						}
						
					# Do I have an extra long signature?
					my $len = length( $exist_sig );
					if ( $len >= 512 )
						{	lprint "$exist_virus_name has a long signature length of $len\n" if ( $opt_verbose );
						}
				}
				
			$count++;
		}
		
	$sth->finish();

	lprint "Counted $count existing signatures\n";
	lprint "Added $added_sig new existing signatures\n";
	lprint "Added $added_multi new multiple signatures\n";

	return( 1 );	
}




################################################################################
# 
sub ExistingSignature( $$$ $$$ )
#
#  Given a virus signature, start offset, and end offset, return True if it is 
#  already in the database - ignoring signatures in the errors category,
#  and ignore itself
#  
################################################################################
{	my $sig				= shift;
	my $start_offset	= shift;
	my $end_offset		= shift;
	
	my $name			= shift;
	my $type			= shift;
	my $app_sig			= shift;
	
	
	# See if I have a signature like this already
	my $data = &GetExistingSignature( $sig );
	
	
	return( undef, undef ) if ( ! defined $data );
	
	my @lines = split /\n/, $data;
	
	foreach ( @lines )
		{	my $line = $_;
			next if ( ! $line );
			
			my ( $exist_virus_name, $exist_virus_type, $exist_app_sig, $exist_start_offset, $exist_end_offset, $exist_category_num, $exist_source_number ) = split /\t/, $line;
			
			# Ignore signatures that are in the errors category and not source 1
			next if ( ( $exist_category_num == 7 )  &&  ( $exist_source_number > 1 ) );
			
			# Is this the same virus name?
			return( undef, $exist_virus_name ) if ( lc( $name ) eq lc( $exist_virus_name ) );
			
			my $existing = 1;
			$exist_start_offset = 0 + $exist_start_offset;
			$exist_end_offset	= 0 + $exist_end_offset;
			
			$start_offset	= 0 + $start_offset;
			$end_offset		= 0 + $end_offset;
			
			# Could they have different start or end offsets?
			$existing = undef if ( $start_offset	!= $exist_start_offset );
			$existing = undef if ( $end_offset		!= $exist_end_offset );
			
			# Some virus type differences aren't that important - like HTM and JS
			if ( $exist_virus_type ne $type )
				{	my $type_diff = 1;
					
					$type_diff = undef if ( ( $exist_virus_type eq "HTM" )  &&  ( $type eq "JS" ) );
					$type_diff = undef if ( ( $exist_virus_type eq "JS" )  &&  ( $type eq "HTM" ) );
					
					$existing = undef if ( $type_diff );
				}
			
			# Could they have different app_sigs?
			# Some app sig difference aren't that important
			if ( ( $existing )  &&  ( lc( $app_sig ) ne lc( $exist_app_sig ) ) )
				{	my $app_diff = 1;
					
					# An app sig of 4d5a and an app sig of 4d5a900003 are the same thing
					$app_diff = undef if ( ( $app_sig =~ m/^4d5a/i )  &&  ( $exist_app_sig =~ m/^4d5a/i ) );
					
					$existing = undef if ( $app_diff );
				}
				
			return( $existing, $exist_virus_name ) if ( $existing );
		}
		
	return( undef, undef );	
}



################################################################################
# 
sub GetExistingSignature( $ )
#
#  Given a virus signature, get any existing data
#  
################################################################################
{	my $sig = shift;
	return( undef ) if ( ! defined $sig );
	
	# Lookup lowercase because the sig column is not case sensitive
	my $lc_sig = lc( $sig );

	my $md5 = Digest::MD5->new;
	$md5->add( $lc_sig );
	my $md5_hex = $md5->hexdigest;	# This should return a 32 byte digest
	
	
	my $sth_existing = $dbh_existing->prepare( "SELECT [Data] FROM ExistingSignatures WHERE [MD5] = \'$md5_hex\'" );

	$sth_existing->execute();
	my ( $data ) = $sth_existing->fetchrow_array();


	$sth_existing->finish();
	
	return( $data );
}



################################################################################
# 
sub SetExistingSignature( $$ )
#
#  Given a virus signature, set the related data into the ExistingSignatures table
#  
################################################################################
{	my $sig		= shift;
	my $data	= shift;
	
	return( undef ) if ( ! defined $sig );
	return( undef ) if ( ! defined $data );
	
	my ( $existing_data ) = &GetExistingSignature( $sig );
	
	
	# If if doesn't exist, then just add it
	if ( ! defined $existing_data )
		{	&AddExistingSignature( $sig, $data );
			return( 1 );
		}
		
	
	# Do I already have this same data?
	return( 1 ) if ( ( defined $existing_data )  &&  ( $data eq $existing_data ) );
	

	# Lookup lowercase because the sig column is not case sensitive
	my $lc_sig = lc( $sig );

	my $md5 = Digest::MD5->new;
	$md5->add( $lc_sig );
	my $md5_hex = $md5->hexdigest;	# This should return a 32 byte digest
	
	my $sth_existing = $dbh_existing->prepare( "UPDATE ExistingSignatures Set [Data] = \'$data\' WHERE [MD5] = \'$md5_hex\'" );

	$sth_existing->execute();

	$sth_existing->finish();
	
	
	return( 1 );
}



################################################################################
# 
sub AddExistingSignature( $$ )
#
#  Given a virus signature, add the related data into the ExistingSignatures table
#  
################################################################################
{	my $sig		= shift;
	my $data	= shift;
	
	return( undef ) if ( ! defined $sig );
	return( undef ) if ( ! defined $data );
	
	# Lookup lowercase because the sig column is not case sensitive
	my $lc_sig = lc( $sig );

	my $md5 = Digest::MD5->new;
	$md5->add( $lc_sig );
	my $md5_hex = $md5->hexdigest;	# This should return a 32 byte digest
	
	my $sth_existing = $dbh_existing->prepare( "INSERT INTO ExistingSignatures ( [MD5], [Data] ) VALUES( \'$md5_hex\', \'$data\' )" );

	if ( ! $sth_existing->execute() )
		{	my $sql_errmsg = $dbh_existing->errstr;
			lprint "SQL error: $sql_errmsg\n";
			
		}
		
	$sth_existing->finish();
	
	return( 1 );
}



################################################################################
# 
sub DeleteExistingSignature( $ )
#
#  Given a virus signature, delete the related data into the ExistingSignatures table
#  
################################################################################
{	my $sig		= shift;
	
	return( undef ) if ( ! defined $sig );
	
	# Lookup lowercase because the sig column is not case sensitive
	my $lc_sig = lc( $sig );

	my $md5 = Digest::MD5->new;
	$md5->add( $lc_sig );
	my $md5_hex = $md5->hexdigest;	# This should return a 32 byte digest
	
	my $sth_existing = $dbh_existing->prepare( "DELETE ExistingSignatures WHERE [MD5] = \'$md5_hex\'" );

	$sth_existing->execute();

	$sth_existing->finish();
	
	return( 1 );
}



################################################################################
# 
sub ClearTestBit( $ )
#
#  Given a virus name, clear the test bit
#  
################################################################################
{	my $name = shift;
	return( undef ) if ( ! $name );
	
	my $sth = $dbh->prepare( "UPDATE VirusSignatures SET [Test] = '0' WHERE VirusName = ?" );
	$sth->bind_param( 1, $name,  DBI::SQL_VARCHAR );
	$sth->execute();
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub SetTestBit()
#
#  Set the test bits on the existing signatures in the virus and spyware category
#  
################################################################################
{	my $sth = $dbh->prepare( "UPDATE VirusSignatures SET [Test] = '1' WHERE CategoryNumber = '63' AND SourceNumber > '1'" );
	$sth->execute();
	$sth->finish();
	
	$sth = $dbh->prepare( "UPDATE VirusSignatures SET [Test] = '1' WHERE CategoryNumber = '62' AND SourceNumber > '1'" );
	$sth->execute();
	$sth->finish();
	
	$sth = $dbh->prepare( "UPDATE VirusSignatures SET [Test] = '1' WHERE CategoryNumber = '6' AND VirusName LIKE 'ClamFalsePositive%' AND SourceNumber > '1'" );
	$sth->execute();
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub MoveTestBitErrors()
#
#  Move any signatures with the test bit still set into the errors category
#  
################################################################################
{		
	my $sth = $dbh->prepare( "UPDATE VirusSignatures SET CategoryNumber = '7', TransactionTime = getutcdate(), [Test] = '0' WHERE CategoryNumber = '63' AND [Test] = '1'" );
	$sth->execute();
	$sth->finish();
	
	my $rows = 0 + $sth->rows;
	lprint "Moved $rows virus signatures into the errors category\n";
	
	$sth = $dbh->prepare( "UPDATE VirusSignatures SET CategoryNumber = '7', TransactionTime = getutcdate(), [Test] = '0' WHERE CategoryNumber = '62' AND [Test] = '1'" );
	$sth->execute();
	$sth->finish();
	
	$rows = 0 + $sth->rows;
	lprint "Moved $rows spyware signatures into the errors category\n";
	
	$sth = $dbh->prepare( "UPDATE VirusSignatures SET CategoryNumber = '7', TransactionTime = getutcdate(), [Test] = '0' WHERE CategoryNumber = '6' AND VirusName LIKE 'ClamFalsePositive%' AND [Test] = '1'" );
	$sth->execute();
	$sth->finish();
	
	$rows = 0 + $sth->rows;
	lprint "Moved $rows Clam False Positive signatures into the errors category\n";
	
	# Clean up the test bit in the table
	$sth = $dbh->prepare( "UPDATE VirusSignatures SET TransactionTime = getutcdate(), [Test] = '0' WHERE [Test] = '1'" );
	$sth->execute();
	$sth->finish();
	
	return( 1 );
}



################################################################################
# 
sub ClamSignature( $$ )
#
#  Given data in Clam format return it in Lightspeed format
#  
################################################################################
{	my $line	= shift;	# A line from the file
	my $file	= shift;	# The name of the file - which gives a clue to the file format
	
	return( undef, undef, undef, undef, undef ) if ( ! defined $line );
	return( undef, undef, undef, undef, undef ) if ( ! defined $file );

	lprint "Clam Signature file: $file line: $line\n" if ( $opt_verbose );
	
	my $extended_format;
	my $mdb_format;
	my $zip_format;
	my $md5_format;
	my $clam_type;
	
	# Is this a new format database file?
	if ( ( $file =~ m/\.ndu$/i )  ||  ( $file =~ m/\.ndb$/i ) )
		{	$mdb_format			= undef;
			$zip_format			= undef;
			$md5_format			= undef;
			$extended_format	= 1;
		}
	
	if ( ( $file =~ m/\.hdu$/i )  ||  ( $file =~ m/\.hdb$/i )  ||  ( $file =~ m/\.fp$/i ) )
		{	$mdb_format			= undef;
			$zip_format			= undef;
			$md5_format			= 1;
			$extended_format	= undef;
		}
	
	if ( $file =~ m/\.zmd$/i )
		{	$mdb_format			= undef;
			$zip_format			= 1;
			$md5_format			= undef;
			$extended_format	= undef;
		}
	
	
	if ( ( $file =~ m/\.mdu$/i )  ||  ( $file =~ m/\.mdb$/i ) )
		{	$mdb_format			= 1;
			$zip_format			= undef;
			$md5_format			= undef;
			$extended_format	= undef;
		}
		
		
	my $name;
	my $sig;
	my $absolute_offset;
	
	
	# Ignore comment lines
	return( undef, undef, undef, undef, undef ) if ( $line =~ m/^#/ );
	
	# Clean the line
	$line =~ s/^\s+//;
	$line =~ s/\s+$//;
	return( undef, undef, undef, undef, undef ) if ( ! $line );
	
	
	if ( $extended_format )
		{	my ( $malware_name, $target_type, $noffset, $hex_sig, $version ) = split /\:/, $line;

			$name = $malware_name;
			
			# Should I ignore this virus name?
			return( undef, undef, undef, undef, undef ) if ( &IgnoreName( $file, $name ) );
			
			$target_type	= 0 + $target_type;
			$clam_type		= 0 + $target_type;
			
			$name = "Vba." . $name	if ( $target_type == 2 );
			$name = $name . ".htm"	if ( ( $target_type == 3 )  &&  ( ! ( $name =~ m/^HTML\./ ) ) );
			$name = $name . ".mail" if ( $target_type == 4 );
			$name = $name . ".jpg"	if ( $target_type == 5 );
			
			$sig = $hex_sig;
			
			
			# Is the signature a regular expression?
			# If so, put a bang on the front
			if ( $sig =~ m/[^a-zA-Z0-9]/ )
				{	$sig = "\!$hex_sig";
				}
			
			
			# Is it an absolute offset?  It is if there is just numbers in the noffset value
			if ( ( defined $noffset )  &&  ( ! ( $noffset =~ m/[^\d]/ ) ) )
				{	$absolute_offset = 0 + $noffset;
				}
			
			# If the offset is *, then it is the same as the old style 
			# If it isn't *, then it is the new style offset
			my $new_offset = $noffset if ( ( defined $noffset )  &&  ( $noffset ne "*" ) );

			if ( defined $new_offset )
				{	$sig = "!" . "EXT:" . $new_offset . ":" . $hex_sig;
				}
				
			lprint( "Extended format sig: $sig\n" ) if ( $opt_verbose );
		}
	elsif ( $md5_format )
		{	my ( $md5, $size, $md5_name ) = split /\:/, $line, 3;
			
			return( undef, undef, undef, undef, undef ) if ( ! $md5_name );
			return( undef, undef, undef, undef, undef ) if ( ! $md5 );

			if ( length( $md5 ) != 32 )
				{	lprint "Bad MD5 value of $md5 for MD5 name $md5_name, file $file\n";
					my $len = length( $md5 );
					lprint "line = $line\n";
					lprint "size = $size\n";
					lprint "MD5 = $md5\n";
					lprint "MD5 Name = $md5_name\n";
					lprint "len = $len\n";
					return( undef, undef, undef, undef, undef );
				}
				
			$name = $md5_name;
			
			# Should I ignore this virus name?
			return( undef, undef, undef, undef, undef ) if ( &IgnoreName( $file, $name ) );
			
			# If this is a false positive file then show the name as a Clam False Positive name
			if ( $file =~ m/\.fp$/i )
				{	$name = "ClamFalsePositive." . $md5_name;
				}
				
			$size = 0 + $size;
			return( undef, undef, undef, undef, undef ) if ( ! $size );
			
			$sig = "!" . "MD5:$size:$md5";
			
			lprint( "MD5 format sig: $sig\n" ) if ( $opt_verbose );
		}
	elsif ( $mdb_format )
		{	my ( $size, $md5, $md5_name ) = split /\:/, $line, 3;
			
			return( undef, undef, undef, undef, undef ) if ( ! $md5_name );
			return( undef, undef, undef, undef, undef ) if ( ! $md5 );

			if ( length( $md5 ) != 32 )
				{	lprint "Bad MD5 value of $md5 for SEGMD5 name $md5_name, file $file\n";
					my $len = length( $md5 );
					lprint "line = $line\n";
					lprint "size = $size\n";
					lprint "MD5 = $md5\n";
					lprint "MD5 Name = $md5_name\n";
					lprint "len = $len\n";
					return( undef, undef, undef, undef, undef );
				}
			
			$name = $md5_name;
			
			# Should I ignore this virus name?
			return( undef, undef, undef, undef, undef ) if ( &IgnoreName( $file, $name ) );
			
			$size = 0 + $size;
			return( undef, undef, undef, undef, undef ) if ( ! $size );
			
			$sig = "!" . "SEGMD5:$size:$md5";
			
			lprint( "SEGMD5 format sig: $sig\n" ) if ( $opt_verbose );
		}
	elsif ( $zip_format )
		{	( $name, $sig ) = split /\:/, $line, 2;
			
			return( undef, undef, undef, undef, undef ) if ( ! defined $name );
			return( undef, undef, undef, undef, undef ) if ( ! defined $sig );
			
			# Should I ignore this virus name?
			return( undef, undef, undef, undef, undef ) if ( &IgnoreName( $file, $name ) );
			
			$sig = "\!ZIP:$sig";
			
			lprint( "Zip format sig: $sig\n" ) if ( $opt_verbose );
		}
	else
		{	( $name, $sig ) = split /\=/, $line, 2;
			
			return( undef, undef, undef, undef, undef ) if ( ! defined $name );
			return( undef, undef, undef, undef, undef ) if ( ! defined $sig );
			
			# Should I ignore this virus name?
			return( undef, undef, undef, undef, undef ) if ( &IgnoreName( $file, $name ) );
			
			# Sometimes Clam makes a mistake and puts an extra = on the front of the sig
			$sig =~ s/^=+//;
		
			# Is the signature a regular expression?
			# If so, put a bang on the front
			if ( $sig =~ m/[^a-zA-Z0-9]/ )
				{	$sig = "\!$sig";
				}
				
			# This type of signature matches any file
			$clam_type = 0 + 0;
			
			lprint( "Original format sig: $sig\n" ) if ( $opt_verbose );
		}


	my $new_name;
	if ( $name )
		{	# Clean up other names
			$name =~ s/trojan/Trojan/ig;
			$name =~ s/backdoor/Backdoor/ig;
			$name =~ s/downloader/Downloader/ig;
			$name =~ s/dropper/Dropper/ig;
			$name =~ s/constructor/Constructor/ig;
			$name =~ s/Macro\.Word/WM97/ig;
			
			$name =~ s/WIN95/W95/g;
			$name =~ s/Win95/W95/g;
			$name =~ s/Win32/W32/g;
			$name =~ s/WIN32/W32/g;
			$name =~ s/\(Clam\)//g;
			
			# Check for a too long a name
			my $len = length( $name );
			if ( $len >= 60 )
				{	$name =~ s/Backdoor\.//;
					$name =~ s/Downloader\.//;
				}
				
			$name =~ s/\s//g if ( $name );
	
			# Get rid of empty ()
			$name =~ s/\(\)//g if ( $name );

			$new_name = &CleanVirusName( $name );
			if ( ! $new_name )
				{	lprint "Invalid virus name = $name\n";
					die;
				}
		}
		
	
	# Signatures for PUA should start with PUA.  PUA signature files all end in "u"
	my $pua;
	$pua = 1 if ( $file =~ m/u$/i );
	if ( ( $pua )  &&  ( ! ( $new_name =~ m/^pua\./i ) ) )
		{	$new_name = "Pua." . $new_name;
		}
	
				 
	# For all Clam old style viruses the start offset is 0, and the end offset is -1
	my $start_offset	= 0 + 0;		
	my $end_offset		= 0 - 1;
				
				
	# If I have an absolute offset, then that is the Lightspeed start offset
	# Set the end offset to -1 is give room for the signature if a wildcard
	# or the the actual end offset if a normal hex signature
	if ( defined $absolute_offset )
		{	my $sig_length	= ( length( $sig ) ) / 2;	# This is divided by 2 because the sig is in hex
			$start_offset	= $absolute_offset;
			$end_offset		= 0 - 1;
			
			# Set the end offset to be exact if the signatures is not a wildcard
			$end_offset = ( $start_offset + $sig_length ) if ( ! ( $sig =~ m/^!/ ) );
			
			print "$new_name has a fixed starting offset and a wildcard signature\n" if ( ( $end_offset == -1 )  &&  ( $opt_verbose ) );
		}
			

	# Do I have an extra long signature?
	my $len = length( $sig );
	if ( $len >= 512 )
		{	print "$new_name has a long signature length of $len\n" if ( $opt_verbose );
		}
		
	
	return( $new_name, $sig, $start_offset, $end_offset, $clam_type );
}



################################################################################
# 
sub IgnoreName( $$ )
#
#  Given a file name and a Clam virus name, return True if I should ignore it,
#  undef if I should use it
#  
################################################################################
{	my $file		= shift;	# The file name that the virus name came from
	my $virus_name	= shift;	# The virus name to check
		
	foreach ( @ignore_list )
		{	my $data = $_;
			next if ( ! $data );
			
			my ( $ignore_file, $ignore_virus_name ) = split /\t/, $data;
			
			next if ( lc( $file ) ne $ignore_file );
			next if ( lc( $virus_name ) ne $ignore_virus_name );
			
			&lprint( "Found $virus_name in file $file that is on the ignore list\n" );
			return( 1 );
		}
		
	return( undef );
}



################################################################################
# 
sub errstr($)
#  
################################################################################
{
    bprint shift;

    return( -1 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "ClamImport";

    bprint "$me\n\n" if (@_);

    bprint <<".";
Usage: $me [OPTION]... [FILE]
Try '$me --help' for more information.
.
   &StdFooter;

    exit;
}




################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "ClamImport";

    bprint <<".";
Usage: $me [OPTION(s)]
Imports virus signatures in Clam format into the Content database

uses clam files: @file_list

options
  -c, --category CATNAME   category to add signatures to, default security.test
  -d, --directory PATH	   clam files directory, default is current directory
  -m, --move               move signatures from \'test\' category to \'virus\'
  -n, --noupdate           do NOT actually update the database
  -s, --source             source number to use on insert, default is 2
  -v, --verbose            display verbose information when adding sigs
  
  -h, --help               display this help and exit
.
   &StdFooter;

    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "ClamImport";

    bprint <<".";
$me $_version
.
   &StdFooter;

    exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
