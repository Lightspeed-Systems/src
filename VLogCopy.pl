################################################################################
#!perl -w
#
#  Read a virus scanner log file and copy the infected files to a directory
#  in Lightspeed virus format
#
#  Copyright 2006 Lightspeed Systems Inc. by Rob McCarthy
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
use IO::Socket;


use Content::File;
use Content::ScanUtil;
use Content::Scanable;
use Content::SQL;
use Content::FileIntegrity;
use Content::Category;
use Content::FileInfo;



my $opt_help;
my $opt_dir;						# This is directory to copy the virus files to
my $opt_logtype;					# This is the type of virus log file I am analyzing
my $opt_filename;					# The is the filename of the virus log file
my $opt_move;						# If set, then move the entire directory to this value
my $opt_test;						# If set, then show the files to copy, but don't actually do the copies
my $opt_database = 1;				# If set, then save the file info into the Program database
my $opt_source_id = 0 + 1;			# The source_id of the source - 1 is Lightspeed Tested OK
my $opt_program;					# If set, just update the program info in the database
my $opt_noprogram;					# If set, don't the program info in the database
my $opt_remove;						# If set, remove the original directory if moving a directory
my $opt_overwrite;					# If set, overwrite existing program info with the new info
my $opt_debug;
my $opt_check;						# Output file of missing viruses
my $opt_scanable;					# Copy scanable but non-executable to another directory
my $opt_verbose;					# True if I should be verbose about what I am doing
my $opt_unlink;						# True if I should delete the virus infected file after copying it
my $opt_delete;						# True if I should delete the files without copying
my $opt_leftover;					# The directory that I should check for leftover files - putting the list into leftover.txt
my $opt_nosubdir;					# If True, then copy the files to the root of the destination directory
my $opt_write;						# If set then write the list of infected files to this text file
my $opt_existing;					# If set then don't copy over existing files

my %filelist;						# The hash of filenames and viruses
my %original_vname;					# The hash of filenames and the original virus name
my $dbhProgram;						# Handle to the Program database
my $add_counter		= 0 + 0;		# Count of files added to the database
my $update_counter	= 0 + 0;		# Count of files updated in the database
my $delete_counter  = 0 + 0;		# Count of old archive files that were deleted
my $file_id_virus_counter = 0 + 0;	# Count of the entries added to the file ID virus table



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
		"a|nosubdir"	=> \$opt_nosubdir,
		"c|check=s"		=> \$opt_check,
		"d|delete"		=> \$opt_delete,
		"e|existing"	=> \$opt_existing,
		"f|file=s"		=> \$opt_filename,
		"l|leftover=s"	=> \$opt_leftover,
		"m|move"		=> \$opt_move,
		"n|noprogram"	=> \$opt_noprogram,
		"o|overwrite"	=> \$opt_overwrite,
		"p|program"		=> \$opt_program,
		"r|remove"		=> \$opt_remove,
		"s|scanable=s"	=> \$opt_scanable,
		"t|test"		=> \$opt_test,
		"u|unlink"		=> \$opt_unlink,
		"v|verbose"		=> \$opt_verbose,
		"w|write=s"		=> \$opt_write,
        "h|help"		=> \$opt_help,
        "x|xdebug"		=> \$opt_debug
      );


    &StdHeader( "VLogCopy" );
	&Usage() if ( $opt_help );

	print "Debugging ...\n" if ( $opt_debug );
	
	
	$opt_filename	= shift;
	$opt_logtype	= shift;
	$opt_dir		= shift;
			

	&Usage() if ( ( ! $opt_logtype )  ||  ( ! $opt_filename ) );
	&Usage() if ( ( ! $opt_write )  &&  ( ! $opt_program )  &&  ( ! $opt_dir )  &&  ( ! $opt_check )  &&  ( ! $opt_delete )  &&  ( ! $opt_leftover )  &&  ( ! $opt_overwrite ) );


	# Make sure that the opt database is turned on if the opt_program option is turned on
	$opt_database = 1 if ( $opt_program );
	
	
	# Make sure that the opt database is turned off if the opt_noprogram option is turned on
	$opt_database = undef if ( $opt_noprogram );
	
	
	# Make sure that the opt database is turned on if the opt_check option is turned on
	$opt_database = 1 if ( $opt_check );
	

	if ( ! -f $opt_filename )
		{	print "Unable to find log file $opt_filename\n";
			exit( 0 + 1 );
		}

	if ( ( $opt_leftover )  &&  ( ! -d $opt_leftover ) )
		{	print "Unable to find leftover directory $opt_leftover\n";
			exit( 0 + 2 );
		}
	
	if ( ( ! $opt_write )  &&  ( ! $opt_program )  &&  ( ! $opt_check )  &&  ( ! $opt_delete )  &&  ( ! $opt_leftover )  &&  ( ! -d $opt_dir ) )
		{	print "Unable to find directory $opt_dir\n";
			exit( 0 + 2 );
		}


	if ( ( $opt_scanable )  &&  ( ! -d $opt_scanable ) )
		{	print "Unable to find directory $opt_scanable\n";
			exit( 0 + 3 );
		}


	print "Moving the entire directory structure containing viruses to $opt_dir ...\n" if ( $opt_move );
	print "Just updating the File ID Virus table ...\n" if ( $opt_program );
	print "Deleting the source infected file ...\n" if ( $opt_unlink );
	print "Just showing what files will be copied ...\n" if ( $opt_test );
	print "Just write the list of infected files to $opt_write ...\n" if ( $opt_write );
	print "Removing the original directory ...\n" if ( ( $opt_remove )  &&  ( $opt_move ) );
	print "Overwriting existing program info in the Program database ...\n" if ( $opt_overwrite );
	print "Do not update the program info in the Program database ...\n" if ( $opt_noprogram );
	print "Write unknown viruses to text file $opt_check ...\n" if ( $opt_check );
	print "Deleting the virus infected files without copying ...\n" if ( $opt_delete );
	print "Just finding the leftover files that at NOT viruses in directory $opt_leftover\n" if ( $opt_leftover );
	print "Not copying over any existing files\n" if ( $opt_existing );
	print "Verbose mode\n" if ( $opt_verbose );

	
	# Check to make sure that I have a valid log file type
	my $ok = 1;
	$ok = undef if ( ( lc( $opt_logtype ) ne "f-prot" )  &&
		( lc( $opt_logtype ) ne "f-protold" )  &&
		( lc( $opt_logtype ) ne "adaware" )  &&
		( lc( $opt_logtype ) ne "avast" )  &&
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
		( lc( $opt_logtype ) ne "nod32" )  &&
		( lc( $opt_logtype ) ne "avg" )  &&
		( ! ( $opt_logtype =~ m/^windefen/i ) )  &&
		( ! ( $opt_logtype =~ m/^kasp/i ) )  &&
		( ! ( $opt_logtype =~ m/^trend/i ) )  &&
		( ! ( $opt_logtype =~ m/^pccill/i ) )  &&
		( ! ( $opt_logtype =~ m/malware/i ) )  &&
		( lc( $opt_logtype ) ne "sa" ) );
					
	if ( ! $ok )
		{	print "Invalid log file type.\n";
			print "Must be AdAware, Avast, Clam, ClamScan, DrWeb, F-Prot, F-ProtOld, F-Secure, Kaspersky,\nMcAfee, NOD32, Norton, NortonExport, SA, Sophos, TrendMicro, PCCillin, \nWindefender, AVG, MalwareBytes, or Winlog.\n";
			exit( 0 + 4 );	
		}


	if ( $opt_database )
		{	$dbhProgram = &ConnectRemoteProgram();
	
			if ( ! $dbhProgram )
				{
print "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

					exit( 0 + 5 );
				}
		}
		
		
	# Build up the list to copy
	%filelist = &FProt( $opt_filename )				if ( lc( $opt_logtype ) eq "f-prot" );
	%filelist = &FProtOld( $opt_filename )			if ( lc( $opt_logtype ) eq "f-protold" );
	%filelist = &Adaware( $opt_filename )			if ( lc( $opt_logtype ) eq "adaware" );
	%filelist = &Avast( $opt_filename )				if ( lc( $opt_logtype ) eq "avast" );
	%filelist = &DrWeb( $opt_filename )				if ( lc( $opt_logtype ) eq "drweb" );
	%filelist = &Clam( $opt_filename )				if ( lc( $opt_logtype ) eq "clam" );
	%filelist = &ClamScan( $opt_filename )			if ( lc( $opt_logtype ) eq "clamscan" );
	%filelist = &Kaspersky( $opt_filename )			if ( $opt_logtype =~ m/^kasp/i );
	%filelist = &FSecure( $opt_filename )			if ( lc( $opt_logtype ) eq "fsecure" );
	%filelist = &FSecure( $opt_filename )			if ( lc( $opt_logtype ) eq "f-secure" );
	%filelist = &Trend( $opt_filename )				if ( $opt_logtype =~ m/^trend/i );
	%filelist = &PCCillin( $opt_filename )			if ( $opt_logtype =~ m/^pccill/i );
	%filelist = &SA( $opt_filename )				if ( lc( $opt_logtype ) eq "sa" );
	%filelist = &McAfee( $opt_filename )			if ( lc( $opt_logtype ) eq "mcafee" );
	%filelist = &Norton( $opt_filename )			if ( lc( $opt_logtype ) eq "norton" );
	%filelist = &NortonExport( $opt_filename )		if ( lc( $opt_logtype ) eq "nortonexport" );
	%filelist = &Sophos( $opt_filename )			if ( lc( $opt_logtype ) eq "sophos" );
	%filelist = &Windefender( $opt_filename )		if ( $opt_logtype =~ m/^wind/i );
	%filelist = &WindefenderLog( $opt_filename )	if ( lc( $opt_logtype ) eq "winlog" );
	%filelist = &NOD32( $opt_filename )				if ( lc( $opt_logtype ) eq "nod32" );
	%filelist = &AVG( $opt_filename )				if ( lc( $opt_logtype ) eq "avg" );
	%filelist = &MalwareBytes( $opt_filename )		if ( $opt_logtype =~ m/malware/i );
	
	
	my @files = keys %filelist;
	my $count = $#files + 1;
	
	
	if ( ! $count )
		{	print "Unable to find any virus infected files\n";
			
			# Write out a zero length file if this option is used
			&OptWrite() if ( $opt_write );
			
			exit( 0 + 0 );
		}
		
	print "Found $count virus infected files\n";
		

	if ( $opt_debug )
		{	print "Debug stop\n";
			exit( 1 );
		}
	elsif ( $opt_test )
		{	&OptTest();
		}
	elsif ( $opt_write )
		{	&OptWrite();
		}
	elsif ( $opt_check )
		{	&VirusCheck();
		}
	elsif ( $opt_move )
		{	my $move_count = &OptMove();
			
			print "Moved $move_count virus infected directories\n";
		}
	elsif ( $opt_program )
		{	open( APPCHANGE, ">>AppChange.txt" ) or die "Error opening AppChange.txt file: $!\n";
			
			&VirusDatabase();
			
			print "Added $add_counter entries to the Programs table\n";
			print "Updated $update_counter entries in the Programs table\n";
			print "Deleted $delete_counter old Virus Archive files\n";
			print "Added $file_id_virus_counter entries to the FileIDVirus table\n";
			
			close( APPCHANGE );
		}
	elsif ( $opt_delete )
		{	my $copy_count = &VirusDelete();
			
			print "Found $count virus infected files\n";
			print "Deleted $copy_count virus infected files\n";
		}
	elsif ( $opt_leftover )
		{	my $leftover_count = &VirusLeftover( $opt_leftover );
			
			print "Found $leftover_count NOT virus infected files in directory $opt_leftover\n";
		}
	else	
		{	my $copy_count = &VirusCopy();
			
			print "Found $count virus infected files\n";
			print "Copied $copy_count virus infected files\n";
			
			if ( $opt_database )
				{	print "Added $add_counter entries to the Programs table\n";
					print "Updated $update_counter entries in the Programs table\n";
					print "Deleted $delete_counter old Virus Archive files\n";
					print "Added $file_id_virus_counter entries to the FileIDVirus table\n";
				}
		}
		
	
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
	&StdFooter;
	
	exit( 0 + 0 );
}



################################################################################
# 
sub VirusCheck()
#
#  Check to see if the virus is in the database - if not, write it out to the 
#  log file
#
################################################################################
{
	if ( ! open( MISSING, ">$opt_check" ) )
		{	print "Error opening file $opt_check: $!\n";
			return( undef );
		}
		
	my @files = sort keys %original_vname;
	
	my $count = 0 + 0;
	
	my $log_company = &CategoryLogCompany( $opt_logtype );
	
	foreach ( @files )
		{	my $vfile = $_;
			
			next if ( ! $vfile );
			
			my $vname = $original_vname{ $vfile };
			
			next if ( ! $vname );
			
			# Make sure it is a regular file with something in it
			next if ( -d $vfile );
			next if ( ! -s $vfile );

			# It the virus file does not exist - this is not fatal - just skip over it
			if ( ! -f $vfile )
				{	print "Error: Unable to find file $vfile\n";
					next;
				}
				
			# Does the vfile name indicate an exe?
			next if ( ! ( $vfile =~ m/\.exe_$/i ) );
		
			# Does the vname indicate something I'm interested in?
			my $interested;
			
			$interested = 1 if ( $vfile =~ m/\.exe_$/i );
			$interested = undef if ( $vname =~ m/spy/i );
			$interested = undef if ( $vname =~ m/keylog/i );
			
			next if ( ! $interested );
			
			# Does this vname exist in the FileIDVirus table?
			my $sth;
			$sth = $dbhProgram->prepare( "SELECT FileID FROM FileIDVirus WITH(NOLOCK) WHERE VirusName = ? AND Company = ?" );
					
			$sth->bind_param( 1, $vname,  DBI::SQL_VARCHAR );
			$sth->bind_param( 2, $log_company,  DBI::SQL_VARCHAR );
			
			$sth->execute();
			my $hex_file_id = $sth->fetchrow_array();

			$sth->finish();
			
			next if ( $hex_file_id );
			
			# Could the filename indicate a CRC32 value?  This is True of files from
			# Antony from collecting@virus.gr
			my ( $dir, $short ) = &SplitFileName( $vfile );
					
			my ( $name, $ext ) = split /\./, $short if ( $short );

			if ( ( $name )  &&  ( length( $name ) == 8 ) )
				{
					$name = uc( $name );
					$sth = $dbhProgram->prepare( "SELECT FileID, AppName, [Filename] FROM Programs WITH(NOLOCK) WHERE CRC32 = \'$name\'" );
							
					$sth->execute();
					
					my $found_virus;
					while ( my ( $hex_file_id, $app_name, $db_filename ) = $sth->fetchrow_array() )
						{	next if ( ! $db_filename );
							if ( $db_filename =~ m/virus archive/i )
								{	$found_virus = 1;
									print "Have CRC32 value $name already as virus $app_name\n";
								}
						}
						
					$sth->finish();
					
					if ( $found_virus )
						{	
							next;	
						}
				}
				

			print "$vfile is infected with $vname\n" if ( $opt_verbose );
			
			print MISSING "$vfile\n";		
			
			$count++;
		}

	close( MISSING );
	
	print "Found $count missing viruses from the database\n";
	
	return( $count );
}



################################################################################
# 
sub OptTest()
#
#	
#  Show the files to copy, but don't actually do the copies
#
################################################################################
{
	my @files = sort keys %filelist;
	
	my $count = 0 + 0;
	
	foreach ( @files )
		{	my $vfile = $_;
			
			next if ( ! $vfile );
			
			my $virus = $filelist{ $vfile };
			
			next if ( ! $virus );
							
			# Make sure it is a regular file with something in it
			next if ( -d $vfile );
			next if ( ! -s $vfile );

			# It the virus file does not exist - this is not fatal - just skip over it
			if ( ! -f $vfile )
				{	print "Error: Unable to find file $vfile\n";
					next;
				}

			my ( $dir, $short ) = &SplitFileName( $vfile );
			
			next if ( ! $short );
			
			# See if I can figure out if it is a VBS, W32, Linux, etc type of virus
			my $virus_dir = &VirusTypeDir( $virus );
			
			my $dest_dir = $opt_dir . "\\$virus";
			$dest_dir = $opt_dir . "\\$virus_dir" . "\\$virus" if ( $virus_dir ); 
			
			my $dest = $dest_dir . "\\$short";
			
			# Add an underscore the file destingation filename if it doesn't already have one
			$dest =~ s/\_+$//;
			$dest .= '_' if ( ! ( $dest =~ m/\_$/ ) );
			
			print "Would copy $vfile to $dest\n";
			
			$count++;
		}

	return( $count );
}



################################################################################
# 
sub OptWrite()
#
#	
#  Write the list of virus infected files to $opt_write
#
################################################################################
{
	if ( ! open( WRITE, ">$opt_write" ) )
		{	print "Error opening file $opt_write: $!\n";
			return( undef );
		}
		
	my @files = sort keys %filelist;
	
	my $count = 0 + 0;
	
	foreach ( @files )
		{	my $vfile = $_;
			
			next if ( ! defined $vfile );
			
			my $virus = $filelist{ $vfile };
			
			next if ( ! defined $virus );
			
			print WRITE "$vfile\t$virus\n";				
			
			$count++;
		}

	print WRITE "\n";	# Put a CRLF to force the file to be written
	
	close( WRITE );
	
	return( $count );
}



################################################################################
# 
sub OptMove()
#
#	Move the virus indefected directories to $opt_move
#
################################################################################
{
	
	my @vfiles = keys %filelist;
	
	my %dirhash;
	
	foreach ( @vfiles )
		{	next if ( ! $_ );
			
			my $vfile = $_;
			
			# Make sure it is a regular file with something in it
			next if ( -d $vfile );
			next if ( ! -s $vfile );

			# It the virus file does not exist - this is not fatal - just skip over it
			if ( ! -f $vfile )
				{	print "Error: Unable to find file $vfile\n";
					next;
				}

			my ( $dir, $short ) = &SplitFileName( $vfile );
			
			next if ( ! defined $dir );
			
			my @parts = split /\\/, $dir;


			# Build up the full path to the important directory
			my $important = $parts[ 0 ];
			for ( my $i = 1;  $i < 4;  $i++ )
				{	my $part = $parts[ $i ];
					next if ( ! defined $part );
					$important .= "\\" . $part;
				}


			next if ( ! defined $important );
			$important = lc( $important );	


			# Skip the directory if it doesn't exist
			if ( ! -d $important )
				{	print "Can't find directory $important\n";
					next;
				}
			
			next if ( defined $dirhash{ $important } );

			print "Found directory $important containing viruses\n";
			$dirhash{ $important } = 1;
		}
		
	my @dirlist = sort keys %dirhash;

	if ( $#dirlist < 0 )
		{	print "Did not find any directories to move\n";
			return( 0 + 0 );
		}
		
	my $count = 0 + 0;	

	foreach ( @dirlist )
		{	next if ( ! defined $_ );
			
			my $src = $_;
			
			my @parts = split /\\/, $src;

			my $domain = $parts[ 3 ];
			my $root = &RootDomain( $domain );
			
			if ( ! $root )
				{	$domain = $parts[ 2 ];
					$root = &RootDomain( $domain );
				}
				
			next if ( ! $root );

			my $ok = &MoveDir( $src, "$opt_dir\\$domain", $opt_remove );
			
			$count++ if ( $ok );
		}

	return( $count );
}



################################################################################
#
sub MoveDir( $$$ )
#
#  Move a directory and optionally remove the original
#
################################################################################
{	my $src		= shift;
	my $target	= shift;
	my $remove	= shift;
	
	return( undef ) if ( ! defined $src );
	return( undef ) if ( ! defined $target );
	
	return( undef ) if ( ! -d $src );
	
	my $ok = &MakeDirectory( $target );
	if ( ! $ok )
		{	print "Unable to make directory $target: $!\n";
			return( undef );	
		}
	
	system "xcopy \"$src\" \"$target\" /s /Y /F /H /R";
	
	system "rmdir \"$src\" /s /q" if ( $remove );
	
	return( 1 );
}



################################################################################
# 
sub VirusCopy()
#
#	Copy the files in the filelist hash
#
################################################################################
{	print "Copying the virus infected files ...\n";
	
	my $copy_count = 0 + 0;
	
	my @files = sort keys %filelist;
	
	my $log_company = &CategoryLogCompany( $opt_logtype );
	
	if ( ! $opt_logtype )
		{	print "Unable to figure out the log company for log type $opt_logtype\n";
			exit( 0 + 7 );
		}
		
	my $count = $#files + 1;
	print "Virus log contains $count virus infected files ...\n";

	foreach ( @files )
		{	my $vfile = $_;
			
			next if ( ! defined $vfile );
			
			my $virus = $filelist{ $vfile };
			
			next if ( ! $virus );
			
			# Make sure it is a regular file with something in it
			next if ( -d $vfile );

			# It the virus file does not exist - this is not fatal - just skip over it
			if ( ! -f $vfile )
				{	print "Error: Unable to find file $vfile\n";
					next;
				}

			my $size = -s $vfile;

			if ( ! defined $size )
				{	print "Error getting file size, Errno: $!\n";
					next;
				}
			next if ( ! $size );
				
			my ( $dir, $short ) = &SplitFileName( $vfile );
			
			next if ( ! $short );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! defined $virus );

			# See if I can figure out if it is a VBS, W32, Linux, etc type of virus
			my $virus_dir = &VirusTypeDir( $virus );
			
			# What directory should I copy it to?			
			my $dest_dir = $opt_dir . "\\$virus";
			$dest_dir = $opt_dir . "\\$virus_dir" . "\\$virus" if ( $virus_dir ); 

			# just copy to the root of the destination directory if that option is selected
			$dest_dir = $opt_dir if ( $opt_nosubdir );
			

			# Is this a scanable but non-executable file that I need to copy some other place?
			if ( $opt_scanable )
				{	my $scanable = &Scanable( $vfile, 1 );
					
					# Copy non-scanable and email files to the opt_scanable directory instead
					if ( ( $scanable )  &&  ( $scanable == 6 ) )
						{	my $scanable_dir = $opt_scanable;
							
							print "Email file - copy to $opt_scanable instead\n";
			
							$dest_dir = $opt_scanable . "\\$virus";
							$dest_dir = $opt_scanable . "\\$virus_dir" . "\\$virus" if ( $virus_dir ); 
						}
				}
			
			
			# If I can't make the directory then this is a real problem
			my $ok = &MakeDirectory( $dest_dir );
			if ( ! $ok )
				{	print "Error making directory $dest_dir: $!\n";
					exit( 0 + 8 );
				}
				
			my $dest = $dest_dir . "\\$short";
			
			# Add an underscore the file destination filename if it doesn't already have one
			$dest =~ s/\_+$//;
			$dest .= '_' if ( ! ( $dest =~ m/\_$/ ) );
			
			# Check to make sure that I'm not copying to myself
			if ( lc( $vfile ) eq lc( $dest ) )
				{	print "Source and destination are the same, so skipping copy ...\n";
					my $original_vname = $original_vname{ $vfile };
					&ProgramDatabase( $dest, $log_company, $virus, $original_vname );
					next;
				}
			
			
			if ( ( $opt_existing )  &&  ( -f $dest ) )
				{	print "Not copying existing file $dest\n";
					$ok = 1;
				}
			else	# Copy the file
				{	print "Copying $vfile ...\n";
			
					$ok = copy( $vfile, $dest );
			
					# Copy errors are a real problem!
					if ( ! $ok )
						{	my $err = $^E;
							print "Error copying $vfile to $dest: $err\n";
							exit( 0 + 9 );
						}
					
					$copy_count++;
				}
			
			# Should I save the data into the Program database?
			if ( ! $opt_database )
				{	unlink( $vfile ) if ( $opt_unlink );
					if ( ! -e $dest )
						{	print "Unable to find file $dest after copying!\n";
							exit( 0 + 10 );
						}
						
					next;	
				}
			
			if ( ! -e $dest )
				{	print "Unable to find file $dest after copying!\n";
					exit( 0 + 11 );
				}
			
			my $original_vname = $original_vname{ $vfile };
			&ProgramDatabase( $dest, $log_company, $virus, $original_vname );
			
			unlink( $vfile ) if ( $opt_unlink );
		}
		
	return( $copy_count );
}



################################################################################
# 
sub VirusDelete()
#
#	Delete the files in the filelist hash
#
################################################################################
{	print "Deleting the virus infected files ...\n";
	
	my $delete_count = 0 + 0;
	
	my @files = sort keys %filelist;
			
	my $count = $#files + 1;
	print "Virus log contains $count virus infected files ...\n";

	foreach ( @files )
		{	my $vfile = $_;
			
			next if ( ! $vfile );
						
			# Make sure it is a regular file with something in it
			next if ( -d $vfile );
			next if ( ! -s $vfile );

			# It the virus file does not exist - this is not fatal - just skip over it
			if ( ! -f $vfile )
				{	print "Error: Unable to find file $vfile\n";
					next;
				}
				
			my $ok = unlink( $vfile );	
			
			# Delete errors are a real problem!
			if ( ! $ok )
				{	my $err = $^E;
					print "Error deleting $vfile: $err\n";
					exit( 0 + 9 );
				}
			
			$delete_count++;
			
		}
		
	return( $delete_count );
}



################################################################################
# 
sub VirusLeftover( $ )
#
#	Delete the files in the filelist hash
#
################################################################################
{	my $leftover_dir = shift;
	
	print "Finding the leftover files and putting the list into \"leftover.txt\" ...\n";
	
	open( LEFTOVERLIST, ">leftover.txt" ) or die "Error creating leftover.txt: $!\n";
	
	my $leftover_count = &LeftoverDirectory( $leftover_dir );
	
	close( LEFTOVERLIST );
		
	return( $leftover_count );
}



################################################################################
#
sub LeftoverDirectory( $ )
#
#  Given a directory, print the list of files that are NOT virues to LEFTOVERLIST
#
################################################################################
{	my $dir	= shift;

	return( 0 + 0 ) if ( ! -d $dir );
	
	my $dir_handle;
	return( 0 + 0 ) if ( ! opendir( $dir_handle, $dir ) );

	print "Checking directory $dir ...\n" if ( $opt_verbose );
	
	my $total = 0 + 0;
	my $lc_dir = lc( $dir );
	while ( my $file = readdir( $dir_handle ) )
		{	next if ( ! defined $file );
			next if ( $file eq '.' );
			next if ( $file eq '..' );	
			
			my $full_file = "$dir\\$file";
			my $vfile = "$lc_dir\\$file";
			
			if ( -d $full_file )
				{	my $subtotal = &LeftoverDirectory( $full_file );
					$total += $subtotal;
				}
			elsif ( ! defined $filelist{ $vfile } )
				{	$total++;
					print LEFTOVERLIST "$full_file\n";
					print "$full_file\n" if ( $opt_verbose );
				}
		}

	closedir( $dir_handle );

	return( $total );
}



################################################################################
# 
sub VirusDatabase()
#
#	Just update the virus database info
#
################################################################################
{
	print "Updating the virus database ...\n";
		
	my $log_company = &CategoryLogCompany( $opt_logtype );
	
	while ( my ( $vfile, $virus ) = each( %filelist ) )
		{	next if ( ! defined $vfile );
			
			# Make sure it is a regular file with something in it
			next if ( -d $vfile );
			next if ( ! -s $vfile );

			# It the virus file does not exist - this is not fatal - just skip over it
			if ( ! -f $vfile )
				{	print "Error: Unable to find file $vfile\n";
					next;
				}

				
			my $original_vname	= $original_vname{ $vfile };


			&ProgramDatabase( $vfile, $log_company, $virus, $original_vname );
		}
		
	return;
}



################################################################################
# 
sub FProt( $ )
#
#	Given a F-Prot log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading F-Prot log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
		
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
			next if ( $line =~ m/possible/i );
			next if ( $line =~ m/probably/i );
			next if ( $line =~ m/probable/i );
#			next if ( $line =~ m/possibly/i );
			
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
			$vword = 1 if ( $line =~ m/is a security risk/i );
			$vword = 1 if ( $line =~ m/is a destructive/i );
			$vword = 1 if ( $line =~ m/found password stealer/i );
			$vword = 1 if ( $line =~ m/contains infected objects/i );
			$vword = 1 if ( $line =~ m/infection\:/i );
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
			
			
			# See if the file exists
			if ( ( ! $opt_check  )  &&  ( ! -e $vfile )  &&  ( ! $opt_debug ) )
				{	# If the file doesn't exist, see if there is a doubled name
					( $vfile, $junk ) = split /_/, $vfile;
					$vfile .= '_' if ( $junk );
					
					# Trim off any trailing \'s
					$vfile =~ s/\\+$// if ( $vfile );
			
					if ( ! -e $vfile )
						{	print "Unable to find the file from this line: $line\n";
							next;
						}
				}
				
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
			$virus =~ s/\(inactive\)//ig;
			$virus =~ s/\(remnants\)//ig;
			$virus =~ s/\(trojan\)//ig;
			$virus =~ s/\(intended\)//ig;
			$virus =~ s/\(bad sample\)//ig;

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
			
			$original_vname{ $vfile } = &CleanVName( $virus );
			
			# Get rid of strange stuff
			$virus =~ s/-based\!maximus//ig if ( $virus );
			$virus =~ s/based//ig if ( $virus );
			$virus =~ s/maximus//ig if ( $virus );
			$virus =~ s/\.unknown\?$//i if ( $virus );
			$virus =~ s/\.damaged\?$//i if ( $virus );
			next if ( ! $virus );
			
			$virus = "Joke.program" if ( ( $virus eq "program" )  &&  ( $line =~ m/joke/ ) );
			
			$virus = &CleanVirusName( $virus );
			
			next if ( ! $virus );

			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from F-Prot log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub FProtOld( $ )
#
#	Given a F-Prot Old style log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading F-Prot older style log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
		
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
			next if ( $line =~ m/is a corrupted or intended virus/i );
			next if ( $line =~ m/possible/i );
			next if ( $line =~ m/probably/i );
			next if ( $line =~ m/probable/i );
#			next if ( $line =~ m/possibly/i );
			
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
			$vword = 1 if ( $line =~ m/is a security risk/i );
			$vword = 1 if ( $line =~ m/is a destructive/i );
			$vword = 1 if ( $line =~ m/found password stealer/i );
			$vword = 1 if ( $line =~ m/contains infected objects/i );
			$vword = 1 if ( $line =~ m/infection\:/i );
			next if ( ! $vword );
			
			my ( $vfile, $virus ) = split /\s/, $line, 2;


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
			
			
			# See if the file exists
			if ( ( ! $opt_check  )  &&  ( ! -e $vfile )  &&  ( ! $opt_debug ) )
				{	# If the file doesn't exist, see if there is a doubled name
					( $vfile, $junk ) = split /_/, $vfile;
					$vfile .= '_' if ( $junk );
					
					# Trim off any trailing \'s
					$vfile =~ s/\\+$// if ( $vfile );
			
					if ( ! -e $vfile )
						{	print "Unable to find the file from this line: $line\n";
							next;
						}
				}
				
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
			$virus =~ s/\(inactive\)//ig;
			$virus =~ s/\(remnants\)//ig;
			$virus =~ s/\(trojan\)//ig;
			$virus =~ s/\(intended\)//ig;
			$virus =~ s/\(bad sample\)//ig;

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
			$virus =~ s/is a security risk named //i;
			$virus =~ s/is a security risk or a \"backdoor\" program//i;
			$virus =~ s/is a destructive program//i;
			$virus =~ s/new or modified variant of //i;
			
			next if ( ! $virus );
			
			$virus =~ s/infection//i;
			$virus =~ s/named //i;
			$virus =~ s/ - dropper//i;
			$virus =~ s/ - packed//i;
			$virus =~ s/image file//ig;
			$virus =~ s/\: //i;
			$virus =~ s/\?//g;
			
			next if ( ! $virus );
			
			$original_vname{ $vfile } = &CleanVName( $virus );
			
			# Get rid of strange stuff
			$virus =~ s/-based\!maximus//ig if ( $virus );
			$virus =~ s/based//ig if ( $virus );
			$virus =~ s/maximus//ig if ( $virus );
			$virus =~ s/\.unknown\?$//i if ( $virus );
			$virus =~ s/\.damaged\?$//i if ( $virus );
			next if ( ! $virus );
			
			$virus = "Joke.program" if ( ( $virus eq "program" )  &&  ( $line =~ m/joke/ ) );
			
			$virus = &CleanVirusName( $virus );
			
			next if ( ! $virus );

			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from F-Prot log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub Adaware( $ )
#
#	Given an Adaware log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading Ad-Aware log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
	
	my $linecount = 0 + 0;
	my $family_id;	# This is the Family of viruses from Adaware
	my $virus_count = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			# Trim off leading and trailing whitespace
			$line =~ s/^\s+//;
			next if ( ! $line );
			
			$line =~ s/\s+$//;
			next if ( ! $line );
			
			# Is this a Family ID?
			if ( $line =~ m/^Family Id\:/i )
				{	$family_id = undef;
					
					# I need to see Name: and Category: on the line
					next if ( ! $line =~ m/Name\:/ );
					next if ( ! $line =~ m/Category\:/ );
					
					my $category;
					my $junk;
					
					( $junk, $family_id ) = split /Name\:/, $line, 2;
					
					next if ( ! defined $family_id );
					
					( $family_id, $category ) = split /Category\:/, $family_id, 2;
					next if ( ! defined $family_id );
					
					# Trim leading and trailing spaces
					$family_id =~ s/^\s+//;
					$family_id =~ s/\s+$//;

					next;
				}

			# I don't have anything until I've got that Family ID				
			next if ( ! $family_id );
			
			# Now I should have an Item ID line
			next if ( ! ( $line =~ m/Item Id\:/ ) );

			# Now it should also have a File: or Value:
			next if ( ! ( $line =~ m/File:/ )  &&  ! ( $line =~ m/Value:/ ) );
			
			my ( $junk, $vfile );
			
			if ( $line =~ m/File:/ )
				{	( $junk, $vfile ) = split /File:/, $line, 2 ;
				}
			elsif ( $line =~ m/Value:/ )
				{	( $junk, $vfile ) = split /Value:/, $line, 2;
				}
				
			my $virus;
			
			# Do I have a separate virus name instead of a family ID?
			if ( $vfile =~ m/\xa4/ )
				{	my ( $actual_file, $virus_part ) = split /\xa4/, $vfile, 2;
					$vfile = $actual_file;

					# The virus should be the last name on the line
					my @parts = split /\s/, $virus_part;
					$virus = $parts[ $#parts ];
					
					$virus =~ s/^\s+// if ( $virus );
					$virus =~ s/\s+$// if ( $virus );					
				}
			else	# If there isn't that xA4 character, then the family_id is the virus
				{	$virus = $family_id;
				}
			
				
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			$vfile =~ s/\s+$// if ( $vfile );
			$vfile =~ s/^\s+// if ( $vfile );
	
			if ( ( ! $vfile )  ||  ( ! -f $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					print "vfile = $vfile\n";
					next;	
				}

			my $original_vname = $virus;
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Did I find everything?
			if ( ( ! $vfile )  ||  ( ! $virus ) )
				{	print( "Unable to parse the virus file from this line: $line\n" );
					next;
				}
				
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
	
			$filelist{ $vfile } = $virus;
			$original_vname{ $vfile } = &CleanVName( $original_vname );
			

			print "$vfile is infected with $virus\n" if ( $opt_verbose );
			$virus_count++;
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from AD Aware log file $filename\n";
	print "Found $virus_count virus infected files from AD Aware log file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub Avast( $ )
#
#	Given an Avast log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading Ad-Aware log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
	
	my $linecount = 0 + 0;
	my $virus_count = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			# Trim off leading and trailing whitespace
			$line =~ s/^\s+//;
			next if ( ! $line );
			
			$line =~ s/\s+$//;
			next if ( ! $line );
			
			# ignore password protected because there is nothing we can do about it
			next if ( $line =~ m/ password protected/ );
			
			# It should have '[L]' characters if it is a virus
			my $is_virus = 1				if ( $line =~ m/ \[L\] /);
			my $is_decompression_bomb = 1	if ( $line =~ m/decompression bomb/);

			# If it isn't a virus, and it isn't a decompression bomb, then give up here
			next if ( ( ! $is_virus )  &&  ( ! $is_decompression_bomb ) );
			
			my ( $junk, $vfile, $stuff );
			
			# The file could be an archive, in which case the archive filename is just before the '|>'
			( $vfile, $stuff ) = split /\|\>/, $line, 2 ;
			
			# If I got some stuff, then the $vfile is the actual archive file name
			if ( ! defined $stuff ) # If not, then the vfile is the name before ' [L]'
				{	( $vfile, $stuff ) = split / \[L\] /, $line, 2;
				}
				
			# if I don't have any stuff then this isn't something I want
			next if ( ! defined $stuff );
			
			# Trim off leading and trailing whitespace off of the stuff
			$stuff =~ s/^\s+//;
			next if ( ! defined $stuff );
			
			$stuff =~ s/\s+$//;
			next if ( ! defined $stuff );

			# Now figure out the virus name
			my $virus;
			
			# If it is a decompression bomb, then the virus name is this
			if ( $is_decompression_bomb )
				{	$virus = "W32.Decompression.Bomb";
				}
			elsif ( $stuff =~ m/ \[L\] / )
				{	( $junk, $virus ) = split / \[L\] /, $stuff, 2;
					$virus =~ s/ \(.\)$// if ( defined $virus );	# Get rid of the (0) crap
				}
			else	# The virus name should be right in from of the first ' ['
				{	( $virus, $junk ) = split /\[/, $stuff, 2;
					$virus =~ s/ \(.\)$// if ( defined $virus );	# Get rid of the (0) crap
				}
			
			next if ( ! defined $virus );
			
			# Trim off leading and trailing whitespace off of the virus name
			$virus =~ s/^\s+//;
			$virus =~ s/\s+$//;


			# Trim off any trailing \'s off of the vfile
			$vfile =~ s/\\+$// if ( $vfile );
			
			$vfile =~ s/\s+$// if ( $vfile );
			$vfile =~ s/^\s+// if ( $vfile );
			
			if ( ( ! $vfile )  ||  ( ! -f $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					print "vfile = $vfile\n";
					next;	
				}

			my $original_vname = $virus;
			$virus = &CleanVirusName( $virus );
			next if ( ! defined $virus );


			# Did I find everything?
			if ( ( ! $vfile )  ||  ( ! $virus ) )
				{	print( "Unable to parse the virus file from this line: $line\n" );
					next;
				}
				
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
	
			$filelist{ $vfile } = $virus;
			$original_vname{ $vfile } = &CleanVName( $original_vname );
			

			print "$vfile is infected with $virus\n" if ( $opt_verbose );
			$virus_count++;
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Avast log file $filename\n";
	print "Found $virus_count virus infected files from Avast log file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub Clam( $ )
#
#	Given a Clam log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading Clam text file $filename ...\n";

	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
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
			
			next if ( ! ( $line =~ m/ FOUND$/ ) );
			
			$line =~ s/ FOUND$//;
			
			my ( $vfile, $virus ) = split /\: /, $line, 2;
			
			next if ( ! $vfile );
			next if ( ! $virus );
			
			$virus =~ s/FOUND//g;
			next if ( ! $virus );
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Clam text file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub ClamScan( $ )
#
#	Given a ClamScan log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading ClamScan log file $filename ...\n";

	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
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
						
			my ( $vfile, $virus ) = split /\: /, $line, 2;
			
			next if ( ! $vfile );
			next if ( ! $virus );
			
			# A clam virus infected line ends with the word 'FOUND'
			next if ( ! ( $virus =~ m/FOUND$/ ) );
			
			$virus =~ s/FOUND//g;
			next if ( ! $virus );
			
			$vfile =~ s/  Infection//g;
			next if ( ! $vfile );
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from ClamScan log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub DrWeb( $ )
#
#	Given a Dr. Web log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading Dr. Web log file $filename ...\n";

	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
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
						
			my ( $vfile, $virus ) = split / infected with /, $line, 2;
			
			next if ( ! $vfile );
			next if ( ! $virus );
			
			# Clean up any extra stuff
			$virus =~ s/modification of //gi;
			$vfile =~ s/^\>+//;		# Sometimes the Dr. Web line starts with > or >> - I don't know why
			
			$vfile =~ s/^\s+//;
			next if ( ! $vfile );
			
			$vfile =~ s/\s+$//;
			next if ( ! $vfile );
			
			$virus =~ s/^\s+//;
			next if ( ! $virus );
			
			$virus =~ s/\s+$//;
			next if ( ! $virus );

			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );

			# Check to see if I can find the file.  If not, it may be an expanded mail file or an archive or something
			while ( ( $vfile )  &&  ( ! -f $vfile ) )
				{	$vfile = &Trim( $vfile );
				}

			if ( ( ! $vfile )  ||  ( ! -f $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}

			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Dr. Web log file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub Windefender( $ )
#
#	Given a Windefender log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading Windows Defender text file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
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
			
			next if ( $line =~ m/^file\:/ );

			my ( $drive, $path ) = split /\:/, $line, 2;
			next if ( ! $path );
			next if ( length( $drive ) != 1 );
			
			my ( $vfile, $junk ) = split /\-\>/, $line, 2;

			next if ( ! $vfile );
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			next if ( ( ! -e $vfile )  &&  ( ! $opt_test ) );
			
			my @parts = split /\\/, $vfile;

			my $domain = $parts[ 4 ] if ( $parts[ 5 ] );
			$domain = $parts[ 3 ] if ( ! $domain );
			$domain = $parts[ 2 ] if ( ! $domain );
			
			next if ( ! $domain );
			
			my ( $dir, $short ) = &SplitFileName( $vfile );
			
			my $virus = $domain . "." . $short;
			
			my $type = &VirusTypeName( $virus );
			
			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = "Spyware." . $domain . "." . $short if ( ! $type );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );	
	
	print "Read $linecount lines from Windowns Defender text file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub WindefenderLog( $ )
#
#	Given a Windefender log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading Windows Defender log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $virus;
	my $original_vname;
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );

			# Get rid of \x00
			$line =~ s/\x00//g;
			
			# Trim off leading and trailing whitespace
			$line =~ s/^\s+//;
			next if ( ! $line );
			
			$line =~ s/\s+$//;
			next if ( ! $line );
			
			# Is line this telling me the current threat name?
			if ( $line =~ m/Threat Name/ )
				{	$virus = $line;
					$virus =~ s/^Threat Name//;
					$virus =~ s/^\s+\:\s+//;
					$virus =~ s/^\:+//;
					$virus =~ s/^\s+//;
					
					$original_vname = $virus;

					$virus = &CleanVirusName( $virus );
				
					$virus = "Spyware." . $virus if ( ( $virus )  &&  ( ! ( $virus =~ m/spyware/i ) ) );
				}
			
			# Is this line telling me the current threat path?	
			if ( $line =~ m/^Resource Path/ )
				{	next if ( ! $virus );
					
					my $vfile = $line;
					$vfile =~ s/^Resource Path//;
					$vfile =~ s/^\s+//;
					$vfile =~ s/^\://;
					$vfile =~ s/^\s+//;
					my $junk;
					( $vfile, $junk ) = split /->/, $vfile, 2 if ( $vfile );
					
					next if ( ! $vfile );
				
					# Trim off leading and trailing whitespace
					$vfile =~ s/^\s+//;
					next if ( ! $vfile );
					
					$vfile =~ s/\s+$//;
					next if ( ! $vfile );
			
					# Trim off any trailing \'s
					$vfile =~ s/\\+$// if ( $vfile );
			
					# Make sure the directory is lowercase in the vfile name
					my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
					$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
					$filelist{ $vfile } = $virus;
					$original_vname{ $vfile } = &CleanVName( $original_vname );
					
					print "$vfile is infected with $virus\n" if ( $opt_verbose );
				}
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Windows Defender log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub Kaspersky( $ )
#
#	Given a Kaspersky log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading Kaspersky log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			next if ( $line =~ m/write not supported/ );
			next if ( $line =~ m/can't be disinfected/ );
			next if ( $line =~ m/possible/i );
			next if ( $line =~ m/probably/i );
			next if ( $line =~ m/probable/i );
#			next if ( $line =~ m/possibly/i );

			# A virus can be "detected" or "suspicious"
			my ( $time, $vfile, $virus );
			if ( $line =~ m/detected/ )
				{	my $detected;
					( $time, $vfile, $detected, $virus ) = split /\t/, $line, 4;
					next if ( ! $detected );
					next if ( $detected ne "detected" );

				}
			elsif ( $line =~ m/suspicion/ )
				{	my $suspicious;
					( $time, $vfile, $suspicious, $virus ) = split /\t/, $line, 4;
					next if ( ! $suspicious );
					next if ( $suspicious ne "suspicion" );
				}
			else	# It isn't detected or suspicion
				{	next;
				}
				
			next if ( ! $time );
			next if ( ! $vfile );
			next if ( ! $virus );

			$virus =~ s/not-a-virus\://;
			$virus =~ s/not-virus\://;
			
			my $junk;
			( $vfile, $junk ) = split /\//, $vfile, 2;
			next if ( ! $vfile );
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			# Check to see if I can find the file.  If not, it may be an expanded mail file or an archive or something
			while ( ( $vfile )  &&  ( ! -f $vfile ) )
				{	$vfile = &Trim( $vfile );
				}

			if ( ( ! $vfile )  ||  ( ! -f $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}

			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Kaspersky log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub AVG( $ )
#
#	Given an AVG log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading AVG log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;

			next if ( ! $line );
			
			# Take out the hex 00s
			$line =~ s/\x00//g;
			
			my $virus_found;
			$virus_found = 1 if ( $line =~ m/Virus found/i );
			$virus_found = 1 if ( $line =~ m/Virus identified/i );
			$virus_found = 1 if ( $line =~ m/Trojan horse/i );

			next if ( ! $virus_found );

			my ( $blank, $vfile, $virus, $infected ) = split /\;/, $line, 4;

			next if ( ! $blank );
			last if ( $blank =~ m/"Warnings"/i );
			last if ( $blank =~ m/"Information"/i );
			
			next if ( ! $vfile );
			next if ( ! $virus );
			next if ( ! $infected );

			next if ( ! ( $infected =~ m/Infected/ ) );
			
			
			# Knock off the virus found from the virus name
			$virus =~ s/Virus found //i;
			$virus =~ s/Virus identified //i;
			$virus =~ s/Trojan horse //i;
			
			
			# Trim off any trailing "
			$vfile =~ s/\"+$// if ( $vfile );
			$virus =~ s/\"+$// if ( $virus );
			
			# Trim off any leading "
			$vfile =~ s/^\"+// if ( $vfile );
			$virus =~ s/^\"+// if ( $virus );

			if ( ( $opt_test )  &&  ( ! $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}
				
			if ( ( $opt_test )  &&  ( ! $virus ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}
			
			next if ( ! $vfile );
			next if ( ! $virus );

			# Check to see if I can find the file.  If not, it may be an expanded mail file or an archive or something
			while ( ( ! $opt_test )  &&  ( $vfile )  &&  ( ! -f $vfile ) )
				{	$vfile = &Trim( $vfile );
				}
			
			if ( ! $vfile )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}
				
			if ( ( ! $opt_test )  &&  ( ! -f $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}

			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from AVG log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub MalwareBytes( $ )
#
#	Given a MalwareBytes log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading MalwareBytes log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, , "<:encoding(UTF-16LE)", $filename ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	my $files_infected;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			# Don't look at anything in the log file until I see the line "Files Infected:"
			$files_infected = 1 if ( ( $line =~ m/^Files Infected\:/i ) || ( $line =~ m/^Files Detected\:/i ) );
			
			next if ( ! $files_infected );

		
			# The line must have the phrase "No action taken."
			next if ( ! ( $line =~ m/No action taken\./i ) );
					 
			
			my ( $vfile, $junk ) = split / \(/, $line, 2;
			next if ( ! $vfile );
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );

			# The name of the virus will be inside ()
			next if ( ! ( $line =~ m/\((.*?)\)/ ) );
			my $virus = $1;
			next if ( ! $virus );

			if ( ( ! $vfile )  ||  ( ! -f $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}

			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from MalwareBytes log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub FSecure( $ )
#
#	Given a FSecure log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading F-Secure log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			my $infected;
			$infected = 1 if ( $line =~ m/Infection\:/i );
			$infected = 1 if ( $line =~ m/Spyware\:/i );
			$infected = 1 if ( $line =~ m/Riskware\:/i );

			next if ( ! $infected );
			
			next if ( $line =~ /could be /i );
			next if ( $line =~ m/possible/i );
			next if ( $line =~ m/probably/i );
			next if ( $line =~ m/probable/i );
#			next if ( $line =~ m/possibly/i );
			
			my $vfile;
			my $virus;
			
			if ( $line =~ m/ Suspected infection\: / )
				{	( $vfile, $virus ) = split / Suspected infection\: /, $line, 2;
				}
			elsif ( $line =~ m/Infection\:/i )
				{	( $vfile, $virus ) = split / Infection\: /, $line, 2;
				}
			elsif ( $line =~ m/Spyware\:/i )
				{	( $vfile, $virus ) = split / Spyware\: /, $line, 2;
				}
			elsif ( $line =~ m/Riskware\:/i )
				{	( $vfile, $virus ) = split / Riskware\: /, $line, 2;
				}
				
			next if ( ! $vfile );
			next if ( ! $virus );
	
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			# Check to see if I can find the file.  If not, it may be an expanded mail file or an archive or something
			while ( ( ! $opt_debug )  &&  ( $vfile )  &&  ( ! -f $vfile ) )
				{	$vfile = &Trim( $vfile );
				}

			if ( ( ! $opt_debug )  &&  ( ( ! $vfile )  ||  ( ! -f $vfile ) ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}

			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from F-Secure log file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub McAfee( $ )
#
#	Given a McAfee log filename, return the list of virus infected files to copy
#   Rob M. modified this on 2/11/14 because McAfee changed their log file format
#
################################################################################
{	my $filename = shift;

	print "Reading McAfee log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
	
			# If it is a virus or something the first characters on the line are 'TYPE'
			next if ( ! ( $line =~ m/^TYPE/ ) );
			
			my ( $type, $stuff ) = split /NAME\"/, $line, 2;

			next if ( ! defined $stuff );
			next if ( ! defined $type );
			
			# Clean up the type
			$type =~ s/^TYPE\=\"//;
			$type =~ s/\s+$//;
			$type =~ s/\"$//;
			
			my ( $virus, $more_stuff ) = split /\" PATH=\"/, $stuff, 2;
			
			next if ( ! defined $virus );
			next if ( ! defined $more_stuff );
			
			# Trim off any trailing white space
			$virus =~ s/\s+$//;
			my ( $vfile, $status ) = split /\" STATUS=\"/, $more_stuff, 2;
			
			next if ( ! defined $vfile );
			next if ( ! defined $status );
			
			# Clean off leading and trailing spaces
			$vfile =~ s/\s+$//;
			$vfile =~ s/^\s+// if ( $vfile );
			next if ( ! $vfile );
			
			# Trim off any trailing white space from the status
			$status =~ s/\s+$//;

			# Trim off a trailing " from the status
			$status =~ s/\"$//;
			

			if ( $opt_debug )
				{	print "\ntype = $type\n";			
					print "virus = $virus\n";
					print "vfile = $vfile\n";
					print "status = $status\n";
				}
				
			
			# Ignore the files that McAfee can't handle or is wobbly about
			next if ( $status =~ m/password-protected/i );
			next if ( $status =~ m/is corrupted/i );
			next if ( $status =~ m/could not be opened/i );
			next if ( $status =~ m/possible/i );
			next if ( $status =~ m/probably/i );
			next if ( $status =~ m/probable/i );
			next if ( $status =~ m/possibly/i );
			next if ( $status =~ m/potentially/i );

			# These next two are ones that McAfee hasn't actually positively identified, so we call them a possible
			next if ( $status =~ m/Found trojan or variant/i );
			next if ( $status =~ m/Found virus or variant/i );
			

			# If not debugging, it could be in a zip file
			if ( ! $opt_debug )
				{	my $original_vfile = $vfile;

					while ( ( $vfile )  &&  ( ! -f $vfile ) )
						{	$vfile = &Trim( $vfile );
						}
					
					$vfile = $original_vfile if ( ( ! $vfile )  ||  ( ! -f $vfile ) );
				}
				
				
			# Clean off some weird stuff
			$virus =~ s/possibly a variant of //i;
			$virus =~ s/a variant of //i;
			
			# Add Trojan back on if it was the type, but it was not in the virus name
			$virus = "Trojan." . $virus if ( ( $type =~ m/trojan/i )  &&  ( ! ( $virus =~ m/trojan/i ) ) );
			
			# Add Virus back on if it was on the type, but not in the virus name
			$virus = "Virus." . $virus if ( ( $type =~ m/virus !!!/i )  &&  ( ! ( $virus =~ m/virus/i ) ) );
			
			$original_vname{ $vfile } = &CleanVName( $virus );
			$virus = &CleanVirusName( $virus );
			
			next if ( ! $virus );


			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );			
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from McAfee log file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub Norton( $ )
#
#	Given a Norton log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading Norton log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
	my @data;
	my $counter = 0 + 0;
	my $linecount = 0 + 0;

	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			my ( $time, $feature, $virus, $result, $item_type, $virus_def_version, $product_version, $user_name, $computer_name, $details ) = split /,/, $line, 10;
			
			next if ( ! $time );
			next if ( ! $feature );
			
			next if ( $feature eq "Feature" );	# This gets rid of the second line of the file - which is the field definitions
			next if ( ! $virus );
			next if ( ! $details );
			
			my $original_vname = $virus;
			$virus = &CleanVirusName( $virus );
			
			next if ( ! $virus );
			
			my ( $vfile, $junk ) = split /,/, $details, 2;
			$vfile =~ s/^\"Source: //;
			
			next if ( ! $vfile );

			# Clean up the vfile if the actual virus infected file in found inside of the file on disk
			if ( $details =~ m/inside of / )
				{	my @parts = split /inside of /, $details;
					my $stuff = $parts[ $#parts ];
					( $vfile, $junk ) = split /\]/, $stuff, 2 if ( $stuff );
					
					# Trim off the leading [
					$vfile =~ s/^\[// if ( $vfile );
				}

			# Knock of any - Deleted
			next if ( ! $vfile );
			$vfile =~ s/\- Deleted$//;
			
			# Trim off leading and trailing spaces
			next if ( ! $vfile );
			$vfile =~ s/^\s+//;
			
			next if ( ! $vfile );
			$vfile =~ s/\s+$//;
			
			next if ( ! $vfile );
			
			# Trim off any leading \\?\
			$vfile =~ s#^\\\\\?\\##;
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			$original_vname{ $vfile } = &CleanVName( $original_vname );
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );

			$counter++;
		}
		
	close( LOGFILE );

	print "Read $linecount lines from Norton log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub NortonExport( $ )
#
#	Given a Norton export filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading Norton export file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
			
	my @data;
	my $counter = 0 + 0;
	my $linecount = 0 + 0;

	my $start_line = 0 + 1;
	my $dash_line = 0 + 0;
	my $vname;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			$line =~ s/\x00//g if ( $line );
			
			# Trim off leading and trailing spaces
			$line =~ s/^\s+// if ( $line );			
			$line =~ s/\s+$// if ( $line );
			
			if ( ! $line )
				{	$start_line = 0 + 0;
					$dash_line = 0 + 0;
					next;
				}
			
			next if ( $line =~ m/^1 Browser Cache/i );
			next if ( $line =~ m/^Unresolved Threats/i );
			next if ( $line =~ m/^HKEY_/i );
			next if ( $line =~ m/^c\:\\windows\\/i );
			next if ( $line =~ m/^c\:\\documents/i );
			next if ( $line =~ m/^c\:\\winnt/i );


			# Norton will pick up Internet Explorer sometimes, and other stuff
			if ( $line =~ m/\\Program Files\\/i )
				{	print "Ignoring line $line\n";
					next;
				}
				
			# Norton will pick up Internet Explorer sometimes, and other stuff
			if ( $line =~ m/\\Documents and Settings\\/i )
				{	print "Ignoring line $line\n";
					next;
				}
				
			# Norton will pick up Internet Explorer sometimes, and other stuff
			if ( $line =~ m/C\:\\Windows\\/i )
				{	print "Ignoring line $line\n";
					next;
				}
				
			# Norton will pick up Internet Explorer sometimes, and other stuff
			if ( $line =~ m/\\Program Files\\/i )
				{	print "Ignoring line $line\n";
					next;
				}
				
			$start_line++;
			
			$vname = $line if ( $start_line == 1 );
			
			next if ( ! $vname );
			
			$dash_line = $start_line if ( $line =~ m/------/ );
			
			next if ( ! $dash_line );
			next if ( $start_line <= $dash_line + 1 );
			
			next if ( ! $vname );
			
			my $original_vname = $vname;
			my $virus = &CleanVirusName( $vname );
			
			next if ( ! $virus );
			
			# Ignore anything after "host file entries"
			if ( $line =~ m/host file entries/i )
				{	$start_line = 0 + 0;
					$dash_line = 0 + 0;
					next;
				}
			
			# Any virus line should have "No action taken" or "Infected"
			next if ( ( ! ( $line =~ m/No action taken/i ) )  &&  ( ! ( $line =~ m/Infected/i ) ) );
			
			my ( $vfile, $junk ) = split / - No action/, $line, 2;
			
			# Is this a virus inside of a zip or other type archive?
			# Note: you can get files inside of files inside of files
			if ( $line =~ m/inside of/ )
				{	my ( @parts ) = split /inside of/, $line;
					
					my $stuff = $parts[ $#parts ];
					$stuff =~ m/\[(.*)\]/;
					
					my $str = $1;

					$vfile = $str if ( $str );
					
					$vfile = $1 if ( $1 );
				}
				
			
			next if ( ! $vfile );

			# Trim off leading and trailing spaces
			$vfile =~ s/^\s+// if ( $vfile );			
			$vfile =~ s/\s+$// if ( $vfile );

			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			

			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			$original_vname{ $vfile } = &CleanVName( $original_vname );

			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );

			$counter++;
		}

	close( LOGFILE );

	print "Read $linecount lines from Norton export file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub Trend( $ )
#
#	Given a Trend log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;

	print "Reading Trend Micro log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );

			my @parts = split /\|/, $line;

			my $virus = $parts[ 6 ];			
			next if ( ! defined $virus );
			my $vfile = $parts[ 7 ];
			next if ( ! defined $vfile );
			
			# Convert from Unicode
			$virus =~ s/\x00//g;
			$vfile =~ s/\x00//g;
			
			next if ( $virus eq "" );
			next if ( $vfile eq "" );
			
			my $original_vname = $virus;
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Sometimes Trend puts the actual filename inside parenthesis
			if ( $vfile =~ m/\((.+)\)/ )
				{	my $inside_parenthesis = $1;
					$vfile = $inside_parenthesis if ( defined $inside_parenthesis );
				}
				
			if ( ( ! $opt_debug )  &&  ( ! -e $vfile ) )
				{	print "Unable to find the file from this line: $line\n";
					next;
				}
				
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			$original_vname{ $vfile } = &CleanVName( $original_vname );
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Trend Micro log file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub PCCillin( $ )
#
#	Given a PCCillan stype Trend log filename, return the list of virus infected files to copy
#   PCCillin is the old name of Trend Micros product
#
################################################################################
{	my $filename = shift;

	print "Reading Trend Micro PC-Clillin log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );

			# Get rid of \x00
			$line =~ s/\x00//g;
			
			# Trim off leading and trailing whitespace
			$line =~ s/^\s+//;
			next if ( ! $line );
			
			$line =~ s/\s+$//;
			next if ( ! $line );
			
			my @parts = split /\|/, $line;
			my $virus = $parts[ 6 ];
			my $vfile = $parts[ 7 ];			

			next if ( $virus eq "---" );
			
			my $original_vname = $virus;
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# The vfile name is wrapped with quotes
			$vfile =~ s/^\"//;
			$vfile =~ s/\"$//;
			
			# If the vfile name doesn't have a drive letter and a colon, then it is an enclosed file
			if ( ! ( $vfile =~ m/^.\:/ ) )
				{	
					$vfile =~ m/\((.*)\)/;
					
					my $str = $1;
					$vfile = $str if ( $str );
				}
			
			# Sometimes Trend puts another copy of the filename in paranthesis
			my $junk;
			( $vfile, $junk ) = split /\(/, $vfile, 2;
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			if ( ! -e $vfile )
				{	print "Unable to find the file from this line: $line\n";
					next;
				}
				
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			$original_vname{ $vfile } = &CleanVName( $original_vname );
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Trend Micro PC-Cillin log file $filename\n";

	return( %filelist );
}



################################################################################
# 
sub Sophos( $ )
#
#	Given a Sophos log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading Sophos log file $filename ...\n";

	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
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
			
			# Make sure the line starts with a >>> Virus
			next if ( ! ( $line =~ m/^>>> Virus / ) );
			
			$line =~ s/^>>> Virus fragment \'//;
			$line =~ s/^>>> Virus \'//;
			
			# Also has to have a found in file
			next if ( ! ( $line =~ m/\' found in file / ) );
			
			my ( $virus, $vfile ) = split /\' found in file /, $line, 2;
			
			next if ( ! $vfile );
			next if ( ! $virus );
			
			# Sometimes Sophos appends a \FILE:0000 or something to the file name
			my $junk;
			( $vfile, $junk ) = split /\\FILE:/, $vfile, 2;
			next if ( ! $vfile );
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			# Then sometimes Sophos expands out archives and self extracting .exes
			while ( ( $vfile )  &&  ( ! -f $vfile ) )
				{	$vfile = &Trim( $vfile );
					last if ( ! $vfile );
					last if ( -d $vfile );
				}

			if ( ( ! $vfile )  ||  ( ! -f $vfile ) )
				{	print "Can't find the virus from this line: $line\n";
					next;	
				}

			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Sophos log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub SA( $ )
#
#	Given a SA log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading Security Agent log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
							
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			print "line: $line\n" if ( $opt_verbose );
			
			# Trim off leading and trailing whitespace
			$line =~ s/^\s+//;
			next if ( ! $line );
			
			$line =~ s/\s+$//;
			next if ( ! $line );
			
			next if ( ! ( $line =~ m/: Infection\: / ) );
			
			$line =~ s/ FOUND$//;
			
			my ( $vfile, $comment ) = split /: Infection\: /, $line, 2;
			
			next if ( ! $vfile );
			next if ( ! $comment );
			
			my ( $virus, $action ) = split /\: /, $comment;
			next if ( ! $virus );
			next if ( ! $action );
			
			$virus = &CleanVirusName( $virus );
			next if ( ! $virus );
			
			# Trim off any IDL or MD5
			$virus =~ s/\.IDL$//i;
			$virus =~ s/\.MD5$//i;
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
			
			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			# In this special case for the Security Agent, the original name and the virus name are exactly the same
			$original_vname{ $vfile } = $virus;
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from Security Agent log file $filename\n";
	
	return( %filelist );
}



################################################################################
# 
sub NOD32( $ )
#
#	Given a NOD32 log filename, return the list of virus infected files to copy
#
################################################################################
{	my $filename = shift;
	
	print "Reading NOD32 log file $filename ...\n";
	
	my %filelist = ();
	
	if ( ! open( LOGFILE, "<$filename" ) )
		{	print "Unable to open file $filename: $!\n";
			exit( 0 + 12 );
		}
	
	my $linecount = 0 + 0;
	
	while ( my $line = <LOGFILE> )									 
		{	chomp( $line );
			$linecount++;
			
			next if ( ! $line );
			
			next if ( $line =~ m/possible/i );
#			next if ( $line =~ m/possibly/i );
			next if ( $line =~ m/probable/i );
			next if ( $line =~ m/probably/i );
			
			# Trim off leading and trailing whitespace
			$line =~ s/^\s+//;
			next if ( ! $line );
			
			$line =~ s/\s+$//;
			next if ( ! $line );

			my @line_parts = split /\, /, $line;
			
			my %line;
			foreach ( @line_parts )
				{	my $line_part = $_;
					next if ( ! $line_part );
					
					my ( $type, $value ) = split /\=/, $line_part, 2;
					
					next if ( ! $type );
					next if ( ! $value );
					
					$value =~ s/^\"//;
					$value =~ s/\"$// if ( $value );
					next if ( ! $value );
					
					$line{ $type } = $value;
				}
				
			
			my $vfile = $line{ "name" };
			my $virus = $line{ "threat" };
			
			next if ( ! $vfile );
			next if ( ! $virus );
			
			# Trim off stuff past »
			my $junk;
			( $vfile, $junk ) = split /\»/, $vfile, 2;
			
			# Trim off leading and trailing whitespace from vfile
			$vfile =~ s/^\s+//;
			next if ( ! $vfile );
			
			$vfile =~ s/\s+$//;
			next if ( ! $vfile );
			
			# Trim off any trailing \'s
			$vfile =~ s/\\+$// if ( $vfile );
						
			next if ( ! $virus );
			next if ( $virus =~ m/^is OK/i );

			# Trim off leading and trailing whitespace from virus
			$virus =~ s/^\s+//;
			next if ( ! $virus );
			
			$virus =~ s/\s+$//;
			next if ( ! $virus );
			
			$virus =~ s/ virus$//				if ( $virus );
			$virus =~ s/ worm$//				if ( $virus );
			$virus =~ s/ trojan$//				if ( $virus );
			$virus =~ s/ adware$//				if ( $virus );
			$virus =~ s/ dialer$//				if ( $virus );
			$virus =~ s/ downloader$//			if ( $virus );
			$virus =~ s/ application$//			if ( $virus );
			$virus =~ s/ backdoor$//			if ( $virus );
			$virus =~ s/ security risk$//		if ( $virus );
			$virus =~ s/ destructive$//			if ( $virus );
			$virus =~ s/ password stealer$//	if ( $virus );

			$virus =~ s/\s+$// if ( $virus );
			next if ( ! $virus );
			
			# See if the file exists
			if ( ( ! $opt_check  )  &&  ( ! -e $vfile )  &&  ( ! $opt_debug ) )
				{	print "Unable to find the file from this line: $line\n";
					next;
				}
						
			next if ( ! $virus );
			
			$original_vname{ $vfile } = &CleanVName( $virus );
			
			$virus = &CleanVirusName( $virus );
			
			next if ( ! $virus );

			# Make sure the directory is lowercase in the vfile name
			my ( $vdir, $shortfile ) = &SplitFileName( $vfile );
			$vfile = lc( $vdir ) . "\\$shortfile" if ( defined $vdir );
			
			$filelist{ $vfile } = $virus;
			
			print "$vfile is infected with $virus\n" if ( $opt_verbose );
		}
		
	close( LOGFILE );									 

	print "Read $linecount lines from NOD32 log file $filename\n";

	return( %filelist );
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
sub Trim($)
#  Given a path, trim off a level.  Return undef if down to nothing
################################################################################
{	my $path = shift;
	
	return( undef ) if ( ! $path );
	
	# Get rid of repeated \\
	$path =~ s/\\\\/\\/g;
   my  @parts = split /\\/, $path;
   my  $i;
   my  $trim;

   #  Return undef if down to the last parts
   return( undef ) if ( $#parts < 1 );
   
   for ( $i = 0;  $i < $#parts;  $i++ )
      {  if ( defined $trim )  {  $trim = $trim . "\\" . $parts[ $i ];  }
         else  {  $trim = $parts[ $i ];  }
      }

	return( undef ) if ( ! $trim =~ m/\\/ );
    return( $trim );
}



################################################################################
#
sub ProgramDatabase( $$$$ )
#
#  Insert or update the data into the Program database
#
################################################################################
{	my $vfile			= shift;
	my $log_company		= shift;
	my $virus			= shift;
	my $original_vname	= shift;
	

	return( undef ) if ( ! $vfile );
	return( undef ) if ( ! $log_company );
	return( undef ) if ( ! defined $virus );
	
	$original_vname = $virus if ( ! $original_vname );
	
	return( undef ) if ( ! -f $vfile );

	
	my ( $dir, $short_file ) = &SplitFileName( $vfile );
	$dir = lc( $dir );
	

	# Get all the file info that I can
	my %file_info;
	my @sections;
	my $ok = &FileInfo( $vfile, \%file_info, \@sections, $opt_verbose );	
	return( undef ) if ( ! $ok );
	

	my $file_id = $file_info{ FileID };
	
	# If no file id, bag it
	if ( ! $file_id )
		{	print "$vfile does not have a file ID\n" if ( $opt_verbose );
			return( undef );
		}
		
		
	# If not a Win32/Win64 file then don't add it to the database	
	my $scan_fileid_type = $file_info{ ScanableFileID };
	return( undef ) if ( ! $scan_fileid_type );
	return( undef ) if ( $scan_fileid_type != 1 );
	
	
	my $hex_file_id = $file_info{ HexFileID };
	
	if ( $opt_verbose )
		{	print "File: $vfile\n";		
			print "File ID: $hex_file_id\n";
		}
		
	my $type = &VirusTypeName( $virus );
	
	
	# Set the virus info into the file info hash
	$file_info{ VirusType } = $type;
	$file_info{ Virus }		= $virus;
	$file_info{ AppName }	= $virus;

	# Set the right category number for this type of virus
	my $category_num = VirusGuessCategory( $vfile, 0 + 63, $virus );
	$file_info{ CategoryNumber } = $category_num;
	
	
	# Add this into the FileIDVirus table
	&UpdateFileIDVirus( $hex_file_id, $log_company, $original_vname, $type );
	
	
	# Does this file ID already exist in the Programs table in the Program database?
	# And does it have a virus style filename?
	my $sth;
	$sth = $dbhProgram->prepare( "SELECT Filename, AppName FROM Programs WITH(NOLOCK) WHERE FileID = ?" );
			
	$sth->bind_param( 1, $hex_file_id,  DBI::SQL_VARCHAR );
	$sth->execute();
	my $rows = 0 + $sth->rows;
	my ( $db_filename, $db_app_name ) = $sth->fetchrow_array();

	$sth->finish();
	
	
	# Should I overwrite the current data in the Program database?
	# If it already exists, and the filename hasn't changed, and I'm not overwriting, quit here
	return( undef ) if ( ( $db_filename )  &&  ( lc( $db_filename ) eq lc( $vfile ) )  &&  ( ! $opt_overwrite )  &&  ( ! $opt_program ) );
	
	my $old_archive = 1 if ( ( $db_filename )  &&  ( $db_filename =~ m/^q\:\\virus archive\\/i ) );
	my $new_archive = 1 if ( $vfile =~ m/^q\:\\virus archive\\/i );
	
	# If the old name is in the virus archive, and the new one isn't, return here
	return( undef ) if ( ( $old_archive )  &&  ( ! $new_archive ) );
	
	# Am I just updating the program information, and the app name hasn't changed?
	return( undef ) if ( ( $opt_program )  &&  ( defined $db_app_name )  &&  ( lc( $virus ) eq lc( $db_app_name ) ) );
	
	# If updating program info and the AppName changed then save the file ID that I changed
	if ( ( $opt_program )  &&  ( $db_app_name ) )
		{	print APPCHANGE "$hex_file_id\n";
			print "Virus $db_app_name changed to $virus\n";
		}
	
	my $hex_md5 = $file_info{ HexMD5 };
	$hex_md5 = "" if ( ! defined $hex_md5 );
	
	my $hex_crc32 = $file_info{ HexCRC32 };
	$hex_crc32 = "" if ( ! defined $hex_crc32 );


	my $source_id = $opt_source_id;
	my $id = 0 + 0;	
	
	my $time_date	= $file_info{ TimeDate };
	$time_date = "" if ( ! defined $time_date );
	my $image_size	= $file_info{ ImageSize };
	$image_size = "" if ( ! defined $image_size );
	my $entry_point	= $file_info{ EntryPoint };
	$entry_point = "" if ( ! defined $entry_point );
	my $code_size	= $file_info{ CodeSize };
	$code_size = "" if ( ! defined $code_size );
	
	
	my $file_version	= $file_info{ FileVersion };
	my $desc			= $file_info{ Description };
	my $company			= $file_info{ Company };
	my $file_size		= $file_info{ FileSize };
	
	# Show I show the info?
	if ( ( $opt_verbose )  ||  ( $opt_program ) )
		{	print "\nAppName: $virus\n";
			print "File: $vfile\n";
			print "File Version: $file_version\n";
			print "File Size; $file_size\n";
			print "MD5: $hex_md5\n";		
			print "CRC32: $hex_crc32\n";		
			print "Description: $desc\n";
			print "Company: $company\n";
			print "Source ID: $source_id\n";
			print "Time Date: $time_date\n";
			print "Image Size: $image_size\n";
			print "Entry Point: $entry_point\n";
			print "Code Size: $code_size\n";
		}
		

	my $ret = &CategoryUpdateFileInfo( \%file_info, \@sections, $rows );
	return( undef ) if ( ! defined $ret );
	
	$add_counter++ if ( $ret > 0 );
	$update_counter++ if ( $ret < 0 );
	

	# If the old archive filename is different than the new one, then delete the old one
	if ( ( ! $opt_program )  &&  
		( ! $opt_leftover )  &&
		( $old_archive )  &&  
		( $new_archive )  &&  
		( lc( $db_filename ) ne lc( $vfile ) ) )
		{	print "Deleting old archive file $db_filename ...\n";
			print "Replacing with new archive file $vfile ...\n";
			unlink( $db_filename );
			$delete_counter++;
		}
		
	
	return;
}



################################################################################
# 
sub UpdateFileIDVirus( $$$$ )
#
#	Put the new information into the database
#   Return 1 if added, undef if an error
#
################################################################################
{	my $hex_file_id	= shift;
	my $company		= shift; 
	my $virus_name	= shift;
	my $virus_type	= shift;
	
	
	return( undef ) if ( ! $hex_file_id );
	return( undef ) if ( ! $virus_name );
	return( undef ) if ( ! $company );
	$virus_type = "Virus" if ( ! defined $virus_type );
	
	my $original_virus_name = $virus_name;
	
	$virus_name			= &quoteurl( $virus_name );
	$virus_name			= &SqlColumnSize( $virus_name, 64 );

	$company			= &quoteurl( $company );
	$company			= &SqlColumnSize( $company, 32 );

	
	# Convert them to values for the insert
	my $vhex_file_id	= "\'" . $hex_file_id . "\'";
	my $vvirus_name	= "\'" . $virus_name . "\'";
	my $vcompany	= "\'" . $company . "\'";
	my $vvirus_type	= "\'" . $virus_type . "\'";

	
	# Show I show the info?
	if ( $opt_verbose )
		{
			print "Antivirus Company: $company\n";			
			print "Virus: $virus_name\n";
		}


	# Does this already exist?
	my $str = "SELECT VirusName, VirusType FROM FileIDVirus WITH(NOLOCK) WHERE FileID = $vhex_file_id AND Company = $vcompany";

	my $sth = $dbhProgram->prepare( $str );

	my $ok = $sth->execute();
	
	my ( $db_virus_name, $db_virus_type ) = $sth->fetchrow_array();	
	
	my $rows = 0 + $sth->rows;

	$sth->finish();
	
	
	# If the virus name already exists, and it is the same in the database, then return here
	# Also make sure the virus type is the same
	if ( ( $db_virus_name )  &&
		( lc( $db_virus_name ) eq lc( $original_virus_name ) )  &&
		( $db_virus_type )  &&
		( lc( $db_virus_type ) eq lc( $virus_type ) ) )
		{	return( undef );
		}
	
		
	# If it already exists in the database, but the virus name is different, then update the virus name here
	if ( $rows )
		{	$str = "UPDATE FileIDVirus SET VirusName = $vvirus_name, VirusType = $vvirus_type WHERE FileID = $vhex_file_id AND Company = $vcompany";
			
			$sth = $dbhProgram->prepare( $str );
			
			$ok = $sth->execute();

			$rows = 0 + $sth->rows;

			print "Error updating the virus name $virus_name in the FileIDVirus table\n" if ( $rows ne 1 );
			
			$sth->finish();
			
			return( undef );
		}
		
		
	# Insert the row into the database
	$str = "INSERT INTO FileIDVirus ( FileID, VirusName, Company, VirusType ) VALUES ( $vhex_file_id, $vvirus_name, $vcompany, $vvirus_type )";

	$sth = $dbhProgram->prepare( $str );
	
	$ok = $sth->execute();

	$rows = 0 + $sth->rows;

	print "Error inserting FileID $hex_file_id into the FileIDVirus table\n" if ( $rows ne 1 );
	
	$sth->finish();
	
	$file_id_virus_counter += $rows;

	return( 0 + 1 ) if ( $ok );
	
	return( undef );
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
	
	# Get rid of leading or trailing :
	$vname =~ s/^\:+// if ( $vname );
	$vname =~ s/\:+$// if ( $vname );

	# Get rid of leading or trailing .
	$vname =~ s/^\.+// if ( $vname );
	$vname =~ s/\.+$// if ( $vname );
	$vname =~ s/\.+/\./ if ( $vname );	# Change repeated ... to .

	$vname =~ s/^\s+// if ( $vname );
	$vname =~ s/\s+$// if ( $vname );
	
	$vname =~ s/^\.+// if ( $vname );
	$vname =~ s/\.+$// if ( $vname );

	return( $vname );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";

Usage: VlogCopy logfile logtype destdir [options]

This utility analyses the logfile, and then copies any discovered virus
infected files to destdir in the Lightspeed Virus Archive format.

It can also move the entire directory structure containing the virus to 
destdir with the -m option.  The -m option does not use Lightspeed Virus
Archive format.

Logtypes are: AdAware, Avast, DrWeb, Clam, ClamScan, F-Prot, F-ProtOld,
F-Secure, Kaspersky, McAfee, NOD32, Norton, NortonExport,
SA (Security Agent), Sophos,TrendMicro, PCCillin, Windefender, AVG, 
MalwareBytes, and Winlog (Windefender Log format)

Possible options are:


  -a, --nosubdir        Copy to the root of the destination directory
  -c, --check MISSING   output the unknown viruses list         
  -d, --delete          delete the virus infected files without copying
  -e, --existing        if set then don\'t copy over existing files
  -l, --leftover DIR    put the list of files that are NOT viruses from DIR
                        into leftover.txt
  -m, --move            move the entire directory with the virus to destdir
  -n, --noprogram       do not update the program database
  -o, --overwrite       overwrite existing program info in the database
  -p, --program         just update the database with the virus info
  -r, --remove          remove the original directory if moving
  -s, --scanable SDIR   copy scanable but non-executable to directory SDIR
                        This is used to separate email files with embedded
                        viruses from virus infected programs.
  -t, --test            show the files to copy, but don\'t actually copy them
  -u, --unlink          delete the source infected file after copying
  -v, --verbose         verbose
  -w, --write VFILE     don't copy the files, but write the list of infected
                        files to VFILE

  -h, --help            print this message and exit

.

exit( 0 + 13 );
}



################################################################################

__END__

:endofperl
