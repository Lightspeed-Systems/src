################################################################################
#!perl -w
#
# Rob McCarthy's MarioCleanup.pl source code
#  Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long();
use Cwd;
use File::Copy;

use Win32API::Registry 0.21 qw( :ALL );


use Content::File;
use Content::Process;
use Content::ScanRegistry;



my $opt_help;
my $opt_debug;
my $opt_verbose;
my $opt_cleanupinit;
my $opt_check_only;



# Global values
my $app_init;					# This is the registry value changed from AppInit by MarioForever
my $muicache;					# This is the registry value added by MarioForever to the MUICache
my $muicache_program;			# This is the actual program added by MarioForever to the MUICache
my $user32_patched;				# This is set to the path of user32.dll in the system32 directory if it has been patched
my $user32_dllcache_patched;	# This is set to the path of user32.dll in the dllcache directory if it has been patched
my $cwd;						# If set this is the current working directory
my $userinit;					# If set then the Userinit registry key has twext in it
		
		
my %dangerous_programs = (
"17c8fd2c40c446a462a10b9254c06b11"	=>	"ldr.exe - Trojan.Spy.Win32.Zbot.Gaq",
"754663cdeead4ca0dd2e1ffcdc1f1924"	=>	"MarioForever.exe - Backdoor.Win32.Agent.Tyj",
"d7e05a0b77e23cc6700459d812fd346c"	=>	"rcrcphyr.exe - Backdoor.Win32.Agent.Tyj",
"0b6382e136401f335b2fc6adddc74c4e"	=>	"MarioForever.bkp - Backdoor.Win32.Agent.Tyj",
"e16d3fb9efe7ed4cb69b6040f10224b5"	=>	"paso.el - Backdoor.Win32.Agent.Tyj",
"707da3a8b362efa100fa11b776eb1c2e"	=>	"res.exe - Trojan.Spy.Tv736.Ad",
"207cd0bf66e872b60b1d3c7f60a80b87"	=>	"twext.exe - Trojan.Spy.Win32.Zbot.Gaq",
"ccd1ed0cb8d4142d03af67b39c02f514"	=>	"cfg.bin - Backdoor.Win32.Agent.Tyj",
"116f53411b079c373e6f6467f3d072e0"	=>	"exe - Trojan.Spy.Win32.Zbot.Glg"
);
		
			
			
################################################################################
#
MAIN:
#
################################################################################
{
	my $options = Getopt::Long::GetOptions
       (
			"c|check"		=> \$opt_check_only,
			"u|userinit"	=> \$opt_cleanupinit,
			"h|help"		=> \$opt_help,
			"v|verbose"		=> \$opt_verbose,
			"x|xxx"			=> \$opt_debug
      );
	   
	   
	&StdHeader( "MarioCleanup" );

	&Usage() if ( $opt_help );


	$cwd = getcwd();
	$cwd =~ s#\/#\\#gm;

	if ( $opt_cleanupinit )
		{	my $reboot = 1 if ( &CleanupUserinit() );
			print "Reboot is required\n" if ( $reboot );
			exit( 0 );
		}

	if ( ! &MarioDetected() )
		{	print "\nThis computer is not infected with the Mario Forever virus\n";
			exit( 0 );
		}

	exit( 0 ) if ( $opt_check_only );
	
	
	my $log_filename = "C:\\MarioCleanup.log";		# The name of the log file to use
	&SetLogFilename( $log_filename, undef );
	
	lprint "\n";
	lprint "Cleaning up after the MarioForver virus ...\n";	

	&MarioCleanup();
	
	chdir( $cwd );
	
	&StdFooter;
	
	exit( 0 );
}



################################################################################
# 
sub MarioDetected()
#
#  Return True if it looks like this machine might be infected with MarioForever
#
################################################################################
{
	my $infected;
	
	print "First checking registry keys ...\n";
	
	my $key;

	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_READ, $key );
	if ( ! $ok )
		{	my $regErr = regLastError();
			print "Unable to open registry value: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows, error: $regErr\n";
		}


	my $uIndex = 0 + 0;
	while ( $ok )
		{	my $osValName;
			my $iolValName;
			my $opValData;
			my $iolValData;
			my $ouType;
			
			$ok = &RegEnumValue( $key, $uIndex, $osValName, $iolValName, [], $ouType, $opValData, $iolValData );
			
			$uIndex++;

			if ( ( $opValData )  &&  ( $opValData =~ m/nvaux/i ) )
				{	$infected = 1;
					
					print "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\$osValName is set to $opValData\n";
				
					$app_init = $osValName;
				}
		}
		
	&RegCloseKey( $key );
	$key = undef;


	my $homedrive = $ENV{ HOMEDRIVE };
	$homedrive = "C:" if ( ! defined $homedrive );

	$ok = &RegOpenKeyEx( HKEY_USERS, ".DEFAULT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache", 0, KEY_READ, $key );
	if ( ! $ok )
		{	my $regErr = regLastError();
			print "Unable to open registry value: HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache, error: $regErr\n";
		}

	$uIndex = 0 + 0;
	while ( $ok )
		{	my $osValName;
			my $iolValName;
			my $opValData;
			my $iolValData;
			my $ouType;
			
			$ok = &RegEnumValue( $key, $uIndex, $osValName, $iolValName, [], $ouType, $opValData, $iolValData );
			
			$uIndex++;
			
			# I am looking for a program being run in the Windows\Temp directory
			if ( ( $osValName )  &&  ( $osValName =~ m/\.exe$/i )  &&  ( $osValName =~ m/\\Windows\\Temp\\/i )  &&  ( $osValName =~ m/^$homedrive/i ) )
				{	$infected = 1;
					
					print "HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache\\$osValName is set to $opValData\n";
				
					$muicache = $osValName;
					$muicache_program = $osValName;
				}
				
			# It is possible the program is being run from the \Local Settings\Temp directory
			if ( ( $osValName )  &&  ( $osValName =~ m/\.exe$/i )  &&  ( $osValName =~ m/\\Local Settings\\Temp\\/i )  &&  ( $osValName =~ m/^$homedrive/i ) )
				{	$infected = 1;
					
					print "HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache\\$osValName is set to $opValData\n";
				
					$muicache = $osValName;
					$muicache_program = $osValName;
				}
		}
		
	&RegCloseKey( $key ) if ( defined $key );
	$key = undef;
	
	
	# Has twext been added to the Userinit registry key?
	$ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, $key );
	if ( ! $ok )
		{	my $regErr = regLastError();
			print "Unable to open registry value: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon, error: $regErr\n";
		}

	my $type;
	my $data;
	$ok = RegQueryValueEx( $key, "Userinit", [], $type, $data, [] ) if ( $ok );
	
	if ( ( $data )  &&  ( $data =~ m/twext/i ) )
		{	$infected = 1;
			
			print "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit is set to $data\n";

			$userinit = 1;
		}
		
	&RegCloseKey( $key ) if ( defined $key );
	$key = undef;


	print "OK so far ...\n" if ( ! $infected );
	print "Now checking for the actual virus files ...\n";
	
	my $system_root = $ENV{ SystemRoot };
	$system_root = "C:\\Windows" if ( ! defined $system_root );
	
	
	# Is the MarioForver on the root drive?
	my $path = "$homedrive\\MarioForever.exe";
	
	my ( $dir, $shortfile ) = &SplitFileName( $path );
	my $running = &ProcessRunningName( $shortfile );

	if ( $running )
		{	$infected = 1;
			
			print "$shortfile is running\n";
		}
		
		
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			
			print "Found $path - Infected\n";
		}


	$path = "$system_root\\system32\\cls.exe";
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path - Infected\n";
		}

	$path = "$system_root\\TEMP\\cls.exe";
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path - Infected\n";
		}


	print "Checking shared folders ...\n";
	my @shared_folders = &SharedFolders();
	foreach ( @shared_folders )
		{	my $folder = $_;
			next if ( ! defined $folder );
			
			print "Checking directory $folder for MarioForever.exe ...\n";
			
			$path = "$folder\\MarioForever.exe";
			
			if ( &CheckFile( $path, undef ) )
				{	$infected = 1;
					
					print "Found $path - Infected\n";
				}
		}
		

	# Is nvaux32.dll in system32?
	$path = "$system_root\\system32\\nvaux32.dll";
	
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path - Infected\n";
		}
	

	# Is the weird process on disk?
	if ( ( defined $muicache_program )  &&  ( &CheckFile( $muicache_program, undef ) ) )
		{	$infected = 1;
			
			print "Found $muicache_program - Infected\n";
		}
	

	# Check to see if some process has twext.exe open
	$path = "$system_root\\system32\\twext.exe";
	
	( $dir, $shortfile ) = &SplitFileName( $path );
	$running = &ProcessRunningName( $shortfile );

	if ( $running )
		{	$infected = 1;
			
			print "$shortfile is running\n";
		}
		
	# Check to see if twext.exe exists
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			
			print "Found $path\n";
			
			my ( $in_use, @pids ) = &ProcessFileInUse( $path );

			if ( $in_use )
				{	foreach( @pids )
						{	my $pid = $_;
							next if ( ! $pid );
							
							my $process_name = &ProcessPIDName( $pid );
							
							print "Process $process_name has $path in use!\n";
						}
				}
		}


	# Check to see if some process has twext.exe open
	$path = "$system_root\\TEMP\\twext.exe";
	
	# Check to see if twext.exe exists
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			
			print "Found $path\n";
			
			my ( $in_use, @pids ) = &ProcessFileInUse( $path );

			if ( $in_use )
				{	foreach( @pids )
						{	my $pid = $_;
							next if ( ! $pid );
							
							my $process_name = &ProcessPIDName( $pid );
							
							print "Process $process_name has $path in use!\n";
						}
				}
		}
		
		
	$path = "$system_root\\system32\\paso.el";
	
	( $dir, $shortfile ) = &SplitFileName( $path );
	$running = &ProcessRunningName( $shortfile );

	if ( $running )
		{	$infected = 1;
			print "$shortfile is running\n";
		}
		
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path\n";
		}

	$path = "$system_root\\TEMP\\paso.el";	
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;	
			print "Found $path\n";
		}


	$path = "$system_root\\system32\\ldr.exe";

	( $dir, $shortfile ) = &SplitFileName( $path );
	$running = &ProcessRunningName( $shortfile );

	if ( $running )
		{	$infected = 1;
			print "$shortfile is running\n";
		}
		
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path\n";
		}

	$path = "$system_root\\TEMP\\ldr.exe";
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path\n";
		}


	$path = "$system_root\\system32\\res.exe";

	( $dir, $shortfile ) = &SplitFileName( $path );
	$running = &ProcessRunningName( $shortfile );

	if ( $running )
		{	$infected = 1;
			print "$shortfile is running\n";
		}
		
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path\n";
		}

	$path = "$system_root\\TEMP\\res.exe";
	if ( &CheckFile( $path, undef ) )
		{	$infected = 1;
			print "Found $path\n";
		}


	$path = "$system_root\\system32\\user32.dll";
	
	print "OK so far ...\n" if ( ! $infected );
	print "Now checking to see if $path has been patched ...\n";
	
	
	if ( ! -f $path )
		{	print "Can not find $path\n";
		}
	else
		{	if ( ! open( USER32, "<$path" ) )
				{	print "Error opening $path: $!\n";
				}
			else
				{	binmode( USER32 );
					
					# Read 
					my $read_size = 12 * 1024;
					my $buf;
					my $nbytes = sysread( USER32, $buf, $read_size, 0 );
				
					close( USER32 );
					
					# Do I see an altered user32.dll?
					my $pInit_DLLs_match = 1 if ( $buf =~ m/\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/ );		
					my $AppInit_DLLs_match = 1 if ( $buf =~ m/\x41\x00\x70\x00\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/ );
	
					if ( ( $pInit_DLLs_match )  && ( ! $AppInit_DLLs_match ) )
						{	$infected = 1;
							print "$path has been patched by a virus!\n";
							$user32_patched = $path;
						}
					else
						{	print "$path is OK\n";
						}
				}
		}
	
	
	# Look in the dllcache as well
	$path = "$system_root\\system32\\dllcache\\user32.dll";
	
	print "OK so far ...\n" if ( ! $infected );
	print "Now checking to see if $path has been patched ...\n";
	
	
	if ( ! -f $path )
		{	print "user32.dll is not in the dllcache - OK\n";
		}
	else
		{	if ( ! open( USER32, "<$path" ) )
				{	print "Error opening $path: $!\n";
				}
			else
				{	binmode( USER32 );
					
					# Read 
					my $read_size = 12 * 1024;
					my $buf;
					my $nbytes = sysread( USER32, $buf, $read_size, 0 );
				
					close( USER32 );
					
					# Do I see an altered user32.dll?
					my $pInit_DLLs_match = 1 if ( $buf =~ m/\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/ );		
					my $AppInit_DLLs_match = 1 if ( $buf =~ m/\x41\x00\x70\x00\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/ );
	
					if ( ( $pInit_DLLs_match )  && ( ! $AppInit_DLLs_match ) )
						{	$infected = 1;
							print "$path has been patched by a virus!\n";
							$user32_dllcache_patched = $path;
						}
					else
						{	print "$path is OK\n";
						}
				}
		}
	

	# If not infected - check the autoruns
	if ( ! $infected )
		{	my ( @ret ) = &ScanRegistryAutoruns();
	
			# Unpack out the return from ScanRegistryAutoruns function
			print "Checking registry autoruns ...\n";
			foreach ( @ret )
				{	next if ( ! $_ );
					my ( $key, $val, $file ) = split /\t/, $_, 3;
					
					if ( &CheckFile( $file, undef ) )
						{	$infected = 1;
							print "Found $path is infected\n";
						}
				}
		}
	
	
	# Check the startup folders
	my @startup_folders = &StartupFolders();
	foreach ( @startup_folders )
		{	my $folder = $_;
			
			print "Checking startup folder $folder ...\n";
			if ( &CheckDir( $folder, undef ) )
				{	$infected = 1;
					print "Directory $folder has infected files\n";
				}
		}
	
	print "Found at least some parts of the Mario Forever virus!\n" if ( $infected );

	return( $infected );
}



################################################################################
# 
sub MarioCleanup()
#
#	Clean up everything from a MarioForever infection
#
################################################################################
{	my $reboot;  # Set this to True if I need to reboot


	# Rename the MarioForver program if it exists
	my $homedrive = $ENV{ HOMEDRIVE };
	$homedrive = "C:" if ( ! defined $homedrive );
	
	my $path = "$homedrive\\MarioForever.exe";
	$reboot = 1 if ( &CheckFile( $path, 1 ) );
	
	
	lprint "Checking shared folders ...\n";
	my @shared_folders = &SharedFolders();
	foreach ( @shared_folders )
		{	my $folder = $_;
			next if ( ! defined $folder );
			
			$path = "$folder\\MarioForever.exe";
			&CheckFile( $path, 1 );
		}
	
	
	# Rename the muicache program if it exists
	if ( ( $muicache_program )  &&  ( -f $muicache_program ) )
		{	$reboot = 1 if ( &CheckFile( $muicache_program, 1 ) );
		}
		
	
	# Is nvaux32.dll in system32?
	my $system_root = $ENV{ SystemRoot };
	$system_root = "C:\\Windows" if ( ! defined $system_root );
	
	$path = "$system_root\\system32\\nvaux32.dll";
	
	if ( -f $path )
		{	my $new_name = $path . ".infected";
			lprint "Renaming $path to $new_name ...\n";
			unlink( $new_name );
			my $ok = rename( $path, $new_name );
			
			if ( $ok )
				{	lprint "Renamed OK\n";
					$ok = unlink( $new_name );
					lprint "Unable to delete $new_name: $!\n" if ( ! $ok );
				}
			else
				{	lprint "Error renaming: $!\n";
				}	
				
			# Always reboot if I find this installed
			$reboot = 1;	
		}
	
	
	# Do I need to cleanup the Userinit registry key?
	if ( $userinit )
		{	$reboot = 1 if ( &CleanupUserinit() );
		}
			
	
	# Is the weird twext.exe program there?
	$path = "$system_root\\system32\\twext.exe";
	$reboot = 1 if ( &CheckFile( $path, 1 ) );
	$path = "$system_root\\TEMP\\twext.exe";
	$reboot = 1 if ( &CheckFile( $path, 1 ) );
	
	
	# Is the weird paso.el program there?
	$path = "$system_root\\system32\\paso.el";
	$reboot = 1 if ( &CheckFile( $path, 1 ) );
	$path = "$system_root\\TEMP\\paso.el";
	$reboot = 1 if ( &CheckFile( $path, 1 ) );
	
	
	# Is the weird cls.exe program there?
	$path = "$system_root\\system32\\cls.exe";
	$reboot = 1 if ( &CheckFile( $path, 1 ) );
	$path = "$system_root\\TEMP\\cls.exe";
	$reboot = 1 if ( &CheckFile( $path, 1 ) );
	
	
	$path = "$system_root\\system32\\ldr.exe";
	&CheckFile( $path, 1 );
	$path = "$system_root\\TEMP\\ldr.exe";
	&CheckFile( $path, 1 );


	$path = "$system_root\\system32\\res.exe";
	&CheckFile( $path, 1 );
	$path = "$system_root\\TEMP\\res.exe";
	&CheckFile( $path, 1 );
	

	# Fix the patched user32.dll from %systemroot%\system32 directory
	if ( $user32_patched )
		{	my $patched = &User32Patched( $user32_patched );
			$reboot = 1 if ( $patched );
		}
		
	
	# Fix the patched user32.dll in the dllcache	
	if ( $user32_dllcache_patched )
		{	my $patched = &User32Patched( $user32_dllcache_patched );
			$reboot = 1 if ( $patched );
		}
		
		
	&CheckIEContent();
		
	
	# Get rid of any suspcious files in \Windows\TEMP
	$path = "$system_root\\TEMP";
	lprint "Renaming and deleting any suspicious programs in $path ...\n";
	chdir( $path );
	system "rename *.exe *.exe.infected";
	system "del \"$path\\*.exe.infected\"";
	
	chdir( $cwd ) if ( defined $cwd );
	
	# Get rid of any suspicious files in the Local Settings\Temp directories
	&CleanupLocalSettings();
	
	
	# Remove any registry keys that are affected
	if ( $app_init )
		{	my $key;
			
			my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_ALL_ACCESS, $key );
			
			# Set this to blank	
			$ok = &RegSetValueEx( $key, $app_init, 0,  REG_SZ, "" ) if ( $ok );

			&RegCloseKey( $key ) if ( $ok );
			
			if ( ! $ok )
				{	my $regErr = regLastError();
					lprint "Unable to delete registry value: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\$app_init, error: $regErr\n";
				}
			else
				{	lprint "Deleted registry value: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\$app_init\n";
				}
		}


	if ( $muicache )
		{	my $key;
			
			my $ok = &RegOpenKeyEx( HKEY_USERS, ".DEFAULT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache", 0, KEY_ALL_ACCESS, $key );
			$ok = &RegDeleteValue( $key, $muicache ) if ( $ok );
			&RegCloseKey( $key ) if ( $ok );
			
			if ( ! $ok )
				{	my $regErr = regLastError();
					lprint "Unable to delete registry value: HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache\\$muicache, error: $regErr\n";
				}
			else
				{	lprint "Deleted registry value: HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache\\$muicache\n";
				}
		}


	# Disinfect any autoruns
	my ( @ret ) = &ScanRegistryAutoruns();
	
	# Unpack out the return from ScanRegistryAutoruns function
	foreach ( @ret )
		{	next if ( ! $_ );
			my ( $key, $val, $file ) = split /\t/, $_, 3;
			
			&CheckFile( $file, 1 );
		}


	# Disinfect any startup folders
	my @startup_folders = &StartupFolders();
	foreach ( @startup_folders )
		{	my $folder = $_;
			&CheckDir( $folder, 1 );
		}
	


	# Create a dummy service to do nothing ...
	&CreateService();
	
	
	lprint "Disinfect completed OK\n";

	
	if ( $reboot )
		{	lprint "Disinfect requires rebooting (this may not work if Winlogon was killed) ...\n";
			
			my $cmd = "shutdown -t 10 -r";
			
			lprint "Issuing reboot system command: \"$cmd\"\n";
			
			print "Waiting 10 seconds before reboot ...\n";
			sleep( 10 );
			
			&StdFooter;
			
			system $cmd;
			
			# Should never get here
			print "You will have to power off and power back on this PC to finish disinfecting!\n";
			
			exit( 0 );
		}
	else
		{	lprint "No reboot required\n";
		}
		
	return( 1 );
}



################################################################################
# 
sub CheckIEContent()
#
#	Check the Content.IE directory for ldr*.exe
#
################################################################################
{	
	my $homedrive = $ENV{ HOMEDRIVE };
	$homedrive = "C:" if ( ! defined $homedrive );

	my $dir = "$homedrive\\Documents and Settings\\LocalService\\Local Settings\\Temporary Internet Files";
	
	my $ok = chdir( $dir );
	return( undef ) if ( ! $ok );
	
	system "del ldr*.exe /s";
	
	chdir( $cwd ) if ( defined $cwd );
	
	return( 1 );
}



################################################################################
# 
sub User32Patched( $ )
#
#	Clean up user32.dll by patching it back
#
################################################################################
{	my $user32_path = shift;	# This is the full filename of the user32.dll - could be in system32, or the dllcache
	
	lprint "Patching back to a good $user32_path ...\n";
	
	my $new_name = $user32_path . ".infected";
	
	# Rename the current file
	unlink( $new_name );
	my $ok = rename( $user32_path, $new_name );
	if ( ! $ok )
		{	lprint "Error renaming $user32_path to $new_name: $!\n";
			return( undef );
		}
	
	
	$ok = copy( $new_name, $user32_path );
	if ( ! $ok )
		{	lprint "Error copying $new_name to $user32_path: $!\n";
			$ok = rename( $new_name, $user32_path );
			return( undef );
		}

	
	if ( ! open( USER32, "+<$user32_path" ) )
		{	lprint "Error opening $user32_path: $!\n";
			return( undef );
		}
		
		
	binmode( USER32 );
					
	# Read 12 k worth of data - the patched part should be in there
	my $read_size = 12 * 1024;
	my $buf;
	my $nbytes = sysread( USER32, $buf, $read_size, 0 );
				

	if ( ( ! $nbytes )  ||  ( $nbytes != $read_size ) )
		{	close( USER32 );
			
			lprint "Error reading from $user32_path: $!\n";
			return( undef );
		}
		
	
	# Make sure that this still needs to be patched back
	my $pInit_DLLs_match = 1 if ( $buf =~ m/\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/ );

	if ( ! $pInit_DLLs_match )
		{	close( USER32 );
			
			lprint "Error reading pInit_DLLs from $user32_path: $!\n";
			return( undef );
		}
		
	my $AppInit_DLLs_match = 1 if ( $buf =~ m/\x41\x00\x70\x00\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/ );
	
	if ( $AppInit_DLLs_match )
		{	print "$user32_path is not infected!\n";
		}
	else
		{	# make the subsitution for ??pInit_DLLs back to AppInit_DLLs
			$buf =~ s/.\x00.\x00\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/\x41\x00\x70\x00\x70\x00\x49\x00\x6e\x00\x69\x00\x74\x00\x5f\x00\x44\x00\x4c\x00\x4c\x00\x73\x00/;

			sysseek( USER32, 0, 0 );
			
			my $nwrite = syswrite( USER32, $buf, $nbytes );
			
			if ( ( ! $nwrite )  ||  ( $nwrite != $nbytes ) )
				{	close( USER32 );
					
					lprint "Error writing to $user32_path: $!\n";
					return( undef );
				}	
				
			lprint "Restored $user32_path to the original Microsoft values\n";
		}
		
	close( USER32 );
					
	
	# Can I still find user32.dll?
	if ( ! -f $user32_path )
		{	lprint "Can not find $user32_path - copying back the backup file ...\n";
			
			copy( $new_name, $user32_path );
			
			lprint "Copied backup file OK \n" if ( -f $user32_path );
					
			return( undef );
		}
	else
		{	# Delete the new name if I can
			unlink( $new_name );
		}
		
	return( 1 );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
# 
sub CleanupLocalSettings()
#
#	Clean up any programs hanging around in Local Settigs\Temp
#
################################################################################
{	
	my $homedrive = $ENV{ HOMEDRIVE };
	$homedrive = "C:" if ( ! defined $homedrive );

	my $docs_dir = $homedrive . "\\Documents and Settings";
	
	return( undef ) if ( ! opendir( DIRHANDLE, $docs_dir ) );
	
	for my $file ( readdir( DIRHANDLE ) )
		{	# Is it the file current open by the service?
			next if ( ! $file );
				
			next if ( $file eq "." );
			next if ( $file eq ".." );
			
			my $fulldir = "$docs_dir\\$file";	
			
			next if ( ! -d $fulldir );
			
			# Build the path to the temp directory for this user
			my $temp_dir = "$fulldir\\Local Settings\\Temp";
			
			# Does this exist?
			next if ( ! -d $temp_dir );
			
			lprint "Renaming and deleting suspicious files in $temp_dir ...\n";
			
			chdir( $temp_dir );
			
			system "rename *.exe *.exe.infected";
			system "del \"$temp_dir\\*.exe.infected\"";
		}
			
	closedir( DIRHANDLE );

	chdir( $cwd ) if ( defined $cwd );
	
	return( 1 );
}



################################################################################
# 
sub SharedFolders
#
#	Return a array containing the shared folders
#
################################################################################
{
	my $key;

	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\Shares", 0, KEY_READ, $key );

	my @shared_folders;
	
	return( @shared_folders ) if ( ! $ok );
	
	my $uIndex = 0 + 0;
	while ( $ok )
		{	my $osValName;
			my $iolValName;
			my $opValData;
			my $iolValData;
			my $ouType;
			
			$ok = &RegEnumValue( $key, $uIndex, $osValName, $iolValName, [], $ouType, $opValData, $iolValData );
			
			$uIndex++;

			if ( ( $opValData )  &&  ( $opValData =~ m/CSCFlags/i ) )
				{	my @parts = split /\x00/, $opValData;
					
					my $path = $parts[ 2 ];
					next if ( ! defined $path );
					
					next if ( ! ( $path =~ m/^Path\=/ ) );
					
					$path =~ s/^Path\=//;
					next if ( ! $path );
					
					next if ( ! -d $path );
					push @shared_folders, $path;				
				}
		}
		
	&RegCloseKey( $key );
	
	# Add in any network mapped drives
	my @drives = &get_network_drives();
						
	foreach ( @drives )
		{	my $letter = $_;
			push @shared_folders, "$letter:\\" if ( length( $letter ) eq 1 );	# It is a local drive letter
			push @shared_folders, "$letter\\" if ( length( $letter ) gt 1 );	# It is a UNC	return( @shared_folders );
		}
				
	return( @shared_folders );			
}



################################################################################
#
sub get_network_drives( $ )
#
#  Return the drive letter or UNC for local and network drives
#
################################################################################
{
use Win32::DriveInfo;

     my @drives = Win32::DriveInfo::DrivesInUse();
	 my @local_drives;
	 
	 foreach ( @drives )
		{	my $letter = $_;
			my $type = Win32::DriveInfo::DriveType( $letter );

			# Type 3 is a fixed drive
			push @local_drives, $letter if ( $type == 3 );
			
			# Type 4 is a fixed drive
			push @local_drives, $letter if ( $type == 4 );
		}

	return( @local_drives );
}



################################################################################
# 
sub CleanupUserinit
#
#	Remove twext from the userinit registry key
#   Return TRUE if I need to reboot
#
################################################################################
{
	lprint "Cleaning up the userinit registry key ...\n";
	my $key;

	my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_ALL_ACCESS, $key );
	
	return( undef ) if ( ! $ok );
	
	my $type;
	my $data;
	$ok = &RegQueryValueEx( $key, "Userinit", [], $type, $data, [] ) if ( $ok );


	# if I can't read any data then give up
	if ( ! $data )
		{	&RegCloseKey( $key );
			return( undef );
		}
	
	my @parts = split /,/, $data;
	
	my $new_data;
	
	my $reboot;
	
	
	# Filter out any part of Userinit that has a twext in it
	foreach( @parts )
		{	my $part = $_;
			next if ( ! defined $part );
			
			next if ( $part =~ m/twext/ );
			
			$new_data = $new_data . $part . "," if ( defined $new_data );
			$new_data = $part . "," if ( ! defined $new_data );
		}
	
	
	# Do I need to make a change?
	if ( ( $new_data )  &&  ( $new_data ne $data ) )
		{	# In order to change the Userinit key twext.exe has to be dead, and it is loaded as a dll as part of Winlogon
			# In order to kill Winlogon cleanly the smss task has to be killed
			lprint "Killing the twext.exe process ...\n";			
			my $killed = &ProcessKillName( "twext.exe" );
			lprint "Could not find a twext process to kill\n" if ( ! $killed );

			lprint "Killing the ldr.exe process ...\n";			
			$killed = &ProcessKillName( "ldr.exe" );
			lprint "Could not find a ldr process to kill\n" if ( ! $killed );

			lprint "Killing the smss process ...\n";			
			$killed = &ProcessKillName( "smss.exe" );
			lprint "Could not find the smss process to kill\n" if ( ! $killed );
			$reboot = 1 if ( $killed );
			
			lprint "Killing the Winlogon process ...\n";
			$killed = &ProcessKillName( "Winlogon.exe" );
			lprint "Could not find any Winlogon processes to kill\n" if ( ! $killed );
			$reboot = 1 if ( $killed );
			
			# Check to see if some other process has twext.exe open
			my $system_root = $ENV{ SystemRoot };
			$system_root = "C:\\Windows" if ( ! defined $system_root );

			my $path = "$system_root\\system32\\twext.exe";
			
			my ( $in_use, @pids ) = &ProcessFileInUse( $path );

			# Kill any process that has twext.exe in use
			if ( $in_use )
				{	foreach( @pids )
						{	my $pid = $_;
							next if ( ! $pid );
							
							my $process_name = &ProcessPIDName( $pid );
							
							lprint "Killing process $process_name because it has $path in use!\n";
							
							&ProcessTerminate( $pid )
						}
				}
			else
				{	lprint "No other process has $path open\n";
				}
				
			sleep( 1 );
			
			lprint "Changing the Userinit registry from $data to $new_data ...\n";
			$ok = &RegSetValueEx( $key, "Userinit", 0,  $type, $new_data );
			
			if ( ! $ok )
				{	my $regErr = &regLastError();
					lprint "Registry error: $regErr\n";
				}
			
			sleep( 2 );
			
			# Did the change actually happen?
			$ok = RegQueryValueEx( $key, "Userinit", [], $type, $data, [] );
			
			if ( ( $data )  &&  ( $data ne $new_data ) )
				{	lprint "Error - unable to change the Userinit registry key!\n";
				}
			else
				{	$reboot = 1;
				}
		}
	else
		{	lprint "The Userinit registry key does not have twext in it\n";
		}
		
	&RegCloseKey( $key );
	
	return( $reboot );
}



################################################################################
#
sub HexMD5File( $ )
#
#  Given a filename, return the hex MD5 hash, or undef if an error
#
################################################################################
{	my $file = shift;

use Digest::MD5;

	return( undef ) if ( ! $file );
	
	return( undef ) if ( ! -s $file );
					
	open( MD5HANDLE, $file ) or return( undef );
	
	binmode( MD5HANDLE );
	
	my $md5 = Digest::MD5->new;

	$md5->new->addfile( *MD5HANDLE );
	
	my $hex_md5 = $md5->hexdigest;

	close( MD5HANDLE );	
	
	return( $hex_md5 );
}



################################################################################
#
sub CheckFile( $$ )
#
#  Given a filename, check the hex MD5 hash of the dangerous programs, and return
#  True if it is a problem.  If disinfect is TRUE then try to get rid of the
#  file and replace it with a holding file.
#
################################################################################
{	my $filename	= shift;
	my $disinfect	= shift;
	
	print "Checking filename $filename ...\n" if ( $opt_verbose );
	
	return( undef ) if ( ! defined $filename );
	
	if ( ! -f $filename )
		{	print "$filename not found - OK\n" if ( $opt_verbose );
			return( undef );
		}
	
	my $md5_hex = lc( &HexMD5File( $filename ) );
	

	return( undef ) if ( ! defined $md5_hex );

	print "MD5 value $md5_hex\n" if ( $opt_verbose );

	my $original_name = $dangerous_programs{ $md5_hex };

	return( undef ) if ( ! defined $original_name );
	
	# If I just have to identify the program then I can return here
	lprint "$filename is a dangerous program named $original_name\n";
	
	return( 1 ) if ( ! $disinfect );
	
	
	my ( $dir, $shortfile ) = &SplitFileName( $filename );
	my $running = &ProcessRunningName( $shortfile );

	if ( $running )
		{	lprint "$shortfile is currently running\n";
			return( 1 ) if ( ! $disinfect );

			lprint "Killing the running $shortfile now ...\n";
			my $killed = &ProcessKillName( $shortfile );			
			lprint "Killed running process $shortfile\n" if ( $killed );
		}
		
		
	my $new_name = $filename . ".infected";
	lprint "Renaming $filename to $new_name ...\n";
	unlink( $new_name );
	my $ok = rename( $filename, $new_name );
	
	if ( $ok )
		{	lprint "Renamed OK\n";
			$ok = unlink( $new_name );
			lprint "Unable to delete $new_name: $!\n" if ( ! $ok );
			lprint "Deleted the infected file $new_name\n" if ( $ok );
			
			# Now put a holding file into the same place
			if ( ! open( HOLDING, ">$filename" ) )
				{	lprint "Error creating a safe holding file at $filename: $!\n";
					return( 1 );
				}
			else
				{	print HOLDING "This is a safe holding file created by MarioCleanup.exe\n";
					close( HOLDING );
					
					lprint "Replaced $filename with a safe holding file\n";
					
					return( undef );
				}
		}

	# The must have been a problem
	lprint "Error renaming $filename: $!\n";
	
	return( 1 );			
}



################################################################################
#
sub CheckDir( $$ )
#
#  Given a directory, check the hex MD5 hash of the dangerous programs, and return
#  True if it is a problem.  If disinfect is TRUE then try to get rid of the
#  file and replace it with a holding file.
#
################################################################################
{	my $dir			= shift;
	my $disinfect	= shift;
	
	# If it isn't a directory then return
	return( undef ) if ( ! -d $dir );
	
	my $infected;
	if ( opendir( DIRHANDLE, $dir ) )
		{	for my $file ( readdir( DIRHANDLE ) )
				{	# Is it the file current open by the service?
					next if ( ! $file );
					
					next if ( $file eq "." );
					next if ( $file eq ".." );
					
					my $fullfile = "$dir\\$file";
					
					# Ignore directories
					next if ( -d $fullfile );
					
					# Ignore links
					next if ( $fullfile =~ m/\.lnk$/i );
					
					# ignore anything that isn't a normal file
					next if ( ! -f $fullfile );
					
					$infected = 1 if ( &CheckFile( $fullfile, $disinfect ) );
				}
				
			closedir( DIRHANDLE );	
		}
	else # If I can't open the directory, give up
		{	return( undef );
		}
		
	return( $infected );	
}



################################################################################
# 
sub StartupFolders()
#
#	Return a list of startup folders from the current PC
#
################################################################################
{	
	# Look at the StartUp folders for all the users
	my @startup_folders;
	
	
	my $homedrive = $ENV{ HOMEDRIVE };
	
	my $startup_dir = "C:\\Documents and Settings";
	$startup_dir =~ s/C:/$homedrive/ if ( $homedrive );
	
	my $start_dir = "C:\\Documents and Settings\\USERNAME\\Start Menu\\Programs\\Startup";
	my $start_menu = "C:\\Documents and Settings\\USERNAME\\Start Menu";
	
	
	if ( opendir( DIRHANDLE, $startup_dir ) )
		{	for my $file ( readdir( DIRHANDLE ) )
				{	# Is it the file current open by the service?
					next if ( ! $file );
					
					next if ( $file eq "." );
					next if ( $file eq ".." );
					
					my $dir = $start_dir;
					$dir =~ s/USERNAME/$file/;
					
					my $menu = $start_menu;
					$menu =~ s/USERNAME/$file/;
					
					push @startup_folders, $dir;
					push @startup_folders, $menu;
				}
				
			closedir( DIRHANDLE );	
		}

	return( @startup_folders );
}



################################################################################
# 
sub CreateService()
#
#	Create a dummp service to stop MarioForever from spreading
#
################################################################################
{	
}



################################################################################
# 
sub Usage
#
################################################################################
{
    print <<".";
Usage: MarioCleanup

Checks to see if the PC is infected with the MarioForever virus.
If the MarioForever virus is NOT detected this program does nothing.
If the MarioForever virus IS detected then this program patches back
\%systemroot\%\\system32\\user32.dll, removes MarioForever registry keys,
stops any MarioForever processes that are running, renames the actual
virus files to "*.infected", and then reboots the PC.  After the
reboot the PC should be clean of any infection.
  
  -c, --check          check for MarioForever but don't disinfect
  -u, --userinit       just try to cleanup the Userinit registry value
  
  -v, --verbose        verbose mode - extra messages
  -h, --help           print this message and exit
.

exit;
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
