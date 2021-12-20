################################################################################
#!perl -w
#
# ApplicationProcess - do the grunt work for processing virus signatures on
# the Application server
#
################################################################################



# Pragmas
use strict;
use warnings;



use Socket;
use Errno qw(EAGAIN);
use Getopt::Long;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use Cwd;
use Sys::Hostname;
use Win32::Process;



use Content::File;
use Content::Process;



# Options
my $opt_help;
my $opt_version;
my $opt_wait;
my $appslave_count = 0 + 4;		# This is the number of AppSlaves that are scanning - defaulted to 4



my $_version = "1.0.0";
my $curdir;



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
        "s|slaves=i"	=>	\$appslave_count,
        "w|wait"		=>	\$opt_wait,
        "v|version"		=>	\$opt_version,
        "h|help"		=>	\$opt_help
    );


    &StdHeader( "ApplicationProcess" );

    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );

	$curdir = getcwd;
	$curdir =~ s#\/#\\#gm;

	print "Waiting for $appslave_count AppSlaves to start and finish scanning ...\n";
	
	# Make sure all the required directories exist
	&CheckDirectories();


	if ( $opt_wait )
		{	&StartProcess();
		}
	else
		{	&FinishProcess();
		}

	chdir( $curdir );
	
	&StdFooter();
	
    exit( 0 );
}



################################################################################
# 
sub StartProcess()
#
#  Wait for the AppSlaves to start working
#
################################################################################
{
	print "Waiting for all the AppSlaves to start working ...\n";
	
	my $found = 1;
	
	while ( $found )
		{	$found = undef;
			
			for ( my $slave_num = 0 + 1; $slave_num <= $appslave_count;  $slave_num++ )
				{	my $formatted_slave_num = sprintf( "%02d", $slave_num );
					if ( ! -f "i:\\AppSlave\\AppSlave$formatted_slave_num.started.txt" )
						{	print "Giving AppSlave$formatted_slave_num another minute to start scanning ...\n";
							$found = 1;
						}
				}
				

			if ( $found )
				{	sleep( 60 );
					print "\n\n";
				}
		}
		
	print "All the AppSlaves have started scanning ...\n";	
}



################################################################################
# 
sub FinishProcess()
#
#  Wait for the AppSlaves to finish working
#
################################################################################
{
	print "Waiting for all the AppSlaves to finish scanning ...\n";
	my $found = 1;
	while ( $found )
		{	$found = undef;
			
			for ( my $slave_num = 0 + 1; $slave_num <= $appslave_count;  $slave_num++ )
				{	my $formatted_slave_num = sprintf( "%02d", $slave_num );
					if ( ! -f "i:\\AppSlave\\AppSlave$formatted_slave_num.finished.txt" )
						{	print "Giving AppSlave$formatted_slave_num another minute to finish scanning ...\n";
							$found = 1;
						}
				}

			if ( $found )
				{	sleep( 60 );
					print "\n\n";
				}
		}
		
	print "All the AppSlaves have finished scanning ...\n";	
	
	
	# Did anything find a virus?
	my $virus;

	for ( my $slave_num = 0 + 1; $slave_num <= $appslave_count;  $slave_num++ )
		{	my $formatted_slave_num = sprintf( "%02d", $slave_num );
			next if ( ! -f "i:\\AppSlave\\AppSlave$formatted_slave_num.log" );
			if ( -s "i:\\AppSlave\\AppSlave$formatted_slave_num.log" )
				{	print "AppSlave$formatted_slave_num found at least one virus!\n";
					$virus = 1;
				}
		}

		
	if ( ( -f "i:\\AppSlave\\NewNotVirusScan.log" )  &&  ( -s "i:\\AppSlave\\NewNotVirusScan.log" ) )
		{	print "The Application server found a virus in the NewNotVirus Archive!\n";
			$virus = "Application";
		}
		
		
	# Did I find a false positive virus anywhere?	
	if ( $virus )
		{	print "At least one of the AppSlaves or Application found a false positive virus\n";
			exit( 1 );	
		}
	
	print "All the AppSlaves finished scanning without finding a false positive virus\n";
	
	return( 1 );
}



################################################################################
# 
sub CheckDirectories()
#
#  Check to see that all the required directories still exist
#  Do a fatal error if they don't exist.  Return OK if everything
#  does exist
#
################################################################################
{

	my $dir = "c:\\content\\bin";
	if ( ! -d $dir )
		{	print( "Can not find directory $dir\n" );
			exit( 1 );
		}

	$dir = "f:\\content\\bin";
	if ( ! -d $dir )
		{	print( "Can not find directory $dir\n" );
			exit( 1 );
		}

	$dir = "r:\\NotVirus Archive";
	if ( ! -d $dir )
		{	print( "Can not find directory $dir\n" );
			exit( 1 );
		}

	$dir = "r:\\NewNotVirus Archive";
	if ( ! -d $dir )
		{	print( "Can not find directory $dir\n" );
			exit( 1 );
		}

	$dir = "r:\\AppSlave";
	if ( ! -d $dir )
		{	print( "Can not find directory $dir\n" );
			exit( 1 );
		}

	$dir = "i:\\AppSlave";
	if ( ! -d $dir )
		{	print( "Can not find directory $dir\n" );
			exit( 1 );
		}

	$dir = "c:\\Program Files\\Lightspeed Systems\\SecurityAgent";
	if ( ! -d $dir )
		{	print( "Can not find directory $dir\n" );
			exit( 1 );
		}

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
		
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "ApplicationProcess";
    print <<".";
Usage: $me [OPTION(s)]
Do all the grunt work that the Application server need to do to process new
clam virus signatures

  -h, --help        display this help and exit
  -w, --wait        wait for the AppSlaves to start their work
  -v, --version     display version information and exit
.
    exit( 3 );
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "ApplicationProcess";

    print <<".";
$me $_version
.
    exit( 4 );
}



################################################################################

__END__

:endofperl
