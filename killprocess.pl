################################################################################
#!perl -w
#
# Kill the process named on the command line
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use Win32;
use Win32::API;
use Win32::File;
use Win32::OLE::Variant;
use Win32::Event;
use Win32::Process;




my $_version = "1.0.0";




################################################################################
#
MAIN:
#
################################################################################
{

	my $process = shift;
	if ( $process )
		{	print "Killing process $process\n";
			&KillProcessName( $process );
 		}

    exit;
}



################################################################################
#
sub KillProcessName( $ )
#
#  Given a process name, find the pid and kill it
#
################################################################################
{	my $process_name = shift;
	
	# Define some contants
	my $DWORD_SIZE = 4;
	my $PROC_ARRAY_SIZE = 100;
	my $MODULE_LIST_SIZE = 200;
	
	# Define some Win32 API constants
	my $PROCESS_QUERY_INFORMATION = 0x0400;
	my $PROCESS_VM_READ = 0x0010;

	
	my $EnumProcesses = new Win32::API( 'psapi.dll', 'EnumProcesses', 'PNP', 'I' );

	my @PidList;
	
	my $ProcArrayLength = $PROC_ARRAY_SIZE;
    my $iIterationCount = 0;
    my $ProcNum;
    my $pProcArray;

    do
    {
        my $ProcArrayByteSize;
        my $pProcNum = MakeBuffer( $DWORD_SIZE );
        # Reset the number of processes since we later use it to test
        # if we worked or not
        $ProcNum = 0;
        $ProcArrayLength = $PROC_ARRAY_SIZE * ++$iIterationCount;
        $ProcArrayByteSize = $ProcArrayLength * $DWORD_SIZE;
        # Create a buffer
        $pProcArray = MakeBuffer( $ProcArrayByteSize );
        if( 0 != $EnumProcesses->Call( $pProcArray, $ProcArrayByteSize, $pProcNum ) )
        {
            # Get the number of bytes used in the array
            # Check this out -- divide by the number of bytes in a DWORD
            # and we have the number of processes returned!
            $ProcNum = unpack( "L", $pProcNum ) / $DWORD_SIZE;
        }
    } while( $ProcNum >= $ProcArrayLength );
   
    
	if( 0 != $ProcNum )
		{
			# Let's play with each PID
			# First we must unpack each PID from the returned array
			@PidList = unpack( "L$ProcNum", $pProcArray );
		}
	
	return( undef ) if ( $#PidList < 0 );
	
	
	my $OpenProcess = new Win32::API( 'kernel32.dll', 'OpenProcess', 'NIN', 'N' );
	my $CloseHandle = new Win32::API( 'kernel32.dll', 'CloseHandle', 'N', 'I' );
	my $GetModuleBaseName = new Win32::API( 'psapi.dll', 'GetModuleBaseName', 'NNPN', 'N' );
	my( $BufferSize ) = $MODULE_LIST_SIZE * $DWORD_SIZE;
	my( $MemStruct ) = MakeBuffer( $BufferSize );
		
	my $lc_process_name = lc( $process_name );

	my $process_id;
	foreach ( @PidList )
		{	next if ( ! $_ );	# Ignore the idle process
			
			my $pid = $_;
			
			my( $hProcess ) = $OpenProcess->Call( $PROCESS_QUERY_INFORMATION | $PROCESS_VM_READ, 0, $pid );

			my( $StringSize ) = 255 * ( ( Win32::API::IsUnicode() )? 2 : 1 );
            my( $ModuleName ) = MakeBuffer( $StringSize );
			my( @ModuleList ) = unpack( "L*", $MemStruct );
            my $hModule = $ModuleList[0];

            my $TotalChars;

			if( $TotalChars = $GetModuleBaseName->Call( $hProcess, $hModule, $ModuleName, $StringSize ) )
				{	my $name = FixString( $ModuleName );
					my $lc_name = lc( $name );
					$process_id = $pid if ( index( $lc_name, $lc_process_name ) > -1 );
				}
				
			$CloseHandle->Call( $hProcess );

			last if ( $process_id );
		}

	return( undef ) if ( ! $process_id );
	
	my $ok = Win32::Process::KillProcess( $process_id, 0 );

	return( $ok );
}



################################################################################
sub MakeBuffer
################################################################################
{
    my( $BufferSize ) = @_;
    return( "\x00"  x $BufferSize );
}



################################################################################
sub FixString	 
################################################################################
{
    my( $String ) = @_;
    $String =~ s/(.)\x00/$1/g if( Win32::API::IsUnicode() );
    return( unpack( "A*", $String ) );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "UpdateDB";

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
    my $me = "UpdateDB";
    print <<".";
Usage: $me [OPTION(s)]  input-file
Runs continuously the update database program, with one minute pauses.

Command line options:

-t, --time   to set the time between updates, in seconds
    
.
    exit;
}




################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "FileCategorize";

    print <<".";
$me $_version
.
    exit;
}



################################################################################

__END__

:endofperl
