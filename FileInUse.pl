my @ProcessUsingFile;

################################################################################
sub FileInUse( $ )
################################################################################
{
	my $file = shift;

	&lprint( "Checking to see if $file is currently in use...\n" );

    my $PROCESS_QUERY_INFORMATION = 0x0400;
    my $PROCESS_VM_READ = 0x0010;
    my $MODULE_LIST_SIZE = 200;
    my $DWORD_SIZE = 4;

	@ProcessUsingFile = ();
	%new_process_hash = ();
    
    &ProcessHash();
    
    my @PidList = keys %new_process_hash;
    my $OpenProcess = new Win32::API( 'kernel32.dll', 'OpenProcess', 'NIN', 'N' );
    my $EnumProcessModules = new Win32::API( 'psapi.dll', 'EnumProcessModules', 'NPNP', 'I' );
    my $GetModuleFileNameEx = new Win32::API( 'psapi.dll', 'GetModuleFileNameEx', 'NNPN', 'N' );
    my $CloseHandle = new Win32::API( 'kernel32.dll', 'CloseHandle', 'N', 'I' );
    
    foreach (@PidList)
    {
        my $pid = $_;

        # We can not open the system Idle process so just skip it.
        next if( 0 == $pid );
        
        my( $hProcess ) = $OpenProcess->Call( $PROCESS_QUERY_INFORMATION | $PROCESS_VM_READ, 0, $pid );

	    next if ( ! $hProcess );

        my( $BufferSize ) = $MODULE_LIST_SIZE * $DWORD_SIZE;
        my( $MemStruct ) = MakeBuffer( $BufferSize );
        my( $iReturned ) = MakeBuffer( $BufferSize );

        my $TotalChars;
        my( $StringSize ) = 255 * ( ( Win32::API::IsUnicode() )? 2 : 1 );
        my( $FileName ) = MakeBuffer( $StringSize );

        if( $EnumProcessModules->Call( $hProcess, $MemStruct, $BufferSize, $iReturned ) )
        {
            my( $ModuleName ) = MakeBuffer( $StringSize );
            my( @ModuleList ) = unpack( "L*", $MemStruct );
            my $hModule = $ModuleList[0];
            my $match;

            # Like EnumProcesses() divide $Returned by the # of bytes in an HMODULE
            # (which is the same as a DWORD)
            # and that is the number of module handles returned.
            # In this case we only want 1; the first returned in the array is
            # always the module of the process (typically an executable).
            $iReturned = unpack( "L", $iReturned ) / $DWORD_SIZE;

            my $iIndex;
            
            for( $iIndex = 0; $iIndex < $iReturned; $iIndex++ )
            {
                $hModule = $ModuleList[$iIndex];
                $ModuleName = MakeBuffer( $StringSize );
                if( $GetModuleFileNameEx->Call( $hProcess,
                                            $hModule,
                                            $ModuleName,
                                            $StringSize ) )
                {
                    my $ModuleNameFixed = FixString( $ModuleName );
                    my $strPrint = sprintf("[%04x] %s\n", $pid, $ModuleNameFixed);
                    &lprint( $strPrint );
                    push (@ProcessUsingFile, $pid) if (lc($ModuleNameFixed) eq lc($file));
                }
            }
        
            $CloseHandle->Call( $hProcess );
        }
    }
    return ($#ProcessUsingFile > 0);
}
