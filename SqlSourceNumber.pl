################################################################################
#!perl -w
#
#  SqlSourceNumber - Reset any SourceNumbers back to Lightspeed values
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use Cwd;



use Content::File;
use Content::SQL;



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_wizard;					# True if I should't display headers and footers
my $opt_table;					# The table name if transfering only a single table



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
        "t|table=s"		=> \$opt_table,
        "w|wizard"		=> \$opt_wizard,
        "v|version"		=> \$opt_version,
		"x|xdebug"		=> \$opt_debug,
        "h|help"		=> \$opt_help
       );


	&StdHeader( "SqlSourceNumber" ) if ( ! $opt_wizard );

	lprint "Reset source number 1 to 2, and source numbers \> 3 to 3 for all Content tables\n";
	
	# This is the list of tables with source numberd
	my @tables = qw( ApplicationProcesses BannedProcesses IntrusionRuleSet IpmContentCategoryHits
	IpmContentCategoryMisses IpmContentDomain IpmContentIpAddress IpmContentURL RegistryControl
	SpamPatterns VirusSignatures DisinfectScripts );


	# Am I changing a single table?
	if ( $opt_table )
		{	my $opt_table = lc( $opt_table );
			
			my $found;
			foreach ( @tables )
				{	$found = 1 if ( $opt_table eq lc( $_ ) );
				}
				
			if ( $found )
				{	@tables = ();
					push @tables, $opt_table;
				}
			else
				{	print "Table $opt_table is not a valid table name\n";
					exit;
				}
		}
		
				
    &Usage() if ( $opt_help );



	&SetLogFilename( "SqlSourceNumber.log", undef );


	# Display the options
	lprint "Reset source numbers only for table $opt_table\n" if ( $opt_table );

	my $dbh = &ConnectServer() or die;

	foreach ( @tables )
		{	next if ( ! $_ );
			my $table = $_;
			
			$dbh = &SqlErrorCheckHandle( $dbh );

			die if ( ! $dbh);
			die if ( $dbh->err );
	
			my $str = "UPDATE $table SET SourceNumber = 2 WHERE SourceNumber = 1";
			my $sth = $dbh->prepare( $str );
			$sth->execute();
			
			my $rows = $sth->rows;
			
			lprint "Set $rows rows from source number 1 to 2 in table $table\n";

			&SqlErrorHandler( $dbh );
			$sth->finish();

			$dbh = &SqlErrorCheckHandle( $dbh );

			die if ( ! $dbh);
			die if ( $dbh->err );

			$str = "UPDATE $table SET SourceNumber = 3 WHERE SourceNumber > 3";
			$sth = $dbh->prepare( $str );
			$sth->execute();
			
			$rows = $sth->rows;
			
			lprint "Set $rows rows from source numbers \> 3 to 3 in table $table\n";
			
			&SqlErrorHandler( $dbh );
			$sth->finish();

			$dbh = &SqlErrorCheckHandle( $dbh );

		}
		
	$dbh->disconnect if ( $dbh );
	
	&StdFooter if ( ! $opt_wizard );

exit;
}

exit;
################################################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename;
	my $dir = &SoftwareDirectory();

	$filename = $dir . "\\SqlTransferErrors.log";
	
	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or &lprint( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	&lprint( "Set error logging set to SqlOptimizeErrors.log\n" ); 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlSourceNumber";

    bprint <<".";
Usage: $me
There are no command line arguments.

 
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
    my $me = "SqlTransfer";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



__END__

:endofperl
