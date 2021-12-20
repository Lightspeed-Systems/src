################################################################################
#!perl -w
#
#  SqlTransfer - Transfer any locally edited data back to Lightspeed
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use Cwd;



use Content::File;
use Content::SqlReload;



my $opt_help;
my $opt_version;
my $opt_debug;
my $opt_wizard;					# True if I should't display headers and footers
my $opt_source;					# The source number to transfer if specifiying a single source
my $opt_transaction_time;		# The transaction date to transfer if overriding the last transfer date
my $opt_table;					# The table name if transfering only a single table
my $opt_no_email;				# If create, then create the data filee, but don't email it



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
        "d|date=s"		=> \$opt_transaction_time,
        "n|noemail"		=> \$opt_no_email,
        "s|source=s"	=> \$opt_source,
        "t|table=s"		=> \$opt_table,
        "w|wizard"		=> \$opt_wizard,
        "v|version"		=> \$opt_version,
		"x|xdebug"		=> \$opt_debug,
        "h|help"		=> \$opt_help
       );


	&StdHeader( "SqlTransfer" ) if ( ! $opt_wizard );

	
	# This is the default list of tables to backup and restore local data for
	my @tables = qw( ApplicationProcesses BannedProcesses IntrusionRuleSet IpmContentCategoryHits
	IpmContentCategoryMisses IpmContentDomain IpmContentIpAddress IpmContentURL RegistryControl
	SpamPatterns VirusSignatures DisinfectScripts );


	# Am I transferring a single table?
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
		
		
	# Did I set a transaction time?
	if ( $opt_transaction_time )
		{	my @parts = split /\//, $opt_transaction_time;
			
			my $format_ok = 1;
			
			$format_ok = undef if ( $#parts ne 2 );
			my $numeric = 1;
			foreach ( @parts )
				{	$numeric = undef if ( $_ =~ m/\D/ );
				}
				
			$format_ok = undef if ( ( $format_ok )  &&  ( ! $numeric ) );
			$format_ok = undef if ( ( $format_ok )  &&  ( $parts[ 0 ] lt 1 ) );
			$format_ok = undef if ( ( $format_ok )  &&  ( $parts[ 0 ] gt 12 ) );
			
			$format_ok = undef if ( ( $format_ok )  &&  ( $parts[ 1 ] lt 1 ) );
			$format_ok = undef if ( ( $format_ok )  &&  ( $parts[ 1 ] gt 31 ) );
				
			$format_ok = undef if ( ( $format_ok )  &&  ( $parts[ 2 ] lt 2000 ) );
			$format_ok = undef if ( ( $format_ok )  &&  ( $parts[ 2 ] gt 2010 ) );
		
			if ( ! $format_ok )	
				{	print "$opt_transaction_time is not a valid date - should be in the format MM/DD/YYYY\n";
					exit;
				}
		}
		
		
    &Usage() if ( $opt_help );


	# Catch any errors 
	&TrapErrors() if ( ! $opt_debug );


	&SetLogFilename( "SqlTransfer.log", undef );


	# Display the options
	lprint "Transfer only table $opt_table\n" if ( $opt_table );
	lprint "Transfer only source $opt_source\n" if ( $opt_source );
	lprint "Transfer since date $opt_transaction_time\n" if ( $opt_transaction_time );
	lprint "Create the data files but do not transfer them\n" if ( $opt_no_email );


	my  $dbh;             #  My database handle
	my $ok = &SqlTransfer( $dbh, $opt_source, $opt_transaction_time, $opt_no_email, @tables );
	
	
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
    my $me = "SqlTransfer";

    bprint <<".";
Usage: $me

Optional command line arguments:

  -d, --date mm/dd/yyyy  date to select the local data by.  Default is the
                         last successful transfer date
  -n, --noemail          prepare the data files but don\'t send the email
  -t, --table=name       to only select from a given table
  -h, --help             display this help and exit
 
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
