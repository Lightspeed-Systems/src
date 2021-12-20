################################################################################
#!perl -w
#
#  SqlReload - reload the Content database, saving locally added entries
#  and rebuilding indexes
#
################################################################################



# Pragmas
use strict;
use warnings;


my $_version = "6.03.00";


use Getopt::Long;
use MIME::Base64;
use LWP::Simple;
use LWP::UserAgent;
use Benchmark;
use Cwd;
use Win32API::Registry 0.21 qw( :ALL );


use Content::File;
use Content::SQL;
use Content::ScanFile;
use Content::Mail;
use Content::SqlReload;
use Content::Optimize;
use Content::ScanUtil;


my $opt_help;
my $opt_source = 0 + 1;		# The source number to back up and restore ...
my $opt_version;
my $opt_wizard;				# True if run from the Wizard, and I don't want html headers
my $opt_debug;
my $opt_local;				# Reload the database from the local files only - don't download anything
my $opt_restore;			# Only restore the local data
my $opt_backup;				# Only backup the local data
my $opt_table;				# If set, only do operations on this table
my $opt_format;				# If set, only check the local database format against the downloaded format
my $opt_no_email;			# If set, don't email results
my $opt_not_create;			# If set, DO NOT drop and recreate the tables in the local database
my $opt_dir;				# If set, this is the working directory to use
my $opt_update;				# If set, reload the source and source transaction update tables
my $dbh;					# Global database handle
my $dbhStat;				# Global statistics handle
my $monitor_server = "monitor.lightspeedsystems.com";
my $opt_verbose;			# If true, then display lots of stuff
my @tmp_files;				# This is the list of tmp files that I created




# This is the list of tables to backup and restore local data for
my @tables = qw( VirusSignatures IpmContentCategory ApplicationProcesses BannedProcesses IntrusionRuleSet 
IpmContentCategoryHits IpmContentCategoryMisses IpmContentDomain IpmContentIpAddress IpmContentURL RegistryControl
SpamPatterns DisinfectScripts );


# This is the hash of the unique keys for each of the tables
my %table_key = ( 
'IpmContentCategory'		=> 'CategoryName',
'ApplicationProcesses'		=> 'FileID',
'BannedProcesses'			=> 'Process',
'DisinfectScripts'			=> 'VirusName',
'IntrusionRuleSet'			=> 'Name',
'IpmContentCategoryHits'	=> 'URL',
'IpmContentCategoryMisses'	=> 'URL',
'IpmContentDomain'			=> 'DomainName',
'IpmContentIpAddress'		=> 'IpAddress',
'IpmContentURL'				=> 'URL',
'RegistryControl'			=> '[Key]',
'SpamPatterns'				=> 'Name',
'VirusSignatures'			=> 'VirusName'
);



# This hash has a key of the table name, and the value is the SQL commands to create the table and it's indexes
my %table_creation = (

'ApplicationProcesses' =>
		'create table IpmContent..ApplicationProcesses
		(
			FileID varchar(128) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			[AppName] varchar(255) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			Process varchar(512) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			[Description] varchar(512) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Manufacturer varchar(255) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Recommended bit not null default 0,
			Dangerous bit not null default 0,
			CurrentVersion bit not null default 0,
			Ports varchar(128) COLLATE SQL_Latin1_General_CP1_CI_AS null,
			ProgramPermissions varchar(8) COLLATE SQL_Latin1_General_CP1_CI_AS not null default \'00000000\',
			CategoryNumber Int not null default 3,
			SourceNumber Int not null,
			TransactionTime datetime NOT NULL default getutcdate(),
			[AppType] varchar(32) NULL,
		)

		create unique index CkApplicationProcessesIndex
			on ApplicationProcesses (FileID) with IGNORE_DUP_KEY

		create clustered index ApplicationProcessesIndexTransTime on ApplicationProcesses (TransactionTime)
		
		alter table ApplicationProcesses add primary key (FileID)
		',



'BannedProcesses' =>
		'create table IpmContent..BannedProcesses
		(
			Process varchar(255) COLLATE SQL_Latin1_General_CP1_CI_AS unique not null,
			[Description] varchar(512) COLLATE SQL_Latin1_General_CP1_CI_AS,
			CategoryNumber Int not null default 3,
			SourceNumber Int not null,
			TransactionTime datetime NOT NULL default getutcdate()
		)

		create unique index CkBannedProcessesIndex
			on BannedProcesses (Process) with IGNORE_DUP_KEY

		create clustered index BannedProcessesIndexTransTime on BannedProcesses (TransactionTime)
		
		alter table BannedProcesses add primary key (Process)
		',



'IntrusionRuleSet' =>
		'create table IntrusionRuleSet
		(
			[Name] VarChar(100) COLLATE SQL_Latin1_General_CP1_CI_AS unique not null,
			[Action] VarChar(100) COLLATE SQL_Latin1_General_CP1_CI_AS,
			[Log] VarChar(100) COLLATE SQL_Latin1_General_CP1_CI_AS,
			[Description] VarChar(1000) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Definition VarChar(5000) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			Designer bit not null default 1,
			CategoryNumber Int not null default 3,
			SourceNumber Int not null,
			TransactionTime datetime NOT NULL default getutcdate(),
			[KBID] [varchar] (50) COLLATE SQL_Latin1_General_CP1_CI_AS NULL
		)

		create unique clustered index CkIntrusionRuleSetIndex
			on IntrusionRuleSet ([Name]) with IGNORE_DUP_KEY

		create index IntrusionRuleSetIndexTransTime on IntrusionRuleSet (TransactionTime)
		
		alter table IntrusionRuleSet add primary key ([Name])
		',



'DisinfectScripts' =>
		'create table IpmContent..DisinfectScripts
		(
			[VirusName] varchar(64) COLLATE SQL_Latin1_General_CP1_CI_AS unique not null,
			[Description] varchar(255) COLLATE SQL_Latin1_General_CP1_CI_AS,
			[Script] text COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			[CategoryNumber] Int not null default 16,
			[SourceNumber] Int not null,
			[TransactionTime] datetime NOT NULL default getutcdate(),
			[KBID] [varchar] (50) COLLATE SQL_Latin1_General_CP1_CI_AS NULL
		)
		
		create unique clustered index CkDisinfectScriptsIndex
			on DisinfectScripts ([VirusName]) with IGNORE_DUP_KEY
		
		create index DisinfectScriptsIndexTransTime on DisinfectScripts (TransactionTime)
		
		alter table DisinfectScripts add primary key ([VirusName])
		',



'IpmContentCategoryHits' => 
		'create table IpmContent..IpmContentCategoryHits
		(
			URL VarChar(128) collate SQL_Latin1_General_CP1_CI_AS not null,
			CategoryNumber Int not null,
			SourceNumber int not null,
			TransactionTime datetime NOT NULL default getutcdate()
		)

		create unique clustered index CkCategoryHits
			on IpmContentCategoryHits (URL, CategoryNumber) with IGNORE_DUP_KEY',



'IpmContentCategoryMisses' => 
		'create table IpmContent..IpmContentCategoryMisses
		(
			URL VarChar(128) collate SQL_Latin1_General_CP1_CI_AS not null,
			CategoryNumber Int not null,
			SourceNumber int not null,
			TransactionTime datetime NOT NULL default getutcdate()
		)

		create unique clustered index CkCategoryMisses
			on IpmContentCategoryMisses (URL, CategoryNumber) with IGNORE_DUP_KEY',



'IpmContentDomain' => 
		'create table IpmContent..IpmContentDomain
		(
			DomainName VarChar(64) collate SQL_Latin1_General_CP1_CI_AS not null,
			CategoryNumber Int not null,
			SourceNumber Int not null,
			TransactionTime datetime not null default getutcdate(),
			ReviewTime datetime not null default getutcdate(),
			AssociatedUrls Bit default 0 not null,
			StarRating tinyint NULL
		)

		create unique clustered index CkDomainIndex
			on IpmContentDomain (DomainName desc) with IGNORE_DUP_KEY

		create index DomainIndexTransTime on IpmContentDomain (TransactionTime)
		
		alter table IpmContentDomain add primary key (DomainName)
		',



'IpmContentIpAddress' => 
		'create table IpmContent..IpmContentIpAddress
		(
			IpAddress Char(4) collate Latin1_General_BIN not null,
			CategoryNumber Int not null,
			SourceNumber Int not null,
			TransactionTime datetime not NULL default getutcdate(),
			ReviewTime datetime not null default getutcdate(),
			AssociatedUrls Bit default 0 not null,
			StarRating tinyint NULL
		)

		create unique clustered index CkIpAddressIndex
			on IpmContentIpAddress (IpAddress) with IGNORE_DUP_KEY

		create index IpAddressIndexTransTime on IpmContentIpAddress (TransactionTime)
		
		alter table IpmContentIpAddress add primary key (IpAddress)
		',



'IpmContentURL'	=> 
		'create table IpmContent..IpmContentURL
		(
			URL VarChar(128) collate SQL_Latin1_General_CP1_CI_AS not null,
			CategoryNumber Int not null,
			SourceNumber Int not null,
			TransactionTime datetime NOT NULL default getutcdate(),
			ReviewTime datetime not null default getutcdate(),
			StarRating tinyint NULL
		)

		create unique clustered index CkUrlIndex
			on IpmContentURL (URL desc) with IGNORE_DUP_KEY

		create index UrlIndexTransTime on IpmContentURL (TransactionTime)
		
		alter table IpmContentURL add primary key (URL)
		',



'RegistryControl' =>
		'create table RegistryControl
		(	ID bigint identity (1, 1) not for replication,
		    [Key] varchar(512) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
		    [ValName] varchar(128) COLLATE SQL_Latin1_General_CP1_CI_AS null,
		    [ValType] varchar(15) COLLATE SQL_Latin1_General_CP1_CI_AS null,
		    [ValData] varchar(512) COLLATE SQL_Latin1_General_CP1_CI_AS null,
		    [Protected] bit default 0 not null,
		    [Monitored] bit default 0 not null,
		    [Set] bit default 0 not null,
		    [Delete] bit default 0 not null,
			[PolicyName] varchar(50) COLLATE SQL_Latin1_General_CP1_CI_AS null,
		    CategoryNumber Int not null default 14,
		    SourceNumber Int not null,
		    TransactionTime datetime NOT NULL default getutcdate()
		)
		
		create unique clustered index CkRegistryControlIndex
			on RegistryControl ([Key], [ValName]) with IGNORE_DUP_KEY
			
		alter table RegistryControl add primary key (ID)
		',
		

		
'SpamPatterns' =>
		'create table IpmContent..SpamPatterns
		(
			[Name] varchar(64) COLLATE SQL_Latin1_General_CP1_CI_AS unique not null,
			Result varchar(16) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			Type1 varchar(16) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Value1 varchar(256) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Type2 varchar(16) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Value2 varchar(256) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Type3 varchar(16) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Value3 varchar(256) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Type4 varchar(16) COLLATE SQL_Latin1_General_CP1_CI_AS,
			Value4 varchar(256) COLLATE SQL_Latin1_General_CP1_CI_AS,
			CategoryNumber Int not null default 55,
			SourceNumber Int not null,
			TransactionTime datetime NOT NULL default getutcdate()
		)

		create unique clustered index CkSpamPatternsIndex
			on SpamPatterns ([Name]) with IGNORE_DUP_KEY

		create index SpamPatternsIndexTransTime on SpamPatterns (TransactionTime)
		
		alter table SpamPatterns add primary key ([Name])
		',



'VirusSignatures' =>
		'create table IpmContent..VirusSignatures
		(
			[VirusName] varchar(64) COLLATE SQL_Latin1_General_CP1_CI_AS unique not null,
			[VirusType] varchar(32) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			[AppSig] varchar(32) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			[SigStart] int not null,
			[SigEnd] int not null,
			[Signature] varchar(1024) COLLATE SQL_Latin1_General_CP1_CI_AS not null,
			[Test] bit not null default 0,
			[CategoryNumber] Int not null default 16,
			[SourceNumber] Int not null,
			[TransactionTime] datetime NOT NULL default getutcdate(),
			[KBID] [varchar] (50) COLLATE SQL_Latin1_General_CP1_CI_AS NULL
		)

		create unique index CkVirusSignaturesIndex
			on VirusSignatures ([VirusName]) with IGNORE_DUP_KEY

		create clustered index VirusSignaturesIndexTransTime on VirusSignatures (TransactionTime)
		
		alter table VirusSignatures add primary key ([VirusName])
		',



'IpmContentCategory' =>
        'create table IpmContent..IpmContentCategory
        (
            [CategoryNumber] [int] IDENTITY (1, 1) not for replication unique NOT NULL ,
            [CategoryName] [nvarchar] (255) COLLATE SQL_Latin1_General_CP1_CI_AS NOT NULL ,
            [CategoryDescription] [nvarchar] (255) COLLATE SQL_Latin1_General_CP1_CI_AS NULL ,
            [Allow] [bit] NOT NULL ,
            [RedirectURL] [varchar] (128) COLLATE SQL_Latin1_General_CP1_CI_AS NULL ,
            [TransactionTime] [datetime] DEFAULT (getutcdate()) NOT NULL,
            [CategoryType] [varchar] (255) COLLATE SQL_Latin1_General_CP1_CI_AS NULL,
			[KBID] [varchar] (50) COLLATE SQL_Latin1_General_CP1_CI_AS NULL,
 			[ContentRating] [varchar](10) COLLATE SQL_Latin1_General_CP1_CI_AS NULL
       )

		create unique clustered index CkCategoryNameIndex
			on IpmContentCategory (CategoryName) with IGNORE_DUP_KEY
			
		alter table IpmContentCategory add primary key (CategoryNumber)'

);



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
		"b|backup"		=> \$opt_backup,
		"c|notcreate"	=> \$opt_not_create,
		"d|directory=s"	=> \$opt_dir,
		"f|format"		=> \$opt_format,
		"l|local"		=> \$opt_local,
		"m|monitor=s"	=> \$monitor_server,
		"n|noemail"		=> \$opt_no_email,
		"r|restore"		=> \$opt_restore,
		"s|source=s"	=> \$opt_source,
		"t|table=s"		=> \$opt_table,
		"w|wizard"		=> \$opt_wizard,
		"u|update"		=> \$opt_update,
        "v|version"		=> \$opt_verbose,
		"x|xdebug"		=> \$opt_debug,
        "h|help"		=> \$opt_help
       );


	&StdHeader( "SqlReload" ) if ( ! $opt_wizard );

	
	&Usage() if ( $opt_help );
	&Version() if ( $opt_version );
	

	# Catch any errors 
	&TrapErrors() if ( ! $opt_debug );
	
	
	&SetLogFilename( "SqlReload.log", undef );
	
	&lprint( "Version: $_version\n" );
	
	if ( ( $opt_source < 1 )  ||  ( $opt_source > 100 ) )
		{	&lprint( "Illegal source number = $opt_source\n" );
			exit( -1 );
		}
	
	
	# Did I specify a single table?
	if ( $opt_table )
		{	my $found;
			my $table = lc( $opt_table );
			foreach ( @tables )
				{	next if ( ! defined $_ );
					
					my $lc_table = lc( $_ );
					
					$found = 1 if ( $lc_table eq $table );
				}
			
			if ( ! $found )
				{	&lprint( "Illegal table name = $opt_table\n" );
					exit( -1 );
				}
				
			# Reset the table names to just the one table	
			@tables = ();
			push @tables, $opt_table;
		}
		
		
	# Show the options
	&lprint( "Backup data with source number <= $opt_source\n" ) if ( $opt_source ne 1 );
	&lprint( "Don\'t download new database files - use database.zip from disk instead.\n" ) if ( $opt_local );
	&lprint( "Show debugging information.\n" ) if ( $opt_debug );
	&lprint( "Only backup the local data.\n" ) if ( $opt_backup );
	&lprint( "Only restore the local data.\n" ) if ( $opt_restore );
	&lprint( "Only do operation on table $opt_table.\n" ) if ( $opt_table );
	&lprint( "Only check the local database format against Lightspeed\'s format.\n" ) if ( $opt_format );
	&lprint( "Do NOT drop and create all the tables.\n" ) if ( $opt_not_create );
	&lprint( "Reload the update sources and transaction data.\n" ) if ( $opt_update );
	&lprint( "Don\'t email results back to support\@lightspeedsystems.com.\n" ) if ( $opt_no_email );
	&lprint( "\n" );
	
	
	# What actions should I take?
	# Start out doing everything, and then turn stuff off based on the command line
	my $download		= 1;
	my $unzip			= 1;
	my $backup			= 1;
	my $reload			= 1;
	my $restore			= 1;
	my $checkformat		= 1;
	my $create			= 1;
	my $updatetrans		= 1;
	my $check_indexes	= 1;
	my $email_results	= 1;
	my $clean_tmpfiles	= 1;
	
	
	if ( $opt_backup )
		{	$download		= undef;
			$unzip			= undef;
			$reload			= undef;
			$restore		= undef;
			$updatetrans	= undef;
			$clean_tmpfiles	= undef;
		}
	
	if ( $opt_restore )
		{	$download		= undef;
			$unzip			= undef;
			$reload			= undef;
			$backup			= undef;
			$updatetrans	= undef;
			$checkformat	= undef;
			$clean_tmpfiles	= undef;
		}
	
	if ( $opt_local )
		{	$download		= undef;
			$clean_tmpfiles	= undef;
		}

	if ( $opt_format )
		{	$download		= undef;
			$unzip			= undef;
			$backup			= undef;
			$reload			= undef;
			$restore		= undef;
			$updatetrans	= undef;
			$check_indexes	= undef;
			$clean_tmpfiles	= undef;
		}

	if ( $opt_not_create )
		{	$create	= undef;
		}

	if ( $opt_no_email )
		{	$email_results	= undef;
		}

	if ( ( $create )  &&  ( ! $reload ) )
		{	&lprint( "You can\'t create the tables without reloading the data back into them.\n" );
			exit( -1 );
		}
		
	if ( ( $opt_restore )  &&  ( $opt_backup ) )
		{	&lprint( "You have to backup only and restore only as separate commands\n" );
			exit( -1 );
		}
		
	if ( ( $opt_table )  &&  ( ! $opt_restore )  &&  ( ! $opt_backup ) )
		{	&lprint( "You can\'t set a tablename unless you are backing up or restoring a single table\n" );
			exit( -1 );
		}
		
		
	# Get my working directory and make sure it exists
	my $dir;
	
	if ( $opt_dir )
		{	$dir = $opt_dir;
			$dir = getcwd if ( $dir eq "." );	# Convert a . to the current directory
			$dir =~ s#\/#\\#gm;
		}
	else	
		{	$dir = &SoftwareDirectory();
			$dir = "$dir\\ContentFilterInitData";
			mkdir( $dir );
		}
		
	if ( ! -e $dir )
		{	&lprint( "Unable to open directory $dir\n" );
			exit( 9 );
		}
		
	&lprint( "Using working directory $dir\n" );


	# Keep track of how long it takes
	my $start = new Benchmark;


	# Start out with everything OK
	my $ok = 1;
	
	# Check to make sure there is enough disk space
	$ok = &CheckDiskSpace( $dir ) if ( $download );
	
	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 1 );
		}
	
	
	# Backup the local entries
	$ok = &BackupLocal( $dir, $dbh, $opt_source, undef, @tables ) if ( $backup );
	
	
	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 2 );
		}
		
		
	# Transfer the database from Lightspeed
	$ok = &GetNewDatabase( $dir ) if ( $download );
	
	
	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 3 );
		}
	
	
	# Unzip the database
	$ok = &UnzipDatabase( $dir ) if ( $unzip );


	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 10 );
		}
	
	
	# Drop and create the tables
	$ok = &CreateTables( $dir ) if ( $create );
	
	
	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 4 );
		}
	
		
	# Check the database format
	$ok = &CheckDatabaseFormat( $dir ) if ( $checkformat );
	
	
	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 5 );
		}


	# Import the new database
	$ok = &DatabaseReload( $dir ) if ( $reload );
	
	
	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 6 );
		}
		
		
	# Update the transaction table with the current date
	$ok = &UpdateTransaction( $dir ) if ( $updatetrans );
	
	
	if ( ! $ok )
		{	&start_ipmagic();
			&email_results() if ( $email_results );
			&StdFooter if ( ! $opt_wizard );
			exit( 7 );
		}
		
		
	# Restore the local entries
	$ok = &RestoreLocal( $dir ) if ( $restore );
	
	&lprint( "\nReloaded the content database OK\n" ) if ( ( $reload )  &&  ( $ok ) );	
	
	&start_ipmagic();
	
	
	# Check all the indexes
	&ReloadSqlCheckIndexes() if ( $check_indexes );
	
	
	# Cleanup any tmp files that were created
	$ok = &CleanupTmpFiles( $dir )  if ( ( $ok )  &&  ( $clean_tmpfiles ) );
	
	
	# Calc the benchmark statistics
	my $finish = new Benchmark;

	my $diff = timediff($finish, $start);
	my $strtime = timestr( $diff );
	my ( $secs, $junk ) = split /\s/, $strtime;
	my $min = 0 + 0;
	$min = &Integer( $secs / 60 ) if ( $secs );
	
	&lprint( "\nTotal time for all operations: $min minutes - $strtime\n" );
	
	
	# Should I email what happened?
	&email_results() if ( $email_results );
	
	
	&StdFooter if ( ! $opt_wizard );

	exit( 0 ) if ( $ok );
	exit( 8 );
}
exit;
################################################################################




################################################################################
#
sub ReloadSqlCheckIndexes()
#
#  Check all the indexes in the databases - return True if ok, undef if not
#
################################################################################
{
	# Check the indexes to see if they are created OK
	$dbh = &ConnectServer() if ( ! $dbh );
	if ( ! $dbh )
		{	&lprint( "ReloadSqlCheckIndexes: Unable to connect to the Content database\n" );
			return( undef );
		}

	$dbhStat = &ConnectStatistics() if ( ! $dbhStat );
	if ( ! $dbhStat )
		{	&lprint( "ReloadSqlCheckIndexes: Unable to connect to the Statistics database\n" );
			return( undef );
		}

	my $ok = &SqlCheckIndexes();
	
	$dbh->disconnect if ( $dbh );
	$dbh = undef;
	
	$dbhStat->disconnect if ( $dbhStat );
	$dbhStat = undef;

	return( $ok );
}




################################################################################
#
#   LWP::Simple modified code
#
################################################################################

my $ua;

sub rob_init_ua( $ )
{	
    require LWP;
    require LWP::UserAgent;
    require HTTP::Status;
    require HTTP::Date;
    
	my $url = shift;
	
	$ua = new LWP::UserAgent;  # we create a global UserAgent object
    my $ver = $LWP::VERSION = $LWP::VERSION;  # avoid warning
    $ua->agent("LWP::Simple/$LWP::VERSION");
	$ua->timeout( 60 * 15 );	# 15 minute timeout
	
	# See if I need to use a proxy server for this root domain
	my $root_domain = &RootDomain( $url );
	my $proxy_server = &ScanUtilIEProxy( $root_domain );
	$ua->proxy( [ 'http' ], $proxy_server ) if ( $proxy_server );
}

sub rob_getstore ($$)
{
    my($url, $file) = @_;
    rob_init_ua( $url ) unless $ua;

    my $request = HTTP::Request->new(GET => $url);
    my $response = $ua->request($request, $file);

    $response->code;
}



################################################################################
#
sub GetNewDatabase( $ )
#
#  Transfer the database from Lightspeed
#
################################################################################
{	my $dir = shift;
	&lprint( "Transfering the database from Lightspeed (approx. 500 Megs of zipped data) ...\n" );
	
	my $full_filename = "$dir\\database.zip";
	unlink( $full_filename );
	
	my $response = rob_getstore( 'http://opendb.lightspeedsystems.com/contentupdate/database.htm', $full_filename );
	
	my $ok = is_success( $response );
	
	my $size = -s $full_filename;
	$size = 0 if ( ! $size );
	$size = &Integer( $size / ( 1024 * 1024 ) );
	
	&lprint( "Transferred the database from Lightspeed OK (actual size $size Megs of zipped data)\n" ) if ( $ok );
	&lprint( "Unable to transfer the database from Lightspeed, response code $response\n" ) if ( ! $ok );
	
	return( undef ) if ( ! $ok );
	
	# Keep track of this tmp file
	push @tmp_files, $full_filename;
	
	return( $ok );	
}



################################################################################
#
sub UnzipDatabase( $ )
#
#  Unzip the database from Lightspeed
#
################################################################################
{	my $dir = shift;
	my $ok = 1;
	my $full_filename = "$dir\\database.zip";
	
	&lprint( "Unzipping $full_filename\n" );
	
	my ( $err_msg, @files ) = &ScanUnzipFile( $dir, $full_filename );

	if ( $err_msg )
		{	&lprint( "Unable to unzip database $full_filename: $err_msg\n" );
			return( undef );					
		}
	
	if ( ! $files[ 0 ] )
		{	&lprint( "Unable to unzip database $full_filename\n" );
			return( undef );					
		}
	
	my $error = &ScanLastUnzipError();
	if ( $error )
		{	&lprint( "Error unzipping database $full_filename: $error\n" );
			return( undef );					
		}
	
	&lprint( "Unzipped database OK\n" );
	
	
	# Keep track of these tmp files
	foreach ( @files )
		{	my $file = $_;
			next if ( ! defined $file );
			
			push @tmp_files, $file;
		}
		
	
	return( $ok );	
}



################################################################################
#
sub CleanupTmpFiles( $ )
#
#  Drop and create the tables
#
################################################################################
{	my $dir = shift;
	
	&lprint( "Cleaning up all the temporary files that were created ...\n" );

	# Add the two old ipaddress files, and the old search query data file
	push @tmp_files, "$dir\\ipmcontentipaddress2.dat";
	push @tmp_files, "$dir\\ipmcontentipaddress2.fmt";
	push @tmp_files, "$dir\\TrafficClassSearchQuery.sql.dat";

	push @tmp_files, "$dir\\IpmContentURL.sql.dat";
	push @tmp_files, "$dir\\SpamPatterns.sql.dat";
	push @tmp_files, "$dir\\virussigimport.cmd";
	
	
	# Put in the local data files names
	foreach ( @tables )
		{	my $table = $_;
			next if ( ! defined $table );
			
			my $datafile = "$dir\\$table.sql.dat";
			
			push @tmp_files, $datafile;
		}
	
	
	# Now delete everything	
	foreach ( @tmp_files )
		{	my $fullfile = $_;
			next if ( ! defined $fullfile );
			if ( ! -f $fullfile )
				{	&lprint( "Unable to find file: $fullfile\n" ) if ( $opt_debug );
					next;
				}
			
			&lprint( "Deleting temporary file: $fullfile\n" );
			unlink( $fullfile );
		}
		
	&lprint( "Done cleaning up all the temporary files.\n" );
	
	return( 1 );
}



################################################################################
#
sub CreateTables( $ )
#
#  Drop and create the tables
#
################################################################################
{	my $dir = shift;
	$dbh = &ConnectServer() if ( ! $dbh );
	if ( ! $dbh )
		{	&lprint( "CreateTables: Unable to connect to the Content database\n" );
			return( undef );
		}
	
	my $ok = 1;
	
	&lprint( "Dropping and creating the tables ...\n" );
	
	# Stop the service so that I can drop the tables
	&stop_ipmagic();
	
	
	foreach ( @tables )
		{	next if ( ! defined $_ );
			my $table = $_;
			
			my $create_cmds = $table_creation{ $table };
			
			if ( ! $create_cmds )
				{	&lprint( "No creation commands for table $table\n" );
					next;	
				}
			
			
			&ltprint( "\nDropping table $table ...\n" );
			my $ok_dokey = &CreateCommand( "DROP TABLE $table" );
			if ( ! $ok_dokey )
				{	&ltprint( "Error when dropping table $table\n" ); 
				}
				
				
			&ltprint( "\nCreating table $table ...\n" );
			
			my @lines = split /\n/, $create_cmds;
			
			my $cmd;
			
			foreach ( @lines )
				{	my $line = $_;
					
					$line =~ s/^\s+// if ( $line );	# Dump leading whitespace
					$line =~ s/\s+$// if ( $line );	# Dump trailing whitespace
					
					if ( ( ! $line )  &&  ( $cmd ) )
						{	# Execute the SQL command
							$ok_dokey = &CreateCommand( $cmd );
							$ok = undef if ( ! $ok_dokey );
							$cmd = undef;
							next;
						}
						
					if ( $line )
						{	$cmd = $cmd . " " . $line if ( $cmd );
							$cmd = $line if ( ! $cmd );
						}
				}
				
			# Execute the last command if there was one
			$ok_dokey = 1;
			$ok_dokey = &CreateCommand( $cmd ) if ( $cmd );
			$ok = undef if ( ! $ok_dokey );
			
			last if ( ! $ok );
		}
	
	&lprint( "Dropped and created the tables OK.\n" ) if ( $ok );
	&lprint( "Errors when dropping and creating the tables.\n" ) if ( ! $ok );
	
	$dbh->disconnect if ( $dbh );
	$dbh = undef;
	
	return( $ok );
}



################################################################################
#
sub CreateCommand( $ )
#
#  Given a create table command - execute it
#
################################################################################
{	my $cmd = shift;
	return( undef ) if ( ! $cmd );
	
	my $errmsg;
	
	&ltprint( "SQL command: $cmd\n" );
	
	$dbh = &SqlErrorCheckHandle( $dbh );

	if ( ( ! $dbh )  ||  ( $dbh->err ) )
		{	$errmsg = $dbh->errstr;
			$errmsg = "." if ( ! $errmsg );
			&ltprint( "Error executing command $errmsg\n" );
			return( undef );
		}

	my $sth = $dbh->prepare( $cmd );
	$sth->execute();

	if ( ( ! $dbh )  ||  ( $dbh->err ) )
		{	$errmsg = $dbh->errstr;
			$errmsg = "." if ( ! $errmsg );
			&ltprint( "Error executing command $errmsg\n" );
			&SqlErrorHandler( $dbh );
			$sth->finish();
			return( undef );
		}

	$sth->finish();
	
	return( 1 );
}



################################################################################
#
sub DatabaseReload( $ )
#
#  Import the new database
#
################################################################################
{	my $dir = shift;
	
	&lprint( "\nReloading the database ...\n" );
	
	# Handle the "old-school" char(4) IpAddress insert (can cause duplicates because of character translation!)
	my $bcp_import_ipaddress_table = "bcp IpmContent.dbo.IpmContentIpAddress in \"%sInDir%IpmContentIpAddress.dat\" -f\"%sInDir%IpmContentIpAddress.fmt\" -T -h\"TABLOCK\"";
	
	# if the "new" IP address export file(s) exist, then use the binary insert instead...
	if ( -e "$dir\\ipmcontentipaddress2.dat" && -e "$dir\\ipmcontentipaddress2.fmt")
		{
			$bcp_import_ipaddress_table = "bcp IpmContent.dbo.IpmContentIpAddress in \"%sInDir%IpmContentIpAddress2.dat\" -f\"%sInDir%IpmContentIpAddress2.fmt\" -T -h\"TABLOCK\"";
		}
	
	# These are all the commands to run to reload the database
	my @reload_commands = (
	"osql -E -Q\"alter database IpmContent set Recovery BULK_LOGGED\"",
	"osql -E -dIpmContent -oVirusSignaturesTruncateTable.out -Q \"truncate table VirusSignatures\"",
	"osql -E -dIpmContent -oVirusSignaturesDropIndex.out -Q \"drop index VirusSignatures.CkVirusSignaturesIndex\"",
	"osql -E -dIpmContent -oVirusSignaturesDropTransIndex.out -Q \"drop index VirusSignatures.VirusSignaturesIndexTransTime\"",
	"bcp IpmContent.dbo.VirusSignatures in \"%sInDir%VirusSignatures.dat\" -f\"%sInDir%VirusSignatures.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oVirusSignaturesCreateIndex.out -Q \"create unique index CkVirusSignaturesIndex on VirusSignatures (VirusName) with IGNORE_DUP_KEY\"",
	"osql -E -dIpmContent -oVirusSignaturesCreateTransIndex.out -Q \"create clustered index VirusSignaturesIndexTransTime on VirusSignatures (TransactionTime)\"",
	
	
	"osql -E -dIpmContent -oIpmContentCategoryTruncateTable.out -Q \"truncate table IpmContentCategory\"",
	"osql -E -dIpmContent -oIpmContentCategoryDropIndex.out -Q \"drop index IpmContentCategory.CkCategoryNameIndex\"",
	"bcp IpmContent.dbo.IpmContentCategory in \"%sInDir%IpmContentCategory.dat\" -f\"%sInDir%IpmContentCategory.fmt\" -E -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oIpmContentCategoryCreateIndex.out -Q \"create unique clustered index CkCategoryNameIndex on IpmContentCategory (CategoryName)\"",
						   
						   
	"osql -E -dIpmContent -oApplicationProcessesTruncateTable.out -Q \"truncate table ApplicationProcesses\"",
	"osql -E -dIpmContent -oApplicationProcessesDropIndex.out -Q \"drop index ApplicationProcesses.CkApplicationProcessesIndex\"",
	"osql -E -dIpmContent -oApplicationProcessesTransDropIndex.out -Q \"drop index ApplicationProcesses.ApplicationProcessesIndexTransTime\"",
	"bcp IpmContent.dbo.ApplicationProcesses in \"%sInDir%ApplicationProcesses.dat\" -f\"%sInDir%ApplicationProcesses.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oApplicationProcessesCreateIndex.out -Q \"create unique index CkApplicationProcessesIndex on ApplicationProcesses (FileID) with IGNORE_DUP_KEY\"",
	"osql -E -dIpmContent -oApplicationProcessesTransCreateIndex.out -Q \"create clustered index ApplicationProcessesIndexTransTime on ApplicationProcesses (TransactionTime)\"",
	
	
	"osql -E -dIpmContent -oBannedProcessesTruncateTable.out -Q \"truncate table BannedProcesses\"",
	"osql -E -dIpmContent -oBannedProcessesDropIndex.out -Q \"drop index BannedProcesses.CkBannedProcessesIndex\"",
	"osql -E -dIpmContent -oBannedProcessesDropTransIndex.out -Q \"drop index BannedProcesses.BannedProcessesIndexTransTime\"",
	"bcp IpmContent.dbo.BannedProcesses in \"%sInDir%BannedProcesses.dat\" -f\"%sInDir%BannedProcesses.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oBannedProcessesCreateIndex.out -Q \"create unique index CkBannedProcessesIndex on BannedProcesses (Process) with IGNORE_DUP_KEY\"",
	"osql -E -dIpmContent -oBannedProcessesCreateTransIndex.out -Q \"create clustered index BannedProcessesIndexTransTime on BannedProcesses (TransactionTime)\"",
	
	
	"osql -E -dIpmContent -oIntrusionRuleSetTruncateTable.out -Q \"truncate table IntrusionRuleSet\"",
	"osql -E -dIpmContent -oIntrusionRuleSetDropIndex.out -Q \"drop index IntrusionRuleSet.CkIntrusionRuleSetIndex\"",
	"osql -E -dIpmContent -oIntrusionRuleSetDropIndex.out -Q \"drop index IntrusionRuleSet.IntrusionRuleSetIndexTransTime\"",
	"bcp IpmContent.dbo.IntrusionRuleSet in \"%sInDir%IntrusionRuleSet.dat\" -f\"%sInDir%IntrusionRuleSet.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oIntrusionRuleSetCreateIndex.out -Q \"create unique index CkIntrusionRuleSetIndex on IntrusionRuleSet ([Name]) with IGNORE_DUP_KEY\"",
	"osql -E -dIpmContent -oIntrusionRuleSetIndexTransTime.out -Q \"create clustered index IntrusionRuleSetIndexTransTime on IntrusionRuleSet (TransactionTime)\"",
	
	
	"osql -E -dIpmContent -oIpmContentCategoryHitsTruncateTable.out -Q \"truncate table IpmContentCategoryHits\"",
	"osql -E -dIpmContent -oIpmContentCategoryHitsDropIndex.out -Q \"drop index IpmContentCategoryHits.CkCategoryHits\"",
	"bcp IpmContent.dbo.IpmContentCategoryHits in \"%sInDir%IpmContentCategoryHits.dat\" -f\"%sInDir%IpmContentCategoryHits.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oIpmContentCategoryHitsCreateIndex.out -Q \"create unique clustered index CkCategoryHits on IpmContentCategoryHits (URL, CategoryNumber) with IGNORE_DUP_KEY\"",
	
	
	"osql -E -dIpmContent -oIpmContentCategoryMissesTruncateTable.out -Q \"truncate table IpmContentCategoryMisses\"",
	"osql -E -dIpmContent -oIpmContentCategoryMissesDropIndex.out -Q \"drop index IpmContentCategoryMisses.CkCategoryMisses\"",
	"bcp IpmContent.dbo.IpmContentCategoryMisses in \"%sInDir%IpmContentCategoryMisses.dat\" -f\"%sInDir%IpmContentCategoryMisses.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oIpmContentCategoryMissesCreateIndex.out -Q \"create unique clustered index CkCategoryMisses on IpmContentCategoryMisses (URL, CategoryNumber) with IGNORE_DUP_KEY\"",
	
	
	"osql -E -dIpmContent -oIpmContentDomainTruncateTable.out -Q \"truncate table IpmContentDomain\"",
	"osql -E -dIpmContent -oIpmContentDomainDropIndex.out -Q \"drop index IpmContentDomain.CkDomainIndex\"",
	"osql -E -dIpmContent -oIpmContentDomainDropIndex.out -Q \"drop index IpmContentDomain.DomainIndexTransTime\"",
	"bcp IpmContent.dbo.IpmContentDomain in \"%sInDir%IpmContentDomain.dat\" -f\"%sInDir%IpmContentDomain.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oIpmContentDomainCreateIndex.out -Q \"create unique clustered index CkDomainIndex on IpmContentDomain (DomainName desc) with IGNORE_DUP_KEY\"",
	
	
	"osql -E -dIpmContent -oIpmContentIpAddressTruncateTable.out -Q \"truncate table IpmContentIpAddress\"",
	"osql -E -dIpmContent -oIpmContentIpAddressDropIndex.out -Q \"drop index IpmContentIpAddress.CkIpAddressIndex\"",
	"osql -E -dIpmContent -oIpmContentIpAddressDropIndex.out -Q \"drop index IpmContentIpAddress.IpAddressIndexTransTime\"",
	$bcp_import_ipaddress_table,
	"osql -E -dIpmContent -oIpmContentIpAddressCreateIndex.out -Q \"create unique clustered index CkIpAddressIndex on IpmContentIpAddress (IpAddress) with IGNORE_DUP_KEY\"",
	
	
	"osql -E -dIpmContent -oIpmContentUnknownUrlsTruncateTable.out -Q \"truncate table IpmContentUnknownUrls\"",
	
	
	"osql -E -dIpmContent -oIpmContentURLTruncateTable.out -Q \"truncate table IpmContentURL\"",
	"osql -E -dIpmContent -oIpmContentURLDropIndex.out -Q \"drop index IpmContentURL.CkUrlIndex\"",
	"osql -E -dIpmContent -oIpmContentURLDropIndex.out -Q \"drop index IpmContentURL.UrlIndexTransTime\"",
	"bcp IpmContent.dbo.IpmContentURL in \"%sInDir%IpmContentURL.dat\" -f\"%sInDir%IpmContentURL.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oIpmContentURLCreateIndex.out -Q \"create unique clustered index CkUrlIndex on IpmContentURL (URL desc) with IGNORE_DUP_KEY\"",
	"osql -E -dIpmContent -oIpmContentURLCreateIndex.out -Q \"create index UrlIndexTransTime on IpmContentURL (TransactionTime)\"",
	
	
	"osql -E -dIpmContent -oRegistryControlTruncateTable.out -Q \"truncate table RegistryControl\"",
	"osql -E -dIpmContent -oRegistryControlDropIndex.out -Q \"drop index RegistryControl.CkRegistryControlIndex\"",
	"bcp IpmContent.dbo.RegistryControl in \"%sInDir%RegistryControl.dat\" -f\"%sInDir%RegistryControl.fmt\" -T -q -h\"TABLOCK\"",
	"osql -E -dIpmContent -oRegistryControlCreateIndex.out -Q \"create unique clustered index CkRegistryControl on RegistryControl ([Key], [ValName]) with IGNORE_DUP_KEY\"",
	
	
	"osql -E -dIpmContent -oSpamPatternsTruncateTable.out -Q \"truncate table SpamPatterns\"",
	"osql -E -dIpmContent -oSpamPatternsDropIndex.out -Q \"drop index SpamPatterns.CkSpamPatternsIndex\"",
	"osql -E -dIpmContent -oSpamPatternsDropTransIndex.out -Q \"drop index SpamPatterns.SpamPatternsIndexTransTime\"",
	"bcp IpmContent.dbo.SpamPatterns in \"%sInDir%SpamPatterns.dat\" -f\"%sInDir%SpamPatterns.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oSpamPatternsCreateIndex.out -Q \"create unique index CkSpamPatternsIndex on SpamPatterns ([Name]) with IGNORE_DUP_KEY\"",
	"osql -E -dIpmContent -oSpamPatternsCreateTransIndex.out -Q \"create clustered index SpamPatternsIndexTransTime on SpamPatterns (TransactionTime)\"",
	
	
	"osql -E -dIpmContent -oDisinfectScriptsTruncateTable.out -Q \"truncate table DisinfectScripts\"",
	"osql -E -dIpmContent -oDisinfectScriptsDropIndex.out -Q \"drop index DisinfectScripts.CkDisinfectScriptsIndex\"",
	"osql -E -dIpmContent -oDisinfectScriptsDropTransIndex.out -Q \"drop index DisinfectScripts.DisinfectScriptsIndexTransTime\"",
	"bcp IpmContent.dbo.DisinfectScripts in \"%sInDir%DisinfectScripts.dat\" -f\"%sInDir%DisinfectScripts.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oDisinfectScriptsCreateIndex.out -Q \"create unique clustered index CkDisinfectScriptsIndex on DisinfectScripts (VirusName) with IGNORE_DUP_KEY\"",
	"osql -E -dIpmContent -oDisinfectScriptsCreateTransIndex.out -Q \"create index DisinfectScriptsIndexTransTime on DisinfectScripts (TransactionTime)\"",
	
	
	"osql -E -dIpmContent -oIpmContentSourceTruncateTable.out -Q \"truncate table IpmContentSource\"",
	"bcp IpmContent.dbo.IpmContentSource in \"%sInDir%IpmContentSource.dat\" -f\"%sInDir%IpmContentSource.fmt\" -E -T -h\"TABLOCK\"",
	
	
	"osql -E -dIpmContent -oIpmContentTransactionTruncateTable.out -Q \"truncate table IpmContentTransaction\"",
	"osql -E -dIpmContent -oIpmContentTransactionDropIndex.out -Q \"drop index IpmContentTransaction.CkTransactionIndex\"",
	"bcp IpmContent.dbo.IpmContentTransaction in \"%sInDir%IpmContentTransaction.dat\" -f\"%sInDir%IpmContentTransaction.fmt\" -T -h\"TABLOCK\"",
	"osql -E -dIpmContent -oIpmContentTransactionCreateIndex.out -Q \"create unique clustered index CkTransactionIndex on IpmContentTransaction (SourceNumber, TableName) with IGNORE_DUP_KEY\"",
	
	
	"osql -E -dIpmContent -oIpmContentIpAddressRowDropIndex.out -Q \"drop index IpmContentIpAddressRow.CkIpAddressRowIndex\"",
	"osql -E -dIpmContent -oIpmContentIpAddressRowNameDropIndex.out -Q \"drop index IpmContentIpAddressRow.CkIpAddressRowNameIndex\"",
	"osql -E -dIpmContent -oIpmContentIpAddressRowTruncateTable.out -Q \"truncate table IpmContentIpAddressRow\"",
	
	"osql -E -dIpmContent -oIpmContentURLRowDropIndex.out -Q \"drop index IpmContentURLRow.CkUrlRowIndex\"",
	"osql -E -dIpmContent -oIpmContentURLRowNameDropIndex.out -Q \"drop index IpmContentURLRow.CkUrlRowNameIndex\"",
	"osql -E -dIpmContent -oIpmContentURLRowTruncateTable.out -Q \"truncate table IpmContentUrlRow\"",
	
	"osql -E -dIpmContent -oIpmContentDomainRowDropIndex.out -Q \"drop index IpmContentDomainRow.CkDomainRowIndex\"",
	"osql -E -dIpmContent -oIpmContentDomainRowNameDropIndex.out -Q \"drop index IpmContentDomainRow.CkDomainRowNameIndex\"",
	"osql -E -dIpmContent -oIpmContentDomainRowTruncateTable.out -Q \"truncate table IpmContentDomainRow\"",
	"osql -E -Q \"alter database IpmContent set Recovery SIMPLE\""
	);
	
	
	
	# These are superceded commands to build the DomainRow, IpAddressRow, and UrlRow tables
	# These commands used to be at the end of the reload_commands, right before the shrinkdatabase command
	#"osql -E -dIpmContent -oIpmContentDomainRowInsert.out -Q \"insert into IpmContentDomainRow (DomainName) select DomainName from IpmContentDomain order by TransactionTime\"",
	#"osql -E -dIpmContent -oIpmContentDomainRowCreateIndex.out -Q \"create clustered index CkDomainRowIndex on IpmContentDomainRow (RowNumber)\"",
	#"osql -E -dIpmContent -oIpmContentDomainRowNameCreateIndex.out -Q \"create index CkDomainRowNameIndex on IpmContentDomainRow (DomainName)\"",
	
	#"osql -E -dIpmContent -oIpmContentIpAddressRowInsert.out -Q \"insert into IpmContentIpAddressRow (IpAddress) select IpAddress from IpmContentIpAddress order by TransactionTime\"",
	#"osql -E -dIpmContent -oIpmContentIpAddressRowCreateIndex.out -Q \"create clustered index CkIpAddressRowIndex on IpmContentIpAddressRow (RowNumber)\"",
	#"osql -E -dIpmContent -oIpmContentIpAddressRowNameCreateIndex.out -Q \"create index CkIpAddressRowNameIndex on IpmContentIpAddressRow (IpAddress)\"",
	
	#"osql -E -dIpmContent -oIpmContentURLRowInsert.out -Q \"insert into IpmContentURLRow (URL) select URL from IpmContentURL order by TransactionTime\"",
	#"osql -E -dIpmContent -oIpmContentURLRowCreateIndex.out -Q \"create clustered index CkUrlRowIndex on IpmContentURLRow (RowNumber)\"",
	#"osql -E -dIpmContent -oIpmContentURLRowNameCreateIndex.out -Q \"create index CkUrlRowNameIndex on IpmContentURLRow (URL)\"",

	# Get rid of the out files
	unlink glob( "*.out" ) if ( ! $opt_debug );
	
	&stop_ipmagic();

    my $msde_sql;
     
	$dbh = &ConnectServer() if ( ! $dbh );
	if ( $dbh )
		{	$msde_sql = &SqlMSDE();
          	$dbh->disconnect if ( $dbh );
		}

	$dbh = undef;
	
	my $no_row_tables = &NoRowTableKey();
	
	
	foreach ( @reload_commands )
		{	next if ( ! $_ );
			chomp( $_ );
			next if ( ! $_ );
			
			my $cmd = $_;
	
			
			# Should I ignore this command?
			my $ignore;
			if ( ! $opt_update )	# Am I not supposed to update the sources and transaction tables?
				{	$ignore = 1 if ( $cmd =~ m/IpmContentSource/ );
					$ignore = 1 if ( $cmd =~ m/IpmContentTransaction/ );
				}
				
     		if ( ( $msde_sql )  ||  ( $no_row_tables ) )# Do not import the Row Table data if the server is running MSDE or there is no row table key
          		{    $ignore = 1 if ( $cmd =~ m/insert into IpmContentDomainRow/ );
          		     $ignore = 1 if ( $cmd =~ m/insert into IpmContentIpAddressRow/ );
          		     $ignore = 1 if ( $cmd =~ m/insert into IpmContentURLRow/ );
          		}
          		
               if ( $ignore )
				{	&lprint( "IGNORING COMMAND: $cmd\n" );
					next;	
				}
			
			
			$cmd =~ s/%sInDir%/$dir\\/g;
			
			&lprint( "$cmd\n" );
			
			system $cmd;
			
			my $ok = &CheckOutFiles();
			
			if ( ! $ok )
				{	&start_ipmagic();
					&lprint( "\nErrors occurred when reloading the database\n" );
					return( undef );
				}
		}
		
	&start_ipmagic();
	
	# Get rid of the out files
	unlink glob( "*.out" ) if ( ! $opt_debug );
	
	&lprint( "\nReloaded the database OK\n" );
	
	return( 1 );	
}



################################################################################
#
sub UpdateTransaction( $ )
#
#  I've reload the database, so now reset the transaction time for any Lightspeed
#  sources
#
################################################################################
{	my $dir = shift;
	
	&lprint( "Updating the table transaction times for any Lightspeed sources ...\n" );

	$dbh = &ConnectServer() if ( ! $dbh );
	if ( ! $dbh )
		{	&lprint( "UpdateTransaction: Unable to connect to the Content database\n" );
			return( undef );
		}
	

	# First get the SourceNumber from the IpmContentSource table where the SourceUrl is a Lightspeed URL
	$dbh = &SqlErrorCheckHandle( $dbh );
	return( undef ) if ( ! $dbh);
	return( undef ) if ( $dbh->err );
	
    my $sth = $dbh->prepare( "select SourceUrl, SourceNumber from IpmContentSource" );
    $sth->execute();
	 	
	my @lightspeed_sources;
	my %lightspeed_urls;
	
	while ( ( ! $dbh->err )  &&  ( my ( $source_url, $source_number ) = $sth->fetchrow_array() ) )
		{	&SqlSleep();
			
			next if ( ! defined $source_number );
			next if ( ! defined $source_url );
			
			$source_url = lc( $source_url );

			if ( ( $source_url =~ m/contentdb/i )  ||
				( $source_url =~ m/opendb/i )  ||
				( $source_url =~ m/securityagent/i ) )
				{	&lprint( "Source URL $source_url is from Lightspeed\n" );
					push @lightspeed_sources, $source_number;
					$lightspeed_urls{ $source_number } = $source_url;
				}
		}
		
		
	&SqlErrorHandler( $dbh );
	$sth->finish();


	# Did i find any source numbers?
	if ( ! defined $lightspeed_sources[ 0 ] )
		{	&lprint( "Could not find any Lightspeed sources to update the transaction times\n" );
			return( 1 );	
		}
		
		
	# Set the time to midnight today
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d", $year, $mon, $mday, 0, 0, 0 );
	
	
	# Set each tables transaction time to the datestr for any Lightspeed Source numbers
	foreach ( @lightspeed_sources )
		{	next if ( ! defined $_ );
			my $source_number = $_;
			my $source_url = $lightspeed_urls{ $source_number };
			
			&lprint( "Setting the transaction times to $datestr for Source URL $source_url\n" );
			
			$dbh = &SqlErrorCheckHandle( $dbh );
			return( undef ) if ( ! $dbh);
			return( undef ) if ( $dbh->err );
			
			my $str = "UPDATE IpmContentTransaction SET TransactionTime = \'$datestr\' WHERE SourceNumber = $source_number";
			$sth = $dbh->prepare( $str );
			$sth->execute();
			 
			&SqlErrorHandler( $dbh );
			$sth->finish();
		}
		
		
	$dbh->disconnect if ( $dbh );
	$dbh = undef;
	
	&lprint( "Updated table transaction times OK\n" );
	
	return( 1 );		
}



my $stopped_service;	# True if I had to stop the service
################################################################################
#
sub stop_ipmagic( $ )
#
#  Stop the IpMagic service
#
################################################################################
{	
	if ( ! &ProcessRunning( "IpmService.exe" ) )
		{	&lprint( "No need to stop IP Magic - the IP Magic Service is not currently running\n" );
			return( undef );
		}

	&lprint( "Stopping IP Magic services\n" );
	system "net stop \"IP Magic Service\"";
	
	$stopped_service = 1;
	
	return( 1 );
}



################################################################################
#
sub start_ipmagic( $ )
#
#  Stop the IpMagic service
#
################################################################################
{	return( undef ) if ( ! $stopped_service );  # Don't do anything if I didn't actually stop the service
	
	&lprint( "Starting IP Magic services\n" );	
	system "net start \"IP Magic Service\"";
	
	$stopped_service = undef;
	
	return( 1 );
}



################################################################################
#
sub CheckOutFiles( $ )
#
#  osql and bcp commands create .out files - see if any of them have something in
#  them ...
#
################################################################################
{
use Cwd;

	my $old_cwd = getcwd;
	$old_cwd =~ s#\/#\\#gm;


	# Get the list of *.out files
	my $ok = opendir( DIRHANDLE, $old_cwd );
	return( 1 ) if ( ! $ok );
		
	my @out_files;
	
	for my $item ( readdir( DIRHANDLE ) )
		{	next if ( ! $item );
			next if ( $item eq "." );
			next if ( $item eq ".." );

			$item = lc( $item );
			
			next if ( ! ( $item =~ m/\.out$/ ) );
			
			my $full_file = $old_cwd . "\\$item";
			
			push @out_files, $full_file;
			
			# Keep track of these tmp files
			push @tmp_files, $full_file;
		}
		
	closedir( DIRHANDLE );


	# Go through each of the out files
	foreach ( @out_files )
		{	next if ( ! $_ );
			my $out_file = $_;
			
			if ( ! -e $out_file )
				{
				}
			elsif ( ! -s $out_file )	# If the out file is empty, delete it
				{	unlink( $out_file );
				}
			else
				{	open( OUTFILE, "<$out_file" ) or next;
					
					&ltprint( "Command results from $out_file:\n" );
					
					while ( my $line = <OUTFILE> )
						{	next if ( ! defined $line );
							&ltprint( $line );
						}
					
					close( OUTFILE );
					
					unlink( $out_file );
				}
		}
		
	return( 1 );	
}



################################################################################
#
sub RestoreLocal( $ )
#
#  Restore the local entries
#
################################################################################
{	my $dir = shift;

	$dbh = &ConnectServer() if ( ! $dbh );
	if ( ! $dbh )
		{	&lprint( "RestoreLocal: Unable to connect to the Content database\n" );
			return( undef );
		}
		
	foreach ( @tables )
		{	next if ( ! defined $_ );
			my $table = $_;
			
			&lprint( "\nRestoring data from table $table ...\n" );
			
			my $lc_table = lc( $table );
			
			
			# Open a file to read this data from
			my $handle;
			my $datafile = "$dir\\$table.sql.dat";
			
			if ( ! open( $handle, "<$datafile" ) )
				{	&lprint( "Unable to open backup data file $datafile: $!\n" );
					next;	
				}
				
			
			# Keep track of these tmp files
			push @tmp_files, $datafile;
			
			
			my @columns = &ReadColumn( $handle, 0 );
			
			# Figure out the number of columns in this table
			my $column_count = $#columns;
			
			if ( ! $columns[ 0 ] )
				{	&lprint( "No column data from data file $datafile\n" );
					close( $handle );
					$handle = undef;
					next;	
				}
			
			
			# Find the key column number
			my $key_name = $table_key{ $table };
			
			if ( ! $key_name )
				{	&lprint( "No key defined for table $table\n" );
					close( $handle );
					$handle = undef;
					next;	
				}
			
			my $lc_key_name = lc( $key_name );
			my $key_column;	
			my $ipaddress_column;	# If an IpAddress is in the table, I have to do a bind parameter
			my $counter = 0 + 0;
			foreach ( @columns )
				{	next if ( ! $_ );
					
					my $lc_column = lc( $_ );
					
					$key_column = $counter if ( $lc_key_name eq $lc_column );
					$ipaddress_column = $counter if ( "ipaddress" eq $lc_column );
					$counter++;
				}
				

			# Did I find the column that the key is in?
			if ( ! defined $key_column )
				{	&lprint( "No key column found for table $table\n" );
					close( $handle );
					$handle = undef;
					next;	
				}
				
				
			# Now insert the local data back into the database
			
			# Build up the column names in the right format for an insert
			my $column_names;
			
			foreach ( @columns )
				{	next if ( ! $_ );
					
					$column_names = $column_names . ", " . $_ if ( $column_names );
					$column_names = $_ if ( ! $column_names );
				}
				
			my $data_counter = 0 + 0;
			
			&lprint( "Starting insert for table $table\n" );
			my $done;
			while ( ! $done )
				{	my @column_data = &ReadColumn( $handle, $column_count );

					last if ( ! defined $column_data[ 0 ] );
				
					# Delete any row that matches my key
					my $key_value = $column_data[ $key_column ];
					
					# Changed single quotes into double single quotes for the column key
					$key_value =~ s/\'/\'\'/g;

					my $str = "DELETE $table WHERE $key_name = \'$key_value\'";
					
					# Special case for Ip Address
					$str = "DELETE $table WHERE $key_name = ?" if ( $lc_key_name eq "ipaddress" );
						
					$dbh = &SqlErrorCheckHandle( $dbh );

					return( undef ) if ( ! $dbh);
					return( undef ) if ( $dbh->err );
			
					my $sth = $dbh->prepare( $str );
					
					$sth->bind_param( 1, $key_value, DBI::SQL_BINARY ) if ( $lc_key_name eq "ipaddress" );

					$sth->execute();
					
					$dbh = &SqlErrorCheckHandle( $dbh );
					return( undef ) if ( ! $dbh);
					return( undef ) if ( $dbh->err );
					$sth->finish();
					
					# If no problems, go ahead and insert the row data back in
					my $values;
					$counter = 0 + 0;
					my $ip_address;
					foreach ( @column_data )
						{	next if ( ! defined $_ );
							
							my $data = $_;
							
							# Changed single quotes into double single quotes for each column data
							my $quoted = $data;
							$quoted =~ s/\'/\'\'/g;
							
							my $val = "\'$quoted\'";	# Put single quotes around it
							$val = 'NULL' if ( $data eq 'NULL' );	# Is it an undefined value?
							
							
							# Is it an IP Address column?
							if ( ( defined $ipaddress_column )  &&  ( $counter eq $ipaddress_column ) )
								{	$val = "?" ;
									$ip_address = $data;
								}
								
							$values = $values . ", " . $val if ( $values );
							$values = $val if ( ! $values );
							
							$counter++;
						}

									
					$str = "INSERT INTO $table ( $column_names ) VALUES ( $values )";


					# Special case for IpmContentCategory table
					if ( $lc_table eq "ipmcontentcategory" )
						{	my $category_insert = "set identity_insert IpmContent..IpmContentCategory on " . $str . " set identity_insert IpmContent..IpmContentCategory off";
							$str = $category_insert;
						}
						
						
					$dbh = &SqlErrorCheckHandle( $dbh );


					return( undef ) if ( ! $dbh);
					return( undef ) if ( $dbh->err );
			
					$sth = $dbh->prepare( $str );
					$sth->bind_param( 1, $ip_address, DBI::SQL_BINARY ) if ( defined $ip_address );
					$sth->execute();
					
					if ( $dbh->err )
						{	my $sql_errmsg	= $dbh->errstr;
							my $err			= $dbh->err;
							$sql_errmsg = "SQL error number = $err" if ( ! $sql_errmsg );
	
							&lprint( "SQL Error: $sql_errmsg" );
							&lprint( "SQL Statement: $str" );
						}
						
					$sth->finish();
					$data_counter++;
				}
				
			close( $handle );
			$handle = undef;

			
			&lprint( "Restored $data_counter rows of local data for table $table\n" );
		}
		
		
	$dbh->disconnect if ( $dbh );
	$dbh = undef;


	return( 1 );	
}



################################################################################
# 
sub email_results()
#
################################################################################
{	
use MIME::Base64;

	&lprint( "Emailing results using $monitor_server as a HTML Email Relay\n" );
	
	my $software_dir = &SoftwareDirectory();
	
	chdir( $software_dir );
		
	my $log_file = $software_dir . "\\SqlReload.log";
	
	
	# Add the errors file back into the log file
	my $errors_file = $software_dir . "\\SqlReloadErrors.log";
	
	if ( ( -e $errors_file )  &&  ( -s $errors_file ) )
		{	open( ERRORS, "<$errors_file" );
			&lprint( "\nSqlReloadErrors.log contents:\n" );
			
			while ( my $line = <ERRORS> )
				{	next if ( ! defined $line );
					&lprint( $line );
				}
			close( ERRORS );
		}
		
		
	# Build up the email message
	my $filename	= "SqlReloadResults";
	my $from		= "support\@lightspeedsystems.com";
	
	my @to;
	
	push @to, "support\@lightspeedsystems.com";
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time );
	$year = 1900 + $year;
	$mon = $mon + 1;	 
	my $datestr = sprintf( "%04d\-%02d\-%02d %02d\:%02d\:%02d", $year, $mon, $mday, $hour, $min, $sec );
	my $filestr = sprintf( "%04d%02d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min, $sec );

	$filename .= $filestr;
	$filename .= $to[ 0 ] . ".txt";
	
	
	my $subject = "SqlReload results";
	
	my $hostname = &MonitorHostname();
	$subject = $subject . " from $hostname" if ( $hostname );
	
	# Build the message to send
	my ( $header, $b ) = &MailHeader( $from, $subject, @to );

	my $message = $header;
   
	# Buid up a text message as the first part of the multipart
    $message .= sprintf"\n--%s\n",$b;       
	$message .= "Content-Type: text/plain;\n";
	$message .= "	charset=\"us-ascii\"\n";
	$message .= "Content-Transfer-Encoding: quoted-printable\n\n";
	
    $message .= "=20\n\n";
	
    my $text;
		
	$text = "Here are the results from the SqlReload program\.";
	
	$message .= $text . "=20\n\n";
	
	$message .= sprintf"\n--%s\n",$b;
		  
	$message .= "Content-Type: application/x-zip-compressed;
	name=\"SqlReload.log\"
Content-Transfer-Encoding: base64
Content-Description: sqlreload.log
Content-Disposition: attachment;
	filename=\"SqlReload.log\"
\n";
	
	
	open( INFILE, "<$log_file" );
	binmode( INFILE );
	
	my $buf;
	my $len = 0 + 57;
	
	while ( read( INFILE, $buf, $len ) )
		{	my $outbuf = encode_base64( $buf );
			$message .= "$outbuf";
		}
		
	close( INFILE );
		 
	$message .= sprintf"\n--%s\n",$b;
	$message .= ".\n";
	
	my ( $ok, $msg ) = &PostMessageFile( $monitor_server, $filename, $from, $message, undef, undef, @to );
	
	&lprint( "Emailed results OK\n" ) if ( $ok );
	return( $ok ) if ( $ok );
	
	&lprint( "Error emailing results: $msg\n" );
	
	return( undef );
}



################################################################################
# 
sub CheckDatabaseFormat( $ )
#
#	Check to make sure the local database has the format of the downloaded database
#
################################################################################
{	my $dir = shift;

	&lprint( "Checking the database format ...\n" );
	
	my $ok = 1;
	
	# First, build all the local format files
	foreach ( @tables )
		{	next if ( ! defined $_ );
			my $table = $_;
			
			my $table_dat		= "$dir\\$table.local.dat";
			my $table_fmt		= "$dir\\$table.local.fmt";
			my $original_fmt	= "$dir\\$table.fmt";
			
			
			# Does the original format file exist?
			if ( ! -e $original_fmt )
				{	&lprint( "Table $table does not have a format file $original_fmt\n" );
					$ok = undef;
					next;
				}
				
				
			unlink( $table_fmt );
			unlink( $table_dat );
			
			system "bcp IpmContent.dbo.$table format \"$table_dat\" -f \"$table_fmt\" -n -T";
			
			
			# Keep track of these tmp files
			push @tmp_files, $table_dat;
			push @tmp_files, $table_fmt;
			push @tmp_files, $original_fmt;
			
			
			# Did I have a problem creating the local format file?
			if ( ! -e $table_fmt )
				{	&lprint( "Unable to create local format table $table_fmt\n" );
					$ok = undef;
					next;
				}
				
				
			&lprint( "Created local format table $table_fmt\n" ) if ( -e $table_fmt );
			&lprint( "Error: unable to created local format table $table_fmt\n" ) if ( ! -e $table_fmt );
			
			# Get rid of the empty data table
			unlink( $table_dat );

			# Is the local database different than the downloaded database?
			if ( &FormatCompare( $table, $original_fmt, $table_fmt ) )
				{	&ltprint( "\nTable $table has a different format locally than the format from Lightspeed\n" );
					
					&ltprint( "\nLightspeed format:\n" );
					&LogFile( $original_fmt );
					
					&ltprint( "\nLocal format:\n" );
					&LogFile( $table_fmt );
					
					&ltprint( "\n" );
					
					$ok = undef;
				}
		}

	&lprint( "Done checking the database format\n" );
	
	return( $ok );
}



################################################################################
#
sub LogFile( $ )
#
#  Give a text file, lprint it into this program's log file
#
################################################################################
{	my $file = shift;
	
	if ( ! -e $file )
		{	&lprint( "File $file does not exist\n" );
			return( undef );
		}
		
	if ( ! open( LOG, "<$file" ) )
		{	&lprint( "Error opening file $file: $!\n" );
			return( undef );
		}
	

	while ( my $line = <LOG> )
		{	next if ( ! defined $line );
			&ltprint( "$line" );
		}
		
	close( LOG );
	
	return( 1 );	
}



################################################################################
#
sub FormatCompare( $$$ )
#
#  Compare 2 format files.  If the files are different, return TRUE
#
################################################################################
{	my $table	= shift;
	my $from	= shift;
	my $to		= shift;
	
	use File::Compare 'cmp';

	return( undef ) if ( ! defined $table );
	return( undef ) if ( ! defined $from );
	return( undef ) if ( ! defined $to );
	
	# Do the files exist?
	return( 1 ) if ( !-e $from );
	return( 1 ) if ( !-e $to );
	
	
	# We added a column called KBID to a couple of tables, so their format may not
	# match, but the import should still work
	return( undef ) if ( $table =~ m/IpmContentCategory/i );
	return( undef ) if ( $table =~ m/DisinfectScripts/i );
	return( undef ) if ( $table =~ m/IntrusionRuleSet/i );
	return( undef ) if ( $table =~ m/VirusSignatures/i );
	
	
	# We added a column called 'ID' to the front of this table in version 6.02, but the import should still work
	return( undef ) if ( $table =~ m/RegistryControl/i );
	
	
	# We added a column called StarRating in version 6.3, but the import should still work
	return( undef ) if ( $table =~ m/IpmContentDomain/i );
	return( undef ) if ( $table =~ m/IpmContentIPAddress/i );
	return( undef ) if ( $table =~ m/IpmContentURL/i );


	# We added a column called AppType in version 7.1, but the import should still work
	return( undef ) if ( $table =~ m/ApplicationProcesses/i );

	
	# Read each file - ignoring the first line which is the database version, and compressing white space
	if ( ! open( FORMAT_FROM, "<$from" ) )
		{	lprint "Error opening format file $from: $!\n";
			return( 1 );
		}


	# Read the from formatted file ...	
	my $count = 0 + 0;
	my $from_fmt = "";
	while ( my $line = <FORMAT_FROM> )
		{	$count++;
			
			# Ignore the first line
			next if ( $count == 1 );
			
			chomp( $line );
			$line =~ s/\s//g;
			
			# Get rid of the field separator
			$line =~ s/\~\~\~\~\~// if ( $line );
			
			$from_fmt .= $line;
		}
		
	close( FORMAT_FROM );
	
	
	if ( ! open( FORMAT_TO, "<$to" ) )
		{	lprint "Error opening format file $to: $!\n";
			return( 1 );
		}
		
		
	# Read the to formatted file ...	
	$count = 0 + 0;
	my $to_fmt = "";
	while ( my $line = <FORMAT_TO> )
		{	$count++;
			
			# Ignore the first line
			next if ( $count == 1 );
			
			chomp( $line );
			$line =~ s/\s//g;
			
			# Get rid of the field separator
			$line =~ s/\~\~\~\~\~// if ( $line );
			
			$to_fmt .= $line;
		}
		
	close( FORMAT_TO );


	return( 1 ) if ( $from_fmt ne $to_fmt );
	
	return( undef );
}



################################################################################
sub Integer( $ )	 # Round off to 0 decimal places
################################################################################
{	my $val = shift;
	
	$val =~ s/\,/\./g;	# Get rid of commas
	my $rnd = 0.005 + $val;
	$rnd = sprintf( "%.0f", $rnd );
	$rnd =~ s/\,//g;	# Get rid of commas
	$rnd =~ s/\.//g;	# Get rid of dots
	$rnd = 0 + $rnd;
	
	return( $rnd );
}



my %new_process_hash;				# New process hash, hash key is pid, value if process path
################################################################################
# 
sub ProcessRunning( $ )
#
# Return TRUE if the process is currently running, undef if not
#
################################################################################
{	my $process = shift;
	
	&ProcessHash;
	
	my @process_names = values %new_process_hash;
	
	my $found;
	$process = lc( $process );
	foreach ( @process_names )
		{	next if ( ! $_ );
			my $full_path = lc( $_ );
			$found = 1 if ( $full_path =~ m/$process/ );
			
		}
		
	return( $found );
}



################################################################################
# 
sub ProcessHash()
#
#  Return the hash of processes that are currently running - and save it into 
# the %new_process_hash
#
################################################################################
{
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
	my $GetModuleFileNameEx = new Win32::API( 'psapi.dll', 'GetModuleFileNameEx', 'NNPN', 'N' );
	my( $BufferSize ) = $MODULE_LIST_SIZE * $DWORD_SIZE;
	my( $MemStruct ) = MakeBuffer( $BufferSize );
		
	
	foreach ( @PidList )
		{	next if ( ! $_ );	# Ignore the idle process
			
			my $pid = $_;
			
			my( $hProcess ) = $OpenProcess->Call( $PROCESS_QUERY_INFORMATION | $PROCESS_VM_READ, 0, $pid );

			next if ( ! $hProcess );
		
			my( $StringSize ) = 255 * ( ( Win32::API::IsUnicode() )? 2 : 1 );
            my( $FileName ) = MakeBuffer( $StringSize );
			my( @ModuleList ) = unpack( "L*", $MemStruct );
            my $hModule = $ModuleList[0];

            my $TotalChars;

			if( $TotalChars = $GetModuleFileNameEx->Call( $hProcess, $hModule, $FileName, $StringSize ) )
				{	my $name = FixString( $FileName );				
					$new_process_hash{ $pid } = $name;
				}

			$CloseHandle->Call( $hProcess );
		}

	return( %new_process_hash );
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
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename;
	my $dir = &SoftwareDirectory();

	$filename = $dir . "\\SqlReloadErrors.log";
	
	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or &lprint( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	&lprint( "Set error logging set to SqlReloadErrors.log\n" ); 
}



################################################################################
# 
sub CheckDiskSpace( $ )
#
#  Check to make sure that the disk drive of the working directory has enogh space
#
################################################################################
{	my $dir = shift;
	my $result;
use Win32::DriveInfo;
	
	
	my ( $drive, $junk ) = split /:/, $dir;
	
	$drive = $drive . ":";
	
	&lprint( "Checking the free space on drive $drive ...\n" );
	
	my $free = ( Win32::DriveInfo::DriveSpace( $drive ) )[ 6 ];
	
			
	# If I can't figure out the free space, assume it is enough
	if ( ! defined $free )
		{	&lprint( "Can\'t figure out free disk space - so continuing anyway\n" );
			return( 1 );
		}
	
	my $free_megs = $free / ( 1024 * 1024 );
	$free_megs = &Integer( $free_megs );
		
	if ( $free_megs < 500 )
		{	&lprint( "Not enough disk space free - only $free_megs Megs\n" );
			return( undef );
		}
	
	&lprint( "$free_megs Megs disk space available\n" );

	return( 1 );
}



################################################################################
# 
sub NoRowTableKey()
#
#  Return True if there isn't a registry key to enable row tables,
#   undef if row tables are enabled
#
################################################################################
{   my  $key;
    my  $type;
    my  $data;
  
    my $ok = &RegOpenKeyEx( HKEY_LOCAL_MACHINE, "SOFTWARE\\Lightspeed Systems\\IP Magic Service\\Configurations\\00001\\Content Filtering", 0, KEY_READ, $key );

	# If the key is totally missing, return row tables enabled
    return( undef )  if ( ! $ok );

    $ok = &RegQueryValueEx( $key, "RowTable", [], $type, $data, [] );

	&RegCloseKey( $key );

	# If I didn't read any data at all out of the registry, then I must not be using row tables
	return( 1 ) if ( ! $ok );
	return( 1 ) if ( ! length( $data ) );
	return( 1 ) if ( length( $data ) < 0 );

	# If the data value is a DWORD eq 1, then it is enabled and I return undef
	return( undef ) if ( $data eq "\x01\x00\x00\x00" );
		
	return( 1 );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "SqlReload";

    bprint <<".";
Usage: $me

This utility backups up the locally added database entries, transfers a new
database from Lightspeed, imports the database into SQL, and then restores 
the local database entries.  It will stop and start the IP Magic service if 
necessary.  If the local database is formatted differently than the
Lightspeed database you can use the -c (create) option to drop and create
the tables.

  -b, --backup            Only backup local table data
  -c, --notcreate         To NOT drop and recreate the tables
  -d, --directory dir     To set the working directory to dir
                          (default is Traffic\\ContentFilterInitData) 
  -f, --format            Only check the database format
  -l, --local             Use local database.zip file instead of downloading
  -m, --monitor server    To use server as the monitor to relay emails 
  -n, --noemail           Don't email SqlReload.log back to support
  -r, --restore           Only restore local table data
  -s, --source sourcenum  Backup up data with source <= sourcenum
  -t, --table tablename   Only do operations on the given tablename
  -u, --update            Reload the update sources transaction data
  -v, --verbose           display extented information
  -h, --help              display this help and exit
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
    my $me = "SqlReload";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}



__END__

:endofperl
