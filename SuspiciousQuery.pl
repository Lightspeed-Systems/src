################################################################################
#!perl -w
#
# Rob McCarthy's Suspicious Query source code
#  Copyright 2004 Lightspeed Systems Corp.
# Go through the Search Engire Query table looking for Suspicious Queries
# Move the Suspicious Querys into their own table
#
################################################################################



# Pragmas
use strict;
use warnings;

use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Win32;
use Win32API::Registry 0.21 qw( :ALL );
use Win32::Event;


use Content::File;
use Content::SQL;
use Content::Process;



# Options
my $opt_help;
my $opt_version;
my $opt_verbose;
my $opt_all;										# If True then process all the search queries in the database
my $opt_debug; 										# True if I should write to a debug log file


# Globals
my $_version = "1.0.0";
my $dbhStat;										# My database handle
my $suspicious		= "SuspiciousQueryNew.txt";		# The file holding the suspicious queries to check
my $suspicious_time = "SuspiciousQueryNew.dat";		# The file holding the time and query that I last looked at
my $custom			= "CustomSuspiciousQuery.txt";	# The file holding the custom queries to check
my @querys;											# A multidimensional array holding the querys
my @expressions;									# The list of regular expressions
my @not_expressions;								# The list of regular NOT expressions
my $total_queries = 0 + 0;
my $total_suspicious = 0 + 0;



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "Suspicious Query" );


    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "a|all"			=> \$opt_all,
        "v|verbose"		=> \$opt_verbose,
        "h|help"		=> \$opt_help,
        "x|xxx"			=> \$opt_debug
    );


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


	&KillOtherSuspiciousQuery();
	

	&TrapErrors() if ( ! $opt_debug );
	
	&SetLogFilename( "SuspiciousQuery.log", undef );
	
	&lprint( "Checking all the search engine queries in the database\n" ) if ( $opt_all );;
	&lprint( "Verbose mode\n" ) if ( $opt_verbose );
	

	# Clear the expressions arrays
	@expressions = ();	
	@not_expressions = ();	
	
	my $count = &LoadSuspicious( $suspicious );
	if ( ! $count )
		{	&lprint( "Unable to load any suspicious queries from file $suspicious\n" );
			exit( 1 );
		}

	&lprint( "Loaded $count suspicious query wildcards to check from file $suspicious\n" );


	$count = &LoadSuspicious( $custom );
	&lprint( "Loaded $count suspicious query wildcards to check from file $custom\n" ) if ( $count );
	
	
#my $check = "arianna huffington";
#my $match = &SuspiciousMatch( $check );
#print "Check $check matched $match\n" if ( defined $match );
#print "Not matched\n" if ( ! defined $match );
#die;

    #  Open the database
    $dbhStat = &ConnectStatistics() or die "Unable to open Statistics database";
	
	if ( ! &StatTableExists( "TrafficClassSearchQuery" ) )
		{	lprint "The TrafficClassSearchQuery table does not exist\n";
			
			#  Clean up everything and quit
			$dbhStat->disconnect;
			exit( 2 );
		}
		
			
	if ( ! &StatTableExists( "TrafficClassSuspiciousSearchQuery" ) )
		{	lprint "The TrafficClassSuspiciousSearchQuery table does not exist\n";
			
			#  Clean up everything and quit
			$dbhStat->disconnect;
			exit( 3 );
		}
		

	if ( $opt_all )
		{	&lprint( "Dropping any old suspicious queries ...\n" );
			
			my $sth = $dbhStat->prepare( "DELETE TrafficClassSuspiciousSearchQuery" );
			$sth->execute();
			
			&SqlErrorHandler( $dbhStat );
			$sth->finish();
			
		}
		
	# Loop through the query tables, processing up to 1,000 suspicious search queries at a time		
	my $done;
	$count = 0 + 0;
	
	my $total_matched = 0 + 0;
	my $total_loaded = 0 + 0;
	
	while ( ! $done )
		{	my ( $matched_count, $loaded_count );
			
print "top of main loop\n" if ( $opt_debug );
			( $matched_count, $loaded_count, $done ) = &LoadSearchTable();
			
			$total_matched += $matched_count;
			$total_loaded += $loaded_count;
			
			if ( $matched_count )
				{	&lprint( "Writing $matched_count suspicious queries to the database ...\n" );
					$count += &WriteSuspiciousTable();
				}
				
print "bottom of main loop\n" if ( $opt_debug );
			$done = 1 if ( ! $loaded_count );
		}
		
		
	#  Clean up everything and quit
	$dbhStat->disconnect;

	lprint "Searched through $total_loaded search engine queries total\n";
	lprint "Found $total_matched new suspicious search engine queries\n" if ( $total_matched );
	lprint "Did not find any new suspicious search engine queries\n" if ( ! $total_matched );
	
	&StdFooter;

exit( 0 );
}
################################################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $dir = &SoftwareDirectory();
	my $filename = $dir . "\\SuspiciousQueryErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or die( "Unable to open $filename: $!\n" );  
		
	&CarpOut( $MYLOG );
   
	&debug( "Fatal error trapping set to file $filename\n" ); 
}



################################################################################
# 
sub KillOtherSuspiciousQuery()
#
#  Make sure that I'm the only SuspiciousQuery program running
#
################################################################################
{	
	# At this point I've been nice - now I'm getting mean
	my $my_pid = &ProcessGetCurrentProcessId();

	my %processes = &ProcessHash();
	
	# Figure out if there are any SuspiciousQuery processes running besides myself
	my @process_names	= values %processes;
	my @process_pids	= keys %processes;
	
	my @kill_pids;
	
	my $index = 0 - 1;
	foreach ( @process_names )
		{	$index++;
			
			next if ( ! $_ );
			
			my $name = lc( $_ );
			
			# Is this an SuspiciousQuery process?
			next if ( ! ( $name =~ m/suspiciousquery\.exe/ ) );
			
			my $this_pid = $process_pids[ $index ];
			
			next if ( $this_pid eq $my_pid );
	
			push @kill_pids, $this_pid;				 
		}


	print "Found SuspiciousQuery processes being run by other users, so killing them now ...\n" if ( $kill_pids[ 0 ] );
	
	# If I found any, kill them
	foreach ( @kill_pids )
		{	next if ( ! $_ );
			my $kill_pid = $_;
			print "Killing process $kill_pid\n";
			&ProcessTerminate( $kill_pid );
		}
				
	return( 1 );
}



################################################################################
# 
sub LoadSuspicious( $ )
#
#  Load up the search engine querys string to compare
#  Return True if loaded ok, undef if not
#
################################################################################
{	my $file = shift;
	
	return( undef ) if ( ! -e $file );
	
	if ( ! open( FILE, "<$file" ) )
		{	print "Error opening $file: $!\n";
			return( undef );
		}
	
	my $count = 0 + 0;
	
#my @not_sorted;
	while (my $line = <FILE>)
		{	chomp( $line );
			next if ( ! $line );
			my $wildcard = $line;
			
#push @not_sorted, $wildcard;
			my $reg_expression = &ValueToRegExpression( $wildcard );
			next if ( ! defined $reg_expression );
			
			# Is it a NOT expression?
			if ( $reg_expression =~ m/^!/ )
				{	$reg_expression =~ s/^!//;
					push @not_expressions, $reg_expression;
				}
			else
				{	push @expressions, $reg_expression;
				}
				
			$count++;
		}
		
	close FILE;

#my @sorted = sort @not_sorted;
#open( SORTED, ">sorted" );
#foreach ( @sorted )
#	{	print SORTED "$_\n";
#	}
#close( SORTED );

#die;
	return( $count );
}



################################################################################
# 
sub LoadSearchTable()
#
#  Load up to 1000 suspicious search engine queries
#  Return the count the matched, the total count checked, and True if done
#
################################################################################
{	$dbhStat = &SqlErrorCheckHandle( $dbhStat );
	
	
	my ( $last_time, $last_query ) = &GetLastQueryTime();


	# If I'm getting all the search queries, then clear out the last time variable on the first time through
	if ( $opt_all )
		{	$last_time	= undef;
			$opt_all	= undef;	
		}
		
		
	my $str;
	
	if ( $last_time )
		{	$str = "SELECT ObjectID, [Time], CONVERT(BINARY(4), IpAddress) as IpAddress, UserName, HostName, Site, QueryString 
					FROM TrafficClassSearchQuery WITH(NOLOCK) 
					WHERE [Time] > '$last_time'
					ORDER BY [Time]";
			
			&lprint( "Getting search engine queries since $last_time ...\n" );
		}
	else
		{	$str = "SELECT ObjectID, [Time], CONVERT(BINARY(4), IpAddress) as IpAddress, UserName, HostName, Site, QueryString 
				FROM TrafficClassSearchQuery WITH(NOLOCK) 
				ORDER BY [Time]";
			
			&lprint( "Getting all the search engine queries in the database  ...\n" );
		}


	my $sth = $dbhStat->prepare( $str );
	$sth->execute();
	
	&SqlErrorHandler( $dbhStat );
	
	my $count = 0 + 0;
	my $checked = 0 + 0;
	
	my $this_last_time	= $last_time;
	my $this_last_query = $last_query;
			
			
	# Clear the querys array out
	@querys = ();
	
	lprint "Now comparing the search queries to check for suspicious phrases ...\n";
	
	my $progress = 0 + 0;
	my $total_progress = 0 + 0;
	
	while ( my ( $object_id, $time, $ip_address, $user_name, $host_name, $site, $query_string ) = $sth->fetchrow_array() )
		{	# Quit if an error
			last if ( $dbhStat->err );
				
			next if ( ! defined $query_string );
			
			$progress++;
			$total_progress++;
			$total_queries++;
			
			if ( $progress >= 1000 )
				{	lprint "Finished comparing $total_progress queries this pass ($total_queries total)...\n";
					&lprint( "Found $count suspicious queries so far this pass ($total_suspicious total) ...\n" );
					$progress = 0 + 0;
				}
				
			# Don't repeat old stuff
			next if ( ( $last_time )  &&  ( $last_query )  &&  ( $time eq $last_time )  &&  ( $query_string eq $last_query ) );
			
			$checked++;
			
			$this_last_time		= $time;
			$this_last_query	= $query_string;

			my $match = &SuspiciousMatch( $query_string );
			
			next if ( ! defined $match );
			
print "matched $query_string\n" if ( $opt_debug );
	
			# Clean up the query string
			$query_string =~ s/^\s//gm;
			$query_string =~ s/\s$//gm if ( $query_string );

			next if ( ! defined $query_string );
			
			&lprint( "Query: $query_string matched pattern $match\n" );
			
			$querys[ $count ][ 0 ] = $object_id;
			$querys[ $count ][ 1 ] = $time;
			$querys[ $count ][ 2 ] = $ip_address;
			$querys[ $count ][ 3 ] = $user_name;
			$querys[ $count ][ 4 ] = $host_name;
			$querys[ $count ][ 5 ] = $site;
			$querys[ $count ][ 6 ] = $query_string;
			
			$count++;
			$total_suspicious++;
			
			if ( $count > ( 0 + 1000 ) )
				{	&SqlErrorHandler( $dbhStat );
					$sth->finish();
					
					&lprint( "Found $count suspicious queries so far ...\n" );
					
					&SaveLastQueryTime( $this_last_time, $this_last_query );
					
					return( $count, $checked, undef );
				}
print "bottom of fetchrow\n" if ( $opt_debug );
		}


	&SqlErrorHandler( $dbhStat );
	$sth->finish();

	lprint "Read $count suspicious queries\n";
	
	&SaveLastQueryTime( $this_last_time, $this_last_query );
	
	return( $count, $checked, 1 );
}



################################################################################
# 
sub SuspiciousMatch( $ )
#
#  Given a query string, see if it matches one of my suspicious queries
#
#  Return True if it does, undef if not
#
################################################################################
{	my $query = shift;
	
	# Clean up the string
	$query = lc( $query );
	$query =~ s/\-/ /g;		# Subsitute spaces for dashes
	$query =~ s/\"/ /g;		# Subsitute spaces for "
	$query =~ s/\'/ /g;		# Subsitute spaces for '
	$query =~ s/^\s//gm;
	$query =~ s/\s$//gm;
	$query =~ s/\s+/ /gm;  # Changed repeated white space to a single space

	study( $query );
	
	&lprint( "Checking query: $query\n" ) if ( $opt_verbose );

	# Check the NOT expressions first
	foreach ( @not_expressions )
		{	next if ( ! defined $_ );
			my $wildcard = $_;

			return( undef ) if ( $query =~ m/$wildcard/ );
		}
		
	# Now check the match expressions
	foreach ( @expressions )
		{	next if ( ! defined $_ );
			my $wildcard = $_;
			if ( $query =~ m/$wildcard/ )
				{	return( $wildcard );
				}
		}

	return( undef );
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
}



################################################################################
#
sub ValueToRegExpression( $ )
#
#  Given a compare string, return the regular expression
#  to use for a string compare
#
################################################################################
{	my $wildcard = shift;
	
	return( undef ) if ( ! defined $wildcard );
	
	# Clean up the string	
	$wildcard = lc( $wildcard );
	$wildcard =~ s/^\s//gm;
	$wildcard =~ s/\s$//gm;
	
	# Is it a straight string compare?  That is no * or ?
	if ( ( ! ( $wildcard =~ m/\*/ ) )  &&  ( ! ( $wildcard =~ m/\?/ ) ) )
		{	return( $wildcard );
		}
	
	
	# Is it a wildcard before?
	my $before;
	if ( $wildcard =~ m/^\*/ )
		{	$before = 1;
			$wildcard =~ s/^\*//gm;
		}
	
	# Is it a wildcard after?
	my $after;
	if ( $wildcard =~ m/\*$/ )
		{	$after = 1;
			$wildcard =~ s/\*$//gm;
		}

	# Is there a '*' in the middle?
	my $middle;
	$middle = 1 if ( $wildcard =~ m/\*/ );

	
	$wildcard = quotemeta( $wildcard );

	$wildcard = ".*" . $wildcard if ( $before );
	$wildcard = $wildcard . ".*" if ( $after );
	
	
	# Substitute . for \? for single character wildcards
	$wildcard =~ s#\\\?#\.#g;
	

	# Was there an '*' in the middle?
	if ( $middle )
		{	$wildcard =~ s/\\\*/\.\*/g;
		}
	
	
	return( $wildcard );
}



################################################################################
# 
sub GetLastQueryTime()
#
#  Get the time of the last query I have already processed, or undef if
#  I have never processed them, and the last query
#
################################################################################
{	my $time;
	my $query;
print "top of GetLastQueryTime\n" if ( $opt_debug );
	
	my $dir		= &SoftwareDirectory();
	my $file	= $dir . "\\$suspicious_time";
	
	
	# Default to midnight of the current day
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year += 1900;
	$mon++;
	my $datestr = sprintf( "%04d-%02d-%02d 00:00:00.000", $year, $mon, $mday, $hour, $min, $sec );
	
	return( $datestr, "nothing" ) if ( ! open FILE, "<$file" );
		
	my $line = <FILE>;
	
	chomp( $line );
	
	return( $datestr, "nothing" ) if ( ! $line );
	
	( $time, $query ) = split /\t/, $line, 2;
	
	close FILE;
	
	return( $time, $query );
}



################################################################################
# 
sub SaveLastQueryTime( $$ )
#
#  Save the last time and query string I got
#
################################################################################
{   my $time	= shift;
	my $query	= shift;
	
print "top of SaveLastQueryTime\n" if ( $opt_debug );
	return( undef ) if ( ( ! defined $time )  ||  ( ! defined $query ) );
	
	my $dir		= &SoftwareDirectory();
	my $file = $dir . "\\$suspicious_time";
	
	open FILE, ">$file" or return( undef );
	
	print FILE "$time\t$query\n";
	close FILE;
	
	return( 1 );
}



################################################################################
# 
sub WriteSuspiciousTable()
#
#  Go through the loaded search engine queries, copying suspicious ones to the
#  suspicious table.
#
#  Return the count copied to the table
#
################################################################################
{
	my $count = 0 + 0;
	
print "top of WriteSuspiciousTable\n" if ( $opt_debug );
	
	while ( $querys[ $count ][ 0 ] )
		{	my ( $object_id, $time, $ip_address, $user_name, $host_name, $site, $query_string );
			
			$object_id    = $querys[ $count ][ 0 ];
			$time         = $querys[ $count ][ 1 ];
			$ip_address   = $querys[ $count ][ 2 ];
			$user_name    = &quoteurl( $querys[ $count ][ 3 ] );
			$host_name    = &quoteurl( $querys[ $count ][ 4 ] );
			$site         = &quoteurl( $querys[ $count ][ 5 ] );
			$query_string = &quoteurl( $querys[ $count ][ 6 ] );
			
			my @values;
			push @values, "\'" . $object_id . "\',";		# 0 entry
			push @values, "\'" . $time . "\',";				# 1 entry
			
			if ( defined $ip_address )
				{	push @values, "?, ";		# I have to do a bind parameter for an IP address
				}
			else
				{	push @values, 'NULL, ';
				}
				
			push @values, "\'" . $user_name . "\',"		if ( $user_name );		# 3 entry
			push @values, "\'" . "blank" . "\',"		if ( ! $user_name );	# 3 entry
			push @values, "\'" . $host_name . "\',"		if ( $host_name );		# 4 entry
			push @values, "\'" . "unknown" . "\',"		if ( ! $host_name );	# 4 entry
			push @values, "\'" . $site . "\',"			if ( $site );			# 5 entry
			push @values, "\'" . "unknown site" . "\',"	if ( ! $site );			# 5 entry
			push @values, "\'" . $query_string . "\'";		# 6 entry
			
			
			my $value;
			foreach ( @values )
				{	$value .= $_ if ( $value );
					$value = $_ if ( ! $value );
				}
				
			my $str = "INSERT INTO TrafficClassSuspiciousSearchQuery ( ObjectId, [Time], IpAddress, UserName, HostName, Site, QueryString ) VALUES ( $value )";

			$dbhStat = &SqlErrorCheckHandle( $dbhStat );
			my $sth = $dbhStat->prepare( $str );
			
			$sth->bind_param( 1, $ip_address, DBI::SQL_BINARY ) if ( defined $ip_address );

			if ( ! $sth->execute() )
				{	lprint "Error inserting into database query $query_string\n";
					
					&SqlErrorHandler( $dbhStat );	
					$sth->finish();
					last;
				}
			else
				{	$count++;
				}
			
			&SqlErrorHandler( $dbhStat );	
			$sth->finish();
		}
		
	
	lprint "Wrote $count suspicious queries to the Statistics database\n" if ( $count );
	
	return( $count );
}




################################################################################
# 
sub StatTableExists( $ )
#
#  Return True if a database table exists in the Statistics database, undef if not
#
################################################################################
{	my $tablename = shift;
	
	$dbhStat = &SqlErrorCheckHandle( $dbhStat );
	return( undef ) if ( ! $dbhStat );
	return( undef ) if ( $dbhStat->err );
	
    my $sth = $dbhStat->prepare( "select name from sysobjects where name = '$tablename'" );
    $sth->execute();
	 
	my $exists;
	while ( ( ! $dbhStat->err )  &&  (  my ( $name ) = $sth->fetchrow_array() ) )
        {  $exists = 1;
	    }
	
	&SqlErrorHandler( $dbhStat );	
	$sth->finish();
	
	return( undef ) if ( ! $dbhStat );
	return( undef ) if ( $dbhStat->err );
	
	return( $exists );
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
sub debug( @ )
#
#  Print a debugging message to the log file
#
################################################################################
{
     return if ( !$opt_debug );

     lprint( @_ );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "Suspicious Query";

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
    my $me = "Suspicious Query";

    bprint <<".";
Usage: $me
This utility goes through the Search Engine Query table, copying suspicious
looking querys into the Suspicious Query table.  By default it processes the
queries done since the last time it was run.

  -a, --all              process all the queries in the database
                         drops any old suspicious queries  
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
    my $me = "Suspicious Query";

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
