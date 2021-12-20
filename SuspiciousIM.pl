################################################################################
#!perl -w
#
# Rob McCarthy's Suspicious IM source code
#  Copyright 2006 Lightspeed Systems Corp.
# Go through the TrafficClassInstantMsg table looking for Suspicious IMs
# Move the Suspicious IMs into their own table - TrafficClassSuspiciousIM
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
my $suspicious		= "SuspiciousQueryNew.txt";		# The file holding the suspicious strings to check
my $suspicious_time = "SuspiciousIM.dat";			# The file holding the time and query that I last looked at
my $custom			= "CustomSuspiciousQuery.txt";	# The file holding the custom strings to check
my @ims;											# A multidimensional array holding the ims
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
    &StdHeader( "Suspicious IM" );


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


	&KillOtherSuspiciousIM();
	

	&TrapErrors() if ( ! $opt_debug );
	
	&SetLogFilename( "SuspiciousIM.log", undef );
	
	&lprint( "Checking all the instant messages in the database\n" ) if ( $opt_all );;
	&lprint( "Verbose mode\n" ) if ( $opt_verbose );
	

	# Clear the expressions arrays
	@expressions = ();	
	@not_expressions = ();	
	
	my $count = &LoadSuspicious( $suspicious );
	if ( ! $count )
		{	&lprint( "Unable to load any suspicious queries from file $suspicious\n" );
			exit( 1 );
		}

	&lprint( "Loaded $count suspicious IM wildcards to check from file $suspicious\n" );


	$count = &LoadSuspicious( $custom );
	&lprint( "Loaded $count suspicious IM wildcards to check from file $custom\n" ) if ( $count );
	
	
#my $check = "arianna huffington";
#my $match = &SuspiciousMatch( $check );
#print "Check $check matched $match\n" if ( defined $match );
#print "Not matched\n" if ( ! defined $match );
#die;

    #  Open the database
    $dbhStat = &ConnectStatistics() or die "Unable to open Statistics database";
	
	if ( ! &StatTableExists( "TrafficClassInstantMsg" ) )
		{	lprint "The TrafficClassInstantMsg table does not exist\n";
			
			#  Clean up everything and quit
			$dbhStat->disconnect;
			exit( 2 );
		}
		
			
	if ( ! &StatTableExists( "TrafficClassSuspiciousIM" ) )
		{	lprint "The TrafficClassSuspiciousIM table does not exist so creating it ...\n";
			
			my $str = "CREATE TABLE [dbo].[TrafficClassSuspiciousIM] (
						[ObjectId] [uniqueidentifier] NOT NULL ,
						[Time] [smalldatetime] NOT NULL ,
						[IpAddress] [char] (4) COLLATE SQL_Latin1_General_CP1_CI_AS NOT NULL ,
						[UserName] [varchar] (255) COLLATE SQL_Latin1_General_CP1_CI_AS NOT NULL ,
						[HostName] [varchar] (255) COLLATE SQL_Latin1_General_CP1_CI_AS NOT NULL ,
						[MsgFrom] [varchar] (250) COLLATE SQL_Latin1_General_CP1_CI_AS NOT NULL ,
						[MsgTo] [varchar] (250) COLLATE SQL_Latin1_General_CP1_CI_AS NOT NULL ,
						[MsgText] [varchar] (1000) COLLATE SQL_Latin1_General_CP1_CI_AS NOT NULL )";
			
			my $sth = $dbhStat->prepare( $str );
			$sth->execute();
			$sth->finish();	
		}
			

	if ( $opt_all )
		{	&lprint( "Dropping any old suspicious IM ...\n" );
			
			my $sth = $dbhStat->prepare( "DELETE TrafficClassSuspiciousIM" );
			$sth->execute();
			
			&SqlErrorHandler( $dbhStat );
			$sth->finish();
			
		}
		
	# Loop through the IM tables, processing up to 1,000 suspicious search queries at a time		
	my $done;
	$count = 0 + 0;
	
	my $total_matched = 0 + 0;
	my $total_loaded = 0 + 0;
	
	while ( ! $done )
		{	my ( $matched_count, $loaded_count );
			
print "top of main loop\n" if ( $opt_debug );
			( $matched_count, $loaded_count, $done ) = &LoadIMTable();
			
			$total_matched += $matched_count;
			$total_loaded += $loaded_count;
			
			if ( $matched_count )
				{	&lprint( "Writing $matched_count suspicious IMs to the database ...\n" );
					$count += &WriteIMTable();
				}
				
print "bottom of main loop\n" if ( $opt_debug );
			$done = 1 if ( ! $loaded_count );
		}
		
		
	#  Clean up everything and quit
	$dbhStat->disconnect;

	lprint "Searched through $total_loaded instant messages total\n";
	lprint "Found $total_matched new suspicious instant messages\n" if ( $total_matched );
	lprint "Did not find any new suspicious instant messages\n" if ( ! $total_matched );
	
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
	my $filename = $dir . "\\SuspiciousIMErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or die( "Unable to open $filename: $!\n" );  
		
	&CarpOut( $MYLOG );
   
	&debug( "Fatal error trapping set to file $filename\n" ); 
}



################################################################################
# 
sub KillOtherSuspiciousIM()
#
#  Make sure that I'm the only SuspiciousIM program running
#
################################################################################
{	
	# At this point I've been nice - now I'm getting mean
	my $my_pid = &ProcessGetCurrentProcessId();

	my %processes = &ProcessHash();
	
	# Figure out if there are any SuspiciousIM processes running besides myself
	my @process_names	= values %processes;
	my @process_pids	= keys %processes;
	
	my @kill_pids;
	
	my $index = 0 - 1;
	foreach ( @process_names )
		{	$index++;
			
			next if ( ! $_ );
			
			my $name = lc( $_ );
			
			# Is this an SuspiciousIM process?
			next if ( ! ( $name =~ m/suspiciousim\.exe/ ) );
			
			my $this_pid = $process_pids[ $index ];
			
			next if ( $this_pid eq $my_pid );
	
			push @kill_pids, $this_pid;				 
		}


	print "Found SuspiciousIM processes being run by other users, so killing them now ...\n" if ( $kill_pids[ 0 ] );
	
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
#  Load up the strings to compare
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
sub LoadIMTable()
#
#  Load up to 1000 suspicious IMs
#  Return the count the matched, the total count checked, and True if done
#
################################################################################
{	$dbhStat = &SqlErrorCheckHandle( $dbhStat );
	
	
	my ( $last_time, $last_im ) = &GetLastIMTime();


	# If I'm getting all the IMs, then clear out the last time variable on the first time through
	if ( $opt_all )
		{	$last_time	= undef;
			$opt_all	= undef;	
		}
		
		
	my $str;
	
	if ( $last_time )
		{	$str = "SELECT ObjectID, [Time], CONVERT(BINARY(4), IpAddress) as IpAddress, UserName, HostName, MsgFrom, MsgTo, MsgText 
					FROM TrafficClassInstantMsg 
					WHERE [Time] > '$last_time'
					ORDER BY [Time]";
			
			&lprint( "Getting instant messages since $last_time ...\n" );
		}
	else
		{	$str = "SELECT ObjectID, [Time], CONVERT(BINARY(4), IpAddress) as IpAddress, UserName, HostName, MsgFrom, MsgTo, MsgText 
				FROM TrafficClassInstantMsg 
				ORDER BY [Time]";
			
			&lprint( "Getting all the instant messages in the database  ...\n" );
		}


	my $sth = $dbhStat->prepare( $str );
	$sth->execute();
	
	&SqlErrorHandler( $dbhStat );
	
	my $count = 0 + 0;
	my $checked = 0 + 0;
	
	my $this_last_time	= $last_time;
	my $this_last_im	= $last_im;
			
			
	# Clear the ims array out
	@ims = ();
	
	lprint "Now comparing the IMs to check for suspicious phrases ...\n";
	
	my $progress = 0 + 0;
	my $total_progress = 0 + 0;
	
	while ( my ( $object_id, $time, $ip_address, $user_name, $host_name, $msg_from, $msg_to, $msg_text ) = $sth->fetchrow_array() )
		{	# Quit if an error
			last if ( $dbhStat->err );
				
			next if ( ! defined $msg_text );
			
			$progress++;
			$total_progress++;
			$total_queries++;
			
			if ( $progress >= 1000 )
				{	lprint "Finished comparing $total_progress queries this pass ($total_queries total)...\n";
					&lprint( "Found $count suspicious queries so far this pass ($total_suspicious total) ...\n" );
					$progress = 0 + 0;
				}
				
			# Don't repeat old stuff
			next if ( ( $last_time )  &&  ( $last_im )  &&  ( $time eq $last_time )  &&  ( $msg_text eq $last_im ) );
			
			$checked++;
			
			my $match = &SuspiciousMatch( $msg_text );
			
			next if ( ! defined $match );
			
print "matched $msg_text\n" if ( $opt_debug );
	
			# Clean up the message text
			$msg_text =~ s/^\s//gm;
			$msg_text =~ s/\s$//gm if ( $msg_text );

			next if ( ! defined $msg_text );
			
			&lprint( "IM: $msg_text matched pattern $match\n" );
			
			$ims[ $count ][ 0 ] = $object_id;
			$ims[ $count ][ 1 ] = $time;
			$ims[ $count ][ 2 ] = $ip_address;
			$ims[ $count ][ 3 ] = $user_name;
			$ims[ $count ][ 4 ] = $host_name;
			$ims[ $count ][ 5 ] = $msg_from;
			$ims[ $count ][ 6 ] = $msg_to;
			$ims[ $count ][ 7 ] = $msg_text;
			
			$this_last_time	= $time;
			$this_last_im	= $msg_text;
			
			$count++;
			$total_suspicious++;
			
			if ( $count > ( 0 + 1000 ) )
				{	&SqlErrorHandler( $dbhStat );
					$sth->finish();
					
					&lprint( "Found $count suspicious instant messages so far ...\n" );
					
					&SaveLastIMTime( $this_last_time, $this_last_im );
					
					return( $count, $checked, undef );
				}
print "bottom of fetchrow\n" if ( $opt_debug );
		}


	&SqlErrorHandler( $dbhStat );
	$sth->finish();

	lprint "Read $count suspicious instant messages\n";
	
	&SaveLastIMTime( $this_last_time, $this_last_im );
	
	return( $count, $checked, 1 );
}



################################################################################
# 
sub SuspiciousMatch( $ )
#
#  Given a IM message text, see if it matches one of my suspicious instant messages
#
#  Return True if it does, undef if not
#
################################################################################
{	my $msg_text = shift;
	
	# Clean up the string
	$msg_text = lc( $msg_text );
	$msg_text =~ s/\-/ /g;		# Subsitute spaces for dashes
	$msg_text =~ s/\"/ /g;		# Subsitute spaces for "
	$msg_text =~ s/\'/ /g;		# Subsitute spaces for '
	$msg_text =~ s/^\s//gm;
	$msg_text =~ s/\s$//gm;
	$msg_text =~ s/\s+/ /gm;  # Changed repeated white space to a single space

	study( $msg_text );
	
	&lprint( "Checking IM: $msg_text\n" ) if ( $opt_verbose );

	# Check the NOT expressions first
	foreach ( @not_expressions )
		{	next if ( ! defined $_ );
			my $wildcard = $_;

			return( undef ) if ( $msg_text =~ m/$wildcard/ );
		}
		
	# Now check the match expressions
	foreach ( @expressions )
		{	next if ( ! defined $_ );
			my $wildcard = $_;
			if ( $msg_text =~ m/$wildcard/ )
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
sub GetLastIMTime()
#
#  Get the time of the last IM I have already processed, or undef if
#  I have never processed them, and the last IM text
#
################################################################################
{	my $time;
	my $msg_text;
print "top of GetLastIMTime\n" if ( $opt_debug );
	
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
	
	( $time, $msg_text ) = split /\t/, $line, 2;
	
	close FILE;
	
	return( $time, $msg_text );
}



################################################################################
# 
sub SaveLastIMTime( $$ )
#
#  Save the last time and msg_text I got
#
################################################################################
{   my $time		= shift;
	my $msg_text	= shift;
	
print "top of SaveLastIMTime\n" if ( $opt_debug );
	return( undef ) if ( ( ! defined $time )  ||  ( ! defined $msg_text ) );
	
	my $dir		= &SoftwareDirectory();
	my $file = $dir . "\\$suspicious_time";
	
	open FILE, ">$file" or return( undef );
	
	print FILE "$time\t$msg_text\n";
	close FILE;
	
	return( 1 );
}



################################################################################
# 
sub WriteIMTable()
#
#  Go through the loaded instant messages, copying suspicious ones to the
#  suspicious table.
#
#  Return the count copied to the table
#
################################################################################
{
	my $count = 0 + 0;
	
print "top of WriteIMTable\n" if ( $opt_debug );
	
	while ( $ims[ $count ][ 0 ] )
		{	my ( $object_id, $time, $ip_address, $user_name, $host_name, $msg_from, $msg_to, $msg_text );
			
			$object_id		= $ims[ $count ][ 0 ];
			$time			= $ims[ $count ][ 1 ];
			$ip_address		= $ims[ $count ][ 2 ];
			$user_name		= &quoteurl( $ims[ $count ][ 3 ] );
			$host_name		= &quoteurl( $ims[ $count ][ 4 ] );
			$msg_from		= &quoteurl( $ims[ $count ][ 5 ] );
			$msg_to			= &quoteurl( $ims[ $count ][ 6 ] );
			$msg_text		= &quoteurl( $ims[ $count ][ 7 ] );
			
			my @values;
			push @values, "\'" . $object_id . "\',";		# 0 entry
			push @values, "\'" . $time . "\',";				# 1 entry
			
			if ( defined $ip_address )
				{	push @values, "?, ";		# I have to do a bind parameter for an IP address
				}
			else
				{	push @values, 'NULL, ';
				}
				
			push @values, "\'" . $user_name . "\',";		# 3 entry
			push @values, "\'" . $host_name . "\',";		# 4 entry
			push @values, "\'" . $msg_from . "\',";			# 5 entry
			push @values, "\'" . $msg_to . "\',";			# 6 entry
			push @values, "\'" . $msg_text . "\'";			# 7 entry
			
			
			my $value;
			foreach ( @values )
				{	$value .= $_ if ( $value );
					$value = $_ if ( ! $value );
				}
				
			my $str = "INSERT INTO TrafficClassSuspiciousIM ( ObjectId, [Time], IpAddress, UserName, HostName, MsgFrom, MsgTo, MsgText ) VALUES ( $value )";

			$dbhStat = &SqlErrorCheckHandle( $dbhStat );
			my $sth = $dbhStat->prepare( $str );
			
			$sth->bind_param( 1, $ip_address, DBI::SQL_BINARY ) if ( defined $ip_address );

			if ( ! $sth->execute() )
				{	lprint "Error inserting into database suspicious IM $msg_text\n";
					
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
		
	
	lprint "Wrote $count suspicious instant messages to the Statistics database\n" if ( $count );
	
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
     return if ( ! $opt_debug );

     lprint( @_ );
}



################################################################################
# 
sub UsageError( $ )
#
################################################################################
{
    my $me = "Suspicious IM";

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
    my $me = "Suspicious IM";

    bprint <<".";
Usage: $me
This utility goes through the instant message table, copying suspicious
looking instant messages into the Suspicious IM table.  By default it 
processes the IMs sent since the last time it was run.

  -a, --all              process all the IMs in the database
                         drops any old suspicious IMs  
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
    my $me = "Suspicious IM";

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
