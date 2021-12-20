################################################################################
#!perl -w
#
# Rob McCarthy's BulkRetrieve source code
#  Copyright 2010 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use Getopt::Long;
use Win32::File;
use Cwd;
use MIME::Base64;

use IO::Socket;
use Sys::Hostname;
use Net::DNS;
use Net::SMTP;


use Pack::PackFile;
use Pack::PackUtil;
use Pack::PackSQL;
use Pack::Pack;



my $opt_help;					# True if I should just display the help and exit
my $opt_version;				# True if I should just display the version and exit
my $opt_logging = 1;			# True if I should log
my $opt_debug;	 				# True if I should write to a debug log file
my $opt_prepend = "RESTORED:";	# This is the prepend to the subject line to use

my $old_date;					# This is the date range to restore
my $new_date;

my $hostname;					# This is the hostname to email the messages to
my $host_ipaddress;				# Have to have this to email straight to the host

my $opt_email;					# This is set if just getting a single email address
my $opt_email_file;				# This is set if getting a list of emails

my $opt_test;					# If set, this will send all email to opt_test addr
my $opt_max;					# If set, this is the maximum number of emails to retrieve
my $opt_attach;					# If set then send the original email as an attachment
my $opt_from;					# If set the only retrieve the emails FROM this address


my @email;						# This is the list of emails TO:s to get

my $dbhIndex;					# Handle to the Index database

my $table = "ArchiveEmailInfo";	# This is the default table to use - the other table is CurrentEmailInfo


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
        "a|attach"		=> \$opt_attach,
        "e|email=s"		=> \$opt_email,
        "f|from=s"		=> \$opt_from,
        "l|list=s"		=> \$opt_email_file,
        "n|new=s"		=> \$new_date,
        "m|max=i"		=> \$opt_max,
        "o|old=s"		=> \$old_date,
        "p|prepend=s"	=> \$opt_prepend,
        "t|test=s"		=> \$opt_test,
        "h|help"		=> \$opt_help,
        "x|xxx"			=> \$opt_debug
    );

	
    &StdHeader( "BulkRetrieve" );
	
	
    &Usage() if ( $opt_help );
    &Version() if ($opt_version);
	
	# Should I trap programming errors?
	&TrapErrors() if ( ! $opt_debug );	
			
	# Does the hostname exist?
	$hostname = shift;
	
	if ( ! defined $hostname )
		{	print "You must specify a mail server hostname to email the retrieved messages to\n";
			&Usage();
			exit( 1 );
		}
		
	$hostname = lc( $hostname );
	
	# Figure out the hostname IP address
	my $host = gethostbyname( $hostname );
	if ( ! gethostbyname( $hostname ) )
		{	print "Unable to find the fully qualified name of hostname $hostname\n";
			exit( 1 );
		}
		
	$host_ipaddress = inet_ntoa( ( gethostbyname( $hostname ) )[ 4 ] );
	
	if ( ! $host_ipaddress )
		{	print "Unable to find the IP address of hostname $hostname\n";
			exit( 1 );
		}
		
	&SetLogFilename( '.\\BulkRetrieve.log', $opt_debug ) if ( $opt_logging );

	&lprint( "Sending retrieved emails to hostname $hostname, IP address $host_ipaddress\n\n" );
			
	&lprint( "Only retrieving a maximum of $opt_max emails\n\n" ) if ( $opt_max );
		
	&lprint( "Sending the original email as an attachment\n\n" ) if ( $opt_attach );

	&lprint( "DEBUGGING - not actually sending the emails\n\n" ) if ( $opt_debug );


	# Are the email addresses valid?
	if ( ( ! $opt_email )  &&  ( ! $opt_email_file )  &&  ( ! $opt_from ) )
		{	print "ERROR: You must specify either a single email address to retrieve, or a file containing a list of email addresses\n";
			exit( 1 );
		}

	if ( $opt_email_file )
		{	if ( ! open( INPUT, "<$opt_email_file" ) )
				{	print "Unable to open file $opt_email_file: $!\n";
					exit( 1 );	
				}
				
			my $counter = 0 + 0;
			
			while ( my $email = <INPUT> )
				{	my $clean_email = &CleanEmail( $email );
					next if ( ! $clean_email );
					
					push @email, $clean_email;
					$counter++;
				}

			close( INPUT );
			
			if ( ! $counter )
				{	print "ERROR: Unable to read any valid email addresses from $opt_email_file\n";
					exit( 1 );
				}
			
			&lprint( "Read $counter valid email addresses from $opt_email_file\n\n" );
		}
	
	# Do I have a single TO: address to use?
	if ( $opt_email )	
		{	if ( ! &CleanEmail( $opt_email ) )
				{	print "ERROR: TO: Email address $opt_email is not a valid email address\n";
					exit( 1 );
				}
			else
				{	push @email, $opt_email;
				}
		}
		
		
	# Do I have a FROM: address?	
	if ( ( $opt_from )  &&  ( ! &CleanEmail( $opt_from ) ) )
		{	print "ERROR: FROM: Email address $opt_from is not a valid email address\n";
			exit( 1 );
		}


	if ( $opt_test )
		{	if ( ! &CleanEmail( $opt_test ) )
				{	print "Error: $opt_test is not a valid email address\n";
					exit( 1 );
				}
			
			&lprint( "Sending all retrieved email to $opt_test ...\n\n" );
		}
		
	
	if ( $#email > -1 )	
		{	&lprint( "Retrieving email for the folowing list of TO: email addresses: ...\n" );
			foreach ( @email )
				{	my $email = $_;
					next if ( ! $email );
					&lprint( "$email\n" );
				}
			&lprint( "\n" );
		}
		
	&lprint( "Retrieving email FROM: email address $opt_from\n" ) if ( $opt_from );


	# Figure out the dates to use	
	my $now = time;
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $now );
	$mon = $mon + 1;
	$year = 1900 + $year;
	
	my $today = "$mon\/$mday\/$year";
	
	my $old = $now - ( 24 * 60 *60 );
	( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( $old );
	$mon = $mon + 1;
	$year = 1900 + $year;

	my $yesterday = "$mon\/$mday\/$year";


	$old_date = $yesterday if ( ! $old_date );
	$new_date = $today if ( ! $new_date );
	
	if ( ! &CheckDate( $new_date ) )
		{	print( "Invalid new date: $new_date\n" );
			exit( 1 );	
		}
		
	if ( ! &CheckDate( $old_date ) )
		{	print( "Invalid old date: $old_date\n" );
			exit( 1 );	
		}

	# Can I actually use the CurrentEmailInfo table?
	# I can if the old date is newer than the optimization days
	$table = "CurrentEmailInfo" if ( &CurrentTable( $old_date ) );

	&lprint( "Retrieving email for the period $old_date to $new_date ...\n\n" );
	

	# Start up packing - readonly mode
	my $ok = &PackStart( 1 );
	if ( ! $ok )
		{	&lprint( "Error starting to unpack\n" );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 2 );
		}
	
	&lprint( "Connecting to SQL ...\n" );	
	$dbhIndex = &PackSqlConnectIndex();
	if ( ! $dbhIndex )
		{	&lprint( "Unable to get a handle to the Index database\n" );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			exit( 2 );	
		}


	# Start doing some work ...	
	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	# For each email TO: get the docids that match the period
	my $total = 0 + 0;
	foreach ( @email )
		{	my $email = $_;
			next if ( ! $email );
			
			&lprint( "Retrieving emails for $email ...\n" );
			
			my $email_total = 0 + 0;
			
			my @docids = &BulkDocIDs( $dbhIndex, $email, $old_date, $new_date, $opt_from );
			foreach ( @docids )
				{	my $docid = $_;
					next if ( ! $docid );
					
					my $email_addr = $email;
					$email_addr = $opt_test if ( $opt_test );
					
					my $ok = 1;
					
					$ok = &EmailDocID( $docid, $email_addr, $email_total ) if ( ! $opt_debug );
					next if ( ! $ok );
					
					$email_total++;
					$total++;
					
					last if ( ( $opt_max )  &&  ( $total >= $opt_max ) );
				}
				
			&lprint( "Emailed $email_total messages that were TO: $email\n" ) if ( $email_total );	
			&lprint( "Emailed nothing to $email\n" ) if ( ! $email_total );	
			
			last if ( ( $opt_max )  &&  ( $total >= $opt_max ) );
		}


	# Do I only have an email from?
	if ( ( $#email < 0 )  &&  ( $opt_from ) )
		{	my $email_total = 0 + 0;
			
			my @docids = &BulkDocIDs( $dbhIndex, undef, $old_date, $new_date, $opt_from );
			foreach ( @docids )
				{	my $docid = $_;
					next if ( ! $docid );
					
					my $email_addr = $opt_from;
					$email_addr = $opt_test if ( $opt_test );
					
					my $ok = 1;
					
					$ok = &EmailDocID( $docid, $email_addr, $email_total ) if ( ! $opt_debug );
					next if ( ! $ok );
					
					$email_total++;
					$total++;
					
					last if ( ( $opt_max )  &&  ( $total >= $opt_max ) );
				}
				
			&lprint( "Emailed $email_total messages that were FROM: $opt_from\n" ) if ( $email_total );	
			&lprint( "Emailed no messages that were FROM: $opt_from\n" ) if ( ! $email_total );	
			
			last if ( ( $opt_max )  &&  ( $total >= $opt_max ) );
			
		}
		
		
	&lprint( "Emailed $total messages in total\n" );	

	if ( ( $opt_max )  &&  ( $total >= $opt_max ) )
		{	&lprint( "Reached the maximum of $opt_max messages sent\n" );
		}
		
	chdir( $cwd );
	
	&PackStop();
	
	&StdFooter;

	exit( 1 );
}
################################################################################



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	# Pick a filename
	my $filename = ".\\BulkRetrieveErrors.log";
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">$filename" ) )
		{	print( "Unable to open $filename for error logging: $!\n" ); 
			return;
		}
		
	&CarpOut( $MYLOG );
   
	print( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub CurrentTable( $ )
#
#  Given a date in the format MM/DD/YYYY, return True if the date is within
#  the CurrentEmailInfo table date period, or undef if not
#
################################################################################
{	my $date = shift;

use Time::Local;

	return( undef ) if ( ! $date );
	
	my %properties;					# The hash of properties for Mail Archiving
	my $ok = &PackUtilGetProperties( \%properties );
	return( undef ) if ( ! $ok );
	
	my $hex = $properties{ "Search Optimization" };
	return( undef ) if ( ! $hex );
	
	# This days is the number of days worth of data that is kept in the Current tables
	my $days = &HexToInt( $hex );

	# Figure out that time in seconds
	my $current_table_time = time - ( $days * 24 * 60 *60 );
	
	# Now convert the date in MM/DD/YYYY to seconds
	my ( $mm, $dd, $yyyy ) = split /\//, $date, 3;
	return( undef ) if ( ! $mm );
	return( undef ) if ( ! $dd );
	return( undef ) if ( ! $yyyy );
	
	my $year = $yyyy - 1900;
	my $mon = $mm - 1;
	
	my $time = timelocal( 0, 0, 0, $dd, $mon, $year );

	return( undef ) if ( ! $time );
	
	if ( $time > $current_table_time )
		{	&lprint( "The oldest date to retrieve of $date is newer that the Search Optimization days of $days\n" );
			&lprint( "Therefore using the CurrentEmailInfo table to get faster results\n" );
			return( 1 );
		}
		
	return( undef );
}



################################################################################
# 
sub BulkDocIDs( $$$$$ )
#
#  Given a handle to the database, an email address, and an option period, return
#  the list of docids that match, or na empty list if nothing does match
#
################################################################################
{	my $dbhIndex	= shift;
	my $email		= shift;
	my $old_date	= shift;
	my $new_date	= shift;
	my $from		= shift;

	my @docids;

	return( @docids ) if ( ! $dbhIndex );
	return( @docids ) if ( ( ! $email )  &&  ( ! $from ) );
	
	$dbhIndex = &PackSqlErrorCheckHandle( $dbhIndex );
	return( @docids ) if ( ! $dbhIndex );
	return( @docids ) if ( $dbhIndex->err );
	
	my $email_id;
	if ( $email )
		{	my $qemail = &PackSqlQuoteValue( $email );
	
			my $sth = $dbhIndex->prepare( "SELECT EmailID from EmailAddress WITH(NOLOCK) where Email = \'$qemail\'" );
			$sth->execute();
			$email_id = $sth->fetchrow_array();

 			&PackSqlErrorHandler( $dbhIndex );
			$sth->finish();

			if ( ! $email_id )
				{	&lprint( "Found no documents at all for TO: email address $email\n" );		
					return( @docids );	
				}
		 
			&lprint( "TO: Email TO: address $email corresponds to email ID $email_id\n" );
		}
		

	# Do I have a FROM email address to check?
	my $from_email_id;
	if ( $from )
		{	my $qemail = &PackSqlQuoteValue( $from );
			my $sth = $dbhIndex->prepare( "SELECT EmailID from EmailAddress WITH(NOLOCK) where Email = \'$qemail\'" );
			$sth->execute();
			$from_email_id = $sth->fetchrow_array();

 			&PackSqlErrorHandler( $dbhIndex );
			$sth->finish();

			if ( ! $from_email_id )
				{	&lprint( "Found no documents at all for FROM: email address $from\n" );		
					return( @docids );	
				}
		 
			&lprint( "Email FROM: address $from corresponds to email ID $from_email_id\n" );
		}
	
	
	# Now using the email ID I just got, retrieve all the doc IDs that match the date range
	$dbhIndex = &PackSqlErrorCheckHandle( $dbhIndex );
	return( @docids ) if ( ! $dbhIndex );
	return( @docids ) if ( $dbhIndex->err );
	
	my $str;
	
	# Does I have a TO: address?
	if ( $email )
		{	$str = "SELECT DocID FROM $table WITH(NOLOCK) WHERE EmailToID = \'$email_id\'";
			$str .= " AND [TIME] > \'$old_date\'" if ( defined $old_date );
			$str .= " AND [TIME] < \'$new_date\'" if ( defined $new_date );

			# Do I have a FROM: email ID?
			$str .= " AND EmailFromID = \'$from_email_id\'" if ( $from_email_id );
		}
	else
		{	$str = "SELECT DocID FROM $table WITH(NOLOCK) WHERE EmailFromID = \'$from_email_id\'";
			$str .= " AND [TIME] > \'$old_date\'" if ( defined $old_date );
			$str .= " AND [TIME] < \'$new_date\'" if ( defined $new_date );
		}

	# Is the email from: and email to: the same?
	if ( ( $email_id )  &&  ( $from_email_id )  &&  ( $email_id == $from_email_id ) )
		{	$str = "SELECT DocID FROM $table WITH(NOLOCK) WHERE ( EmailToID = \'$email_id\' OR EmailFromID = \'$from_email_id\' )";
			$str .= " AND [TIME] > \'$old_date\'" if ( defined $old_date );
			$str .= " AND [TIME] < \'$new_date\'" if ( defined $new_date );
		}
	
	# Put it in the right order
	$str .= " ORDER BY [TIME]";
	
	&lprint( "SQL Statement: $str\n" );
	
    my $sth = $dbhIndex->prepare( $str );
    $sth->execute();
	
	my $counter = 0 + 0;
	while ( ( ! $dbhIndex->err )  &&  (  my ( $docid ) = $sth->fetchrow_array() ) )
        {	next if ( ! $docid );
			
			push @docids, $docid;
			
			$counter++;
	    }

 	&PackSqlErrorHandler( $dbhIndex );
	$sth->finish();

	&lprint( "Found $counter emails that match this SQL statement\n" ) if ( $counter );
	&lprint( "Found no emails that match this SQL statement\n" ) if ( ! $counter );
	
	return( @docids );
}



################################################################################
# 
sub EmailDocID( $$$ )
#
#  Given a doc ID, email it to a server
#  Return True if OK, undef if not
#
################################################################################
{	my $docid			= shift;
	my $email			= shift;
	my $email_counter	= shift;
	
	return( undef ) if ( ! $docid );
	return( undef ) if ( ! $email );
	
	$email_counter = 0 + 0 if ( ! $email_counter );
	
	# Figure out a tmp file to use
	my $pid = &PackUtilPID();
	my $tmp_file = &TmpDirectory() . "\\BulkRetrieve-$pid-$email_counter-$docid.tmp";
	my $meta_file = $tmp_file . ".metadata";
	
	&lprint( "Unpacking Doc ID $docid to tmp file $tmp_file ...\n" );
	
	my $ok = &UnpackDocID( $docid, $tmp_file, $meta_file );		
				
	# Did I have a problem unpacking the file?
	if ( ! $ok )
		{	&lprint( "Error unpacking $docid\n" );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			
			unlink( $tmp_file );
			unlink( $meta_file );
			
			return( undef );	
		}
		
		
	&lprint( "Emailing doc ID $docid to email $email ...\n" );
	
	$ok = &BulkEmailFile( $docid, $tmp_file, $email );

	if ( ! $ok )
		{	&lprint( "Error emailing Doc ID $docid to $email\n" );
			my $last_err = &PackLastError();
			&lprint( "$last_err\n" ) if ( defined $last_err );
			
			unlink( $tmp_file );
			unlink( $meta_file );
			
			return( undef );
		}	
	
	# Clean up any tmp files that I created
	unlink( $tmp_file );
	unlink( $meta_file );
	
	return( 1 );
}


################################################################################
# 
sub CheckDate( $ )
#
#  Make sure that a date field is in the format MM/DD/YYYY
#  Return True if OK, undef if not
#
################################################################################
{	my $date = shift;

	return( undef ) if ( ! $date );
	
	my ( $mm, $dd, $yyyy ) = split /\//, $date, 3;

	return( undef ) if ( ! $mm );
	return( undef ) if ( ! $dd );
	return( undef ) if ( ! $yyyy );
	
	return( undef ) if ( length( $mm) > 2 );
	return( undef ) if ( length( $dd) > 2 );
	return( undef ) if ( length( $yyyy) != 4 );

	$mm = 0 + $mm;
	return( undef ) if ( ( $mm < 1 )  ||  ( $mm > 12 ) );
	
	$dd = 0 + $dd;
	return( undef ) if ( ( $dd < 1 )  ||  ( $dd > 31 ) );
	
	$yyyy = 0 + $yyyy;
	return( undef ) if ( ( $yyyy < 1900 )  ||  ( $yyyy > 2100 ) );
	
	return( 1 );
}



################################################################################
#
sub LoadTemplate()
#
#  Return the email template - 
#  Template uses IpmEMAILTO, IpmSUBJECT, IpmFILENAME, IpmENCODEDMSG
#
################################################################################
{

return( "Content-class: urn:content-classes:message
MIME-Version: 1.0
Content-Type: multipart/mixed;
	boundary=\"----_=_NextPart_001_01C664D0.34B0D3B7\"
Subject: Mail Archive Retrieve: IpmSUBJECT
X-MimeOLE: Produced By Microsoft Exchange V6.5.7226.0
X-MS-Has-Attach: yes
X-MS-TNEF-Correlator: 
From: IpmEMAILFROM
To: <IpmEMAILTO>

This is a multi-part message in MIME format.

------_=_NextPart_001_01C664D0.34B0D3B7
Content-Type: multipart/alternative;
	boundary=\"----_=_NextPart_002_01C664D0.34B0D3B7\"


------_=_NextPart_002_01C664D0.34B0D3B7
Content-Type: text/plain;
	charset=\"us-ascii\"
Content-Transfer-Encoding: quoted-printable

Attached is the archived message you requested.

Original Message
From: IpmORIGINALFROM
To: IpmORIGINALTO
Subject: IpmSUBJECT
Date: IpmDATE

=20

If you have any questions regarding this service, or to get=20
more information visit: www.lightspeedsystems.com <http://www.lightspeedsystems.com/>=20

=20


------_=_NextPart_002_01C664D0.34B0D3B7
Content-Type: text/html;
	charset=\"us-ascii\"
Content-Transfer-Encoding: quoted-printable

<html xmlns:o=3D\"urn:schemas-microsoft-com:office:office\" =
xmlns:w=3D\"urn:schemas-microsoft-com:office:word\" =
xmlns=3D\"http://www.w3.org/TR/REC-html40\">

<head>
<meta http-equiv=3D\"Content-Type\" 
content=3D\"text/html; charset=3Diso-8859-1\" />
<title>Mail Archive Message Retrieved</title>
<style type=3D\"text/css\">
<!--
body {
	margin:20px;
	font-size:12px;
	font-family:Verdana, Arial, Helvetica, sans-serif;
	line-height:18px;
}
.documentTitle
{
	font-family:Trebuchet, 'Trebuchet MS'; 
	font-size:25px; 
	letter-spacing:-1px; 
	color:#333333;
}
.roundBox{
display:block
}
.roundBox *{
display:block;
height:1px;
overflow:hidden;
background:#dee5f0
}
.roundBox1{
border-right:1px solid #f0f3f8;
padding-right:1px;
margin-right:3px;
border-left:1px solid #f0f3f8;
padding-left:1px;
margin-left:3px;
background:#e6ebf3;
}
.roundBox2{
border-right:1px solid #fbfcfd;
border-left:1px solid #fbfcfd;
padding:0px 1px;
background:#e4e9f2;
margin:0px 1px;
}
.roundBox3{
border-right:1px solid #e4e9f2;
border-left:1px solid #e4e9f2;
margin:0px 1px;
}
.roundBox4{
border-right:1px solid #f0f3f8;
border-left:1px solid #f0f3f8;
}
.roundBox5{
border-right:1px solid #e6ebf3;
border-left:1px solid #e6ebf3;
}
.roundBox_content{
padding:0px 5px;
background:#dee5f0;
} 
.detailsLabel{
	color:#7a7a7a;
}
#Footer{
	margin-top:50px;
	border-top:1px solid #cccccc;
	font-size:10px;
	text-align:center;
}
#Footer a{
	color:#000000;
	text-decoration:underline;
}	
-->
</style></head>

<body>
Attached is the archived message you requested:
<div style=3D\"margin-top:25px;\"><b class=3D\"roundBox\">
<b class=3D\"roundBox1\"><b></b></b><b class=3D\"roundBox2\"><b></b></b>
	<b class=3D\"roundBox3\"></b><b class=3D\"roundBox4\"></b>
	<b class=3D\"roundBox5\"></b></b><div class=3D\"roundBox_content\">
		<span class=3D\"detailsLabel\">
		To:</span> <span class=3D\"detailsContent
		\">IpmORIGINALTO</span><br />
		<span class=3D\"detailsLabel\">From:</span>
		<span class=3D\"detailsContent\">IpmORIGINALFROM</span>
		<br /><br />
		<span class=3D\"detailsLabel\">Subject:</span>
		<span class=3D\"detailsContent\">IpmSUBJECT</span><br />
		<span class=3D\"detailsLabel\">Sent on:</span>
		<span class=3D\"detailsContent\">IpmDATE</span>
	</div>
	<b class=3D\"roundBox\"><b class=3D\"roundBox5\">
	</b><b class=3D\"roundBox4\"></b><b class=3D\"roundBox3\"></b>
	<b class=3D\"roundBox2\"><b></b></b><b class=3D\"roundBox1\">
	<b></b></b>
	</b>
	</div> 

<div id=3D\"Footer\">
	If you have any questions regarding this service, 
	or to get more information visit: 
	<a href=3D\"http://www.lightspeedsystems.com\" target=3D\"_blank
	\">www.lightspeedsystems.com</a><br />
</div>
</body>
</html>

------_=_NextPart_002_01C664D0.34B0D3B7--

------_=_NextPart_001_01C664D0.34B0D3B7
Content-Type: message/rfc822

IpmENCODEDMSG

" );
	
}



################################################################################
#
sub BulkEmailFile( $$$ )
#
#  Given a docid, file and an email address, email the file as an attached email
#  Return OK if sent, and the message file created
#
################################################################################
{	my $docid		= shift;
	my $file		= shift;
	my $email_to	= shift;
	
	return( undef ) if ( ! $docid );
	return( undef ) if ( ! $file );
	return( undef ) if ( ! $email_to );


	# Read any email info that I have in the SQL database - if possible - don't worry if I can't
	my %email_info;
	&PackSQLGetEmailInfo( $docid, \%email_info );
	
	
	# Read all of the file data into the string data
	my $data = "";
	
	if ( ! open( FILE, "<$file" ) )
		{	&lprint( "Error opening file $file: $!\n" );
			return( undef );
		}
		
		
	my $subject;
	my $original_from;
	my $original_to;
	while ( my $line = <FILE> )
		{	
			# Is this a subject line?  I should rewrite it with the prepend if I have one
			if ( ( ! $subject )  &&  ( $line =~ m/^subject:/i ) )
				{	my $junk;
					( $junk, $subject ) = split /\:/, $line, 2;
					$subject =~ s/^\s+// if ( $subject );
					$subject =~ s/\s+$// if ( $subject );
					$subject =~ s/[^\x20-\x7e]//gm if ( $subject );
					
					# Prepend the subject
					my $prepend_subject = $opt_prepend . " " . $subject if ( $opt_prepend );
					$prepend_subject = $subject if ( ! $opt_prepend );

					# If I am sending the original as an attach then don't change anything
					if ( $opt_attach )
						{	$data .= $line;
						}
					else		
						{	$data .= "subject: " . $prepend_subject;
						}
					next;
				}

			$data .= $line;
			
			#  Am I a setting the email from?
			if ( ( ! $original_from )  &&  ( $line =~ m/^from:/ ) )
				{   my $stuff = $line;
					
					$stuff =~ s/from://i;
					
					$original_from = $stuff;
					$original_from =~ s/^\s//g;
					$original_from =~ s/\s$//g;
				}

			#  Am I a setting the email to?
			if ( ( ! $original_to )  &&  ( $line =~ m/^to:/ ) )
				{   my $stuff = $line;
					
					$stuff =~ s/to://i;
					
					$original_to = $stuff;
					$original_to =~ s/^\s//g;
					$original_to =~ s/\s$//g;
				}

		}
		
	close( FILE );
	
		
	# Use the fields out of the hash if I couldn't read them from the file itself
	my $date		= $email_info{ "Time" };
	$subject		= $email_info{ "Subject" }		if ( ! $subject );
	$original_to	= $email_info{ "EmailTo" }		if ( ! $original_to );
	$original_from	= $email_info{ "EmailFrom" }	if ( ! $original_from );
	

	# Default it if I couldn't find anything	
	$subject = "No Subject"			if ( ! $subject );
	$date = "Unknown"				if ( ! $date );
	$original_from = "Unknown FROM" if ( ! $original_from );
	$original_to = "Unknown TO"		if ( ! $original_to );


	# Prepend the subject
	my $prepend_subject = $opt_prepend . " " . $subject if ( $opt_prepend );
	$prepend_subject = $subject if ( ! $opt_prepend );
	
	# Get the email from
	my %properties;
	&PackUtilGetProperties( \%properties, undef );
	my $email_from = $properties{ "Archive Email" };
	$email_from = "\"No Reply\" <noreply\@lightspeedsystems.com>" if ( ! $email_from );

	# Put all of the fields into the body now ...
	my $body = &LoadTemplate();
	
	$body =~ s/IpmEMAILTO/$email_to/g;
	$body =~ s/IpmEMAILFROM/$email_from/g;
	$body =~ s/IpmSUBJECT/$prepend_subject/g;
	$body =~ s/IpmORIGINALTO/$original_to/g;
	$body =~ s/IpmORIGINALFROM/$original_from/g;
	$body =~ s/IpmDATE/$date/g;
	$body =~ s/IpmENCODEDMSG/$data/;

	# Create a unique filename for the message file
	my $filename = "BulkRetrieve-";
	
	# Clean up the email to so that it works as part of a filename
	my $temp = $email_to;
	$temp =~ s/\@/\-/g;
	$temp =~ s/\./\-/g;
	$filename .= $temp;
	
	my $pid = &PackUtilPID();
	$pid = 0 + 0 if ( ! $pid );
	
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time() );
	$year = 1900 + $year;
	$mon = $mon + 1;
	my $datestr = sprintf( "%04d%02d%02d%02d%02d%02d%d", $year, $mon, $mday, $hour, $min, $sec, $pid );

	# Use the docid as part of the random name
	
	$filename .= "\-" . $datestr . "-" . $docid . ".txt";


	# To send with original email I send the $data variable - to send as an attachment I send the $body variable
	my $ok;
	my $errmsg;
	my $message_filename;
	
	if ( $opt_attach )
		{	( $ok, $errmsg, $message_filename ) = &SMTPMessageFile( $filename, $email_from, $body, undef, $host_ipaddress, $email_to );
		}
	else
		{	( $ok, $errmsg, $message_filename ) = &SMTPMessageFile( $filename, $original_from, $data, undef, $host_ipaddress, $email_to );
		}

	if ( ! $ok )
		{	my $err = "Error emailing to: $email_to: $errmsg" if ( $errmsg );
			$err = "Error emailing to: $email_to" if ( ! $errmsg );
	
			&lprint( "$err\n" );
			return( undef );
		}

	# Wait around for a few seconds to see if it went out
#	my $count = 0 + 0;
#	while ( -e $message_filename )
#		{	sleep( 1 );
#			$count++;		
#			last if ( $count > 30 );
#		}
	
#	if ( ! -e $message_filename )	
#		{	&lprint( "Emailed doc ID $docid (message file $message_filename) to $email_to OK\n" );
#		}
#	else
#		{	&lprint( "$message_filename is still waiting to be mailed in the SMTP spool directory after 30 seconds\n" );
#		}

	return( 1 );
}



################################################################################
# 
sub HexToInt( $ )
#
#  Convert a registry hex value to a decimal value
#
################################################################################
{  my $hexstring = shift;

   my $dec = unpack( "CH", $hexstring );
 
   return( $dec );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "BulkRetrieve";

    print <<".";
Usage: BulkRetrieve HOSTNAME [OPTION(s)]

BulkRetrieve unpacks and emails copies of messages from the Lightspeed 
message journal archive.

HOSTNAME is the DNS hostname or IP address of the server to email the
retrieved messages to.  The hostname may be a SMTP, Novell Groupwise, or 
Microsoft Exchange server.

BulkRetrieve will retrieve email sent TO: a single email address or TO: a 
list of email addresses that are specified in a text file.  To retrieve the
email sent TO: a single email address use the -e option, or to get the emails
sent TO: a list of email address use the -l option.

You can also specify a date range to retrieve and/or a subject.

You can also further restrict the retrieved email by using the -f option to
specify the emails FROM:.  For example, if you want to retrieve all the email
FROM rodger\@domain.com TO: sally\@domain.com you in January would use this 
command:

BulkRetrieve -e sally\@domain.com -f rodger\@domain.com -o 1/1/2010 -n 1/31/2010

You can also retrieve all the emails that were either sent TO: or FROM: the
same email address.  This example retrieves all the email sent TO: or FROM:
sally\@domain.com in January, 2010:

BulkRetrieve -e sally\@domain.com -f sally\@domain.com -o 1/1/2010 -n 1/31/2010


OPTIONs 

  -a, --attach               if set then send retrieved email as an attachment

  -e, --email EMAILTO        TO: email address to retrieve
  
  -f, --from EMAILFROM       FROM: email address to retrieve
  
  -l, --list EMAILLISTTO     a text file with a list of TO: email addresses
                             to retrieve  

  -p, --prepend PREPEND      Subject line prepend to identify the mail
                             default is \'RESTORED:\'  
  
  -o, --old OLDDATE          the oldest date to retrieve in MM/DD/YYYY format
                             default is yesterday  

  -n, --new NEWDATE          the newest date to retrieve in MM/DD/YYYY format
                             default is today  
  
  -m, --max MAXNUM           if set will only retrieve and send MAXNUM emails
  
  -t, --test TESTADDR        if set will send any retrieved email, no matter
                             what the original TO: address is, to TESTADDR
  
  -x, --xdebug               if set then do all the processing except do not
                             actually send the emails

  -h, --help                 display this help and exit
  -v, --version              display version information and exit
  
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
    my $me = "BulkRetrieve";

    print <<".";
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

