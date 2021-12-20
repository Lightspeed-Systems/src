################################################################################
#!perl -w
#
# AddAutoWhite.pl - a perl script to add an AutoWhite list entry into the IpmContent
#  database on BSD
#
#  Copyright 2009 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use SpamPlus::Options;
use SpamPlus::OS;
use SpamPlus::File;
use SpamPlus::SQL;



# OS specific globals
my $slash = '\\';								# This is the slash char for this OS
if ($^O ne 'MSWin32')
{	$slash = '/';
}



################################################################################
#
MAIN:
#
################################################################################
{  
	my $comp = shift;

	print "AddAutoWhite\n";

	die "Usage: AddAutoWhite \"EMAIL_FROM:EMAIL_TO\"\n\n" if ( ! $comp );
	
	my ( $email_from, $email_to ) = split /\:/, $comp, 2;

	die "Usage: AddAutoWhite \"EMAIL_FROM:EMAIL_TO\"\n" if ( ( ! defined $email_to )  ||  ( ! defined $email_from ) );
	
	$email_to = &CleanEmail( $email_to );
	die "Invalid EMAIL_TO\"\n" if ( ! defined $email_to );
	
	$email_from = &CleanEmail( $email_from );
	die "Invalid EMAIL_FROM\"\n" if ( ! defined $email_from );

	
	# Do any module startup necessary
	&OsStart();
	
	&TrapErrors();
	
	my $uid = &OptionsGet( "SQLUsername" );
	my $pwd = &OptionsGet( "SQLPassword" );
	
	
	print "Opening IpmContent database ...\n";
	my $dbh = &SqlConnectServer( $uid, $pwd ) or die( "Unable to connect to Content SQL database\n" );
	
	print "Adding AutoWhiteList entry \"$email_from:$email_to\" ...\n";
	&SqlAddAutoWhiteEntry( "$email_from:$email_to" );


	# Close the SQL database	
	print "Closing the IpmContent database ...\n";
	$dbh->disconnect if ( $dbh );
	$dbh	= undef;
	
	print "\nDone\n";


	exit;
}
###################    End of MAIN  ############################################



################################################################################
#
sub TrapErrors( $ )
#
#  Setup to Trap Errors
#
################################################################################
{  
	my $log_dir = &OptionsGet( "log_dir" );
	
	my $pid = $$;
	
	my $filename = $log_dir . $slash . "AddAutoWhiteErrors.$pid.log";	
	
	# Delete the errors file if it is getting too big ...
	my $size = -s $filename;
	unlink( $filename) if ( ( $size )  &&  ( $size > 20000 ) );
	
	my $MYLOG;
   
	if ( ! open( $MYLOG, ">>$filename" ) )
		{	&lprint( "Unable to open $filename: $!\n" );  
			return( undef );
		}
		
	&CarpOut( $MYLOG );
   
	print( "Error trapping set to file $filename\n" ); 
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
