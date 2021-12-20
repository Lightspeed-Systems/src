################################################################################
#!perl -w
#
# IpmLocalUsers - import a text file into the SQL database table of local users
#
################################################################################



# Pragmas
use strict;
use Getopt::Long;
use Content::File;
use Content::SQL;
use DBI qw(:sql_types);
use DBD::ODBC;



my $opt_drop;		# True if I should drop all the existing users and passwords
my $opt_help;
my $opt_verbose;	# True if I should be chatty
my $opt_version;
my $opt_wizard;		# True if I shouldn't display headers or footers



# Globals
my $_version = "1.0.0";
my $dbh;             #  My database handle



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
        "d|drop"	=> \$opt_drop,
        "v|verbose" => \$opt_verbose,
		"w|wizard"	=> \$opt_wizard,
        "h|help"	=> \$opt_help
    );


	&StdHeader( "IpmLocalUsers" ) if ( ! $opt_wizard );

    &Usage() if ($opt_help);
 

	my $file = shift;
	if ( ! $file )
		{	print "No filename specified to import users and passwords from.\n";
			exit;
		}

		
	if ( ! -e $file )
		{	print "File $file does not exist\n";
			exit;
		}
		
		
	if ( ! open FILE, "<$file" )
		{	print "Unable to open file $file: $!\n";
			exit;
		}
		
		
	$dbh = &ConnectServer() or die;
	
	if ( ! &SqlTableExists( "ContentFilterusers" ) )
		{	print "The ContentFilterUsers table does not exist in the local IpmContent database\n";
			close FILE;
			exit;
		}
		
		
	print "Importing local users and passwords from $file  ... \n";
	my $counter = 0 + 0;
	
	
	if ( $opt_drop )
		{	print "Dropping all the exisiting users ...\n";
			my $sth;
			$sth = $dbh->prepare( "DELETE ContentFilterUsers" );
			$sth->execute();
			$sth->finish();
		}
		
	
	while (<FILE>)
		{	next if ( ! $_ );
			my $line = $_;
			chomp( $line );
			next if ( ! $line );
						
			my @parts = split /\,/, $line, 3;

			my $userid = $parts[ 0 ];
			my $password = $parts[ 1 ];
			my $groups = $parts[ 2 ];

			next if ( ! $userid );
			
			$userid = &CleanText( $userid );
			next if ( ! $userid );
			
			$password = &CleanText( $password );
			$groups = &CleanText( $groups );
			
			print "Adding user $userid ...\n";
			
			# delete any existing userid that matches
			my $sth;
			$sth = $dbh->prepare( "DELETE ContentFilterUsers WHERE UserID = ?" );
			
			$sth->bind_param( 1, $userid,  DBI::SQL_VARCHAR );
			$sth->execute();
			$sth->finish();

			my $vuserid;
			my $vpassword;
			my $vgroups;
			
			$vuserid = "\'" . $userid . "\'";
			$vpassword = "\'" . $password . "\'" if ( $password );
			$vgroups = "\'" . $groups . "\'" if ( $groups );
			
			# Set up the differnet inserts
			my $str = "INSERT INTO ContentFilterUsers ( UserID ) VALUES ( $vuserid )" if ( ( ! $password )  &&  ( ! $groups ) );
			$str = "INSERT INTO ContentFilterUsers ( UserID, password ) VALUES ( $vuserid, $vpassword )" if ( ( $password )  &&  ( ! $groups ) );
			$str = "INSERT INTO ContentFilterUsers ( UserID, Password, Groups ) VALUES ( $vuserid, $vpassword, $vgroups )" if ( ( $password )  &&  ( $groups ) );

			$sth = $dbh->prepare( $str );
			my $ok = 1;	
			$ok = undef if ( ! $sth->execute() );
			$sth->finish();

			$counter++ if ( $ok );
		}
	
	
	close FILE;
	
	print "Added $counter users into the database\n";
	
	$dbh->disconnect;

	&StdFooter if ( ! $opt_wizard );

exit;
}

exit;
################################################################################



################################################################################
# 
sub CleanText( $ )
#
#	Clean the text used for a userid, password, or group
#
################################################################################
{	my $txt = shift;
	
	return( undef ) if ( ! $txt );
	
	$txt =~ s/\://g;	# Get rid of colons
	$txt =~ s/\'//g;	# Get rid of '
	$txt =~ s/\?//g;	# Get rid of ?
	$txt =~ s/\%//g;	# Get rid of %
	$txt =~ s/\*//g;	# Get rid of *
	$txt =~ s/\"//g;	# Get rid of #
	$txt =~ s#\s+##gm;	#  Spaces should be removed

	
	return( $txt );
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmLocalUsers";

    bprint <<".";
Usage: $me [OPTION(s)]
Import a comma delimited file containg userids, passwords, and groups into
the Total Traffic server's Content Filtering Local Users table.

  -d, --drop      drop all the existing local users and passwords
  -h, --help      display this help and exit
  -v, --version   display version information and exit
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
    my $me = "IpmLocalUsers";

    bprint <<".";
$me $_version
.
     &StdFooter;

    exit;
}



__END__

:endofperl
