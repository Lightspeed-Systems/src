################################################################################
#!perl -w
#
# Rob McCarthy's NetTrekkerLinkID - Analyze netTrekker results
# 
# Copyright 2008 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Content::File;



my $_version = "1.00.00";
my $opt_debug;
my $opt_version;
my $opt_verbose;
my $opt_wizard;
my $opt_help;
my $opt_content;		# If true, then save all the http content to NetTrekkerContent.txt
my $opt_max = 0 + 10;	# If set, this is the maximum number of NetTrekker URLs to read
my $opt_reload;
my $opt_all_reload;
my $opt_linkid;



my %link_ids;		# This is a hash of NetTrekker link id urls as the key, val is the tabbed urls that were found
my %blocked;		# This is the hash of the blocked domains, and the number of times they are referenced



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
		"a|allreload"	=> \$opt_all_reload,
		"c|content"		=> \$opt_content,
		"l|linkid"		=> \$opt_linkid,
		"m|max=i"		=> \$opt_max,
		"r|reload"		=> \$opt_reload,
		"v|verbose"		=> \$opt_verbose,
		"w|wizard"		=> \$opt_wizard,
		"h|help"		=> \$opt_help,
		"x|xxxdebug"	=> \$opt_debug
    );


    &StdHeader( "NetTrekker Link ID Utility" ) if ( ! $opt_wizard );

    &Usage()	if ( $opt_help );
    &Version()	if ( $opt_version );
	
	my $blocked_filename = shift;
	
	&Usage() if ( ! $blocked_filename );
	
	open( BLOCKED, "<$blocked_filename" ) or die "Can not open file $blocked_filename: $!\n";
	
	&TrapErrors();

    &SetLogFilename( ".\\NetTrekkerLinkID.log", undef );


	print "Loading blocked domains from $blocked_filename ...\n";
	my $count = 0 + 0;
	while ( my $line = <BLOCKED> )
		{	chomp( $line );
			next if ( ! $line );
			
			my ( $domain, $stuff ) = split /\t/, $line, 2;
			
			next if ( ! $domain );
			
			my $root = &RootDomain( $domain );
			next if ( ! $root );
			
			$stuff = " " if ( ! $stuff );
			$blocked{ $domain } = $stuff;
			
			$count++;
		}
		
		
	close( BLOCKED );


	&NetTrekkerLinkID();
	
	
	&StdFooter();
	
    exit;
}



################################################################################
# 
sub NetTrekkerLinkID()
#
#  Analyze the Link ID file
#
################################################################################
{	
	
	print "Analyzing the NetTrekker Link ID file ...\n";
	
	# Keys start the line, val urls start with a tab
	if ( open( LINKID, "<NetTrekkerLinkID.txt" ) )
		{	my $key;
			my $val;
			
			while ( my $line = <LINKID> )
				{	chomp( $line );
					next if ( ! $line );
					
					# If the line doesn't start with a tab, then it is a key
					if ( ! ( $line =~ m/^\t/ ) )
						{	# Save the last key/val pair if the val exisits
							$link_ids{ $key } = $val if ( ( $val )  &&  ( $key ) );
							
							$key = $line;
							$val = undef;
						}
					else	# It must be a val URL
						{	# Trim the tab off the front of the line
							$line =~ s/^\t//;
							
							# Is this a blocked domain?
							my $root = &RootDomain( $line );
							
							# Is this blocked?
							next if ( ! exists $blocked{ $root } );
							
							$val .= "\t" . $line if ( $val );
							$val = $line if ( ! $val );
						}
				}
			
			# Save the last key/val pair
			$link_ids{ $key } = $val if ( ( $val )  &&  ( $key ) );
			
			close( LINKID );
		}


	print "Writing the results to NetTrekkerLinkIDBlocked.txt ...\n";
	
	open( LINKIDBLOCKED, ">NetTrekkerLinkIDBlocked.txt" ) or die "Error opening file NetTrekkerLinkIDBlocked.txt: $!\n";
	
	my @keys = sort keys %link_ids;
	
	# Write out each Link ID URL, and then on tabbed lines the URLS found from that Link ID
	foreach ( @keys )
		{	my $key = $_;
			next if ( ! defined $key );
			
			my $val = $link_ids{ $key };
			next if ( ! defined $val );
			
			print LINKIDBLOCKED "$key\n";
			
			my @urls = split /\t/, $val;
			
			foreach ( @urls )
				{	my $url = $_;
					my $root = &RootDomain( $url );
					next if ( ! $root );
					my $stuff = $blocked{ $root };
					next if ( ! $stuff );
					
					print LINKIDBLOCKED "\t$url\t$stuff\n";
				}
		}
		
	close( LINKIDBLOCKED );
		
	return( 1 );
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = "NetTrekkerLinkIDErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	print "Error logging set to $filename\n"; 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "NetTrekkerLinkID blockeded_list";

    print <<".";
Usage: $me

Analyze the NetTrekker Link ID file.


  -v, --verbose          verbose mode
  -h, --help             show this help text
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
    my $me = "NetTrekkerLinkID";

    print <<".";
$me $_version
.
    &StdFooter;

    exit;
}



################################################################################

__END__

:endofperl
