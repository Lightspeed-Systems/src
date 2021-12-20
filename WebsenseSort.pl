################################################################################
#!perl -w
#
#  Rob McCarthy's WebsenseSort source code
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



use warnings;
use strict;


use IO::Handle;
use Cwd;


my $websense_sort_root = "C:\\WebsenseSort";
my %opened;			# This is a hash of opened directories
my @handles;		# This is a list of opened handles


# This hash is a mapping between the Websense category number, the equivalent Lightspeed category name,
# and the Websense sub category (if it exists)
my %websense_names =
(
 "2"	=> "business",
 
 "10"	=> "society.politics\tabortion",
 "92"	=> "society.politics\tpro-choise",
 "93"	=> "society.politics\tpro-life",
 
 "65"	=> "porn\tnudity",
 "66"	=> "adult\tadult_content",
 "67"	=> "porn\tsex",
 "94"	=> "education.sex\tsex_education",
 "95"	=> "adult\tlingerie_and_swimsuit",
 
 "11"	=> "society\tadvocacy_groups",
 
 "114"	=> "audio-video\tinternet_radio_and_tv",
 "108"	=> "audio-video\tinternet_telephony",
 "115"	=> "forums.p2p\tpeer_to_peer_file_sharing",
 "113"	=> "audio-video\tpersonal_network_storage_and_backup",
 "109"	=> "audio-video\tstreaming_media",
 
 "68"	=> "finance\tfinancial_data_and_services",
 
 "90"	=> "drugs\tabused_drugs",
 "88"	=> "health\tprescribed_medications",
 "89"	=> "health\tsuppliments_and_unregulated_compounds",
 "111"	=> "drugs\tmarijuana",

 "69"	=> "society\tcultural_institutions",
 "97"	=> "education\teducational_institutions",
 "118"	=> "education\teducational_materials",
 "121"	=> "education\treference_materials",

 "12"	=> "entertainment",
 "70"	=> "audio-video\tmp3_and_audio_download_services",
 
 "13"	=> "gambling",
 
 "14"	=> "games",

 "4"	=> "government",
 "72"	=> "government\tmilitary",
 "73"	=> "society.politics\tpolitical_organizations",
 
 "27"	=> "health",
 
 "15"	=> "adult\tillegal_or_questionable",
 
 "9"	=> "computers\tinformation_technology",
 "28"	=> "search\ttranslation",
 "76"	=> "search",
 "78"	=> "forums.personals\tweb_hosting",
 "80"	=> "security.hacking\thacking",
 "138"	=> "computer\tcomputer_security",
 "75"	=> "security.proxy\tproxy_avoidance",
 
 "74"	=> "mail\tweb_based_email",
 "79"	=> "forums.chat\tweb_chat",
 
 "16"	=> "jobs\tjob_search",
 
 "25"	=> "society.politics\tmilitancy_and_extremist",
 
 "150"	=> "computers\tcontent_delivery_networks",
 "156"	=> "computers\tfile_download_servers",
 "148"	=> "computers\timage_servers",
 
 "5"	=> "news\tnews_and_media",
 "81"	=> "news\talternate_journals",
 
 "29"	=> "ads\tadvertisements",
 "96"	=> "finance\tonline_brokerage_and_trading",
 "98"	=> "forums.im\tinstant_messaging",
 "99"	=> "security.warez\tfreeware_and_software_download",
 "112"	=> "forums\tmessage_boards_and_clubs",
 "100"	=> "access-denied\tpay_to_surf",
 
 "26"	=> "violence.hate\tracism_and_hate",
 
 "82"	=> "family.religion\tnon-traditional_religions",
 "83"	=> "family.religion\ttraditional_religions",
 
 "166"	=> "security.spyware\tkeyloggers",
 "128"	=> "security.virus\tmalicious_websites",
 "164"	=> "security.phishing",
 "154"	=> "security.spyware",
 
 "17"	=> "shopping",
 "101"	=> "shopping.auctions",
 "102"	=> "real_estate",
 
 "125"	=> "society\tprofessional",
 "123"	=> "society\tservice",
 "124"	=> "society\tsocial",
 
 "7"	=> "education.lifestyles",
 "87"	=> "alcohol\talcohol_and_tobacco",
 "85"	=> "adult.lifestyles\tgay_or_lesbian_or_bisexual_interest",
 "86"	=> "forums.personals\tpersonals_and_dating",
 "84"	=> "family.food\trestaurants_and_dining",
 "103"	=> "hobby",
 "117"	=> "forums.personals",
 
 "8"	=> "general\tspecial_events",

 "18"	=> "sports",
 "107"	=> "weapons\tsport_hunting_and_gun_clubs",
 
 "19"	=> "adult\ttasteless",

 "20"	=> "travel",
 "21"	=> "automobile\tvehicles",
 "22"	=> "violence",
 "23"	=> "violence.weapons",

 "152"	=> "expired",
 "153"	=> "unknown"
);



my $match		= "Websense.match";
my $miss		= "Websense.miss";
my $unknown		= "Websense.unknown";
my @input_files = ( $match, $miss, $unknown );




################################################################################
#
MAIN:
#
################################################################################
{


	print "Websense Sort\n";

				
	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;		
		
	
	# Sort any files found
	foreach ( @input_files )
		{	&WebsenseSort( $_ );
		}
	
	
	# Close any opened handles
	foreach ( @handles )
		{	my $handle = $_;
			close $handle;
		}
	
exit;
}
################################################################################



################################################################################
# 
sub WebsenseSort( $ )
#
#  Given a file that contains a list of urls, Websense catnumber number and name,
#  sort the urls into the Websense categories
#
################################################################################
{	my $file = shift;
	
	return( undef ) if ( ( ! -e $file )  ||  ( ! -s $file ) );
	
	open( INPUT, "<$file" ) or die "Unable to open $file: $!\n";
	
	print "Processing file $file ...\n";
	
	my $counter = 0 + 0;
	
	# Loop through reading the list of urls and getting the Websense category
	while (<INPUT>)
		{	my $line = $_;
			chomp( $line );
			next if ( ( ! defined $line )  ||  ( $line eq "" ) );
			
			my ( $url, $websense_catnum, $websense_catname ) = split /\t/, $line, 3;
			
			# Is the url unknown by Websense?
			if ( $file =~ m/websense\.unknown/i )
				{	next if ( ! defined $url );
					&WriteCategory( "unknown", $url );
				}
			else
				{	next if ( ! defined $url );
					next if ( ! defined $websense_catnum );
					
					$websense_catname = &WebsenseCatname( $websense_catnum );
					&WriteCategory( $websense_catname, $url );
				}
				
			$counter++;
		}

	print "Sorted $counter URLs from file $file\n";
	
	close INPUT;
}



################################################################################
# 
sub WriteCategory( $$ )
#
#  Given a category and a url, write it out to a results file
#
################################################################################
{	my $catname = shift;
	my $url = shift;
	
	my $dir = $websense_sort_root . "\\" . $catname;
	
	my $handle;
	if ( ! $opened{ $dir } )
		{	&MakeDirectory( $dir );
			
			open( $handle, ">>$dir\\domains.hit" ) or die "Error opening $dir\\domains.hit: $!\n";
			$handle->autoflush( 1 );

			push( @handles, $handle );
			
			$opened{ $dir } = $handle;
		}
	else
		{	$handle = $opened{ $dir };
		}
	
	print $handle "$url\n";
}



################################################################################
# 
sub WebsenseCatname( $ )
#
#  Given a category number, return the Websense category name
#
################################################################################
{	my $catnum = shift;
	
	return( "unknown" ) if ( ! defined $catnum );
	
	my $name = $websense_names{ "$catnum" };
	return( "unknown" ) if ( ! defined $name );
	
	my ( $lightspeed, $websense ) = split /\t/, $name, 2;
	
	my $catname = $lightspeed;
	$catname = $websense if ( defined $websense );
	
	return( $catname );
}



################################################################################
# 
sub MakeDirectory( $ )
#
#	Make sure the directory exists - create it if necessary
#
################################################################################
{	my $dir = shift;
	
	return( undef ) if ( ! defined $dir );
	
	# Return OK if the directory already exists
	return( 1 ) if ( -d $dir );
	
	my @parts = split /\\/, $dir;
	
	my $created_dir;
	foreach ( @parts )
		{	next if ( ! defined $_ );
			
			$created_dir .= "\\" . $_ if ( defined $created_dir );
			$created_dir = $_ if ( ! defined $created_dir );

			if ( ! -d $created_dir )
				{	mkdir $created_dir;
				}
		}
		
	return( 1 );
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl

