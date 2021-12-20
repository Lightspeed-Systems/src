################################################################################
#!perl -w
#
#  IpmBuildKeywords
#  Rob McCarthy's version of corpus building perl for building keywords from hits and misses dump directories
#  Copyright 2005 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use Getopt::Long;
use DBI qw(:sql_types);
use DBD::ODBC;
use Cwd;


use Content::File;
use Content::SQL;
use Content::Category;
use Content::Categorize;



# Options
my $opt_hits_dir			= "hits\\dump";
my $opt_miss_dir			= "misses\\dump";
my $opt_hits_url			= "hits.urls";
my $opt_miss_url			= "misses.urls";
my $opt_standard_url		= "\\Content\\blacklists\\general\\hits.urls";
my $opt_outfile;
my $opt_help;
my $opt_version;
my $opt_dump;					# If True, then there should be dump files in the directory catname\hits\dump and catname\misses\dump
my $opt_delete;					# If True, then delete any token file that doesn't have enough tokens
my $opt_clean;					# If True, clean http errors on hits and misses urls from the database
my $opt_category;				# Category to build keywords for
my $opt_wizard;
my $opt_debug;
my $opt_tokens;					# If True then write out each URLs tokens and links to files
my $opt_hits_tokens_dir		= "hits";
my $opt_misses_tokens_dir	= "misses";
my $opt_read_tokens;			# Read tokens from the tokens files
my $opt_sensitivity;			# Keyword sensitivity - from 0 to 100, 50 is the default
my $opt_lang;					# True if building language keywords



#  These are all the fudge factors
my $error_percent			= 0 + 2;		# This is the expected error rate of hits in percent
my $min_frequency			= 0 + 20;		# Number of times a token needs to be used before it is considered significant
my $maxsize					= 0 + 100000;	# Ignore files that are larger
my $pure_hit				= 0 + 0.91;		# Probability of a token that only occurs in a hit file
my $pure_miss				= 0 + 0.10;		# Probability of a token that only occurs in a miss file
my $pure_hit_keyword		= 0 + 0.92;		# Probability of a keyword token that only occurs in a hit file
my $pure_miss_keyword		= 0 + 0.09;		# Probability of a keyword token that only occurs in a miss file
my $expected_good_to_bad	= 0 + 2.0;		# This is the ratio of the expected number of good sites to bad sites - slightly biases tokens to be good
my $max_tokens				= 0 + 3000;		# The maximum number of tokens to read from a URL before quitting
my $min_tokens				= 0 + 100;		# The minimum number of tokens necessary to make a statistical judgement
my $min_hits				= 0 + 100;		# The minimum number of hit files to create a keywords file
my $min_misses				= 0 + 100;		# The minimum number of misses files to create a keywords file



# Globals
my $_version		= "2.0.0";
my $keyword_count	= 0 + 0;
my $category_num;				#  The SQL database category number
my $dbh;						#  My database handle
my $working_dir;				#  This is usually the current directory



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
		"c|category=s"		=> \$opt_category,
        "d|delete"			=> \$opt_delete,
        "e|error=f"			=> \$error_percent,
        "g|goodtobad=f"		=> \$expected_good_to_bad,
        "l|lang"			=> \$opt_lang,
        "m|minimum=i"		=> \$min_frequency,
        "o|output=s"		=> \$opt_outfile,
        "p|purge"			=> \$opt_clean,
        "r|readtokens"		=> \$opt_read_tokens,
        "s|sensitivity=i"	=> \$opt_sensitivity,
        "w|writetokens"		=> \$opt_tokens,
		"v|version"			=> \$opt_version,
		"x|xxx"				=> \$opt_debug,
        "h|help"			=> \$opt_help
    );


	&StdHeader( "IpmBuildKeywords" ) if ( ! $opt_wizard );
    &SetLogFilename( "IpmBuildKeywords.log", undef );

	&Usage() if ($opt_help);
    &Version() if ($opt_version);

    &UsageError( "You must specify a category to build keywords for with the \'-c CATNAME\' command line" ) if ( ! $opt_category );
    &UsageError() if ( ( $opt_sensitivity )  &&  ( $opt_sensitivity < 0  ||  $opt_sensitivity > 100 ) );

    $opt_category = lc( $opt_category );  #  Force it to lower case

    lprint( "Building keywords for category $opt_category ...\n\n" );

    &UsageError( "Can\'t build keywords for the general category" ) if ( $opt_category eq "general" );
    &UsageError( "Can\'t build keywords for the errors category" ) if ( $opt_category eq "errors" );
    &UsageError( "Can\'t build keywords for the suspicious category - must be edited by hand" ) if ( $opt_category eq "suspicious" );
    &UsageError( "Can\'t both read and write tokens files at the same time" ) if ( ( $opt_tokens )  &&  ( $opt_read_tokens ) );
    &UsageError( "Must specify both hits-urls and misses-urls or neither!" ) unless (!@ARGV || @ARGV == 2);
	&UsageError( "Absolute minimum frequency should be between 2 and 100 - default is 20\n" ) if ( ( $min_frequency < 2 )  ||  ( $min_frequency > 100 ) );
	&UsageError( "Expected good to bad ratio should be between 1 and 3 - default is 2\n" ) if ( ( $expected_good_to_bad < 1 )  ||  ( $expected_good_to_bad > 3 ) );
	&UsageError( "Error percent of hit URL should be between 0.5 and 20 - default is 2\n" ) if ( ( $error_percent < 0.5 )  ||  ( $error_percent > 20 ) );


	lprint "Building a language file for $opt_category\n" if ( $opt_lang );
	lprint "Writing tokens and links to tokens files\n" if ( $opt_tokens );
	lprint "Reading tokens and links from tokens files\n" if ( $opt_read_tokens );
	lprint "Deleting tokens files that don\'t have enough keywords\n" if ( $opt_delete );


	# Do I need to build the keyword file name?
    if ( $#ARGV > 1 )  
		{  $opt_outfile = $ARGV[2];  
		}


	&TrapErrors() if ( ! $opt_debug );


	$working_dir = getcwd();
	$working_dir =~ s#\/#\\#gm;
	lprint "Using working directory $working_dir\n";
	

    $opt_hits_url = shift if ( @ARGV );
    $opt_miss_url = shift if ( @ARGV );


	lprint "Trying to open a connection to the ODBC System DSN \'TrafficRemote\' ...\n";
	$dbh = &ConnectRemoteServer();

	if ( ! $dbh )
		{	lprint "Now trying to open a connection to the local ODBC System DSN \'Trafficserver\' ...\n";
			$dbh = &ConnectServer();

			if ( ! $dbh )
				{	lprint "Unable to connect to the remote or local IpmContent database with ODBC\n";
					exit( 0 );
				}
		}
		
    &LoadCategories();


	if ( ! $opt_lang )
		{	$category_num = &CategoryNumber( $opt_category );

			&UsageError( "Unknown category name = $opt_category\n" )   if ( ! $category_num );
		}
		

	if ( ! $opt_read_tokens	)
		{	#  Make sure that there are some HITS defined for this category
			my $sth = $dbh->prepare( "SELECT count (*)  from IpmContentCategoryHits WHERE CategoryNumber = $category_num" );
			$sth->execute() or &UsageError( $DBI::errstr );
			my $count = $sth->fetchrow_array();
			&UsageError( "No Hits URLs are defined for category $opt_category in the database\n" ) if ( !$count || $count == 0 );
		}


	# Now that everything is set up, actually build the keywords
    &BuildKeywords(); 


	&StdFooter if ( ! $opt_wizard );

exit;
}



################################################################################
#
sub BuildKeywords()
#
#  Actually build the keywords file
#
################################################################################
{
    # Process the misses files
    my $misses_files = 0 + 0;
    my %misses_occurrences;


    if ( $opt_dump )
		{	lprint "Processing misses files in directory $opt_miss_dir\n";
			( $misses_files, %misses_occurrences ) = &MakeTokenProbabilityHashFromDirectory( $opt_miss_dir );
		}
    elsif ( $opt_read_tokens )
		{	my $dir = $working_dir . "\\$opt_category\\". $opt_misses_tokens_dir;
			
			lprint "Reading tokens from directory $dir\n";
			( $misses_files, %misses_occurrences ) = &MakeHashFromTokensFile( $dir );
		}
    else
		{	lprint "Processing the misses urls from category $opt_category\n";
			( $misses_files, %misses_occurrences ) = &MakeTokenProbabilityHashFromInternet( $category_num, "misses" );

			my $standard_files;
			my %standard_occurrences;
		}


    # Process the hits files
    my $hits_files = 0 + 0;
    my %hits_occurrences;


    if ( $opt_dump )
		{	lprint "Processing hits files in directory $opt_hits_dir\n";
			( $hits_files, %hits_occurrences ) = &MakeTokenProbabilityHashFromDirectory( $opt_hits_dir );
		}
    elsif ( $opt_read_tokens )
		{	my $dir = $working_dir . "\\$opt_category\\". $opt_hits_tokens_dir;
			
			lprint "Reading tokens from directory $dir\n";
			( $hits_files, %hits_occurrences ) = &MakeHashFromTokensFile( $dir );
		}
    else
		{	lprint "Processing the hits urls from category $opt_category\n";
			( $hits_files, %hits_occurrences ) = &MakeTokenProbabilityHashFromInternet( $category_num, "hits" );
		}


    $dbh->disconnect if ( $dbh );


    #  If I don't have enough data - bail out ...
    &UsageError( "Not enough hits and/or misses files for category $opt_category" )  if ( ( $hits_files < $min_hits )  ||  ( $misses_files < $min_misses ) );


	# Check to see that there are approximately the same number of hits and misses files
	my $hit_limit = 0.2 * $hits_files;
	my $miss_limit =  0.2 * $misses_files;
	my $limit = $hit_limit;
	$limit = $miss_limit if ( $miss_limit > $hit_limit );
	
	
	# Are the numbers of hits and misses files close enough?
	if ( $hits_files > $misses_files )
		{    &UsageError( "Not enough misses files compared to hits files for category $opt_category" )  if ( $misses_files + $limit < $hits_files );
		}
	else
		{	&UsageError( "Not enough hits files compared to misses files for category $opt_category" )  if ( $hits_files + $limit < $misses_files );
		}
	
	
    # Open the corpus file
	# Does the c:\\content\\keywords directory exist?  If so, use it
	my $dir = &KeywordsDirectory();
	$dir = "c:\\content\\keywords" if ( -d "c:\\content\\keywords" );

    $opt_outfile = $dir . '\\' . $opt_category . '.keywords' if ( ! $opt_outfile );
    $opt_outfile = $dir . '\\' . $opt_category if ( $opt_lang );
	
    open CORPUS, ">$opt_outfile" or &UsageError( "Can\'t create keywords file $opt_outfile: $!\n" );


	# Calculate the actual min freqeuncy - taking into account the hits error rate
	my $actual_min_frequency = $error_percent * $hits_files / 100;
	$actual_min_frequency = 0 + sprintf ("%d", $actual_min_frequency );
	$actual_min_frequency = $min_frequency if ( $actual_min_frequency < $min_frequency );
	lprint "Only counting tokens that occur $actual_min_frequency times\n";
	
    lprint "Creating keywords file: $opt_outfile\n";


	# Get the highest and lowest frequencies
	my $high_freq	= 0 + 0;
	my $low_freq	= 0 + 0;
	
	
	# Save the good and bad count totals in the token "the"
	$hits_occurrences{ "the" }		= $hits_files;
	$misses_occurrences{ "the" }	= $misses_files;
	
	
    # Go through the list of misses
    foreach ( keys %misses_occurrences )
		{	next if ( ! defined $_ );
			
			my $token = $_;
			
			my $goodcount = 0 + 0;
			$goodcount = 0 + $misses_occurrences{ $token } if ( exists $misses_occurrences{ $token } );

			my $badcount = 0 + 0;
			$badcount = 0 + $hits_occurrences{ $token } if ( exists $hits_occurrences{ $token } );

			# Normalize the goodvalue to account for the sample size and factor in the fudge amount
			my $goodnorm = $expected_good_to_bad * ( ( $goodcount * $hits_files ) / $misses_files );
			#my $goodnorm = $expected_good_to_bad * $goodcount;

			# Is this token used enough to keep?
			my $total = $goodnorm + $badcount;
			next if ( $total < $actual_min_frequency );
	        
			#  Calculate the percentage of the time this token appears in a hit file versus a misses file
			my $pw = $badcount / ( $goodnorm + $badcount );


			#  Make sure that rare words don't totally drive the calculation wild
			# Is it a keyword?
			my $keyword = 1 if ( $token =~ m/:/ );
			
			if ( ( $pw > $pure_hit )  &&  ( ! $keyword ) )
                {  $pw = $pure_hit;
                }

			if ( ( $pw > $pure_hit_keyword )  &&  ( $keyword ) )
                {  $pw = $pure_hit_keyword;
                }
				
			if ( ( $pw < $pure_miss )  &&  ( ! $keyword ) )
                {  $pw = $pure_miss;
                }

			if ( ( $pw < $pure_miss_keyword )  &&  ( $keyword ) )
                {  $pw = $pure_miss_keyword;
                }
				
				
			#  Round off to 4 decimal places
			my $temp = 0 + sprintf( "%1.4f", $pw );
			$pw = 0 + $temp;
		            
					
			# Calculate how frequently and important this token is used in bad files
			my $freq = $pw * ( $badcount - $goodcount );
				
			$high_freq	= $freq if ( $freq > $high_freq );
			$low_freq	= $freq if ( $freq < $low_freq );
			
			
			printf CORPUS ("%s\t%2.4f\t%2.4f\n", $token, $pw, $freq );  
			$keyword_count++;
		}


    # Do the same thing with the pure hits, but goodcount, goodnorm are 0
    foreach ( keys %hits_occurrences )
		{	next if ( ! defined $_ );
			
			my $token = $_;
			
			if ( ! exists $misses_occurrences{ $token } )
				{   my $badcount = 0 + $hits_occurrences{ $token };

					# Is this token used enough to keep?
					next if ( $badcount < $actual_min_frequency );
					
					
					# Calculate how frequently and important this token is used in bad files
					my $freq = $pure_hit * $badcount;
						
					$high_freq	= $freq if ( $freq > $high_freq );
					$low_freq	= $freq if ( $freq < $low_freq );


					#  Calculate the percentage of the time this token appears in a spam file versus a non spam file
					my $pw = 0 + $pure_hit;
					
					# Is this a pure hit keyword?
					$pw = 0 + $pure_hit_keyword if ( $token =~ m/\:/ );
					
					
					printf CORPUS ( "%s\t%2.4f\t%2.4f\n", $token, $pw, $freq );

					$keyword_count++;
				}
		}


    lprint  "Total keywords occurring at least $actual_min_frequency times = $keyword_count\n";
    lprint  "Done calculating keyword values in file: $opt_outfile\n";

    close CORPUS;


    lprint  "Sorting keywords ...\n";

    if ( ! open CORPUS, "<$opt_outfile" )
		{   &UsageError( "Unable to re-read keyword file $opt_outfile: $!\n" );
		}


    my  %token_hit_rating;
    my  %token_freq;
    while ( my $line = <CORPUS> )
		{	chomp( $line );
			next if ( ! $line );
			
			my ( $key, $rating, $freq ) = split /\t/, $line;
			next if ( ! defined $key );
			next if ( ! defined $rating );
			next if ( ! defined $freq );
			
			# Normalize the frequency
			my $normalized_freq = ( $freq - $low_freq ) / ( $high_freq - $low_freq );
			$normalized_freq = sprintf "%2.4f", $normalized_freq;
			
			$token_hit_rating{ $key }	= $rating;
			$token_freq{ $key }			= $normalized_freq;
		}

	close CORPUS;


    my $new_factor = 2 - ( 1.5 * ( $opt_sensitivity / 100 ) ) if ( $opt_sensitivity );

	
	open CORPUS, ">$opt_outfile" or &UsageError( "Can\'t re-create keywords file $opt_outfile: $!\n" );
	my  $key;
	foreach my $token ( sort { $token_freq{ $b } <=> $token_freq{ $a }  } keys %token_freq )
		{   next if ( ! defined $token );
			
			my $goodcount = 0 + 0;
			$goodcount = 0 + $misses_occurrences{ $token } if ( exists $misses_occurrences{ $token } );

			my $badcount = 0 + 0;
			$badcount = 0 + $hits_occurrences{ $token } if ( exists $hits_occurrences{ $token } );

			my $rating	= $token_hit_rating{ $token };
			my $freq	= $token_freq{ $token };
			
			#  Modify the rating based on the opt_sensitivity
			if ( ( $opt_sensitivity )  &&  ( $rating < 1.0 ) )  #  Don't modify 1.0 ratings - which had to be set by hand
				{	my  $g = ( 1 / ( 2 * $rating ) ) - 0.5;
					my  $new_rating = 1 / ( 1 + ( $new_factor * $g ) );

					#  Check for rationality
					$new_rating = 0.09 if ( $new_rating < 0.09 );
					$new_rating = 0.92 if ( $new_rating > 0.92 );
					$rating = $new_rating;
				}
				
			print  CORPUS "$token\t$rating\t$freq\t$goodcount\t$badcount\n";
		}
		
	close CORPUS;


	return( 1 );	
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $dir = &SoftwareDirectory();

	my $filename = "$dir\\IpmBuildKeywordsErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or die( "Unable to open $filename: $!\n" );       	   
	&CarpOut( $MYLOG );
   
	lprint( "Error logging set to $filename\n" ); 
}



################################################################################
#
sub MakeTokenProbabilityHashFromDirectory( $ )
#
# Given a directory name, go through all the files in that directory,
# treat each one as a downloaded URL, and count each token
#
################################################################################
{	my	$directory = shift;

    # Read the directory
    opendir DIR, $directory or &UsageError( "Can\'t opendir $directory: $!\n" );
    my @files = readdir(DIR);
    closedir(DIR);
    

    # Process the files
    my $file_num = 0 + 0;

    my %token_occurrences;

    foreach ( @files )
		{	next if ( ! $_ );
			
			my $file = "$directory\\$_";
			next if ( ! -e $file );
			next if ( -d $file );
			
			my $size = -s $file;
			next if ( ! $size );
			
			next if (-s $file > $maxsize);
	        
			# Open the file
			next if ( ! open FILE, "<$file" );

			$file_num++;
			
			# Read the file
			my %unique_tokens;

			while (my $line = <FILE>)
				{	next if ( ! defined $line );
					
					# Split into tokens
					my @token_list = split /[^a-zA-Z\d]+/, $line;

					foreach ( @token_list )  
						{	next if ( ! $_ );
							
							my $token = $_;
							
							# Only count a unique token once per each file
							if ( ! exists $unique_tokens{ $token } )  
								{   # Count the token
									$token_occurrences{ $token } += 1.0;
									$unique_tokens{ $token } = 1.0;
								}
						}
				}

			close( FILE );
		}

	my $token_count = scalar keys %token_occurrences;
	my $file_count = $#files + 1;
	
	lprint "Processed $token_count tokens in $file_count files\n";

	return ( $file_num, %token_occurrences );
}



################################################################################
#
sub MakeHashFromTokensFile( $ )
#
# Given a directory name, go through all the files in that directory,
# reading each token file and adding the tokens together
#
################################################################################
{	my	$directory = shift;

    # Read the directory
    opendir DIR, $directory or &UsageError( "Can\'t opendir $directory: $!\n" );
    my @files = readdir(DIR);
    closedir(DIR);
    

    # Process the files
    my $file_num = 0 + 0;

    my %token_occurrences;

    foreach ( @files )
		{	# Is this a tokens file?
			next if ( ! $_ );
			
			my $short_file = $_;
			
			next if ( ! ( $short_file =~ m/\.tokens\.txt$/ ) );
			my $file = "$directory\\$short_file";
	        
			# Check for too small of a file
			my $size = -s $file;
			if ( ! $size )
				{	print "File $file is 0 length\n";
					unlink( $file ) if ( $opt_delete );
					next;
				}
			
			# Open the file
			next if ( ! open FILE, "<$file" );


			# Read the file
			my %unique_tokens;

			while (my $line = <FILE>)
				{	chomp( $line );
					next if ( ! $line );
										
					my $token = $line;
					
					# Only count a unique token once per each file
					if ( ! exists $unique_tokens{ $token } )  
						{   $unique_tokens{ $token } = 1.0;
						}
				}

			close( FILE );

			my @unique_tokens = keys %unique_tokens;
			
			my $tcount = $#unique_tokens;
			
			if ( $tcount < $min_tokens )
				{	if ( $opt_delete )
						{	print "Deleting $file - has only $tcount tokens\n";
							unlink( $file );
							next;
						}
						
					print "Skipping $file - has only $tcount tokens\n";
					next;	
				}
				
			$file_num++;
			
			# Put the tokens into the main hash
			foreach ( @unique_tokens )
				{	my $token = $_;
					next if ( ! defined $token );
					
					if ( exists $token_occurrences{ $token } )
						{	$token_occurrences{ $token } += 0 + 1;
						}
					else
						{	$token_occurrences{ $token } = 0 + 1;
						}
							
				}

		}

	my $token_count = scalar keys %token_occurrences;
	
	lprint "Processed $token_count tokens in $file_num token files\n";

	return ( $file_num, %token_occurrences );
}



################################################################################
#
sub MakeTokenProbabilityHashFromInternet( $$ ) 
#
# Given a list of urls, go through all them
# treat each one as a "file", and count each token
#
################################################################################
{	my $category_num	= shift;
	my $cat_type		= shift;   #  Either misses or hits
	
    my $good_urls = 0 + 0;
    my %token_occurrences;

    #  Pick the right table
    my $tablename = "IpmContentCategoryHits";
    $tablename = "IpmContentCategoryMisses" if ( $cat_type eq "misses" );


    my $cmd = "SELECT URL from $tablename WHERE CategoryNumber = $category_num";

    my $sth = $dbh->prepare( $cmd );
    $sth->execute() or &UsageError( $DBI::errstr );

    my $counter = 0 + 0;
    my @urls;


    while ( my ( $url ) = $sth->fetchrow_array() )
        {   $counter++;
            push @urls, $url;            
        }

    $sth->finish();


	if ( ! $counter )
		{	lprint "Found no URLs in $tablename for category number $category_num\n";
			return( $good_urls, %token_occurrences );
		}
		
		
    # Process the urls
    my $url_num = 0 + 0;


	foreach ( @urls )
		{	next if ( ! $_ );
			my $url = $_;

			$url_num++;            

			lprint "Reading URL: $url ...\n";


			my  @tokens;
			my %link_urls;
			my @ipaddresses = ();
			my %labels;

			
			# Read the tokens from the URL
			my ( $token_count, $errmsg ) = &TokenizeUrl( $url, \@tokens, \%link_urls, \@ipaddresses, $max_tokens, \%labels );
			
			if ( ! $token_count )
				{   if ( $opt_clean )
						{   lprint "Deleting dead URL $url\n";
							$sth = $dbh->prepare( "DELETE $tablename WHERE URL like ? AND CategoryNumber = $category_num" );
							$sth->bind_param( 1, $url, DBI::SQL_VARCHAR );
							$sth->execute();
							$sth->finish();
						}
				}

			my $catname = &CategoryName( $category_num );
			my $dump_dir = ".\\$catname\\$cat_type";
			
			&DumpTokensFile( $dump_dir, $url, $errmsg, \@tokens, \%link_urls, \%labels ) if ( $opt_tokens );
			
			$good_urls++;
			my %unique_tokens;

			foreach ( @tokens )  
				{	next if ( ! $_ );
					
					my $token = $_;
					
					# Only count a unique token once per each file
					if ( ! exists $unique_tokens{ $token } )  
						{    
							# Count the token
							$token_occurrences{ $token } += 1.0;
							$unique_tokens{ $token } = 1.0;
						}  #  end of !exists $unique_tokens

				}  # end of foreach token_list

		}  # end of foreach @urls


	my $token_count = scalar keys %token_occurrences;
	lprint "Processed $token_count tokens in $good_urls urls\n";


    return( $good_urls, %token_occurrences );
}



################################################################################
# 
sub UsageError
#
#	Some sort of error occurred and I can't go on
#
################################################################################
{
	lprint "@_\n";
	exit( 1 );	
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "IpmBuildKeywords";

    bprint <<".";
Usage: $me [OPTION(s)] -c CATNAME
Builds a category keywords file from the hits and misses URLs.

    
  -c, --category=CATNAME category to build keywords for
  -d, --delete           to delete any token file that has too few keywords
  -e, --errorpercent     expected error percentage of hit URLs
                         default is $error_percent\% errors
  -l, --lang             to build a language keywords file
  -m, --minimum=NUM      minimum urls a keyword must be used in before it is 
                         considered important.  The default is $min_frequency URLs
  -o, --output=FILE      output file to put the important keywords, values,
                         and frequencies.  The default is "CATNAME.keywords".
  -p, --purge            purge hits or misses URLs that have http errors
  -r, --readtokens       builds keywords by reading saved token files
                         uses \.\\CATNAME\\hits\\tokens and \.\\CATNAME\\misses\\tokens
  -s, --sensitivity      keyword sensitivity, 50 default, 100 most aggressive
  -w, --writetokens      write token and link files for each URL
                         uses \.\\CATNAME\\hits\\tokens and \.\\CATNAME\\misses\\tokens
  -h, --help             display this help and exit
  -v, --version          display version information and exit
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
    my $me = "IpmBuildKeywords";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit;
}


################################################################################

__END__

:endofperl
