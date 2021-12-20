################################################################################
#!perl -w
#
# Rob McCarthy's version of corpus building perl - IpmSpamTokens
#
#  Copyright 2003 Lightspeed Systems Corp.
#
################################################################################


# Pragmas
use strict;


use Getopt::Long;
use Content::File;


my %nonspam_occurrences;
my $nonspam_files = 0;

my %spam_occurrences;
my $spam_files = 0;


my $spamtokens_file		= "SpamTokens.txt";			# This is the name of the file that is ftp'd from Lightspeed
my $corpus_file			= "SpamTokens.txt";         # This is named "localtokens.txt" if in archive mode
my $archive_corpus_file = "LocalTokens.txt";
my $spam_directory		= "\.\\spam";
my $notspam_directory	= "\.\\notspam";



my $_version = "2.0.0";
my $opt_version;
my $opt_help;
my $opt_wizard;		# True if I shouldn't display headers or footers



#  These are all the fudge factors
my $max_files = 0 + 20000;				# The maximum number of files to build the corpus from, either spam or ham
my $min_frequency = 0 + 20;				# Number of times a token needs to be used before it is considered significant
my $maxsize = 0 + 50000;		        # Ignore files that are larger
my $pure_spam = 0 + 0.9;		       	# Probability of a token that only occurs in a spam file
my $pure_notspam = 0 + 0.1;	        	# Probability of a token that only occurs in a non spam file
my $expected_good_to_bad = 0 + 1.15;    # This is the ratio of the expected number of non spams to spams in a normal day of email
my $archive_mode = -1;                  # True if the spam and hams should be read out of the Mail Archive directory
my $opt_archive;                        # Set if archive mode should be turned off  
my $opt_dir;                            # Directory of the Spam Tokens file
my $bad_token_value = 0 + 0.4;			# The neutral value of a token in the bad token list


my %bad_tokens = (						# The list of bad tokens - these are bad because my sampling artifically raising their spam value
	ffffff				=> 0,
	lightspeed			=> 0,
	lightspeedsystems	=> 0,
	cleanmail01			=> 0,
	cleanmail1			=> 0,
	bgcolor				=> 0,
	body				=> 0,
	font				=> 0,
	face				=> 0
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
        "a|archive"		=> \$opt_archive,
        "d|directory=s" => \$opt_dir,
        "f|filename=s"	=> \$corpus_file,
        "n|notspam=s"	=> \$notspam_directory,
        "m|minimum=s"	=> \$min_frequency,
        "s|spam=s"		=> \$spam_directory,
        "v|version"		=> \$opt_version,
		"w|wizard"		=> \$opt_wizard,
        "h|help"		=> \$opt_help
    );


    &StdHeader( "IpmSpamTokens" ) if ( ! $opt_wizard );

    $archive_mode = undef if ( $opt_archive );

    if ( $ARGV[ 0 ] )  {  $notspam_directory = $ARGV[ 0 ];  $archive_mode = undef;  } 
    if ( $ARGV[ 1 ] )  {  $spam_directory = $ARGV[ 1 ];  }


    &Usage() if ($opt_help);
    &Version() if ($opt_version);


    #  Figure out what directory to use
    $opt_dir = &SoftwareDirectory() if ( !$opt_dir );


    if ( $archive_mode )
		{	$notspam_directory = $opt_dir . "\\Mail Archive";
			$spam_directory = $notspam_directory;
			$corpus_file = $archive_corpus_file;
			&ReadSpamTokens();
		 
			# Delete the old localtokens file
			my  $full_filename = $opt_dir . "\\$corpus_file";
			unlink( $full_filename );
			bprint "Reading Mail Archive directory to learn local tokens ...\n";
		}

     
    # Process the non-spam files
    bprint "Processing non-spam (ham) files ... \n";
    my $new_nonspam_files;
    my %new_tokens;
    ( $new_nonspam_files, %new_tokens ) = &MakeTokenProbabilityHashFromDirectory( $notspam_directory, undef );
		
    bprint "Done processing $new_nonspam_files non-spam (ham) emails from $notspam_directory\n";
    $nonspam_files += $new_nonspam_files;
	
    foreach ( keys %new_tokens )
       {  if ( defined( $nonspam_occurrences{ $_ } ) )
            {   $nonspam_occurrences{ $_ } += $new_tokens{ $_ };
                 next;
            }

          $nonspam_occurrences{ $_ } = $new_tokens{ $_ };
       }  

    &FatalError( "$nonspam_files is not enough nonspam files to build new spam tokens file.\n" )  if ( $nonspam_files < 500 );


    # Process the spam files
    bprint "Processing spam files ... \n";
    my $new_spam_files;
    ( $new_spam_files, %new_tokens ) = &MakeTokenProbabilityHashFromDirectory( $spam_directory, 1 );
	
    bprint "Done processing $new_spam_files spam emails from $spam_directory\n";
    
	$spam_files += $new_spam_files;
    foreach ( keys %new_tokens )
       {  if ( defined( $spam_occurrences{ $_ } ) )
            {   $spam_occurrences{ $_ } += $new_tokens{ $_ };
                next;
            }

          $spam_occurrences{ $_ } = $new_tokens{ $_ };
       }  

    &FatalError( "$spam_files is not enough spam files to build new spam tokens file.\n" )  if ( $spam_files < 500 );
    &FatalError( "No new spam and nonspam files to build new spam tokens file.\n" )  if ( ( $new_spam_files + $new_nonspam_files ) < 1 );


    #  Check the ratio of spam and nonspam file for rationality
    my $ratio_range = ( $spam_files + 1 ) / ( $nonspam_files + 1 );
    &FatalError( "The ratio of $nonspam_files nonspam to $spam_files spam files is not close enough to even\nto build new spam tokens file.\n" )  if ( ( $ratio_range < ( 0 + .5 ) )  ||  ( $ratio_range > ( 0 + 2 ) ) );


    #  Make sure that the word "the" has the count of all of the files used
    $nonspam_occurrences{ "the" } = $nonspam_files;
    $spam_occurrences{ "the" } = $spam_files;


    if ( $archive_mode )
		{   bprint( "Merged together $nonspam_files non-spam files, $spam_files spam files\n" );
		}


     my %all_tokens = %nonspam_occurrences;
     foreach ( keys %spam_occurrences )
        {   $all_tokens{ $_ } = 1 if ( !defined( $all_tokens{ $_ } ) );
        }


     my @tokens_list = sort keys %all_tokens;
     %all_tokens = ();


    # Open the corpus file
    my  $full_filename = $opt_dir . "\\$corpus_file";

    bprint "Creating spam tokens file: $full_filename ...\n";

    if ( !open CORPUS, ">$full_filename" )
		{  &FatalError( "Cannot open $full_filename: $!\n" );
		}


    my  $badlist_messagecount = $spam_files;
    my  $goodlist_messagecount = $nonspam_files;
    my $token_counter = 0 + 0;
	foreach ( @tokens_list )
		{	next if ( !$_ );

			my  $token = $_;

            #  Use the same variable names as Paul Graham
            my  $goodcount = 0 + 0;
    		my  $badcount = 0 + 0;

			if ( defined( $nonspam_occurrences{ $token } ) )
  				{  $goodcount = $nonspam_occurrences{ $token };
				}

            if ( defined ( $spam_occurrences{ $token } ) )
				{  $badcount = $spam_occurrences{ $token };
				}

             #  Is this token used enough to keep?
             my $total = $goodcount + $badcount;
             next if ( $total < $min_frequency );

			# Normalize the goodvalue to account for the sample size and factor in the fudge amount
			my $goodnorm =  $expected_good_to_bad * ( ( $goodcount * $badlist_messagecount ) / $goodlist_messagecount );

			#  Calculate the percentage of the time this token appears in a spam file versus a non spam file
			my $pw = $badcount / ( $goodnorm + $badcount );

			#  Make sure that rare words don't totally drive the calculation wild
			if ( $pw > $pure_spam )
                {  $pw = $pure_spam;
                }

			if ( $pw < $pure_notspam )
                {  $pw = $pure_notspam;
                }

			# Check to see if it is in our bad token list
			if ( defined( $bad_tokens{ $token } ) )
				{	$pw = $bad_token_value;
					$badcount = 0 + 1000;
					$goodcount = ( $badcount / $pw ) - $badcount;
				}
				
			#  Round off to 4 decimal places
			my $temp = 0 + sprintf( "%1.4f", $pw );

			print CORPUS "$token $temp $goodcount $badcount\n";

			$token_counter++;
        }

    close CORPUS;

    bprint "Created $full_filename with $token_counter tokens\n";

    &StdFooter if ( ! $opt_wizard );

    exit;
}



################################################################################
#
sub ReadSpamTokens()
#
#  Read the existing the spam tokens file
#
################################################################################
{
    $nonspam_files = 0 + 0;
    $spam_files = 0 + 0;

    # Load the spam tokens
    my  $full_filename = $opt_dir . "\\$spamtokens_file";

    bprint "Reading in the Spam Tokens file: $full_filename ... \n";

    open TOKENS, "<$full_filename" or &FatalError( "Cannot open $full_filename\n  $!" );

    my $counter = 0;
    while ( <TOKENS> )
       {	chomp;
			my $line = $_;
			my ( $token, $weight, $good, $bad ) = split /\s/, $line, 4;

			next if ( !$token );

			$counter++;

			if ( $bad > 0 )
				{  $spam_occurrences{ $token } = 0 + $bad;
				}

			if ( $good > 0 )
				{  $nonspam_occurrences{ $token } = 0 + $good;
				}


              #  Is this my "the" token that holds the count of spam and nonspam files?
              next if ( $token ne "the" );
 
              $spam_files = 0 + $bad;
              $nonspam_files = 0 + $good;
		}

    close TOKENS;

    bprint "Read in $counter tokens from $full_filename\n";
    bprint "Built from $nonspam_files non-spam and $spam_files spam files\n\n";

    return( 0 );
}



my %token_occurrences;
################################################################################
#
sub MakeTokenProbabilityHashFromDirectory( $$ )
#
# Given a directory name, go thru all the files in that directory,
#	treat each one as an email, and count how many times each token
#	appears in it.  A "token" is any group of alphanumerics, apostrophes,
#	dashes, and dollar signs -- words, in other words.
#
################################################################################
{	my $directory	= shift;
	my $spam		= shift;
	
	my @files;
	my $number_of_files = 0 + 0;
	my $retcode;

	%token_occurrences = ();  # Clear the hash

	opendir( DIR, $directory ) or &FatalError( "Can not opendir $directory: $!" );


	while ( my $file = readdir( DIR ) )
		{   next if ( $file eq '.' );
			next if ( $file eq '..' );
			last if ( $number_of_files >= $max_files );

			#  Is it a sub directory?
			if ( opendir( SUBDIR, "$directory\\$file" ) )
				{   while ( my $subfile = readdir( SUBDIR ) )
						{	next if ( $subfile eq '.' );
							next if ( $subfile eq '..' );
							last if ( $number_of_files >= $max_files );

							# In archive mode, spam files start with s and ham files start with h
							# And weird files start with something else
							if ( $archive_mode )
								{	my $spam_file = $subfile =~ m/^s/;
									my $ham_file = $subfile =~ m/^h/;

									next if ( !$spam_file  &&  !$ham_file );
									next if ( $spam  &&  $ham_file );
									next if ( !$spam  &&  $spam_file );
								}

							$retcode = &TokenizeFile( "$directory\\$file", $subfile );
							$number_of_files++ if ( ! $retcode );
						}

					closedir( SUBDIR );
				} 
                
			else  #  It is just a file
				{	# In archive mode, spam files start with s and ham files start with h
					# And weird files start with something else
                    if ( $archive_mode )
						{	my $spam_file = $file =~ m/^s/;
							my $ham_file = $file =~ m/^h/;

							next if ( !$spam_file && !$ham_file );
							next if ( $spam && $ham_file );
							next if ( !$spam && $spam_file );
						}

					$retcode = &TokenizeFile( $directory, $file );
					$number_of_files++ if ( ! $retcode );
				}
			}

	closedir( DIR );
	
	return ( $number_of_files, %token_occurrences );
}



################################################################################
# 
sub TokenizeFile( $$ )
#  Given a directory and a file, split it in to tokens and add it to the token_occurrences
#
################################################################################
{   my $dir = shift;
    my $file = shift;
    my @token_list=[];

	my %unique_tokens;

	my $fsize = ( stat( "$dir\\$file" ) )[7];
	
	return( -1 ) if ( ! $fsize );

	if ( $fsize > $maxsize )
		{	#if the file is too big, just ignore it
			bprint "Ignoring large file $file\n";
			return( -1 );
		}

	return( -1 ) if ( !open( FILE, "<$dir\\$file" ) );

	while (<FILE>)
		{	# Split into tokens
			@token_list = split(/[^a-zA-Z\d]+/);
	  
			foreach ( @token_list )	
				{	# Length restriction
					my $len = length;
					my $token = lc( $_ );

					next if ( ($len > 40 ) || ( $len < 3) );

					# Ignore all-numeric tokens
					next if (/^[0-9.]+$/);

					# Ignore tokens that start with a number
					next if ( m/^[0-9]/ );
							
					#  Only count a unique token once per each file
					if ( !defined $unique_tokens{ $token }  )  
						{	# Count the token
							$token_occurrences{ $token } += 0 + 1;
							$unique_tokens{ $token } = 0 + 1;
						}
				}
		}

	close( FILE );

	return( 0 );
}



################################################################################
# 
sub UsageError ($)
#
################################################################################
{
    my $me = "IpmSpamTokens";

    bprint "$_[0]\n\n" if (@_);

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
    my $me = "IpmSpamTokens";

    bprint <<".";
Usage: $me [OPTION(s)] [ham directory] [spam directory]

Running IpmSpamTokens with no arguments will cause the
program to read up to 10,000 spam and ham emails in 
the default mail directory, statistically analyze them, and
finally merge the new tokens with the "SpamTokens.txt" file,
creating a new file called "LocalTokens.txt".

Running IpmSpamTokens with the ham and spam directory
options will cause the program to read all of the emails
in those directories and create the "SpamTokens.txt" file.

Default email directory is "\\Software Directory\\Mail Archive"

  -d, --directory=PATH   to change default email directory
  -f, --filename=FILE    to set the spam tokens file name
                         default = "SpamTokens.txt" or "LocalTokens.txt"
  -h, --help             display this help and exit
  -m, --minimum          to set the mimimum number of files for a
                         relevant token to use - default = 20
  -n, --notspam          to set the notspam directory
  -s, --spam             to set the spam directory
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
    my $me = "IpmSpamTokens";

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
