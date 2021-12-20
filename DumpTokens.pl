################################################################################
#!perl -w
#
# DumpTokens
# Given a list of urls, dump to tkens and links to a directory
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
use Benchmark;
use File::Copy;
use Sys::Hostname;
use Archive::Zip qw( :ERROR_CODES );

use HTML::Entities;
use HTML::LinkExtor;
use HTTP::Request;
use HTTP::Response;
use HTTP::Cookies;
use LWP::Simple;
use LWP::UserAgent;
use LWP::ConnCache;
use URI::Heuristic;



use Content::File;
use Content::SQL;
use Content::Categorize;
use Content::Category;
use Content::FileIntegrity;
use Content::ScanUtil;
use Content::Process;
use Content::EmailError;
use Content::ImageAnalyze;
use Content::FileInfo;
use Content::TestAnalyze;



# Common directories
my $opt_prog_dir				= 'J:\\DonePrograms';		# This is the root directory of the program done directory
my $dump_directory				= 'C:\\Content\\Dump';		# This is the directory of working URLs to dump and categorize
my $log_directory				= 'C:\\Content\\Log';		# This is the directory to write the logs to
my $tmp_directory				= 'C:\\Content\\tmp';		# This is the tmp directory to download programs and images to



# Options
my $opt_help;
my $opt_version;
my $opt_all;					# If True then download absolutely everything I can
my $opt_dir;					# The directory to dump the tokens and links to
my $opt_website;				# Set to a website if I am just supposed to dump that
my $opt_debug;
my $opt_infile;					# This is the filename of the url file that I should download
my $opt_existing;				# If True then overwrite existing token files
my $opt_benchmark;				# True if I should benchmark the speed
my $opt_log_file;				# The name of the log file to use
my $opt_verbose;
my $opt_content;				# If True then save the html content to disk
my $opt_content_dir;			# If set then this is the directory to put .content.htm files into
my $opt_programs;				# If True then download programs to the Program Archive
my $opt_images;					# If True then download images - downloading images is usually done by the Categorize command so this should be undefined normally in the DumpTokens program


# Globals
my $_version		= "1.0.0";
my $working_dir;					#  This is usually the current directory
my $max_tokens		= 0 + 1500;		# The maximum number of tokens to read from a URL before quitting - this is usually smaller than when building keywords in IpmBuildKeywords					
my $max_site_urls	= 0 + 250;		# The maximum number of URLs to read from the local site when getting tokens
my %prog_hash;						# A hash of recently downloaded programs - so that I don't download the same program twice
my $my_pid;							# My process ID
my $current_work;					# The file name of my current work file

my $max_program_download	= 0 + 100000000;	# The maximum number of bytes of programs to download from any given website
my $max_image_download		= 0 + 2000000;		# The maximum number of bytes of images to download from any given website
my $max_image_count			= 0 + 25;			# The maximum number of images to download from any given site



my $dbhProgram;						# The handle to the Program database
my $dbhCategory;



################################################################################
#
MAIN:
#
################################################################################
{  

#&CheckUrlsContent( "18tini.net.content.htm", "18tini.net" );
#die;

#my $readable = &ReadableUrl( "18tini.net/index.php?cat=tini", "18tini.net" );
#print "Readable\n" if ( $readable );
#print "not Readable\n" if ( ! $readable );
#die;

    # Get the options
    Getopt::Long::Configure("bundling");

    my $options = Getopt::Long::GetOptions
    (
        "a|all"			=> \$opt_all,
        "b|benchmark"	=> \$opt_benchmark,
		"c|content"		=> \$opt_content,
		"d|directory=s"	=> \$opt_dir,
        "e|existing"	=> \$opt_existing,
 		"f|logfile=s"	=> \$opt_log_file,
		"i|images"		=> sub 
							{	if ( $opt_images ) 
									{	$opt_images = undef;
									} 
								else 
									{	$opt_images = 1;
									} 
							},
 		"m|max=i"		=> \$max_tokens,
		"p|programs"	=> sub 
							{	if ( $opt_programs ) 
									{	$opt_programs = undef;
									} 
								else 
									{	$opt_programs = 1;
									} 
							},
		"s|size=i"		=> \$max_program_download,
		"w|website=s"	=> \$opt_website,
 		"u|urls=i"		=> \$max_site_urls,
		"v|verbose"		=> \$opt_verbose,
		"x|xxx"			=> \$opt_debug,
        "h|help"		=> \$opt_help
    );


	$SIG{'INT'} = 'INT_handler';

	# Get rid of too big or too small error messages	
	if ( ! $opt_debug )
		{	local $SIG{__WARN__} = sub 
				{	warn @_ unless $_[0] =~ m(^.* too (?:big|small)); 
				};
		}
		

	# Figure out the hostname
	my $hostname = uc( hostname );
	$hostname = "UNKNOWN" if ( ! defined $hostname );

	$my_pid = &ProcessGetCurrentProcessId();
	
	
	mkdir( $log_directory );
	$opt_log_file = "$log_directory\\DumpTokens-$my_pid.log" if ( ! defined $opt_log_file );


	my $dir = getcwd;
	$dir =~ s#\/#\\#gm;

	# Does the opt_logfile include a pathname?  If not, use the current directory
	if ( ! ( $opt_log_file =~ m/\\/ ) )
		{	$opt_log_file = $dir . "\\" . $opt_log_file if ( defined $dir );
		}

	&StdHeader( "DumpTokens" );
	
	
    &SetLogFilename( $opt_log_file, undef );
	&lprint( "Logging set to $opt_log_file\n" ) if ( defined $opt_log_file );
 
	&Usage() if ($opt_help);
    &Version() if ($opt_version);

	if ( ! $opt_website )
		{	$opt_infile = shift if ( ! $opt_infile );
			&Usage() if ( ! $opt_infile );
		}
		
	if ( ! $opt_dir )
		{	$opt_dir = shift;
		}
		
	&TrapErrors( "$log_directory\\DumpTokensErrors-$my_pid.log" ) if ( ! $opt_debug );
	
	
	&lprint( "My process ID (pid) = $my_pid\n" ) if ( defined $my_pid );
	&lprint( "My current directory = $dir\n" ) if ( defined $dir );


	# Show options
	lprint "Dumping tokens from input file $opt_infile ...\n"		if ( ! $opt_website );
	lprint "Dumping tokens from website $opt_website ...\n"			if ( $opt_website );
	lprint "Overwriting existing URL tokens files ...\n"			if ( $opt_existing );
	lprint "Downloading any programs found ...\n"					if ( $opt_programs );
	lprint "Downloading a random sample of images found ...\n"		if ( $opt_images );
	lprint "NOT downloading any images ...\n"						if ( ! $opt_images );
	lprint "Saving HTM content files ...\n"							if ( $opt_content );
	
	
	if ( $opt_all )
		{	lprint "Downloading all the content possible from each URL ...\n";
			$max_tokens = 0 + 150000;	# Put this to really big so I that get everything
			$max_site_urls = 0 + 1000;
		}
	else
		{	lprint "Downloading a maximum of $max_tokens tokens from each website ...\n";
			lprint "Downloading a maximum of $max_site_urls URLs from each website ...\n";
		}
		
	lprint "Downloading a maximum of $max_program_download bytes of programs from each website ...\n" if ( ( $max_program_download )  &&  ( $opt_programs ) );


	if ( $opt_programs )
		{	# Connect to the category database
			$dbhCategory = &CategoryConnect();
			if ( ! $dbhCategory )
				{
lprint "Unable to open the Remote Category database.
Run ODBCAD32 and add the Category SQL Server as a System DSN named
\'TrafficCategory\' with default database \'Category\'.\n";

					my ( $ok, $msg ) = &EmailError( "Unable to open the Remote Category database", "DumpTokens", $my_pid );
					&CategoryClose() if ( $dbhCategory );
					$dbhCategory = undef;
					
					&ProgramClose() if ( $dbhProgram );
					$dbhProgram = undef;
					exit( 1 );
				}
				
				
			$dbhProgram = &ConnectRemoteProgram();
			
			if ( ! $dbhProgram )
				{
lprint "Unable to open the Remote Program database.
Run ODBCAD32 and add the PROGRAM SQL Server as a System DSN named
\'ProgramRemote\' with default database \'Program\'.\n";

					&CategoryClose() if ( $dbhCategory );
					$dbhCategory = undef;
					
					&ProgramClose() if ( $dbhProgram );
					$dbhProgram = undef;
					exit( 1 );
				}
		}	# end if if $opt_programs
		
		
	# Default to the current directory if the opt_dir isn't set by now
	$working_dir = getcwd();
	
	if ( defined $opt_dir )
		{	if ( $opt_dir =~ m/^\.\\/ )
				{	$opt_dir =~ s/^\.\\//;
					$working_dir =~ s/\\$//;
					$working_dir = $working_dir . '\\' . $opt_dir;
				}
			else
				{	$working_dir = $opt_dir;
				}
		}
		
	$working_dir =~ s#\/#\\#gm;
	lprint "Using working directory $working_dir\n";


	if ( ! -d $working_dir )
		{	lprint "Working directory $working_dir does not exist!\n";

			my ( $ok, $msg ) = &EmailError( "Working directory $working_dir does not exist!", "DumpTokens", $my_pid );
			&CategoryClose() if ( $dbhCategory );
			$dbhCategory = undef;
			
			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;
			exit( 2 );
		}


	if ( ( $opt_programs )  &&  ( ! -d $opt_prog_dir ) )
		{	lprint "Program archive directory $opt_prog_dir does not exist!\n";
			my ( $ok, $msg ) = &EmailError( "Program archive directory $opt_prog_dir does not exist!\n", "DumpTokens", $my_pid );
			&CategoryClose() if ( $dbhCategory );
			$dbhCategory = undef;
			
			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;
			exit( 3 );
		}
	lprint "Using program archive directory $opt_prog_dir ...\n";
	
	mkdir( $tmp_directory );
	if ( ! -d $tmp_directory )
		{	lprint "Tmp Program directory $tmp_directory does not exist!\n";
			my ( $ok, $msg ) = &EmailError( "Tmp Program directory $tmp_directory does not exist!\n", "DumpTokens", $my_pid );
			&CategoryClose() if ( $dbhCategory );
			$dbhCategory = undef;
			
			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;
			exit( 3 );
		}
	lprint "Using tmp program directory $tmp_directory ...\n";
	
	if ( ! -d $dump_directory )
		{	lprint "Dump directory $dump_directory does not exist!\n";
			my ( $ok, $msg ) = &EmailError( "Dump directory $dump_directory does not exist!\n", "DumpTokens", $my_pid );
			&CategoryClose() if ( $dbhCategory );
			$dbhCategory = undef;
			
			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;
			exit( 5 );
		}

	if ( ( ! $opt_website )  &&  ( ! open( INFILE, "<$opt_infile" ) ) )
		{	lprint "Unable to open file $opt_infile: $!\n";
			my ( $ok, $msg ) = &EmailError( "Unable to open file $opt_infile: $!\n", "DumpTokens", $my_pid );
			&CategoryClose() if ( $dbhCategory );
			$dbhCategory = undef;
			
			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;
			exit( 6 );
		}
		
	
	# Figure out the file name that has the current work the DumpTokens program is on
	$current_work = "$dump_directory\\DumpTokensWork-$my_pid.log";
	&lprint( "Saving current working url to file $current_work ...\n" );
	
	
	$opt_content_dir = $working_dir	if ( $opt_content );
	
	lprint "Saving HTML content to directory $opt_content_dir ...\n" if ( defined $opt_content_dir );


	# Tell the Categorize.pm module about any options
	my %options = (
			"debug"					=> $opt_debug,
			"contentdir"			=> $opt_content_dir,
			"max tokens"			=> $max_tokens,
			"maxsiteurls"			=> $max_site_urls
			);
			
		
	&CategorizeOptions( \%options );
		
		
	# Load up any virus signatures ...	
	my $alt_virus_filename	= "\\content\\keywords\\VirusSignatures.nx";
	
	if ( -e $alt_virus_filename )
		{	my $signature_count = &HtmlVirusLoad( $alt_virus_filename );
			lprint "Loaded $signature_count HTML virus signatures from $alt_virus_filename\n";
		}
	else
		{	lprint "No virus signature file found!\n";
		}
	

	# Can I talk out to the Internet?
	if ( ! &CheckConnectivity() )
		{	lprint "Connectivity failure: Unable to connect to test websites!\n";

			lprint "Waiting 10 minutes to try the connectivity test one more time ...\n";
			
			for ( my $i = 1;  $i < 11;  $i++ )
				{	sleep( 60 );
					lprint "Waited $i minutes so far ...\n";
				}
				
			if ( ! &CheckConnectivity() )
				{	lprint "Connectivity failure: Unable to connect to test websites!\n";
					my ( $ok, $msg ) = &EmailError( "Connectivity failure: Unable to connect to test websites!\n", "DumpTokens", $my_pid );
				
					&CategoryClose() if ( $dbhCategory );
					$dbhCategory = undef;
					
					&ProgramClose() if ( $dbhProgram );
					$dbhProgram = undef;
					exit( 9 );
				}
				
			lprint "Finally passed the connectivity check!\n";
		}
		
		
	&BenchmarkStart() if ( $opt_benchmark );
	
	&CategorizeVerbose( $opt_verbose );
	

	my @urls;
	
	# Am I supposed to take a look at just one website?
	if ( $opt_website )
		{	push @urls, $opt_website;
		}
	else
		{	while (my $url = <INFILE>)
				{	chomp( $url );
					next if ( ! $url );
					
					$url =~ s/^\s+//;
					next if ( ! $url );
					
					$url =~ s/\s+$//;
					next if ( ! $url );
					
					push @urls, $url;
				}
				
			close( INFILE );
			
			&BenchmarkTime( "Read URL File" );
		}
		
	
	# Check to make sure that I haven't got some weird file instead of a url file
	my $url_count		= 0 + 0;
	my $bad_url_count	= 0 + 0;
	
	foreach( @urls )
		{	my $url = $_;
			next if ( ! $url );
			if ( length( $url ) > 0 + 512 )
				{	lprint "URL $url is too long\n";
					$bad_url_count++;
				}
				
			$url_count++;
		}
		
	
	# Was there anything weird in the URL file?	
	if ( ( $url_count > 0 + 400 )  ||  ( $bad_url_count ) )
		{	lprint "URL file $opt_infile contains too many urls, or has badly formed urls\n";
			my ( $ok, $msg ) = &EmailError( "URL file $opt_infile contains too many urls, or has badly formed urls\n", "DumpTokens", $my_pid );
			&CategoryClose() if ( $dbhCategory );
			$dbhCategory = undef;
			
			&ProgramClose() if ( $dbhProgram );
			$dbhProgram = undef;
			
			# Delete the current work file now that I've finished
			unlink( $current_work );

			exit( 10 );
		}
		

	my $dump_start = new Benchmark;
	&DumpTokens( $working_dir, @urls );
	&BenchmarkTimeSection( $dump_start, "DumpTokens" );
	
	
	# Delete the current work file now that I've finished
	unlink( $current_work );
	
	&ProgramClose() if ( $dbhProgram );
	$dbhProgram = undef;
	
	# Write out an OK file so the the controlling task knows that everything is OK
	my $finished_log_file = "$log_directory\\DumpTokens-$my_pid.OK";
	open( FINISHED, ">$finished_log_file" );      	   
	print FINISHED "Done\n";
	close( FINISHED );

	&BenchmarkEnd( $hostname, $my_pid, $dbhCategory ) if ( $opt_benchmark );
	
	&CategoryClose() if ( $dbhCategory );
	$dbhCategory = undef;
	
	chdir( $dir );
	
	&StdFooter;

exit( 0 );
}



################################################################################
#
sub INT_handler( $ )
#
#  Interrupt handler
#
################################################################################
{		
	#  Close up the databases
	$dbhCategory->disconnect	if ( $dbhCategory );
	$dbhCategory = undef;
	
	$dbhProgram->disconnect		if ( $dbhProgram );
	$dbhProgram = undef;
  
	exit( 253 ); 
}



################################################################################
#
sub TrapErrors( $ )
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = shift;
	
	return( undef ) if ( ! defined $filename );
	
	my $MYLOG;
	
	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	lprint( "Error logging set to $filename\n" ); 
}



################################################################################
#
sub DumpTokens( $@ ) 
#
# Given a list of urls, dump the tokens and the links to a directory
#
################################################################################
{	my $dir		= shift;
	my @urls	= @_;
	
	
	# Load any language definitions available
	&LanguagesLoad( undef );
	
    # Process the urls
    my $url_num = 0 + 0;
	my $done;
	
	while ( ! $done )
		{	my $line = $urls[ $url_num ];
			last if ( ! defined $line );
			
			$url_num++;            

			my @site_urls = split /\t/, $line;

			my $url = $site_urls[ 0 ];
			next if ( ! defined $url );

			# Find the root domain, if it exists
			my $root = &RootDomain( $url );
			next if ( ! defined $root );
			
			
			# See if the next lines are from the same root domain
			while ( my $next_line = $urls[ $url_num ] )
				{	my @next_site_urls = split /\t/, $next_line;

					my $next_url = $next_site_urls[ 0 ];
					last if ( ! defined $next_url );

					my $next_root = &RootDomain( $next_url );
					last if ( ! defined $next_root );
					
					last if ( $root ne $next_root );
					
					# The root domains match, so push this site urls into the array
					push @site_urls, @next_site_urls;
					$url_num++;
				}
			
			
			my $full_filename = &TokensFileName( $dir, $url, "token" );
			next if ( ! defined $full_filename );
			
			if ( ( ! $opt_existing )  &&  ( -e $full_filename ) )
				{	lprint "Skipping existing tokens file $full_filename\n";
					next;
				}
				

			lprint "Dumptokens started reading URL # $url_num: $url ...\n";


			# Save what I'm working on to a file so that QueueStart can restart me if I get stuck
			&CurrentWork( $opt_infile, $url ) if ( ! $opt_website );
			
			my  @tokens;
			my %link_urls;
			my @ipaddresses = ();
			my %labels;
			my $lang;
			my $charset;
			my %site_urls;
			my %virus_urls = ();


			# Fill the site urls hash if I know some already from the site_urls array
			foreach ( @site_urls )
				{	my $site_url = $_;
					next if ( ! $site_url );
					next if ( $site_url eq $url );
					$site_urls{ $site_url } = 0;
				}
				
				
			# Read the tokens from the URL
			my ( $token_count, $errmsg ) = &TokenizeUrl( $url, \@tokens, \%link_urls, \@ipaddresses, $max_tokens, \%labels, \$lang, \$charset, \%site_urls, \%virus_urls );

			&DumpTokensFile( $dir, $url, $errmsg, \@tokens, \%link_urls, \@ipaddresses, \%labels, $lang, $charset, \%site_urls, \%virus_urls );

			my $total_prog_downloaded_size	= 0 + 0;
			
			if ( $opt_programs )
				{	my $prog_count = 0 + 0;
					
					# Download any programs from this site
					while ( my $prog_url = each( %site_urls ) )
						{	next if ( $total_prog_downloaded_size > $max_program_download );
							
							# Can I ignore this url?
							next if ( &ReadableUrlIgnore( $prog_url, $url ) );

							next if ( ! &ProgramUrl( $prog_url ) );
							
							next if ( ( ! $opt_existing )  &&  ( &CategoryRecentProgramLink( $prog_url, $url ) ) );
							
							my ( $hex_file_id, $archive_file ) = &DownloadProgram( $dir, $prog_url, $url );
							
							if ( defined $hex_file_id )
								{	$prog_count++;
									&CategorySaveProgramLink( $hex_file_id, $prog_url, $url );
									
									my $size = -s $archive_file if ( $archive_file );
									$total_prog_downloaded_size += $size if ( $size );
								}
						}
					
					# Download any programs that this site links to
					while ( my $prog_url = each( %link_urls ) )
						{	next if ( $total_prog_downloaded_size > $max_program_download );
							
							# Can I ignore this url?
							next if ( &ReadableUrlIgnore( $prog_url, $url ) );

							next if ( ! &ProgramUrl( $prog_url ) );
							
							next if ( &CategoryRecentProgramLink( $prog_url, $url ) );
							
							my ( $hex_file_id, $archive_file ) = &DownloadProgram( $dir, $prog_url, $url );
							
							if ( defined $hex_file_id )
								{	$prog_count++;		
									&CategorySaveProgramLink( $hex_file_id, $prog_url, $url );
									
									my $size = -s $archive_file if ( $archive_file );
									$total_prog_downloaded_size += $size if ( $size );
								}
						}
					
					lprint "Downloaded $prog_count new programs from $url links\n" if ( $prog_count );
					lprint "Downloaded no new programs from $url links\n" if ( ! $prog_count );
					
					lprint "Downloaded a total of $total_prog_downloaded_size bytes of programs from $url\n";
				}

			if ( $opt_images )	# Am I downloading images?
				{	my $image_zip = &ImageAnalyzeDownload( $url, \%site_urls, $max_image_download, $max_image_count, $tmp_directory );
				}
		}  # end of foreach @urls

    return( $url_num );
}



################################################################################
#
sub CurrentWork( $$$ ) 
#
# Write out the stuff I'm currently working on so that I can be restarted
#
################################################################################
{	my $opt_infile	= shift;
	my $url			= shift;
	
	return( undef ) if ( ! open( CURRENT_WORK, ">$current_work" ) );
	print CURRENT_WORK "$opt_infile\t$url\n";
	close( CURRENT_WORK );
}



################################################################################
#
sub DownloadProgram( $$$ ) 
#
# Given a URL, download the program at that URL, and add the program info into 
# the program database.
# Return the hex file ID and the program file created, or undef if unsuccessful
#
################################################################################
{	my $dir			= shift;
	my $prog_url	= shift;
	my $url			= shift;
	
	
	# Clean off any parameters so that I can build a clean filename
	my $junk;
	( $prog_url, $junk ) = split /\&/, $prog_url, 2;
	( $prog_url, $junk ) = split /\#/, $prog_url, 2;
	( $prog_url, $junk ) = split /\?/, $prog_url, 2;
	
	$prog_url =~ s#\/+$##;
	$prog_url =~ s#\\+$##;
	$prog_url =~ s#\/+$##;
	
	
	# Have I just downloaded this same thing?
	if ( exists $prog_hash{ $prog_url } )
		{	lprint "Already downloaded $prog_url\n";
			return( undef, undef );
		}
		
	$prog_hash{ $prog_url } = 0;
	
	
	# Create a tmp file with the content
	my ( $domain, $url_ext ) = split /\//, $prog_url, 2;
	my $root = &RootDomain( $domain );
	return( undef, undef ) if ( ! defined $root );
	
	my $ext;
	my @parts = split /\./, $url_ext;
	
	# Is there a name extension?
	if ( $#parts > 0 )
		{	$ext = lc( $parts[ $#parts ] );
			$ext .= "_" if ( ! ( $ext =~ m/_$/ ) );
		}

	# Clean up the extension
	if ( $ext )
		{	$ext =~ s/\s+//g;
			$ext = lc( $ext ) if ( $ext );
			$ext = undef if ( ( $ext )  &&  ( $ext eq "_" ) );
		}
		
	if ( $ext )
		{	$ext = undef if ( length( $ext ) > 5 );
			$ext = undef if ( ( $ext )  &&  ( length( $ext ) < 3 ) );
		}
		
		
	my $final_dir	= $opt_prog_dir . "\\$root";
	$final_dir		= &CleanFileName( $final_dir );
	return( undef, undef ) if ( ! defined $final_dir );
	
	$final_dir		=~ s#\\+$##;		# Trim off any trailing backslash
	return( undef, undef ) if ( ! defined $final_dir );
	
	
	my $tmp_filename = $tmp_directory . "\\$domain" . ".tmp_";
	$tmp_filename = $tmp_directory . "\\$domain" . ".$ext" if ( $ext );


	# Delete the tmp filename if it already exists ...
	unlink( $tmp_filename );
	
	
	lprint "Trying to download a program from $prog_url to file $tmp_filename ... \n";
	
	my ( $ok, $errmsg ) = &ReadProgramUrl( $prog_url, $tmp_filename );
	
	if ( ! $ok )
		{	lprint "Error reading $prog_url: $errmsg\n" if ( defined $errmsg );
			lprint "Unknown error reading $prog_url\n" if ( ! defined $errmsg );
			unlink( $tmp_filename );
			return( undef, undef );
		}

	if ( ! -e $tmp_filename )
		{	lprint "Error: $tmp_filename does not exist\n";
			return( undef, undef );	
		}
		
	
	# If I have a zero length file then just delete it and go on ...
	if ( ! -s $tmp_filename )
		{	unlink( $tmp_filename );
			return( undef, undef );
		}


	lprint "Downloaded $prog_url OK\n";
	
	
	# Get all the file info that I can
	my %file_info;
	my @sections;
	$ok = &FileInfo( $tmp_filename, \%file_info, \@sections, $opt_verbose );	
	if ( ! $ok )
		{	lprint "Error getting file info for $tmp_filename\n";
			unlink( $tmp_filename );
			return( undef, undef );
		}


	my $file_id = $file_info{ FileID };
	
	
	if ( ! defined $file_id )
		{	lprint "Error getting file ID for $tmp_filename\n";
			unlink( $tmp_filename );
			return( undef, undef );	
		}
		
	my $hex_file_id = $file_info{ HexFileID };


	if ( &CategoryRecentProgramFileID( $hex_file_id ) )
		{	lprint "Recently processed this file ID, so skipping storing it ...\n";
			unlink( $tmp_filename );
			return( $hex_file_id, undef );	
		}

		
	my $hex_md5 = $file_info{ HexMD5 };
	
	
	if ( ! $hex_md5 )
		{	unlink( $tmp_filename );
			return( undef, undef );
		}
		
	
	my ( $fullpath, $renamed, $deleted ) = &RenameMD5( $tmp_filename, $hex_md5 );
	if ( ! $fullpath )
		{	unlink( $tmp_filename );
			return( undef, undef );
		}
		
	lprint "Renamed file to $fullpath ...\n";
	
	
	# Mark the hash that I downloaded this successfully	
	$prog_hash{ $prog_url } = 1;
	
	
	# Finally, copy the file to the final location ...
	&MakeDirectory( $final_dir );

	my ( $current_dir, $shortfile ) = &SplitFileName( $fullpath );
	
	my $final_filename = "$final_dir\\$shortfile";
	
	lprint "Copying $fullpath to $final_filename ...\n";
	$ok = copy( $fullpath, $final_filename );
	
	unlink( $fullpath );
	
	# Did I do the final copy OK?
	if ( ! $ok )
		{	unlink( $final_filename );
			my $err = $!;
			$err = "Unknown error" if ( ! $err );
			lprint "Error copying $fullpath to $final_filename: $err\n";
			return( undef, undef );	
		}
	
	lprint "Downloaded, calculated file info, added to the database, and copied OK file $final_filename\n";
	
	return( $hex_file_id, $final_filename );
}



################################################################################
# 
sub RenameMD5( $$ )
#
#  Given a full path filename, rename it to the MD5 file name, and return the new
#  name, and the rename status.  Delete duplicate files. Return undef if an error
#
################################################################################
{	my $fullpath	= shift;
	my $hex_md5		= shift;
	
	my ( $dir, $shortfile ) = &SplitFileName( $fullpath );
	
	my $ext;
	
	my @parts = split /\./, $shortfile;
	
	# Is there a name extension?
	if ( $#parts > 0 )
		{	$ext = lc( $parts[ $#parts ] );
			$ext .= "_" if ( ! ( $ext =~ m/_$/ ) );
		}

	# Clean up the extension
	if ( $ext )
		{	$ext =~ s/\s+//g;
			$ext = lc( $ext ) if ( $ext );
			$ext = undef if ( ( $ext )  &&  ( $ext eq "_" ) );
		}
		
	if ( $ext )
		{	$ext = undef if ( length( $ext ) > 5 );
			$ext = undef if ( ( $ext )  &&  ( length( $ext ) < 3 ) );
		}
		
	my $new_name = $hex_md5;
	$new_name = $hex_md5 . "." . $ext if ( $ext );
	
	my $full_new_name = $new_name;
	$full_new_name = $dir . "\\" . $new_name;
	
	# Is the file already named the right thing?
	return( $full_new_name, undef, undef ) if ( $full_new_name eq $fullpath );
	
	my $ok = rename( $fullpath, $full_new_name );


	# If renamed ok, return here
	if ( $ok )
		{	return( $full_new_name, 1, undef );
		}
		
		
	# If not ok, was it because the file already exists?
	if ( -f $full_new_name )
		{	rename( $full_new_name, $full_new_name );  # Rename it again to make sure the upper/lowercase is right

			# Is there an upper/lower case problem?
			if ( lc( $fullpath ) eq lc( $full_new_name ) )
				{	return( $full_new_name, 1, undef );
				}
				
			# Get rid of the duplicate	
			unlink( $fullpath );
			return( $full_new_name, undef, 1 );
		}
	
	# If I got to here, then I couldn't rename it at all
	return( $fullpath, undef, undef );
}



################################################################################
#
#   LWP::Simple modified code
#
################################################################################

my $ua;
my $cache;

sub rob_init_ua
{
 
	# Set it so that I reuse the same connection cache each time
	if ( ! $cache )
		{	$cache = LWP::ConnCache->new;
			$cache->total_capacity( 1 );
		}
		
    $ua = LWP::UserAgent->new( protocols_forbidden => ['https'] );
	$ua->agent("Mozilla/4.0 (compatible; MSIE 7.0;Windows NT 5.1;.NET CLR 1.1.4322;.NET CLR 2.0.50727;.NET CLR 3.0.04506.30)");
	$ua->cookie_jar( HTTP::Cookies->new( file => "dumptokens.cookies.txt") );
    $ua->env_proxy;
	$ua->timeout( 60 * 15 );	# 15 minute timeout
}


sub rob_getstore ($$)
{
  my($url, $file) = @_;
  &rob_init_ua() unless $ua;

	# Set the download size limit (12MB)
	my $max_size = (12 * 1024 *1024);	
	
  my $request = HTTP::Request->new(HEAD => $url);
  my $response = $ua->request($request);
	
	my $ok = is_success( $response );
	my $errmsg = $response->status_line;

	# A 200 errmsg is OK
	if ( $errmsg =~ m/^200/ )
		{
			my $content_length = $response->header('Content-Length');
			
			# Is this file too large?
			if (!defined $content_length || ($content_length < $max_size))
				{
					$request = HTTP::Request->new(GET => $url);
					$response = $ua->request($request, $file);
					
					$ok = is_success( $response );
					$errmsg = $response->status_line;
					
					$ok = 1 if ( $errmsg =~ m/^200/ );
				}
			else
				{
					$ok = undef;
					$errmsg = "File from $url is too large ($content_length) to download/process!\n";
				}
		}
	
	
  return( $ok, $errmsg );
}



################################################################################
#
sub ReadProgramUrl( $$ )
#
#  Read a program URL using the rob_getstore function
#
################################################################################
{	my $prog_url = shift;
	my $filename = shift;
		
	my $full_url = "http://" . $prog_url;
	
	my ( $ok, $errmsg ) = &rob_getstore( $full_url, $filename );
	
	return( $ok, $errmsg );
}



################################################################################
#
sub Test( $ )
#
#  Temporary test code
#
################################################################################
{	

my $content = "";

#if ( ! open( FILE, "<lesbellesfleur.com.content.htm" ) ) 
#	{	die "Unable to open file: $!\n";
#	}
if ( ! open( FILE, "<test.txt" ) ) 
	{	die "Unable to open file: $!\n";
	}
	
while ( my $line = <FILE> )
	{	next if ( $line =~ m/^\=\=\=\>/ );
		$content .= $line;
	}
close( FILE );


my $base = 	"lesbellesfleur.com";
my $root = 	"lesbellesfleur.com";
	my %link_urls	= ();
	my %site_urls	= ();

my $charset;
my $read_date = "now";

	&UrlsContent( $content, $base, $root, \%site_urls, \%link_urls, $charset, $read_date );

while ( my ( $key, $value ) = each( %site_urls ) )
	{	print "$key\t$value\n";
	}
	
	return( 1 ); 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "DumpTokens";

    bprint <<".";
Usage: $me urllist directory
Dump the tokens and links from each URL in the url file

  -a, --all            to dump all the content possible from each URL
  -b, --benchmark      to track performance benchmarks
  -c, --content        to dump html content to *.htm files  
  -d, --directory=DIR  directory to dump the tokens and links files
  -e, --existing       to overwrite existing URL tokens files
  -f, --logfile=FILE   file to use instead of the default log file
  -i, --images         to toggle on/off downloading any images found
  -m, --maxtokens=MAX  the maximum number of tokens to download - default $max_tokens 
  -p, --programs       to toggle on/off downloading any programs found
  -s, --size=SIZE      the maximum program bytes to download from each website
  -u, --urls=URLMAX    the maximum number of site urls to download
  -v, --verbose        verbose mode
  -w, --website SITE   to dump a single website
.
    &StdFooter;

    exit( 7 );
}



################################################################################
# 
sub Version
#
################################################################################
{
    my $me = "DumpTokens";

    bprint <<".";
$me $_version
.
    &StdFooter;

    exit( 8 );
}


################################################################################

__END__

:endofperl
