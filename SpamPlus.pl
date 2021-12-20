################################################################################
#!perl -w
#
# Rob McCarthy's version of SpamPlus.pl
#
#  Copyright 2009 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use warnings;
use strict;



use File::Glob;


use SpamPlus::File;
use SpamPlus::Options;
use SpamPlus::SpamPlus;
use SpamPlus::Util;



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
	&StdHeader( "SpamPlus" );

	# Do any module startup necessary
	&debug( "SpamPlus start ...\n" );
	&SpamPlusStart( @_ );
	
	# Actually start processing spam files
	&debug( "Processing files ...\n" );
	&Process( @ARGV );

	# Do any module finish necessary
	&debug( "Spam Plus finish ...\n" );
	&SpamPlusFinish();
	
	&StdFooter;


	exit;
}
###################    End of MAIN  ############################################



################################################################################
#
sub Process( @ )
#
# This is the actual processsing that gets the files names from the command line
# and then calls AnalyzeFile to decide if the file is spam or ham
#
################################################################################
{	my @arg = @_;


	# Just read the filenames from the command line
	my $item;
	my $spam_counter = 0 + 0;
	my $file_counter = 0 + 0;
	foreach $item ( @arg )
		{	# Handle wildcards
			if ($item =~ /\*/ || $item =~ /\?/)
				{	$item = "*" if ( $item eq "*.* " );
					
					# Loop through the globbed names
					my @glob_names = glob( $item );

					foreach ( @glob_names )
						{   $file_counter++;
								
							my $file = $_;

							# Ignore my own log file
							next if ( $file =~ m/SpamPlus\.log$/i );
							
							my $is_spam += &AnalyzeFile( $file );  
							$spam_counter++ if ( $is_spam );
						}
				}  #  end of handle wild cards

			# Handle single entities
			else
				{	# Analyze a directory
					if ( -d $item )
						{	# Process the directory
							opendir( DIR, $item );

							while ( my $file = readdir(DIR) )
								{	# Skip subdirectories
									my $filename = $item . $slash . $file;
									next if ( -d $filename );
									
									# Ignore my own log file
									next if ( $file =~ m/SpamPlus\.log$/i );
							
									# Skip clue files
									next if ( $file =~ m/\.clue$/i );
									
									$file_counter++;
									
									my $is_spam += &AnalyzeFile( $filename );  
									$spam_counter++ if ( $is_spam );
								}

							closedir( DIR );
						}
					# Analyze a single file
					else
						{	$file_counter++;
							my $is_spam += &AnalyzeFile( $item );  
							$spam_counter++ if ( $is_spam );
						}
				}
		}  #  end of foreach item
	
	
	# Show the totals
	my $ham_total = $file_counter - $spam_counter;

	&lprint( "Final results - $file_counter files, $spam_counter spam, $ham_total not spam\n" );
	
	return( 1 );
}



################################################################################
#
sub AnalyzeFile( $ )
#
#  Given a file name, return 1 if it is Spam, 0 if OK, -1 if definitely Ham
#
################################################################################
{	my $file = shift;
	

	# First, load the file into @data	
	my @data;
	
    #  Load the file into memory
    @data = ();
    if ( ! open SPAM, "<$file" )
	  {   &lprint( "Error opening file $file: $!\n" );
		  
		  return( 1 );
      }
	  
	my $line_counter = 0 + 0;
	while ( my $line = <SPAM> )
		{   $line_counter++;
			
			my $len = length( $line );
			next if ( $len > 1000 );  #  Skip long lines
			
			chomp( $line );
			
			push @data, $line;
		}
		
	close( SPAM );

	print "Read $line_counter lines from $file\n";
	
	my $ret = &SpamPlusEntry( \@data, $file );
	
	return( $ret );
}



################################################################################
################################################################################
################################################################################
__END__

:endofperl
