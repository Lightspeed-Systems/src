################################################################################
#!perl -w
#
# Rob McCarthy's FileCompare source code
#  Copyright 2008 Lightspeed Systems Corp.
# do a binary compare between two or more files looking for common code segments
#
################################################################################



# Pragmas
use strict;
use warnings;


use Getopt::Long;
use Cwd;
use Content::File;



# Options
my $opt_dir;								# Directory to get stuff from - the default is the current directory
my $opt_help;
my $opt_version;
my $opt_verbose;
my $opt_debug;


my $opt_size;								# This is the size of each chunk that is searched at one time
my $opt_match;								# If set this is the minimum number of files that need to match
my $opt_length = 0 + 32;					# If set this is the minimum length of a match that we are interested in
my $opt_offset;								# If set this is the starting offset of the first file to use
my $opt_end_length;							# If set this is the end length of the first file to use
my $opt_grab;								# If set, grab a chunk of file out of file1 and put into grab.bin
my $opt_normalize;							# If set then normalize the file content
my $opt_contained;							# If set, don't calculate contained fragments
my $opt_fragments = 0 + 100;				# This is the maximum number of matching fragments per file compare
my $opt_pattern;							# If true, then when grabbing look for this pattern


my $_version = "1.00.00";
my @file_list;								# This is the list of files to analyze
my @frags;									# This is the array of fragments found
my $normalize_buf;							# A buffer containing the normalized file_list[ 0 ] contents


my %matched_count;							# key is formatted count and size, value is data
my %matched_size;							# key is size and count, value is data



################################################################################
#
MAIN:
#
################################################################################
{
    &StdHeader( "FileCompare" );

    # Get the options
    Getopt::Long::Configure("bundling");

		my $options = Getopt::Long::GetOptions
		(
			"c|contained"	=> \$opt_contained,
			"d|directory=s" => \$opt_dir,
			"e|end=i"		=> \$opt_end_length,
			"f|fragments=i"	=> \$opt_fragments,
			"g|grab"		=> \$opt_grab,
			"l|length=i"	=> \$opt_length,
			"m|match=i"		=> \$opt_match,
			"n|normalize"	=> \$opt_normalize,
			"o|offset=i"	=> \$opt_offset,
			"p|pattern=s"	=> \$opt_pattern,
			"s|size=i"		=> \$opt_size,
			"v|verbose"		=> \$opt_verbose,
			"h|help"		=> \$opt_help,
			"x|xxx"			=> \$opt_debug
		);


    &Usage() if ( $opt_help );
    &Version() if ( $opt_version );
	
	# Start doing some work ...	
	while ( my $file = shift )
		{	push @file_list, $file;
		}


	my $cwd = getcwd;
	$cwd =~ s#\/#\\#gm;
	
	
	# If no files are specified, then compare all the files in the current directory
	$file_list[ 0 ] = '*' if ( ! defined $file_list[ 0 ] );
	
	# If file1 is specified, but not file2, then compare all the files in the current directory
	$file_list[ 1 ] = '*' if ( ( defined $file_list[ 0 ] )  &&  ( ! defined $file_list[ 1 ] ) );
	
	
	# Is file1 a wildcard?
	if ( ( defined $file_list[ 0 ] )  &&  ( $file_list[ 0 ] =~ m/\*/ ) )
		{	$opt_dir = $cwd if ( ! $opt_dir );
			
			@file_list = ();
			
			if ( opendir( DIRHANDLE, $opt_dir ) )
				{	for my $file ( readdir( DIRHANDLE ) )
						{	# Is it the file current open by the service?
							next if ( ! $file );
							
							next if ( $file eq "." );
							next if ( $file eq ".." );
							
							# Ignore my own log files, etc
							next if ( $file =~ m/^filecompare/i );
							
							my $fullfile = "$opt_dir\\$file";
							
							next if ( -d $fullfile );
							
							push @file_list, $file;
						}
						
					closedir( DIRHANDLE );	
				}
		}


	# Is file2 a wildcard?
	if ( ( defined $file_list[ 1 ] )  &&  ( $file_list[ 1 ] =~ m/\*/ ) )
		{	$opt_dir = $cwd if ( ! $opt_dir );
			
			pop @file_list;
			
			if ( opendir( DIRHANDLE, $opt_dir ) )
				{	for my $file ( readdir( DIRHANDLE ) )
						{	# Is it the file current open by the service?
							next if ( ! $file );
							
							next if ( $file eq "." );
							next if ( $file eq ".." );
							
							# Ignore my own log files, etc
							next if ( $file =~ m/^filecompare/i );
							
							my $fullfile = "$opt_dir\\$file";
							
							next if ( -d $fullfile );
							
							push @file_list, $file;
						}
						
					closedir( DIRHANDLE );	
				}
		}
		
		
	# Make sure that I have at least two files ...
	&Usage() if ( ( ! $file_list[ 0 ] )  ||  ( ! $file_list[ 1 ] ) );
	&Usage() if ( ( ! -f $file_list[ 0 ] )  ||  ( ! -f $file_list[ 1 ] ) );
	&Usage() if ( ( ! -s $file_list[ 0 ] )  ||  ( ! -s $file_list[ 1 ] ) );
	
	
	# Calculate the chunk size if it isn't set
	if ( ! $opt_size )
		{	my $size = ( $opt_length - 2 ) / 2;
			$opt_size = 0 + sprintf( "%d", $size );
			$opt_size = 0 + 4 if ( $opt_size < 4 );
		}


	# Show the options
	print "Start comparing $file_list[ 0 ] at offset $opt_offset\n" if ( $opt_offset );
	print "Only compare $opt_end_length bytes of $file_list[ 0 ]\n" if ( $opt_end_length );
	print "Matches must be $opt_length bytes long or greater\n" if ( $opt_length );
	print "Use chunk size of $opt_size\n" if ( $opt_size );
	print "Only show matches that are in at least $opt_match different files\n" if ( $opt_match );
	

	
	my $not_matched = 0 + 0;	
	my $compare_count = 0 + 1;
	for ( my $i = 0 + 1;  $file_list[ $i ];  $i++ )
		{	# Skip repeated files
			next if ( lc( $file_list[ 0 ] ) eq lc( $file_list[ $i ] ) );
			next if ( ! -s $file_list[ $i ] );
			
			# Ignore my own log files, etc
			next if ( $file_list[ $i ] =~ m/^filecompare/i );
	
			print "Compare #$compare_count:  $file_list[ 0 ] to $file_list[ $i ] ...\n";

			my @fragments = &FileCompare( $file_list[ 0 ], $file_list[ $i ], $opt_offset, $opt_end_length );
			
			$not_matched++ if ( $#fragments < 0 );
			
			# Add the fragments from this file to the globlal list
			push @frags, @fragments;
			
			my $total_frags = $#frags + 1;
			print "$total_frags total fragments so far\n" if ( $opt_verbose );
			
			$compare_count++;
		}


	# Calculate any fragments contained inside other matches
	if ( ! $opt_contained )
		{	my @fragments = &ContainedFragment();
			push @frags, @fragments;
		}
		
	
	# Add up how many files match the different fragments
	my $total = &CalculateFragments();
			
	
	print "Found $total matches that are at least $opt_length bytes long\n" if ( $total );
	print "Found no matches that are $opt_length long or longer that matched in $opt_match different files\n" if ( ( ! $total )  &&  ( $opt_match ) );
	print "Found no matches that are $opt_length long or longer that matched\n" if ( ( ! $total )  &&  ( ! $opt_match ) );
	
	
	# Figure out the places the files match	
	print "\n\nMatching Sections of file $file_list[ 0 ]:\n" if ( $total );
	
	
	# Do I need to grab the matches?
	my $grab_file = "FileCompare.txt";
	unlink( $grab_file ) if ( $opt_grab );
	
	
	my @keys = sort keys %matched_count;
	foreach ( @keys )
		{	my $matched_count_key = $_;
			next if ( ! defined $matched_count_key );
			
			my $data = $matched_count{ $matched_count_key };
			next if ( ! defined $data );
			
			my ( $count, $start1, $end1, $match_length ) = split /\t/, $data, 5;
			my $hex_offset = sprintf( "0x%06x", $start1 );
			
			my $file_count = $count + 1;
			print "\n$file_count files matched at offset $start1 - $hex_offset for $match_length bytes\n";
		
			if ( $opt_verbose )
				{	my $match_str = &ReadString( $file_list[ 0 ], $start1, $match_length );
					&DisplayBuffer( $match_str );
				}
				
			if ( $opt_grab )
				{	&FileGrab( $file_list[ 0 ], $start1, $match_length, $grab_file, $file_count );
				}
		}


	# If grabbing from a pattern, get that now ...
	if ( ( $opt_grab )  &&  ( defined $opt_pattern ) )	
		{	print "Looking for pattern: $opt_pattern in file $file_list[ 0 ] ...\n";

			open( FILE1, "<$file_list[ 0 ]" ) or die "Unable to open $file_list[ 0 ]: $!\n";
			binmode( FILE1 );
	
	
			# Read all the bytes in the file
			my $buf;
			my $file_size = -s $file_list[ 0 ];
			my $nbytes_file1 = &ReadFile1( \$buf, $file_size );
			
			if ( ! $file_size )
				{	die "Error reading $file_size bytes from $file_list[ 0 ]\n";
				}
			
			
			my $match_str = &ReadString( $file_list[ 0 ], 0 + 0, $file_size );
			
			&File1Close();

			my $start1 = index( $match_str, $opt_pattern );
			print "Did not find pattern: $opt_pattern in file $file_list[ 0 ]\n" if ( $start1 < 0 );

			# Loop around until I find all the matches
			while ( $start1 >= 0 )
				{	&FileGrab( $file_list[ 0 ], $start1, 0 + 256, $grab_file, 0 + 0 );
					my $offset = $start1 + length( $opt_pattern );
					
					$start1 = index( $match_str, $opt_pattern, $offset );
				}	
		}

		
	my $total_files = $#file_list + 1;
	
	print "\n$total_files total files compared\n";
	
	&StdFooter;

exit;
}
################################################################################



################################################################################
#
sub FileGrab( $$$$$ )
#
#  Grab a match from input and write the data formatted to output
#
################################################################################
{	my $input_file		= shift;	# This is the file to read the data from
	my $start_offset	= shift;	# This is the starting offset to read
	my $match_length	= shift;	# This is the length of data to read
	my $output_file		= shift;	# The is the file to write the formatted output to
	my $file_count		= shift;	# The number of files that match
	
	print "Grabbing from $input_file at offset $start_offset ...\n";
				
	open( FILE1, "<$input_file" ) or die "Unable to open $input_file: $!\n";
	binmode( FILE1 );
	
	
	# Read the bytes up to the offset
	my $buf;
	my $nbytes_file1 = &ReadFile1( \$buf, $start_offset );
	
	if ( $nbytes_file1 != $start_offset )
		{	die "Error reading $start_offset bytes from $input_file\n";
		}
	
	
	my $match_str = &ReadString( $input_file, $start_offset, $match_length );
	
	&File1Close();
	
	open( GRAB, ">>$output_file" ) or die "Error opening $output_file: $!\n";
	
	$buf = &HexBuffer( $match_str );
	
	print "Writing $match_length formatted hex bytes to grab file $output_file ...\n";
	
	print GRAB "Matches: $file_count  File $input_file  Start Offset: $start_offset  Length: $match_length\n";
	print GRAB "$buf\n";
	
	close( GRAB );

	return( 1 );
}



################################################################################
#
sub FileCompare( $$ $$ )
#
#  Compare 2 files - getting the similar chunks of files together
#
################################################################################
{	my $file1			= shift;
	my $file2			= shift;
	
	my $start_offset	= shift;
	my $end_length		= shift;
	
	
	my $file_count = 0 + 0;	
	
	
	open( FILE1, "<$file1" ) or die "Error opening file $file1: $!\n";
	binmode( FILE1 );
	if ( defined $start_offset )
		{	sysseek( FILE1, $start_offset, 0 );
			print "Starting the compare at offset $start_offset in $file1 ...\n";
		}
	
	open( FILE2, "<$file2" ) or die "Error opening file $file2: $!\n";
	binmode( FILE2 );
	
	my $previous_chunk;
	my $chunk;
	my $chunk_size = 0 + $opt_size;
	
	
	# Figure out the starting offset of the first file
	my $file1_offset = 0 + 0;
	$file1_offset = $start_offset if ( $start_offset );
	
	
	# Figure out the ending position of the first file
	$end_length += $start_offset if ( ( $start_offset )  &&  ( $end_length ) );
	
	
	my $big_buff;
	my $big_buff_size = 4 * 1024 * 1024;
	my $file2_size = -s $file2;
	$big_buff_size = $file2_size if ( $file2_size < $big_buff_size );
	
	
	# Read a big chunk from file2
	my $nbytes_file2 = sysread( FILE2, $big_buff, $big_buff_size, 0 );
	
	
	# Do I need to normalize the data from FILE2
	if ( ( $opt_normalize )  &&  ( $nbytes_file2 ) )
		{	$big_buff = &Normalize( $big_buff );
			$nbytes_file2 = length( $big_buff );
		}
	
	
	# Keep track of the fragments I have found in this comparison
	my @fragments;
	
	
	# If I didn't read anything from file2 I can quit here
	return( @fragments ) if ( ! $nbytes_file2 );
	
	
	my $counter = 0 + 0;
	while ( my $nbytes_file1 = &ReadFile1( \$chunk, $chunk_size ) )
		{	$counter++;
			
			print "Read $counter chunks of $file1 ...\n" if ( $opt_debug );
			
			# Don't try to match a small chunk at the end of a file
			last if ( $nbytes_file1 < $opt_size );
			
			# Don't try to match a bunch of hex 00's
			next if ( ! ( $chunk =~ m/[^\x00]/ ) );
			
			
			my $offset = 0 + 0;
			my $file2_offset = index( $big_buff, $chunk );
			
			while ( $file2_offset > -1 )
				{	print "Chunk match found at pos $file1_offset in $file1, pos $file2_offset in $file2\n" if ( $opt_verbose );
				
					
					my $start1 = $file1_offset;
					my $start2 = $file2_offset;
					
					my $match_start = "";
					
					# Does part of the previous chunk match at the right place?
					if ( defined $previous_chunk )
						{	my $start_offset = $file2_offset - $chunk_size;
							my $start_size = $chunk_size;
							
							if ( $start_offset < 0 )
								{	$start_size = $chunk_size + $start_offset;
									$start_offset = 0 + 0;
								}
								
							my $bigbuff_substr = substr( $big_buff, $start_offset, $start_size );

							my @chars_bigbuff = split //, $bigbuff_substr;
							my @chars_previous = split //, $previous_chunk;

							my $previous_length = 0 + 0;
							
							my $big_buff_pos = $start_size - 1;
							my $chunk_pos = $chunk_size - 1;


							# Work my way backwards, matching characters on at a time
							while ( ( $big_buff_pos > 0 )  &&  ( $chunk_pos > 0 )  &&
								   ( $chars_bigbuff[ $big_buff_pos ] eq $chars_previous[ $chunk_pos ] ) )
								{	$previous_length++;
									$big_buff_pos--;
									$chunk_pos--;
								}
								

							# Recalculate the start match
							$start1 = $file1_offset - $previous_length;
							$start2 = $file2_offset - $previous_length;
							

							# Figure out the string the matches in the previous chunk
							if ( ! $previous_length )
								{	$match_start = undef;
								}
							else
								{	$match_start = substr( $previous_chunk, $chunk_size - $previous_length, $previous_length );
								}	
						}


					# Calculate my current position in file1
					my $end1 = $counter * $chunk_size;
					
					# Read in up to 100k from file1 - this will be normalized if necessary
					my $file1_buffer = &ReadString( $file1, $end1, 100 * 1024 );
					my $file1_bytes = length( $file1_buffer );
					
					# Calculate my current position in file2
					my $end2 = $file2_offset + $chunk_size;
					
					my $match_end_length = 0 + 0;
					while ( ( $match_end_length < $file1_bytes )  &&  ( $end2 < $big_buff_size )  &&
						   ( substr( $file1_buffer, $match_end_length, 1 ) eq substr( $big_buff, $end2, 1 ) ) )
						{	$end1++;
							$end2++;
							$match_end_length++;
						}
						
					
					my $match_end = substr( $file1_buffer, 0, $match_end_length ) if ( $match_end_length );
					
					
					# Build up the total string that is matched
					my $match_str = $match_start . $chunk if ( defined $match_start );
					$match_str = $chunk if ( ! defined $match_start );
					$match_str .= $match_end if ( defined $match_end );
		
		
					# Figure out the total length of the matching string
					my $match_length = length( $match_str );
					

					# Is this length of match enough?
					# If so then keep track of it
					if ( ( ! $opt_length )  ||  ( $match_length >= $opt_length ) )
						{	my $overlapped;
							
							# Is this match the same as a previous match?
							for ( my $i = 0 + 0;  $i < $file_count;  $i++ )
								{	# Does this match start and end at the same place?
									$overlapped = 1 if ( ( $start1 == $fragments[ $i ][ 0 ] )  &&
														( $start1 + $match_length ) == $fragments[ $i ][ 1 ] );
									last if ( $overlapped );
								}
							
							
							# Check to make sure that this match is not overlapped by a previous match in file1
							if ( ! $overlapped )
								{	for ( my $i = 0 + 0;  $i < $file_count;  $i++ )
										{	# Is the start of this match before the current match in file1?
											next if ( $fragments[ $i ][ 0 ] > $start1 );
											
											# Does this match end at the same place?
											$overlapped = 1 if ( ( $start1 + $match_length ) == $fragments[ $i ][ 1 ] );
											last if ( $overlapped );
										}
								}
								
								
							# Check to make sure this match doesn't contain a previous match
							if ( ! $overlapped )
								{	for ( my $i = 0 + 0;  $i < $file_count;  $i++ )
										{	# Is this match longer than the previous match?
											next if ( $fragments[ $i ][ 2 ] > $match_length );
											
											my $match_end_pos = $start1 + $match_length;

											# Does this match end at the same place?
											# If so, then replace the fragments array with this information
											if ( ( $start1 + $match_length ) == $fragments[ $i ][ 1 ] )
												{	$overlapped = 1;
													
													$fragments[ $i ][ 0 ] = $start1;
													$fragments[ $i ][ 1 ] = $start1 + $match_length;
													$fragments[ $i ][ 2 ] = $match_length;
													$fragments[ $i ][ 3 ] = $start2;
													$fragments[ $i ][ 4 ] = $file2;
													
													last;
												}												
										}
								}
								
							
							# If this match isn't overlapped by a previous match then keep track of it	
							if ( ! $overlapped )	
								{	print "Matched $match_length bytes at pos $start1\n" if ( $opt_verbose );
									
									# Keep track of how many matches I have for this file that meet the minimum length
									$fragments[ $file_count ][ 0 ] = $start1;
									$fragments[ $file_count ][ 1 ] = $start1 + $match_length;
									$fragments[ $file_count ][ 2 ] = $match_length;
									$fragments[ $file_count ][ 3 ] = $start2;
									$fragments[ $file_count ][ 4 ] = $file2;
									
									$file_count++;
								}

						}

					# Is there another match for this chunk later on in the big_buff?
					$offset = $file2_offset + $chunk_size;
					
					# Start look for another match past where I currently matched ...
					$file2_offset = index( $big_buff, $chunk, $offset );
				}
				
			$file1_offset += $nbytes_file1;
			$previous_chunk = $chunk;
			
			# Have I reached the end of what I was supposed to check in file1?
			if ( ( $end_length )  &&  ( $file1_offset >= $end_length ) )
				{	print "Reached the end section at byte $end_length of $file1\n";
					last;
				}
		}
		
	
	&File1Close();
	
	close( FILE2 );

	
	print "Compressing matches between $file1 and $file2 ...\n" if ( $opt_verbose );
	
	my @comp_frags;
	my $comp_count = 0 + 0;
	my $ignored_fragments = 0 + 0;
	
	for ( my $k = 0 + 0;  $k < $file_count;  $k++ )
		{	my $start1			= $fragments[ $k ][ 0 ];
			my $end1			= $fragments[ $k ][ 1 ];
			my $match_length	= $fragments[ $k ][ 2 ];
			my $start2			= $fragments[ $k ][ 3 ];
			my $file2			= $fragments[ $k ][ 4 ];
			
			# is this fragment disabled?
			next if ( $end1 == 0 );	
			
			# Is this match too short?
			next if ( $match_length < $opt_length );

			# Now figure out if I need to compress some contained fragments
			my $overlapped;
			
			
			# Is this match the same as a previous match?
			for ( my $i = 0 + 0;  $i < $file_count;  $i++ )
				{	next if ( $i == $k );  # Don't compare to myself
					next if ( $fragments[ $i ][ 1 ] == 0 );	# has this match been disabled?
					
					# Does this match start and end at the same place?
					# If so then disable this fragment
					$fragments[ $i ][ 1 ] = 0 + 0 if ( ( $start1 == $fragments[ $i ][ 0 ] )  &&
										( $start1 + $match_length ) == $fragments[ $i ][ 1 ] );
				}
			
							
			# Check to make sure that this match is not overlapped by another match in file1
			# i.e. do the ends match
			for ( my $i = 0 + 0;  $i < $file_count;  $i++ )
				{	next if ( $i == $k );  # Don't compare to myself
					next if ( $fragments[ $i ][ 1 ] == 0 );	# has this match been disabled?
					
					# Is the start of this match before the current match in file1?
					next if ( $fragments[ $i ][ 0 ] > $start1 );
					
					# Does this match end at the same place or before?
					$overlapped = 1 if ( $end1 <= $fragments[ $i ][ 1 ] );
					last if ( $overlapped );
				}
								
			# If it isn't overlapped, then it is a real fragment
			next if ( $overlapped );

			# Check to make sure that this match is not overlapped by another match in file1
			# i.e. do the starts match?
			for ( my $i = 0 + 0;  $i < $file_count;  $i++ )
				{	next if ( $i == $k );  # Don't compare to myself
					next if ( $fragments[ $i ][ 1 ] == 0 );	# has this match been disabled?
					
					# Is the start of this match the same as the current match in file1?
					next if ( $fragments[ $i ][ 0 ] != $start1 );
					
					# Disable the shorter match
					if ( $end1 < $fragments[ $i ][ 1 ] )
						{	$overlapped = 1;
						}
					else
						{	$fragments[ $i ][ 1 ] = 0 + 0;
						}
						
					last if ( $overlapped );
				}
								

			# If it isn't overlapped, then it is a real fragment
			next if ( $overlapped );
			
			if ( $comp_count < $opt_fragments )
				{	$comp_frags[ $comp_count ][ 0 ] = $start1;
					$comp_frags[ $comp_count ][ 1 ] = $start1 + $match_length;
					$comp_frags[ $comp_count ][ 2 ] = $match_length;
					$comp_frags[ $comp_count ][ 3 ] = $start2;
					$comp_frags[ $comp_count ][ 4 ] = $file2;
					
					$comp_count++;
				}
			else
				{	$ignored_fragments++;
				}
		}
		
		
	print "Matched at $file_count different places\n" if ( $comp_count );
	print "No matches\n" if ( ! $comp_count );

	print "Ignored $ignored_fragments matches\n" if ( $ignored_fragments );
	
	return( @comp_frags );
}



my $readfile1_buf;
################################################################################
# 
sub ReadFile1( $$ )
#
#	Read size1 bytes from FILE1 - buffer up and normalize if necessary
#
################################################################################
{	my $chunk_ref	= shift;
	my $size		= shift;
	
	if ( ! $opt_normalize )
		{	my $nbytes_file1 = sysread( FILE1, $$chunk_ref, $size, 0 );
			return( $nbytes_file1 );
		}
	
	
	# If I get to here then I need to normalize the data
	# Do I need to read another buf?
	if ( ( ! defined $readfile1_buf )  ||  
		( ! length( $readfile1_buf ) )  ||  
		( length( $readfile1_buf ) < $size ) )	
		{	# Save the old buf - if it exists
			my $old_buf = $readfile1_buf;
			
			# Read up to 1 meg at a time
			my $read_size = 1024 * 1024;
			
			# Read more if I have to
			$read_size = $size + ( 10 * 1024 ) if ( ( $size + 10 * 1024 )  >= $read_size );
			
			# Read from file1
			my $nbytes_file1 = sysread( FILE1, $readfile1_buf, $read_size, 0 );
			
			# Add the old buf back in
			$readfile1_buf = $old_buf . $readfile1_buf if ( defined $old_buf );
			
			# Normalize the file1 buf
			$readfile1_buf = &Normalize( $readfile1_buf );
			
			# Keep track of what I have read
			$normalize_buf .= $readfile1_buf;
		}
	
	
	# Do I have anything to return?
	my $len = length( $readfile1_buf );
	return( 0 + 0 ) if ( ! $len );
	
	my $ret_size = $size;
	$ret_size = $len if ( $len < $size );
	
	$$chunk_ref = substr( $readfile1_buf, 0, $ret_size );
	
	# Chop off the front chunk from file1_buf
	my $buf = substr( $readfile1_buf, $ret_size );
	$readfile1_buf = $buf;

	return( $ret_size );
}



################################################################################
# 
sub File1Close()
#
#	Close file1 and free any memory used
#
################################################################################
{
	$readfile1_buf = undef;
#	$normalize_buf = undef;
	
	my $ok = close( FILE1 );
	return( $ok );
}



################################################################################
# 
sub ReadString( $$$ )
#
#	Read size bytes from the file at the offset - normalize if necessary
#   Return the bytes read
#
################################################################################
{	my $file		= shift;	# The file name to read from
	my $offset		= shift;	# The starting offset to read
	my $size		= shift;	# The number of bytes to return
	
	
	my $file_buf;
	
	if ( ! $opt_normalize )
		{	open( READFILE, "<$file" ) or die "Error opening file $file: $!\n";
			binmode( READFILE );

			sysseek( READFILE, $offset, 0 );
			my $nbytes_file1 = sysread( READFILE, $file_buf, $size, 0 );
			
			close( READFILE );
			return( $file_buf );
		}

	# If normalizing, I have the file contents already in a buffer, so
	# I just have to get the right string out
	$file_buf = substr( $normalize_buf, $offset, $size );
	
	return( $file_buf );
}	
	


################################################################################
# 
sub Normalize( $ )
#
#	Given a buffer - normalize it
#
################################################################################
{	my $buf = shift;
	
	return( undef ) if ( ! defined $buf );
	
	# Convert 0x09 to 0x0d to spaces
	$buf =~ s/[\x09\x0a\x0b\x0c\x0d]/ /g;
	
	# Convert repeated spaces to a single space
	$buf =~ s/\s+/ /g if ( defined $buf );

	# Ignore anything outside of 0x20 to 0x7f	
	$buf =~ s/[^\x20-\x7e]//g;
	
	# Only use lowercase chars
	$buf = lc( $buf );
	
	return( $buf );
}



################################################################################
# 
sub DisplayBuffer( $ )
#
#	Given a buffer - display it
#
################################################################################
{	my $buf = shift;
	
	return( undef ) if ( ! defined $buf );
	
	my $printable = $buf;
	$printable =~ s/[^\x20-\x7e]//g;

	# Is the buffer completely displayble?
	if ( length( $buf ) == length( $printable ) )
		{	print "Buffer Contents Ascii:\n$buf\n";
			return( undef );	
		}

	my $hex = &StrToHex( $buf );
	
	# Only use up to the first 256 bytes of the hex buffer (512 in hex)
	my $len = 0 + 512;
	my $hex_len = length( $hex );
	
	$len = $hex_len if ( $hex_len < 0 + 512 );
	
	my $short_hex = substr( $hex, 0, $len );
	
	print "Buffer Contents Hex:\n$short_hex\n";
	print "Buffer Contents Ascii:\n$printable\n";
	
	my $unescape = &Unescape( $printable );
	print "Buffer Contents Unescaped:\n$unescape\n" if ( defined $unescape );
	
	return( undef );
}



################################################################################
# 
sub HexBuffer( $ )
#
#	Given a buffer - return a buffer in display format
#
################################################################################
{	my $buf = shift;
	
	return( undef ) if ( ! defined $buf );
	
	my $printable = $buf;
	$printable =~ s/[^\x20-\x7e]//g;

	my $return_buf;
	
	my $hex = &StrToHex( $buf );
	
	# Only use up to the first 256 bytes of the hex buffer (512 in hex)
	my $len = 0 + 512;
	my $hex_len = length( $hex );
	
	$len = $hex_len if ( $hex_len < 0 + 512 );
	
	my $short_hex = substr( $hex, 0, $len );
	
	$return_buf = sprintf( "%s", "Buffer Contents Hex:\n$short_hex\nBuffer Contents Ascii:\n$printable\n" );
	
	my $unescape = &Unescape( $printable );
	$return_buf .= "Buffer Contents Unescaped:\n$unescape\n" if ( defined $unescape );
	
	return( $return_buf );
}



################################################################################
# 
sub Unescape( $ )
#
#	Given a buffer - return an unescaped buffer if there are unescapes inside
#
################################################################################
{	my $printable = shift;
	
	return( undef ) if ( ! defined $printable );
	return( undef ) if ( ! ( $printable =~ m/unescape\(.+\)/i ) );
	
	$printable = lc( $printable );
	
	my $start = index( $printable, "unescape(" );
	
	my $unescaped_buffer = "";
	
	while ( $start >= 0 )
		{	my $str = substr( $printable, $start, length( $printable ) );

			$str =~ m/unescape\((.+?)\)/i;
			
			my $escape_sequence = $1;

			last if ( ! defined $escape_sequence );

			if ( ( defined $escape_sequence )  &&  ( $escape_sequence =~ m/\%/ ) )
				{	# Convert % encoded other stuff to the real characters - if possible
					$escape_sequence =~ m/(.*?)(\%)(.*)/;
					my $rebuilt_sequence = $1;
					my $remainder = $3;
					
					while ( $remainder )
						{	my $hex = substr( $remainder, 0, 2 );
							my $dec;
							
							# Make sure the hex string actually contains hex characters before packing it
							$dec = pack( "H2", $hex ) if ( ( $hex )  &&  ( $hex =~ m/[0-9a-f][0-9a-f]/i ) );

							# Odd characters still stay encoded
							if ( ( $dec )  &&  ( $dec ge "\x20" )  &&  ( $dec lt "\x80" ) )
								{	$rebuilt_sequence .= $dec;
								}
							else	
								{	$rebuilt_sequence .= "%$hex" if ( $hex );
								}
							
							
							# Trim off the hex string
							my $len = length( $remainder );
							$remainder = undef if ( $len <= ( 0 + 2 ) ); 
							$remainder = substr( $remainder, 2 ) if ( $len > ( 0 + 2 ) );
								
								
							# Get set up for the next encoded char
							if ( $remainder )
								{	if ( $remainder =~ m/(.*?)(%)(.*)/i )
										{	$rebuilt_sequence .= $1 if ( $1 );
											$remainder = $3;
										}
									else
										{	$rebuilt_sequence .= $remainder;
											$remainder = undef;
										}
								}
						}
						
					$unescaped_buffer .= "UNESCAPED( $rebuilt_sequence ) ";
				}
			
			my $offset = $start + length( "unescape(" ) + length( $escape_sequence );	
			
			$start = index( $printable, "unescape(", $offset );
		}

	return( $unescaped_buffer );	
}



################################################################################
# 
sub ContainedFragment()
#
#	Create new match fragments that are contained inside the current matches
#
################################################################################
{	print "\nChecking for overlapping matches ...\n";
	
	my $total_count = $#frags + 1;
	
	print "Currently have $total_count fragments ...\n";
	
	die "Too many matching fragments to handle at one time\n" if ( $total_count > 20000 );
	
	my @fragments;
	my $fragments_count = 0 + 0;
	my %file_count;


	# First - keep track of the fragments I already have	
	for ( my $k = 0 + 0;  $k < $total_count;  $k++ )
		{	my $start1			= $frags[ $k ][ 0 ];
			my $match_length	= $frags[ $k ][ 2 ];
			my $file2			= $frags[ $k ][ 4 ];
			
			my $formatted_start		= sprintf( "%08d", $start1 );
			my $formatted_length	= sprintf( "%08d", $match_length );
			
			my $file_count_key = "$file2\t$formatted_start\t$formatted_length";
			
			$file_count{ $file_count_key } = 0 + 1;
		}
		
	
	# Now figure out if I need to create some contained fragments
	for ( my $k = 0 + 0;  $k < $total_count;  $k++ )
		{	my $start1			= $frags[ $k ][ 0 ];
			my $end1			= $frags[ $k ][ 1 ];
			my $match_length	= $frags[ $k ][ 2 ];
			my $file2			= $frags[ $k ][ 4 ];
			
			# Now see if there are matches in other files that overlap this particular match
			# and so should added to the total count
			for ( my $i = 0 + 0;  $i < $total_count;  $i++ )
				{	# Am I comparing myself?
					next if ( $i == $k );
					
					# Is this from a different file?
					# If this is checking against the same file then skip it
					my $this_file = $frags[ $i ][ 4 ];
					next if ( $this_file eq $file2 );

					# Now figure out if the matched sections overlap by at least the minimum 
					# match length of $opt_length
					
					# Get the start and end of this compared match
					my $start2	= $frags[ $i ][ 0 ];
					my $end2	= $frags[ $i ][ 1 ];
					
					# First - is the end of this match before the start of the compared match?
					next if ( $end1 < $start2 );
					
					# Is the start of this match after the end of the compared match?
					next if ( $start1 > $end2 );
					
					# Are they already the same as the compared match?
					next if ( ( $start1 == $start2 )  &&  ( $end1 == $end2 ) );
					
					
					# At this point I know that these matches could overlap enough,
					# so handle the three scenarios:
					# BUT - only create new fragments when start1 < start2 so that we don't
					# double count fragments
					# And make sure that I don't already have this fragment
					
					# Scenario 1 - start1 and end1 completely overlap the compared match before and after
					if ( ( $start1 < $start2 )  &&  ( $end1 >= $end2 ) )
						{	# Do I already have this fragment?
							my $overlap_length = $end2 - $start2;
							
							my $formatted_start		= sprintf( "%08d", $start2 );
							my $formatted_length	= sprintf( "%08d", $overlap_length );
							
							my $file_count_key = "$this_file\t$formatted_start\t$formatted_length";
							
							# If this entry exists then I already have this frament
							next if ( exists $file_count{ $file_count_key } );
							
							# Create a new fragment with the match of the compared fragment
							# I know the overlap length is enough because it is the same as the compared match
							$fragments[ $fragments_count ][ 0 ] = $start2;
							$fragments[ $fragments_count ][ 1 ] = $end2;
							$fragments[ $fragments_count ][ 2 ] = $overlap_length;
							$fragments[ $fragments_count ][ 3 ] = $frags[ $i ][ 3 ];
							$fragments[ $fragments_count ][ 4 ] = $frags[ $i ][ 4 ];
							
							# Keep track that I created this fragment
							$file_count{ $file_count_key } = 0 + 1;
							
							$fragments_count++;
						}
						
					# Scenario 2 - start1 and end1 overlap the first part of the compared match
					elsif ( ( $start1 < $start2 )  &&  ( $end1 > $start2 ) )
						{	my $overlap_length = $end1 - $start2;
							
							# Is the overlap length long enough?
							# If not, give up here
							next if ( $overlap_length < $opt_length );
							
							# Do I already have this fragment?
							my $formatted_start		= sprintf( "%08d", $start2 );
							my $formatted_length	= sprintf( "%08d", $overlap_length );
							
							my $file_count_key = "$this_file\t$formatted_start\t$formatted_length";
							
							# If this entry exists then I already have this frament
							next if ( exists $file_count{ $file_count_key } );
									 
							# Create a new fragment with the overlap length
							$fragments[ $fragments_count ][ 0 ] = $start2;
							$fragments[ $fragments_count ][ 1 ] = $end1;
							$fragments[ $fragments_count ][ 2 ] = $overlap_length;
							
							# Recalculate the $new_match_str start in file2
							$fragments[ $fragments_count ][ 3 ] = $frags[ $k ][ 3 ] + ( $start2 - $start1 );
							$fragments[ $fragments_count ][ 4 ] = $frags[ $i ][ 4 ];
							
							# Keep track that I created this fragment
							$file_count{ $file_count_key } = 0 + 1;
							
							$fragments_count++;
						}
						
					# Scenario 3 - start1 and end1 overlap the end of the compared match
					elsif ( ( $start1 < $end2 )  &&  ( $end1 >= $end2 ) )
						{	# Don't create a new fragment for this since start1 is greater than start2
						}
					
					next;
				}
		}
		
	print "Created $fragments_count new fragments ...\n";
	
	return( @fragments );
}



################################################################################
# 
sub CalculateFragments()
#
#	Count up how many fragments match in all of the files
#
################################################################################
{	print "\nCalculating how many matches are in each file ...\n";
	
	my %count;
	my %file_count;
	
	for ( my $i = 0 + 0;  $frags[ $i ][ 1 ];  $i++ )
		{	my $start1			= $frags[ $i ][ 0 ];
			my $match_length	= $frags[ $i ][ 2 ];
			my $file2			= $frags[ $i ][ 4 ];
			
			my $formatted_start		= sprintf( "%08d", $start1 );
			my $formatted_length	= sprintf( "%08d", $match_length );
			
			my $count_key = "$formatted_length\t$formatted_start";
			my $file_count_key = "$file2\t$formatted_start\t$formatted_length";
			
			# Don't count the same match twice for the same file
			next if ( defined $file_count{ $file_count_key } );
			
			# If I have only counted this match once for this file then keep track of it
			if ( defined $count{ $count_key } )
				{	$count{ $count_key }++;
				}
			else
				{	$count{ $count_key } = 0 + 1;
				}
				
			# Don't double count the same file for the same match	
			$file_count{ $file_count_key } = 0 + 1;	
		}
		
		
	# Now that I've got the counts, build up the %matched_count and %matched_size
	my $total = 0 + 0;
	
	for ( my $i = 0 + 0;  $frags[ $i ][ 1 ];  $i++ )
		{	my $start1			= $frags[ $i ][ 0 ];
			my $match_length	= $frags[ $i ][ 2 ];
			
			my $formatted_start		= sprintf( "%08d", $start1 );
			my $formatted_length	= sprintf( "%08d", $match_length );
			
			my $count_key = "$formatted_length\t$formatted_start";
			
			my $count = $count{ $count_key };
			next if ( ! $count );
			
			# Is there a minimum number of matches before I care?
			next if ( ( $opt_match )  &&  ( $count < $opt_match ) );
			
			my $formatted_count	= sprintf( "%08d", $count );
			
			my $matched_count_key = "$formatted_count\t$formatted_length\t$formatted_start";
			
			# have I already figured this out?
			next if ( defined $matched_count{ $matched_count_key } );
			
			my $data = "$count\t$frags[ $i ][ 0 ]\t$frags[ $i ][ 1 ]\t$frags[ $i ][ 2 ]";
			
			$matched_count{ $matched_count_key } = $data;
			
			my $matched_size_key = "$formatted_length\t$formatted_count\t$formatted_start";
			
			$matched_size{ $matched_size_key } = $data;
			
			$total++;
		}
		
	return( $total );	
}



################################################################################
# 
sub StrToHex( $ )
#
#	Given a normal representation of a string, return the hex value
#
################################################################################
{	my $str = shift;
	
	return( undef ) if ( ! defined $str );
	
	my $hex = unpack( "H*", $str );
	
	return( $hex );
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
   
	print( "Error logging set to $filename\n" ); 
}



################################################################################
# 
sub Usage
#
################################################################################
{
    my $me = "FileCompare File1 File2";

    print <<".";
Usage: FileCompare [OPTION(s)]
Does a binary compare of two or more files.  If no files are specified, or if
the files are '*', will compare all the files in the directory.

options
  -c, --contained           to NOT calculate contained fragments
  -d, --directory PATH	    files directory, default is current directory
  -e, --end ENDOFFSET       only compare File1 to ENDOFFSET - default is all
  -f, --fragments FRAGS     ignore matching fragments after FRAGS count
  -g, --grab OFFSET         grab bytes starting at OFFSET from the first file
  -l, --length LENGTH       the minimum length of a match - default is 32
  -m, --match COUNT         the minimum COUNT of files that match
  -n, --normalize           Normalize the files - used for Javascript, not HTML
  -p, --pattern PATTERN     Grab 256 byte chunks that match PATTERN
  -o, --offset STARTOFFSET  only compare File1 starting at STARTOFFSET
  -s, --size SIZE           the size of each chunk to compare
                            default is ( 1/2 LENGTH ) - 1 
							
  -v, --verbose             display verbose information  
  -h, --help                display this help and exit
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
    my $me = "FileCompare";

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
