################################################################################
#!perl -w
#
# Rob McCarthy's DMOZimport - import DMOZ XML file into squid guard format
# 
# Copyright 2003 Lightspeed Systems Corp.
#
################################################################################



# Pragmas
use strict;
use warnings;


use Content::File;
use Content::Categorize;



my $opt_debug;
my $opt_input_file		= "content.rdf.u8";
my $opt_topic_map		= "dmoztopics.map";
my $opt_topics_file		= "topics.txt";
my $opt_topics_errors	= "topics.error";
my $opt_namefile		= "namecategorize.txt";
my $opt_dir;                                         # Directory to put stuff to
my $log_file;



my %topicMap;         #  hash of the topics, with the value corresponding open db category
my %topicCategory;    #  hash of all of the dmoz topics, and the value the corresponding open db category



################################################################################
#
MAIN:
#
################################################################################
{
    print "DMOZImport\n";
	
	my $cmd_line = shift;

    $opt_input_file = $cmd_line if ( $cmd_line );

#	&TrapErrors();
	
    open( TOPIC_MAP, "<$opt_topic_map" ) or die "Cannot open input file $opt_topic_map: $!\n";

	open( $log_file, ">dmozimport.log" ) or die "Error opening log file: $!\n";
		 
		 
    while (<TOPIC_MAP>)
       {
           chomp;
           next if (!length);  #  Ignore empty lines
           next if /^#/;  #  Skip comments
           next if /^\s*(#|$)/;

           my $line = lc( $_ );

           my ($topic, $category ) = split /\s+/, $line, 2;

			# Clean off spaces and tabs
			$topic =~ s/\s+//gm;
			$category =~ s/\s+//gm;

			$topicMap{ $topic } = $category;
		}

    close TOPIC_MAP;


     #  Clean up the topic map table
     open( TOPIC_MAP, ">$opt_topic_map" ) or die "Cannot open output file $opt_topic_map: $!\n";
	 
     my @topic_map = sort keys %topicMap;
     foreach ( @topic_map )
        {   my $topic = $_;
            next if ( ! defined $_ );
            print TOPIC_MAP "$topic\t$topicMap{ $topic }\n";
        }

     close TOPIC_MAP;

    &tprint( "Reading in file $opt_input_file\n" );

    open( INFILE, "<$opt_input_file" ) or die "Cannot open input file $opt_input_file: $!\n";

    open( NAMEFILE, ">$opt_namefile" ) or die "Cannot open name file $opt_namefile: $!\n";

    open( CATERROR, ">$opt_topics_errors" ) or die "Cannot open input file $opt_topics_errors: $!\n";


    # Open the right file to write the suspicious hit urls to
    my $dir = "suspicious";
    $dir = $opt_dir . "\\suspicious" if ( $opt_dir );
    my  $filename = "$dir\\domains.hit";

    #  Can I open an existing file?
    my $err;
    open( OUTSUSPICIOUS, ">>$filename" ) or $err = 1;
    if ( $err )
      {   my $cmd = "mkdir \"$dir\"";
          system( $cmd );

          open( OUTSUSPICIOUS, ">>$filename" ) or die "Cannot create output file: $filename,\n$!\n";
     }


    my $url;
    my $counter = 0;
    my $category_counter = 0;
    my $category = "errors";
    my $last_category = " ";
    my $outdomains;
    my $output;			# The current output domain file handle


    while (<INFILE>)
       {
           my $line = lc( $_ );
          chomp( $line );

           next if ( ! length( $line ) );  #  Ignore empty lines
           next if /^#/;  #  Skip comments
           next if /^\s*(#|$)/;


 
		next if ( ! $line );

		$line =~ s/^\s+//;
		$line =~ s/\s+$//;

		next if ( ! $line );

		print "Line: $line\n" if ( $opt_debug );

           my @parts = split /\s+/, $line;

           if ( $parts[ 0 ] =~ m/^\<topic\>/i )
              {    my $original_topic = $line;

					# Trim off the trailing <topic> stuff				
					$original_topic =~ s/^\<topic\>//;
					$original_topic =~ s/\<\/topic\>$//;
					
                   $outdomains = undef;  # Flag it that I don't have a outdomain file currently selected
				   
                   next if ( ! defined $original_topic );

					&tprint( "Original topic: $original_topic\n" ) if ( $opt_debug );

                   #  See if I have a mapping for this topic
                   my $topic = $original_topic;
                   my $done;
                   while ( !$done )
                      {  if ( $topicMap{ $topic } )
						    { $done = 1;
							}
                         else
                            {  $topic = &TrimTopic( $topic );
                            }

                         $done = 1 if ( $topic eq "top" ); 
                      }


					&tprint( "Mapped topic = $topic\n" ) if ( $opt_debug );

                   # Get the right category name
                   if ( defined $topicMap{ $topic } )  
				     {  $category = $topicMap{ $topic };
						 
						 &tprint( "Topic: $topic, mapped category: $category\n" ) if ( $opt_debug );
				     }
                   else
                     {   &tprint( "No mapped category\n" ) if ( $opt_debug );
						 
						 print CATERROR "$original_topic\n";  
                         $category = undef;
                     }


                   # Is it a special mapped category?
                   # These are subcategories that are all through the DMOZ directory that map directly to Content Filter directories
                   if ( ( $category ) &&  ( ! &Blocked( $category ) ) )
                     {  my $start_category = $category;
						 
#                        $category = "directory" if ( index( $original_topic, "directories" ) != -1 );
#                        $category = "directory" if ( index( $original_topic, "directory" ) != -1 );
                        $category = "forums" if ( index( $original_topic, "chats_and_forums" ) != -1 );
                        $category = "forums.personals" if ( index( $original_topic, "personal_pages" ) != -1 );
                        $category = "forums.personals" if ( index( $original_topic, "personal_homepages" ) != -1 );
                        $category = "forums.newsgroups" if ( index( $original_topic, "newsgroups" ) != -1 );
                        $category = "news" if ( index( $original_topic, "news_and_media" ) != -1 );
                        $category = "jobs" if ( index( $original_topic, "employment" ) != -1 );
                        $category = "travel" if ( index( $original_topic, "travel_and_tourism" ) != -1 );
                        $category = "science" if ( index( $original_topic, "science_and_enviroment" ) != -1 );
                        $category = "lifestyles" if ( index( $original_topic, "gay,_lesbian,_and_bisexual" ) != -1 );
                        $category = "business" if ( index( $original_topic, "business_and_economy" ) != -1 );
						
                        $category = "sports.youth" if ( ( index( $original_topic, "top\/sports" ) != -1 )  &&
														( index( $original_topic, "youth" ) != -1 ) );

                        $category = "sports.youth" if ( ( index( $original_topic, "top\/sports" ) != -1 )  &&
														( index( $original_topic, "kids_and_teens" ) != -1 ) );
						
						&tprint( "Special mapped category = $category\n" ) if ( ( $opt_debug )  &&  ( $category ne $start_category ) );
                     }


					
					if ( $original_topic =~ m/top\/world/ )
						{	my $espanol = "\x65\x73\x70\x61\xc3\xb1\x6f\x6c";
							my $francais = "\x66\x72\x61\x6e\xc3\xa7\x61\x69\x73";

							if ( $original_topic =~ m/$espanol/ )
								{	&tprint( "Spanishtopic\n" ) if ( $opt_debug );
									$category = "world.es";
								}
								
							if ( $original_topic =~ m/$francais/ )
								{	&tprint( "Frenchtopic\n" ) if ( $opt_debug );
									$category= "world.fr";
								}
						}
						


                   if ( $category )
                     {   my $short_topic = &ShortTopic( $original_topic );

                         #  if we haven't seen this short category before, record it
                         if ( !$topicCategory{ $short_topic } )
                           {  $topicCategory{ $short_topic } = $category if ( $category ne "skip" );
                           }
                     }


                   $category_counter++;

                   if ( ( !$category )  ||  ( $category eq "skip" ) )
					{	&tprint( "Skipping\n" ) if ( $opt_debug );
						next;
					}


					$output = &OpenFile( $category );

                   $outdomains = 1;
              }

           elsif ( $parts[ 0 ] =~ m/\<externalpage/i )
              {    my ( $junk1, $str, $junk2 ) = split /\"/, $line, 3;

                   next if ( !$category );
                   next if ( $category eq "skip" );
                   next if ( !$outdomains );
                   next if ( $str =~ m/^mailto:/ );   #  Skip mailto: urls

                   $url = &CleanUrl( $str );
                   next if ( !$url );
					
                   $counter++;

                   my $catname = &CategorizeByUrlName( $url );
					$catname = "general" if ( ! $catname );
					
                    
					print "Found Category $category: URL $url\n" if ( $opt_debug );
					
                   if ( &Blocked( $category ) )
				     {  print $output "$url\n";
					 }
                   elsif ( &SuspiciousUrl( $url ) )  
				     {   &tprint( "Suspicious $url\n" ) if ( $opt_debug );
						 
						 print OUTSUSPICIOUS "$url\n";  
					 }
                   elsif ( ( $catname ne "general" )  &&  ( $catname ne $category ) ) 
				     {   $category = $catname;
						 &tprint( "Name categorize to $catname\n" ) if ( $opt_debug );
						 &NameCategorize( $category, $url );  
				     }
                   else  
				     {  print $output "$url\n";
					 }
					 
					&tprint( "Page: $category - $url\n" ) if ( $opt_debug );					
              }

           elsif ( $parts[ 0 ] =~ m/\<link\>/i )
              {    my ( $junk1, $str, $junk2 ) = split /\"/, $line, 3;

                   next if ( !$category );
                   next if ( $category eq "skip" );
                   next if ( !$outdomains );
                   next if ( $str =~ m/^mailto:/ );   #  Skip mailto: urls

                   $url = &CleanUrl( $str );
                   next if ( !$url );
                   $counter += 1;

                   my $catname = &CategorizeByUrlName( $url );

                   if ( &Blocked( $category ) )  
				     {  print $output "$url\n";  
					 }
                   elsif ( &SuspiciousUrl( $url ) )  
				     {  &tprint( "Suspicious $url\n" ) if ( $opt_debug );
						 
						 print OUTSUSPICIOUS "$url\n";  
					 }
                   elsif ( ( $catname ne "general" )  &&  ( $catname ne $category ) )
				     {   $category = $catname;
						 &tprint( "Name categorize to $catname\n" ) if ( $opt_debug );
						 &NameCategorize( $catname, $url );  
					 }
                   else  
				     {  print $output "$url\n";  
					 }
					 
				    &tprint( "Link: $category - $url\n" ) if ( $opt_debug );	 
              }

       }  #  end of INFILE

  
     close INFILE;
     close CATERROR;
     close OUTSUSPICIOUS;
     close NAMEFILE;
     $outdomains = undef;


     # Close the the domains.hit files
	 close $output if ( $output );
	$output = undef;
	

     &tprint( "Read in a total of $counter URLs in $category_counter categories from file $opt_input_file\n" );


     open( TOPICS, ">$opt_topics_file" ) or die "Cannot open output file $opt_topics_file: $!\n";


     #  Put the topic category list into category order
     my @topic_list = sort sort_values keys %topicCategory;
     $last_category = " ";
     foreach ( @topic_list )
        {   my $topic = $_;
            $category = $topicCategory{ $topic };
            print TOPICS "$category\n" if ( $category ne $last_category );
            $last_category = $category;
            print TOPICS "\t$topic\n";
        }

     close TOPICS;

	close $log_file;

    exit;
}



################################################################################
#
sub TrapErrors()
#
#  Setup to Trap Errors
#
################################################################################
{	my $filename = "DMOZImportErrors.log";

	my $MYLOG;
   
	open( $MYLOG, ">$filename" ) or return( undef );      	   
	&CarpOut( $MYLOG );
   
	print "Error logging set to $filename\n"; 
}





sub  Blocked( $ )
{    my $catname = shift;

     return( undef ) if ( !$catname );

     return( -1 ) if ( $catname eq "porn" );
     return( -1 ) if ( $catname eq "adult" );
     return( -1 ) if ( $catname eq "drugs" );
     return( -1 ) if ( $catname eq "gambling" );
     return( -1 ) if ( $catname eq "hate" );
     return( -1 ) if ( $catname eq "violence" );
     return( -1 ) if ( $catname eq "warez" );
     return( -1 ) if ( $catname eq "proxy" );

     return( undef );
}



sub  sort_values
{ 
my $ret = $topicCategory{ $a } cmp $topicCategory{ $b };
return( $ret ) if ( $ret != 0 );
$a cmp $b;
}



sub NameCategorize( $$ )
{   my $category = shift;
    my $url = shift;

    print NAMEFILE "$category \t $url\n";

    # Open the right file to write the hit urls to
    my $dir = $category;
    $dir = $opt_dir . "\\" . $category if ( $opt_dir );
    my  $cmd;
    my  $filename = "$dir\\domains.hit";

    #  Can I open an existing file?
    my $err;
    open( OUTPUT, ">>$filename" ) or $err = 1;
    if ( $err )
      {  $cmd = "mkdir \"$dir\"";
         system( $cmd );

         open( OUTPUT, ">>$filename" ) or die "Cannot create output file: $filename,\n$!\n";
     }

    print OUTPUT "$url\n";
    close OUTPUT;
}



################################################################################
# 
sub TrimTopic($)
#  Given a dmoz topic, trim off a level.  Return "top" if down to the root topic
#
################################################################################
{
   my  @parts = split /\//, shift;
   my  $i;
   my  $trim;


   #  Return top if down to the last parts
   return( "top" ) if ( $#parts < 2 );
   
   for ( $i = 0;  $i < $#parts;  $i++ )
      {  if ( $trim )  {  $trim = $trim . "\/" . $parts[ $i ];  }
         else  {  $trim = $parts[ $i ];  }
      }

    return( $trim );
}




################################################################################
# 
sub ShortTopic($)
#  Given a dmoz topic, return the shorted level of 5 deep.
#
################################################################################
{
   my $topic = shift;
   my  @parts = split /\//, $topic;
   my  $i;
   my  $trim;


   #  Return top if down to the last parts
   return( $topic ) if ( $#parts < 4 );
   
   for ( $i = 0;  $i < 4;  $i++ )
      {  if ( $trim )  {  $trim = $trim . "\/" . $parts[ $i ];  }
         else  {  $trim = $parts[ $i ];  }
      }

    return( $trim );
}



my $current_handle;	# The handle of the currently opened file
my $current_file;	# The filename of the currently opned file
################################################################################
# 
sub OpenFile( $ )
#
#  Given a category, return an open handle to the category filename
#  Close any previously opened file
#
################################################################################
{	my $category = shift;
	
    # Get the right file to write the hit urls to, open it if necessary
    my $dir = $category;
    $dir = $opt_dir . "\\" . $category if ( $opt_dir );
    my $filename = "$dir\\domains.hit";
	
	
	# Is this file already opened?
	if ( ( $current_file )  &&  ( $current_file eq $filename ) )
		{	return( $current_handle );
		}
	
	
	# Close any current file
	if ( $current_handle )
		{	close $current_handle;
			$current_handle = undef;
			$current_file = undef;
		}
	
	
	if ( ! -d $dir )
		{	my $cmd = "mkdir \"$dir\"";
			system( $cmd );	
		}
		
		
	if ( ! open( $current_handle, ">>$filename" ) )
		{	print "Error opening file $filename: $!\n";
			exit;	
		}
		
	$current_file = $filename;	
	return( $current_handle );
}



sub tprint
{	print "@_";
	print $log_file "@_";	
}



################################################################################

__END__

:endofperl
