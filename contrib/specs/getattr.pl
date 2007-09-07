#!/usr/bin/perl -w

#
# find /var/ossec/ -exec ./getattr.pl {} \;
#

use File::stat;

my %UID;
my %GUID;

$filename = shift || die "\nsyntax: $0 <file|directory>\n\n";

get_uid();
get_gid();

$sb = stat($filename);

die "\nUID $sb->uid doesn't exist?! ($filename)\n\n" if (! exists($UID[$sb->uid]));
die "\nGID $sb->uid doesn't exist?! ($filename)\n\n" if (! exists($GID[$sb->gid]));

if ( -d $filename ) {  ### directory
  print '%dir ' . $filename . "\n";
} elsif ( -f $filename ) { ### file
  print $filename . "\n";
} else {
  die("\nI can't handle: $filename\n\n");
}

# %attr(550, root, ossec) /var/ossec/etc

printf "%%attr(%03o, %s, %s) %s\n",
    $sb->mode & 07777,
    $UID[$sb->uid], $GID[$sb->gid], $filename;

#printf "%s: perm %04o, owner: %s, group: %s \n",
#    $filename, $sb->mode & 07777,
#    $UID[$sb->uid], $GID[$sb->gid];

sub get_uid
{
   open(FP,'</etc/passwd') || die "\nCan't open /etc/passwd\n\n";

   while ($line = <FP>) {
     ($name,$id) = (split(/:/,$line,))[0,2];
     $UID[$id] = $name;
   }
   close(FP);
}

sub get_gid
{
   open(FP,'</etc/group') || die "\nCan't open /etc/group\n\n";

   while ($line = <FP>) {
     ($name,$id) = (split(/:/,$line,))[0,2];
     $GID[$id] = $name;
   }
   close(FP);
}  

