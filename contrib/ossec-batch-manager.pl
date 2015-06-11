#!/usr/bin/perl
# vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:

   #########################################################
  # Written Aug 4, 2007 and released under the GNU/GPLv2  ##
 # by Jeff Schroeder (jeffschroeder@computer.org)        # #
#########################################################  #
#                                                       #  #
# ossec-batch-manager.pl - Add and extract agents from  #  #
# the ossec client.keys file non-interactively. This    #  #
# started as a hack to properly script manage_agents.   #  #
#                                                       # #
##########################################################
# Modified by Tim Meader (Timothy.A.Meader@nasa.gov)
# on 2013/07/01
#
# - corrected a MAJOR logic error in the remove
#   function. The comparison was being done across the
#   entire line of the agent keys file, so both IPs
#   and the SSH keys at the end could be matched against
#   the 'agent ID' wanting to be removed. Changed the
#   match to only compare the first column of the file
# - added an error output message to the remove
#   function if it's fed an 'agent ID' that doesn't
#   exist
# - the script now also removes the corresponding
#   associated agent rid files after a successful remove
#   operation, or gives an error on failure
#            
##########################################################
# Modified by Tim Meader (Timothy.A.Meader@nasa.gov)
# on 2010/12/08
#            
# - fixed two errors that were popping up during add or
#   remove operations due to the code not taking into
#   account the old key entries that have the "#*#*#*"
#   pattern after the ID number. Simple fix was to do
#   a "if (defined(xxx))" on the vars
# - fixed the "list" operation to only show valid key
#   entries
# - changed the extract operation to store options
#   in an array, and subsequently rewrote the 
#   "extract_key" (now called "extract_keys") func
#   to accept this new behavior
# - modified "extract_keys" func to accept either ID,
#   name, or IP address as the argument after the
#   "-e" operator. Output of key extraction now
#   include the name and IP address by default in the
#   format: "name,IP  extracted_key"
#
#########################################################


#$Id$
# TODO:
# 	- Add check for ossec 1.4 and support longer agent names
#	- Add in eval so that older version of perl without
#	  Time::HiRes still can use this script.

use strict;
use warnings;
require 5.8.2; # Time::HiRes is standard from this version forth
#use diagnostics;
use MIME::Base64;
use Digest::MD5 qw(md5_hex);
use Getopt::Long;

use constant AUTH_KEY_FILE => "/var/ossec/etc/client.keys";
use constant RIDS_PATH => "/var/ossec/queue/rids/";

my ($key, $add, $remove, @extracts, $import, $listagents);
my ($agentid, $agentname, $ipaddress);

GetOptions(
  'k|key=s'     => \$key,         # Unencoded ssh key
  'a|add'       => \$add,         # Add a new agent
  'r|remove=s'  => \$remove,      # Remove an agent
  'e|extract=s' => \@extracts,     # Extract a key
  'm|import'    => \$import,      # Import a key
  'l|list'      => \$listagents,  # List all agents
  'i|id=s'      => \$agentid,     # Unique agent id
  'n|name=s'    => \$agentname,   # Agent name. 32 char max
  'p|ip=s'      => \$ipaddress    # IP Address in "dotted quad" notation
);

# Spit out a list of available agents, their names, and ip information
if ($listagents) {
  list_agents();
}
# Decode and extract the key for $agentid
elsif (@extracts) {
  if (@extracts) {
    extract_keys(@extracts);
  }
  else {
    usage();
  }
}
# Adding a new agent
elsif ($add) {
  if ($agentname && $ipaddress && $ipaddress =~
      m/(1?\d\d?|2[0-4]\d|25[0-5])(\.(1?\d\d?|2[0-4]\d|25[0-5])){3}/ &&
      # ossec doesn't like agent names > 32 characters.
      length($agentname) <= 32) {

      # Autogenerate an id incremented 1 from the last in a sorted list of
      # all current ones if it isn't specified from the command line.
      if (!$agentid) {

        # Make a list of all of the used agentids and then sort it.
        if (-r AUTH_KEY_FILE) {
          my @used_agent_ids = ();
          open (FH, "<", AUTH_KEY_FILE);
          while (<FH>) {
            my ($id, $name, $ip, $key) = split;
            push(@used_agent_ids, $id);
          }
          close(FH);

          if (@used_agent_ids) {
            @used_agent_ids = sort {$a <=> $b} @used_agent_ids;
            $agentid = sprintf("%03d", $used_agent_ids[-1] + 1);
          }
        }
        # If the client.keys is empty or doesn't exist set the id to 001
        $agentid = sprintf("%03d", 001) if (!$agentid);
        }

    # Autogenerate a key unless one was specified on the command line
    if (!$key) {
      use Time::HiRes; # Standard with perl >= 5.8.2

      my $rand_str1 = time() . $agentname . rand(10000);
      my $rand_str2 = Time::HiRes::time . $ipaddress . $agentid . rand(10000);
      $key = md5_hex($rand_str1) . md5_hex($rand_str2);
    }
      
    add_agent($agentid, $agentname, $ipaddress, $key);
  }
  else {
    warn "Error: adding agents requires: --name and --ip options.\n";
    usage();
  }
}
elsif ($remove) {
  if ($agentid) {
    remove_agent($agentid);
  }
  else {
    remove_agent($remove)
  }
}
elsif ($import) {
  # Every option needs to be specified and NOT autogenerated because what
  # is autogenerated on the server and the agent will likely be different
  if (!$agentid || !$agentname || !$ipaddress || !$key) {
    warn "Error: importing requires: --id, --name, --ip, and --key\n";
    usage();
  }
  else {
    # The key extracted from the server needs to be decoded before being put
    # into the client.keys 
    $key = MIME::Base64::decode($key);

    add_agent($agentid, $agentname, $ipaddress, $key);
  }
}
else {
  warn "Error: no options specified!\n";
  usage();
}

sub usage {
  warn "Usage: $0 [OPERATION] [OPTIONS]\n";
  warn "  [operations]\n";
  warn "    -a or --add                    = Add a new agent\n";
  warn "    -r or --remove  [id]           = Remove agent\n";
  warn "    -e or --extract [id|name|ip]   = Extract key\n";
  warn "    -m or --import  [keydata]      = Import key\n";
  warn "    -l or --list                   = List available agents\n";
  warn "  [options]\n";
  warn "    -k or --key     [keydata]  = Key data\n";
  warn "    -n or --name    [name]     = Agent name (32 character max)\n";
  warn "    -i or --id      [id]       = Agent identification (integer)\n";
  warn "    -p or --ip      [ip]       = IP address\n\n";
  exit 1;
}

sub list_agents {
  if (-r AUTH_KEY_FILE) {
    open (FH, "<", AUTH_KEY_FILE);
  }
  else {
    die "Error reading ".AUTH_KEY_FILE.": $!\n";
  }
  print "Available Agents:\n";
  print "ID",     " " x (25 - length('ID')),
        "NAME",   " " x (25 - length('NAME')),
        "IP",     " " x (25 - length('IP'));
  print "\n";
  while (<FH>) {
    chomp;
    my ($id, $name, $ip, $key) = split;
    if (defined($key)) {
      print "$id",    " " x (25 - length($id)),
            "$name",  " " x (25 - length($name)),
            "$ip",    " " x (25 - length($ip)) . "\n";
    }
  }
  close(FH);
  exit 0;
}

sub extract_keys {
  if (-r AUTH_KEY_FILE) {
    open (FH, "<", AUTH_KEY_FILE);
  }
  else {
    die "No ".AUTH_KEY_FILE."!\n";
  }
  
  foreach my $extract (@_) {
    my ($encoded, $decoded);
    my $found = 0;

    while (<FH>) {
      chomp;
      my ($id, $name, $ip, $key) = split;
      # Check to make sure it's a valid entry
      if (defined($key)) {
        if (($extract =~ /^\d+$/) && ($id == $extract)) {
          $found = 1;
        }
        elsif ($name eq $extract) {
          $found = 1;
        }
        elsif ($ip eq $extract) {
          $found = 1;
        }
        else {
          next;
        }
        # Newlines are valid base64 characters so use '' instead for \n
        $decoded = MIME::Base64::encode($_, '');
        print "$name,$ip  $decoded\n";
        next;
      }
    }
    if (!$found) {
      warn "Error: Agent $extract doesn't exist!\n";
    }
    seek FH,0,0;
  }
}

sub add_agent {
  my $id = shift;
  my $name = shift;
  my $ip = shift;
  my $agentkey = shift;

  if ($name && $ip && $agentkey) {
    # Valid example key:
    # 5a832efb8f93660857ce2acf8eec66a19fd9d4fa58e3221bbd2927ca8a0b40c3
    if ($agentkey !~ m/[a-z0-9]{64}/) { 
      warn "Error: invalid keydata! Let this script autogenerate it.\n";
      usage();
    }

    my @newagent = ($id, $name, $ip, $agentkey);
    my $exists = check_if_exists(\@newagent);

    if ($exists == 0) {
      # Append if client.keys exists and create it if it doesn't
      if (-e AUTH_KEY_FILE) {
        open(FH, ">>", AUTH_KEY_FILE) or die AUTH_KEY_FILE." error: $!\n";
      }
      else {
        open(FH, ">", AUTH_KEY_FILE) or die AUTH_KEY_FILE." error: $!\n";
      }
      print FH join(' ', @newagent), "\n";
      close(FH);
    }
    elsif ($exists == 1) {
      warn "ID: $id already in ".AUTH_KEY_FILE."!\n";
    }
    elsif ($exists == 2) {
      warn "Agent: $name already in ".AUTH_KEY_FILE."!\n";
    }
    elsif ($exists == 3) {
      warn "IP: $ip already in ".AUTH_KEY_FILE."!\n";
    }
  }
  else {
    warn "Missing options to --add or problem with ".AUTH_KEY_FILE.": $!\n";
    usage();
  }
}

sub remove_agent {
  my $removeid = shift;
  my @agent_array;

  if (-r AUTH_KEY_FILE) {
    open (FH, "<", AUTH_KEY_FILE);
  }
  else {
    die "Error: with ".AUTH_KEY_FILE.": $!\n";
  }
  while (<FH>) {
    push(@agent_array, $_);
  }
  close(FH);

  if (-w AUTH_KEY_FILE) {
    open (FHRW, ">", AUTH_KEY_FILE);
  }
  else {
    die "Error writing ".AUTH_KEY_FILE.": $!\n";
  }

  my $key_found = 0;

  foreach my $line (@agent_array) {
    my @split_line = split(/\s/,$line);

    if ($split_line[0] ne $removeid) {
      print FHRW "$line";
    }
    else {
      my $rids_file = RIDS_PATH.$removeid;
      $key_found = 1;
      unlink $rids_file or warn "Could not remove rids file for Agent ID \'".$removeid."\'!\n";
    }
  }
  close(FHRW);

  if (!$key_found) {
    die "Agent ID \'".$removeid."\' not found! Nothing removed.\n";
  }
  exit(0);
}

sub check_if_exists {
  my $agentlist_ref = shift;
  my ($newid, $newname, $newip);
  my $rval = 0;

  $newid = $agentlist_ref->[0];
  $newname = $agentlist_ref->[1];
  $newip = $agentlist_ref->[2];

  # If the file isn't readable, the id probably isn't already in it
  if (-r AUTH_KEY_FILE) {
    open (FH, "<", AUTH_KEY_FILE);
    while (<FH>) {
      chomp;
      my ($id, $name, $ip, $key) = split;
      if(defined($key)) {
        $rval = 1 if ($id == $newid && $rval == 0);
        $rval = 2 if ($name eq $newname && $rval == 0); 
        $rval = 3 if ($ip eq $newip && $rval == 0);
      }
    }
    close(FH);
  }
  return $rval;
}
