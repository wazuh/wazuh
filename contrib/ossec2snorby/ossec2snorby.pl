#!/usr/bin/perl -w
use Socket;
use POSIX 'setsid';
use strict;
use ossecmysql;
# ---------------------------------------------------------------------------
# Author: Meir Michanie (meirm@riunx.com)
# Co-Author: J.A.Senger (jorge@br10.com.br)
# $Id$
# ---------------------------------------------------------------------------
# http://www.riunx.com/
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
# About this script
# ---------------------------------------------------------------------------
#
# "Ossec to Snorby" records the OSSEC HIDS alert logs in MySQL database.
# It can run as a daemon (ossec2snorby.pl), recording in real-time the logs in database or
# as a simple script (ossec2snorby.pl).
#
# ---------------------------------------------------------------------------
# Snorby support by Jean-Pierre Zurbrugg (jp.zurbrugg@live.com)
# ---------------------------------------------------------------------------
# The original script by the Author and Co-author was taken as a template and
# modified to work with Snorby (http://snorby.org) which uses a Snort DB schema.
# Credit must go to the author\Co-author for the initial template. 
#
########################### WARNING ###############################
# My modifications are by far stable and worthy of a production environment
# WHITHOUT INICIAL TWEAKING. Please setup your labs and make sure everything
# works properly before using this script on a production environment.
########################### WARNING ###############################
#
#
#  Changelog:
#     * Extra validations were added to make sure srcip\dstip do not remain with
#           a default value of "0" which causes GUI parsing errors if left unhandled.
#     * Validation against '$hostname'; if localhost then srcip="127.0.0.1"
#     * Snorby expects IP related data to be published on its "iphdr" table.
#     * Snorby expects OSSEC's logs to be converted to HEX and wordwrapped.
#     * Modified the scripts "Daemon" mode; it now uses "tail -Fn 0 <file>"
#
# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
#
# MySQL Server
# Perl DBD::mysql module
# Perl DBI module
#
# Snorby prerequesites:
#   import ossec2snorby_category.sql from contrib directory
#   Populate "domain" in /etc/ossec2snorby.conf
#
# ---------------------------------------------------------------------------
# Installation steps
# ---------------------------------------------------------------------------
# 
# 1) Create a user to access the database initially created by Snorby;
# 2) Copy ossec2snorby.conf to /etc/ossec2snorby.conf with 0600 permissions
# 3) Edit /etc/ossec2snorby.conf according to your needs:
#   dbhost=localhost
#   database=snorby
#   debug=5
#   dbport=3306
#   dbpasswd=mypassword
#   dbuser=ossecuser
#   daemonize=0
#   resolve=1
#   domain=mydomain.local
#
# NOTE: It is recommended to keep "resolve" as "1" and populate "domain" with
#       your actual domain. Not doing so will restrict the script and force it
#       to populate IPs as "0.0.0.1" for events whose SRC or DST IP are unknown.
#
# ---------------------------------------------------------------------------
# License
# ---------------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# ---------------------------------------------------------------------------
# About OSSEC HIDS
# ---------------------------------------------------------------------------
#
# OSSEC HIDS is an Open Source Host-based Intrusion Detection System.
# It performs log analysis and correlation, integrity checking,
# rootkit detection, time-based alerting and active response.
# http://www.ossec.net
#
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
my $VERSION="0.4";
$SIG{TERM} = sub { &gracefulend('TERM')};
$SIG{INT} = sub { &gracefulend('INT')};

# If no ARGV are given then present &help().
&help() unless @ARGV;

my ($RUNASDAEMON)=0;
my ($DAEMONLOGFILE)='/var/log/ossec2snorby.log';
my ($DAEMONLOGERRORFILE) = '/var/log/ossec2snorby.err';
# Declare OSSEC's log path and filename format.
my $LOG='/var/ossec/logs/alerts/alerts.log';  # we need to tail this file instead of the old.
                                              # With this we can survive file rotations while
                                              # running in daemon mode.

my ($LOGGER)='ossec2snorby';
my($OCT) = '(?:25[012345]|2[0-4]\d|1?\d\d?)';
my($IP) = $OCT . '\.' . $OCT . '\.' . $OCT . '\.' . $OCT;
my $dump=0;
my ($hids_id,$hids,$hids_interface,$last_cid)=(undef, 'localhost', 'ossec',0);
my ($tempvar,$VERBOSE)=(0,0); 

my %conf;
$conf{dbhost}='localhost';
$conf{database}='snort';
$conf{debug}=5;
$conf{dbport}='3306';
$conf{dbpasswd}='password';
$conf{dbuser}='user';
$conf{daemonize}=0;
$conf{sensor}='sensor';
$conf{hids_interface}='ossec';
$conf{resolve}=1;
$conf{domain}='';

# OSSEC's default class_ID
# We will categorize events as "unknown" if a match could not be found...
my $sig_class_id=2;  # We will try to fetch the correct class_id later.

my($sig_class_name,$taillog);
# ---------------------------------------------------------------------------
# Arguments parsing
# ---------------------------------------------------------------------------
while (@ARGV){
        $_= shift @ARGV;
    if (m/^-d$|^--daemon$/){
        $conf{daemonize}=1;
    }elsif ( m/^-h$|^--help$/){
                &help();
        }elsif ( m/^-n$|^--noname$/){
                $conf{'resolve'}=0;
        }elsif ( m/^-v$|^--verbose$/){
         $VERBOSE=1;
    }elsif ( m/^--interface$/){
                $conf{hids_interface}= shift @ARGV if @ARGV; # ossec-rt/ossec-feed
        }elsif ( m/^--sensor$/){
                $conf{sensor}= shift @ARGV if @ARGV; # monitor
        }elsif ( m/^--conf$/){
                $conf{conf}= shift @ARGV if @ARGV; # localhost
        &loadconf(\%conf);
        }elsif ( m/^--dbhost$/){
                $conf{dbhost}= shift @ARGV if @ARGV; # localhost
        }elsif ( m/^--dbport$/){
                $conf{dbport}= shift @ARGV if @ARGV; # localhost
        }elsif ( m/^--dbname$/){
                $conf{database}= shift @ARGV if @ARGV; # snort
        }elsif ( m/^--dbuser$/){
                $conf{dbuser}= shift @ARGV if @ARGV; # root
        }elsif ( m/^--dbpass$/){
                $conf{dbpasswd}= shift @ARGV if @ARGV; # monitor
        }

}
if ($conf{dbpasswd}=~ m/^--stdin$/){
    print "dbpassword:";
    $conf{dbpasswd}=<>;
    chomp $conf{dbpasswd};
}
$hids=$conf{sensor} if exists($conf{sensor});
$hids_interface=$conf{hids_interface} if exists($conf{hids_interface});

# START IN DAEMON MODE ?
&daemonize() if $conf{daemonize};

my $dbi= ossecmysql->new(%conf) || die ("Could not connect to $conf{dbhost}:$conf{dbport}:$conf{database} as $conf{dbpasswd}\n");

####
# SQL vars;
my ($query,$numrows,$row_ref);

####
#get sensor id
$query= 'select sid,last_cid from sensor where hostname=? and interface=?';
$numrows= $dbi->execute($query,$hids,$hids_interface);
if (1==$numrows){
    $row_ref=$dbi->{sth}->fetchrow_hashref;
    $hids_id=$row_ref->{sid};
    $last_cid=$row_ref->{last_cid};
}else{
    $query="INSERT INTO sensor ( sid , hostname , interface , filter , detail , encoding , last_cid )
VALUES (
NULL , ?, ? , NULL , ? , ?, ?
)";
    $numrows= $dbi->execute($query,$hids,$hids_interface,1,2,0);
    $hids_id=$dbi->lastid();
}
$dbi->{sth}->finish;
&forceprintlog ("SENSOR:$hids; feed:$hids_interface; id:$hids_id; last cid:$last_cid");

my $newrecord=0;
my %stats;
my %resolv;
my ($timestamp,$sec,$mail,$date,$alerthost,$alerthostip,$datasource,$rule,$level,$description,
        $srcip,$dstip,$user,$text,$filtered,$osseclevel)=();
my $lasttimestamp=0;
my $delta=0;

&taillog($last_cid,$LOG);
################################################################
sub forceprintlog(){
    $tempvar=$VERBOSE;
    $VERBOSE=1;
    &printlog (@_);
    $VERBOSE=$tempvar;
}

sub taillog {
   my ($last_cid,$LOG)=@_;
   while (<>) {
    if (m/^$/){
        # we reached a newline, finish up with current record.
        $newrecord=1;
        next unless $timestamp;
        $alerthostip=$alerthost if $alerthost=~ m/^$IP$/;
        
        # Populate DST IP
        if ($alerthostip){
            $dstip=$alerthostip;
            $resolv{$alerthost}=$dstip;

        }else{
            if (exists $resolv{$alerthost}){
                $dstip=$resolv{$alerthost};
            }else{
                if ($conf{'resolve'}){
                    if ($alerthost =~m/(\d+\.\d+\.\d+\.\d+)/ ){
                        $dstip=$1;
                    }else{
                        # the "host" command doesn't work with Flatname\NetBIOS names.
                        # The server's hostname is almost always a flatname and OSSEC
                        # doesn't return an IP for alerts generated from localhost.
                        # Ex. 2013 Jan 24 15:51:36 ubuntu->/var/log/auth.log                    
                        my $x = `cat /etc/hostname`;  # get Host's hostname
                        chomp $x;  # remove extra lines, if any.
                        if ($x eq $alerthost) {  # Validate if $alerthost is us, localhost.
                            $dstip='127.0.0.1';  # Snorby does not allow empty\"0" as IP value.
                        }else{
                            my $fetch=&host2ip($alerthost);
                        
                            if (defined $fetch){
                                $dstip=$fetch;
                            }else{
                                $dstip=$srcip;
                            }
                        }
                    }
                }
                $resolv{$alerthost}=$dstip;
            }
        }
        
        #Populate SRC IP (requires dstip to be populated)
        if (! defined $srcip) {
            if (defined $dstip) {
    #Feb  6 15:18:21 1.1.1.1 %ASA-3-313001: Denied ICMP type=3, code=3 from 111.111.1.1 on interface OUTSIDE
                $filtered =~ s/$dstip//;            # filter out known dstip from log output.
                $srcip=$1 if $filtered=~ m/\s($IP)\s/;  # Search all text for an IP address.
                                                        # This could easily bug out with logs that contains
                                                        # version numbering such as mysql 1.3.4.5.
            }
    # Windows logs include "User Name" in their log output. Some companies name their employees's PCs after its users which is
    # resolvable via DNS.
    # Windows logs may state a computer name as "User Name". Lets strip out the "$" from the computer name...
            if (defined $user and ! defined $srcip) {
                my $u=$user;
                $u=~ s/\$//;  # remove "$" from computer names.

                my $fetch=&host2ip($u);
                $srcip=$fetch if (defined $fetch);
            }
            if (! defined $srcip or $srcip eq '') {
                # NO recognizable IPs or User Names were found on log output,
                # this suggests the log was generated by dstip.
                $srcip=$dstip;                    
            }
        }
        #
        $last_cid= &prepair2basedata(
            $hids_id,
            $last_cid,
            $timestamp,
            $sec,
            $mail,
            $date,
            $alerthost,
            $datasource,
            $rule,
            $level,
            $description,
            $srcip,
            $dstip,
            $user,
            $text
        );
        ($timestamp,$sec,$mail,$date,$alerthost,$alerthostip,$datasource,$rule,$level,$description,
        $srcip,$dstip,$user,$text)=();
        next ;
    }
    if (m/^\*\* Alert ([0-9]+).([0-9]+):(.*)$/){
        $timestamp=$1;
        if ( $timestamp == $lasttimestamp){
            $delta++;
        }else{
            $delta=0;
            $lasttimestamp=$timestamp;
        }
        $sec=$2;
        $mail=$3;
        $mail=$mail ? $mail : 'nomail';
#2006 Aug 29 17:19:52 firewall -> /var/log/messages
#2006 Aug 30 11:52:14 192.168.0.45->/var/log/secure
#2006 Sep 12 11:12:16 92382-Snort1 -> 172.16.176.132
        }elsif ( m/^([0-9]+\s\w+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+)\s+(\S+)\s*->(.*)$/){
                $date=$1;
                $alerthost=$2;
                $datasource=$3;
                if ($datasource=~ m/(\d+\.\d+\.\d+\.\d+)/){
                        $alerthost=$1;
                        $datasource="remoted";
                }
#2006 Aug 29 17:33:31 (recepcao) 10.0.3.154 -> syscheck
    }elsif ( m/^([0-9]+\s\w+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+)\s+\((.*?)\)\s+(\S+)\s*->(.*)$/){
        $date=$1;
        $alerthost=$2;
        $alerthostip=$3;
        $datasource=$4;
    }elsif ( m/^([0-9]+\s\w+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+)\s(.*?)$/){
                $date=$1;
                $alerthost='localhost';
                $datasource=$2;
    }elsif ( m/Rule: ([0-9]+) \(level ([0-9]+)\) -> \'(.*)\'$/ ){
        $rule=$1;
        $level=$2;
        $osseclevel=$level;  # Keep copy of OSSEC level as it will later be converted to snort level.
        $description= $3;
    }elsif ( m/src\s?ip:/i){
        if ( m/($IP)/){
            $srcip=$1;
        }else{
            $srcip='1';  # Snorby doesn't like srcip\dstip = 0\null.
        }
    }elsif ( m/User: (.*)$/){
        $user=$1;
    }elsif ( m/(.*)$/){
        my $x=$1;
 
        # Get IP from User Name + DNS query.
        if (! defined $user){
             if ( m/User\s?Name:\s?(\S+)\s/i){
                my $u=$1;
                $user="$u";
            }
        }
        $x =~ s/(.$)/$1\r\n/;  # lets multiline this string for cleaner output once $payload wordwraps it.
        $text .=$x;
        
        # This variable will be used to populate srcip once we reach the end of the current log entry.
        $filtered=$text;
    }
   } # End of while read line
}

sub prepair2basedata(){
    my (
        $hids_id,
        $last_cid,
        $timestamp,
        $sec,
        $mail,
        $date,
        $alerthost,
        $datasource,
        $rule,
        $level,
        $description,
        $srcip,
        $dstip,
        $user,
        $text
    )=@_;
    my ($payload,$count,$query,$row_ref,$sig_id);
    
   
###
# Get sig_class_id
#
# Note: the original script stated sig_class_id as "1" by default which in BASE might be ok but for 
# snorby it maps to a category of "not-suspicious" which is not efficient when stats are ran based on
# event categories alone...
#
# Furthermore, OSSEC allows a rule to have multiple categories assigned to it which snorby was not prepared to handle GUI
# wize. (The event details contains a small section where the category value can be shown, this section is too small
# to show OSSEC's sometimes long category results such as :
#  syslog,sshd,invalid_login,authentication_failed,)
#
# We will use the last category shown only...This isn't the correct approach but my programing skills prevent me
# from providing a better solution.

    # ex: - syslog,sshd,invalid_login,authentication_failed,
    if ($mail=~ m/\.*\,?(\w+\_?\w+)\,?$/){  # $mail contains the rule's categories. No clue why its named $mail...
        $sig_class_name=$1;
        &printlog ("SIG_CLASS_NAME: $sig_class_name \n");
        $query = "SELECT sig_class_id FROM category WHERE cat_name=?";
        $dbi->execute($query,$sig_class_name);
        $count=$dbi->{sth}->rows;
        if ($count){
            $row_ref=$dbi->{sth}->fetchrow_hashref;
            $sig_class_id=$row_ref->{sig_class_id};
            &printlog ("SIG_CLASS_ID: $sig_class_id");
        }else{
            &printlog ("SIG_CLASS_ID NOT FOUND. USING DEFAULT SIG.");
            $sig_class_id=2;
        }
    }else{
        &printlog ("COULD NOT GET A RULE CATEGORY. USING DEFAULT SIG.");
        $sig_class_id=2;
    }

###
#
# Get/Set signature id

    # Convert OSSEC Severity to Snort Severity.
    #   Dont modify this after having live data on Snorby as it will create duplicated
    #   sig_names.
    $level=4 if ($level <= 4);  # Informational only.
    $level=3 if ($level == 5);  # User generated errors \ low severity.
    $level=2 if (($level >= 6) && ($level <=11));  # Low to mid severity attacks.
    $level=1 if ($level >= 12);  # High importance events \ Successfull attacks \ all our bases belong to them!

    $query = "SELECT sig_id FROM signature where sig_name=? and sig_class_id=? and sig_priority=? and sig_rev=? and sig_sid=? and sig_gid is NULL";
    $dbi->execute($query,$description,$sig_class_id,$level,0,$rule);
    $count=$dbi->{sth}->rows;
    if ($count){
        $row_ref=$dbi->{sth}->fetchrow_hashref;
        $sig_id=$row_ref->{sig_id};
        &printlog ("REUSING SIGNATURE\n");
    }else{
        $query="INSERT INTO signature ( sig_id , sig_name , sig_class_id , sig_priority , sig_rev , sig_sid , sig_gid )
VALUES (
NULL ,?, ? , ? , ? , ?, NULL
)";
        $dbi->execute($query,$description,$sig_class_id,$level,0,$rule);
        $sig_id = $dbi->lastid();
    }
    $dbi->{sth}->finish;
    &printlog ("SIGNATURE: $sig_id\n");
    
    
    ############################
    ############################
        #DEBUG
    # &printlog ("filtered: $filtered \n");
    # &printlog ("SRC IP: $srcip \n");
    # &printlog ("DST IP: $dstip \n");
    # &printlog ("mail: $mail \n");
    # &printlog ("sig_class_name: $sig_class_name");
    # &printlog ("date: $date \n");
    # &printlog ("alerthost: $alerthost \n");
    # &printlog ("rule: $rule \n");
    # &printlog ("level: $level \n");
    # &printlog ("OSSEC level: $osseclevel \n");
    # &printlog ("USER: $user \n");
    # &printlog ("text: $text \n");
    # &printlog ("sec?: $sec \n");
    # &printlog ("datasource: $datasource \n");
    # &printlog ("description: $description \n");
    # exit 1;
    ############################
    
    
#######
#
# Set event
    $query="INSERT INTO event ( sid , cid , signature , timestamp )
VALUES (
? , ? , ? ,? 
)";
    $last_cid++;
    $dbi->execute($query,$hids_id,$last_cid,$sig_id,&fixdate2base($date));

    &printlog ("EVENT: ($query,$hids_id,$last_cid,$sig_id,&fixdate2base($date)\n");
    $dbi->{sth}->finish;
#########
#
# Set iphdr

    # And yet again,Snorby doesn't like empty IP fields; Validate if srcip or dstip are empty.
    $srcip = "1" if !defined $srcip;  # leaving the fields srcip / dstip with a value = 0
    $dstip = "1" if !defined $dstip;  # causes output to get messed up on the GUI.  

    $query=" INSERT INTO iphdr ( sid , cid , ip_src , ip_dst , ip_ver , ip_hlen , ip_tos , ip_len , ip_id , ip_flags , ip_off , ip_ttl , ip_proto , ip_csum )
VALUES (
? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ?
) ";
    $dbi->execute($query,$hids_id,$last_cid,$srcip,$dstip,4,5,0,20,0,0,0,0,0,0);
    &printlog ("iphdr: ($query,$hids_id,$last_cid,$srcip,$dstip,4,5,0,undef,undef,undef,undef,undef,undef,undef)\n");
    $dbi->{sth}->finish;

#########
#
#
# Set data
    $payload = "$date ($alerthost) $dstip->$datasource\r\nRule: $rule (OSSEC level $osseclevel) -> $description\r\n$text";
    $payload =~ s/(.{1,109}\S|\S+)\s+/$1\r\n/mg;  # Snorby does not wordwrap the payload, lets wrap the first 109 non-whitespace chars. 
    $payload = unpack("H*",$payload);             # Convert to HEX

    $query=" INSERT INTO data ( sid , cid , data_payload ) 
VALUES (
?,?,?)";
    $dbi->execute($query,$hids_id,$last_cid,$payload);
    &printlog ("DATA: ($query,$hids_id,$last_cid,$payload)\n");
    $dbi->{sth}->finish;
##########
#
    $query="UPDATE sensor SET last_cid=? where sid=? limit 1";
    $numrows= $dbi->execute($query,$last_cid,$hids_id);

    $dbi->{sth}->finish;
    return $last_cid;
} # end sub

sub host2ip {
    # This sub requires argument 0 to be a named host. We also need to know
    # the domain to which we belong to in order to append it to the host if
    # its a flatname host.
    my $host=$_[0];
    my $domain=$conf{domain} if exists($conf{domain});
    my $CMD;

    # Validate if we were fed a flatnamed host or a FQDN.
    if ($host =~ m/.*\..+/){
        # FQDN
        $CMD=`host $host 2>/dev/null | grep 'has address' `;
        if ($CMD =~m/(\d+\.\d+\.\d+\.\d+)/ ){
            return($1);
        }else{
            return undef; # return False.
        }
        
    }else{
        # FLATNAME
        if (! defined $domain or $domain eq ''){
            &printlog ('[WARNING]: domain value was not populated on ossec2snorby.conf." . 
            " DNS resolutions cannot be completed for NetBIOS\Flatname hosts.');
            return undef;
        }

        # There is an extra "." after $domain, this is to ensure linux
        # does not append "localdomain" at the end of the host.
        $CMD=`host $host.$domain. 2>/dev/null | grep 'has address' `;
        if ($CMD =~m/(\d+\.\d+\.\d+\.\d+)/ ){
            return($1);
        }else{
            return undef; # return False.
        }
    }
}

sub fixdate2base(){
    my ($date)=@_;
    $date=~ s/ Jan /-01-/;
    $date=~ s/ Feb /-02-/;
    $date=~ s/ Mar /-03-/;
    $date=~ s/ Apr /-04-/;
    $date=~ s/ May /-05-/;
    $date=~ s/ Jun /-06-/;
    $date=~ s/ Jul /-07-/;
    $date=~ s/ Aug /-08-/;
    $date=~ s/ Sep /-09-/;
    $date=~ s/ Oct /-10-/;
    $date=~ s/ Nov /-11-/;
    $date=~ s/ Dec /-12-/;
    $date=~ s/\s$//g;
    return $date;
}
sub version(){
    print "OSSEC report tool $VERSION\n";
    print "Licensed under GPL\n";
    print "Contributor Meir Michanie\n";
}

sub help(){
    &version();
    print "This tool helps you import into base the alerts generated by ossec."
        . " More info in the doc directory .\n";
        print "Usage:\n";
        print "$0 [-h|--help] # This text you read now\n";
    print "Options:\n";
    print "\t--dbhost <hostname>\n";
    print "\t--dbname <database>\n";
    print "\t--dbport <[0-9]+>\n";
    print "\t--dbpass <dbpasswd>\n";
    print "\t--dbuser <dbuser>\n";
    print "\t-d|--daemonize\n";
    print "\t-n|--noname\n";
    print "\t-v|--verbose\n";
    print "\t--conf <ossec2based-config>\n";
    print "\t--sensor <sensor-name>\n";
    print "\t--interface <ifname>\n";
    
    exit 0;
}


sub daemonize {
    my $running = kill 0, `cat /var/run/ossec2base2.pid`;
    if ($running){
        print "OSSEC2SNORBY is already running...\n";
        exit 1;
    }

    chdir '/'               or die "Can't chdir to /: $!";
    
    open STDOUT, ">>$DAEMONLOGFILE"
                           or die "Can't write to $DAEMONLOGFILE: $!";

    # I may be mistaken but the original script didn't seem to actually
    # tail the logs. It would run until it hit EOF and then exit script.
    $taillog= open STDIN,"-|", "/usr/bin/tail", "-Fn 0", "$LOG";
    if ($taillog){
        &forceprintlog ("Daemon started TAIL PID: $taillog");
        &forceprintlog ("NOW MONITORING: $LOG");
    }else{
        &forceprintlog ("Could not start daemon on $LOG: $!");
        exit 1;
    }

    defined(my $pid = fork) or die "Can't fork: $!";
    if ($pid){
            open (PIDFILE , ">/var/run/ossec2snorby.pid") ;
            print PIDFILE "$pid\n";
            close (PIDFILE);
            exit 0;
    }
    setsid                  or die "Can't start a new session: $!";
    open STDERR, ">>$DAEMONLOGERRORFILE" or die "Can't write to $DAEMONLOGERRORFILE: $!";
}

sub gracefulend(){
    my ($signal)=@_;
    &forceprintlog ("Terminating upon signal $signal");
    &forceprintlog ("Daemon halted");
    # This might be paranoid or simply useless but better safe than sorry.
    close STDOUT or die "WARNING: Closing STDOUT failed.";
    close STDERR or die "WARNING: Closing STDERR failed.";
    kill 3, $taillog or die "WARNING: Closing $taillog failed.";
    close STDIN or die "WARNING: Closing STDIN failed.";
    exit 0;
}

sub printlog(){
    return unless $VERBOSE;
        my (@lines)=@_;
        foreach my $line(@lines){
                chomp $line;
                my ($date)=scalar localtime;
                $date=~ s/^\S+\s+(\S+.*\s[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}).*$/$1/;
                print "$date $LOGGER: $line\n";
        }
    }


sub loadconf(){
    my ($hash_ref)=@_;
    my $conf=$hash_ref->{conf};
    unless (-f $conf) { &printlog ("ERROR: I can't find config file $conf"); exit 1;}
    unless (open ( CONF , "$conf")){ &printlog ("ERROR: I can't open file $conf");exit 1;}
    while (<CONF>){
        next if m/^$|^#/;
        if ( m/^(\S+)\s?=\s?(.*?)$/) {
                        $hash_ref->{$1} = $2;
                }
    }
    close CONF;
}
