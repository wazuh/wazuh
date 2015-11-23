#!/usr/bin/perl -w
use Socket;
use POSIX 'setsid';
use strict;
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
# "Ossec to Mysql" records the OSSEC HIDS alert logs in MySQL database.
# It can run as a daemon (ossec2mysqld.pl), recording in real-time the logs in database or
# as a simple script (ossec2mysql.pl).
#
# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
#
# MySQL Server
# Perl DBD::mysql module
# Perl DBI module
#
# ---------------------------------------------------------------------------
# Installation steps
# ---------------------------------------------------------------------------
# 
# 1) Create new database
# 2a) Run ossec2mysql.sql to create MySQL tables in your database
# 2b) Create BASE tables with snort tables extention
# 3) Create a user to access the database;
# 4) Copy ossec2mysql.conf to /etc/ossec2mysql.conf with 0600 permissions
# 3) Edit /etc/ossec2mysql.conf according to your configuration:
#	dbhost=localhost
#	database=ossecbase
#	debug=5
#	dbport=3306
#	dbpasswd=mypassword
#	dbuser=ossecuser
#	daemonize=0
#	resolve=1
#	
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
$SIG{TERM} = sub { &gracefulend('TERM')};
$SIG{INT} = sub { &gracefulend('INT')};
my ($RUNASDAEMON)=0;
my ($DAEMONLOGFILE)='/var/log/ossec2mysql.log';
my ($DAEMONLOGERRORFILE) = '/var/log/ossec2mysql.err';
my ($LOGGER)='ossec2mysql';
use ossecmysql;

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


my($OCT) = '(?:25[012345]|2[0-4]\d|1?\d\d?)';

my($IP) = $OCT . '\.' . $OCT . '\.' . $OCT . '\.' . $OCT;

my $VERSION="0.4";
my $sig_class_id=1;
&help() unless @ARGV;
my $dump=0;
my ($hids_id,$hids,$hids_interface,$last_cid)=(undef, 'localhost', 'ossec',0);
my ($tempvar,$VERBOSE)=(0,0); 
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
        $srcip,$dstip,$user,$text)=();
my $lasttimestamp=0;
my $delta=0;
########################################################
my $datepath=`date "+%Y/%b/ossec-alerts-%d.log"`;
my $LOG='/var/ossec/logs/alerts/'. $datepath;
chomp $LOG;
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
		$newrecord=1;
		next unless $timestamp;
		$alerthostip=$alerthost if $alerthost=~ m/^$IP$/;
		if ($alerthostip){
			$dstip=$alerthostip;
			$resolv{$alerthost}=$dstip;
		}else{
			if (exists $resolv{$alerthost}){
				$dstip=$resolv{$alerthost};
			}else{
				if ($conf{'resolve'}){
					$dstip=`host $alerthost 2>/dev/null | grep 'has address' `;
					if ($dstip =~m/(\d+\.\d+\.\d+\.\d+)/ ){
						$dstip=$1;
					}else{
						$dstip=$srcip;
					}
				}else{
					$dstip=$alerthost;
				}
				$resolv{$alerthost}=$dstip;
				
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
#
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
	}elsif ( m/Rule: ([0-9]+) \(level ([0-9]+)\) -> (.*)$/ ){
		$rule=$1;
		$level=$2;
		$description= $3;
	}elsif ( m/Src IP:/){
		if ( m/($IP)/){
                        $srcip=$1;
                }else{
                        $srcip='0.0.0.0';
                }
	}elsif ( m/User: (.*)$/){
                $user=$1;
        }elsif( m/(.*)$/){
		$text .=$1;
	}
		

   } # End while read line
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
	my ($count,$query,$row_ref,$sig_id);
###
#
# Get/Set signature id
	$query = "SELECT sig_id FROM signature where sig_name=? and sig_class_id=? and sig_priority=? and sig_rev=? and sig_sid=? and sig_gid is NULL";
	$dbi->execute($query,$description,1,$level,0,$rule);
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
		$dbi->execute($query,$description,1,$level,0,$rule);
		$sig_id = $dbi->lastid();
	}
$dbi->{sth}->finish;
&printlog ("SIGNATURE: $sig_id\n");
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
# Set acid_event
	$query=" INSERT INTO acid_event ( sid , cid , signature , sig_name , sig_class_id , sig_priority , timestamp , ip_src , ip_dst , ip_proto , layer4_sport , layer4_dport )
VALUES (
? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ?, ?
) ";
	$dbi->execute($query,$hids_id,$last_cid,$sig_id,$description,1,$level,&fixdate2base($date),$srcip,$dstip,undef,undef,undef);
&printlog ("ACID_EVENT: ($query,$hids_id,$last_cid,$sig_id,$description,1,$level,&fixdate2base($date),$srcip,$dstip,undef,undef)\n");
$dbi->{sth}->finish;

#########
#
#
# Set data
	$text = "** Alert $timestamp.$sec:\t$mail\n$date $alerthost -> $datasource\nRule: $rule (level $level) -> $description\nSrc IP: ($srcip)\nUser: $user\n$text";
	$query=" INSERT INTO data ( sid , cid , data_payload ) 
VALUES (
?,?,?)";
	$dbi->execute($query,$hids_id,$last_cid,$text);
&printlog ("DATA: ($query,$hids_id,$last_cid,$text)\n");
$dbi->{sth}->finish;
##########
#
	$query="UPDATE sensor SET last_cid=? where sid=? limit 1";
        $numrows= $dbi->execute($query,$last_cid,$hids_id);
# end sub
$dbi->{sth}->finish;
return $last_cid;
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
        chdir '/'               or die "Can't chdir to /: $!";
        open STDIN, '/dev/null' or die "Can't read /dev/null: $!";
        open STDOUT, ">>$DAEMONLOGFILE"
                               or die "Can't write to $DAEMONLOGFILE: $!";
        defined(my $pid = fork) or die "Can't fork: $!";
        if ($pid){
                open (PIDFILE , ">/var/run/ossec2base2.pid") ;
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
        close STDOUT;
	close STDERR;
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

