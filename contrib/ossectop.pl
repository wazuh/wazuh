#!/usr/bin/perl -w
#use strict;
use Socket;
use POSIX 'setsid';
# ---------------------------------------------------------------------------
# Author: Meir Michanie (meirm@riunx.com)
# File: ossectop.pl
# Version 0.1 (09/2006)
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

my %conf;
$conf{resolve}=1;


my($OCT) = '(?:25[012345]|2[0-4]\d|1?\d\d?)';

my($IP) = $OCT . '\.' . $OCT . '\.' . $OCT . '\.' . $OCT;

my $VERSION="0.1";
my $sig_class_id=1;
my $dump=0;
my ($hids_id,$hids,$hids_interface,$last_cid)=(undef, 'localhost', 'ossec',0);
my ($tempvar,$VERBOSE)=(0,0);
# ---------------------------------------------------------------------------
#  Arguments parsing
# ---------------------------------------------------------------------------
 
while (@ARGV){
        $_= shift @ARGV;
	if ( m/^-h$|^--help$/){
                &help();
	}elsif ( m/^-n$|^--noname$/){
                $conf{'resolve'}=0;
	}
}


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
$date='';
format TOPREPORT =
 ==========================================================================================================================
|                                                  OSSEC-HIDS TOP                                                          |
 ==========================================================================================================================
| Alert  |  Date                 | SRC          | DST          | LVL | Name                                                |
 ==========================================================================================================================
.
format REPORT =
|@<<<<<  |@<<<<<<<<<<<<<<<<<<<<< |@<<<<<<<<<<<< |@<<<<<<<<<<<< |@<<< |@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< |
$rule,$date,$srcip,$dstip,$level,$description
.
#$~='REPORT';
#$~='TOPREPORT';

&taillog();
###############################################################
sub taillog {
   my($offset, $line, $stall) = '';

   $offset = (-s $LOG); # Don't start at beginning, go to end

	my $count=10;
   while (1==1) {
       sleep(1);
	%resolv=();
       $| = 1;
       $stall += 1;
	$datepath=`date "+%Y/%b/ossec-alerts-%d.log"`;
	$LOG='/var/ossec/logs/alerts/'. $datepath;
	chomp $LOG;
	unless ( -f $LOG){print "Error -f $LOG\n"; next; }
       if ((-s $LOG) < $offset) {
           $offset = 0;
       }

        unless (open(TAIL, $LOG)){ print "Error opening $LOG: $!\n";next ;}

        if (seek(TAIL, $offset, 0)) {
           # found offset, log not rotated
       } else {
           # log reset, follow
           $offset=0;
           seek(TAIL, $offset, 0);
       }
       while (<TAIL>) {
	if (m/^$/){
		$newrecord=1;
		next unless $timestamp;
		$count++;
		if ($count>10){
			system ("clear");
			$~='TOPREPORT';
		        write;
			$count=0;
		}

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
		$~='REPORT';
		write;
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
#
	}elsif ( m/^([0-9]+\s\w+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+)\s+(\S+)\s*->(.*)$/){
		$date=$1;
		$alerthost=$2;
		$datasource=$3;
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
	}elsif ( m/Rule: ([0-9]+) \(level ([0-9]+)\) -> '(.*)'$/ ){
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
       $offset=tell(TAIL);
       close(TAIL);
   }
}

sub version(){
	print "OSSEC report tool $VERSION\n";
	print "Licensed under GPL\n";
	print "Contributor Meir Michanie\n";
}

sub help(){
	&version();
	print "List alerts generated by ossec."
        . " More info in the doc directory .\n";
        print "Usage:\n";
        print "$0 [-h|--help] # This text you read now\n";
	print "Options:\n";
	print "\t-n|--noname\n";
	
	exit 0;
}


sub gracefulend(){
        my ($signal)=@_;
        close TAIL;
        close STDOUT;
	close STDERR;
        exit 0;
}
