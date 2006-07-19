#!/usr/bin/perl
# ---------------------------------------------------------------------------
# Author: J.A.Senger (jorge@br10.com.br)
# File: ossec2mysql.pl
# Version 0.6 (07/2006)
# ---------------------------------------------------------------------------
# http://www.jasenger.com/ossec2mysql
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
# Perl File::Tail module (only for ossec2mysqld.pl)
#
# ---------------------------------------------------------------------------
# Installation steps
# ---------------------------------------------------------------------------
#
# 1) Run mysql_ossec.sql to MySQL's database and table;
# 2) Create a user to access the database;
# 3) Change the variables on session "Parameters":
#       $par{dir_logs}: The OSSEC alert logs dir. Default is /var/ossec/logs/alerts/
#       $par{db_host}: Host that runs MySQL database. Default is localhost
#       $par{db_user}: User to access the database. Default is ossec
#       $par{db_passwd}: Password to access the database. Default is ossec
#       $par{db_db}: Database name. Default is ossec
# If you change the database name, you must edit ossec_mysql.sql with the new db name.
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

$| = 1;
&today();
$par{dir_logs} = "/var/ossec/logs/alerts/";
$par{db_host} = "localhost";
$par{db_user} = "ossec";
$par{db_passwd} = "ossec";
$par{db_db} = "ossec";

# Show logs and status on screen ?
# 1/Yes 0/No

$par{show_screen} = 1;

# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

use DBI;
$dbh = DBI->connect("DBI:mysql:$par{db_db}:$par{db_host}", $par{db_user}, $par{db_passwd});

# ---------------------------------------------------------------------------
# Writing the log file in database
# ---------------------------------------------------------------------------

if ($par{show_screen})
{
	print "Writing log file in database $par{db_db} on $par{db_host} ...\n";
}
$count = 0;
$records = 0;
$par{log_file} = $par{dir_logs}.$today{year}."/".$txt_month."/ossec-alerts-".$today{day}.".log";
open(ARQ, "$par{log_file}") or die("Could not open log file.");
@lines = <ARQ>;
chomp @lines;
close ARQ;
foreach $line (@lines)
{
	if ($count == 6)
	{
                &month_number;
                $date = $year."-".$month_number."-".$day." ".$hour;
		$query = "select * from alerts where code = '$code'";
		$sth = $dbh->prepare($query);
		$sth->execute;
		if (!$sth->rows)
		{
			$records++;
			$query = "insert into alerts (code, date, agent, logfile, host, rule, level, description, source, user) values ('$code', '$date', '$agent', '$logfile', '$host', '$rule', '$level', '$description', '$source', '$user')";
			$dbh->do($query);
		}
		if ($par{show_screen})
		{
			print "\n";
			print "-------------------------\n";
			print "Code: $code\n";
			print "Year: $year\n";
			print "Month: $month\n";
			print "Day: $day\n";
			print "Hour: $hour\n";
			print "Agent: $agent\n";
			print "Logfile: $logfile\n";
			print "Host: $host\n";
			print "Rule \#: $rule_number\n";
			print "Level: $level\n";
			print "Description: $description\n";
			print "Source IP: $src_ip\n";
			print "User: $user\n";
			print "-------------------------\n";
			print "\n";
		}
		($count, $code, $year, $month, $day, $hour, $agent, $logfile, $host, $rule_number, $level, $description, $src_ip, $user, $date) = 0;
	}
	if (!$count)
	{
		if (!$line)
		{
			next;
		}
		if (grep(/\*\*/, $line))
		{
			($trash, $trash, $code) = split(/ /, $line);
			$code =~ s/[^0-9a-z-_\.]//g;
			$count = 1;
			next;
		}
	}
	if ($count == 1)
	{
		if (grep(/\(/, $line))
		{
			($year, $month, $day, $hour, $agent, $host) = split(/ /, $line);
			($host, $logfile) = split(/\-/, $host);
                        $agent =~ s/[^0-9a-z-_\.]//g;
			$logfile =~ s/\>//g;
		}
		else
		{
                        ($year, $month, $day, $hour, $logfile) = split(/ /, $line);
			$host = "localhost";
                }
		$count = 2;
		next;
	}
	if ($count == 2)
	{
		($trash, $rule_number, $trash, $level, $description) = split(/ /, $line);
		$level =~ s/[^0-9a-z-_\.]//g;
		$count = 3;
		next;
	}
        if ($count == 3)
        {
		($trash, $trash, $src_ip) = split(/ /, $line);                
                $src_ip =~ s/[^0-9a-z-_\.]//g;
                $count = 4;
		next;
        }
        if ($count == 4)
        {
		($trash, $user) = split(/ /, $line);                
		$user =~ s/[^0-9a-z-_\.]//g;
                $count = 5;
                next;
        }
        if ($count == 5)
        {
                $description = $line;
                $count = 6;
                next;
        }
}
if ($par{show_screen})
{
	if ($records > 0)
	{
		print "Added $records new line(s) to database\n";
	}
	else
	{
		print "No new records\n";
	}
}

# ---------------------------------------------------------------------------
# Disconnect dbh and exit
# ---------------------------------------------------------------------------

undef @lines;
$sth->finish;
$dbh->disconnect;
exit;

# ---------------------------------------------------------------------------
# Libraries
# ---------------------------------------------------------------------------

sub today
{
	($today{second}, $today{minute}, $today{hour}, $today{day}, $today{month}, $today{year}, $trash) = localtime(time);
	$today{month}++;
	if ($today{month} == 1)
	{
		$txt_month = "Jan";
	}
        if ($today{month} == 2)
        {
                $txt_month = "Feb";
        }
        if ($today{month} == 3)
        {
                $txt_month = "Mar";
        }
        if ($today{month} == 4)
        {
                $txt_month = "Apr";
        }
        if ($today{month} == 5)
        {
                $txt_month = "May";
        }
        if ($today{month} == 6)
        {
                $txt_month = "Jun";
        }
        if ($today{month} == 7)
        {
                $txt_month = "Jul";
        }
        if ($today{month} == 8)
        {
                $txt_month = "Aug";
        }
        if ($today{month} == 9)
        {
                $txt_month = "Sep";
        }
        if ($today{month} == 10)
        {
                $txt_month = "Oct";
        }
        if ($today{month} == 11)
        {
                $txt_month = "Nov";
        }
        if ($today{month} == 12)
        {
                $txt_month = "Dec";
        }
	$today{day} = sprintf("%02d", $today{day});
	$today{month} = sprintf("%02d", $today{month});
	$today{year} = sprintf("%04d", $today{year} + 1900);
	$today{hour} = sprintf("%02d", $today{hour});
	$today{minute} = sprintf("%02d", $today{minute});
	$today{second} = sprintf("%02d", $today{second});
}
sub month_number
{
        if ($txt_month eq "Jan")
        {
                $month_number = 1;
        }
        if ($txt_month eq "Feb")
        {
                $month_number = 2;
        }
        if ($txt_month eq "Mar")
        {
                $month_number = 3;
        }
        if ($txt_month eq "Apr")
        {
                $month_number = 4;
        }
        if ($txt_month eq "May")
        {
                $month_number = 5;
        }
        if ($txt_month eq "Jun")
        {
                $month_number = 6;
        }
        if ($txt_month eq "Jul")
        {
                $month_number = 7;
        }
        if ($txt_month eq "Aug")
        {
                $month_number = 8;
        }
        if ($txt_month eq "Sep")
        {
                $month_number = 9;
        }
        if ($txt_month eq "Oct")
        {
                $month_number = 10;
        }
        if ($txt_month eq "Nov")
        {
                $month_number = 11;
        }
        if ($txt_month eq "Dec")
        {
                $month_number = 12;
        }
}
