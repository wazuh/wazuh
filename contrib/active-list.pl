#!/usr/bin/perl
#
# OSSEC active-response script to store a suspicious IP address in a MySQL table.
#
# Available actions are:
#	'add'	 - Create a new record in the MySQL DB
#	'delete' - Remove a existing record 
#
# History
# -------
# 2010/10/24	xavir@rootshell.be	Created
#

use strict;
use warnings;
use DBI;

# -----------------------
# DB access configuration
# -----------------------
my $db_name  = 'ossec_active_lists';
my $db_user  = 'suspicious';
my $db_pass  = 'xxxxxxxxxx';

my ($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek, $dayOfYear, $daylightSavings) = localtime();
my $theTime  = sprintf("%d-%02d-%02d %02d:%02d:%02d", 
	$yearOffset+1900, $month+1, $dayOfMonth, $hour, $minute, $second);

my $nArgs = $#ARGV + 1;
if ($nArgs != 5) {
	print STDERR "Usage: active-list.pl <action> <username> <ip>\n";
	exit 1;
}

my $action	= $ARGV[0];
my $ipAddr	= $ARGV[2];
my $alertId	= $ARGV[3];
my $ruleId	= $ARGV[4];

if ($action ne "add" && $action ne "delete") {
	WriteLog("Invalid action: $action\n");
	exit 1;
}

if ($ipAddr =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)/) {
	if ($1 > 255 || $2 > 255 || $3 > 255 || $4 > 255) {
		WriteLog("Invalid IP address: $ipAddr\n");
		exit 1;
	}
}
else {
	WriteLog("Invalid IP address: $ipAddr\n");
}

WriteLog("active-list.pl $action $ipAddr $alertId $ruleId\n");

my $dbh = DBI->connect('DBI:mysql:' .  $db_name, $db_user, $db_pass) || \
	die "Could not connect to database: $DBI::errstr";

if ( $action eq "add" ) {
	my $sth = $dbh->prepare('SELECT ip FROM ip_addresses WHERE ip = "' . $ipAddr . '"');
	$sth->execute();
	my $result = $sth->fetchrow_hashref();
	if (!$result->{ip}) {
		$sth = $dbh->prepare('INSERT INTO ip_addresses VALUES ("' . $ipAddr . '","'. $theTime . '",' . $alertId . ',' . $ruleId . ',"Added by suspicious-ip Perl Script")');
		if (!$sth->execute) {
			WriteLog("Cannot insert new IP address: $DBI::errstr\n");
		}
	}
	else {
		$sth = $dbh->prepare('UPDATE ip_addresses SET timestamp = "' . $theTime . '", alertid = ' . $alertId . ', ruleid = ' . $ruleId . ' WHERE ip = "' . $ipAddr . '"');
		if (!$sth->execute) {
			WriteLog("Cannot update IP address: $DBI::errstr\n");
		}
	}
} 
else {
	my $sth = $dbh->prepare('DELETE FROM ip_addresses WHERE ip = "' . $ipAddr . '"');
	if (!$sth->execute) {
		WriteLog("Cannot remove IP address: $DBI::errstr\n");
	}
}

$dbh->disconnect;
exit 0;

sub WriteLog
{
	if ( $_[0] eq "" ) { return; }

	my $pwd  = `pwd`;
	chomp($pwd);
	my $date = `date`;
	chomp($date);

	open(LOGH, ">>" . $pwd . "/../active-responses.log") || die "Cannot open log file.";
	print LOGH $date . " " . $_[0];
	close(LOGH);
	return;
}
