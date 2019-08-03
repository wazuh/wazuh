#!/usr/bin/env perl
#######################################
# Name:    ossec-add-ung.pl
# Desc:    Add ossec users and groups on OSX using the NetInfo cmds
# Author:  Chuck L.
# License: GPL
# Copyright (C) 2015-2019, Wazuh Inc.
###
# for vi: set tabstop=4
#######################################

# Variables and whatnot
my ($debug, $oUid, $oGid, @inUseUids, @inUseGids, $rev, $revDate, $USER, $USER_MAIL, $USER_REM, $INSTYPE, @NEWUSERS);
$rev     = '0.2-1';
$revDate = '30-Aug-2006';
$debug   = '0';
$fName   = "/tmp/niusers.tmp";
$USER=$ARGV[0];
$USER_MAIL=$ARGV[1];
$USER_REM=$ARGV[2];
$INSTYPE=$ARGV[3];
@NEWUSERS=($USER);

# Commands
$NILOAD  = "/usr/bin/niload";
$NIRPT   = "/usr/bin/nireport";
$NIUTIL  = "/usr/bin/niutil";
$SORT    = "/usr/bin/sort";
$GREP    = "/usr/bin/grep";
$SUDO    = "/usr/bin/sudo";

# Subroutine calls
findUsersGroups();
createUsersGroups();

sub findUsersGroups {
    @inUseUids = `$NIRPT . /users uid | $GREP "^5[0-9][0-9]" | $SORT -ru`;
    @inUseGids = `$NIRPT . /groups gid | $GREP "^5[0-9][0-9]" | $SORT -ru`;

    foreach (@inUseUids) {
        chomp();
        print "In use UID: $_\n" if $debug;
        if ($oUid < $_) {
            $oUid = $_;
        }
    }
    $oUid++;
    print "Next available UID: $oUid\n" if $debug;

    foreach (@inUseGids) {
        chomp();
        print "In use GID: $_\n" if $debug;
        if ($oGid < $_) {
            $oGid = $_;
        }
    }
    $oGid++;
    print "Next available GID: $oGid\n" if $debug;
} # end sub

sub createUsersGroups {
    print "Sub - UID is: $oUid\n" if $debug;
    print "Sub - GID is: $oGid\n" if $debug;

    if ($INSTYPE eq "server") {
        push @NEWUSERS, $USER_MAIL;
        push @NEWUSERS, $USER_REM;
    } elsif ($INSTYPE eq "local") {
        push @NEWUSERS, $USER_MAIL;
    }

    $niPid = open (NIFH, "| $SUDO $NILOAD -v group /");
    print "Adding ossec group\n" if $debug;
    print NIFH "ossec:*:" . $oGid . ":" . join(',', @NEWUSERS) . "\n";
    close (NIFH);

    $fh = open (NITMP, ">$fName") or die "Unable to create temp file: $!\n";

    print "Adding ossec users\n" if $debug;
    foreach(@NEWUSERS){
        print NITMP $_ . ":*:" . $oUid . ":" . $oGid . "::0:0:" . $_ . " acct:/var/ossec:/sbin/nologin\n";
        $oUid++;
    }

    close ($fh);
    $rtnVal = system("$SUDO $NILOAD -v passwd / < $fName");
    print "Return value from syscmd: $rtnVal\n" if $debug;
    unlink ($fName);

} # end sub
