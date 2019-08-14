#!/usr/bin/perl

# Copyright (C) 2015-2019, Wazuh Inc.

use strict;
use warnings;

if (@ARGV < 2) {
    die "$0 file error_msg\n";
}

my ($prog, $file,$msg) = (@ARGV);

open(FILE,$file) || die "Error opening file: $file\n";

if (! -f $prog) {
    die "File $prog not present\n";
}

while(<FILE>) {
    my $line = $_;
    print "running: $prog $line\n";
    my $result =  `$prog $line`;
    if ($result =~ /$msg/) {
        print $result;
        print "\t ** $line **\n";
        <STDIN>;
    } else {
        print $result;
    }
}

