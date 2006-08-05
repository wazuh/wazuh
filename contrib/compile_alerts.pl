#!/usr/bin/perl -w
use strict;
# Contrib by Meir Michanie
# meirm at riunx.com
# Licensed under GPL
my $VERSION='0.1';
my $ossec_path='/var/ossec';
my $rules_config="$ossec_path/etc/rules_config.xml";
my $usersignatures_path="$ossec_path/user_signatures";
my $signatures_path="$ossec_path/signatures";
while ( @ARGV) {
	$_=shift @ARGV;
	if (m/^-u$|^--user-signatures$/) {
		$usersignatures_path= shift @ARGV;
		&help() unless -d $usersignatures_path;
	}elsif (m/^-s$|^--signatures$/){
		$signatures_path= shift @ARGV;
		&help() unless -d $signatures_path;
	}elsif (m/^-c$|^--rules_config$/){
                $rules_config= shift @ARGV;
                &help() unless -f $rules_config;
        }elsif (m/^-h$|^--help$/){
		&help;
	}
}
print STDERR "Adding $rules_config\n";
my @rules_files=($rules_config);
opendir (USERDEFINED , "$usersignatures_path") || die ("Could not open dir $usersignatures_path\n");
my @temparray=();
while ($_ = readdir(USERDEFINED)){
	chomp; 
	next unless  -f "$usersignatures_path/$_";
	print STDERR "Adding $usersignatures_path/$_\n";
	push @temparray, "$usersignatures_path/$_";
}
close (USERDEFINED);
push @rules_files , sort (@temparray);

@temparray=();
opendir(RULES,"$signatures_path") || die ("Could not open dir $signatures_path\n");
while ($_ = readdir(RULES)){
	chomp;
	next unless  -f "$signatures_path/$_";
	print STDERR "Adding $signatures_path/$_\n";
        push @temparray, "$signatures_path/$_";
}
close (RULES);
push @rules_files , sort (@temparray);
map { print STDERR "processing: $_\n";} @rules_files;
foreach (@rules_files){
	open (RFILE, "$_") ||die ("Could not open file $_");
	my @content=<RFILE>;
	close (RFILE);
	print  join ('',@content);
}

sub help(){
	print STDERR "$0\nRules compilation tool for OSSEC \n";
	print "This tool facilitates the building of monolitic rules file to be included in ossec.xml.\n"
	. "You only need one rules include entry in ossec.xml\n"
	. "<rules>\n"
	. "\t<include>ossec_rules.xml</include>"
 	."</rules>"

	. "$0 will print to STDOUT the result of the mixing.\n"
	. "If no parameter are passed then the application will use the default locations.\n"
	. "Default values:\n"
	. "--user-signatures -> $usersignatures_path\n"
	. "--signatures -> $signatures_path\n"
	. "--rules-config -> $rules_config\n"
	. "Compiling rules allows us to generate multiple configurations and even facilitate the upgrade of them.\n"
	. "By instance, you can make a directory with symbolic links to rules you want to use without altering the standard repository.\n"
	. "There are more examples of situation where you can use a subset of the rules repository\n"
	. "I invite someone to reword this explanation.\n";
	
	print STDERR "\n\nUsage:\n";
	print STDERR "$0  [-u|--user-signatures] <user-signatures-dir> [-s|--signatures] <signatures-dir>\n"
	."\n\nBUGS:\n"
	. "I just wanted to deliver version one.\n"
	. "I will change the script to read the directory sorted, so you can link signatures with names that would emulate the behavios of the sysV system.\n";
	
	exit;
}
