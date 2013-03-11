#!/usr/bin/perl -w
# by Meir Michanie
# GPL licensed
# meirm@riunx.com
my $VERSION="0.1";
use strict;
&help() unless @ARGV;
if ($ARGV[0]=~ m/^-h$|^--help$/i){
	&help();
}
&help unless $ARGV[0]=~ m/^-r$|^--report$|^-s$|^--summary$|^-t$|^--top$/;
my (@argv) = ();
while (@ARGV){
	push @argv, shift @ARGV;
}

my $newrecord=0;
my %stats;
my ($timestamp,$sec,$mail,$date,$alerthost,$datasource,$rule,$level,$description,
$srcip,$user,$text);
while(<>){
	if (m/^$/){
		$newrecord=1;
		$stats{$alerthost}{mail}{$mail}++;
		$stats{$alerthost}{alerthost}{$alerthost}++;
		$stats{$alerthost}{datasource}{$datasource}++;
		$stats{$alerthost}{rule}{$rule}++;
		$stats{$alerthost}{level}{$level}++;
		$stats{$alerthost}{description}{$description}++;
		if (defined $srcip) { $stats{$alerthost}{srcip}{$srcip}++; }
		if (defined $user)  { $stats{$alerthost}{user}{$user}++; }
		next ;
	}
	if (m/^\*\* Alert ([0-9]+).([0-9]+):(.*)$/){
		$timestamp=$1;
		$sec=$2;
		$mail=$3;
	}elsif ( m/^([0-9]+\s\w+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+)\s(.*?)->(.*)$/){
		$date=$1;
		$alerthost=$2;
		$datasource=$3;
	}elsif ( m/^([0-9]+\s\w+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+)\s(.*?)$/){
                $date=$1;
                $alerthost='none';
                $datasource=$2;
	}elsif ( m/Rule: ([0-9]+) \(level ([0-9]+)\) -> (.*)$/ ){
		$rule=$1;
		$level=$2;
		$description= $3;
	}elsif ( m/Src IP: (.*)$/){
                $srcip=$1;
	}elsif ( m/User: (.*)$/){
                $user=$1;
        }elsif( m/(.*)$/){
		$text=$1;
	}
		

}
if ($argv[0]=~ m/^-r$|^--report$/i){
	&report(\%stats);
}elsif ($argv[0]=~ m/^-s$|^--summary$/){
	&summary(\%stats);
}elsif ($argv[0]=~ m/^-t$|^--top$/){
	$argv[1]= $argv[1] ? $argv[1] : 'srcip' ;
	&top(\%stats,$argv[1]);
}else{
	&help();
}

sub printversion(){
	print "OSSEC report tool $VERSION\n";
	print "Licensed under GPL\n";
	print "Contributor Meir Michanie\n";
}

sub help(){
	&printversion();
	print "$0 [-h|--help] # This text you read now\n";
	print "$0 [-r|--report] # prints a report for each element\n";
	print "$0 [-s|--summary] # prints a summary report\n";
	print "$0 [-t|--top] <field> #prints the top list\n";
	print "\nHow To:\n";
	print   "=======\n";
	print "$0\tOSSEC report tool $VERSION\n";
	print "  $0 is a GNU style program.\nIt reads from STDIN and write to stdout. ";
	print "This gives you the advantage to use it in pipes.\n";
	print "i.e.\n";
	print " cat ossec-alerts-05.log | $0 -r | mail root -s 'OSSEC detailed report'\n";
	print " cat ossec-alerts-05.log | $0 -s | mail root -s 'OSSEC summary report'\n";
	print " cat ossec-alerts-05.log | $0 -t srcip |  head -n 15 | mail root -s 'OSSEC top 15 offenders report'\n";
	print " Crontab entry:\n";
	print "58 23 * * * (cat ossec-alerts-05.log | $0 -s)\n";
	exit 0;
}

sub report(){
	my ($statref)=@_;
my ($stat,$key,$value);
format TOPREPORT =
=============================================================================
|		Summary report                  			    |
=============================================================================
|Alerthost | Stat       | Key					    | Count |
=============================================================================
.
$~='TOPREPORT';
write; 
format REPORT =
|@<<<<<<<<<<|@<<<<<<<<<<<|@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<|@######|
$alerthost,$stat,$key,$value
.
$~='REPORT';
foreach(sort keys %{$statref}){
	$alerthost=$_;
	foreach(sort keys %{${$statref}{$alerthost}}){
		$stat=$_;
		foreach(sort keys %{${$statref}{$alerthost}{$stat}}){
			$key=$_;
			$value=${$statref}{$alerthost}{$stat}{$key};
			write;
		}
	}
}
}

sub summary(){	
my ($statref)=@_;
my (%totals);
my ($stat,$key,$value);
foreach(sort keys %{$statref}){
	$alerthost=$_;
	foreach(sort keys %{${$statref}{$alerthost}}){
		$stat=$_;
		foreach(sort keys %{${$statref}{$alerthost}{$stat}}){
			$key=$_;
			$value=${$statref}{$alerthost}{$stat}{$key};
			$totals{$stat}{$key}+=$value;
		}
	}
}
format TOPSUMREPORT =
=================================================================
|		Statistic report                  		|
=================================================================
|Stat        | Key					| Count |
=================================================================
.
$~='TOPSUMREPORT';
write; 
format SUMREPORT =
|@<<<<<<<<<<<|@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<|@######|
$stat,$key,$value
.
$~='SUMREPORT';
foreach(sort keys %totals){
			$stat=$_;
			foreach(sort keys %{$totals{$stat}}){
	                        $key=$_;
        	                $value=$totals{$stat}{$key};
			write;
	}
}
}

sub top(){
my ($statref,$stat)=@_;
my (%totals,%mytest);
my ($key,$value);
foreach(keys %{$statref}){
        $alerthost=$_;
                foreach( keys %{${$statref}{$alerthost}{$stat}}){
                        $key=$_;
                        $value=${$statref}{$alerthost}{$stat}{$key};
                        $totals{$stat}{$key}+=$value;
                }
}
foreach (keys %{$totals{$stat}}){
	$mytest{$totals{$stat}{$_}}=$_;
}; 
foreach (sort {$b <=> $a}  keys %mytest){
	print "$mytest{$_} => $_\n";
}
}
