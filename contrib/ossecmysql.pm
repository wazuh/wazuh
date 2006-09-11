use DBI;
use strict;
package ossecmysql;

sub new(){
	my $type = shift;
	my %conf=@_;
	my $self={};
	my $flag;
	$self->{database}=$conf{database};
	$self->{dbhost}=$conf{dbhost};
	$self->{dbport}=$conf{dbport};
	$self->{dbuser}=$conf{dbuser};
	$self->{dbpasswd}=$conf{dbpasswd};

	$self->{dsn} = "DBI:mysql:database=$self->{database};host=$self->{dbhost};port=$self->{dbport}";
        $self->{dbh} = DBI->connect($self->{dsn}, $self->{dbuser},$self->{dbpasswd});
	bless $self, $type;
}
sub fetchrecord(){
	my $self= shift ;
	my ($rows)=@_;
	my ($pointer,$numrows,$fields)=(${$rows}[0],${$rows}[1],${$rows}[2]);
	my @result;
	return if $pointer == $numrows;
	for (my $i=0; $i <  $fields; $i ++){
	 my $field=  @{$rows}[($pointer * $fields) + 3 + $i ];
	 push (@result, $field);
	}
	${$rows}[0] ++;
	
	return @result;
}
sub fetchrows(){
	my $self = shift ;
	my ($query)=shift;
	my @params= @_;
        my @rows;
        my $numFields;
        my $numRows;
        $numRows=$numFields=0;
        $self->{sth}=$self->{dbh}->prepare($query);
        $self->{sth}->execute(@params) ;
        $numRows = $self->{sth}->rows;
        my @row=();
	return @rows unless $numRows>0;
        $numFields = $self->{sth}->{'NUM_OF_FIELDS'};
	push (@rows,0,$numRows,$numFields);
	while(@row=$self->{sth}->fetchrow_array){
                push (@rows,@row);
        }

        $self->{sth}->finish;
        return @rows;
	
}

sub execute(){
	my $self = shift ;
	my $flag;
	my ($query)=shift;
	my @params= @_;
        my @rows= ();
        my $numFields;
        my $numRows;
        $numRows=$numFields=0;
        $self->{sth} = $self->{dbh}->prepare($query);
        return $self->{sth}->execute(@params) ;
}

sub lastid(){
	my $self = shift ;
	return $self->{sth}->{mysql_insertid};
}
1
