#!perl
# Script for creating a test MaxMind DB file.
# Dependencies: MaxMind::DB::Writer (cpan)

use strict;
use warnings;
use feature qw( say );

use MaxMind::DB::Writer::Tree;

my $filename = 'testdb.mmdb';

# Your top level data structure will always be a map (hash).  The MMDB format
# is strongly typed.
# See https://metacpan.org/pod/MaxMind::DB::Writer::Tree#DATA-TYPES
my %types = (
    city         => 'map',
    name         => 'map',
    en           => 'utf8_string',
    continent    => 'map',
    names        => 'map',
    code         => 'utf8_string',
    country      => 'map',
    iso_code     => 'utf8_string',
    location     => 'map',
    latitude     => 'double',
    longitude    => 'double',
    time_zone    => 'utf8_string',
    postal       => 'map',
    autonomous_system_number => 'uint32',
    autonomous_system_organization => 'utf8_string',
);

my $tree = MaxMind::DB::Writer::Tree->new(

    # Arbitrary string describing the database.
    database_type => 'My-IP-Data',

    # "description" is a hashref where the keys are language names and the
    # values are descriptions of the database in that language.
    description =>
        { en => 'Test database', es => "Base de datos de prueba", },

    # "ip_version" can be either 4 or 6
    ip_version => 4,

    # add a callback to validate data going in to the database
    map_key_type_callback => sub { $types{ $_[0] } },

    # "record_size" is the record size in bits.  Either 24, 28 or 32.
    record_size => 24,
);

my %address_for_test = (
    '1.2.3.4/32' => {
        city  => { names => {en => 'Wazuh city' }},
        continent  => {code => 'WC', names => {en => 'Wazuh Continent' }},
        country  => {iso_code => 'WCtry', names => {en => 'Wazuh Country' }},
        location  => {latitude => 41.7776, longitude => 88.4293, time_zone => 'Wazuh/Timezone'},
        postal  => {code => '7777'},
        autonomous_system_number => 1234,
        autonomous_system_organization => 'Wazuh Organization',
    }
);

for my $network ( keys %address_for_test ) {
    $tree->insert_network( $network, $address_for_test{$network} );
}

# Write the database to disk.
open my $fh, '>:raw', $filename;
$tree->write_tree( $fh );
close $fh;

say "$filename has now been created";
