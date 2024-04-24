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
    test_map         => 'map',
    test_str1        => 'utf8_string',
    test_str2        => 'utf8_string',
    test_uint32      => 'uint32',
    test_double      => 'double',
    test_float       => 'float',
    test_bytes       => 'bytes',
    test_uint16      => 'uint16',
    test_uint64      => 'uint64',
    test_uint128     => 'uint128',
    test_boolean     => 'boolean',
    test_array        => [ 'array', 'utf8_string' ],
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
        test_map  => { test_str1 => 'Wazuh', test_str2 => 'Wazuh2' },
        test_uint32 => 94043,
        test_double => 37.386,
        test_float => 122.0838,
        test_bytes => pack( 'H*', 'abcd' ),
        test_uint16 => 123,
        test_uint64 => 1234567890,
        test_uint128 => 12345678901234567890,
        test_boolean => 1,
        test_array => [ 'a', 'b', 'c' ],
    },
    '1.2.3.5/32' => {
        test_map  => { test_str1 => 'Missing values'},
    },
);

for my $network ( keys %address_for_test ) {
    $tree->insert_network( $network, $address_for_test{$network} );
}

# Write the database to disk.
open my $fh, '>:raw', $filename;
$tree->write_tree( $fh );
close $fh;

say "$filename has now been created";
