Feature: Manage Geolocation Databases
    As a user of the Wazuh geo manager API
    I want to be able to add, delete, list, and remotely upsert geolocation databases
    So that I can manage databases effectively in the system

    Background:
        Given the engine is running with an empty geo manager

    Scenario: Add a new geolocation database
        Given an existing db file "testdb-city.mmdb"
        When I send a request to add a database with path to "testdb-city.mmdb" and type "city"
        Then the response should be a "success"
        And the database list "should" include "testdb-city.mmdb"

    Scenario: Attempt to add a database with invalid path
        Given a non-existent db file "nonexistent.mmdb"
        When I send a request to add a database with path to "nonexistent.mmdb" and type "city"
        Then the response should be a "failure"
        And the error message "Cannot add database '{nonexistent.mmdb}': Error opening the specified MaxMind DB file" is returned

    Scenario: Attempt to add a database with an invalid type
        Given an existing db file "testdb-city.mmdb"
        When I send a request to add a database with path to "testdb-city.mmdb" and type "invalid"
        Then the response should be a "failure"
        And the error message "Invalid geo::Type name string 'invalid'" is returned

    Scenario: Delete an existing database
        Given an existing db file "testdb-city.mmdb"
        And the database "testdb-city.mmdb" for type "asn" is already added to the geo manager
        When I send a delete request for the path to "testdb-city.mmdb"
        Then the response should be a "success"
        And the database list "should not" include "testdb-city.mmdb"

    Scenario: Attempt to delete a non-existent database
        When I send a delete request for the path to "testdb-city.mmdb"
        Then the response should be a "failure"
        And the error message "Database 'testdb-city.mmdb' not found" is returned

    Scenario: List all databases
        Given an existing db file "testdb-asn.mmdb"
        And an existing db file "testdb-city.mmdb"
        And the database "testdb-asn.mmdb" for type "asn" is already added to the geo manager
        And the database "testdb-city.mmdb" for type "city" is already added to the geo manager
        When I send a request to list all databases
        Then the response should be a "success"
        Then the response should include "testdb-asn.mmdb"
        And the response should include "testdb-city.mmdb"

    Scenario: Remotely upsert a geolocation database
        When I send a request to remotely upsert a database with path to "testdb-city.mmdb", type "city", db url "https://github.com/wazuh/wazuh/raw/main/src/engine/test/integration_tests/geo/data/base.mmdb" and hash url "https://github.com/wazuh/wazuh/raw/main/src/engine/test/integration_tests/geo/data/base.md5"
        Then the response should be a "success"
        And the database list "should" include "testdb-city.mmdb"

    Scenario: Added db persists after restart
        Given an existing db file "testdb-city.mmdb"
        When I send a request to add a database with path to "testdb-city.mmdb" and type "city"
        Then the response should be a "success"
        When I restart the engine
        Then the database list "should" include "testdb-city.mmdb"

    Scenario: Remotely added db persists after restart
        When I send a request to remotely upsert a database with path to "testdb-city.mmdb", type "city", db url "https://github.com/wazuh/wazuh/raw/main/src/engine/test/integration_tests/geo/data/base.mmdb" and hash url "https://github.com/wazuh/wazuh/raw/main/src/engine/test/integration_tests/geo/data/base.md5"
        Then the response should be a "success"
        When I restart the engine
        Then the database list "should" include "testdb-city.mmdb"
