Feature: Query Geolocation Databases
    As a user of the Wazuh geo manager API
    I want to be able to list databases and query IP addresses
    So that I can retrieve geolocation information

    Background:
        Given the engine is running with geo manager

    Scenario: List all databases
        When I send a request to list all databases
        Then the response should be a "success"
        And the response should contain a list of databases

    Scenario: Query IP address with both CITY and ASN data
        When I query the IP address "1.2.3.4"
        Then the response should be a "success"
        And the response should contain "geo" data
        And the response should contain "as" data

    Scenario: Query IP address with only CITY data
        When I query the IP address "1.2.3.4"
        Then the response should be a "success"
        And the response should contain "geo" data
        And the response should contain empty "as" data

    Scenario: Query IP address with empty IP
        When I query the IP address "<empty>"
        Then the response should be a "failure"
        And the error message should contain "IP cannot be empty"

    Scenario: Query IP address not in databases
        When I query the IP address "127.0.0.1"
        Then the response should be a "success"
        And the response should contain empty "geo" data
        And the response should contain empty "as" data
