Feature: Engine status / readiness endpoint
    As an operator of the Wazuh engine
    I want to query GET /status
    So that I can know whether the engine is ready to process events

    Background:
        Given the engine is running

    Scenario: Status endpoint is reachable over GET
        # This scenario guards against a method mismatch between the Python client
        # (which sends GET /status) and the server route registration.
        When I request the engine status
        Then the status response should be a "success"

    Scenario: Status response exposes the readiness contract
        When I request the engine status
        Then the status response should be a "success"
        And the status response should contain a boolean "ready" field
        And the status response should contain the "spaces", "ioc" and "geo" sections

    Scenario: Every reported space exposes all required fields
        When I request the engine status
        Then the status response should be a "success"
        And every "spaces" entry should expose the space fields

    Scenario: Every reported IOC database exposes all required fields
        When I request the engine status
        Then the status response should be a "success"
        And every "ioc" entry should expose the resource fields

    Scenario: Every reported geo database exposes all required fields
        When I request the engine status
        Then the status response should be a "success"
        And every "geo" entry should expose the resource fields

    Scenario: Reported status values are within the allowed set
        When I request the engine status
        Then the status response should be a "success"
        And every reported "status" value should be one of "ready", "updating" or "failed"

    Scenario: Reported timestamps are valid unix timestamps
        When I request the engine status
        Then the status response should be a "success"
        And every "last_successful_update" should be a non-negative integer

    Scenario: Geo section reports the city and asn databases
        When I request the engine status
        Then the status response should be a "success"
        And the "geo" section should contain the keys "city" and "asn"

    Scenario: Spaces section reports the default standard and custom spaces
        When I request the engine status
        Then the status response should be a "success"
        And the "spaces" section should contain the keys "standard" and "custom"

    Scenario: IOC section reports exactly the supported databases
        When I request the engine status
        Then the status response should be a "success"
        And the "ioc" section keys should be exactly "connection, url_domain, url_full, hash_md5, hash_sha1, hash_sha256"

    Scenario: Geo section reports exactly city and asn
        When I request the engine status
        Then the status response should be a "success"
        And the "geo" section keys should be exactly "city, asn"

    Scenario: Only spaces expose the enabled flag
        When I request the engine status
        Then the status response should be a "success"
        And only "spaces" entries expose the "enabled" field

    Scenario: Global readiness is consistent with per-resource availability
        # ready must be true only when all enabled spaces, all IOC and all geo are available.
        When I request the engine status
        Then the status response should be a "success"
        And the "ready" flag should match the per-resource availability

    Scenario: Status can be queried repeatedly without changing state
        When I request the engine status
        And I request the engine status again
        Then both status responses should be a "success"
        And both status responses should report the same "ready" value
        And both status responses should report the same resource keys
