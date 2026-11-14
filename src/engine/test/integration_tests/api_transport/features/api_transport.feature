Feature: Answers the engine API server gives before any endpoint handler runs
    As a client of the engine API
    I want the server's own answers reported as errors
    So that an unknown path or a body over the limit is never read as an endpoint's response

    Background:
        Given the engine is running

    Scenario: A path the engine does not serve is reported as a 404 error
        When I send a request to a path the engine does not serve
        Then the client reports the error "Error 404: Unknown endpoint"
        And the engine still answers its status

    Scenario: A body over the metrics routes' limit is reported with the server's 413 text
        # The metrics routes take at most 4 KiB, whatever analysisd.server_api_payload_max_bytes says.
        When I send a metrics request whose name is 5000 bytes long
        Then the client reports the error "Payload too large. Max allowed: 4096 bytes (4 KiB)."
        And the engine still answers its status
