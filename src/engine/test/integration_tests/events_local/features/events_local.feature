Feature: Local Events Endpoint

  Scenario: Single manager event accepted
    When I send a local event with header and one event
    Then the response status should be 200

  Scenario: Multiple manager events accepted
    When I send a local event with header and two events
    Then the response status should be 200

  Scenario: Malformed body rejected
    When I send a local event with invalid body
    Then the response status should be 400

  Scenario: Missing header rejected
    When I send a local event without header line
    Then the response status should be 400

  Scenario: Empty body rejected
    When I send a local event with empty body
    Then the response status should be 400
