Feature: Tester API Management

  @wip
  Scenario: Add a repeated session for testing via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to the tester to add a new session called "test" with the data from policy:"policy/wazuh/0"
    Then I should receive a failture response indicating that "Error creating session: The name of the testing environment already exist"

  Scenario: Add a new session for testing via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to the tester to add a new session called "test1" with the data from policy:"policy/wazuh/0"
    Then I should receive a success response

  Scenario: Get all sessions via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to the tester to add 5 sessions called "dummy" with policy "policy/wazuh/0"
    And I send a request to the tester to get all sessions
    Then I should receive a size list of 5

  Scenario: Get specific session via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to the tester to add 5 sessions called "dummy" with policy "policy/wazuh/0"
    And I send a request to the tester to get the session "dummy1"
    Then I should receive a session with name "dummy1"

  Scenario: Remove specific session via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to the tester to add 5 sessions called "dummy" with policy "policy/wazuh/0"
    And I send a request to the tester to delete the session "dummy1"
    Then I should receive a size list of 4

  Scenario: Change sync of specific session via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to the policy "policy/wazuh/0" to add an integration called "integration/other-wazuh-core-test/0"
    And I send a request to get the session "test"
    Then I should receive a session with sync "OUTDATED"
    And I send a request to the tester to rebuild the "test" session and the sync change to "UPDATED" again

  Scenario: Send events to specific session without debug session via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to send the event "hi! i am an event test!" from "test" session without debug level
    Then I should receive the next output: "{"output": {"event": {"original": "hi! i am an event test!"}, "wazuh": {"location": "any", "queue": 49.0}}}"

  Scenario: Send events to specific session with low debug via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to send the event "hi! i am an event test!" from "test" session with "ASSET_ONLY" debug "system" namespace and "decoder/test-message/0" asset trace
    Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/test-message/0","success":true}],"output":{"event":{"original":"hi! i am an event test!"},"wazuh":{"location":"any","queue":49.0}}}"

  Scenario: Send events to specific session with high debug via API
    Given I want create a session called "test" with a policy "policy/wazuh/0"
    When I send a request to send the event "hi! i am an event test!" from "test" session with "ALL" debug "system" namespace and "decoder/test-message/0" asset trace
    Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/test-message/0","success":true}],"output":{"event":{"original":"hi! i am an event test!"},"wazuh":{"location":"any","queue":49.0}}}"
