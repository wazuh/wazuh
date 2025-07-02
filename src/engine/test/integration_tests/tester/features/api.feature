Feature: Tester API Management

  @wip
  Scenario: Add a repeated session for testing via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to the tester to add a new session called "default" with the data from policy:"policy/wazuh/0"
    Then I should receive a failture response indicating that "The name of the testing environment already exist"

  Scenario: Add a new session for testing via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to the tester to add a new session called "test1" with the data from policy:"policy/wazuh/0"
    Then I should receive a success response

  Scenario: Remove specific session via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to the tester to add 5 sessions called "dummy" with policy "policy/wazuh/0"
    And I send a request to the tester to delete the session "default"
    And I send a request to the tester to delete the session "dummy1"
    Then I should receive a size list of 4

  Scenario: Remove a non-existent session via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to the tester to delete the session "non-existent"
    Then I should receive a failture response indicating that "The testing environment not exist"

  Scenario: Get all sessions via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to the tester to add 5 sessions called "dummy" with policy "policy/wazuh/0"
    Then I should receive a size list of 6

  Scenario: Get specific session via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to the tester to get the session "default"
    Then I should receive a session with name "default"

  Scenario: Change sync to OUTDATED of specific session via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to the policy "policy/wazuh/0" to add an integration called "other-wazuh-core-test"
    And I send a request to the tester to get the session "default"
    Then I should receive a session with sync "OUTDATED"
    And I send a request to the tester to reload the "default" session and the sync change to "UPDATED" again

  Scenario: Change sync to ERROR of specific session via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "policy/wazuh/0"
    When I send a request to delete the policy "policy/wazuh/0"
    And I send a request to the tester to get the session "default"
    Then I should receive a session with sync "ERROR"
    And I send a request to the tester to reload the "default"
    And I should receive an error response

  Scenario: Send events to specific session without debug session via API
    Given I have a policy "policy/wazuh/0" that has an integration called "other-wazuh-core-test" loaded
    And I create a "test" session that points to policy "policy/wazuh/0"
    When I send a request to send the event "hi! i am an event test!" from "test" session with "NONE" debug "system" namespace, agent.id "001ASD" and "decoder/other-test-message/0" asset trace
    Then I should receive the next output: "{"output":"{\"wazuh\":{\"queue\":49,\"location\":\"any_module\"},\"event\":{\"original\":\"hi! i am an event test!\"},\"agent\":{\"name\":\"any_name\",\"id\":\"001ASD\"}}"}"

  Scenario: Send events to specific session with low debug via API
    Given I have a policy "policy/wazuh/0" that has an integration called "other-wazuh-core-test" loaded
    And I create a "test" session that points to policy "policy/wazuh/0"
    When I send a request to send the event "hi! i am an event test!" from "test" session with "ASSET_ONLY" debug "system" namespace, agent.id "BB22" and "decoder/other-test-message/0" asset trace
    Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/other-test-message/0","success":true}],"output":"{\"wazuh\":{\"queue\":49,\"location\":\"any_module\"},\"event\":{\"original\":\"hi! i am an event test!\"},\"agent\":{\"name\":\"any_name\",\"id\":\"BB22\"}}"}"

  Scenario: Send events to specific session with high debug via API
    Given I have a policy "policy/wazuh/0" that has an integration called "other-wazuh-core-test" loaded
    And I create a "test" session that points to policy "policy/wazuh/0"
    When I send a request to send the event "hi! i am an event test!" from "test" session with "ALL" debug "system" namespace, agent.id "BB22" and "decoder/other-test-message/0" asset trace
    Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/other-test-message/0","success":true,"traces":["[check: $agent.id == BB22] -> Success"]}],"output":"{\"wazuh\":{\"queue\":49,\"location\":\"any_module\"},\"event\":{\"original\":\"hi! i am an event test!\"},\"agent\":{\"name\":\"any_name\",\"id\":\"BB22\"}}"}"
