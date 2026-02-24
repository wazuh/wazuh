Feature: Tester API Management

  @wip
  Scenario: Add a repeated session for testing via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to the tester to add a new session called "default" with the data from policy:"testing"
    Then I should receive a failture response indicating that "The name of the testing environment already exist"

  Scenario: Add a new session for testing via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to the tester to add a new session called "test1" with the data from policy:"testing"
    Then I should receive a success response

  Scenario: Remove specific session via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to the tester to add 5 sessions called "dummy" with policy "testing"
    And I send a request to the tester to delete the session "default"
    And I send a request to the tester to delete the session "dummy1"
    Then I should receive a size list of 4

  Scenario: Remove a non-existent session via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to the tester to delete the session "non-existent"
    Then I should receive a failture response indicating that "The testing environment not exist"

  Scenario: Get all sessions via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to the tester to add 5 sessions called "dummy" with policy "testing"
    Then I should receive a size list of 6

  Scenario: Get specific session via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to the tester to get the session "default"
    Then I should receive a session with name "default"

  Scenario: Change sync to OUTDATED of specific session via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to the policy "testing" to add an integration called "other-wazuh-core-test"
    And I send a request to the tester to get the session "default"
    Then I should receive a session with sync "OUTDATED"
    And I send a request to the tester to reload the "default" session and the sync change to "UPDATED" again

  Scenario: Change sync to ERROR of specific session via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" session that points to policy "testing"
    When I send a request to delete the policy "testing"
    And I send a request to the tester to get the session "default"
    Then I should receive a session with sync "ERROR"
    And I send a request to the tester to reload the "default"
    And I should receive an error response

  Scenario: Send events to specific session without debug session via API
    Given I have a policy "testing" that has an integration called "other-wazuh-core-test" loaded
    And I create a "test" session that points to policy "testing"
    When I send a request to send the event "hi! i am an event test!" from "test" session with "NONE" debug, agent.id "001ASD", agent.name "agent-ex" and "decoder/other-test-message/0" asset trace
    Then I should receive the next output: "{"output":{"wazuh":{"agent":{"name":"agent-ex","id":"001ASD"},"protocol":{"location":"[001ASD] (agent-ex) any->SomeModule","queue":49},"space":{"name":"UNDEFINED"}},"event":{"original":"hi! i am an event test!"}}}"

  Scenario: Send events to specific session with low debug via API
      Given I have a policy "testing" that has an integration called "other-wazuh-core-test" loaded
      And I create a "test" session that points to policy "testing"
      When I send a request to send the event "hi! i am an event test!" from "test" session with "ASSET_ONLY" debug, agent.id "BB22", agent.name "agent-ex" and "decoder/other-test-message/0" asset trace
      Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/other-test-message/0","success":true}],"output":{"wazuh":{"agent":{"id":"BB22","name":"agent-ex"},"integration":{"category":"other","decoders":["decoder/other-test-message/0"],"name":"other-wazuh-core-test"},"protocol":{"location":"[BB22] (agent-ex) any->SomeModule","queue":49},"space":{"name":"UNDEFINED"}},"event":{"category":["test"],"kind":"metric","original":"hi! i am an event test!","type":["info"]}}}"

  Scenario: Send events to specific session with high debug via API
      Given I have a policy "testing" that has an integration called "other-wazuh-core-test" loaded
      And I create a "test" session that points to policy "testing"
      When I send a request to send the event "hi! i am an event test!" from "test" session with "ALL" debug, agent.id "BB22", agent.name "agent-ex" and "decoder/other-test-message/0" asset trace
      Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/other-test-message/0","success":true,"traces":["[check: $wazuh.agent.id == BB22] -> Success","event.category: array_append(\"test\") -> Success","event.kind: map(\"metric\") -> Success","event.type: array_append(\"info\") -> Success"]}],"output":{"wazuh":{"agent":{"id":"BB22","name":"agent-ex"},"integration":{"category":"other","decoders":["decoder/other-test-message/0"],"name":"other-wazuh-core-test"},"protocol":{"location":"[BB22] (agent-ex) any->SomeModule","queue":49},"space":{"name":"UNDEFINED"}},"event":{"category":["test"],"kind":"metric","original":"hi! i am an event test!","type":["info"]}}}"

  Scenario: Send events to specific session with high debug with unclassified event via API
      Given I have a policy "testing" that has an integration called "other-wazuh-core-test" loaded
      And I create a "test" session that points to policy "testing"
      When I send a request to send the event "hi! i am an event test!" from "test" session with "ALL" debug, agent.id "BB22", agent.name "agent-ex" and "ALL" asset trace
      Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/other-test-message/0","success":true,"traces":["[check: $wazuh.agent.id == BB22] -> Success","event.category: array_append(\"test\") -> Success","event.kind: map(\"metric\") -> Success","event.type: array_append(\"info\") -> Success"]},{"asset":"filter/UnclassifiedEvents","success":true,"traces":["dropUnclassifiedEvent() -> Event is classified, allowing event"]},{"asset":"filter/DiscardedEvents","success":true,"traces":["Event will be indexed (wazuh.space.event_discarded=false)"]}],"output":{"wazuh":{"agent":{"id":"BB22","name":"agent-ex"},"integration":{"category":"other","decoders":["decoder/other-test-message/0"],"name":"other-wazuh-core-test"},"protocol":{"location":"[BB22] (agent-ex) any->SomeModule","queue":49},"space":{"name":"UNDEFINED"}},"event":{"category":["test"],"kind":"metric","original":"hi! i am an event test!","type":["info"]}}}"

  Scenario: Send events without agent metadata - empty struct assumed
      Given I have a policy "testing" that has an integration called "other-wazuh-core-test" loaded
      And I create a "test" session that points to policy "testing"
      When I send a request to send the event "hi! i am an event test!" from "test" session with "NONE" debug and no agent metadata
      Then I should receive the next output: "{"output":{"wazuh":{"protocol":{"location":"[] () any->SomeModule","queue":49},"space":{"name":"UNDEFINED"}},"event":{"original":"hi! i am an event test!"}}}"

  Scenario: Send events with custom agent metadata fields
      Given I have a policy "testing" that has an integration called "other-wazuh-core-test" loaded
      And I create a "test" session that points to policy "testing"
      When I send a request to send the event "hi! i am an event test!" from "test" session with "ASSET_ONLY" debug, agent.id "CUSTOM123", agent.name "custom-agent", agent.type "endpoint" and "decoder/other-test-message/0" asset trace
      Then I should receive the next output: "{"assetTraces":[{"asset":"decoder/other-test-message/0"}],"output":{"wazuh":{"agent":{"id":"CUSTOM123","name":"custom-agent","type":"endpoint"},"protocol":{"location":"[CUSTOM123] (custom-agent) any->SomeModule","queue":49},"space":{"name":"UNDEFINED"}},"event":{"original":"hi! i am an event test!"}}}"

  Scenario: Cleanup logtest removes testing session and temp namespace
    Given I have no tester sessions
    When I validate a full policy with load_in_tester enabled
    And I request logtest cleanup
    Then the "testing" session should not exist
    And no "policy_validate_" namespaces should exist

  Scenario: Cleanup logtest is idempotent when nothing exists
    Given I have no tester sessions
    When I request logtest cleanup
    Then the "testing" session should not exist
