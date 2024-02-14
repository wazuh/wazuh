Feature: Policy API Management

  @wip
  Scenario: Create an existing policy
    Given I have a policy called "policy/wazuh/0"
    When I send a request to add a new policy called "policy/wazuh/0"
    Then I should receive a failed response indicating "Policy already exists: policy/wazuh/0"

  Scenario: Create a valid policy
    Given I have a policy called "policy/wazuh/0"
    When I send a request to add a new policy called "policy/wazuh/1"
    Then I should receive a success response

  Scenario: Delete an existing policy
    Given I have a policy called "policy/wazuh/0"
    When I send a request to remove the policy called "policy/wazuh/0"
    Then I should receive a success response

  Scenario: Delete a non-existent policy
    Given I have a policy called "policy/wazuh/0"
    When I send a request to remove the policy called "policy/wazuh/1"
    Then I should receive a failed response

  Scenario: Get a valid policy without assets loaded with namespace filters
    Given I have a policy called "policy/wazuh/0"
    When I send a request to get the policy called "policy/wazuh/0" in the namespaces "wazuh system user"
    Then I should receive a policy with 0 assets in those namespaces

  Scenario: Get a valid policy without assets loaded with namespace system
    Given I have a policy called "policy/wazuh/0"
    Given I load an integration called "wazuh-core-test" in the namespace "wazuh"
    When I send a request to get the policy called "policy/wazuh/0" in the namespaces "system"
    Then I should receive a policy with 0 assets in those namespaces

  Scenario: Get a valid policy with assets loaded in the namespace system
    Given I have a policy called "policy/wazuh/0"
    Given I load an integration called "wazuh-core-test" in the namespace "wazuh"
    When I send a request to get the policy called "policy/wazuh/0" in the namespaces "wazuh"
    Then I should receive a policy with 1 assets in those namespaces

  Scenario: Obtain a nonexistent policy
    Given I have a policy called "policy/wazuh/0"
    When I send a request to get the policy called "policy/wazuh/1" in the namespaces "wazuh system user"
    Then I should receive a failed response

  Scenario: Get a policy with invalid name
    Given I have a policy called "policy/wazuh/0"
    When I send a request to get the policy called "policy/wazuh" in the namespaces "wazuh system user"
    Then I should receive a failed response indicating "Error: Policy name (/policy) must have 3 parts"

  Scenario: List all policies
    Given I have a policy called "policy/wazuh/0"
    When I send a request to add a new policy called "policy/wazuh/1"
    And I send a request to add a new policy called "policy/wazuh/2"
    And I send a request to add a new policy called "policy/wazuh/3"
    Then I should receive a list with size 4

  Scenario: Add a new asset to an existing policy
    Given I have a policy called "policy/wazuh/0"
    When I load an integration called "wazuh-core-test" in the namespace "wazuh" to the policy "policy/wazuh/0"
    Then I should receive a success response

  Scenario: Add an asset to a non-existent policy
    Given I have a policy called "policy/wazuh/0"
    When I load an integration called "wazuh-core-test" in the namespace "wazuh" to the policy "policy/wazuh/1"
    Then I should receive a failed response

  Scenario: Delete an asset from an existing policy
    Given I have a policy called "policy/wazuh/0"
    Given I load an integration called "wazuh-core-test" in the namespace "wazuh"
    When I send a request to delete the asset "wazuh-core-test" from the policy called "policy/wazuh/0" in the namespace "wazuh"
    And I send a request to get the policy called "policy/wazuh/0" in the namespaces "wazuh"
    Then I should receive a policy with 0 assets in those namespaces

  Scenario: Delete an asset from a non-existent policy

  Scenario: List assets from an existing policy

  Scenario: List assets of a non-existent policy

  Scenario: List assets of a policy with invalid namespace identifier

  Scenario: Delete an asset with an invalid name from an existing policy
