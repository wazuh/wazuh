Feature: Router Routes API Management

  @wip
  Scenario: Add a new route to the router via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that uses the filter "filter/allow-all/0" and points to policy "policy/wazuh/0"
    When I send a request to the router to add a new route called "dummy" with the data from policy:"policy/wazuh/0" filter:"filter/allow-all/0" priority:"255"
    Then I should receive an error response indicating "The priority of the route  is already in use"

  Scenario: Update an existing route in the router via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that uses the filter "filter/allow-all/0" and points to policy "policy/wazuh/0"
    When I send a request to update the priority from route "default" to value of "250"
    Then I should receive a success response indicating that the route was updated
    And I should check if the new priority is 250

  Scenario: Delete a route from the router via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that uses the filter "filter/allow-all/0" and points to policy "policy/wazuh/0"
    When I send a request to delete the route "default"
    Then I should receive a success response indicating that the route was deleted

  Scenario: View a list of routes in the router via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that uses the filter "filter/allow-all/0" and points to policy "policy/wazuh/0"
    When I send a request to get the route "default"
    Then I should receive a list of routes with their filters, priorities, and security policies

  Scenario: Check invalid priorities via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that uses the filter "filter/allow-all/0" and points to policy "policy/wazuh/0"
    When I send a request to update the priority from route "default" to value of "0"
    Then I should receive an error response indicating "Priority of the route cannot be 0"

  Scenario: Check valid priorities -Route- via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that uses the filter "filter/allow-all/0" and points to policy "policy/wazuh/0"
    When I send a request to update the priority from route "default" to value of "1001"
    Then I should receive an error response indicating "Priority of the route cannot be greater than 1000"

  Scenario: Change sync of specific route via API
    Given I have a policy "policy/wazuh/0" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that uses the filter "filter/allow-all/0" and points to policy "policy/wazuh/0"
    When I send a request to the policy "policy/wazuh/0" to add an integration called "other-wazuh-core-test"
    And I send a request to get the route "default"
    Then I should receive a route with sync "OUTDATED"
    And I send a request to the router to reload the "default" route and the sync change to "UPDATED" again
