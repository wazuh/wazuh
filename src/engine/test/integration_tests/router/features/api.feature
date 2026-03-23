Feature: Router Routes API Management

  @wip
  Scenario: Add new existing priority route to router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to the router to add a new route called "dummy" with priority "255" that points to policy "testing"
    Then I should receive an error response indicating "The priority of the route  is already in use"

  Scenario: Add new existing named route to router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to the router to add a new route called "default" with priority "200" that points to policy "testing"
    Then I should receive an error response indicating "The name of the route is already in use"

  Scenario: Add new route to router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to the router to add a new route called "dummy" with priority "200" that points to policy "testing"
    Then I should receive a success response

  Scenario: Update an existing route in the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to update the priority from route "default" to value of "250"
    Then I should receive a success response
    And I should check if the new priority is 250

  Scenario: Update a non-existent route on the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to update the priority from route "route-not-exist" to value of "250"
    Then I should receive an error response indicating "The route not exist"

  Scenario: Update a route to a priority already occupied on the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to the router to add a new route called "dummy" with priority "200" that points to policy "testing"
    When I send a request to update the priority from route "default" to value of "200"
    Then I should receive an error response indicating "Failed to change the priority, it is already in use"

  Scenario: Update a route to zero priority on the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to update the priority from route "default" to value of "0"
    Then I should receive an error response indicating "Priority of the route cannot be 0"

  Scenario: Update a route to a priority greater than thousand on the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to update the priority from route "default" to value of "1001"
    Then I should receive an error response indicating "Priority of the route cannot be greater than 1000"

  Scenario: Delete a route from the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to delete the route "default"
    Then I should receive a success response

  Scenario: Delete a a non-existent route from the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to delete the route "route-not-exist"
    Then I should receive an error response indicating "The route not exist"

  Scenario: View of all the information of a certain route via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to get the route "default"
    Then I should receive all the "default" route information with policy "testing" and priority "255"

  Scenario: View a list of routes in the router via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to the router to add a new route called "dummy" with priority "200" that points to policy "testing"
    And I send a request to the router to add a new route called "other-dummy" with priority "500" that points to policy "testing"
    And I send a request to get the list of routes
    Then I should receive a list with size equal to "3"

  Scenario: Change sync of specific route via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to the policy "testing" to add an integration called "other-wazuh-core-test"
    And I send a request to get the route "default"
    Then I should receive a route with sync "OUTDATED"
    And I send a request to the router to reload the "default" route and the sync change to "UPDATED" again

  Scenario: Failded to try reload specific route via API
    Given I have a policy "testing" that has an integration called "wazuh-core-test" loaded
    And I create a "default" route with priority "255" that points to policy "testing"
    When I send a request to delete the policy "testing"
    And I send a request to get the route "default"
    Then I should receive a route with sync "ERROR"
    And I send a request to the router to reload the "default"
    And I should receive an error response
