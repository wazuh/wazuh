Feature: Router Routes API Management

  @wip
  Scenario: Add a new route to the router via API
    Given I am authenticated with the router API "default"
    When I send a request POST to the router to add a new route called "dummy" with the data from policy:"policy/wazuh/0" filter:"filter/allow-all/0" priority:"255"
    Then I should receive an error response indicating that the policy already exists

  Scenario: Update an existing route in the router via API
    Given I am authenticated with the router API "default"
    When I send a PATCH request to update the priority from route "default" to value of "250"
    Then I should receive a success response indicating that the route was updated
    And I should check if the new priority is 250

  Scenario: Delete a route from the router via API
    Given I am authenticated with the router API "default"
    When I send a DELETE request to the route "default"
    Then I should receive a success response indicating that the route was deleted

  Scenario: View a list of routes in the router via API
    Given I am authenticated with the router API "default"
    When I send a GET request to get the route "default"
    Then I should receive a list of routes with their filters, priorities, and security policies

  Scenario: Check invalid priorities -Sessions- via API
    Given I am authenticated with the router API "default"
    When I send a PATCH request to update the priority from route "default" to value of "40"
    Then I should receive an error response indicating that "Route priority (40) must be greater than or equal to 50"

  Scenario: Check valid priorities -Route- via API
    Given I am authenticated with the router API "default"
    When I send a PATCH request to update the priority from route "default" to value of "300"
    Then I should receive an error response indicating that "Route priority (300) must be less than or equal to 255"
