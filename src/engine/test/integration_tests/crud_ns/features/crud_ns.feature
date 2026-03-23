Feature:  Namespace management via cmcrud namespace handlers
  The cmcrud namespace API allows listing, creating and deleting namespaces
  backed by CMStore, enforcing forbidden names and consistency rules.

  Background:
    # Remove all user-defined namespaces using cmcrud,
    # leaving only read-only (forbidden) namespaces.
    Given the CM store has no user-defined namespaces

  # ===================================================================
  #                             LIST
  # ===================================================================

  Scenario: List namespaces when there are no user-defined namespaces
    When I request the namespace list
    Then the namespace request should succeed
    And the namespace list should be empty

  Scenario: List namespaces after creating new namespaces
    Given I have created the namespace "analytics"
    And I have created the namespace "logs"
    When I request the namespace list
    Then the namespace request should succeed
    And the namespace list should contain "analytics"
    And the namespace list should contain "logs"

  # ===================================================================
  #                            CREATE
  # ===================================================================

  Scenario: Create a new namespace successfully
    When I send a request to create the namespace "analytics"
    Then the namespace request should succeed
    And the namespace list should contain "analytics"

  Scenario: Create multiple namespaces successfully
    When I send a request to create the namespace "analytics"
    And I send a request to create the namespace "logs"
    Then the namespace request should succeed
    And the namespace list should contain "analytics"
    And the namespace list should contain "logs"

  Scenario: Fail to create a namespace with an empty space field
    When I send a request to create a namespace with an empty space
    Then the namespace request should fail
    And the error message should be "Field /space cannot be empty"

  Scenario: Fail to create a namespace that already exists
    Given I have created the namespace "analytics"
    When I send a request to create the namespace "analytics"
    Then the namespace request should fail
    And the error message should be "Failed to create namespace 'analytics': Namespace already exists: analytics"

  Scenario Outline: Fail to create a namespace with a forbidden name
    When I send a request to create the namespace "<forbidden_space>"
    Then the namespace request should fail
    And the error message should be "<expected_error>"

    Examples:
      | forbidden_space | expected_error                                                                                  |
      | system          | Failed to create namespace 'system': Namespace name is forbidden: system                        |
      | output          | Failed to create namespace 'output': Namespace name is forbidden: output                        |
      | default         | Failed to create namespace 'default': Namespace name is forbidden: default                      |

  # ===================================================================
  #                            DELETE
  # ===================================================================

  Scenario: Delete an existing namespace successfully
    Given I have created the namespace "analytics"
    When I send a request to delete the namespace "analytics"
    Then the namespace request should succeed
    And the namespace list should not contain "analytics"

  Scenario: Deleting one namespace does not affect others
    Given I have created the namespace "analytics"
    And I have created the namespace "logs"
    When I send a request to delete the namespace "analytics"
    Then the namespace request should succeed
    And the namespace list should not contain "analytics"
    And the namespace list should contain "logs"

  Scenario: Fail to delete a namespace with an empty space field
    When I send a request to delete a namespace with an empty space
    Then the namespace request should fail
    And the error message should be "Field /space cannot be empty"

  Scenario: Fail to delete a namespace that does not exist
    When I send a request to delete the namespace "ghost"
    Then the namespace request should fail
    And the error message should be "Failed to delete namespace 'ghost': Namespace does not exist: ghost"

  Scenario Outline: Fail to delete a forbidden namespace that does not exist
    When I send a request to delete the namespace "<forbidden_space>"
    Then the namespace request should fail
    And the error message should be "Failed to delete namespace '<forbidden_space>': Namespace does not exist: <forbidden_space>"

    Examples:
      | forbidden_space |
      | system          |
      | output          |
      | default         |
