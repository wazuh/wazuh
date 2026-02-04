Feature: Resource management via cmcrud resource handlers
  The cmcrud resource API allows creating, listing, updating and deleting resources
  for a given namespace and type, validating input fields and propagating
  underlying CMStore/CrudService errors.

  Background:
    # Ensure we have a clean, user-defined namespace to work with.
    Given I have created the namespace "analytics"
    And there are no "decoder" resources in namespace "analytics"
    And there are no "integration" resources in namespace "analytics"

  # ===================================================================
  #                         SUCCESS CASES
  # ===================================================================

  Scenario: Create a decoder resource and list it
    When I send a request to create a "decoder" resource named "decoder/my_decoder/0" in namespace "analytics"
    Then the resource request should succeed
    When I request the list of "decoder" resources in namespace "analytics"
    Then the resource list request should succeed
    And the resource list should contain a resource named "decoder/my_decoder/0"

  Scenario: Update an existing decoder resource using its UUID and see the hash change
    Given I have created a "decoder" resource named "decoder/my_decoder/0" in namespace "analytics"
    And I have fetched the decoder resources in namespace "analytics"
    And I have stored the UUID and hash of the resource named "decoder/my_decoder/0"
    When I send a request to update that decoder resource with modified YAML in namespace "analytics"
    Then the resource request should succeed
    When I request the list of "decoder" resources in namespace "analytics"
    Then the resource list request should succeed
    And the hash for that stored resource in namespace "analytics" should be different

  Scenario: Delete an existing decoder resource and verify it is gone
    Given I have created a "decoder" resource named "decoder/my_decoder/0" in namespace "analytics"
    And I have fetched the decoder resources in namespace "analytics"
    And I have stored the UUID of the resource named "decoder/my_decoder/0"
    When I send a request to delete the resource with that UUID in namespace "analytics"
    Then the resource request should succeed
    When I request the list of "decoder" resources in namespace "analytics"
    Then the resource list request should succeed
    And the resource list should not contain a resource named "decoder/my_decoder/0"

  # ===================================================================
  #                       VALIDATION ERRORS (CREATE)
  # ===================================================================

  Scenario: Fail to create a resource with an empty space field
    When I send a request to create a "decoder" resource named "decoder/my_decoder/0" in an empty space
    Then the resource request should fail
    And the resource error message should be "Field /space cannot be empty"

  Scenario: Fail to create a resource with an empty type field
    When I send a request to create a resource with empty type in namespace "analytics" and name "decoder/my_decoder/0"
    Then the resource request should fail
    And the resource error message should be "Field /type is required"

  Scenario: Fail to create a resource with an empty YAML content
    When I send a request to create a "decoder" resource with empty YAML in namespace "analytics"
    Then the resource request should fail
    And the resource error message should be "Field /ymlContent cannot be empty"

  Scenario: Fail to create a resource with an unsupported type
    When I send a request to create a resource with type "unknown_type" in namespace "analytics" and name "decoder/my_decoder/0"
    Then the resource request should fail
    And the resource error message should be "Unsupported value for /type"

  Scenario: Fail to create a decoder resource in a namespace that does not exist
    Given there is no namespace called "ghost"
    When I send a request to create a "decoder" resource named "decoder/my_decoder/0" in namespace "ghost"
    Then the resource request should fail
    And the resource error message should be "Failed to upsert resource of type 'decoder' in namespace 'ghost': Namespace does not exist: ghost"

  Scenario: Fail to create a decoder resource without name
    When I send a request to create a "decoder" resource without a name in namespace "analytics"
    Then the resource request should fail
    And the resource error message should be "Failed to upsert resource of type 'decoder' in namespace 'analytics': Missing or empty asset name at JSON path '/name'"

  Scenario: Fail to create a decoder resource with an invalid name
    When I send a request to create a "decoder" resource with invalid name "invalid/name" in namespace "analytics"
    Then the resource request should fail
    And the resource error message should be "Failed to upsert resource of type 'decoder' in namespace 'analytics': Asset name 'invalid/name' must have exactly 3 parts 'decoder/<name>/<version>'"

  # ===================================================================
  #                       VALIDATION ERRORS (DELETE)
  # ===================================================================

  Scenario: Fail to delete a resource with an empty space field
    When I send a request to delete a resource with empty space and UUID "some-uuid"
    Then the resource request should fail
    And the resource error message should be "Field /space cannot be empty"

  Scenario: Fail to delete a resource with an empty UUID field
    When I send a request to delete a resource with empty UUID in namespace "analytics"
    Then the resource request should fail
    And the resource error message should be "Field /uuid cannot be empty"

  Scenario: Fail to delete a resource with a non-existing UUID in an existing namespace
    When I send a request to delete a resource with UUID "non-existing-uuid" in namespace "analytics"
    Then the resource request should fail
    And the resource error message should start with "Failed to delete resource with UUID 'non-existing-uuid' in namespace 'analytics':"

  Scenario: Fail to delete a resource in a namespace that does not exist
    Given there is no namespace called "ghost"
    When I send a request to delete a resource with UUID "non-existing-uuid" in namespace "ghost"
    Then the resource request should fail
    And the resource error message should be "Failed to delete resource with UUID 'non-existing-uuid' in namespace 'ghost': Namespace does not exist: ghost"

  # ===================================================================
  #                         POLICY HANDLERS (SUCCESS)
  # ===================================================================

  Scenario: Successfully upsert and delete a policy
    Given I have prepared a valid integration and decoders for policies in namespace "analytics"
    When I send a request to upsert a valid policy in namespace "analytics"
    Then the policy request should succeed
    When I send a request to delete a policy in namespace "analytics"
    Then the policy request should succeed

  # ===================================================================
  #                         POLICY HANDLERS (ERRORS)
  # ===================================================================

  Scenario: Fail to upsert a policy with an empty space field
    When I send a request to upsert a policy in an empty space with valid policy YAML
    Then the policy request should fail
    And the policy error message should be "Field /space cannot be empty"

  Scenario: Fail to upsert a policy with an empty YAML content
    When I send a request to upsert a policy in namespace "analytics" with empty policy YAML
    Then the policy request should fail
    And the policy error message should be "Field /ymlContent cannot be empty"

  Scenario: Fail to upsert a policy in a namespace that does not exist
    Given there is no namespace called "ghost"
    When I send a request to upsert a policy in namespace "ghost" with valid policy YAML
    Then the policy request should fail
    And the policy error message should start with "Failed to upsert policy in namespace 'ghost':"

  Scenario: Fail to upsert a policy missing the integrations array
    When I send a request to upsert a policy in namespace "analytics" with YAML missing the integrations array
    Then the policy request should fail
    And the policy error message should be "Failed to upsert policy in namespace 'analytics': Policy JSON must have an 'integrations' array"

  Scenario: Fail to upsert a policy with an empty integrations array
    When I send a request to upsert a policy in namespace "analytics" with YAML having an empty integrations array
    Then the policy request should fail
    And the policy error message should be "Failed to upsert policy in namespace 'analytics': Policy JSON must have at least one integration"

  Scenario: Fail to delete a policy with an empty space field
    When I send a request to delete a policy in an empty space
    Then the policy request should fail
    And the policy error message should be "Field /space cannot be empty"

  Scenario: Fail to delete a policy in a namespace that does not exist
    Given there is no namespace called "ghost"
    When I send a request to delete a policy in namespace "ghost"
    Then the policy request should fail
    And the policy error message should start with "Failed to delete policy in namespace 'ghost':"
