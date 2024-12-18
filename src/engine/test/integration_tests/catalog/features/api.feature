Feature: Catalog API Management

  @wip

  Scenario: Try to create a resource that is not a collection type
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "non-exist" that contains
      """
      nothing
      """
    Then I should receive a failed response indicating "Invalid collection type "unknown""


  Scenario: Try to create a resource with a invalid name
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      name: decoder/testing
      """
    Then I should receive a failed response indicating "The asset 'decoder/testing' cannot be added to the store: The name format is not valid as it is identified as a 'collection'"


  Scenario: Try to create a resource with a invalid content
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      decoder/testing/0
      """
    Then I should receive a failed response indicating "Field 'name' is missing in content"


  Scenario: Try to create a resource in invalid namespace
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh/other" a new resource of type "decoder" that contains
      """
      name: decoder/testing/0
      """
    Then I should receive a failed response indicating "Invalid namespace 'wazuh/other': NamespaceId must have only one part and cannot be empty"

  Scenario: Try to create a resource in invalid namespace
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh/" a new resource of type "decoder" that contains
      """
      name: decoder/testing/0
      """
    Then I should receive a success response


  Scenario: Try to create a resource whose type does not match its name
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "filter" that contains
      """
      name: decoder/testing/0
      """
    Then I should receive a failed response indicating "Invalid content name 'decoder/testing/0' for collection 'filter'"


  Scenario: Try to create the same resource in the same namespace
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      name: decoder/testing/0
      """
    And I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      name: decoder/testing/0
      """
    Then I should receive a failed response indicating "Content 'decoder/testing/0' could not be added to store: Document already exists"


  Scenario: Try to create the same resource in different namespace
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      name: decoder/testing/0
      """
    And I send a request to publish in the "yml" format in the namespace "user" a new resource of type "decoder" that contains
      """
      name: decoder/testing/0
      """
    Then I should receive a failed response indicating "Content 'decoder/testing/0' could not be added to store: Document already exists"


  Scenario: Try to create a resource whose content does not correspond to the type
    Given I have a clear catalog
    When I send a request to publish in the "json" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      name: decoder/testing/0
      """
    Then I should receive a failed response indicating "JSON object could not be created from 'json decoder': JSON document could not be parsed: Invalid value."


  Scenario: Try to create a resource whose content has duplicate keys
    Given I have a clear catalog
    When I send a request to publish in the "json" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0",
        "name":"decoder/testing/1"
      }
      """
    Then I should receive a failed response indicating "JSON object could not be created from 'json decoder': JSON document has duplicated keys: Unable to build json document because there is a duplicated key"


  Scenario: Try to create a resource whose content has duplicate keys (defective case)
    Given I have a clear catalog
    When I send a request to publish in the "json" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0",
        "name":"decoder/testing/0"
      }
      """
    Then I should receive a failed response indicating "An error occurred while trying to validate 'decoder/testing/0': Could not find builder for stage 'name'"


  Scenario: Try to get a resource with different format
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    And I send a request to get the resource "decoder/testing/0" with format "yaml" in the namespace "wazuh"
    Then I should receive a success response
    And I should receive the next content
      """
      name: decoder/testing/0
      """


  Scenario: Try to get non-exist resource
    Given I have a clear catalog
    When I send a request to get the resource "decoder" with format "yaml" in the namespace "wazuh"
    Then I should receive a failed response indicating "Collection 'decoder' does not exist on namespace 'wazuh'"

  Scenario: Try to get non-exist resource in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    When I send a request to get the resource "decoder" with format "yaml" in the namespace "system"
    Then I should receive a failed response indicating "Collection 'decoder' does not exist on namespace 'system'"

  Scenario: Try to get non-exist resource in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    When I send a request to get the resource "decoder/testing/0" with format "yaml" in the namespace "system"
    Then I should receive a failed response indicating "Could not get resource 'decoder/testing/0': Does not exist in the 'system' namespace"


  Scenario: Try to get non-exist resource in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    When I send a request to get the resource "decoder" with format "yaml" in the namespace "system"
    Then I should receive a failed response indicating "Collection 'decoder' does not exist on namespace 'system'"


  Scenario: Try to get a collection in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing-1/0"
      }
      """
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing-2/0"
      }
      """
    When I send a request to get the resource "decoder" with format "yaml" in the namespace "wazuh"
    Then I should receive a success response
    And I should receive the next content
      """
      - decoder/testing
      - decoder/testing-1
      - decoder/testing-2
      """

  Scenario: Try to delete non-exist resource in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    When I send a request to delete the resource "decoder/testing/0" in the namespace "system"
    Then I should receive a failed response indicating "Could not delete resource 'decoder/testing/0': Does not exist in the 'system' namespace"


  Scenario: Try to delete resource in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    And I send a request to delete the resource "decoder/testing/0" in the namespace "wazuh"
    Then I should receive a success response
    When I send a request to get the resource "decoder/testing/0" with format "yaml" in the namespace "wazuh"
    Then I should receive a failed response indicating "Could not get resource 'decoder/testing/0': Resource 'decoder/testing/0' does not have an associated namespace"


  Scenario: Try to delete collection in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing-1/0"
      }
      """
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing-2/0"
      }
      """
    And I send a request to delete the resource "decoder" in the namespace "wazuh"
    Then I should receive a success response
    When I send a request to get the resource "decoder" with format "yaml" in the namespace "wazuh"
    Then I should receive a failed response indicating "Collection 'decoder' does not exist on namespace 'wazuh'"


  Scenario: Try to update the name of a resource
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    And I send a request to update in the "yml" format in the namespace "wazuh" the resource "decoder/testing/0" that contains
      """
      {
        "name":"decoder/testing-updated/0"
      }
      """
    Then I should receive a failed response indicating "Invalid content name 'decoder/testing-updated/0' of 'decoder/testing/0' for type 'decoder'"

  Scenario: Try to update non-exist resource in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    And I send a request to update in the "yml" format in the namespace "system" the resource "decoder/testing/0" that contains
      """
      {
        "name":"decoder/testing/0",
        "metadata": {
          "description": "this is a test decoder"
        }
      }
      """
    Then I should receive a failed response indicating "Could not update resource 'decoder/testing/0': Does not exist in the 'system' namespace"


  Scenario: Try to update exists resource in namespace selected
    Given I have a clear catalog
    When I send a request to publish in the "yml" format in the namespace "wazuh" a new resource of type "decoder" that contains
      """
      {
        "name":"decoder/testing/0"
      }
      """
    And I send a request to update in the "yml" format in the namespace "wazuh" the resource "decoder/testing/0" that contains
      """
      {
        "name":"decoder/testing/0",
        "metadata": {
          "description": "this is a test decoder"
        }
      }
      """
    Then I should receive a success response
    When I send a request to get the resource "decoder/testing/0" with format "yaml" in the namespace "wazuh"
    Then I should receive a success response
    And I should receive the next content
      """
      name: decoder/testing/0
      metadata:
        description: this is a test decoder
      """


  Scenario: Try to validate the resource that has duplicate keys
    Given I have a clear catalog
    When I send a request to validate in the "yml" format in the resource "decoder/testing/0" that contains
      """
        name: decoder/testing/0
        check: 1 == 2
        check: 1 == 1
      """
    Then I should receive a failed response indicating "Content could not be parsed to json: Unable to build json document because there is a duplicated key"


  Scenario: Try to validate the resource that has non-exist helper
    Given I have a clear catalog
    When I send a request to validate in the "yml" format in the resource "decoder/testing/0" that contains
      """
        name: decoder/testing/0
        check: helper_not_exist(field)
      """
    Then I should receive a failed response indicating
      """
      Stage 'check' failed to build expression 'helper_not_exist(field)': Expression parsing failed.
      Main error: Unexpected token at 0
      helper_not_exist(field)
      ^

      List of errors:
      Unexpected token at 0
      helper_not_exist(field)
      ^

      """


  Scenario: Try to validate the resource that has a non-exist field en schema
    Given I have a clear catalog
    When I send a request to validate in the "yml" format in the resource "decoder/testing/0" that contains
      """
        name: decoder/testing/0
        parse|message:
          - <user> <ip> <address>
      """
    Then I should receive a failed response indicating "An error occurred while parsing a log: Field 'user' not found in schema"


  Scenario: Try to validate the resource that has a duplicate stage parse
    Given I have a clear catalog
    When I send a request to validate in the "yml" format in the resource "decoder/testing/0" that contains
      """
        name: decoder/testing/0
        parse|message:
          - <event.code> <event.kind> <event.action>
        parse|event.original:
          - <_url> <_ip> <_address>
      """
    Then I should receive a failed response indicating "Could not find builder for stage 'parse|event.original'"


  Scenario: Try to validate the resource that map invalid value
    Given I have a clear catalog
    When I send a request to validate in the "yml" format in the resource "decoder/testing/0" that contains
      """
        name: decoder/testing/0
        map:
          - event.category: test
      """
    Then I should receive a failed response indicating "Failed to build operation 'event.category: map("test")': Operation expects a non-array, but field 'event.category' is"


  Scenario: Try to validate the resource that has invalid check-map
    Given I have a clear catalog
    When I send a request to validate in the "yml" format in the resource "decoder/testing/0" that contains
      """
        name: decoder/testing/0
        check: 1 == 2 OR 3 == 3
          - map:
            - event.kind: test
      """
    Then I should receive a failed response indicating "Content could not be parsed to json: yaml-cpp: error at line 3, column 10: illegal map value"

  Scenario: Try to validate the resource valid
    Given I have a clear catalog
    When I send a request to validate in the "yml" format in the resource "decoder/testing/0" that contains
      """
        name: decoder/testing/0
        check: $log.file.path == /var/log/apache2/access.log
        parse|message:
          - <event.code> <event.kind> <event.action>
        normalize:
          - check: $event.code == '1'
            map:
              - event.category: array_append(dns)
              - event.kind: test
          - parse|message:
              - "File does not exist: <file.path>(?, referer: <http.request.referrer>)"
          - map:
              - event.dataset: integration-test
      """
    Then I should receive a success response
