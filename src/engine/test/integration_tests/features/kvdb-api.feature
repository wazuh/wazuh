Feature: KVDB API functionality
  As a user of the KVDB API
  I want to be able to manage key-value databases and key-value pairs programmatically
  So that I can easily integrate KVDB into my applications

  @wip
  Scenario: Create a new key-value database using API
    Given I have access to the KVDB API
    When I send a POST request to KVDB API with "database-name" as unique database name
    Then I should receive a success response with the new database information

  Scenario: Attempt to create a new key-value database with an existing name using API
    Given I have already created a database named "TestDB" using the KVDB API
    When I send a POST request with the database name "TestDB"
    Then I should receive an error response indicating that the database name already exists

  Scenario: Delete a key-value database using API
    Given I have a database named "TestDB" created using the KVDB API
    When I send a DELETE request to "TestDB"
    Then I should receive a success response indicating the database "TestDB" has been deleted

  Scenario: Add a key-value pair to a database using API
    Given I have a database named "TestDB" created using the KVDB API
    When I send a PUT request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValue"
    Then I should receive a success response with the new key-value pair information

  Scenario: Attempt to add a key-value pair with an existing key using API
    Given I have a database named "TestDB" created using the KVDB API
    And I have already added a key-value pair to the database "TestDB" with the key "dummy" and value "dummyValue"
    When I send a PUT request to modify a key-value pair to the database "TestDB" with the key "dummy" and value "otherDummyValue"
    Then I should receive a success indicating that the key value has been updated

  Scenario: Delete a key-value pair from a database using API
    Given I have a database named "TestDB" created using the KVDB API
    And I have already added a key-value pair to the database "TestDB" with the key "dummy" and value "dummyValue"
    When I send a DELETE request to remove from the database "TestDB" the key named "dummy"
    Then I should receive a success response indicating that the key-value pair with the key has been deleted
