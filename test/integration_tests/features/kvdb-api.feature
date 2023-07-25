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
    When I send a POST request to "/databases" with the database name "TestDB"
    Then I should receive an error response indicating that the database name already exists

  Scenario: Delete a key-value database using API
    Given I have a database named "TestDB" created using the KVDB API
    When I send a DELETE request to "/databases/TestDB"
    Then I should receive a success response indicating the database "TestDB" has been deleted

  Scenario: Add a key-value pair to a database using API
    Given I have a database named "TestDB" created using the KVDB API
    When I send a POST request to "/databases/TestDB/keys" with a unique key and a value
    Then I should receive a success response with the new key-value pair information

  Scenario: Attempt to add a key-value pair with an existing key using API
    Given I have a database named "TestDB" created using the KVDB API
    And I have already added a key-value pair with the key "sampleKey"
    When I send a POST request to "/databases/TestDB/keys" with the key "sampleKey"
    Then I should receive an error response indicating that the key already exists in the database

  Scenario: Update a key-value pair in a database using API
    Given I have a database named "TestDB" created using the KVDB API
    And I have added a key-value pair with the key "sampleKey" and value "sampleValue"
    When I send a PUT request to "/databases/TestDB/keys/sampleKey" with the new value "updatedValue"
    Then I should receive a success response indicating that the key-value pair with the key "sampleKey" has been updated

  Scenario: Delete a key-value pair from a database using API
    Given I have a database named "TestDB" created using the KVDB API
    And I have added a key-value pair with the key "sampleKey" and value "sampleValue"
    When I send a DELETE request to "/databases/TestDB/keys/sampleKey"
    Then I should receive a success response indicating that the key-value pair with the key "sampleKey" has been deleted

  Scenario: Retrieve a list of key-value pairs with pagination using API
    Given I have a database named "LargeDB" with more than 50 key-value pairs created using the KVDB API
    When I send a GET request to "/databases/LargeDB/keys" with a page number parameter
    Then I should receive a success response containing a maximum of 50 key-value pairs per page
    And the response should include pagination information to navigate between pages