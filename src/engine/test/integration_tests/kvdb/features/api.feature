Feature: KVDB API functionality
  As a user of the KVDB API
  I want to be able to manage key-value databases and key-value pairs programmatically
  So that I can easily integrate KVDB into my applications

  @wip
  Scenario: Create a new key-value database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "database-name"
    Then I should receive a success response

  Scenario: Attempt to create a new key-value database with an existing name using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a POST request to database called "TestDB"
    Then I should receive a failed response indicating "The Database already exists."

  Scenario: Delete a key-value database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a DELETE request to database called "TestDB"
    Then I should receive a success response

  Scenario: Delete a non-exists key-value database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a DELETE request to database called "TestDB"
    And I send a DELETE request to database called "TestDB"
    Then I should receive a failed response indicating "The KVDB 'TestDB' does not exist."

  Scenario: Add a key-value pair to a non-exist database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a request to add a key-value pair to the database "TestDB1" with key "dummy" and value "dummyValue"
    Then I should receive a failed response indicating "The KVDB 'TestDB1' does not exist." 

  Scenario: Add a key-value pair to a database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValue"
    Then I should receive a success response

  Scenario: Add a key-value pair to a database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValue"
    Then I should receive a success response

  Scenario: Attempt to add a key-value pair with an existing key using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValue"
    And I send a request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValueCopy"
    Then I should receive a success response  

  Scenario: Delete a key-value pair from a database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValue"
    And I send a request to remove from the database "TestDB" the key named "dummy"
    Then I should receive a success response
  
  Scenario: Delete a non-exist key-value pair from a database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValue"
    And I send a request to remove from the database "TestDB" the key named "dummy"
    And I send a request to remove from the database "TestDB" the key named "dummy"
    Then I should receive a success response

  Scenario: Delete a key-value pair from a non-exist database using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I send a request to add a key-value pair to the database "TestDB" with key "dummy" and value "dummyValue"
    And I send a DELETE request to database called "TestDB"
    And I send a request to remove from the database "TestDB" the key named "dummy"
    Then I should receive a failed response indicating "The KVDB 'TestDB' does not exist."

  Scenario: Search prefix using API
    Given I have access to the KVDB API
    When I send a POST request to database called "TestDB"
    And I add in the database "TestDB" 1 key-value pairs with the key called "genericKey"_id and another 2 key-value pairs with the key called "otherGenericKey"_id
    And I send a request to search by the prefix "other" in database "TestDB"
    Then I should receive a list of entries with the 2 key-value pairs whose keyname contains the prefix.
