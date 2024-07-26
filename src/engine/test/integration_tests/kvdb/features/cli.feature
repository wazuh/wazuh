Feature: KVDB CLI functionality
  As a user of the KVDB CLI
  I want to be able to manage key-value databases and key-value pairs programmatically
  So that I can easily integrate KVDB into my applications using the command line

  @wip
  Scenario: Create a new key-value database using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    Then I should receive a success message

  Scenario: Attempt to create a new key-value database with an existing name using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    And I run the command "kvdb create --name TestDB"
    Then I should receive an error message indicating that "The Database already exists."

  Scenario: Delete a key-value database using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    And I run the command "kvdb delete --name TestDB"
    Then I should receive a success message

  Scenario: Delete a non-exist key-value database using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    And I run the command "kvdb delete --name TestDB1"
    Then I should receive an error message indicating that "The KVDB 'TestDB1' does not exist."

  Scenario: Add a key-value pair to a database using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    And I run the command "kvdb insert -n TestDB -k sampleKey -v sampleValue"
    Then I should receive a success message

  Scenario: Attempt to add a key-value pair with an existing key using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    And I run the command "kvdb insert --name  TestDB --key sampleKey --value sampleValue"
    And I run the command "kvdb insert --name  TestDB --key sampleKey --value newValue"
    Then I should receive a success message

  Scenario: Delete a key-value pair from a database using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    And I run the command "kvdb insert -n TestDB -k sampleKey -v sampleValue"
    And I run the command "kvdb remove -n TestDB -k sampleKey"
    Then I should receive a success message

  Scenario: Search prefix using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    And I add using CLI in the database "TestDB" 1 key-value pairs with the key called "genericKey"_id and another 2 key-value pairs with the key called "otherGenericKey"_id
    And I run the command "kvdb search -n TestDB -f other"
    Then I should receive a JSON of entries with the 2 key-value pairs whose keyname contains the prefix.
