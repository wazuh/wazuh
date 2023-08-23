Feature: KVDB CLI functionality
  As a user of the KVDB CLI
  I want to be able to manage key-value databases and key-value pairs programmatically
  So that I can easily integrate KVDB into my applications using the command line

  Scenario: Create a new key-value database using CLI
    Given I have access to the KVDB CLI
    When I run the command "kvdb create --name TestDB"
    Then I should receive a success message with the new database information

  Scenario: Attempt to create a new key-value database with an existing name using CLI
    Given I have already created a database named "TestDB" using the KVDB CLI
    When I execute the command "kvdb create --name TestDB"
    Then I should receive an error message indicating that "The Database already exists."

  Scenario: Delete a key-value database using CLI
    Given I have a database named "TestDB" created using the KVDB CLI
    When I run the command "kvdb delete --name TestDB"
    Then I should receive a success message indicating that "The database TestDB has been deleted."

  Scenario: Add a key-value pair to a database using CLI
    Given I have a database named "TestDB" created using the KVDB CLI
    When I run the command "kvdb insert -n TestDB -k sampleKey -v sampleValue"
    Then I should receive a success message with the new key-value pair information

  Scenario: Attempt to add a key-value pair with an existing key using CLI
    Given I have a database named "TestDB" created using the KVDB CLI
    And I have already added a key-value pair with the key "sampleKey"
    When I run the command "kvdb insert -n TestDB -k sampleKey -v newValue"
    Then I should receive for CLI a success indicating that the key value has been updated

  Scenario: Delete a key-value pair from a database using CLI
    Given I have a database named "TestDB" created using the KVDB CLI
    And I have already added a key-value pair with the key "sampleKey"
    When I run the command "kvdb remove -n TestDB -k sampleKey"
    Then I should receive a success message indicating that the key-value pair with the key "sampleKey" has been deleted

  Scenario: Search prefix using CLI
    When I add using CLI in the database "TestDB" 1 key-value pairs with the key called "genericKey"_id and another 2 key-value pairs with the key called "otherGenericKey"_id
    AND I run from CLI the command "kvdb search -n TestDB -p other"
    Then I should receive a JSON of entries with the 2 key-value pairs whose keyname contains the prefix.