Feature: Configuration API Management

  @wip

  Scenario: Successful configuration get with specifying a name
    Given I make a backup for security
    Given I have a valid configuration file called general.conf
    When I send a request to get configuration of the following fields ["server.queue_flood_attempts", "server.api_queue_tasks", "server.router_threads"]
    Then I should receive the same value that ["server.queue_flood_attempts", "server.api_queue_tasks", "server.router_threads"] in general.conf

  Scenario: Successful configuration get with specifying a name and compare his value
    Given I have a valid configuration file called general.conf
    When I send a request to get configuration of the following fields ["server.log_level"]
    Then I should receive "error" like log_level

  Scenario: Failed configuration save with directory path
    Given I have a valid configuration file called general.conf
    When I send a request to save configuration file located in "./test/integration_tests/configuration_files/"
    Then I should receive a failed response indicating "Cannot open file './test/integration_tests/configuration_files/': Is a directory"

  Scenario: Successful configuration save without specifying a path
    Given I have a valid configuration file called general.conf
    When I send a request to save configuration file located in "./test/integration_tests/tmp-general.conf"
    Then I should receive a success response

  Scenario: Failed when trying to update a non-existent item in the configuration
    Given I have a valid configuration file called general.conf
    When I send a request to update the iteam "non-exist" to "default" value
    Then I should receive a failed response indicating "--non-exist not found"

  Scenario: Failed when trying to update an item with avoid value
    Given I have a valid configuration file called general.conf
    When I send a request to update the iteam "server.server_threads" to "string" value
    Then I should receive a failed response indicating "Invalid value 'string' for option 'server.server_threads'"

  Scenario: Failed when trying to update an item with avoid value
    Given I have a valid configuration file called general.conf
    When I send a request to update the iteam "server.server_threads" to "string" value
    Then I should receive a failed response indicating "Invalid value 'string' for option 'server.server_threads'"

  Scenario: Failed when trying to update an server.log_level with avoid value
    Given I have a valid configuration file called general.conf
    When I send a request to update the iteam "server.log_level" to "9999" value
    Then I should receive a failed response indicating "--log_level: 9999 not in {trace,debug,info,warning,error,critical}"

  Scenario: Successful verification when updating a configuration parameter without save configuration
    Given I have a valid configuration file called general.conf
    When I send a request to get configuration of the following fields ["server.log_level"]
    Then I should receive "error" like log_level
    When I send a request to update the iteam "server.log_level" to "info" value
    And I send a request to get configuration of the following fields ["server.log_level"]
    Then I should receive "info" like log_level
    When I send a restart to server definitely
    When I send a request to get configuration of the following fields ["server.log_level"]
    Then I should receive "error" like log_level

  Scenario: Successful verification when updating a configuration parameter with save configuration
    Given I have a valid configuration file called general.conf
    When I send a request to get configuration of the following fields ["server.log_level"]
    Then I should receive "error" like log_level
    When I send a request to update the iteam "server.log_level" to "info" value
    And I send a request to get configuration of the following fields ["server.log_level"]
    Then I should receive "info" like log_level
    When I send a request to save configuration file
    Then I should receive a success response
    When I send a restart to server
    When I send a request to get configuration of the following fields ["server.log_level"]
    Then I should receive "info" like log_level
    When I send a request to update the iteam "server.log_level" to "error" value
    And I send a request to save configuration file
    And I send a restart to server definitely
