"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the cache feature of the API handled by the 'wazuh-apid' daemon
       is working properly. The Wazuh API is an open source 'RESTful' API that allows for interaction
       with the Wazuh manager from a web browser, command line tool like 'cURL' or any script
       or program that can make web requests.

components:
    - api

suite: config

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-execd
    - wazuh-db
    - wazuh-remoted

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#cache

tags:
    - api
"""
import time
import pytest
import requests
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import RULES_FILES_ROUTE, CONFIGURATION_TYPES
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.constants.paths.ruleset import DEFAULT_RULES_PATH
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.file import write_file


# Marks
pytestmark = pytest.mark.server

# Variables
test_file = Path(DEFAULT_RULES_PATH, 'api_test.xml')
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_cache.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_cache.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_cache(test_configuration, test_metadata, add_configuration, truncate_monitored_files, daemons_handler,
               wait_for_api_start, remove_test_file):
    """
    description: Check if the stored response is returned when the cache is enabled.
                 Calls to rules endpoints can be cached. This test verifies if the result
                 of the first call to the rule endpoint is equal to the second call within
                 a period established in the configuration, even though a new file
                 has been created during the process.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Request rules files before creating a new one
            - Create a new file inside DEFAULT_RULES_PATH
            - Request rules files again
            - Check if the API's behavior is the expected when the cache is enabled/disabled
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files
            - Stop daemons defined in `daemons_handler_configuration` in this module

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration data from the test case.
        - test_metadata:
            type: dict
            brief: Metadata from the test case.
        - add_configuration:
            type: fixture
            brief: Add configuration to the Wazuh API configuration files.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - wait_for_api_start:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.
        - remove_test_file:
            type: fixture
            brief: Remove the file before and after the test execution.

    assertions:
        - Verify that the number of files is the same in the first and second response when `cache` is enabled.
        - Verify that the number of files is updated when a new file is added and the cache has expired.
        - Verify that the number of files is greater than before adding a new file when cache is disabled.

    input_description: Different test cases are in the `cases_cache.yaml` file which includes API configuration
                       parameters that will be replaced in the configuration template file.

    expected_output:
        - Number of rule files (if caching is enabled).
        - Number of rule files + 1 (if caching is disabled).

    tags:
        - cache
    """
    cache = test_configuration['blocks']['cache']['enabled']
    cache_expiration_time = test_configuration['blocks']['cache']['time']
    url = get_base_url() + RULES_FILES_ROUTE
    authentication_headers, _ = login()

    # Request rules files before creating a new one
    rule_files = requests.get(url, headers=authentication_headers, verify=False)
    # Get the number of files in total
    first_quantity = rule_files.json()['data']['total_affected_items']

    # Create a new file inside DEFAULT_RULES_PATH
    write_file(file_path=test_file, data='')

    # Request rules files again
    rule_files = requests.get(url, headers=authentication_headers, verify=False)
    # Get the number of files in total after creating a new file
    second_quantity = rule_files.json()['data']['total_affected_items']

    # If cache is enabled, number of files should be the same in the first and second response even with a new one.
    expected_files_without_cache = first_quantity + 1
    if cache is True:
        assert first_quantity == second_quantity, 'The new file was included. This is not correct because ' \
                                                  'cache is enabled, the quantity must be the same.\n' \
                                                  f"Expected quantity: {first_quantity}\n" \
                                                  f"Files in the second request: {second_quantity}"
        # Wait until cache expires (10 seconds)
        time.sleep(cache_expiration_time + 1)
        # Get a new response after cache expiration
        rule_files = requests.get(url, headers=authentication_headers, verify=False)
        third_quantity = rule_files.json()['data']['total_affected_items']

        assert third_quantity == expected_files_without_cache, 'The new file was not included after the ' \
                                                               'cache had expired.' \
                                                               f"Expected quantity: {expected_files_without_cache}\n" \
                                                               f"Files in the second request: {second_quantity}"
    else:
        # Verify that the second response has updated data when cache is disabled.
        assert expected_files_without_cache == second_quantity, 'The new file was not included even though the ' \
                                                                'cache is disabled, the data must be updated.\n' \
                                                                f"Expected quantity: {expected_files_without_cache}\n" \
                                                                f"Files in the second request: {second_quantity}"
