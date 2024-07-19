"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the IP blocking feature of the API handled by the 'wazuh-apid' daemon
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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#access

tags:
    - api
"""
import time
import pytest
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.patterns import API_LOGIN_ERROR_MSG
from wazuh_testing.modules.api.utils import login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variable
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_bruteforce_blocking_system.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_bruteforce_blocking_system.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_bruteforce_blocking_system(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                                    daemons_handler, wait_for_api_start):
    """
    description: Check if the blocking time for IP addresses detected as brute-force attack works.
                 For this purpose, the test causes an IP blocking, make a request before
                 the blocking time finishes and one after the blocking time.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Provoke a block from an unknown IP
            - Try to login to check if the IP is blocked during the block time
            - Try to login after the block time to check if the IP was removed from the blocked IP addresses
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

    assertions:
        - Verify that the IP address is blocked using incorrect credentials.
        - Verify that the IP address is still blocked even when using the correct credentials within the "block time".
        - Verify that the IP address is not blocked after the "block time" expiration.
        - Verify that the API response during the "block time" is the expected.

    input_description: Different test cases are in the `cases_bruteforce_blocking_system.yaml` file which includes API
                       configuration parameters that will be replaced in the configuration template file.

    expected_output:
        - Could not get the login token.
        - Limit of login attempts reached. The current IP has been blocked due to a high number of login attempts
        - 6000

    tags:
        - brute_force_attack
    """
    block_time = test_configuration['blocks']['access']['block_time']
    max_login_attempts = test_configuration['blocks']['access']['max_login_attempts']
    expected_message = test_metadata['expected_message'].rstrip()
    expected_error = test_metadata['expected_error']

    # Provoke a block from an unknown IP (N attempts (N=max_login_attempts) with incorrect credentials).
    for _ in range(max_login_attempts):
        with pytest.raises(RuntimeError):
            login(user='wrong', password='wrong')

    # Verify that the IP address is still blocked even when using the correct credentials within the "block time"
    with pytest.raises(RuntimeError) as login_exception:
        login()

    # Get values from exception information to verify them later
    exception_message = login_exception.value.args[0]
    api_response = login_exception.value.args[1].json()
    response_message = api_response['detail']
    response_error_code = api_response['error']

    # Verify that the IP address is not blocked after the "block time" expiration
    time.sleep(block_time)
    try:
        login()
    except RuntimeError:
        pytest.fail('The login attempt has failed unexpectedly '
                    'but was expected to be successful after the `block_time` expires.')

    # Verify that the API response during the "block time" is the expected
    assert API_LOGIN_ERROR_MSG in exception_message, 'The login attempt was not blocked, instead the token' \
                                                     'was successfully obtained.\n' \
                                                     f"API response: {api_response}"
    assert expected_message == response_message, 'The error message is not the expected.\n' \
                                                 f"Expected: {exception_message}" \
                                                 f"API response error message: {response_message}"
    assert expected_error == response_error_code, f"The error code is not the expected.\n" \
                                                  f"Expected: {expected_error}" \
                                                  f"API response error code: {response_error_code}"
