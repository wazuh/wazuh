'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

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
    - wazuh-analysisd
    - wazuh-syscheckd
    - wazuh-db

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
'''
import os
import time

import pytest
from wazuh_testing.constants.daemons import API_DAEMON
from wazuh_testing.modules.api.configuration import replace_in_api_configuration_template
from wazuh_testing.modules.api.helpers import login
from wazuh_testing.modules.api.patterns import API_LOGIN_ERROR_MSG
from wazuh_testing.utils.configuration import get_test_cases_data


# Marks
pytestmark = pytest.mark.server

# Paths
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configuration_folder_path = os.path.join(test_data_path, 'configuration_template')
cases_folder_path = os.path.join(test_data_path, 'test_cases')
test_configuration_path = os.path.join(configuration_folder_path, 'configuration_bruteforce_blocking_system.yaml')
test_cases_path = os.path.join(cases_folder_path, 'cases_bruteforce_blocking_system.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = replace_in_api_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': [API_DAEMON]}

# Tests

@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_bruteforce_blocking_system(test_configuration, test_metadata, add_configuration, daemons_handler,
                                    wait_for_api_start):
    '''
    description: Check if the blocking time for IP addresses detected as brute-force attack works.
                 For this purpose, the test causes an IP blocking, make a request before
                 the blocking time finishes and one after the blocking time.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_api_environment:
            type: fixture
            brief: Configure a custom environment for API testing.
        - restart_api:
            type: fixture
            brief: Reset 'api.log' and start a new monitor.
        - wait_for_start:
            type: fixture
            brief: Wait until the API starts.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the IP address is blocked using incorrect credentials.
        - Verify that the IP address is still blocked even when using
          the correct credentials within the blocking time.

    input_description: Different test cases are contained in an external YAML file (conf.yaml)
                       which includes API configuration parameters.

    expected_output:
        - r"Error obtaining login token"

    tags:
        - brute_force_attack
    '''
    block_time = test_configuration['base']['access']['block_time']
    max_login_attempts = test_configuration['base']['access']['max_login_attempts']
    expected_message = test_metadata['expected_message'].rstrip()
    expected_error = test_metadata['expected_error']

    # Provoke a block from an unknown IP (N attempts (N=max_login_attempts) with incorrect credentials).
    with pytest.raises(RuntimeError):
        login(user='wrong', password='wrong', login_attempts=max_login_attempts)

    # Request with correct credentials before blocking time expires and get the exception information
    with pytest.raises(RuntimeError) as login_exception:
        login()

    # Request after time expires.
    time.sleep(block_time)
    try:
        login()
    except RuntimeError:
        pytest.fail('The login attempt has failed unexpectedly '
                    'but was expected to be successful after the `block_time` expires.')

    # Get values from exception information
    exception_message = login_exception.value.args[0]
    api_response = login_exception.value.args[1]
    response_message = api_response['detail']
    response_error_code = api_response['error']

    # Check that the API's error is the expected
    assert API_LOGIN_ERROR_MSG in exception_message, 'The login attempt was not blocked, instead the token' \
                                                     'was successfully obtained.\n' \
                                                     f"API response: {api_response}"
    assert expected_message == response_message, 'The error message is not the expected.\n' \
                                                 f"Expected: {exception_message}" \
                                                 f"API response error message: {response_message}"
    assert expected_error == response_error_code, f"The error code is not the expected.\n" \
                                                  f"Expected: {expected_error}" \
                                                  f"API response error code: {response_error_code}"
