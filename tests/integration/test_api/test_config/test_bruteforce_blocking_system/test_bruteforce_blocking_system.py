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
from wazuh_testing.utils.config import get_test_cases_data
from wazuh_testing.modules.api.helpers import login


# Marks
pytestmark = pytest.mark.server

# Paths
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configuration_folder_path = os.path.join(test_data_path, 'configuration_template')
test_configuration_path = os.path.join(configuration_folder_path, 'configuration_bruteforce_blocking_system.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_configuration_path)

# Tests

@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('configuration,metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_bruteforce_blocking_system(configuration, metadata, configure_api_environment, daemons_handler, wait_for_start):
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
    block_time = configuration['block_time']
    max_login_attempts = configuration['max_login_attempts']

    # Provoke a block from an unknown IP (N attempts (N=max_login_attempts) with incorrect credentials).
    with pytest.raises(RuntimeError):
        login(user='wrong', password='wrong', login_attempts=max_login_attempts)

    # Request with correct credentials before blocking time expires.
    with pytest.raises(RuntimeError) as login_exc:
        login()
    assert 'Error obtaining login token' in login_exc.value.args[0], 'An error getting the token was expected, but ' \
                                                                     'it was not obtained. \nFull response: ' \
                                                                     f"{login_exc.value}"

    # Request after time expires.
    time.sleep(block_time)  # 300 = default blocking time
