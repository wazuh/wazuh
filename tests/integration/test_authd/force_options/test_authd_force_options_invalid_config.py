'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if a set of wrong configuration option values in the block force
       are warned in the logs file.

components:
    - authd

suite: force_options

targets:
    - manager

daemons:
    - wazuh-authd

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

tags:
    - enrollment
    - authd
'''
import os
import pytest
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml, truncate_file
from wazuh_testing.authd import DAEMON_NAME, validate_authd_logs
from wazuh_testing.tools.services import control_service


# Data paths
data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(data_path, 'template_configuration.yaml')
tests_path = os.path.join(data_path, 'test_cases', 'invalid_config')

# Configurations
configurations = load_wazuh_configurations(configurations_path, __name__)
local_internal_options = {'authd.debug': '2'}

# Tests
tests = []
test_case_ids = []
for file in os.listdir(tests_path):
    group_name = file.split('.')[0]
    file_tests = read_yaml(os.path.join(tests_path, file))
    tests = tests + file_tests
    test_case_ids = test_case_ids + [f"{group_name} {test_case['name']}" for test_case in file_tests]


# Fixtures

@pytest.fixture(scope='module')
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


@pytest.fixture(scope='function', params=tests, ids=test_case_ids)
def get_current_test_case(request):
    """
    Get current test case from the module
    """
    return request.param


# Tests

def test_authd_force_options_invalid_config(get_current_test_case, configure_local_internal_options_module,
                                            override_authd_force_conf, file_monitoring, tear_down):
    '''
    description:
        Checks that every input with a wrong configuration option value
        matches the adequate output log. None force registration
        or response message is made.

    wazuh_min_version:
        4.3.0

    tier: 0

    parameters:
        - get_current_test_case:
            type: fixture
            brief: gets the current test case from the tests' list
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - override_authd_force_conf:
            type: fixture
            brief: Modified the authd configuration options.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The received output must match with expected due to wrong configuration options.

    input_description:
        Different test cases are contained in an external YAML file (invalid_config folder) which includes
        different possible wrong settings.

    expected_output:
        - Invalid configuration values error.
    '''

    truncate_file(LOG_FILE_PATH)
    try:
        control_service('restart', daemon=DAEMON_NAME)
    except Exception:
        pass
    else:
        raise Exception('Authd started when it was expected to fail')
    validate_authd_logs(get_current_test_case.get('log', []))
