'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check invalid values in the authd.pass (for now just checks 'empty')
       raises the expected error logs.

components:
    - authd

suite: use_password

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

import pytest

import os

from wazuh_testing.modules.authd import event_monitor as evm
from wazuh_testing import DEFAULT_AUTHD_PASS_PATH
from wazuh_testing.tools.file import write_file, delete_file
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.services import control_service


# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_authd_use_password_invalid.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'config_authd_use_password_invalid.yaml')

# Test configurations
params, metadata, case_ids = get_test_cases_data(test_cases_path)
configuration = load_configuration_template(configurations_path, params, metadata)
local_internal_options = {'authd.debug': '2'}


# Fixture
@pytest.fixture()
def set_authd_pass(metadata: dict):
    """Configure the file 'authd.pass' as needed for the test."""
    # Write the content in the authd.pass file.
    write_file(DEFAULT_AUTHD_PASS_PATH, metadata.get('password'))

    yield

    # Delete the file as by default it doesn't exist.
    delete_file(DEFAULT_AUTHD_PASS_PATH)


# Test
@pytest.mark.parametrize('metadata, configuration', zip(metadata, configuration), ids=case_ids)
def test_authd_use_password_invalid(metadata, configuration, truncate_monitored_files,
                                    configure_local_internal_options_module, set_authd_pass,
                                    set_wazuh_configuration, tear_down):
    '''
    description:
        Checks the correct errors are raised when an invalid password value
        is configured in the authd.pass file. This test expects the error log
        to come from the cases yaml, this is done this way to handle easily
        the different error logs that could be raised from different inputs.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - set_authd_pass:
            type: fixture
            brief: Configures the `authd.pass` file as needed.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - Error log 'Empty password provided.' is raised in ossec.log.
        - wazuh-manager.service must not be able to restart.

    input_description:
        ./data/configuration_template/config_authd_use_password_invalid.yaml: Wazuh config needed for the tests.
        ./data/test_cases/cases_authd_use_password_invalid.yaml: Values to be used and expected error.

    expected_output:
        - .*Empty password provided.
        - .*Invalid password provided.
    '''
    if metadata.get('error') == 'Invalid password provided.':
        pytest.xfail(reason="No password validation in authd.pass - Issue wazuh/wazuh#16282.")

    # Verify wazuh-manager fails at restart.
    with pytest.raises(ValueError):
        control_service('restart')

    # Verify the error log is raised.
    evm.check_authd_event(callback=metadata.get('error'))
