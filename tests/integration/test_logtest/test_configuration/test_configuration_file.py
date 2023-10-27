'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logtest' tool allows the testing and verification of rules and decoders against provided log examples
       remotely inside a sandbox in 'wazuh-analysisd'. This functionality is provided by the manager, whose work
       parameters are configured in the ossec.conf file in the XML rule_test section. Test logs can be evaluated through
       the 'wazuh-logtest' tool or by making requests via RESTful API. These tests will check if the logtest
       configuration is valid. Also checks rules, decoders, decoders, alerts matching logs correctly.

components:
    - logtest

suite: configuration

targets:
    - manager

daemons:
    - wazuh-analysisd

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
    - https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/wazuh-logtest/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - logtest_configuration
'''
import os
import pytest

from wazuh_testing.global_parameters import GlobalParameters
from logtest import (callback_logtest_started, callback_logtest_disabled, callback_configuration_error)
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitors.file_monitor import FileMonitor


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/config_templates')
configurations_path = os.path.join(test_data_path, 'config_wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__)

# Variables
wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
global_parameters = GlobalParameters()


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
def test_configuration_file(get_configuration, configure_environment, restart_wazuh):
    '''
    description: Checks if `wazuh-logtest` works as expected under different predefined configurations that cause
                 `wazuh-logtest` to start correctly, to be disabled, or to register an error. To do this, it checks
                 some values in these configurations from 'wazuh_conf.yaml' file.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing
        - restart_wazuh:
            type: fixture
            brief: Restart wazuh, ossec.log and start a new monitor.

    assertions:
        - Verify that a valid configuration is loaded.
        - Verify that wrong loaded configurations lead to an error.

    input_description: Five test cases are defined in the module. These include some configurations stored in
                       the 'wazuh_conf.yaml'.

    expected_output:
        - r'.* Logtest started'
        - r'.* Logtest disabled'
        - r'.* Invalid value for element'
        - 'Event not found'

    tags:
        - settings
        - analysisd
    '''
    callback = None
    if 'valid_conf' in get_configuration['tags']:
        callback = callback_logtest_started
    elif 'disabled_conf' in get_configuration['tags']:
        callback = callback_logtest_disabled
    else:
        callback = callback_configuration_error

    #wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback,
    #                        error_message='Event not found')

    print(f"callback: {callback}")

    wazuh_log_monitor.start(callback=callback, timeout=global_parameters.default_timeout)
    assert wazuh_log_monitor.callback_result, "Event not found"
