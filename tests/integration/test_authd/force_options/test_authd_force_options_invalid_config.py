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
import re
import pytest
from pathlib import Path

from wazuh_testing.utils.file import truncate_file
from wazuh_testing.utils.services import control_service
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.constants.daemons import AUTHD_DAEMON
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.modules.authd import PREFIX

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_force_options.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_force_options_invalid_config.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

local_internal_options = {'authd.debug': '2'}

# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_force_options_invalid_config(test_configuration, test_metadata, set_wazuh_configuration,
                                            configure_local_internal_options, tear_down):
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

    truncate_file(WAZUH_LOG_PATH)
    try:
        control_service('restart', daemon=AUTHD_DAEMON)
    except Exception:
        pass
    else:
        raise Exception('Authd started when it was expected to fail')


    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log = re.escape(test_metadata['log'])
    wazuh_log_monitor.start(callback=callbacks.generate_callback(fr'{PREFIX}{log}'), timeout=10)
    assert wazuh_log_monitor.callback_result, f'Error event not detected'
