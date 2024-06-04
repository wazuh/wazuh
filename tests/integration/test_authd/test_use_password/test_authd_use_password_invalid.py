'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

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

from pathlib import Path
import re

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.utils.services import control_service
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.modules.authd import PREFIX
from wazuh_testing.modules.authd.configuration import AUTHD_DEBUG_CONFIG

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_use_password_invalid.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_use_password_invalid.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Test configurations
local_internal_options = {AUTHD_DEBUG_CONFIG: '2'}

# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_use_password_invalid(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files_module,
                                    configure_local_internal_options, set_authd_pass):
    '''
    description:
        Checks the correct errors are raised when an invalid password value
        is configured in the authd.pass file. This test expects the error log
        to come from the cases yaml, this is done this way to handle easily
        the different error logs that could be raised from different inputs.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - set_authd_pass:
            type: fixture
            brief: Configures the `authd.pass` file as needed.
        - truncate_monitored_files_module:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.

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
    log = test_metadata['error']
    if log == 'Invalid password provided.':
        pytest.xfail(reason="No password validation in authd.pass - Issue wazuh/wazuh#16282.")

    # Verify wazuh-manager fails at restart.
    with pytest.raises(ValueError):
        control_service('restart')

    # Verify the error log is raised.

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log = re.escape(log)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(fr'{PREFIX}{log}'), timeout=10)
    assert wazuh_log_monitor.callback_result, f'Error event not detected'
