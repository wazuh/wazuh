'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of the setting 'timeout' and 'queue_size'.

tier: 0

modules:
    - authd

components:
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html
    - https://documentation.wazuh.com/current/user-manual/registering/key-request.html

tags:
    - key_request
'''
import os
import re
from pathlib import Path

import pytest
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH, WAZUH_PATH
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.modules.authd import PREFIX

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations
local_internal_options = {'authd.debug': '2'}

test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_key_request_limits.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_key_request_limits.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)


# Variables
kreq_sock_path = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'krequest')
receiver_sockets_params = [(kreq_sock_path, 'AF_UNIX', 'UDP')]
script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files')
script_filename = 'fetch_keys_sleep.py'

monitored_sockets_params = [('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets = None, None

# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_key_request_limits(test_configuration, test_metadata, set_wazuh_configuration, copy_tmp_script,
                            configure_local_internal_options, restart_authd_function,
                            wait_for_authd_startup_function, connect_to_sockets_function, tear_down):
    '''
    description:
        Checks that every input message on the key request port with different limits 'timeout' and 'queue_size'
        configuration, along with a delayed script, shows the corresponding error in the manager logs.

    wazuh_min_version: 4.4.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get the configuration of the test.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_current_test_case:
            type: fixture
            brief: Gets the current test case from the tests' list.
        - copy_tmp_script:
            type: fixture
            brief: Copy the script to a temporary folder for testing.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - restart_authd_function:
            type: fixture
            brief: Stops the wazuh-authd daemon.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - tear_down:
            type: fixture
            brief: Cleans the client.keys file.

    assertions:
        - The exec_path must be configured correctly
        - The script works as expected

    input_description:
        Different test cases are contained in an external YAML file (test_key_request_limits.yaml) which
        includes the different possible key requests with different configurations and the expected responses.

    expected_log:
        - Key request responses on 'authd' logs.
    '''

    key_request_sock = receiver_sockets[0]

    messages = test_metadata['input']
    log = test_metadata['log']

    for input in messages:
        key_request_sock.send(input, size=False)
    # Monitor expected log messages
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log = re.escape(log)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(fr'{PREFIX}{log}'), timeout=10)
    assert wazuh_log_monitor.callback_result, f'Error event not detected'
