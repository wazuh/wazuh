'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-authd' daemon correctly responds to the enrollment requests
       messages respecting the valid option values used in the force configuration block.

components:
    - authd

suite: force_options

targets:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db

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
import time
import pytest
import re
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.authd.utils import create_authd_request, validate_authd_response
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.modules.authd import PREFIX

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

AUTHD_KEY_REQUEST_TIMEOUT = 10

# Configurations 1
test_paths_t1 = [Path(TEST_CASES_FOLDER_PATH, 'cases_after_registration_time.yaml'),
                 Path(TEST_CASES_FOLDER_PATH, 'cases_disconnected_time.yaml'),
                 Path(TEST_CASES_FOLDER_PATH, 'cases_key_mismatch.yaml'),
                 Path(TEST_CASES_FOLDER_PATH, 'cases_force_options.yaml') ]

test_configuration_t1 = []
test_metadata_t1 = []
test_cases_ids_t1 = []

for test_path in test_paths_t1:
    test_configuration_tmp, test_metadata_tmp, test_cases_ids_tmp = get_test_cases_data(test_path)
    test_configuration_t1.extend(test_configuration_tmp)
    test_metadata_t1.extend(test_metadata_tmp)
    test_cases_ids_t1.extend(test_cases_ids_tmp)

test_configuration_path_t1 = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_force_options.yaml')
test_configuration_t1 = load_configuration_template(test_configuration_path_t1, test_configuration_t1, test_metadata_t1)

# Configurations 2
test_configuration_path_t2 = Path(CONFIGURATIONS_FOLDER_PATH, 'config_force_insert.yaml')
test_cases_path_t2 = Path(TEST_CASES_FOLDER_PATH, 'cases_force_insert.yaml')
test_configuration_t2, test_metadata_t2, test_cases_ids_t2 = get_test_cases_data(test_cases_path_t2)
test_configuration_t2 = load_configuration_template(test_configuration_path_t2, test_configuration_t2, test_metadata_t2)

# Configurations 3
test_configuration_path_t3 = Path(CONFIGURATIONS_FOLDER_PATH, 'config_force_insert_only.yaml')
test_cases_path_t3 = Path(TEST_CASES_FOLDER_PATH, 'cases_force_insert_only.yaml')
test_configuration_t3, test_metadata_t3, test_cases_ids_t3 = get_test_cases_data(test_cases_path_t3)
test_configuration_t3 = load_configuration_template(test_configuration_path_t3, test_configuration_t3, test_metadata_t3)

# Variables
local_internal_options = {'authd.debug': '2'}
receiver_sockets_params = [(('localhost', 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-authd', None, True), ('wazuh-db', None, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures

# Functions
def check_options(test_metadata):
    authd_sock = receiver_sockets[0]
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    for stage in test_metadata['test_case']:
        # Reopen socket (socket is closed by manager after sending message with client key)
        authd_sock.open()
        authd_sock.send(create_authd_request(stage['input']), size=False)
        timeout = time.time() + AUTHD_KEY_REQUEST_TIMEOUT
        response = ''
        while response == '':
            response = authd_sock.receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        result, err_msg = validate_authd_response(response, stage['output'])
        assert result == 'success', f"Failed stage '{stage['description']}': {err_msg} Complete response: '{response}'"

        for log in stage['log']:
            log = re.escape(log)
            wazuh_log_monitor.start(callback=callbacks.generate_callback(fr'{PREFIX}{log}'), timeout=10, encoding='utf-8')
            assert wazuh_log_monitor.callback_result, f'Error event not detected'



# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration_t1, test_metadata_t1), ids=test_cases_ids_t1)
def test_authd_force_options(test_configuration, test_metadata, set_wazuh_configuration,
                             configure_local_internal_options, insert_pre_existent_agents, restart_authd_function,
                             wait_for_authd_startup_function, connect_to_sockets_function, tear_down):
    '''
    description:
        Checks that every input message in authd port generates the adequate output.

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
        - insert_pre_existent_agents:
            type: fixture
            brief: adds the required agents to the client.keys and global.db
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - restart_authd_function:
            type: fixture
            brief: stops the wazuh-authd daemon.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The received output must match with expected.
        - Verifies the registration responses.

    input_description:
        Different test cases are contained in external YAML files (valid_config folder) which includes
        different possible values for the current authd settings.

    expected_output:
        - Registration request responses on Authd socket.
    '''

    check_options(test_metadata)



@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration_t2, test_metadata_t2), ids=test_cases_ids_t2)
def test_authd_force_insert(test_configuration, test_metadata, set_wazuh_configuration,
                             configure_local_internal_options, insert_pre_existent_agents, restart_authd_function,
                             wait_for_authd_startup_function, connect_to_sockets_function, tear_down):
    '''
    description:
        Checks that every input message in authd port generates the adequate output.

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
        - insert_pre_existent_agents:
            type: fixture
            brief: adds the required agents to the client.keys and global.db
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - restart_authd_function:
            type: fixture
            brief: stops the wazuh-authd daemon.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The received output must match with expected.
        - Verifies the registration responses.

    input_description:
        Different test cases are contained in external YAML files (valid_config folder) which includes
        different possible values for the current authd settings.

    expected_output:
        - Registration request responses on Authd socket.
    '''


    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    for log in test_metadata['log']:
        log = re.escape(log)
        wazuh_log_monitor.start(callback=callbacks.generate_callback(fr'{PREFIX}{log}'), timeout=10, encoding='utf-8')
        assert wazuh_log_monitor.callback_result, f'Error event not detected'

    check_options(test_metadata)



@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration_t3, test_metadata_t3), ids=test_cases_ids_t3)
def test_authd_force_insert_only(test_configuration, test_metadata, set_wazuh_configuration,
                             configure_local_internal_options, insert_pre_existent_agents, restart_authd_function,
                             wait_for_authd_startup_function, connect_to_sockets_function, tear_down):
    '''
    description:
        Checks that every input message in authd port generates the adequate output.

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
        - insert_pre_existent_agents:
            type: fixture
            brief: adds the required agents to the client.keys and global.db
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - restart_authd_function:
            type: fixture
            brief: stops the wazuh-authd daemon.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The received output must match with expected.
        - Verifies the registration responses.

    input_description:
        Different test cases are contained in external YAML files (valid_config folder) which includes
        different possible values for the current authd settings.

    expected_output:
        - Registration request responses on Authd socket.
    '''


    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    for log in test_metadata['log']:
        log = re.escape(log)
        wazuh_log_monitor.start(callback=callbacks.generate_callback(fr'{PREFIX}{log}'), timeout=10, encoding='utf-8')
        assert wazuh_log_monitor.callback_result, f'Error event not detected'

    check_options(test_metadata)