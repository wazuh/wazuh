'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       This tests will check if the server address specified in the configuration is a valid
       address or not.

tier: 0

modules:
    - agentd

components:
    - agent

daemons:
    - wazuh-agentd

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#address

tags:
    - agentd
'''

import sys
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.agentd.patterns import ENROLLMENT_INVALID_SERVER, ENROLLMENT_RESOLVE_ERROR, ENROLLMENT_CONNECTED
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.network import format_ipv6_long

from . import CONFIGS_PATH, TEST_CASES_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_server_address.yaml')
config_path = Path(CONFIGS_PATH, 'config_server_address.yaml')
config_parameters, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, config_parameters, test_metadata)

# Test variables.
socket_listener = None

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}

daemons_handler_configuration = {'all_daemons': True}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_agentd_server_address_configuration(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                             truncate_monitored_files, daemons_handler_module, shutdown_agentd,
                                             configure_socket_listener, restart_agentd):

    '''
    description: Check the messages produced by the agent when introducing
                 a valid and invalid server address, with IPv4 and IPv6

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_socket_listener:
            type: fixture
            brief: Configure MITM.
        - daemons_handler:
            type: fixture
            brief: Restart the agentd daemon for restarting the agent.

    assertions:
        - Verify that the messages have been produced in ossec.log

    input_description: The `server_address_configuration.yaml` file includes configuration settings for the agent.
                       Eight test cases are found in the test module and include parameters
                       for the environment setup using the TCP  protocols.

    tags:
        - agentd
    '''

    manager_address = test_metadata['server_address']

    final_manager_address = ''
    if 'valid_ip' in test_metadata:
        final_manager_address = manager_address

    if 'ipv6' in test_metadata:
        final_manager_address = format_ipv6_long(final_manager_address)

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    if manager_address == 'MANAGER_IP':
        callback=generate_callback(ENROLLMENT_INVALID_SERVER, {'server_ip': str(test_metadata['server_address'])})
        log_monitor.start(timeout=30, callback=callback)
        assert log_monitor.callback_result
    else:
        if 'expected_connection' in test_metadata:
            callback=generate_callback(ENROLLMENT_CONNECTED, {'server_ip': final_manager_address,
                                                              'port': str(DEFAULT_SSL_REMOTE_ENROLLMENT_PORT)})
            log_monitor.start(timeout=30, callback=callback)
            assert log_monitor.callback_result
        else:
            callback=generate_callback(ENROLLMENT_RESOLVE_ERROR, {'server_ip': final_manager_address})
            log_monitor.start(timeout=30, callback=callback)
            assert log_monitor.callback_result
