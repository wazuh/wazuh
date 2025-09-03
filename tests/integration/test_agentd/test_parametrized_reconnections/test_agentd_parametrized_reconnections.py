'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       The objective is to check how the 'wazuh-agentd' daemon behaves when there are delays
       between connection attempts to the 'wazuh-remoted' daemon using TCP and UDP protocols.
       The 'wazuh-remoted' program is the server side daemon that communicates with the agents.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-authd
    - wazuh-remoted

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
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/registering/index.html

tags:
    - enrollment
'''
from datetime import timedelta, datetime
import pytest
from pathlib import Path
import sys

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.modules.agentd.patterns import AGENTD_TRYING_CONNECT, AGENTD_CONNECTED_TO_SERVER
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH
from utils import wait_connect, wait_server_rollback, check_connection_try

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_reconnection_protocol.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '0'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}
local_internal_options.update({AGENTD_TIMEOUT: '5'})

daemons_handler_configuration = {'all_daemons': True}

# Tests
"""
This test covers different options of delays between server connection attempts:
-Different values of max_retries parameter
-Different values of retry_interval parameter
-UDP/TCP connection
-Enrollment between retries
"""

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_parametrized_reconnections(test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                           truncate_monitored_files, clean_keys, add_keys, daemons_handler):
    '''
    description: Check how the agent behaves when there are delays between connection
                 attempts to the server. For this purpose, different values for
                 'max_retries' and 'retry_interval' parameters are tested.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - clean_keys:
            type: fixture
            brief: Cleans keys file content
        - add_keys:
            type: fixture
            brief: Adds keys to keys file
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that when the 'wazuh-agentd' daemon initializes, it connects to
          the 'wazuh-remoted' daemon of the manager before reaching the maximum number of attempts.
        - Verify the successful enrollment of the agent if the auto-enrollment option is enabled.
        - Verify that the rollback feature of the server works correctly.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Trying to connect to server'
        - r'Unable to connect to any server'

    tags:
        - simulator
        - ssl
        - keys
    '''
    if sys.platform == WINDOWS:
        DELTA = 4
    else:
        DELTA = 1

    interval = test_metadata['RETRY_INTERVAL']

    # Get first connection try log timestamp
    matched_line = check_connection_try()
    log_timestamp = parse_time_from_log_line(matched_line)

    for _ in range(1,test_metadata['MAX_RETRIES']):
        # Get second connection try log timestamp
        matched_line = check_connection_try()
        actual_retry = parse_time_from_log_line(matched_line)

        # Compute elapsed time
        delta_retry = actual_retry - log_timestamp

        # Check elapsed time is the spected
        assert delta_retry >= timedelta(seconds=interval - DELTA), "Retries to quick"
        assert delta_retry <= timedelta(seconds=interval + DELTA), "Retries to slow"

        # Second log becomes the first for next cycle
        log_timestamp = actual_retry

    # If auto enrollment is enabled, retry check enrollment
    if test_metadata['ENROLL'] == 'yes':
        # Start RemotedSimulator for successfully enrollment
        remoted_server = RemotedSimulator(protocol=test_metadata['PROTOCOL'])
        try:
            remoted_server.start()
            wait_connect()
        finally:
            # Shutdown RemotedSimulator
            remoted_server.destroy()

    # Wait for server rollback
    wait_server_rollback()

    #Check number of retries messages is the expected
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(accumulations = test_metadata['MAX_RETRIES'], callback=callbacks.generate_callback(AGENTD_TRYING_CONNECT,{'IP':'','PORT':''}))
    assert (wazuh_log_monitor.callback_result != None), f'Trying to connect to server message not found expected times'

    #Check number of connected message is the expected
    if test_metadata['ENROLL'] == 'yes':
        wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_CONNECTED_TO_SERVER))
        assert (wazuh_log_monitor.callback_result != None), f'Connected to the server message not found'


def parse_time_from_log_line(log_line):
    """Create a datetime object from a date in a string.

    Args:
        log_line (str): String with date.

    Returns:
        datetime: datetime object with the parsed time.
    """
    data = log_line.split(" ")
    (year, month, day) = data[0].split("/")
    (hour, minute, second) = data[1].split(":")
    log_time = datetime(year=int(year), month=int(month), day=int(day), hour=int(hour), minute=int(minute),
                        second=int(second))
    return log_time
