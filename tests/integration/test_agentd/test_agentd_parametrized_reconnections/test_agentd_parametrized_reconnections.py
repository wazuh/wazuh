'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

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
import pytest
from pathlib import Path
import sys
import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.modules.agentd.patterns import * 
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.services import control_service

from . import CONFIGS_PATH, TEST_CASES_PATH
from .. import wait_enrollment, wait_connect, wait_server_rollback, add_custom_key, kill_server

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_reconnection_protocol.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}
local_internal_options.update({AGENTD_TIMEOUT: '5'})

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
                             truncate_monitored_files):
    '''
    description: Check how the agent behaves when there are delays between connection
                 attempts to the server. For this purpose, different values for
                 'max_retries' and 'retry_interval' parameters are tested.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - start_authd:
            type: fixture
            brief: Enable the 'wazuh-authd' daemon to accept connections and perform enrollments.
        - stop_agent:
            type: fixture
            brief: Stop Wazuh's agent.
        - set_keys:
            type: fixture
            brief: Write to 'client.keys' file the agent's enrollment details.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - teardown:
            type: fixture
            brief: Stop the Remoted server

    assertions:
        - Verify that when the 'wazuh-agentd' daemon initializes, it connects to
          the 'wazuh-remoted' daemon of the manager before reaching the maximum number of attempts.
        - Verify the successful enrollment of the agent if the auto-enrollment option is enabled.
        - Verify that the rollback feature of the server works correctly.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Valid key received'
        - r'Trying to connect to server'
        - r'Unable to connect to any server'

    tags:
        - simulator
        - ssl
        - keys
    '''
    DELTA = 1
    RECV_TIMEOUT = 5
    ENROLLMENT_SLEEP = 20
    LOG_TIMEOUT = 30
    import pdb; pdb.set_trace()

    # Stop target Agent
    control_service('stop')

    # Add dummy key in order to communicate with RemotedSimulator
    add_custom_key()
    
    # Start service
    control_service('start')

    # Start RemotedSimulator
    remoted_server = RemotedSimulator(protocol = test_metadata['protocol'])
    remoted_server.start()

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # 2 Check for unsuccessful connection retries in Agentd initialization
    interval = test_metadata['retry_interval']
    if test_metadata['protocol'] == 'udp':
        interval += RECV_TIMEOUT

    if test_metadata['enroll'] == 'yes':
        total_retries = test_metadata['max_retries'] + 1
    else:
        total_retries = test_metadata['max_retries']

    for retry in range(total_retries):
        # 3 If auto enrollment is enabled, retry check enrollment and retries after that
        if test_metadata['enroll'] == 'yes' and retry == total_retries - 1:
            # Wait successfully enrollment
            wait_enrollment()
            first_found_log_time = time.time()
            # Next retry will be after enrollment sleep
            interval = ENROLLMENT_SLEEP
    
        wazuh_log_monitor.start(timeout = interval + LOG_TIMEOUT, callback=callbacks.generate_callback(AGENTD_CONNECTED_TO_SERVER))
        second_found_log_time = time.time()
        assert (wazuh_log_monitor.callback_result != None), f'Connected to the server message not found'
        
        if retry > 0:
            delta_retry = actual_retry - last_log
            # Check if delay was applied
            assert delta_retry >= timedelta(seconds=interval - DELTA), "Retries to quick"
            assert delta_retry <= timedelta(seconds=interval + DELTA), "Retries to slow"
        last_log = actual_retry

    # 4 Wait for server rollback
    wait_server_rollback()

    # 5 Check amount of retries and enrollment
    (connect, enroll) = count_retry_mesages()
    assert connect == total_retries
    if test_metadata['enroll'] == 'yes':
        assert enroll == 1
    else:
        assert enroll == 0

    kill_server(remoted_server)