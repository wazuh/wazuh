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
from datetime import datetime, timedelta
import os
import platform
import pytest
from time import sleep

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from wazuh_testing.agent import CLIENT_KEYS_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

params = [
    # Different parameters on UDP
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 1, 'RETRY_INTERVAL': 1, 'ENROLL': 'no'},
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 5, 'RETRY_INTERVAL': 5, 'ENROLL': 'no'},
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 10, 'RETRY_INTERVAL': 4, 'ENROLL': 'no'},
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 3, 'RETRY_INTERVAL': 12, 'ENROLL': 'no'},
    # Different parameters on TCP
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 3, 'RETRY_INTERVAL': 3, 'ENROLL': 'no'},
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 5, 'RETRY_INTERVAL': 5, 'ENROLL': 'no'},
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 10, 'RETRY_INTERVAL': 10, 'ENROLL': 'no'},
    # Enrollment enabled
    {'PROTOCOL': 'udp', 'MAX_RETRIES': 2, 'RETRY_INTERVAL': 2, 'ENROLL': 'yes'},
    {'PROTOCOL': 'tcp', 'MAX_RETRIES': 5, 'RETRY_INTERVAL': 5, 'ENROLL': 'yes'},
]

case_ids = [f"{x['PROTOCOL']}_max-retry={x['MAX_RETRIES']}_interval={x['RETRY_INTERVAL']}_enroll={x['ENROLL']}".lower()
            for x in params]

metadata = params
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)
log_monitor_paths = []
receiver_sockets_params = []
monitored_sockets_params = []
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
authd_server = AuthdSimulator('127.0.0.1', key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)
remoted_server = None

# Tests
"""
This test covers different options of delays between server connection attempts:
-Different values of max_retries parameter
-Different values of retry_interval parameter
-UDP/TCP connection
-Enrollment between retries
"""

def test_agentd_parametrized_reconnections(configure_authd_server, start_authd, stop_agent, set_keys,
                                           configure_environment, get_configuration, teardown):
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

    global remoted_server

    PROTOCOL = protocol = get_configuration['metadata']['PROTOCOL']
    RETRIES = get_configuration['metadata']['MAX_RETRIES']
    INTERVAL = get_configuration['metadata']['RETRY_INTERVAL']
    ENROLL = get_configuration['metadata']['ENROLL']

    control_service('stop')
    clean_logs()
    log_monitor = FileMonitor(LOG_FILE_PATH)
    remoted_server = RemotedSimulator(protocol=PROTOCOL, client_keys=CLIENT_KEYS_PATH)
    control_service('start')

    # 2 Check for unsuccessful connection retries in Agentd initialization
    interval = INTERVAL
    if PROTOCOL == 'udp':
        interval += RECV_TIMEOUT

    if ENROLL == 'yes':
        total_retries = RETRIES + 1
    else:
        total_retries = RETRIES

    for retry in range(total_retries):
        # 3 If auto enrollment is enabled, retry check enrollment and retries after that
        if ENROLL == 'yes' and retry == total_retries - 1:
            # Wait successfully enrollment
            try:
                log_monitor.start(timeout=20, callback=wait_enrollment)
            except TimeoutError as err:
                raise AssertionError("No successful enrollment after retries!")
            last_log = parse_time_from_log_line(log_monitor.result())

            # Next retry will be after enrollment sleep
            interval = ENROLLMENT_SLEEP

        try:
            log_monitor.start(timeout=interval + LOG_TIMEOUT, callback=wait_connect)
        except TimeoutError as err:
            raise AssertionError("Connection attempts took too much!")
        actual_retry = parse_time_from_log_line(log_monitor.result())
        if retry > 0:
            delta_retry = actual_retry - last_log
            # Check if delay was applied
            assert delta_retry >= timedelta(seconds=interval - DELTA), "Retries to quick"
            assert delta_retry <= timedelta(seconds=interval + DELTA), "Retries to slow"
        last_log = actual_retry

    # 4 Wait for server rollback
    try:
        log_monitor.start(timeout=30, callback=wait_server_rollback)
    except TimeoutError as err:
        raise AssertionError("Server rollback took too much!")

    # 5 Check amount of retries and enrollment
    (connect, enroll) = count_retry_mesages()
    assert connect == total_retries
    if ENROLL == 'yes':
        assert enroll == 1
    else:
        assert enroll == 0

    return