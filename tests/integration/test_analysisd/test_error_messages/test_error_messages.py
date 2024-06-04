'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon receives the log messages and compares them to the rules.
       It then creates an alert when a log message matches an applicable rule.
       Specifically, these tests will check if the 'wazuh-analysisd' daemon handles correctly
       the invalid events it receives.

components:
    - analysisd

suite: error_messages

targets:
    - manager

daemons:
    - wazuh-analysisd
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

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - events
'''
import pytest
import time

from pathlib import Path

from wazuh_testing import session_parameters
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.sockets import ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.modules.analysisd import patterns, configuration as analysisd_config
from wazuh_testing.modules.monitord import configuration as monitord_config
from wazuh_testing.tools import mitm
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import configuration, callbacks

from . import TEST_CASES_PATH

pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration and cases data.
test_cases_path = Path(TEST_CASES_PATH, 'cases_error_messages.yaml')

# Test configurations.
_, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)

# Test internal options.
local_internal_options = {analysisd_config.ANALYSISD_DEBUG: '2', monitord_config.MONITORD_ROTATE_LOG: '0'}

# Test variables.
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]

mitm_analysisd = mitm.ManInTheMiddle(address=ANALYSISD_QUEUE_SOCKET_PATH, family='AF_UNIX', connection_protocol='UDP')
monitored_sockets_params = [(ANALYSISD_DAEMON, mitm_analysisd, True)]

receiver_sockets, monitored_sockets = None, None  # Set in the fixtures


# Test function.
@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_cases_ids)
def test_error_messages(test_metadata, configure_local_internal_options, configure_sockets_environment_module,
                       connect_to_sockets_module, wait_for_analysisd_startup, truncate_monitored_files):
    '''
    description: Check if when the 'wazuh-analysisd' daemon socket receives a message with an invalid event,
                 it generates the corresponding error that sends to the 'wazuh-db' daemon socket.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - configure_sockets_environment_module:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Connect to a given list of sockets.
        - wait_for_analysisd_startup:
            type: fixture
            brief: Wait until the 'wazuh-analysisd' has begun and the 'alerts.json' file is created.

    assertions:
        - Verify that the errors messages generated are consistent with the events received.

    input_description: Different test cases that are contained in an external YAML file (error_messages.yaml)
                       that includes 'syscheck' events data and the expected output.

    expected_output:
        - Multiple messages (error logs) corresponding to each test case,
          located in the external input data file.

    tags:
        - errors
        - man_in_the_middle
        - wdb_socket
    '''
    receiver_sockets[0].send(test_metadata['input'])

    # Give time to log file after truncation
    time.sleep(1)

    # Start monitor
    monitor_log = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    monitor_log.start(callback=callbacks.generate_callback(patterns.ANALYSISD_ERROR_MESSAGES),
                      timeout=4*session_parameters.default_timeout)

    # Check that expected log appears
    assert monitor_log.callback_result
    assert monitor_log.callback_result[0] == test_metadata['output']
