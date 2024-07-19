'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon receives the log messages and compares them to the rules.
       It then creates an alert when a log message matches an applicable rule.
       Specifically, these tests will verify if the 'wazuh-analysisd' daemon correctly handles
       'syscheck' events considered rare.

components:
    - analysisd

suite: all_syscheckd_configurations

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
import json

from pathlib import Path

from wazuh_testing import session_parameters
from wazuh_testing.constants.daemons import WAZUH_DB_DAEMON, ANALYSISD_DAEMON
from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH, ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.modules.analysisd import patterns, configuration as analysisd_config
from wazuh_testing.modules.monitord import configuration as monitord_config
from wazuh_testing.tools import mitm
from wazuh_testing.utils import configuration, callbacks

from . import TEST_CASES_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Configuration and cases data.
test_cases_path = Path(TEST_CASES_PATH, 'cases_syscheck_rare_events.yaml')

# Test configurations.
_, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)

# Test internal options.
local_internal_options = {analysisd_config.ANALYSISD_DEBUG: '2', monitord_config.MONITORD_ROTATE_LOG: '0'}

# Test variables.
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]

mitm_wdb = mitm.ManInTheMiddle(address=WAZUH_DB_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
monitored_sockets_params = [(WAZUH_DB_DAEMON, mitm_wdb, True), (ANALYSISD_DAEMON, None, None)]

receiver_sockets, monitored_sockets = None, None  # Set in the fixtures


# Test function.
@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_cases_ids)
def test_validate_rare_socket_responses(test_metadata, configure_local_internal_options, configure_sockets_environment_module,
                                        connect_to_sockets_module, wait_for_analysisd_startup):
    '''
    description: Validate each response from the 'wazuh-analysisd' daemon socket
                 to the 'wazuh-db' daemon socket using rare 'syscheck' events
                 that include weird characters.

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
            brief: Module scope version of 'connect_to_sockets_module' fixture.
        - wait_for_analysisd_startup:
            type: fixture
            brief: Wait until the 'wazuh-analysisd' has begun and the 'alerts.json' file is created.
        - test_case:
            type: list
            brief: List of tests to be performed.

    assertions:
        - Verify that the output logs are consistent with the syscheck events received.

    input_description: Different test cases that are contained in an external YAML file (syscheck_rare_events.yaml)
                       that includes 'syscheck' events data and the expected output.

    expected_output:
        - Multiple messages (event logs) corresponding to each test case,
          located in the external input data file.

    tags:
        - man_in_the_middle
        - wdb_socket
    '''
    callback = callbacks.generate_callback(patterns.ANALYSISD_QUEUE_DB_MESSSAGE)

    # Start monitor
    receiver_sockets[0].send(test_metadata['input'])
    monitored_sockets[0].start(callback=callback, timeout=session_parameters.default_timeout)

    # Check that expected message appears
    for actual, expected in zip(monitored_sockets[0].callback_result, callback(test_metadata['output'])):
        try:
            assert json.loads(actual) == json.loads(expected), 'Failed test case stage: {}'.format(test_metadata['stage'])
        except json.decoder.JSONDecodeError:
            assert actual == expected, 'Failed test case stage: {}'.format(test_metadata['stage'])
