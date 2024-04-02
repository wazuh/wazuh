'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the Syscollector events, which are processed by
       the `wazuh-analysisd` daemon, generates appropriate alerts based on the
       information contained in the delta.


components:
    - analysisd

suite: syscollector

targets:
    - manager

daemons:
    - wazuh-analysisd

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html\
        #using-syscollector-information-to-trigger-alerts
'''
import json
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH
from wazuh_testing.constants.paths.sockets import ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.modules.analysisd import utils, configuration as analysisd_config
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import configuration

from . import TEST_CASES_PATH, RULES_SAMPLE_PATH

pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration and cases data.
test_cases_path = Path(TEST_CASES_PATH, 'cases_syscollector.yaml')

# Test configurations.
test_configuration, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)

# Test internal options.
local_internal_options = {analysisd_config.ANALYSISD_DEBUG: '2'}

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Test variables.
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]

receiver_sockets = None  # Set in the fixtures


# Test function.
@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_cases_ids)
def test_syscollector_events(test_metadata, configure_local_internal_options, mock_agent_module, prepare_custom_rules_file,
                             daemons_handler, wait_for_analysisd_startup, connect_to_sockets):
    '''
    description: Check if Analysisd handle Syscollector deltas properly by generating alerts.

    wazuh_min_version: 4.4.0

    tier: 2

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - mock_agent_module:
            type: fixture
            brief: Create mock agent and get agent_id.
        - prepare_custom_rules_file:
            type: fixture
            brief: Copies custom rules_file before test, deletes after test.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_analysisd_startup:
            type: fixture
            brief: Wait until analysisd is ready.
        - connect_to_sockets:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.

    assertions:
        - Verify that specific syscollector deltas trigger specific custom alert with certain values.

    input_description:
        Input dataset (defined as event_header + event_payload in syscollector.yaml)
        cover, in most of the cases, INSERTED, MODIFIED and DELETED deltas
        for each of the available scan; osinfo, hwinfo, processes, packages, network_interface,
        network_address, network_protocol, ports and hotfixes.

    expected_output:
        Expected output (defined as alert_expected_values in syscollector.yaml)

    tags:
        - rules
    '''

    # Get mock agent_id to create syscollector header
    agent_id = mock_agent_module
    event_header = f"d:[{agent_id}] {test_metadata['event_header']}"

    # Add agent_id alert check
    alert_expected_values = test_metadata['alert_expected_values']
    alert_expected_values['agent.id'] = agent_id

    # Create full message by header and payload concatenation
    test_msg = event_header + test_metadata['event_payload']

    # Send delta to analysisd queue
    receiver_sockets[0].send(test_msg)

    # Set callback according to stage parameters
    alert_callback = utils.CallbackWithContext(utils.callback_check_alert, alert_expected_values)

    # Start monitor
    log_monitor = file_monitor.FileMonitor(ALERTS_JSON_PATH)
    log_monitor.start(callback=alert_callback, timeout=20)

    # Check that expected log appears for rules if_sid field being invalid
    assert log_monitor.callback_result
