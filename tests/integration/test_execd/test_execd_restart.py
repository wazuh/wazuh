'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Active responses execute a script in response to the triggering of specific alerts based
       on the alert level or rule group. These tests will check if the 'active responses',
       which are executed by the 'wazuh-execd' daemon via scripts, run correctly.

components:
    - execd

suite: execd

targets:
    - agent

daemons:
    - wazuh-analysisd
    - wazuh-execd

os_platform:
    - linux
    - Windows

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
    - Windows 11
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/active-response/#active-response
'''
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import ACTIVE_RESPONSE_LOG_PATH, WAZUH_LOG_PATH
from wazuh_testing.modules.active_response.patterns import ACTIVE_RESPONSE_RESTART_WAZUH
from wazuh_testing.modules.execd import EXECD_DEBUG_CONFIG
from wazuh_testing.modules.execd.patterns import EXECD_SHUTDOWN_RECEIVED
from wazuh_testing.tools.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data

from . import TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.agent, pytest.mark.tier(level=1)]

# Configuration and cases data.
cases_path = Path(TEST_CASES_PATH, 'cases_execd_restart.yaml')

# Test configurations.
_, test_metadata, cases_ids = get_test_cases_data(cases_path)

# Test internal options.
local_internal_options = EXECD_DEBUG_CONFIG
# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}
# Test Active Response configuration
active_response_configuration = 'restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0'


# Test Function.
@pytest.mark.parametrize('test_metadata', test_metadata, ids=cases_ids)
def test_execd_restart(test_metadata, configure_local_internal_options, truncate_monitored_files,
                       active_response_configuration, daemons_handler, send_execd_message):
    '''
    description: Check if 'restart-wazuh' command of 'active response' is executed correctly.
                 For this purpose, a simulated agent is used, to which the active response is sent.
                 This response includes the order to restart the Wazuh agent,
                 which must restart after receiving this response.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - truncate_monitored_files:
            type: fixture
            brief: Validate the Wazuh version.
        - active_response_configuration:
            type: fixture
            brief: Set the Active Response configuration.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - send_execd_message:
            type: fixture
            brief: Send an execd message to the agent using RemotedSimulator.

    assertions:

    input_description: 

    expected_output:

    tags:
        - simulator
    '''
    # Instantiate the monitors.
    ar_monitor = FileMonitor(ACTIVE_RESPONSE_LOG_PATH)
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # If the command is invalid, check it raised the warning.
    if error_message := test_metadata.get('expected_error'):
        callback = generate_callback(error_message)
        ar_monitor.start(callback=callback)
        assert ar_monitor.callback_result, 'AR `wazuh-restart` did not fail.'
        return

    # Check the shutdown received log is raised.
    wazuh_log_monitor.start(callback=generate_callback(EXECD_SHUTDOWN_RECEIVED))
    assert wazuh_log_monitor.callback_result, 'Execd `shutdown` log not raised.'

    # Wait and check the add command to be executed.
    ar_monitor.start(callback=generate_callback(ACTIVE_RESPONSE_RESTART_WAZUH))
    assert  ar_monitor.callback_result, 'AR `restart-wazuh` program not used.'
