'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/active-response/#active-response
'''
import sys
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH, ACTIVE_RESPONSE_LOG_PATH
from wazuh_testing.modules.execd.active_response import patterns as ar_patterns
from wazuh_testing.modules.execd import patterns as execd_paterns
from wazuh_testing.modules.execd.configuration import EXECD_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_execd_firewall_drop.yaml')
config_path = Path(CONFIGS_PATH, 'config_run_active_response.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Test internal options and configurations.
local_internal_options = {EXECD_DEBUG: '2'}
daemons_handler_configuration = {'all_daemons': True}
ar_conf = 'firewall-drop5 - firewall-drop - 5'


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_execd_firewall_drop(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                             set_wazuh_configuration, configure_ar_conf, remoted_simulator, authd_simulator,
                             daemons_handler, send_execd_message):
    '''
    description: Check if 'firewall-drop' command of 'active response' is executed correctly.
                 For this purpose, a simulated agent is used and the 'active response'
                 is sent to it. This response includes an IP address that must be added
                 and removed from 'iptables', the Linux firewall.

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
        - configure_ar_conf:
            type: fixture
            brief: Set the Active Response configuration.
        - remoted_simulator:
            type: fixture
            brief: Starts an RemotedSimulator instance for the test function.
        - authd_simulator:
            type: fixture
            brief: Starts an AuthdSimulator instance for the test function.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - send_execd_message:
            type: fixture
            brief: Send an execd message to the agent using RemotedSimulator.

    assertions:
        - Check the expected error is raised when it supposed to fail.
        - Check execd is executed correctly.
        - Check the firewall-drop program is used.
        - Check the firewall rule is added and deleted with correct scrip.
    input_description:
        - The `cases_execd_firewall_drop.yaml` file provides the test cases.
    '''
    ar_monitor = FileMonitor(ACTIVE_RESPONSE_LOG_PATH)
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    if error_message := test_metadata.get('expected_error'):
        callback = generate_callback(error_message)
        ar_monitor.start(callback=callback)
        assert ar_monitor.callback_result, 'AR `firewall-drop` did not fail.'
        return

    wazuh_log_monitor.start(callback=generate_callback(execd_paterns.EXECD_EXECUTING_COMMAND))
    assert wazuh_log_monitor.callback_result, 'Execd `executing` command log not raised.'

    ar_monitor.start(callback=generate_callback(ar_patterns.ACTIVE_RESPONSE_FIREWALL_DROP))
    assert ar_monitor.callback_result, 'AR `firewall-drop` program not used.'

    ar_monitor.start(callback=generate_callback(ar_patterns.ACTIVE_RESPONSE_ADD_COMMAND))
    assert ar_monitor.callback_result, 'AR `add` command not executed.'
    assert '"srcip":"3.3.3.3"' in ar_monitor.callback_result, 'AR `srcip` value is not correct.'

    ar_monitor.start(callback=generate_callback(ar_patterns.ACTIVE_RESPONSE_DELETE_COMMAND))
    assert ar_monitor.callback_result, 'AR `delete` command not executed.'
