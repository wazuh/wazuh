'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Integratord manages Wazuh integrations with other applications such as Yara or Slack, by feeding
the integrated aplications with the alerts located in alerts.json file. This test module aims to validate that
given a specific alert, the expected response is recieved, depending if it is a valid/invalid json alert, an
overlong alert (64kb+) or what happens when it cannot read the file because it is missing.

components:
    - integratord

suite: test_integratord

targets:
    - manager

daemons:
    - wazuh-integratord

os_platform:
    - Linux

os_version:
    - Centos 8
    - Ubuntu Focal

references:
    - https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html#slack
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html

pytest_args:
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - slack
'''
import pytest
import time
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing import session_parameters
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON, WAZUH_DB_DAEMON, INTEGRATOR_DAEMON
from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH, WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd.configuration import ANALYSISD_DEBUG
from wazuh_testing.modules.integratord.configuration import INTEGRATORD_DEBUG
from wazuh_testing.modules.integratord.patterns import INTEGRATORD_THIRD_PARTY_RESPONSE, INTEGRATORD_INODE_CHANGED, \
                                                       INTEGRATORD_INVALID_ALERT_READ, INTEGRATORD_OVERLONG_ALERT_READ
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.commands import run_local_command_returning_output
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.file import copy, remove_file


# Marks
pytestmark = [pytest.mark.server]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_alerts_reading.yaml')
test1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_integratord_change_inode_alert.yaml')
test2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_integratord_read_valid_json_alerts.yaml')
test3_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_integratord_read_invalid_json_alerts.yaml')

# Configurations
test1_configuration, test1_metadata, test1_cases_ids = get_test_cases_data(test1_cases_path)
test2_configuration, test2_metadata, test2_cases_ids = get_test_cases_data(test2_cases_path)
test3_configuration, test3_metadata, test3_cases_ids = get_test_cases_data(test3_cases_path)

test1_configuration = load_configuration_template(test_configuration_path, test1_configuration, test1_metadata)
test2_configuration = load_configuration_template(test_configuration_path, test2_configuration, test2_metadata)
test3_configuration = load_configuration_template(test_configuration_path, test3_configuration, test3_metadata)

# Variables
TIME_TO_DETECT_FILE = 2
TEMP_FILE_PATH = ALERTS_JSON_PATH + '.tmp'
daemons_handler_configuration = {'daemons': [INTEGRATOR_DAEMON, WAZUH_DB_DAEMON, ANALYSISD_DAEMON]}
local_internal_options = {INTEGRATORD_DEBUG: '2', ANALYSISD_DEBUG: '1', MONITORD_ROTATE_LOG: '0'}


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test1_configuration, test1_metadata), ids=test1_cases_ids)
def test_integratord_change_json_inode(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                                       configure_local_internal_options, daemons_handler, wait_for_integratord_start):
    '''
    description: Check that wazuh-integratord detects a change in the inode of the alerts.json and continues reading
                 alerts.

    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate Wazuh's logs.
            - Configure internal options.
            - Restart the daemons defined in `daemons_handler_configuration`.
            - Wait for the restarted modules to start correctly.
        - test:
            - Wait until integratord is ready to read alerts.
            - Insert an alert in the `alerts.json` file.
            - Check if the alert was received by Slack.
            - Replace the `alerts.json` file while wazuh-integratord is reading it.
            - Wait for the inode change to be detected by wazuh-integratord.
            - Check if wazuh-integratord detects that the file's inode has changed.
            - Insert an alert in the `alerts.json` file.
            - Check if the alert is processed.
            - Check alert was received by Slack.
        - teardown:
            - Truncate Wazuh's logs.
            - Restore initial configuration, both `ossec.conf` and `local_internal_options.conf`.

    wazuh_min_version: 4.3.5

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_integratord_start:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `configuration_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_json_alerts` file provides the test cases.

    expected_output:
        - r'.+wazuh-integratord.*DEBUG: jqueue_next.*Alert file inode changed.*'
        - r'.+wazuh-integratord.*Processing alert.*'
        - r'.+wazuh-integratord.*<Response [200]>'
    '''
    wazuh_monitor = FileMonitor(WAZUH_LOG_PATH)
    command = f"echo '{test_metadata['alert_sample']}' >> {ALERTS_JSON_PATH}"

    # Wait until integratord is ready to read alerts
    time.sleep(TIME_TO_DETECT_FILE)

    # Insert a new alert
    run_local_command_returning_output(command)

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_THIRD_PARTY_RESPONSE), timeout=session_parameters.default_timeout)

    # Check that expected log appears
    assert wazuh_monitor.callback_result

    # Change file to change inode
    copy(ALERTS_JSON_PATH, TEMP_FILE_PATH)
    remove_file(ALERTS_JSON_PATH)
    copy(TEMP_FILE_PATH, ALERTS_JSON_PATH)

    # Wait for Inode change to be detected
    # The `integratord` library tries to read alerts from the file every 1 second. So, the test waits 1 second + 1
    # until the file is reloaded.
    time.sleep(TIME_TO_DETECT_FILE)

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_INODE_CHANGED), timeout=session_parameters.default_timeout)

    # Check that expected log appears
    assert wazuh_monitor.callback_result

    # Insert a new alert
    run_local_command_returning_output(command)

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_THIRD_PARTY_RESPONSE), timeout=session_parameters.default_timeout)

    # Check that expected log appears
    assert wazuh_monitor.callback_result


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test2_configuration, test2_metadata), ids=test2_cases_ids)
def test_integratord_read_valid_alerts(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                                       configure_local_internal_options, daemons_handler, wait_for_integratord_start):
    '''
    description: Check that when a given alert is inserted into alerts.json, integratord works as expected. In case
    of a valid alert, a slack integration alert is expected in the alerts.json file.

    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate Wazuh's logs.
            - Configure internal options.
            - Restart the daemons defined in `daemons_handler_configuration`.
            - Wait for the restarted modules to start correctly.
        - test:
            - Insert a valid alert in the alerts.json file.
            - Check if the alert was received by Slack correctly (HTTP response status code: 200)
        - teardown:
            - Truncate Wazuh's logs.
            - Restore initial configuration, both `ossec.conf` and `local_internal_options.conf`.

    wazuh_min_version: 4.3.7

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_integratord_start:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `configuration_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_valid_json_alerts` file provides the test cases.

    expected_output:
        - r'.+wazuh-integratord.*alert_id.*\"integration\": \"slack\".*'
    '''
    sample = test_metadata['alert_sample']
    wazuh_monitor = FileMonitor(WAZUH_LOG_PATH)

    run_local_command_returning_output(f"echo '{sample}' >> {ALERTS_JSON_PATH}")

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_THIRD_PARTY_RESPONSE), timeout=session_parameters.default_timeout)

    # Check that expected log appears
    assert wazuh_monitor.callback_result


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test3_configuration, test3_metadata), ids=test3_cases_ids)
def test_integratord_read_invalid_alerts(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                                         configure_local_internal_options, daemons_handler, wait_for_integratord_start):
    '''
    description: Check that when a given alert is inserted into alerts.json, integratord works as expected. If the alert
                 is invalid, broken, or overlong a message will appear in the ossec.log file.

    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate Wazuh's logs.
            - Configure internal options.
            - Restart the daemons defined in `daemons_handler_configuration`.
            - Wait for the restarted modules to start correctly.
        - test:
            - Insert an invalid alert in the alerts.json file.
            - Check if wazuh-integratord process the alert and report an error.
        - teardown:
            - Truncate Wazuh's logs.
            - Restore initial configuration, both `ossec.conf` and `local_internal_options.conf`.

    wazuh_min_version: 4.3.7

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_integratord_start:
            type: fixture
            brief: Detect the start of the Integratord module in the ossec.log

    assertions:
        - Verify the expected response with for a given alert is recieved

    input_description:
        - The `configuration_integratord_read_json_alerts.yaml` file provides the module configuration for this test.
        - The `cases_integratord_read_invalid_json_alerts` file provides the test cases.

    expected_output:
        - r'.+wazuh-integratord.*WARNING: Invalid JSON alert read.*'
        - r'.+wazuh-integratord.*WARNING: Overlong JSON alert read.*'

    '''
    sample = test_metadata['alert_sample']
    wazuh_monitor = FileMonitor(WAZUH_LOG_PATH)

    if test_metadata['alert_type'] == 'invalid':
        callback = INTEGRATORD_INVALID_ALERT_READ
    else:
        callback = INTEGRATORD_OVERLONG_ALERT_READ
        # Add 90kb of padding to alert to make it go over the allowed value of 64KB.
        padding = "0" * 90000
        sample = sample.replace("padding_input", "agent_" + padding)

    run_local_command_returning_output(f"echo '{sample}' >> {ALERTS_JSON_PATH}")

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(callback), timeout=session_parameters.default_timeout)

    # Check that expected log appears
    assert wazuh_monitor.callback_result
