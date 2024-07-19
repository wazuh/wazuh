'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. There is a feature to limit the
       number of events that the manager can process, in order to allow the correct functioning of the daemon. These
       tests validate that this feature works as expected.

components:
    - analysisd

suite: analysisd

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
    - https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#if-sid
'''
import pytest
import time

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd import patterns, configuration as analysisd_config
from wazuh_testing.tools import thread_executor
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.tools.simulators import run_syslog_simulator
from wazuh_testing.utils import callbacks, configuration, file

from . import CONFIGS_PATH, TEST_CASES_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Configuration and cases data.
test_configs_path = Path(CONFIGS_PATH, 'logging_test_module', 'configuration_dropping_events.yaml')
test_cases_path = Path(TEST_CASES_PATH, 'logging_test_module', 'cases_dropping_events.yaml')

# Test configurations.
test_configuration, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)
test_configuration = configuration.load_configuration_template(test_configs_path, test_configuration, test_metadata)

# Test internal options.
local_internal_options = {analysisd_config.ANALYSISD_DEBUG: '2'}

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_dropping_events(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                         configure_local_internal_options, truncate_monitored_files, daemons_handler):
    """
    description: Check that after the event analysis block, if the events queue is full, the events are dropped.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Send events until queue is full and dropping events.
            - Check that "Queues are full and no EPS credits, dropping events" log appears in WARNING mode.
            - Wait timeframe to release the events queue usage and send an event.
            - Check that "Queues back to normal and EPS credits, no dropping events" log appears in INFO mode.
            - Send events until queue is full and dropping events.
            - Check that "Queues are full and no EPS credits, dropping events" log appears in DEBUG mode.
            - Wait timeframe to release the events queue usage and send an event.
            - Check that "Queues back to normal and EPS credits, no dropping events" log appears in DEBUG mode.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check that "Queues are full and no EPS credits, dropping events" log appears in WARNING mode.
        - Check that "Queues back to normal and EPS credits, no dropping events" log appears in INFO mode.
        - Check that "Queues are full and no EPS credits, dropping events" log appears in DEBUG mode.
        - Check that "Queues back to normal and EPS credits, no dropping events" log appears in DEBUG mode.

    input_description:
        - The `configuration_dropping_events.yaml` file provides the module configuration for this test.
        - The `cases_dropping_events.yaml` file provides the test cases.
    """
    # File monitor
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                   'protocol': test_metadata['protocol'], 'eps': test_metadata['eps'],
                                   'messages_number': test_metadata['messages_number']}

    # Run syslog simulator thread for sending events
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for dropping events WARNING log
    log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_QUEUES_FULL, {
                          'log_level': 'WARNING'
                      }))
    assert log_monitor.callback_result

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()

    # Wait until the next timeframe to release elements from the queue (as they will be processed)
    time.sleep(test_metadata['timeframe'])

    # Send 1 event more
    syslog_simulator_parameters.update({'messages_number': 1, 'eps': 1})
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for stop dropping events INFO log
    log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_QUEUES_NORMAL, {
                          'log_level': 'INFO'
                      }))
    assert log_monitor.callback_result

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()

    # Stage 2: If we continue causing this situation, the following logs must be in DEBUG
    file.truncate_file(WAZUH_LOG_PATH)

    # Run syslog simulator thread for sending events
    syslog_simulator_parameters.update({'messages_number': test_metadata['messages_number'], 'eps': test_metadata['eps']})
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for dropping events DEBUG log
    log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_QUEUES_FULL, {
                          'log_level': 'DEBUG'
                      }))
    assert log_monitor.callback_result

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()

    # Wait until the next timeframe to release elements from the queue (as they will be processed)
    time.sleep(test_metadata['timeframe'])

    # Send 1 event more
    syslog_simulator_parameters.update({'messages_number': 1, 'eps': 1})
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for stop dropping events DEBUG log
    log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_QUEUES_NORMAL, {
                          'log_level': 'DEBUG'
                      }))
    assert log_monitor.callback_result

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()
