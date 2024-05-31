"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import ARCHIVES_LOG_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.modules.remoted import patterns
from wazuh_testing.tools import thread_executor
from wazuh_testing.tools.simulators import run_syslog_simulator

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_syslog_msg_parser.yaml')
config_path = Path(CONFIGS_PATH, 'config_syslog_msg_parser.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

# Test variables.
SYSLOG_SIMULATOR_START_TIME = 2


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_syslog_message_parser(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, restart_wazuh_expect_error):

    '''
    description: Check if 'wazuh-remoted' can receive syslog messages through the socket.

    parameters:
        - test_configuration
            type: dict
            brief: Configuration applied to ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - restart_wazuh_expect_error
            type: fixture
            brief: Restart service when expected error is None, once the test finishes stops the daemons.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
    '''

    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                   'protocol': test_metadata['protocol'],
                                   'messages_number': test_metadata['messages_number'],
                                   'message': test_metadata['message']}

    # Run syslog simulator thread
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Wait until syslog simulator is started
    time.sleep(SYSLOG_SIMULATOR_START_TIME)

    # Read the events log data
    log_monitor = FileMonitor(ARCHIVES_LOG_PATH)

    log_monitor.start(callback=generate_callback(patterns.ARCHIVES_FULL_LOG,
                                                 replacement={
                                                    "message": test_metadata['message'],
                                                    "location": test_metadata['address']}),
                                                accumulations = test_metadata['messages_number'])

    assert log_monitor.matches == test_metadata['messages_number']

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()
