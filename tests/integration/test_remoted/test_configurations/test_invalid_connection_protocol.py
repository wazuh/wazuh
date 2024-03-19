"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.constants.paths.configurations import WAZUH_CONF_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

from . import CONFIGS_PATH, TEST_CASES_PATH

from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.modules.remoted import patterns
from wazuh_testing.modules.api import utils

# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_invalid_connection_protocol.yaml')
config_path = Path(CONFIGS_PATH, 'config_invalid_connection.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_invalid_connection_protocol(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, restart_wazuh_expect_error, protocols_list_to_str_upper_case, get_real_configuration):

    '''
    description: Check if 'wazuh-remoted' sets properly prococol values.
                 First of all, it selects a valid protocol to be used. If a pair of protocols is provided, in case one
                 of them is invalid, it should be used the valid protocol. Otherwise, if none of them is valid, TCP
                 should be used(For a syslog connection if more than one protocol is provided only TCP should be used).
                 For this purpose, it selects a valid protocol(within a proper checking), checks if remoted is properly
                 started and if the configuration is the same as the API reponse.

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
        - daemons_handler:
            type: fixture
            brief: Starts/Restarts the daemons indicated in `daemons_handler_configuration` before each test,
                   once the test finishes, stops the daemons.
        - restart_wazuh_expect_error
            type: fixture
            brief: Restart service when expected error is None, once the test finishes stops the daemons.
        - protocols_list_to_str_upper_case
            type: fixture
            brief: convert valid_protocol list to comma separated uppercase string
        - get_real_configuration
            type: fixture
            brief: get elements from section config and convert  list to dict
    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    #detect invalid protocol
    for invalid_protocol in test_metadata['invalid_protocol']:
        log_monitor.start(callback=generate_callback(regex=patterns.IGNORED_INVALID_PROTOCOL, replacement={"protocol": invalid_protocol}))
        assert invalid_protocol in log_monitor.callback_result

    #detect if warning message is created when no valid protocol is provided.
    if len(test_metadata['valid_protocol']) == 0:
        log_monitor.start(callback=generate_callback(patterns.ERROR_GETTING_PROTOCOL))
        assert log_monitor.callback_result
    elif len(test_metadata['valid_protocol']) == 1:
        protocol_valid_upper = protocols_list_to_str_upper_case
        log_monitor.start(callback=generate_callback(patterns.DETECT_REMOTED_STARTED,
                                                     replacement={
                                                        "port": test_metadata['port'],
                                                        "protocol_valid_upper": protocol_valid_upper,
                                                        "connection": test_metadata['connection']}))
        assert log_monitor.callback_result

    else:
        used_protocol = protocols_list_to_str_upper_case
        if test_metadata['connection'] == 'syslog':
            used_protocol = 'TCP'

        log_monitor.start(callback=generate_callback(patterns.DETECT_REMOTED_STARTED,
                                                     replacement={
                                                        "port": test_metadata['port'],
                                                        "protocol_valid_upper": used_protocol,
                                                        "connection": test_metadata['connection']}))
        assert log_monitor.callback_result

        real_config_list = get_real_configuration

        utils.compare_config_api_response(real_config_list, 'remote')
