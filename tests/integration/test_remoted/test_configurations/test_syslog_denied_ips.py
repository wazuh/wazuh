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
from wazuh_testing.utils.network import format_ipv6_long, TCP, UDP
from wazuh_testing.utils.sockets import send_message_to_syslog_socket
from wazuh_testing.modules.api import utils


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_syslog_denied_ips.yaml')
config_path = Path(CONFIGS_PATH, 'config_syslog_allowed_denied_ips.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_denied_ips_syslog(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, restart_wazuh_expect_error, get_real_configuration):

    '''
    description: Check that 'wazuh-remoted' denied connection to the specified 'denied-ips'.
                 For this purpose, it uses the configuration from test cases, check if the different errors are
                 logged correctly and check if the API retrieves the expected configuration.UJHBJJJJJJJJJJJJKKKKKKKKKKKKKKKKKKKKKK

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
    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    allowed_ips = test_metadata['allowed-ips'].split('/')
    denied_ip = test_metadata['denied-ips']
    if test_metadata['ipv6'] == 'yes':
        denied_ip = format_ipv6_long(denied_ip)

    if len(allowed_ips) > 1:
        allowed_ips_mask = allowed_ips[1]
        allowed_ips_address = allowed_ips[0]

        expected_allowed_ips_address = allowed_ips_address
        if test_metadata['ipv6'] == 'yes':
            expected_allowed_ips_address = format_ipv6_long(allowed_ips_address)
        expected_allowed_ips = expected_allowed_ips_address + '/' + allowed_ips_mask

    else:
        expected_allowed_ips = allowed_ips

    log_monitor.start(callback=generate_callback(patterns.DETECT_SYSLOG_ALLOWED_IPS,
                                                    replacement={
                                                    "syslog_ips": expected_allowed_ips}))

    send_message_to_syslog_socket(f'Feb 22 13:08:48 Remoted Syslog Denied {denied_ip}', 514, UDP)
    log_monitor.start(callback=generate_callback(patterns.MSG_SYSLOG_DENIED_IPS,
                                                    replacement={
                                                    "syslog_ips": denied_ip}))

    real_config_list = get_real_configuration

    utils.compare_config_api_response(real_config_list, 'remote')
