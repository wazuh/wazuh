"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import netifaces

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

from . import CONFIGS_PATH, TEST_CASES_PATH

from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.modules.remoted import patterns
from wazuh_testing.modules.api import utils

# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_valid_local_ip.yaml')
config_path = Path(CONFIGS_PATH, 'config_valid_local_ip.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)

#overwrite metadata and configuration dynamically
def get_dynamic_data():
    array_interfaces_ip = []
    final_metadata = []
    final_configuration = []
    network_interfaces = netifaces.interfaces()

    for interface in network_interfaces:
        try:
            ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            array_interfaces_ip.append(ip)
        except KeyError:
            pass
    import copy

    for ip in array_interfaces_ip:
        test_configuration[0]['LOCAL_IP'] = ip
        test_metadata[0]['local_ip'] = ip
        new_test_metadata = copy.deepcopy(test_metadata)
        new_test_configuration = copy.deepcopy(test_configuration)
        final_metadata.append(new_test_metadata[0])
        final_configuration.append(new_test_configuration[0])

    return final_configuration, final_metadata

final_configuration, final_metadata = get_dynamic_data()
test_configuration = load_configuration_template(config_path, final_configuration, final_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, final_metadata))
def test_local_ip_valid(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, restart_wazuh_expect_error, get_real_configuration):
    '''
    description: Check if 'wazuh-remoted' can set 'local_ip' using different IPs without errors.
                 For this purpose, it uses the configuration from test cases and check if the cfg in ossec.conf matches
                 with the API response.

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
        - get_real_configuration
            type: fixture
            brief: get elements from section config and convert  list to dict
    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    real_config_list = get_real_configuration

    utils.compare_config_api_response(real_config_list, 'remote')
