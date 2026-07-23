"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

from . import CONFIGS_PATH, TEST_CASES_PATH

from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.modules.remoted import patterns

# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_shared_config_invalid.yaml')
config_path = Path(CONFIGS_PATH, 'config_shared_config_distribution.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_shared_config_distribution_invalid(test_configuration, test_metadata, configure_local_internal_options,
                                            truncate_monitored_files, set_wazuh_configuration,
                                            restart_wazuh_expect_error):
    '''
    description: Check that invalid 'shared_config_batch_size' and 'shared_config_interval' values are rejected
                 by 'wazuh-manager-remoted', which logs a warning and falls back to the default value without
                 aborting the startup (the option is not fatal).

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration applied to ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - restart_wazuh_expect_error:
            type: fixture
            brief: Restart service when expected error is None, once the test finishes stops the daemons.

    assertions:
        - Verify that a warning about the invalid element is logged.
    '''
    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=generate_callback(patterns.INVALID_VALUE_FOR_ELEMENT))
    assert log_monitor.callback_result, \
        f"Expected warning for invalid '{test_metadata['invalid_element']}' was not found."
