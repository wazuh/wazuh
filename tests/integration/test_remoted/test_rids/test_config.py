"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.services import control_service
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG, REMOTED_WORKER_POOL, REMOTED_VERIFY_MSG_ID
from wazuh_testing.modules.remoted import patterns
from wazuh_testing.utils import configuration

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_config.yaml')
config_path = Path(CONFIGS_PATH, 'config_rids.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_rids_conf(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            daemons_handler, set_wazuh_configuration):

    '''
    description: Check that RIDS configuration works as expected for the following fields, `remoted.verify_msg_id` and
                 `remoted.worker_pool`. To do this, it modifies the local internal options with the test case metadata
                 and restarts Wazuh to verify that the daemon starts or not. Finally, when a correct configuration has
                 been tested, it restores the `internal_options.conf` as it was before running the test.

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
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    local_internal_options = {REMOTED_VERIFY_MSG_ID: test_metadata[REMOTED_VERIFY_MSG_ID], REMOTED_WORKER_POOL: test_metadata[REMOTED_WORKER_POOL]}
    configuration.set_local_internal_options_dict(local_internal_options)

    expected_start = test_metadata['expected_start']
    try:
        control_service('restart')
        assert expected_start, 'Expected configuration error'
    except ValueError:
        assert not expected_start, 'Start error was not expected'

    # Set default config again
    local_internal_options = {REMOTED_VERIFY_MSG_ID: 0, REMOTED_WORKER_POOL: 4}
    configuration.set_local_internal_options_dict(local_internal_options)
