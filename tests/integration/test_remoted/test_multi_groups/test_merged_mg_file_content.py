"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time
import os
import hashlib

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.constants.paths.configurations import SHARED_CONFIGURATIONS_PATH
from wazuh_testing.constants.paths.variables import VAR_MULTIGROUPS_PATH
from wazuh_testing.utils import file

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_file_actions.yaml')
config_path = Path(CONFIGS_PATH, 'config_multi_groups.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


def manipulate_file(action, file_path):
    if action == 'create':
        f = open(file_path, "w")
        f.close()
    else:
        file.remove_file(file_path)


# Variables
groups_list = ['default', 'testing_group']
mg_name = hashlib.sha256(','.join(groups_list).encode()).hexdigest()[:8]
mg_folder_path = os.path.join(VAR_MULTIGROUPS_PATH, mg_name)
merged_mg_file = os.path.join(mg_folder_path, 'merged.mg')
shared_file_name = 'testing_file'
shared_file_path = os.path.join(SHARED_CONFIGURATIONS_PATH, 'testing_group', shared_file_name)
expected_line = f"!0 {shared_file_name}"
wait_time = 3


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_merged_mg_file_content(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, prepare_environment):

    '''
    description: Check the content of the merged.mg file that wazuh-remoted compiles for multi-groups.

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
        - simulate_agents
            type: fixture
            brief: create agents
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.

    '''

    log_monitor = FileMonitor(merged_mg_file)
    action = test_metadata['action']
    manipulate_file(action, shared_file_path)
    time.sleep(wait_time)
    if action == 'created':
        if os.path.exists(merged_mg_file):
            log_monitor.start(callback=generate_callback(regex="{expected_line}", replacement={"expected_line":expected_line}))
            assert log_monitor.callback_result
        else:
            raise FileNotFoundError(f"The file: {merged_mg_file} was not created.")
