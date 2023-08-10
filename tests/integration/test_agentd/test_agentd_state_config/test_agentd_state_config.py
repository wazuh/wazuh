'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       These tests will check if the configuration options related to the statistics file of
       the 'wazuh-agentd' daemon are working properly. The statistics files are documents that
       show real-time information about the Wazuh environment.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-agentd-state.html

tags:
    - stats_file
'''
import os
import pytest
from pathlib import Path
import sys
import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.variables import AGENTD_STATE
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.configuration import get_test_cases_data
from wazuh_testing.utils.configuration import load_configuration_template
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.services import check_if_process_is_running, control_service

from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'wazuh_state_config_tests.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)

test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}

print(test_metadata)

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_state_config(test_configuration, test_metadata, remove_state_file, set_wazuh_configuration, configure_local_internal_options,
                             truncate_monitored_files):
    
    '''
    description: Check that the 'wazuh-agentd.state' statistics file is created
                 automatically and verify that it is updated at the set intervals.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - test_case:
            type: list
            brief: List of tests to be performed.

    assertions:
        - Verify that the 'wazuh-agentd.state' statistics file has been created.
        - Verify that the 'wazuh-agentd.state' statistics file is updated at the specified intervals.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases that are contained in an external YAML file (wazuh_state_config_tests.yaml)
                       that includes the parameters and their expected responses.

    expected_output:
        - r'interval_not_found'
        - r'interval_not_valid'
        - r'file_enabled'
        - r'file_not_enabled'
    '''

    control_service('stop', 'wazuh-agentd')

    if sys.platform == WINDOWS:
        if test_metadata['agentd_ends']:
            with pytest.raises(ValueError):
                control_service('start')
            assert (test_metadata['agentd_ends']
                    is not check_if_process_is_running('wazuh-agentd'))
        else:
            control_service('start')
    else:
        control_service('start', 'wazuh-agentd')
        # Sleep enough time to Wazuh load agent.state_interval configuration and
        # boot wazuh-agentd
        time.sleep(1) 
        assert (test_metadata['agentd_ends']
                    is not check_if_process_is_running('wazuh-agentd'))
    
    # Check if the test requires checking state file existence
    if test_metadata['state_file_exist']:
        time.sleep(int(test_metadata['local_internal_options']['agent.state_interval']))
    assert test_metadata['state_file_exist'] == os.path.exists(AGENTD_STATE)

    # Follow ossec.log to find desired messages by a callback
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    wazuh_log_monitor.start(callback=callbacks.generate_callback(str(test_metadata['event_monitor'])))
    
    assert (wazuh_log_monitor.callback_result != None), f'Error invalid configuration event not detected'
