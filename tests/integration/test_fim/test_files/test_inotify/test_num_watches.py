'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will verify that FIM detects
       the correct 'inotify watches' number when renaming and deleting a monitored directory.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_inotify

targets:
    - agent

daemons:
    - wazuh-syscheckd

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_inotify
'''

from pathlib import Path

import pytest
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils import file
from wazuh_testing.modules.fim.patterns import NUM_INOTIFY_WATCHES

from . import TEST_CASES_PATH, CONFIGS_PATH

# Marks

# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_num_watches.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_num_watches.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2 }

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_num_watches(test_configuration, test_metadata, configure_local_internal_options,
                             truncate_monitored_files, set_wazuh_configuration, folder_to_monitor, daemons_handler):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects the correct number of 'inotify watches' when
                 renaming and deleting a monitored directory. For this purpose, the test will create and monitor
                 a folder with two subdirectories. Once FIM is started, it will verify that three watches have
                 been detected. If these 'inotify watches' are correct, the test will make file operations on
                 the monitored folder or do nothing. Finally, it will verify that the 'inotify watches' number
                 detected in the generated FIM events is correct.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case data.
        - configure_local_internal_options:
            type: fixture
            brief: Set local_internal_options.conf file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - folder_to_monitor:
            type: str
            brief: Folder created for monitoring.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that FIM detects that the 'inotify watches' number is correct
          before and after modifying the monitored folder.
        - Verify that FIM adds 'inotify watches' when monitored directories have been removed or renamed, and
          they are restored.

    input_description: A test case (num_watches_conf) is contained in external YAML file (cases_num_watches.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Folders monitored with real-time engine'

    tags:
        - watches
    '''


    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    wazuh_log_monitor.start(timeout=60, callback=generate_callback(NUM_INOTIFY_WATCHES))
    watches = int(wazuh_log_monitor.callback_result[0]) if wazuh_log_monitor.callback_result else 0

    assert watches == test_metadata['watches_before']

    if test_metadata['action'] == 'delete':
        file.delete_path_recursively(test_metadata['folder_to_monitor'])
    elif test_metadata['action'] == 'rename':
        file.rename(test_metadata['folder_to_monitor'], '/changed_name')

    wazuh_log_monitor.start(timeout=60, callback=generate_callback(NUM_INOTIFY_WATCHES), only_new_events=True)

    watches = int(wazuh_log_monitor.callback_result[0]) if wazuh_log_monitor.callback_result else 0

    assert watches == test_metadata['watches_after']

    if file.exists('/changed_name'):
        file.delete_path_recursively('/changed_name')
