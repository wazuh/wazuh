'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM manages properly
       the 'diff' folder created in the 'queue/diff/local' directory when removing a monitored
       folder or the 'report_changes' option is disabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_report_changes

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows
    - macos

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#diff

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_report_changes
'''
import os

from pathlib import Path

import pytest
import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED, ERROR_MSG_FIM_EVENT_NOT_DETECTED, EVENT_TYPE_DELETED
from wazuh_testing.modules.fim.utils import make_diff_file_path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.file import write_file, delete_files_in_folder
from wazuh_testing.utils.string import generate_string
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.darwin, pytest.mark.tier(level=1)]


# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_report_deleted_diff.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_report_deleted_diff.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)


# Set configurations required by the fixtures.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_WINDOWS_DEBUG: 2}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_report_when_deleted_directories(test_configuration, test_metadata, configure_local_internal_options,
                        truncate_monitored_files, set_wazuh_configuration, create_paths_files, daemons_handler, detect_end_scan):
    '''
    description: Check if the 'wazuh-syscheckd' daemon deletes the 'diff' folder created in the 'queue/diff/local'
                 directory when removing a monitored folder and the 'report_changes' option is enabled.
                 For this purpose, the test will monitor a directory and add a testing file inside it. Then,
                 it will check if a 'diff' file is created for the modified testing file. Finally, the test
                 will remove the monitored folder, wait for the FIM 'deleted' event, and verify that
                 the corresponding 'diff' folder is deleted.

    wazuh_min_version: 4.6.0

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
        - create_paths_files:
            type: list
            brief: Create the required directory or file to edit.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - detect_end_scan
            type: fixture
            brief: Check first scan end.

    assertions:
        - Verify that the FIM event is generated when removing the monitored folder.
        - Verify that FIM adds the 'diff' file in the 'queue/diff/local' directory
          when monitoring the corresponding testing file.
        - Verify that FIM deletes the 'diff' folder in the 'queue/diff/local' directory
          when removing the corresponding monitored folder.

    input_description: Different test cases are contained in external YAML file (configuration_report_deleted_diff.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('deleted' events)

    tags:
        - diff
        - scheduled
    '''
    fim_mode = test_metadata.get('fim_mode')
    folder = test_metadata.get('folder')
    test_file_path = os.path.join(folder, test_metadata.get('filename'))

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # Create the file and and capture the event.
    original_string = generate_string(1, '0')
    write_file(test_file_path, data=original_string)

    wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_ADDED), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_FIM_EVENT_NOT_DETECTED

    # Validate content_changes attribute exists in the event
    diff_file = make_diff_file_path(folder=test_metadata.get('folder'), filename=test_metadata.get('filename'))
    assert os.path.exists(diff_file), f'{diff_file} does not exist'

    delete_files_in_folder(folder)
    wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_DELETED))

    # Wait a second so diff path is deleted
    if 'scheduled' not in fim_mode:
        time.sleep(2)
    assert not os.path.exists(diff_file), f'{diff_file} exists'
