'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM events include
       the 'content_changes' field with the tag 'More changes' when it exceeds the maximum size
       allowed, and the 'report_changes' option is enabled.
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
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
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
import time
import sys

from pathlib import Path

import pytest

from wazuh_testing.constants.platforms import MACOS, WINDOWS
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG, RT_DELAY
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_MODIFIED, EVENT_TYPE_ADDED, ERROR_MSG_FIM_EVENT_NOT_DETECTED, \
                                               EVENT_TYPE_DELETED, EVENT_TYPE_REPORT_CHANGES, ERROR_MSG_REPORT_CHANGES_EVENT_NOT_DETECTED
from wazuh_testing.modules.fim.utils import make_diff_file_path, get_fim_event_data
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.file import write_file_write, delete_files_in_folder, truncate_file
from wazuh_testing.utils.string import generate_string
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.darwin, pytest.mark.tier(level=1)]


# Test metadata, configuration and ids.
cases_path = ''
if sys.platform == MACOS:
    cases_path = Path(TEST_CASES_PATH, 'cases_report_changes_and_diff_macos.yaml')
else:
    cases_path = Path(TEST_CASES_PATH, 'cases_report_changes_and_diff.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_report_changes_and_diff.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)


# Set configurations required by the fixtures.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_WINDOWS_DEBUG: 2, RT_DELAY: 1000}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_reports_file_and_nodiff(test_configuration, test_metadata, configure_local_internal_options,
                        truncate_monitored_files, set_wazuh_configuration, create_paths_files, daemons_handler, detect_end_scan):
    '''
    description: Check if the 'wazuh-syscheckd' daemon reports the file changes (or truncates if required)
                 in the generated events using the 'nodiff' tag and vice versa. For this purpose, the test
                 will monitor a directory and make file operations inside it. Then, it will check if a
                 'diff' file is created for the modified testing file. Finally, if the testing file matches
                 the 'nodiff' tag, the test will verify that the FIM event generated contains in its
                 'content_changes' field a message indicating that 'diff' is truncated because
                 the 'nodiff' option is used.

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
        - Verify that for each modified file a 'diff' file is generated.
        - Verify that FIM events include the 'content_changes' field.
        - Verify that FIM events truncate the modifications made in a monitored file
          when it matches the 'nodiff' tag.
        - Verify that FIM events include the modifications made in a monitored file
          when it does not match the 'nodiff' tag.

    input_description: A test case is contained in external YAML files (configuration_report_changes_and_diff.yaml, cases_report_changes_and_diff.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - diff
        - scheduled
    '''
    if (test_metadata.get('fim_mode') == 'whodata' or test_metadata.get('fim_mode') == 'realtime') and sys.platform == WINDOWS:
        time.sleep(5)
    is_truncated = 'testdir_nodiff' in test_metadata.get('folder')
    folder = test_metadata.get('folder')
    test_file_path = os.path.join(folder, test_metadata.get('filename'))

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # Create the file and and capture the event.
    truncate_file(WAZUH_LOG_PATH)
    original_string = generate_string(1, '0')
    write_file_write(test_file_path, content=original_string)

    wazuh_log_monitor.start(generate_callback(EVENT_TYPE_ADDED), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_FIM_EVENT_NOT_DETECTED

    # Modify the file without new content and check content_changes have the correct message
    time.sleep(1)
    truncate_file(WAZUH_LOG_PATH)
    write_file_write(test_file_path, content=original_string)

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(generate_callback(EVENT_TYPE_REPORT_CHANGES), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_REPORT_CHANGES_EVENT_NOT_DETECTED
    assert 'No content changes were found for this file.' in str(wazuh_log_monitor.callback_result[0]), 'Wrong content_changes field'

    # Modify the file with new content.
    truncate_file(WAZUH_LOG_PATH)
    modified_string = 'test_string' + generate_string(10, '1')
    write_file_write(test_file_path, content=modified_string)

    wazuh_log_monitor.start(generate_callback(EVENT_TYPE_MODIFIED), timeout=20)
    assert wazuh_log_monitor.callback_result
    event = get_fim_event_data(wazuh_log_monitor.callback_result)

    # Validate content_changes attribute exists in the event
    diff_file = make_diff_file_path(folder=test_metadata.get('folder'), filename=test_metadata.get('filename'))
    assert os.path.exists(diff_file), f'{diff_file} does not exist'

    # Validate content_changes value is truncated if the file is set to no_diff
    if is_truncated:
        assert "Diff truncated due to 'nodiff' configuration detected for this file." in event['file']['content_changes'], \
            'content_changes is not truncated'
    else:
        assert 'test_string' in event['file']['content_changes'], 'Wrong content_changes field'

    truncate_file(WAZUH_LOG_PATH)
    delete_files_in_folder(folder)
    wazuh_log_monitor.start(generate_callback(EVENT_TYPE_DELETED))
    assert get_fim_event_data(wazuh_log_monitor.callback_result)['file']['mode'] == test_metadata.get('fim_mode')
