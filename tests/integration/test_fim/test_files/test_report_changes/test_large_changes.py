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
import sys

from pathlib import Path

import pytest

from wazuh_testing.constants.platforms import WINDOWS, MACOS
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_MODIFIED, EVENT_TYPE_ADDED, ERROR_MSG_FIM_EVENT_NOT_DETECTED
from wazuh_testing.modules.fim.utils import get_fim_event_data
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.file import truncate_file, write_file_write
from wazuh_testing.utils.string import generate_string
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.darwin, pytest.mark.tier(level=1)]


# Test metadata, configuration and ids.
cases_path = ''
if sys.platform == MACOS:
    cases_path = Path(TEST_CASES_PATH, 'cases_large_changes_macos.yaml')
else:
    cases_path = Path(TEST_CASES_PATH, 'cases_large_changes.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_large_changes.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)


# Set configurations required by the fixtures.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_WINDOWS_DEBUG: 2}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_large_changes(test_configuration, test_metadata, configure_local_internal_options,
                        truncate_monitored_files, set_wazuh_configuration, folder_to_monitor, daemons_handler, detect_end_scan):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects the character limit in the file changes is reached
                 showing the 'More changes' tag in the 'content_changes' field of the generated events. For this
                 purpose, the test will monitor a directory, add a testing file and modify it, adding more characters
                 than the allowed limit. Then, it will unzip the 'diff' and get the size of the changes. Finally,
                 the test will verify that the generated FIM event contains in its 'content_changes' field the proper
                 value depending on the test case.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Configuration cases.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - folder_to_monitor:
            type: str
            brief: Folder created for monitoring.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - detect_end_scan
            type: fixture
            brief: Check first scan end.

    assertions:
        - Verify that FIM events are generated when adding and modifying the testing file.
        - Verify that FIM events include the 'content_changes' field with the 'More changes' tag when
          the changes made on the testing file have more characters than the allowed limit.
        - Verify that FIM events include the 'content_changes' field with the old content
          of the monitored file.
        - Verify that FIM events include the 'content_changes' field with the new content
          of the monitored file when the old content is lower than the allowed limit or
          the testing platform is Windows.

    input_description: The file 'configuration_large_changes.yaml' provides the configuration template.
                       The file 'cases_large_changes.yaml' provides the test cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)
        - The 'More changes' message appears in content_changes when the changes size is bigger than the set limit.
    '''
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    limit = 50000
    test_file_path = os.path.join(test_metadata.get('folder_to_monitor'), test_metadata.get('filename'))

    # Create the file and and capture the event.
    truncate_file(WAZUH_LOG_PATH)
    original_string = generate_string(test_metadata.get('original_size'), '0')
    write_file_write(test_file_path, content=original_string)

    wazuh_log_monitor.start(generate_callback(EVENT_TYPE_ADDED), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_FIM_EVENT_NOT_DETECTED

    # Modify the file with new content
    truncate_file(WAZUH_LOG_PATH)
    modified_string = generate_string(test_metadata.get('modified_size'), '1')
    write_file_write(test_file_path, content=modified_string)

    wazuh_log_monitor.start(generate_callback(EVENT_TYPE_MODIFIED), timeout=20)
    assert wazuh_log_monitor.callback_result

    event = get_fim_event_data(wazuh_log_monitor.callback_result)

    # Assert 'More changes' is shown when the command returns more than 'limit' characters
    if test_metadata.get('has_more_changes'):
        assert 'More changes' in event['content_changes'], 'Did not find event with "More changes" within content_changes.'
    else:
        assert 'More changes' not in event['content_changes'], '"More changes" found within content_changes.'

    # Assert old content is shown in content_changes
    assert '0' in event['content_changes'], '"0" is the old value but it is not found within content_changes'

    # Assert new content is shown when old content is lower than the limit or platform is Windows
    if test_metadata.get('original_size') < limit or sys.platform == WINDOWS:
        assert '1' in event['content_changes'], '"1" is the new value but it is not found within content_changes'
