'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM limits the size of the file
       monitored to generate 'diff' information to the default value of the 'file_size' tag when
       the 'report_changes' option is enabled.
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-size

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

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG, RT_DELAY
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import FILE_SIZE_LIMIT_REACHED, EVENT_TYPE_REPORT_CHANGES, ERROR_MSG_REPORT_CHANGES_EVENT_NOT_DETECTED, \
                                               ERROR_MSG_FILE_LIMIT_REACHED, DIFF_FOLDER_DELETED, ERROR_MSG_FOLDER_DELETED, EVENT_UNABLE_DIFF
from wazuh_testing.modules.fim.utils import make_diff_file_path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.file import write_file, translate_size
from wazuh_testing.utils.string import generate_string
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.darwin, pytest.mark.tier(level=1)]


# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_file_size_default.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_disk_quota_default.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)


# Set configurations required by the fixtures.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_WINDOWS_DEBUG: '2', RT_DELAY: 1000}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_file_size_default(test_configuration, test_metadata, configure_local_internal_options,
                           truncate_monitored_files, set_wazuh_configuration, folder_to_monitor, file_to_monitor, daemons_handler, detect_end_scan):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of the monitored file to generate
                 'diff' information from the default value of the 'file_size' option. For this purpose,
                 the test will monitor a directory, create a testing file smaller than the default limit,
                 and check if the compressed file has been created. Then, it will increase the size of
                 the testing file. Finally, the test will verify that the FIM event related to the
                 reached file size limit has been generated, and the compressed file in the 'queue/diff/local'
                 directory does not exist.

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
        - file_to_monitor:
            type: str
            brief: File created for monitoring.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - detect_end_scan
            type: fixture
            brief: Check first scan end.

    assertions:
        - Verify that the 'diff' folder is created when a monitored file does not exceed the size limit.
        - Verify that FIM events are generated indicating the size limit reached of monitored files
          to generate 'diff' information with the default limit of the 'file_size' tag (50MB).
        - Verify that the 'diff' folder is removed when a monitored file exceeds the size limit.

    input_description: An external YAML file (configuration_disk_quota_default.yaml) includes configuration settings for the agent.
                       Different test cases are found in the cases_file_size_default.yaml file and include parameters for
                       the environment setup, the requests to be made, and the expected result.

    expected_output:
        - r'.*Sending FIM event: .*"content_changes":"...000...".*'
        - r'.*Folder .* has been deleted.*'
        - r'.*File .* is too big for configured maximum size to perform diff operation'
        - r'.*"content_changes":"Unable to calculate diff due to 'file_size' limit has been reached."'

    tags:
        - diff
        - scheduled
    '''
    if test_metadata.get('fim_mode') == 'whodata' and sys.platform == WINDOWS:
        time.sleep(5)

    size_limit = translate_size('50MB')
    diff_file_path = make_diff_file_path(folder=test_metadata.get('folder_to_monitor'), filename=test_metadata.get('filename'))

    # Modify file with a smaller size than the configured value
    to_write = generate_string(int(size_limit / 100), '0')
    write_file(file_to_monitor, data=to_write)

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_REPORT_CHANGES), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_REPORT_CHANGES_EVENT_NOT_DETECTED
    assert 'More changes...' in str(wazuh_log_monitor.callback_result), 'Wrong content_changes field'

    if not os.path.exists(diff_file_path):
        pytest.raises(FileNotFoundError(f"{diff_file_path} not found. It should exist before increasing the size."))

    # Increase the size of the file over the configured value
    to_write = generate_string(int(size_limit), '1')
    write_file(file_to_monitor, data=to_write)

    wazuh_log_monitor.start(callback=generate_callback(DIFF_FOLDER_DELETED), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_FOLDER_DELETED

    if os.path.exists(diff_file_path):
        pytest.raises(FileExistsError(f"{diff_file_path} found. It should not exist after incresing the size."))

    wazuh_log_monitor.start(callback=generate_callback(FILE_SIZE_LIMIT_REACHED), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_FILE_LIMIT_REACHED

    # Check the content_changes field in the event
    wazuh_log_monitor.start(callback=generate_callback(EVENT_UNABLE_DIFF), timeout=30)
    assert wazuh_log_monitor.callback_result, ERROR_MSG_REPORT_CHANGES_EVENT_NOT_DETECTED
    assert 'Unable to calculate diff due to \'file_size\' limit has been reached.' in wazuh_log_monitor.callback_result, 'Wrong content_changes field'
