'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. In particular, these tests will check if FIM events are still generated when
       a monitored directory is deleted and created again.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: basic_usage

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
    - https://man7.org/linux/man-pages/man8/auditd.8.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/auditing-whodata/who-linux.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim
'''
import sys
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import FILE_LIMIT_PERCENTAGE, INODE_ENTRIES_PATH_COUNT, FILE_LIMIT_AMOUNT, FILE_ENTRIES_PATH_COUNT
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_fill_capacity.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_basic.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_fill_capacity(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                       configure_local_internal_options, folder_to_monitor, fill_folder_to_monitor,
                       daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates events for different capacity thresholds limits.
                 For this purpose, the test will monitor a directory in which several testing files will be created,
                 corresponding to different percentages of the total file limit. Then, it will check if FIM events
                 are generated when the files amount exceeds 80% of the total. Finally, the test will verify that
                 on the FIM event, inodes and monitored files number match.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Set local_internal_options.conf file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - folder_to_monitor:
            type: str
            brief: Folder created for monitoring.
        - fill_folder_to_monitor:
            type: str
            brief: Fill the monitored folder with test files.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - start_monitoring:
            type: fixture
            brief: Wait FIM to start.

    assertions:
        - Verify that FIM events are generated when the number of files to be monitored
          exceeds the established threshold and vice versa.
        - Verify that the FIM events contain the same number of inodes and files in the monitored directory.

    input_description: The test cases are contained in external YAML file (cases_fill_capacity.yaml)
                       which includes configuration parameters for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor. The configuration template is contained in another external YAML
                       file (configuration_basic.yaml).

    expected_output:
        - r".*Fim inode entries: '(d+)', path count: '(d+)'"
        - r".*Maximum number of files to be monitored: '(d+)'"
        - r'.*File database is (d+)% full.'

    tags:
        - scheduled
        - realtime
    '''
    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    files_amount = test_metadata.get('files_amount')
    fill_percentage = test_metadata.get('fill_percentage')
    max_entries = test_metadata.get('max_files_entries')

    log_monitor.start(generate_callback(FILE_LIMIT_AMOUNT), timeout=60)
    assert int(log_monitor.callback_result[0]) == max_entries

    files_amount = files_amount if files_amount <= max_entries else max_entries
    if sys.platform == WINDOWS:
        log_monitor.start(generate_callback(FILE_ENTRIES_PATH_COUNT), timeout=600)
    else:
        log_monitor.start(generate_callback(INODE_ENTRIES_PATH_COUNT), timeout=60)

    assert int(log_monitor.callback_result[0]) == files_amount

    log_monitor.start(generate_callback(FILE_LIMIT_PERCENTAGE), timeout=60)
    if fill_percentage >= 80:
        assert int(log_monitor.callback_result[0]) == fill_percentage
    else:
        assert not log_monitor.callback_result
