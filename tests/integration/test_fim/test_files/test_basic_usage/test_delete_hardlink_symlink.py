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
from wazuh_testing.modules.fim.patterns import INODE_ENTRIES_PATH_COUNT
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_delete_hardlink_symlink.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_basic.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_delete_hardlink_symlink(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                                 configure_local_internal_options, folder_to_monitor, create_links_to_file,
                                 daemons_handler, start_monitoring):
    '''
    description: Check if FIM events contain the correct number of file paths when 'hard'
                 and 'symbolic' links are used. For this purpose, the test will monitor
                 a testing folder and create regular files, also 'symlink' and 'hard link'
                 before the scan starts. Finally, it verifies in the generated FIM event
                 that the correct inodes and file paths are detected.

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
        - create_links_to_file:
            type: str
            brief: Create the required hardlinks and symlinks.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - start_monitoring:
            type: fixture
            brief: Wait FIM to start.

    assertions:
        - Verify that when using hard and symbolic links, the FIM events contain
          the number of inodes and paths to files consistent.

    input_description: The test cases are contained in external YAML file (cases_delete_hardlink_symlink.yaml)
                       which includes configuration parameters for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor. The configuration template is contained in another external YAML
                       file (configuration_basic.yaml).

    expected_output:
        - r".*Fim inode entries: '(d+)', path count: '(d+)'"

    tags:
        - scheduled
        - realtime
    '''
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    hardlink_amount = test_metadata.get('hardlink_amount')
    symlink_amount = test_metadata.get('symlink_amount')

    file.delete_files_in_folder(folder_to_monitor)
    wazuh_log_monitor.start(generate_callback(INODE_ENTRIES_PATH_COUNT))
    inode_entries, path_count = wazuh_log_monitor.callback_result

    assert int(inode_entries) == 1 + hardlink_amount
    assert int(path_count) == 1 + hardlink_amount + symlink_amount
