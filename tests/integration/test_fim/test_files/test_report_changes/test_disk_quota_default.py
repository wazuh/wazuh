'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM limits the size of
       the 'queue/diff/local' folder, where Wazuh stores the compressed files used to perform
       the 'diff' operation, to the default value when the 'report_changes' option is enabled.
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#disk-quota

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
from pathlib import Path

import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import DISK_QUOTA_LIMIT_CONFIGURED_VALUE, ERROR_MSG_DISK_QUOTA_LIMIT
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.darwin, pytest.mark.tier(level=1)]


# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_disk_quota_default.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_disk_quota_default.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

DISK_QUOTA_DEFAULT_VALUE = 1048576


# Set configurations required by the fixtures.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_WINDOWS_DEBUG: '2'}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_disk_quota_default(test_configuration, test_metadata, configure_local_internal_options,
                                    truncate_monitored_files, set_wazuh_configuration, daemons_handler):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of the folder where the data used to perform
                 the 'diff' operations is stored to the default value. For this purpose, the test will monitor
                 a directory and, once the FIM is started, it will wait for the FIM event related to the maximum
                 disk quota to store 'diff' information. Finally, the test will verify that the value gotten from
                 that FIM event corresponds with the default value of the 'disk_quota' tag (1GB).

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
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that an FIM event is generated indicating the size limit of the folder
          to store 'diff' information to the default limit of the 'disk_quota' tag (1GB).

    input_description: An external YAML file (configuration_diff_size.yaml) includes configuration settings for the agent.
                       Different test cases are found in the cases_disk_quota_default.yaml file and include parameters for
                       the environment setup, the requests to be made, and the expected result.

    expected_output:
        - r'.*Maximum disk quota size limit configured to'

    tags:
        - disk_quota
        - scheduled
    '''
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(generate_callback(DISK_QUOTA_LIMIT_CONFIGURED_VALUE), timeout=30)
    callback_result = wazuh_log_monitor.callback_result
    assert callback_result, ERROR_MSG_DISK_QUOTA_LIMIT
    assert str(wazuh_log_monitor.callback_result[0]) == str(DISK_QUOTA_DEFAULT_VALUE), 'Wrong value for disk_quota'
