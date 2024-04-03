'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. All these tests will be performed using ambiguous directory configurations,
       such as directories and subdirectories with opposite monitoring settings. In particular, it
       will be verified that the value of the 'ignore' attribute prevails over the 'restrict' one.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_ambiguous_complex

targets:
    - agent

daemons:
    - wazuh-agentd
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
    - fim_ambiguous_confs
'''
import sys
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=2)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_ignore_works_over_restrict.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_ignore_works_over_restrict.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_ignore_works_over_restrict(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                    truncate_monitored_files, folder_to_monitor, daemons_handler, file_to_monitor, start_monitoring):
    '''
    description: Check if the 'ignore' tag prevails over the 'restrict' one when using both in the same directory.
                 For example, when a directory is ignored and at the same time monitoring is restricted to a file
                 that is in that directory, no FIM events should be generated when that file is modified.
                 For this purpose, the test case configuration is applied, and it is checked if FIM events
                 are generated when required.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Create custom folder and file for monitoring
        - test:
            - Create file and detect event creation event
            - Validate ignored event is generated with matching regex
        - teardown:
            - Delete custom monitored folder
            - Restore configuration
            - Stop Wazuh
            - Clean logs

    wazuh_min_version: 4.2.0

    tier: 2

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
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - folder_to_monitor:
            type: str
            brief: Folder created for monitoring.
        - file_to_monitor:
            type: str
            brief: File created for monitoring.
        - start_monitoring:
            type: fixture
            brief: Wait FIM to start.

    assertions:
        - Verify that when a directory is ignored, the 'restrict' attribute
          is not taken into account to generate FIM events.

    input_description: The file 'configuration_works_over_restrict.yaml' provides the configuration
                       template.
                       The file 'cases_ignore_works_over_restrict.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r".*Ignoring '.*?' '(.*?)' due to (sregex|pattern)? '.*?'" (When the FIM event should be ignored)

    tags:
        - fim
    '''
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=generate_callback(test_metadata['regex']))

    assert wazuh_log_monitor.callback_result
