'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if the process priority of
       the 'wazuh-syscheckd' daemon set in the 'process_priority' tag is applied successfully.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_process_priority

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#process-priority

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_process_priority
'''

from pathlib import Path

import sys
import os

import pytest
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG
from wazuh_testing.constants.platforms import MACOS
from wazuh_testing.utils.services import search_process_by_command
from wazuh_testing.constants.daemons import SYSCHECK_DAEMON

from . import TEST_CASES_PATH, CONFIGS_PATH

# Marks

# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=1)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_process_priority.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_process_priority.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2 }

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_process_priority(test_configuration, test_metadata, configure_local_internal_options,
                             truncate_monitored_files, set_wazuh_configuration, folder_to_monitor, daemons_handler):
    '''
    description: Check if the process priority of the 'wazuh-syscheckd' daemon set in the 'process_priority' tag
                 is updated correctly. For this purpose, the test will monitor a testing folder and, once FIM starts,
                 it will get the priority value from the 'process_priority' tag and the system information of
                 the 'wazuh-syscheckd' process. Finally, the test will compare the current process priority
                 with the target priority to verify that they match.

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
        - Verify that the 'wazuh-syscheckd' daemon is running.
        - Verify that the process priority of the 'wazuh-syscheckd' daemon matches the 'process_priority' tag.

    input_description: A test case (ossec_conf) is contained in external YAML file (cases_process_priority.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and,
                       these are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*Ignoring .* due to'

    tags:
        - realtime
        - scheduled
    '''

    priority = int(test_metadata['priority'])
    syscheckd_process = search_process_by_command(SYSCHECK_DAEMON)

    assert syscheckd_process is not None, f'Process {SYSCHECK_DAEMON} not found'
    assert (os.getpriority(os.PRIO_PROCESS, syscheckd_process.pid)) == priority, \
        f'Process {SYSCHECK_DAEMON} has not updated its priority.'
