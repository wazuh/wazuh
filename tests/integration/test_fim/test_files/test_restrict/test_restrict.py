"""
 copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM generates events
       only for file operations in monitored directories that do not match the 'restrict' attribute.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_restrict

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
    - fim_restrict
"""

import sys
import pytest
import os

from pathlib import Path
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED, FIM_EVENT_RESTRICT
from wazuh_testing.modules.fim.utils import get_fim_event_data
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim import configuration
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH

# Pytest marks to run on any service type on linux.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=2)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_restrict.yaml')
config_path = Path(CONFIGS_PATH, 'config_restrict.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
local_internal_options = {configuration.SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_restrict(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                  truncate_monitored_files, folder_to_monitor, daemons_handler, file_to_monitor):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects or ignores events in monitored files depending
                 on the value set in the 'restrict' attribute. This attribute limit checks to files that match
                 the entered string or regex and its file name. For this purpose, the test will monitor a folder
                 and create a testing file inside it. Finally, the test will verify that FIM 'added' events are
                 generated only for the testing files that not are restricted.

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
        - folder_to_monitor:
            type: str
            brief: Folder created for monitoring.
        - file_to_monitor:
            type: str
            brief: File created for monitoring.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.


    assertions:
        - Verify that FIM events are only generated for file operations in monitored directories
          that do not match the 'restrict' attribute.
        - Verify that FIM 'ignoring' events are generated for monitored files that are restricted.

    input_description: Different test cases are contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*Ignoring entry .* due to restriction .*'

    tags:
        - scheduled
    '''

    path = os.path.join(test_metadata['folder_to_monitor'], test_metadata['data'][0])

    monitor = FileMonitor(WAZUH_LOG_PATH)
    
    if test_metadata['data'][1] == True:
        monitor.start(generate_callback(EVENT_TYPE_ADDED))
        print(monitor.callback_result)
        assert monitor.callback_result
        fim_data = get_fim_event_data(monitor.callback_result)
        assert fim_data['path'] == path
    else:
        ignored_file = monitor.start(generate_callback(FIM_EVENT_RESTRICT))
        assert monitor.callback_result
