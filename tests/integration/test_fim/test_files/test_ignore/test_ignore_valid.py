'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM ignores the elements
       set in the 'ignore' option using both regex and regular names for specifying them.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_ignore

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#ignore

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_ignore
'''

from pathlib import Path

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils import file
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED, IGNORING_DUE_TO_SREGEX, IGNORING_DUE_TO_PATTERN
from wazuh_testing.modules.fim.utils import get_fim_event_data

from . import TEST_CASES_PATH, CONFIGS_PATH


# Marks

# Pytest marks to run on any service type on linux or windows.
# Skipped on Windows due Issue https://github.com/wazuh/wazuh/issues/9298"
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=2)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_ignore_linux.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_ignore_linux.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2 }

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_ignore_subdirectory(test_configuration, test_metadata, configure_local_internal_options,
                             truncate_monitored_files, set_wazuh_configuration, folder_to_monitor, daemons_handler,
                             file_to_monitor):
    '''
    description: Check if the 'wazuh-syscheckd' daemon ignores the files that are in a monitored subdirectory
                 when using the 'ignore' option. It also ensures that events for files tha are not being ignored
                 are still detected. For this purpose, the test will monitor folders containing files to be ignored
                 using names or regular expressions. Then it will create these files and check if FIM events should
                 be generated. Finally, the test will verify that the generated FIM events correspond to the files
                 that must not be ignored.

    wazuh_min_version: 4.2.0

    tier: 2

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
        - file_to_monitor:
            type: str
            brief: File created for monitoring.

    assertions:
        - Verify that FIM 'ignore' events are generated for each ignored element.
        - Verify that FIM 'added' events are generated for files
          that do not match the value of the 'ignore' option.

    input_description: Different test cases are contained in external YAML files
                       (cases_ignore_linux.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon and testing directories to monitor.

    inputs:
        - 288 test cases including multiple regular expressions and names for testing files and directories.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*Ignoring .* due to'

    tags:
        - ignore
    '''

    if test_metadata.setdefault('xfail', False):
        pytest.xfail(reason="Expected fail - Issue https://github.com/wazuh/wazuh/issues/22186.")

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    if test_metadata.setdefault('triggers_event', False) == True:
        wazuh_log_monitor.start(timeout=60, callback=generate_callback(EVENT_TYPE_ADDED))
        callback_result = wazuh_log_monitor.callback_result
        assert callback_result

        event_data = get_fim_event_data(callback_result)
        assert event_data['file']['path'] == test_metadata['file_to_monitor'], 'Event path not equal'
        assert event_data['file']['mode'] == test_metadata['fim_mode'], 'FIM mode not equal'
    else:
        if test_metadata['is_pattern'] == False:
            wazuh_log_monitor.start(callback=generate_callback(IGNORING_DUE_TO_SREGEX))
            assert wazuh_log_monitor.callback_result
        else:
            wazuh_log_monitor.start(callback=generate_callback(IGNORING_DUE_TO_PATTERN))
            assert wazuh_log_monitor.callback_result
