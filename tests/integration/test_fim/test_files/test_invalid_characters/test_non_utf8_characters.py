'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. In particular, these tests will check if FIM can correctly process path names
       containing non-UTF8 characters, logging any problems encountered and treating them correctly.

components:
    - fim

suite: invalid_characters

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - Linux
    - Windows

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
    - fim
'''
import sys
import pytest
import os
import subprocess
import time

if sys.platform == 'win32':
    import win32con
    from win32con import KEY_WOW64_64KEY

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import IGNORING_DUE_TO_INVALID_NAME, SYNC_INTEGRITY_MESSAGE, EVENT_TYPE_ADDED
from wazuh_testing.modules.fim.utils import create_registry
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim import configuration
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_nonUTF8.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_basic.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
local_internal_options = {configuration.SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_nonUTF8(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                  truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' is able to correctly detect a pathname containing an invalid
                 character, preventing its processing and writing a log warning.

    wazuh_min_version: 4.9.0

    tier: 1

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
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - start_monitoring:
            type: fixture
            brief: Wait FIM to start.

    assertions:
        - Verify that the FIM output a warning indicating that the file cannot be processed because it contains nonUTF8 characters.

    input_description: The test cases are contained in external YAML file (cases_nonUTF8.yaml) which includes
                       configuration parameters for the 'wazuh-syscheckd' daemon and testing directories to monitor.
                       The configuration template is contained in another external YAML file
                       (configuration_basic.yaml).

    expected_output:
        - r".*Ignoring file '(.*)' due to unsupported name.*"

    tags:
        - scheduled
        - realtime
        - who_data
    '''
    monitor = FileMonitor(WAZUH_LOG_PATH)

    # Create
    test_path = os.path.join(test_metadata['folder_to_monitor'], '§¨©ª«¬-®¯±²³¶¹º»¼½¾testáéíóú')
    file.truncate_file(WAZUH_LOG_PATH)
    if sys.platform == 'win32':
        file.write_file(test_path)
    else:
        subprocess.run(f'touch $(echo -n "{test_path}" | iconv -f UTF-8 -t ISO-8859-1)', shell=True, check=True)
    monitor.start(generate_callback(IGNORING_DUE_TO_INVALID_NAME))
    assert monitor.callback_result

    # Check Sync
    time.sleep(5)
    file.truncate_file(WAZUH_LOG_PATH)
    monitor.start(generate_callback(SYNC_INTEGRITY_MESSAGE))
    assert monitor.callback_result

if sys.platform == WINDOWS:
    cases_path = Path(TEST_CASES_PATH, 'cases_registries.yaml')
    config_path = Path(CONFIGS_PATH, 'configuration_registries.yaml')
    test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
    test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

    @pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
    def test_invalid_registry(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                              set_wazuh_configuration, daemons_handler, detect_end_scan):
        '''
        description: Check if the 'wazuh-syscheckd' is able to correctly process a registry key name containing an invalid
                     character.

        wazuh_min_version: 4.9.0

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
            - daemons_handler:
                type: fixture
                brief: Handler of Wazuh daemons.
            - detect_end_scan
                type: fixture
                brief: Check first scan end.

        assertions:
            - Verify that the FIM generate correctly an events with a new registry key.

        input_description: The test cases are contained in external YAML file (cases_registries.yaml) which includes
                           configuration parameters for the 'wazuh-syscheckd' daemon and testing directories to monitor.
                           The configuration template is contained in another external YAML file
                           (configuration_registries.yaml).

        expected_output:
            - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

        '''
        monitor = FileMonitor(WAZUH_LOG_PATH)

        # Create
        sub_key = os.path.join(test_metadata['sub_key'], '§¨©ª«¬-®¯±²³¶¹º»¼½¾testáéíóú')
        file.truncate_file(WAZUH_LOG_PATH)
        create_registry(win32con.HKEY_LOCAL_MACHINE, sub_key, KEY_WOW64_64KEY)
        monitor.start(generate_callback(EVENT_TYPE_ADDED))
        assert monitor.callback_result

        # Check Sync
        time.sleep(5)
        file.truncate_file(WAZUH_LOG_PATH)
        monitor.start(generate_callback(SYNC_INTEGRITY_MESSAGE))
        assert monitor.callback_result
