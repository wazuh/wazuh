'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'who-data' feature of the File Integrity Monitoring (FIM)
       system works properly. 'who-data' information contains the user who made the changes
       on the monitored files and also the program name or process used to carry them out.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_ambiguous_complex

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
    - fim_ambiguous_confs
'''
import sys
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import REALTIME_WHODATA_ENGINE_STARTED
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=2)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_whodata_ambiguous_thread.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_whodata_ambiguous_thread.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_whodata_ambiguous_thread(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                  truncate_monitored_files, daemons_handler):
    '''
    description: Check if the 'wazuh-syscheckd' daemon starts the 'whodata' thread when the configuration
                 is ambiguous. For example, when using 'whodata' on the same directory using conflicting
                 values ('yes' and 'no'). For this purpose, the configuration is applied and it checks
                 that the last value detected for 'whodata' in the 'ossec.conf' file is the one used.

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Detect if real-time whodata thread has been started
        - teardown:
            - Restore configuration
            - Stop wazuh
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

    assertions:
        - Verify that 'whodata' thread is started when the last 'whodata' value detected is set to 'yes'.
        - Verify that 'whodata' thread is not started when the last 'whodata' value detected is set to 'no'.

    input_description: Two test cases are contained in external YAML file (cases_whodata_ambiguous_thread.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'File integrity monitoring real-time Whodata engine started'

    tags:
        - who_data
    '''
    monitor = FileMonitor(WAZUH_LOG_PATH)
    monitor.start(callback=generate_callback(REALTIME_WHODATA_ENGINE_STARTED))

    assert bool(monitor.callback_result) == test_metadata['whodata']
