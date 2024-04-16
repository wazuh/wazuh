'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will verify that FIM limits
       the maximum events per second that it generates, set in the 'max_eps' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_max_eps

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_max_eps
'''

from pathlib import Path

import sys
import os
import time
import re
from datetime import datetime

import pytest
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils import file
from wazuh_testing.modules.fim.patterns import SENDING_FIM_EVENT, PATH_MONITORED_REALTIME, PATH_MONITORED_WHODATA, PATH_MONITORED_WHODATA_WINDOWS

from . import TEST_CASES_PATH, CONFIGS_PATH

# Marks

# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=1)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_max_eps.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_max_eps.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2 }
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_max_eps(test_configuration, test_metadata, configure_local_internal_options,
                             truncate_monitored_files, set_wazuh_configuration, folder_to_monitor, daemons_handler):
    '''
    description: Check if the 'wazuh-syscheckd' daemon applies the limit set in the 'max_eps' tag when
                 a lot of 'syscheck' events are generated. For this purpose, the test will monitor a folder,
                 and once FIM is started, it will create multiple testing files in it. Then, the test
                 will collect FIM 'added' events generated and check if the number of events matches
                 the testing files created. Finally, it will verify the limit of events per second (eps)
                 is not exceeded by checking the creation time of the testing files.

    wazuh_min_version: 4.6.0

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
        - Verify that FIM events are generated for each testing file created.
        - Verify that the eps limit set in the 'max_eps' tag has not been exceeded at generating FIM events.

    input_description: A test case (max_eps) is contained in external YAML file (cases_max_eps.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)

    tags:
        - scheduled
    '''
    max_eps = int(test_metadata['max_eps'])
    fim_mode = test_metadata['fim_mode']
    test_directories = test_metadata['folder_to_monitor']

    if fim_mode == 'whodata' and sys.platform == WINDOWS:
        pytest.skip(reason="Unstable behavior on github actions")

    if sys.platform == WINDOWS:
        regex = PATH_MONITORED_REALTIME if test_metadata['fim_mode'] == 'realtime' else PATH_MONITORED_WHODATA_WINDOWS
    else:
        regex = PATH_MONITORED_REALTIME if test_metadata['fim_mode'] == 'realtime' else PATH_MONITORED_WHODATA

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=generate_callback(regex))
    assert wazuh_log_monitor.callback_result

    file_names = []
    for i in range(int(max_eps) * 4):
        file_name = f'file{i}_to_max_eps_{max_eps}_{fim_mode}_mode{time.time()}_.txt'
        path = os.path.join(test_directories, file_name)
        file_names.append(path)
    file.create_files(file_names)

    n_results = max_eps * 3

    wazuh_log_monitor.start(accumulations=n_results, callback=generate_callback(SENDING_FIM_EVENT))
    assert wazuh_log_monitor.callback_result

    result = parse_integrity_message(wazuh_log_monitor.callback_result)
    date_time_count = {}

    for date_time in result:
        if date_time in date_time_count:
            date_time_count[date_time] += 1
        else:
            date_time_count[date_time] = 1

    for date_time, n_occurrences in date_time_count.items():
        assert n_occurrences <= max_eps, f"Sent {n_occurrences} but a maximum of {max_eps} was set"


def parse_integrity_message(lines):
    result = []
    for line in lines:
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            result.append(datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'))
    return result
