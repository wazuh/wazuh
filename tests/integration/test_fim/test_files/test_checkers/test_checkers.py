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
import time
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED, EVENT_TYPE_DELETED, EVENT_TYPE_MODIFIED
from wazuh_testing.modules.fim.utils import get_fim_event_data
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim import configuration
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_checkers.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_basic.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
local_internal_options = {configuration.SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})

base_checks = [configuration.ATTR_CHECKSUM, configuration.ATTR_TYPE]

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_checkers(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                  truncate_monitored_files, folder_to_monitor, file_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generated events the 'check_' specified in
                 the configuration. These checks are attributes indicating that a monitored directory entry has
                 been modified. For example, if 'check_all=yes' and 'check_perm=no' are set for the same entry,
                 'syscheck' must send an event containing every possible 'check_' except the perms.
                 For this purpose, the test will monitor a directory using the 'check_all' attribute in
                 conjunction with one or more 'check_' on the same directory, having 'check_all' to 'yes' and the other
                 one to 'no'. Then it will make directory operations inside it, and finally, the test
                 will verify that the FIM events generated contain only the fields of the 'checks' specified for
                 the monitored keys/values.

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
        - file_to_monitor:
            type: str
            brief: File created for monitoring.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - start_monitoring:
            type: fixture
            brief: Wait FIM to start.

    assertions:
        - Verify that the FIM events generated contains the 'check_' fields specified in the configuration.

    input_description: The test cases are contained in external YAML file (cases_checkers.yaml) which includes
                       configuration parameters for the 'wazuh-syscheckd' daemon and testing directories to monitor.
                       The configuration template is contained in another external YAML file
                       (configuration_basic.yaml).

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - realtime
        - who_data
    '''
    monitor = FileMonitor(WAZUH_LOG_PATH)
    fim_mode = test_metadata.get('fim_mode')
    checks = set(test_metadata.get('checks'))

    # Update
    file.truncate_file(WAZUH_LOG_PATH)
    file.write_file(file_to_monitor, "update")
    monitor.start(generate_callback(EVENT_TYPE_MODIFIED))
    if not checks:
        assert not monitor.callback_result
        checks.update(configuration.ATTR_BASE)
    else:
        fim_data = get_fim_event_data(monitor.callback_result)
        assert fim_data['mode'] == fim_mode
        assert set(fim_data['attributes'].keys()) == checks
        time.sleep(0.1)

    # Delete
    file.truncate_file(WAZUH_LOG_PATH)
    file.remove_file(file_to_monitor)
    monitor.start(generate_callback(EVENT_TYPE_DELETED))
    fim_data = get_fim_event_data(monitor.callback_result)
    assert fim_data['mode'] == fim_mode
    assert set(fim_data['attributes'].keys()) == checks

    # Create
    file.truncate_file(WAZUH_LOG_PATH)
    file.write_file(file_to_monitor)
    monitor.start(generate_callback(EVENT_TYPE_ADDED))
    fim_data = get_fim_event_data(monitor.callback_result)
    assert fim_data['mode'] == fim_mode
    assert set(fim_data['attributes'].keys()) == checks
