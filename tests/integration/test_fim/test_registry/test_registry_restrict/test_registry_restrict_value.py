'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM generates events
       only for registry entry operations in monitored keys that do not match the 'restrict_key'
       or the 'restrict_value' attributes.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: registry_restrict

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#windows-registry

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_restrict
'''
from pathlib import Path

import os
import sys

if sys.platform == 'win32':
    import win32con
    from win32con import KEY_WOW64_32KEY, KEY_WOW64_64KEY

import pytest
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils import file
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED, EVENT_TYPE_MODIFIED, EVENT_TYPE_DELETED
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.utils import get_fim_event_data, delete_registry, delete_registry_value, create_registry_value


from . import TEST_CASES_PATH, CONFIGS_PATH

# Marks

pytestmark = [pytest.mark.agent, pytest.mark.win32, pytest.mark.tier(level=1)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_registry_restrict_value.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_registry_restrict_value.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {AGENTD_WINDOWS_DEBUG: 2}

# Tests

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_restrict_value(test_configuration, test_metadata,configure_local_internal_options,
                            truncate_monitored_files, set_wazuh_configuration, create_registry_key, daemons_handler, detect_end_scan):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects or ignores events in monitored registry entries
                 depending on the value set in the 'restrict_value' attribute. This attribute limit checks to
                 keys that match the entered string or regex and its name. For this purpose, the test will
                 monitor a key, create testing subkeys inside it, and make operations on their values. Finally,
                 the test will verify that FIM 'added' and 'deleted' events are generated only for the testing
                 subkeys that are not restricted.

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
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - create_registry_key
            type: fixture
            brief: Create windows registry key.
        - detect_end_scan
            type: fixture
            brief: Check first scan end.

    assertions:
        - Verify that FIM events are only generated for operations in monitored keys
          that do not match the 'restrict_key' attribute.
        - Verify that FIM 'ignoring' events are generated for monitored keys that are restricted.

    input_description: The file 'configuration_registry_restrict_value.yaml' provides the configuration
                       template.
                       The file 'cases_registry_restrict_value.yaml' provides the tes cases configuration
                       details for each test case.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'deleted' events)
        - r'.*Ignoring entry .* due to restriction .*'

    '''
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # Create values
    create_registry_value(win32con.HKEY_LOCAL_MACHINE, test_metadata['sub_key'], test_metadata['value_name'], win32con.REG_SZ, "added", KEY_WOW64_64KEY if test_metadata['arch'] == 'x64' else KEY_WOW64_32KEY)

    if test_metadata['triggers_event']:
        wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_MODIFIED))
        assert wazuh_log_monitor.callback_result
        event = get_fim_event_data(wazuh_log_monitor.callback_result)
        assert event['type'] == 'modified', 'Key event not modified'
        assert event['path'] == os.path.join(test_metadata['key'], test_metadata['sub_key']), 'Key event wrong path'
        assert event['architecture'] == '[x32]' if test_metadata['arch'] == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_ADDED))
        assert wazuh_log_monitor.callback_result
        event = get_fim_event_data(wazuh_log_monitor.callback_result)
        assert event['type'] == 'added', 'Event type not equal'
        assert event['path'] == os.path.join(test_metadata['key'], test_metadata['sub_key']), 'Event path not equal'
        assert event['value'] == test_metadata['value_name'], 'Value name not equal'
        assert event['architecture'] == '[x32]' if test_metadata['arch'] == KEY_WOW64_32KEY else '[x64]', 'Value event arch not equal'
    else:
        wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_MODIFIED))
        assert wazuh_log_monitor.callback_result
        event = get_fim_event_data(wazuh_log_monitor.callback_result)
        assert event['type'] == 'modified', 'Key event not modified'
        assert event['path'] == os.path.join(test_metadata['key'], test_metadata['sub_key']), 'Key event wrong path'
        assert event['architecture'] == '[x32]' if test_metadata['arch'] == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

    delete_registry_value(win32con.HKEY_LOCAL_MACHINE, test_metadata['sub_key'], test_metadata['value_name'], KEY_WOW64_64KEY if test_metadata['arch'] == 'x64' else KEY_WOW64_32KEY)

    if test_metadata['triggers_event']:
        wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_MODIFIED))
        assert wazuh_log_monitor.callback_result
        event = get_fim_event_data(wazuh_log_monitor.callback_result)
        assert event['type'] == 'modified', 'Key event not modified'
        assert event['path'] == os.path.join(test_metadata['key'], test_metadata['sub_key']), 'Key event wrong path'
        assert event['architecture'] == '[x32]' if test_metadata['arch'] == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'

        wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_DELETED))
        assert wazuh_log_monitor.callback_result
        event = get_fim_event_data(wazuh_log_monitor.callback_result)
        assert event['type'] == 'deleted', 'Event type not equal'
        assert event['path'] == os.path.join(test_metadata['key'], test_metadata['sub_key']), 'Event path not equal'
        assert event['value'] == test_metadata['value_name'], 'Value name not equal'
        assert event['architecture'] == '[x32]' if test_metadata['arch'] == KEY_WOW64_32KEY else '[x64]', 'Value event arch not equal'
    else:
        wazuh_log_monitor.start(callback=generate_callback(EVENT_TYPE_MODIFIED))
        assert wazuh_log_monitor.callback_result
        event = get_fim_event_data(wazuh_log_monitor.callback_result)
        # After deleting the value, we don't expect any message of the value because it's not in the DB
        assert event['type'] == 'modified', 'Key event not modified'
        assert event['path'] == os.path.join(test_metadata['key'], test_metadata['sub_key']), 'Key event wrong path'
        assert event['architecture'] == '[x32]' if test_metadata['arch'] == KEY_WOW64_32KEY else '[x64]', 'Key event arch not equal'
