'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This test runs a scan with a policy containing a valid MITRE object and asserts that the
       event payload contains the MITRE ATT&CK fields (tactic, technique) with the expected values.

components:
    - sca

suite: sca

targets:
    - agent

daemons:
    - wazuh-modulesd

os_platform:
    - linux
    - windows

os_version:
    - CentOS 8
    - Ubuntu 24.04
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html
    - https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html

tags:
    - sca
'''
import json
import re
import sys
from pathlib import Path

import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.modulesd.sca import patterns
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, configuration

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

local_internal_options = {AGENTD_WINDOWS_DEBUG if sys.platform == WINDOWS else MODULESD_DEBUG: '2'}

# Configuration and cases data
configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_sca.yaml')
cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_mitre_payload_win.yaml' if sys.platform == WINDOWS else 'cases_mitre_payload.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = configuration.get_test_cases_data(cases_path)
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

def _callback_mitre_event(line):
    """Return the parsed event JSON when a stateful event containing a MITRE object is found."""
    match = re.match(patterns.SCA_STATEFUL_EVENT_QUEUED, line)
    if match:
        try:
            event = json.loads(match.group(1))
            if event.get('check', {}).get('mitre'):
                return (match.group(1),)
        except (json.JSONDecodeError, KeyError):
            pass
    return None

# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_sca_mitre_payload(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                           set_wazuh_configuration, configure_local_internal_options, daemons_handler,
                           wait_for_sca_enabled):
    '''
    description: Runs a scan with a policy that contains a MITRE object and verifies that the
                 resulting event payload includes the expected MITRE ATT&CK tactic and technique fields.

    test_phases:
        - Copy the MITRE policy file into the agent's ruleset path.
        - Restart wazuh.
        - Verify the SCA module starts.
        - Capture the "Stateful event queued" log and verify the MITRE object in the event payload.

    wazuh_min_version: 4.6.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - test_metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - prepare_cis_policies_file:
            type: fixture
            brief: Copy test SCA policy file. Deleted after test.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local_internal_options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all log files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Restart all wazuh daemons.
        - wait_for_sca_enabled:
            type: fixture
            brief: Wait for the SCA module to start before the test.

    assertions:
        - Verify the SCA module reaches the running state.
        - Verify the stateful event payload contains a "mitre" object with the expected tactic and technique values.

    input_description:
        - The `cases_mitre_payload.yaml` file provides the module configuration for this test.
        - The `cis_ubuntu24_04_mitre.yaml` file provides the SCA policy with MITRE ATT&CK data.

    expected_output:
        - r".*sca.*INFO: SCA module running"
        - r".*sca.*Stateful event queued: (.*)"
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Wait for a stateful event containing a MITRE object
    log_monitor.start(callback=_callback_mitre_event, timeout=60)
    assert log_monitor.callback_result is not None, 'No stateful event with MITRE data was found in the log'

    event = json.loads(log_monitor.callback_result[0])
    mitre = event['check']['mitre']

    assert set(mitre.get('tactic', [])) == set(test_metadata['mitre_tactics']), \
        f"Expected MITRE tactics {test_metadata['mitre_tactics']}, got {mitre.get('tactic')}"
    assert set(mitre.get('technique', [])) == set(test_metadata['mitre_techniques']), \
        f"Expected MITRE techniques {test_metadata['mitre_techniques']}, got {mitre.get('technique')}"
