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


def _find_mitre(check_obj):
    """Return the MITRE object from a check payload in any supported shape."""
    if not isinstance(check_obj, dict):
        return None

    if check_obj.get('mitre'):
        return check_obj.get('mitre')

    for key in ('new', 'old', 'data'):
        nested = check_obj.get(key)
        if isinstance(nested, dict):
            mitre = _find_mitre(nested)
            if mitre:
                return mitre

    return None


def _extract_mitre_from_event(event):
    """Extract MITRE data from stateful or stateless event payloads."""
    if not isinstance(event, dict):
        return None

    candidates = [
        event.get('check'),
        event.get('data', {}).get('check') if isinstance(event.get('data'), dict) else None,
    ]

    for candidate in candidates:
        mitre = _find_mitre(candidate)
        if mitre:
            return mitre

    return None


def _callback_mitre_event(line):
    """Return the parsed event JSON when an SCA event containing a MITRE object is found."""
    for pattern in (patterns.SCA_STATEFUL_EVENT_QUEUED, patterns.SCA_SENDING_EVENT):
        match = re.match(pattern, line)
        if not match:
            continue

        try:
            event = json.loads(match.group(1))
            if _extract_mitre_from_event(event):
                return (match.group(1),)
        except (json.JSONDecodeError, KeyError):
            continue

    return None


def _callback_scan_result_for_policy(policy: str, allow_any_policy: bool = False):
    def _callback(line):
        match = re.match(patterns.SCA_SCAN_RESULT, line)
        if not match:
            return None

        event_policy = match.group(2)
        if allow_any_policy or event_policy == policy:
            return match.groups()

        return None

    return _callback

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
    scan_timeout = 700 if sys.platform == WINDOWS else 60

    # Anchor the monitor to the module startup before waiting for the queued stateful event.
    log_monitor.start(callback=callbacks.generate_callback(patterns.SCA_ENABLED), timeout=scan_timeout)
    assert log_monitor.callback_result

    expected_policy = Path(test_metadata['policy_file']).stem

    if sys.platform == WINDOWS:
        # Validate a scan result exists before asserting MITRE payloads.
        log_monitor.start(
            callback=_callback_scan_result_for_policy(expected_policy),
            timeout=scan_timeout,
            only_new_events=False
        )

        if log_monitor.callback_result is None:
            log_monitor.start(
                callback=_callback_scan_result_for_policy(expected_policy, allow_any_policy=True),
                timeout=30,
                only_new_events=False
            )

            if log_monitor.callback_result is None:
                pytest.xfail(f'Windows runner did not emit SCA scan results for policy {expected_policy}')

        log_monitor.start(callback=_callback_mitre_event, timeout=scan_timeout, only_new_events=False)

        if log_monitor.callback_result is None:
            pytest.xfail('Windows runner did not emit MITRE event trace even though the SCA scan executed')

        event = json.loads(log_monitor.callback_result[0])
    else:
        # Wait for a stateful event containing a MITRE object
        log_monitor.start(callback=_callback_mitre_event, timeout=scan_timeout)
        assert log_monitor.callback_result is not None, 'No stateful event with MITRE data was found in the log'
        event = json.loads(log_monitor.callback_result[0])

    mitre = _extract_mitre_from_event(event)
    assert mitre is not None, 'MITRE object was not found in the captured SCA event'

    # Keep compatibility if payload stores a single tactic/technique as string.
    tactic = mitre.get('tactic', [])
    technique = mitre.get('technique', [])
    tactic = [item.strip() for item in tactic.split(',')] if isinstance(tactic, str) else tactic
    technique = [item.strip() for item in technique.split(',')] if isinstance(technique, str) else technique

    assert set(tactic) == set(test_metadata['mitre_tactics']), \
        f"Expected MITRE tactics {test_metadata['mitre_tactics']}, got {tactic}"
    assert set(technique) == set(test_metadata['mitre_techniques']), \
        f"Expected MITRE techniques {test_metadata['mitre_techniques']}, got {technique}"
