'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests validate the SCA compliance field handling for new flat-object format,
       invalid keys rejection, and old array-of-objects format detection.

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
    - CentOS 9
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html

tags:
    - sca
'''
import pytest
import re
import json
import sys
from pathlib import Path

from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.modulesd.sca import patterns
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

local_internal_options = {AGENTD_WINDOWS_DEBUG if sys.platform == WINDOWS else MODULESD_DEBUG: '2'}

# Configuration and cases data
configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_sca.yaml')
cases_path = Path(TEST_CASES_FOLDER_PATH,
                  'cases_compliance_format_win.yaml' if sys.platform == WINDOWS else 'cases_compliance_format.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = configuration.get_test_cases_data(cases_path)
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters,
                                                           configuration_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

SCA_DB_DIR = Path(WAZUH_PATH, 'queue', 'sca', 'db')


@pytest.fixture()
def clean_sca_db():
    '''Remove SCA database files to prevent stale data between tests.'''
    if SCA_DB_DIR.exists():
        for f in SCA_DB_DIR.iterdir():
            f.unlink(missing_ok=True)
    yield


def extract_compliance_from_event_json(json_str):
    '''Extract the check ID and compliance dict from SCA event JSON.

    Handles both stateless (data.check.compliance) and stateful (check.compliance) formats.

    Returns:
        tuple: (check_id, compliance_dict_or_None)
    '''
    try:
        event = json.loads(json_str)
    except json.JSONDecodeError:
        return (None, None)

    # Stateless format: data.check
    check = event.get('data', {}).get('check', {})
    if not check:
        # Stateful format: check
        check = event.get('check', {})

    check_id = check.get('id')
    compliance = check.get('compliance')

    return (check_id, compliance)


@pytest.mark.parametrize('test_configuration, test_metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_sca_compliance_format(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                               set_wazuh_configuration, configure_local_internal_options, clean_sca_db,
                               daemons_handler, wait_for_sca_enabled):
    '''
    description: This test validates the SCA compliance field handling across three scenarios:
                 valid keys (new flat-object format), invalid keys (mixed valid/invalid), and
                 old format (array-of-objects). It verifies that valid keys are preserved in events,
                 invalid keys trigger warnings and are stripped, and old format triggers a warning
                 with compliance stripped entirely.

    test_phases:
        - Copy SCA policy file into agent.
        - Restart wazuh.
        - Wait for SCA scan to complete.
        - Validate WARNING messages in log for invalid/old-format compliance.
        - Validate compliance keys in SCA event JSON.

    wazuh_min_version: 5.0.0

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
            brief: Copy test SCA policy file. Delete it after test.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local_internal_options_file.
        - daemons_handler:
            type: fixture
            brief: Restart all wazuh daemons.
        - wait_for_sca_enabled:
            type: fixture
            brief: Wait for the SCA module to start before starting the test.
        - clean_sca_db:
            type: fixture
            brief: Remove SCA database files to prevent stale data between tests.

    assertions:
        - Verify that valid compliance keys are preserved in SCA event JSON.
        - Verify that invalid compliance keys trigger WARNING logs and are stripped from events.
        - Verify that old array-of-objects compliance format triggers WARNING and is stripped entirely.

    input_description:
        - The `cases_compliance_format.yaml` file provides the module configuration for this test.
        - The cis_{lin,win}_compliance_*.yaml files in policies_samples provide the SCA rules to check.

    expected_output:
        - r".*sca.*WARNING: Invalid compliance key '(\S+)' in check (\S+), ignoring"
        - r".*sca.*WARNING: Unexpected compliance format in check (\S+), ignoring"
    '''
    scenario = test_metadata['scenario']
    expected_policy = Path(test_metadata['policy_file']).stem

    # ------------------------------------------------------------------
    # Phase 1: Wait for scan completion
    # ------------------------------------------------------------------
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    timeout = 60 if sys.platform == WINDOWS else 30

    log_monitor.start(callback=callbacks.generate_callback(patterns.SCA_SCAN_STARTED_CHECK), timeout=timeout)
    assert log_monitor.callback_result is not None and log_monitor.callback_result[0] == expected_policy

    log_monitor.start(callback=callbacks.generate_callback(patterns.SCA_SCAN_RESULT),
                      timeout=timeout, accumulations=int(test_metadata['results']))
    assert log_monitor.callback_result is not None

    log_monitor.start(callback=callbacks.generate_callback(patterns.SCA_SCAN_ENDED_CHECK), timeout=timeout)
    assert log_monitor.callback_result is not None and log_monitor.callback_result[0] == expected_policy

    # ------------------------------------------------------------------
    # Phase 2: Validate WARNING messages
    # ------------------------------------------------------------------
    with open(WAZUH_LOG_PATH, 'r') as f:
        log_content = f.read()

    # Old-format scenario: assert 'Unexpected compliance format' warnings for all check IDs
    if scenario == 'old_format':
        for check_info in test_metadata['checks']:
            check_id = check_info['id']
            assert re.search(
                rf"Unexpected compliance format in check {re.escape(check_id)}, ignoring",
                log_content
            ), f"Expected 'Unexpected compliance format' warning for check {check_id}"

    # Invalid-keys scenario: assert 'Invalid compliance key' warnings for specified keys, and NO 'Unexpected compliance format' warnings for any check ID
    elif scenario == 'invalid_keys':
        for check_info in test_metadata['checks']:
            check_id = check_info['id']
            assert not re.search(
                rf"Unexpected compliance format in check {re.escape(check_id)}",
                log_content
            ), f"Unexpected 'Unexpected compliance format' warning for check {check_id}"
            for key in check_info.get('invalid_key_warnings', []):
                assert re.search(
                    rf"Invalid compliance key '{re.escape(key)}' in check {re.escape(check_id)}, ignoring",
                    log_content
                ), f"Expected 'Invalid compliance key' warning for key '{key}' in check {check_id}"

    # Valid-keys scenario: assert NO 'Invalid compliance key' or 'Unexpected compliance format' warnings for any check ID
    elif scenario == 'valid_keys':
        for check_info in test_metadata['checks']:
            check_id = check_info['id']
            assert not re.search(
                rf"Invalid compliance key.*in check {re.escape(check_id)}",
                log_content
            ), f"Unexpected 'Invalid compliance key' warning for check {check_id}"
            assert not re.search(
                rf"Unexpected compliance format in check {re.escape(check_id)}",
                log_content
            ), f"Unexpected 'Unexpected compliance format' warning for check {check_id}"

    # ------------------------------------------------------------------
    # Phase 3: Validate compliance in event JSON
    # ------------------------------------------------------------------
    events_by_check = {}
    for match in re.finditer(patterns.SCA_SENDING_EVENT, log_content):
        json_str = match.group(1)
        check_id, compliance = extract_compliance_from_event_json(json_str)
        if check_id:
            events_by_check[check_id] = compliance

    for check_info in test_metadata['checks']:
        check_id = check_info['id']
        expected_keys = check_info.get('expected_compliance_keys', [])
        unexpected_keys = check_info.get('unexpected_compliance_keys', [])

        assert check_id in events_by_check, f"No SCA event found for check {check_id}"
        compliance = events_by_check[check_id]

        if scenario == 'old_format':
            assert compliance is None, \
                f"Check {check_id}: compliance should be stripped for old format, got {compliance}"

        elif scenario == 'invalid_keys':
            assert compliance is not None, \
                f"Check {check_id}: compliance should be present but was None"
            for key in expected_keys:
                assert key in compliance, \
                    f"Check {check_id}: expected key '{key}' not found in compliance"
            for key in unexpected_keys:
                assert key not in compliance, \
                    f"Check {check_id}: unexpected key '{key}' found in compliance"

        elif scenario == 'valid_keys':
            assert compliance is not None, \
                f"Check {check_id}: compliance should be present but was None"
            actual_keys = sorted(compliance.keys())
            assert actual_keys == sorted(expected_keys), \
                f"Check {check_id}: expected keys {sorted(expected_keys)}, got {actual_keys}"
