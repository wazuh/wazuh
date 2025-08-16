'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will that a scan is ran using the configured sci_sca ruleset and regex engine.

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html

tags:
    - sca
'''
import sys
import os
import pytest
import re
import time
import stat
import subprocess
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.modulesd.sca import patterns
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.constants.platforms import WINDOWS

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

local_internal_options = {AGENTD_WINDOWS_DEBUG if sys.platform == WINDOWS else MODULESD_DEBUG: '2'}

# Configuration and cases data
configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_sca.yaml')
cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_validate_remediation_win.yaml' if sys.platform == WINDOWS else 'cases_validate_remediation.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = configuration.get_test_cases_data(cases_path)
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)
test_folder = '/testfile'

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

SCA_SCAN_STARTED = r".*sca.*DEBUG: Starting Policy requirements evaluation for policy *"
SCA_SCAN_ENDED = r".*sca.*DEBUG: Policy checks evaluation completed for policy *"

# Callback functions adapted to new SCA logs
def callback_scan_id_result(line):
    '''Return [check_id, result] when a policy check evaluation completes.'''
    match = re.match(r'.*sca.*DEBUG: Policy check "(\d+)" evaluation completed for policy "[^"]+", result: (\w+)\.', line)
    if match:
        return [match.group(1), match.group(2)]


# Tests
# TODO: Fix test before re-enabling
# @pytest.mark.skip(reason="Needs to be fixed")
@pytest.mark.parametrize('test_configuration, test_metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_validate_remediation_results(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                                      prepare_remediation_test, set_wazuh_configuration,
                                      configure_local_internal_options, daemons_handler,
                                      wait_for_sca_enabled):
    '''
    description: This test will check that a SCA scan results, with the  expected initial results (passed/failed) for a
                 given check, results change on subsequent checks if change is done to the system. For this a folder's
                 permissions will be checked, passing or failing if the permissions match. Then, the permissions for
                 the folder will be changed and wait for a new scan, and validate the results changed as expected.

    test_phases:
        - Copy cis_sca ruleset file into agent
        - Create a folder that will be checked by the SCA rules (Linux)
        - Restart wazuh
        - Validate the result for a given SCA check are as expected
        - Change the folder's permissions / Modifies the user lockout duration (Windows)
        - Validate the result for a given SCA check change as expected

    wazuh_min_version: 4.6.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - prepare_cis_policies_file:
            type: fixture
            brief: copy test sca policy file. Delete it after test.
        - prepare_remediation_test:
            type: fixture
            brief: Create a folder with a given set of permissions or modifies the user
                lockout duration in Windows. Delete it/Restores the value after test.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local_internal_options_file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_modulesd_function:
            type: fixture
            brief: Restart the wazuh-modulesd daemon.
        - wait_for_sca_enabled:
            type: fixture
            brief: Wait for the sca Module to start before starting the test.

    assertions:
        - Assert the result for a given check passed/failed as expected
        - Assert the result for a given check changes as expected after remediation/breaking commands

    input_description:
        - The `cases_validate_remediation.yaml` file provides the module configuration for this test.
        - The cis*.yaml files located in the policies folder provide the sca rules to check.

    expected_output:
        - r".*sca.*wm_sca_hash_integrity.*DEBUG: ID: (\\d+); Result: '(.*)'"
    '''

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Ensure initial state: set directory perms to 0644 so check 2 can initially pass
    if sys.platform != WINDOWS:
        try:
            os.chmod(test_folder, 0o644)
            # Verify
            assert stat.S_IMODE(os.lstat(test_folder).st_mode) == 0o644
        except Exception:
            pass

    # Wait for the SCA scan to start for the specific policy
    policy_name = Path(test_metadata['policy_file']).stem
    log_monitor.start(callback=callbacks.generate_callback(SCA_SCAN_STARTED + fr'"{policy_name}"'), timeout=10, only_new_events=True)
    assert log_monitor.callback_result

    # Get the results for the checks obtained in the initial SCA scan
    log_monitor.start(callback=callback_scan_id_result, timeout=20, \
                      only_new_events=True, accumulations=2)

    results = log_monitor.callback_result

    # Assert the tested check has initial expected results (failed/passed)
    # Find the result for the specific check id
    check_id = str(test_metadata['check_id'])
    check_result = None
    for result in results:
        if result[0] == check_id:
            check_result = result[1]
            break
    assert check_result is not None, f"Did not receive result for check id {check_id}"
    assert check_result.lower() == test_metadata['initial_result'], \
        f"Got unexpected SCA result: expected {test_metadata['initial_result']}, got {check_result}"

    # Ensure we change state between scan cycles
    log_monitor.start(callback=callbacks.generate_callback(SCA_SCAN_ENDED + fr'"{policy_name}"'), timeout=10, only_new_events=True)
    assert log_monitor.callback_result

    if sys.platform == WINDOWS:
        # Modify lockout duration
        subprocess.call('net accounts /lockoutduration:100', shell=True)
    else:
        # Modify the folder's permissions
        try:
            # Interpret perms from metadata correctly whether YAML gave int (decimal representation of octal) or string
            raw_perms = test_metadata['perms']
            if isinstance(raw_perms, int):
                new_mode = raw_perms
            else:
                new_mode = int(str(raw_perms), 8)
            os.chmod(test_folder, new_mode)
            # Verify and retry once if needed
            if stat.S_IMODE(os.lstat(test_folder).st_mode) != new_mode:
                time.sleep(0.2)
                os.chmod(test_folder, new_mode)
        except Exception:
            os.chmod(test_folder, 0o644)

    # Give the agent a brief moment before the next scan starts
    if sys.platform != WINDOWS:
        time.sleep(0.5)

    # Wait for the next scan to start
    log_monitor.start(callback=callbacks.generate_callback(SCA_SCAN_STARTED + fr'"{policy_name}"'), timeout=15, only_new_events=True)
    assert log_monitor.callback_result

    # Get the results for the checks obtained in the next SCA scan
    log_monitor.start(callback=callback_scan_id_result, timeout=20, \
                      only_new_events=True, accumulations=2)
    results = log_monitor.callback_result

    # Assert the tested check result changed as expected (passed to failed, and vice-versa)
    check_result = None
    for result in results:
        if result[0] == check_id:
            check_result = result[1]
            break
    assert check_result is not None, f"Did not receive result for check id {check_id}"
    assert check_result.lower() == test_metadata['final_result'], \
        f"Got unexpected SCA result: expected {test_metadata['final_result']}, got {check_result}"
