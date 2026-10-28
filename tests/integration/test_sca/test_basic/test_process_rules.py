'''
copyright: Copyright (C) Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that SCA process rules match running processes by their kernel task name, also when
       their argv[0] does not carry it.

components:
    - sca

suite: sca

targets:
    - agent

daemons:
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Ubuntu Noble

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html

tags:
    - sca
'''
import shutil
import subprocess
import sys
import tempfile
import pytest
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.modulesd.sca import patterns
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

local_internal_options = {MODULESD_DEBUG: '2'}

# Configuration and cases data
configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_sca.yaml')
cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_process_rules.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = configuration.get_test_cases_data(cases_path)
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


@pytest.fixture()
def start_test_processes():
    '''
    Starts two processes whose argv[0] does not carry their name, so only their kernel task name (comm) does:
      - a copy of sleep named wzsca-proc that rewrites its argv[0] to "wzsca: master process", as nginx does.
      - a script named wzsca-script started through its shebang line, so argv[0] is the interpreter.
    Kills them and removes their files after the test.
    '''
    work_dir = tempfile.mkdtemp(prefix='wzsca-')
    binary = Path(work_dir, 'wzsca-proc')
    shutil.copy(shutil.which('sleep'), binary)
    script = Path(work_dir, 'wzsca-script')
    script.write_text(f'#!{sys.executable}\nimport time\ntime.sleep(3600)\n')
    script.chmod(0o755)

    processes = [subprocess.Popen(['wzsca: master process', '3600'], executable=binary),
                 subprocess.Popen([script])]
    yield
    for process in processes:
        process.kill()
        process.wait()
    shutil.rmtree(work_dir, ignore_errors=True)


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_process_rules(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                       set_wazuh_configuration, configure_local_internal_options, clean_sca_db, start_test_processes,
                       daemons_handler, wait_for_sca_enabled):
    '''
    description: Check that process rules ('p:') match a running process by its kernel task name, without case
                 (also for a plain term of a compound value), and with a regex value, also when the process
                 rewrote its argv[0] or was started through an interpreter.

    test_phases:
        - Copy the process rules policy into the agent.
        - Start the test processes.
        - Restart wazuh.
        - Get the result of each check of the scan and compare it with the expected one.

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
            brief: copy test sca policy file. Delete it after test.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local_internal_options_file.
        - clean_sca_db:
            type: fixture
            brief: Remove SCA database files to prevent stale data between tests.
        - start_test_processes:
            type: fixture
            brief: Start the processes the policy checks. Kill them after test.
        - daemons_handler:
            type: fixture
            brief: Restart the wazuh daemons.
        - wait_for_sca_enabled:
            type: fixture
            brief: Wait for the sca Module to start before starting the test.

    assertions:
        - Verify the process rules of a running process pass for its kernel task name, in any case, as a regex and
          as a compound value.
        - Verify the process rule of a process that is not running fails.

    input_description:
        - The `cases_process_rules.yaml` file provides the module configuration and expected results for this test.
        - The `process_rules.yaml` policy file provides the sca checks.

    expected_output:
        - r".*sca.*DEBUG: Policy check \"([0-9]+)\" evaluation completed for policy \"(.*?)\", result: (Passed|Failed)"
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    expected_policy = Path(test_metadata['policy_file']).stem
    expected_results = test_metadata['expected_results']

    log_monitor.start(callback=callbacks.generate_callback(patterns.SCA_SCAN_RESULT), timeout=60,
                      accumulations=len(expected_results))
    scan_results = log_monitor.callback_result
    if isinstance(scan_results, tuple):
        scan_results = [scan_results]

    assert scan_results is not None, 'The SCA scan did not report the check results'
    results = {check_id: result for check_id, policy, result in scan_results if policy == expected_policy}
    assert results == expected_results
