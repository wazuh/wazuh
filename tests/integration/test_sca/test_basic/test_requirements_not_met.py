'''
copyright: Copyright (C) Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that a policy skipped because its requirements are not met is reported at INFO level.

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
import pytest
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.modulesd.sca import PREFIX

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

SCA_POLICY_SKIPPED = fr'{PREFIX}INFO: Policy "(.*?)" skipped: its requirements are not met\.'

# Configuration and cases data
configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_sca.yaml')
cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_requirements_not_met.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = configuration.get_test_cases_data(cases_path)
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_requirements_not_met(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                              set_wazuh_configuration, clean_sca_db, daemons_handler):
    '''
    description: Check that the agent logs at INFO level, without raising the debug level, that a policy was
                 skipped because its requirements are not met.

    test_phases:
        - Copy a policy whose requirements never pass into the agent.
        - Restart wazuh.
        - Check the INFO line reporting the skipped policy.

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
        - clean_sca_db:
            type: fixture
            brief: Remove SCA database files to prevent stale data between tests.
        - daemons_handler:
            type: fixture
            brief: Restart the wazuh daemons.

    assertions:
        - Verify the skipped policy is reported at INFO level with its id.

    input_description:
        - The `cases_requirements_not_met.yaml` file provides the module configuration for this test.
        - The `requirements_not_met.yaml` policy file has requirements that never pass.

    expected_output:
        - r".*sca.*INFO: Policy \"(.*?)\" skipped: its requirements are not met."
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # wait_for_sca_enabled is not used: it waits for the checks evaluation to start, which never happens here.
    log_monitor.start(callback=callbacks.generate_callback(SCA_POLICY_SKIPPED), timeout=90)
    assert log_monitor.callback_result is not None, 'The skipped policy was not reported at INFO level'
    assert log_monitor.callback_result[0] == Path(test_metadata['policy_file']).stem
