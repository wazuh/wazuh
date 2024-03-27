'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The wazuh-analysisd daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. The 'if_sid' option is used to
       associate a rule to a parent rule by referencing the rule ID of the parent. This test module checks that when
       a null rule_id is used, the rule is ignored.

components:
    - analysisd

suite: analysisd

targets:
    - manager

daemons:
    - wazuh-analysisd

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
    - https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#if-sid
'''
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd.testrule import patterns
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, configuration

from . import CONFIGS_PATH, TEST_CASES_PATH, RULES_SAMPLE_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'configuration_signature_id_values.yaml')
test_cases_path = Path(TEST_CASES_PATH, 'cases_null_signature_id.yaml')

# Test configurations.
test_configuration, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)
test_configuration = configuration.load_configuration_template(configs_path, test_configuration, test_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_null_signature_id(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                           prepare_custom_rules_file, daemons_handler):
    '''
    description: Check that when a rule has a null signature ID value, that references a nonexisten rule,
                 assigned to the if_sid option, the rule is ignored.

    test_phases:
        - Setup:
            - Set wazuh configuration.
            - Copy custom rules file into manager
            - Clean logs files and restart wazuh to apply the configuration.
        - Test:
            - Check "if_sid not found" log is detected
            - Check "empty if_sid" log is detected
        - Teardown:
            - Delete custom rule file
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.4.0

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - prepare_custom_rules_file:
            type: fixture
            brief: Copies custom rules_file before test, deletes after test.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check that wazuh starts
        - Check ".*Signature ID '(\\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\\d*)'" event
        - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

    input_description:
        - The `configuration_signature_id_values.yaml` file provides the module configuration for
          this test.
        - The `cases_null_signature_id.yaml` file provides the test cases.
    '''
    # Instance monitor.
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Check that expected log appears for rules if_sid field pointing to a non existent SID
    log_monitor.start(callback=callbacks.generate_callback(patterns.SID_NOT_FOUND))
    assert log_monitor.callback_result

    # Check that expected log appears for rules if_sid field being empty (empty since non-existent SID is ignored)
    log_monitor.start(callback=callbacks.generate_callback(patterns.EMPTY_IF_SID_RULE_IGNORED))
    assert log_monitor.callback_result
