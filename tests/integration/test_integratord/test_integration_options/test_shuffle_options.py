'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Integratord manages wazuh integrations with other applications such as Slack, Pagerduty, Shuffle, Yara or
       Virustotal by feeding the integrated aplications with the alerts located in alerts.json file. Custom values for
       fields can be configured to be sent using the 'options' tag. This test modules aim to test how the shuffle
       integration works with different configurations, when the options tag is not present or when custom values are
       passed into the tag for the shuffle integration

components:
    - integratord

suite: integration_options

targets:
    - manager

daemons:
    - wazuh-integratord

os_platform:
    - Linux

os_version:
    - Centos 8
    - Ubuntu Focal

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/virustotal-scan/integration.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.htm

pytest_args:
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - shuffle
'''
import pytest
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing import session_parameters
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON, WAZUH_DB_DAEMON, INTEGRATOR_DAEMON
from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH, WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd.configuration import ANALYSISD_DEBUG
from wazuh_testing.modules.integratord.configuration import INTEGRATORD_DEBUG
from wazuh_testing.modules.integratord.patterns import INTEGRATORD_THIRD_PARTY_RESPONSE, INTEGRATORD_ENABLED_INTEGRATION, \
                                                       INTEGRATORD_OPTIONS_FILE_DOES_NOT_EXISTENT, INTEGRATORD_SENDING_MESSAGE, \
                                                       INTEGRATORD_ERROR_RUNNING_INTEGRATION
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.commands import run_local_command_returning_output
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = [pytest.mark.server]

# Paths
t1_configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_shuffle_no_option_tag.yaml')
t2_configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_shuffle_options.yaml')
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_shuffle_no_option_tag.yaml')
t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_shuffle_options.yaml')

# Configurations
test1_configuration, test1_metadata, test1_cases_ids = get_test_cases_data(t1_cases_path)
test2_configuration, test2_metadata, test2_cases_ids = get_test_cases_data(t2_cases_path)

test1_configuration = load_configuration_template(t1_configurations_path, test1_configuration, test1_metadata)
test2_configuration = load_configuration_template(t2_configurations_path, test2_configuration, test2_metadata)

# Variables
JSON_ALERT = '{"timestamp":"2022-05-11T12:29:19.905+0000",' \
              '"rule":{"level":10,"description":"testing","id":"1234","groups":["test"]},' \
              '"agent":{"id":"000","name":"localhost.localdomain"},' \
              '"id":"1652272159.1549653",' \
              '"location":"/test"}'
daemons_handler_configuration = {'daemons': [INTEGRATOR_DAEMON, WAZUH_DB_DAEMON, ANALYSISD_DAEMON]}
local_internal_options = {INTEGRATORD_DEBUG: '2', ANALYSISD_DEBUG: '1', MONITORD_ROTATE_LOG: '0'}


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test1_configuration, test1_metadata), ids=test1_cases_ids)
def test_shuffle_no_option_tag(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                               configure_local_internal_options, daemons_handler, wait_for_integratord_start):
    '''
    description: Check that when the options tag is not present for the Shuffle integration, the integration works
                 properly.

    wazuh_min_version: 4.6.0

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Check integration is enabled
            - Check no options JSON file is created
            - Check the message is sent to the Shuffle server
            - Check the response code is 200
        - teardown:
            - Restore configuration
            - Stop wazuh

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler:
            type: fixture
            brief: Restart wazuh daemon before starting a test.
        - wait_for_integratord_start:
            type: fixture
            brief: Detect the start of the Integratord module

    assertions:
        - Verify the integration is enabled
        - Verify no options JSON file is detected
        - Verify the integration sends message to the integrated app's server
        - Verify the response code from the integrated app

    input_description:
        - The `config_integration_no_option_tag.yaml` file provides the module configuration for this test.
        - The `cases_integration_no_option_tag_alerts` file provides the test cases.

    expected_output:
        - ".*(Enabling integration for: '{integration}')."
        - ".*ERROR: Unable to run integration for ({integration}) -> integrations"
        - '.*OS_IntegratorD.*(JSON file for options  doesn't exist)'
        - '.*Response received.* [200].*'
    '''
    wazuh_monitor = FileMonitor(WAZUH_LOG_PATH)
    command = f"echo '{JSON_ALERT}' >> {ALERTS_JSON_PATH}"

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_ENABLED_INTEGRATION,
                                                   replacement={"integration": test_metadata['integration']}),
                                                   timeout=session_parameters.default_timeout)

    # Check integration is enabled
    assert wazuh_monitor.callback_result

    # Insert a new alert
    run_local_command_returning_output(command)

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_OPTIONS_FILE_DOES_NOT_EXISTENT), timeout=session_parameters.default_timeout)

    # Check no options JSON file is detected
    assert wazuh_monitor.callback_result

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_SENDING_MESSAGE,
                                                   replacement={"integration": 'Shuffle'}),
                                                   timeout=session_parameters.default_timeout)

    # Check the message is sent to the integration's server
    assert wazuh_monitor.callback_result

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_THIRD_PARTY_RESPONSE), timeout=session_parameters.default_timeout)

    # Check the response code from the integration's server
    assert wazuh_monitor.callback_result


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test2_configuration, test2_metadata), ids=test2_cases_ids)
def test_shuffle_options(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                         configure_local_internal_options, daemons_handler, wait_for_integratord_start):
    '''
    description: Check that when configuring the options tag with differents values, the integration works as expected.
                 The test also checks that when it is supposed to fail, it fails.

    wazuh_min_version: 4.6.0

    test_phases:
        - setup:
            - Set wazuh configuration and local_internal_options.
            - Clean logs files and restart wazuh to apply the configuration.
        - test:
            - Check integration is enabled
            - Check the integration is unable to run when expected
            - Check the integration sends the message and gets a response when expected
        - teardown:
            - Restore configuration
            - Stop wazuh

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_template`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - daemons_handler:
            type: fixture
            brief: Restart wazuh daemon before starting a test.
        - wait_for_integratord_start:
            type: fixture
            brief: Detect the start of the Integratord module

    assertions:
        - Verify the integration is enabled
        - Verify no options JSON file is detected
        - Verify the integration sends message to the integrated app's server
        - Verify the response code from the integrated app


    input_description:
        - The `config_shuffle_options.yaml` file provides the module configuration for this test.
        - The `cases_shuffle_options.yaml` file provides the test cases.

    expected_output:
        - ".*(Enabling integration for: '{integration}')."
        - ".*ERROR: Unable to run integration for ({integration}) -> integrations"
        - '.*OS_IntegratorD.*(JSON file for options  doesn't exist)'
        - '.*Response received.* [200].*'

    '''
    wazuh_monitor = FileMonitor(WAZUH_LOG_PATH)
    command = f"echo '{JSON_ALERT}' >> {ALERTS_JSON_PATH}"

    # Start monitor
    wazuh_monitor.start(callback=generate_callback(INTEGRATORD_ENABLED_INTEGRATION,
                                                   replacement={"integration": test_metadata['integration']}),
                                                   timeout=session_parameters.default_timeout)

    # Check integration is enabled
    assert wazuh_monitor.callback_result

    # Insert a new alert
    run_local_command_returning_output(command)

    if not test_metadata['sends_message']:
        # Start monitor
        wazuh_monitor.start(callback=generate_callback(INTEGRATORD_ERROR_RUNNING_INTEGRATION,
                                                    replacement={"integration": 'shuffle'}),
                                                    timeout=session_parameters.default_timeout)

        # Check the message is sent to the integration's server
        assert wazuh_monitor.callback_result
    else:
        # Start monitor
        message = wazuh_monitor.start(callback=generate_callback(INTEGRATORD_SENDING_MESSAGE,
                                                    replacement={"integration": 'Shuffle'}),
                                                    timeout=session_parameters.default_timeout,
                                                    return_matched_line=True)

        # Check the message is sent to the integration's server
        assert wazuh_monitor.callback_result

        # Verify that when the options JSON was not empty the sent information is in the response message.
        if test_metadata['added_option'] is not None:
            assert test_metadata['added_option'] in message, "The configured option is not present in the message sent"

        # Start monitor
        wazuh_monitor.start(callback=generate_callback(INTEGRATORD_THIRD_PARTY_RESPONSE), timeout=session_parameters.default_timeout)

        # Check the response code from the integration's server
        assert wazuh_monitor.callback_result
