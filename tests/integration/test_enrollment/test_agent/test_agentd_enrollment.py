'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of Wazuh Agentd during the enrollment under different configurations.
components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

tags:
    - enrollment
'''

import json
import sys
import time
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.tools.simulators.remoted_simulator import ENROLL_ENDPOINT
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import make_callback

from . import CONFIGS_PATH, TEST_CASES_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_wazuh_enrollment.yaml')
config_path = Path(CONFIGS_PATH, 'config_wazuh_enrollment.yaml')
config_parameters, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, config_parameters, test_metadata)

# Test variables.
socket_listener = None

daemons_handler_configuration = {'all_daemons': True}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_agentd_enrollment(test_configuration, test_metadata, set_wazuh_configuration, daemons_handler_module, shutdown_agentd,
                           set_keys, set_password, configure_socket_listener, restart_agentd):
    """
    description:
        "Check that different configuration generates the adequate enrollment message or the corresponding error
        log. The configuration, keys, and password files will be written with the different scenarios described
        in the test cases. After this, Agentd is started to wait for the expected result."

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.
        - set_keys:
            type: fixture
            brief: Write pre-existent keys into client.keys.
        - set_password:
            type: fixture
            brief: Write the password file.
        - configure_socket_listener:
            type: fixture
            brief: Configure the manager-side listener the agent enrolls against, rejecting
                   it first to force re-enrollment when it starts with a pre-existent key.
        - restart_agentd:
            type: fixture
            brief: Restart Agentd and control if it is expected to fail or not.

    assertions:
        - The enrollment message is sent when the configuration is valid
        - The enrollment message is generated as expected when the configuration is valid.
        - The error log is generated as expected when the configuration is invalid.

    input_description:
        Different test cases are contained in an external YAML file (wazuh_enrollment_tests.yaml) which includes the
        different available enrollment-related configurations.

    expected_output:
        - Enrollment request sent to POST /enroll
        - Error logs related to the wrong configuration block
    """

    if 'expected_error' in test_metadata:
        expected_error_dict = test_metadata['expected_error']
        expected_error = expected_error_dict['agent-enrollment'] if 'agent-enrollment' in expected_error_dict else \
                                                                    expected_error_dict
        try:
            log_monitor = FileMonitor(WAZUH_LOG_PATH)
            log_monitor.start(timeout=10, callback=make_callback(expected_error, prefix='.*', escape=True))
        except Exception as error:
            expected_fail = test_metadata.get('expected_fail')
            if expected_fail and (expected_fail['os'] == "any" or expected_fail['os'] == sys.platform):
                is_xfail = True
                xfail_reason = expected_fail.get('reason')
            else:
                is_xfail = False

            if is_xfail:
                pytest.xfail(f"Xfailing due to {xfail_reason}")
            else:
                raise error

    else:
        expected_fields = test_metadata['message']['expected']

        # Polls socket_listener's own request store (cleared fresh per case by
        # configure_socket_listener) rather than waiting on an ossec.log line: the log
        # isn't truncated between parametrized cases in this module, so a message logged
        # once early (e.g. "Valid key received") would otherwise satisfy every later
        # case's wait instantly, before that case's own /enroll request has even arrived.
        deadline = time.time() + (60 if sys.platform == WINDOWS else 20)
        enroll_request = None
        while time.time() < deadline:
            enroll_request = socket_listener.last_request(ENROLL_ENDPOINT)
            if enroll_request is not None:
                break
            time.sleep(0.1)

        assert enroll_request is not None, 'No /enroll request was captured'
        body = json.loads(enroll_request['body'])

        for field, value in expected_fields.items():
            assert body.get(field) == value, (
                f"Expected {field}={value!r} in the /enroll request, got {body.get(field)!r}")
