'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon receives the log messages and compares them to the rules.
       It then creates an alert when a log message matches an applicable rule.
       Specifically, these tests will verify if the pre-decoding stage of 'wazuh-analysisd' daemon correctly handles
       syslog formats.

components:
    - analysisd

suite: predecoder_stage

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

'''

import pytest
import json

from pathlib import Path

from wazuh_testing.constants.paths.sockets import LOGTEST_SOCKET_PATH
from wazuh_testing.utils import configuration

from . import TEST_CASES_PATH

pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Configuration and cases data.
test_cases_path = Path(TEST_CASES_PATH, 'cases_syslog_socket_input.yaml')

# Test configurations.
_, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Test variables.
receiver_sockets_params = [(LOGTEST_SOCKET_PATH, 'AF_UNIX', 'TCP')]

receiver_sockets = None  # Set in the fixtures


# Test function.
@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_cases_ids)
def test_precoder_supported_formats(test_metadata, daemons_handler, connect_to_sockets):
    '''
    description: Check that the predecoder returns the correct fields when receives different sets of syslog formats.
                 To do this, it receives syslog format and checks that the predecoder JSON responses
                 are the same that the loaded ouput for each test case from the 'syslog_socket_input.yaml' file.

    wazuh_min_version: 4.3.0

    tier: 2

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - connect_to_sockets:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.

    assertions:
        - Checks that the predecoder gives the expected output.

    input_description: Different test cases that are contained in an external YAML file (syslog_socket_input.yaml)
                       that includes syslog events data and the expected precoder output.

    expected_output:
        - Precoder JSON with the correct fields (timestamp, program name, etc) corresponding to each test case.
    '''
    receiver_sockets[0].send(test_metadata['input'], size=True)

    result = json.loads(receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode())

    assert json.loads(test_metadata['output']) == result["data"]["output"]["predecoder"], \
        'Failed test case: the receved precoded is: {} but was expected to be {}' \
        .format(result["data"]["output"]["predecoder"], test_metadata['output'])
