'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logtest' tool allows the testing and verification of rules and decoders against provided log examples
       remotely inside a sandbox in 'wazuh-analysisd'. This functionality is provided by the manager, whose work
       parameters are configured in the ossec.conf file in the XML rule_test section. Test logs can be evaluated through
       the 'wazuh-logtest' tool or by making requests via RESTful API. These tests will check if the logtest
       configuration is valid. Also checks rules, decoders, decoders, alerts matching logs correctly.

components:
    - logtest

suite: ruleset_refresh

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
    - https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/wazuh-logtest/index.html
    - https://documentation.wazuh.com/current/user-manual/ruleset/testing.html?highlight=logtest
    - https://documentation.wazuh.com/current/user-manual/capabilities/wazuh-logtest/logtest-configuration.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - logtest_configuration
'''
from pathlib import Path
import pytest

from wazuh_testing.constants.paths.sockets import LOGTEST_SOCKET_PATH
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON, WAZUH_DB_DAEMON
from json import loads
from wazuh_testing.utils import configuration

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
t_configurations = []
t_config_metadata = []
t_case_ids = []

for i in range(1,5):
    t_aux_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_decoder_labels_' + str(i) + '.yaml')
    t_aux_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_decoder_labels_' + str(i) + '.yaml')
    t_aux_config_parameters, t_aux_config_metadata, t_aux_case_ids = configuration.get_test_cases_data(t_aux_cases_path)
    t_aux_configurations = configuration.load_configuration_template(t_aux_config_path,
                                                                     t_aux_config_parameters, t_aux_config_metadata)
    t_configurations = t_configurations + t_aux_configurations
    t_config_metadata = t_config_metadata + t_aux_config_metadata
    t_case_ids = t_case_ids + t_aux_case_ids

# Variables
receiver_sockets_params = [(LOGTEST_SOCKET_PATH, 'AF_UNIX', 'TCP')]
receiver_sockets = None

# Test daemons to restart.
daemons_handler_configuration = {'daemons': [ANALYSISD_DAEMON, WAZUH_DB_DAEMON]}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t_configurations, t_config_metadata), ids=t_case_ids)
def test_rules_verbose(test_configuration, test_metadata, set_wazuh_configuration,
                       daemons_handler_module, configure_decoders_list,
                       wait_for_logtest_startup, connect_to_sockets):
    '''
    description: Checks if modifying the configuration of the decoder, by using its labels, takes effect when opening
                 new logtest sessions without having to reset the manager. To do this, it sends a request to logtest
                 socket with the test case and it checks that the result matches with the test case.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.
        - configure_cdbs_list:
            type: fixture
            brief: Configure a custom cdbs for testing.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - connect_to_sockets:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.

    assertions:
        - Verify that the result does not contain errors.
        - Verify that the result is from the decoder list.
        - Verify that the 'rule_id' sent matches with the result.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'decoder_list.yaml'.

    expected_output:
        - result.error == 0
        - name not in result.data.output.decoder
        - result.data.output.decoder.name == test_case.decoder_name

    tags:
        - decoder
        - analysisd
    '''
    # send the logtest request
    receiver_sockets[0].send(test_metadata['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = loads(response)

    assert result['error'] == 0
    if 'test_exclude' in test_metadata:
        assert 'name' not in result['data']['output']['decoder']
    else:
        assert result['data']['output']['decoder']['name'] == test_metadata['decoder_name']
