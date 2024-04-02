'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       The objective is to check that, with different states in the 'clients.keys' file,
       the agent successfully enrolls after losing connection with the 'wazuh-remoted' daemon.
       The wazuh-remoted program is the server side daemon that communicates with the agents.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-authd
    - wazuh-remoted

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

references:
    - https://documentation.wazuh.com/current/user-manual/registering/index.html

tags:
    - enrollment
'''
import pytest
from pathlib import Path
import sys

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.tools.simulators.authd_simulator import AuthdSimulator
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH
from utils import wait_keepalive, wait_enrollment, wait_enrollment_try

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_reconnection_protocol.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}
local_internal_options.update({AGENTD_TIMEOUT: '5'})

daemons_handler_configuration = {'all_daemons': True}

# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_reconection_enrollment_no_keys(test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files, clean_keys, daemons_handler):
    '''
        description: Check how the agent behaves when losing communication with
                 the 'wazuh-remoted' daemon and a new enrollment is sent to
                 the 'wazuh-authd' daemon.
                 In this case, the agent has its 'client.keys' file empty

    wazuh_min_version: 4.2.0

    tier: 0

   parameters:
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - clean_keys:
            type: fixture
            brief: Cleans keys file content
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that the agent enrollment is successful.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Two test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Valid key received'
        - r'Sending keep alive'

    tags:
        - simulator
        - ssl
        - keys
    '''
    # Prepare test
    authd_server = AuthdSimulator()
    authd_server.start()

    # Wait until Agent asks keys for the first time
    wait_enrollment()

    # Start RemotedSimulator
    remoted_server = RemotedSimulator(protocol = test_metadata['PROTOCOL'])
    remoted_server.start()

    # Wait until Agent is notifying Manager
    wait_keepalive()

    # Reset simulator
    remoted_server.destroy()

    # Start rejecting Agent
    remoted_server = RemotedSimulator(protocol = test_metadata['PROTOCOL'], mode = 'WRONG_KEY')
    remoted_server.start()

    # Wait until Agent asks a new key to enrollment
    wait_enrollment_try()

    # Reset simulator
    remoted_server.destroy()

    # Start RemotedSimulator
    remoted_server = RemotedSimulator(protocol = test_metadata['PROTOCOL'])
    remoted_server.start()

    # Wait until Agent is notifying Manager
    wait_keepalive()

    # Reset simulator
    authd_server.destroy()

    # Reset simulator
    remoted_server.destroy()
