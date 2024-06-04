"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.constants.paths.sockets import ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON
from wazuh_testing.modules.analysisd.patterns import ANALYSISD_STARTED
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.utils import callbacks
from wazuh_testing.tools.monitors import file_monitor

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_protocols_communication.yaml')
config_path = Path(CONFIGS_PATH, 'config_protocols_communication.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


EXAMPLE_MESSAGE_EVENT = '1:/root/test.log:Feb 23 17:18:20 35-u20-manager4 sshd[40657]: Accepted publickey for root' \
                        ' from 192.168.0.5 port 48044 ssh2: RSA SHA256:IZT11YXRZoZfuGlj/K/t3tT8OdolV58hcCOJFZLIW2Y'

# Test variables.
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]

mitm_analysisd = ManInTheMiddle(address=ANALYSISD_QUEUE_SOCKET_PATH, family='AF_UNIX', connection_protocol='UDP')
monitored_sockets_params = [(ANALYSISD_DAEMON, mitm_analysisd, True)]

receiver_sockets, monitored_sockets = None, None  # Set in the fixtures


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_protocols_communication(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents, configure_sockets_environment_module,
                       connect_to_sockets_module, waiting_for_analysisd_startup):

    '''
    description: Check agent-manager communication via TCP, UDP or both.
                 For this purpose, the test will log and send the message to check if the communication works fine.
                 Then, after the sender ends, the socket connection is closed.

    parameters:
        - test_configuration
            type: dict
            brief: Configuration applied to ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - daemons_handler:
            type: fixture
            brief: Restart service once the test finishes stops the daemons.
        - simulate_agents
            type: fixture
            brief: create agents
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_sockets_environment_module:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Connect to a given list of sockets.
        - waiting_for_analysisd_startup:
            type: fixture
            brief: Wait until the 'wazuh-analysisd' has begun and the 'alerts.json' file is created.

    '''
    agent = simulate_agents[0]

    message = EXAMPLE_MESSAGE_EVENT

    callback = callbacks.generate_callback(".*")

    sender, injector = connect(agent, protocol = test_metadata['protocol1'], manager_port = test_metadata['port'])

    sender.send_event(agent.create_event(message))

    monitored_sockets[0].start(callback=callback)

    assert monitored_sockets[0].callback_result

    injector.stop_receive()
