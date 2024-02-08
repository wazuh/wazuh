"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time

from pathlib import Path
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.constants.paths.sockets import ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.utils import callbacks

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_invalid_protocols_communication.yaml')
config_path = Path(CONFIGS_PATH, 'config_invalid_protocols_communication.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

injectors = []
search_patterns = []


receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]
mitm_analysisd = ManInTheMiddle(address=ANALYSISD_QUEUE_SOCKET_PATH, family='AF_UNIX', connection_protocol='UDP')
monitored_sockets_params = [(ANALYSISD_DAEMON, mitm_analysisd, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures



# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_invalid_protocols_communication(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, configure_sockets_environment_module, daemons_handler, simulate_agents,
                       connect_to_sockets_module, waiting_for_analysisd_startup):

    '''
    description: Check agent-manager communication with several agents simultaneously via TCP, UDP or both.
                 For this purpose, the test will create all the agents and select the protocol using Round-Robin. Then,
                 an event and a message will be created for each agent created. Finally, it will search for
                 those events within the messages sent to the manager.


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


    def validate_agent_manager_protocol_communication(protocol='TCP', manager_port=1514):


        def send_event(event, protocol, manager_port, agent):
            """Send an event to the manager"""

            sender, injector = connect(agent, manager_port = manager_port, protocol = protocol, wait_status= '' if protocol == 'UDP' else 'active' )
            sender.send_event(event)
            injectors.append(injector)
            return injector


        # Generate custom events for each agent
        search_pattern = f"test message from agent {agent.id}"
        agent_custom_message = f"1:/test.log:Feb 23 17:18:20 manager sshd[40657]: {search_pattern}"
        event = agent.create_event(agent_custom_message)

        # Create sender event threads
        send_event_thread = ThreadExecutor(send_event, {'event': event, 'protocol': protocol,
                                                        'manager_port': manager_port, 'agent': agent})

            # If protocol is TCP, then just send the message as the attempt to establish the connection will fail.
        if protocol == 'TCP':
            send_event_thread.start()
            send_event_thread.join()
        else:  # If protocol is UDP, then monitor the  socket queue to verify that the event has not been received.

            callback = callbacks.generate_callback(fr"{search_pattern}")
            monitored_sockets[0].start(callback=callback)
            assert monitored_sockets[0].callback_result


            # Wait until socket monitor is fully initialized
            time.sleep(5)

            send_event_thread.start()
            send_event_thread.join()

            time.sleep(5)
        for injector in injectors:
            injector.stop_receive()


    if test_metadata['protocol'] == 'TCP':
        # Check that the connection is not established
        with pytest.raises(ConnectionRefusedError):
            validate_agent_manager_protocol_communication(protocol=test_metadata['protocol'], manager_port=test_metadata['port'])
            raise ValueError('The manager has established a TCP connection when only UDP is allowed.')
    else:
        # Check that no event is received in the socket queue
        with pytest.raises(AssertionError):
            validate_agent_manager_protocol_communication(protocol=test_metadata['protocol'], manager_port=test_metadata['port'])
            raise ValueError('The manager has received an event from a protocol not allowed.')
