"""
 Copyright (C) 2015-2043, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time
from wazuh_testing.tools.thread_executor import ThreadExecutor

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd.patterns import ANALYSISD_STARTED
from wazuh_testing.utils import callbacks
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.tools.simulators.agent_simulator import connect

@pytest.fixture(scope='module')
def waiting_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(ANALYSISD_STARTED))


@pytest.fixture
def validate_agent_manager_protocol_communication():

    def validate_agent_manager_protocol_communication(monitored_sockets, simulate_agents, protocol, manager_port):

        agent =simulate_agents[0]
        injectors = []

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

        yield
        time.sleep(5)
        for injector in injectors:
            injector.stop_receive()

    return validate_agent_manager_protocol_communication
