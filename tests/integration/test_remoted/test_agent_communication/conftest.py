"""
 Copyright (C) 2015-2043, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.utils import callbacks

# SSH public-key auth event — triggers rule 5715 "Authentication success" if it reaches the engine.
_SSH_AUTH_EVENT = (
    '1:/root/test.log:Feb 23 17:18:20 35-u20-manager4 sshd[40657]: Accepted publickey for root'
    ' from 192.168.0.5 port 48044 ssh2: RSA SHA256:IZT11YXRZoZfuGlj/K/t3tT8OdolV58hcCOJFZLIW2Y'
)

_ALERT_PATTERN = r'.*Accepted publickey.*'
_NEGATIVE_TIMEOUT = 10  # seconds to wait confirming no alert appears


@pytest.fixture
def validate_agent_manager_protocol_communication():
    """Send an SSH event via the specified protocol and verify it does NOT generate an alert.

    Used by invalid-protocol tests: if the manager is configured for the opposite protocol,
    the event never reaches the engine and no alert is generated.
    """

    def _validate(simulate_agents, protocol, manager_port):
        agent = simulate_agents[0]
        injectors = []

        def _send(event, protocol, manager_port, agent):
            try:
                sender, injector = connect(agent, manager_port=manager_port, protocol=protocol,
                                           wait_status='')
                sender.send_event(event)
                injectors.append(injector)
            except OSError:
                pass  # invalid-protocol connections are expected to fail at the transport layer

        Path(ALERTS_JSON_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(ALERTS_JSON_PATH).touch(exist_ok=True)

        alert_monitor = FileMonitor(ALERTS_JSON_PATH)

        event = agent.create_event(_SSH_AUTH_EVENT)
        thread = ThreadExecutor(_send, {'event': event, 'protocol': protocol,
                                        'manager_port': manager_port, 'agent': agent})
        thread.start()

        alert_monitor.start(timeout=_NEGATIVE_TIMEOUT,
                            callback=callbacks.generate_callback(_ALERT_PATTERN))

        thread.join()

        assert not alert_monitor.callback_result, (
            f"An alert was generated for an event sent via {protocol} to port {manager_port} "
            f"even though the manager is configured for the opposite protocol — "
            f"the event should not have reached the engine."
        )

        for injector in injectors:
            injector.stop_receive()

    return _validate
