# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import pytest
import time
import uuid

from wazuh_testing.constants.paths.configurations import AR_CONF
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import AGENTD_ACTIVE_RESPONSE_MALFORMED_PAYLOAD, AGENTD_HTTPS_STARTUP_ACCEPTED
from wazuh_testing.modules.execd.patterns import EXECD_RECEIVED_MESSAGE
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture()
def send_execd_message(test_metadata: dict, remoted_simulator: RemotedSimulator) -> None:
    """
    Fixture for sending an execd message and monitoring its execution.

    This fixture validates the input, instantiates a `RemotedSimulator` and a `FileMonitor`,
    starts the simulator and waits for the agent to connect to it. It then sends the input
    message to the simulator and waits for the execd to start processing the message. After
    the test, the simulator is shut down.

    Args:
        test_metadata (dict): Metadata containing the test input.

    Raises:
        AttributeError: If the `input` key is missing in the `test_metadata`.
    """
    if test_metadata.get('input') is None:
        raise AttributeError('No `input` key in `test_metadata`.')

    # Use independent monitors for the connection and the execd events so we can
    # safely mix full log scans with only-new-events tailing without sharing state.
    connection_monitor = FileMonitor(WAZUH_LOG_PATH)

    # Don't use only_new_events for the connection check since the agent may have already
    # connected during daemons_handler restart (which runs before this fixture).
    # The log file is already truncated by truncate_monitored_files fixture.
    connection_monitor.start(callback=generate_callback(AGENTD_HTTPS_STARTUP_ACCEPTED), timeout=150)
    assert connection_monitor.callback_result is not None, 'Agent did not connect to remoted simulator'

    # Give the agent some time to stabilize after connection
    time.sleep(2)

    # send_custom_message() (an unsolicited push over the legacy protocol's persistent
    # connection) has no HTTPS equivalent: there is no such thing as the manager pushing
    # bytes whenever it wants. An active_response command is a /control task instead --
    # delivered as the "payload" of a task_type=="active_response" entry riding the
    # agent's next notify (bridge_dispatch_active_response(), https_client_bridge.c),
    # forwarded to execd's queue unchanged. The task payload IS the AR document itself,
    # with no wrapper -- test_metadata['input'] is already that exact JSON shape, with no
    # "#!-execd " wire-format prefix left to strip (that legacy header has no bearing on
    # this path at all).
    # task_id must be unique per call: agent-info's task registry is durable (persists
    # across an agent restart, by design -- see https_client_bridge.c's dispatch comment
    # on at-least-once redelivery), so a fixed id would make every parametrized case in
    # this file after the first get silently dropped as "already seen".
    payload = json.loads(test_metadata['input'])
    task_id = f'test-execd-ar-{uuid.uuid4()}'
    remoted_simulator.add_task({'task_id': task_id, 'task_type': 'active_response', 'payload': payload})

    # Don't tail only new events here: on fast platforms (Windows) execd can log the
    # reception line before we start monitoring, so we need to scan from the beginning
    # of the truncated file to catch it reliably.
    if 'wazuh' not in payload:
        # bridge_dispatch_active_response() drops this at the agent, before it ever
        # reaches execd's queue -- there's no "received" line to wait for.
        drop_monitor = FileMonitor(WAZUH_LOG_PATH)
        drop_monitor.start(callback=generate_callback(AGENTD_ACTIVE_RESPONSE_MALFORMED_PAYLOAD), timeout=60)
        assert drop_monitor.callback_result is not None, 'Agent did not log the malformed-payload drop'
        return

    execd_monitor = FileMonitor(WAZUH_LOG_PATH)
    execd_monitor.start(callback=generate_callback(EXECD_RECEIVED_MESSAGE), timeout=60)
    assert execd_monitor.callback_result is not None, 'Execd did not receive the message'
