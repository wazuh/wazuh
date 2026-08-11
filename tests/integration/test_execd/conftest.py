# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import time
import uuid

import pytest

from wazuh_testing.constants.paths.configurations import AR_CONF
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import AGENTD_CONNECTED_TO_SERVER, AGENTD_HTTPS_STARTUP_ACCEPTED
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
    starts the simulator and waits for the agent to connect to it. It then queues the input
    as an active_response task on the simulator (delivered on the next /control notify cycle)
    and waits for execd to start processing it. After the test, the simulator is shut down.

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
    # connected during daemons_handler restart (which runs before this fixture). Accept
    # either the legacy TCP line or the HTTPS client's own (both run side by side during
    # the migration, wazuh/wazuh#37831). The log file is already truncated by
    # truncate_monitored_files fixture.
    connected_pattern = fr'({AGENTD_CONNECTED_TO_SERVER}|{AGENTD_HTTPS_STARTUP_ACCEPTED})'
    connection_monitor.start(callback=generate_callback(connected_pattern), timeout=150)
    assert connection_monitor.callback_result is not None, 'Agent did not connect to remoted simulator'

    # Give the agent some time to stabilize after connection
    time.sleep(2)

    # `input` carries the legacy queue-message wire format ("#!-execd {json}") -- the "#!-execd"
    # part was only ever a routing marker for the old shared mq transport (stripped upstream of
    # ExecdRun(), which cJSON_Parse()s the message as-is). Under HTTPS, routing is the task's own
    # task_type: strip that marker and deliver the same JSON payload as an active_response task
    # (bridge_dispatch_active_response(), https_client_bridge.c, forwards it to execd verbatim).
    _, _, raw_payload = test_metadata['input'].partition(' ')
    payload = json.loads(raw_payload)
    remoted_simulator.add_task({
        'task_id': str(uuid.uuid4()),
        'task_type': 'active_response',
        'payload': payload,
    })

    # bridge_dispatch_active_response() itself now validates the payload has a top-level
    # "wazuh" key before ever forwarding it to execd -- a case missing it entirely is
    # rejected agent-side and never reaches execd's queue at all (unlike a "wazuh" key with
    # invalid *contents*, which execd's own ExecdRun() still receives and rejects). Only wait
    # for execd's reception line when the payload can actually get there.
    if 'wazuh' in payload:
        # Don't tail only new events here: on fast platforms (Windows) execd can log the
        # reception line before we start monitoring, so we need to scan from the beginning
        # of the truncated file to catch it reliably.
        execd_monitor = FileMonitor(WAZUH_LOG_PATH)
        execd_monitor.start(callback=generate_callback(EXECD_RECEIVED_MESSAGE), timeout=60)
        assert execd_monitor.callback_result is not None, 'Execd did not receive the message'
