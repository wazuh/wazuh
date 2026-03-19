# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest
import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import AGENTD_CONNECTED_TO_SERVER
from wazuh_testing.modules.execd.patterns import EXECD_RECEIVED_MESSAGE
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
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

    monitor = FileMonitor(WAZUH_LOG_PATH)

    monitor.start(only_new_events=True, callback=generate_callback(AGENTD_CONNECTED_TO_SERVER), timeout=150)
    assert monitor.callback_result is not None, 'Agent did not connect to remoted simulator'

    # Give the agent some time to stabilize after connection
    time.sleep(2)

    remoted_simulator.send_custom_message(test_metadata['input'])
    monitor.start(only_new_events=True, callback=generate_callback(EXECD_RECEIVED_MESSAGE), timeout=60)
    assert monitor.callback_result is not None, 'Execd did not receive the message'
