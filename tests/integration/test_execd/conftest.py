# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest

from wazuh_testing.constants.paths.configurations import AR_CONF
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import AGENTD_CONNECTED_TO_SERVER
from wazuh_testing.modules.execd.patterns import EXECD_RECEIVED_MESSAGE
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture()
def configure_ar_conf(request: pytest.FixtureRequest) -> None:
    """
    Fixture for configuring the ar.conf file.

    This fixture checks if the `ar_conf` variable is defined in the module and reads its
    value. It then backs up the original state of the `ar.conf` file, writes the new
    configuration, specified in `ar_conf`, and restores the original state after the test.

    Args:
        request (pytest.FixtureRequest): The request object representing the fixture.

    Raises:
        AttributeError: If the `ar_conf` variable is not defined in the module.
    """
    if not hasattr(request.module, 'ar_conf'):
        raise AttributeError('The var `ar_conf` is not defined in module.')

    ar_config = getattr(request.module, 'ar_conf')

    if file.exists_and_is_file(AR_CONF):
        backup = file.read_file_lines(AR_CONF)
    else:
        backup = None

    file.write_file(AR_CONF, ar_config)

    yield

    if backup:
        file.write_file(AR_CONF, backup)
    else:
        file.remove_file(AR_CONF)


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

    monitor.start(callback=generate_callback(AGENTD_CONNECTED_TO_SERVER))
    remoted_simulator.send_custom_message(test_metadata['input'])
    monitor.start(callback=generate_callback(EXECD_RECEIVED_MESSAGE))
