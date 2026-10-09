"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest

from wazuh_testing.constants.paths.logs import WAZUH_API_LOG_FILE_PATH, WAZUH_API_JSON_LOG_FILE_PATH
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.constants.api import WAZUH_API_PORT
from wazuh_testing.modules.api.patterns import API_STARTED_MSG
from wazuh_testing.modules.api.utils import wait_for_api_port


@pytest.fixture(scope='module')
def wait_for_api_startup_module():
    """Monitor the API log file and port to detect whether it has been started or not.

    Raises:
        RuntimeError: When the log was not found or the port never accepted connections.
    """
    # Set the default values
    logs_format = 'plain'
    host = ['0.0.0.0', '::']
    port = WAZUH_API_PORT

    # Check if specific values were set or set the defaults
    file_to_monitor = WAZUH_API_JSON_LOG_FILE_PATH if logs_format == 'json' else WAZUH_API_LOG_FILE_PATH
    monitor_start_message = file_monitor.FileMonitor(file_to_monitor)
    monitor_start_message.start(
        callback=generate_callback(API_STARTED_MSG, {
            'host': str(host),
            'port': str(port)
        })
    )

    if monitor_start_message.callback_result is None:
        raise RuntimeError('The API was not started as expected.')

    # The log above is written from the ASGI lifespan, before uvicorn actually binds
    # the port, so it is not a reliable readiness signal on its own.
    if not wait_for_api_port(timeout=30):
        raise RuntimeError('wazuh-apid did not start accepting connections in time.')
