"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import socket
import time

import pytest

from wazuh_testing.constants.paths.logs import WAZUH_API_LOG_FILE_PATH, WAZUH_API_JSON_LOG_FILE_PATH
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.constants.api import WAZUH_API_PORT
from wazuh_testing.modules.api.patterns import API_STARTED_MSG
from wazuh_testing.utils import configuration as wazuh_config


def wait_for_tcp_port(port, host='localhost', timeout=30, interval=0.5):
    """Wait until a TCP port accepts connections.

    A daemon can log that it started before it binds its port, so the log line alone is not a
    reliable readiness signal right after a restart.

    Args:
        port (int): Port to connect to.
        host (str): Host to connect to. Default `localhost`.
        timeout (int): Max seconds to wait for the port to accept connections.
        interval (float): Seconds between attempts.

    Returns:
        bool: True if the port accepted a connection before the timeout, False otherwise.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            with socket.create_connection((host, int(port)), timeout=1):
                return True
        except OSError:
            time.sleep(interval)

    return False


@pytest.fixture(scope='module')
def configure_for_api_test():
    """Write an auth-enabled configuration so authd is running when daemons restart for API tests."""
    backup = wazuh_config.get_wazuh_conf()
    config_with_auth = wazuh_config.set_section_wazuh_conf([{
        'section': 'auth',
        'elements': [
            {'disabled': {'value': 'no'}},
            {'remote_enrollment': {'value': 'yes'}},
        ]
    }])
    wazuh_config.write_wazuh_conf(config_with_auth)
    yield
    wazuh_config.write_wazuh_conf(backup)


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
    if not wait_for_tcp_port(port, timeout=30):
        raise RuntimeError('wazuh-apid did not start accepting connections in time.')
