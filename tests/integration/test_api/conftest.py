"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

from time import sleep

import pytest
import requests

from wazuh_testing.constants.paths.logs import (
    WAZUH_API_LOG_FILE_PATH,
    WAZUH_API_JSON_LOG_FILE_PATH,
)
from wazuh_testing.constants.api import WAZUH_API_PORT, CONFIGURATION_TYPES
from wazuh_testing.modules.api.configuration import (
    get_configuration,
    append_configuration,
    delete_configuration_file,
)
from wazuh_testing.modules.api.utils import login
from wazuh_testing.modules.api.patterns import API_STARTED_MSG
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture
def add_configuration(
    test_configuration: list[dict], request: pytest.FixtureRequest
) -> None:
    """Add configuration to the Wazuh API configuration files.

    Args:
        test_configuration (dict): Configuration data to be added to the configuration files.
        request (pytest.FixtureRequest): Gives access to the requesting test context and has an optional `param`
                                         attribute in case the fixture is parametrized indirectly.
    """
    # Configuration file that will be used to apply the test configuration
    test_target_type = request.module.configuration_type
    # Save current configuration
    backup = get_configuration(configuration_type=test_target_type)
    # Set new configuration at the end of the configuration file
    append_configuration(test_configuration["blocks"], test_target_type)

    yield

    # Restore base configuration file or delete security configuration file
    if test_target_type != CONFIGURATION_TYPES[1]:
        append_configuration(backup, test_target_type)
    else:
        delete_configuration_file(test_target_type)


@pytest.fixture
def wait_for_api_start(test_configuration: dict) -> None:
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        test_configuration (dict): Configuration data.

    Raises:
        RuntimeError: When the log was not found.
    """
    # Set the default values
    logs_format = "plain"
    host = ["0.0.0.0", "::"]
    port = WAZUH_API_PORT
    protocol = "https"
    skip_login_probe = False

    # Check if specific values were set or set the defaults
    if test_configuration is not None:
        if test_configuration.get("blocks") is not None:
            logs_configuration = test_configuration["blocks"].get("logs")
            # Set the default value if `format`` is not set
            logs_format = (
                "plain"
                if logs_configuration is None
                else logs_configuration.get("format", "plain")
            )
            host = test_configuration["blocks"].get("host", ["0.0.0.0", "::"])
            port = test_configuration["blocks"].get("port", WAZUH_API_PORT)
            https_configuration = test_configuration["blocks"].get("https")
            if (
                https_configuration is not None
                and https_configuration.get("enabled") is False
            ):
                protocol = "http"
            intervals_configuration = test_configuration["blocks"].get("intervals")
            if intervals_configuration is not None:
                request_timeout = intervals_configuration.get("request_timeout")
                skip_login_probe = request_timeout in (0, "0")

    file_to_monitor = (
        WAZUH_API_JSON_LOG_FILE_PATH
        if logs_format == "json"
        else WAZUH_API_LOG_FILE_PATH
    )
    monitor_start_message = file_monitor.FileMonitor(file_to_monitor)
    monitor_start_message.start(
        callback=generate_callback(
            API_STARTED_MSG, {"host": str(host), "port": str(port)}
        )
    )

    if monitor_start_message.callback_result is None:
        raise RuntimeError("The API was not started as expected.")

    if skip_login_probe:
        return

    configured_hosts = host if isinstance(host, list) else [host]
    local_hosts = {"0.0.0.0", "::", "127.0.0.1", "::1", "localhost"}
    if not any(configured_host in local_hosts for configured_host in configured_hosts):
        return

    last_exception = None
    authentication_headers = None
    for _ in range(15):
        try:
            authentication_headers, _ = login(
                host="localhost",
                port=str(port),
                protocol=protocol,
                timeout=2,
                login_attempts=1,
                backoff_factor=0,
            )
            break
        except Exception as exception:
            last_exception = exception
            sleep(1)

    if authentication_headers is None:
        if last_exception is not None:
            raise last_exception
        raise RuntimeError("The API was not ready to accept logins.")

    # A working login does not mean the cluster DAPI is up: every /cluster/* controller resolves
    # the system nodes over clusterd's internal socket before anything else (RBAC included), and
    # right after a restart that path lags the API itself, answering connexion's generic 500 to
    # the first request. Wait for it here so no test eats that warm-up 500, and surface the last
    # body if it never comes up. The token can expire mid-wait (the jwt_token_exp_timeout cases
    # configure TTLs as low as 5s), so a 401 renews the login instead of spinning on a dead token.
    last_error = None
    for _ in range(30):
        try:
            response = requests.get(
                f"{protocol}://localhost:{port}/cluster/local/info",
                headers=authentication_headers,
                verify=False,
                timeout=10,
            )
            if response.status_code == 200:
                return
            if response.status_code == 401:
                try:
                    authentication_headers, _ = login(
                        host="localhost",
                        port=str(port),
                        protocol=protocol,
                        timeout=2,
                        login_attempts=1,
                        backoff_factor=0,
                    )
                except Exception:
                    pass
            last_error = f"HTTP {response.status_code}: {response.text}"
        except Exception as exception:
            last_error = str(exception)
        sleep(2)

    raise RuntimeError(f"The cluster DAPI never became ready after the API start: {last_error}")
