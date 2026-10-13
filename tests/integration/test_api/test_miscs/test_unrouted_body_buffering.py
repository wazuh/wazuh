"""
copyright: Copyright (C) 2015-2026, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests verify the API answers an unauthenticated request to a path that matches no
    route without ever reading the body it declares, so a caller cannot make wazuh-apid buffer an
    arbitrary amount of memory before routing or authentication run.

components:
    - api

suite: miscs

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-execd
    - wazuh-db
    - wazuh-remoted

os_platform:
    - linux

tags:
    - api
    - security
"""

import socket

import pytest

from wazuh_testing.constants.api import WAZUH_API_HOST, WAZUH_API_PORT
from wazuh_testing.constants.daemons import API_DAEMON
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.utils.services import wait_expected_daemon_status


pytestmark = pytest.mark.server

# Every 5.0 manager request goes through clusterd (DAPI), which API_DAEMONS_REQUIREMENTS does not restart:
# after a module that stopped the whole manager, the API would answer 500 until clusterd came back.
daemons_handler_configuration = {"all_daemons": True}


@pytest.fixture
def test_configuration():
    return {}


# Declared but never sent: the access logger used to block reading this body before authentication
DECLARED_BODY_SIZE = 200 * 1024 * 1024
UNROUTED_PATH = "/this-path-does-not-exist"
ROUTED_PATH = "/security/user/authenticate"


@pytest.mark.tier(level=0)
@pytest.mark.parametrize("path, expected_status", [(UNROUTED_PATH, "404"), (ROUTED_PATH, "401")])
def test_unrouted_path_ignores_undelivered_declared_body(
    path,
    expected_status,
    truncate_monitored_files,
    daemons_handler,
    wait_for_api_start,
):
    """
    description: Send an unauthenticated request declaring a large Content-Length, then close the
        connection without ever sending that body. WazuhAccessLoggerMiddleware skips buffering a body
        whose declared length exceeds the logging cap, whether or not the path is routed.

    wazuh_min_version: 4.14.10

    test_phases:
        - setup:
            - Truncate logs
            - Restart API daemon
            - Wait for API startup
        - test:
            - Open a raw TLS connection to the API
            - Send a POST to an unrouted or a routed path declaring a large Content-Length
            - Close the connection without sending the declared body
            - Read the response
        - teardown:
            - Truncate logs

    tier: 0

    assertions:
        - Verify the API answers 404 (unrouted) or 401 (routed) without waiting for the undelivered body.
        - Verify wazuh-apid is still running afterwards.

    tags:
        - security
        - api
    """
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {WAZUH_API_HOST}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {DECLARED_BODY_SIZE}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    with SocketController(
        address=(WAZUH_API_HOST, int(WAZUH_API_PORT)), family="AF_INET", connection_protocol="ssl_tls", timeout=10
    ) as controller:
        controller.send(request)
        # The body is never sent; a server that reads it before responding hangs until the timeout
        try:
            response = controller.receive().decode(errors="replace")
        except socket.timeout:
            pytest.fail("No response within 10s: the API is waiting for the declared body that was never sent")

    status_line = response.splitlines()[0] if response else ""
    assert expected_status in status_line, (
        f"Expected a prompt {expected_status} without the declared body ever being sent, got: {status_line!r}\n"
        f"Full response: {response!r}"
    )

    wait_expected_daemon_status(target_daemon=API_DAEMON, running_condition=True, timeout=30)
