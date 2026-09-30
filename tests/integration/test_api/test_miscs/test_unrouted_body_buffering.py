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
from wazuh_testing.constants.daemons import API_DAEMON, API_DAEMONS_REQUIREMENTS
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.utils.services import wait_expected_daemon_status


pytestmark = pytest.mark.server

daemons_handler_configuration = {"daemons": API_DAEMONS_REQUIREMENTS}


@pytest.fixture
def test_configuration():
    return {}


# Declared but never delivered. Before the fix, WazuhAccessLoggerMiddleware read a request's body in
# full before routing or authentication ever ran, so declaring a length this large and never sending
# it was enough to make the daemon block trying to read bytes that don't exist -- and, sent for
# real, to make it allocate memory proportional to whatever length an unauthenticated caller chose.
DECLARED_BODY_SIZE = 200 * 1024 * 1024
UNROUTED_PATH = "/this-path-does-not-exist"


@pytest.mark.tier(level=0)
def test_unrouted_path_ignores_undelivered_declared_body(
    truncate_monitored_files,
    daemons_handler,
    wait_for_api_start,
):
    """
    description: Send an unauthenticated request to a path that matches no route, declaring a large
        Content-Length, then close the connection without ever sending that body. The fix in
        WazuhAccessLoggerMiddleware skips buffering the body once its declared length exceeds the
        logging cap, regardless of routing; this test just picks a path that also happens to be
        unrouted.

    wazuh_min_version: 4.14.10

    test_phases:
        - setup:
            - Truncate logs
            - Restart API daemon
            - Wait for API startup
        - test:
            - Open a raw TLS connection to the API
            - Send a POST to an unrouted path declaring a large Content-Length
            - Close the connection without sending the declared body
            - Read the response
        - teardown:
            - Truncate logs

    tier: 0

    assertions:
        - Verify the API answers 404 without waiting for the undelivered body.
        - Verify wazuh-apid is still running afterwards.

    tags:
        - security
        - api
    """
    request = (
        f"POST {UNROUTED_PATH} HTTP/1.1\r\n"
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
        # Never send the declared body. A server that reads it before responding hangs here
        # until the socket timeout fires, which is exactly the defect under test.
        try:
            response = controller.receive().decode(errors="replace")
        except socket.timeout:
            pytest.fail("No response within 10s: the API is waiting for the declared body that was never sent")

    status_line = response.splitlines()[0] if response else ""
    assert "404" in status_line, (
        f"Expected a prompt 404 without the declared body ever being sent, got: {status_line!r}\n"
        f"Full response: {response!r}"
    )

    wait_expected_daemon_status(target_daemon=API_DAEMON, running_condition=True, timeout=30)
