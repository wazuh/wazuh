"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests verify the API answers an unauthenticated request to a path that matches no
    route without ever reading the body it declares, so a caller cannot make wazuh-apid buffer an
    arbitrary amount of memory before routing or authentication run.

components:
    - api

suite: middlewares

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
import ssl

import pytest

from wazuh_testing.constants.api import WAZUH_API_HOST, WAZUH_API_PORT
from wazuh_testing.constants.daemons import API_DAEMON, API_DAEMONS_REQUIREMENTS
from wazuh_testing.utils.services import wait_expected_daemon_status


pytestmark = pytest.mark.server

daemons_handler_configuration = {"daemons": API_DAEMONS_REQUIREMENTS}


@pytest.fixture
def test_configuration():
    return {}


# Declared but never sent: the access logger used to block reading this body before authentication
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
        Content-Length, then close the connection without ever sending that body. The path does not
        route anywhere, so answering it does not require the body at all; the fix must not read it
        on the strength of the declared header alone.

    wazuh_min_version: 4.10.6

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

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((WAZUH_API_HOST, int(WAZUH_API_PORT)), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=WAZUH_API_HOST) as tls_sock:
            tls_sock.sendall(request)
            # The body is never sent; a server that reads it before responding hangs until the timeout
            tls_sock.settimeout(10)
            response = tls_sock.recv(4096).decode(errors="replace")

    status_line = response.splitlines()[0] if response else ""
    assert "404" in status_line, (
        f"Expected a prompt 404 without the declared body ever being sent, got: {status_line!r}\n"
        f"Full response: {response!r}"
    )

    wait_expected_daemon_status(target_daemon=API_DAEMON, running_condition=True, timeout=30)
