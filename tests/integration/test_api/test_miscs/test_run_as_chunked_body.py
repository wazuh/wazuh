"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests verify that the run_as login endpoint accepts an authorization context whose length is not
       declared up front, and still refuses a request that carries no context at all.

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
    - run_as
"""

import json

import pytest
import requests
from requests.adapters import HTTPAdapter, Retry

from wazuh_testing.constants.api import (
    WAZUH_API_PROTOCOL,
    WAZUH_API_USER,
    WAZUH_API_PASSWORD,
)
from wazuh_testing.modules.api.utils import get_base_url


pytestmark = pytest.mark.server

daemons_handler_configuration = {"all_daemons": True}


@pytest.fixture
def test_configuration():
    return {}


def stream_body(payload: dict):
    """Yield an encoded body so `requests` sends it with `Transfer-Encoding: chunked`.

    A generator has no length, so `requests` cannot set a `Content-Length` header and streams the
    body in chunks instead. That is the case this test exists for: the request body validator
    decides whether a body is present from `Content-Length` alone, so a chunked body must not be
    mistaken for an absent one.
    """
    yield json.dumps(payload).encode()


@pytest.mark.tier(level=0)
@pytest.mark.parametrize(
    "auth_context",
    [
        {"user_name": "wazuh-admin"},
        {},
    ],
    ids=["matching_context", "empty_context"],
)
def test_run_as_chunked_auth_context(
    auth_context,
    truncate_monitored_files,
    daemons_handler,
    wait_for_api_start,
):
    """
    description: Validate that an authorization context sent with `Transfer-Encoding: chunked` is
                 read and resolved, instead of being rejected as a missing request body.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup:
            - Truncate logs
            - Restart API daemon
            - Wait for API startup
        - test:
            - Send the authorization context without declaring its length
            - Validate the login succeeds
        - teardown:
            - Truncate logs

    tier: 0

    parameters:
        - auth_context:
            type: dict
            brief: Authorization context to stream as the request body.

    assertions:
        - Verify the login returns a token instead of a 400.

    tags:
        - run_as
        - security
    """
    url = get_base_url() + "/security/user/authenticate/run_as"

    session = requests.Session()
    retry = Retry(total=None, connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount(f"{WAZUH_API_PROTOCOL}://", adapter)

    response = session.post(
        url=url,
        auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
        data=stream_body(auth_context),
        headers={"Content-Type": "application/json"},
        verify=False,
        timeout=30,
    )

    assert response.status_code == 200, (
        "A chunked authorization context must be read, not treated as a missing body\n"
        f"Expected: 200\n"
        f"Got: {response.status_code}\n"
        f"Response: {response.text}"
    )
    assert "token" in response.json()["data"], f"No token in the response: {response.text}"


@pytest.mark.tier(level=0)
def test_run_as_no_auth_context(
    truncate_monitored_files,
    daemons_handler,
    wait_for_api_start,
):
    """
    description: Validate that a run_as login carrying no request body at all is refused. This is
                 the control for `test_run_as_chunked_auth_context`: an undeclared length must be
                 read as a body, while a genuinely absent body must still be rejected.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup:
            - Truncate logs
            - Restart API daemon
            - Wait for API startup
        - test:
            - Send the request with no body
            - Validate the request is refused
        - teardown:
            - Truncate logs

    tier: 0

    assertions:
        - Verify the login is refused with a 400.

    tags:
        - run_as
        - security
    """
    url = get_base_url() + "/security/user/authenticate/run_as"

    session = requests.Session()
    retry = Retry(total=None, connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount(f"{WAZUH_API_PROTOCOL}://", adapter)

    response = session.post(
        url=url,
        auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
        headers={"Content-Type": "application/json"},
        verify=False,
        timeout=30,
    )

    assert response.status_code == 400, (
        "A run_as login with no authorization context must be refused\n"
        f"Expected: 400\n"
        f"Got: {response.status_code}\n"
        f"Response: {response.text}"
    )
