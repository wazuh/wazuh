"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests verify the API behavior when receiving JSON payloads with different nesting depths.

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
    - json
    - recursion
"""

import pytest
import requests
import sys
from requests.adapters import HTTPAdapter, Retry

from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
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


def generate_nested_json(depth: int) -> dict:
    data = {}
    cursor = data
    for _ in range(depth - 1):
        cursor["k"] = {}
        cursor = cursor["k"]
    cursor["k"] = "END"
    return data


@pytest.mark.tier(level=0)
@pytest.mark.parametrize(
    "depth, expected_status",
    [
        (100, 200),
        (500, 200),  # Below Python's default recursion limit (~1000)
        (1100, 400),  # Exceeds recursion limit - triggers RecursionError
    ],
)
def test_json_nesting_depth(
    depth,
    expected_status,
    truncate_monitored_files,
    daemons_handler,
    wait_for_api_start,
):
    """
    description: Validate API behavior with different JSON nesting depths.

    wazuh_min_version: 4.0.0

    test_phases:
        - setup:
            - Truncate logs
            - Restart API daemon
            - Wait for API startup
        - test:
            - Send JSON with defined nesting depth
            - Validate response status code
        - teardown:
            - Truncate logs

    tier: 0

    parameters:
        - depth:
            type: int
            brief: JSON nesting depth.
        - expected_status:
            type: int
            brief: Expected HTTP status code.

    assertions:
        - Verify HTTP status code matches expected result.

    tags:
        - recursion
        - json
    """
    url = get_base_url() + "/security/user/authenticate/run_as"

    session = requests.Session()
    retry = Retry(total=None, connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount(f"{WAZUH_API_PROTOCOL}://", adapter)

    current_recursion_limit = sys.getrecursionlimit()
    recursion_margin = 100
    if depth >= current_recursion_limit:
        sys.setrecursionlimit(depth + recursion_margin)

    payload = generate_nested_json(depth)

    response = session.post(
        url=url,
        auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
        json=payload,
        verify=False,
        timeout=30,
    )

    sys.setrecursionlimit(current_recursion_limit)

    assert response.status_code == expected_status, (
        f"Unexpected status for depth {depth}\n"
        f"Expected: {expected_status}\n"
        f"Got: {response.status_code}\n"
        f"Response: {response.text}"
    )
