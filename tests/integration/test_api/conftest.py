"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time
import requests
import urllib3

from wazuh_testing.constants.api import WAZUH_API_PORT, CONFIGURATION_TYPES
from wazuh_testing.modules.api.configuration import (
    get_configuration,
    append_configuration,
    delete_configuration_file,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    test_target_type = request.module.configuration_type
    backup = get_configuration(configuration_type=test_target_type)
    append_configuration(test_configuration["blocks"], test_target_type)

    yield

    if test_target_type != CONFIGURATION_TYPES[1]:
        append_configuration(backup, test_target_type)
    else:
        delete_configuration_file(test_target_type)


@pytest.fixture
def wait_for_api_start(test_configuration: dict) -> None:
    """Monitor the API to detect whether it has been started or not.

    Args:
        test_configuration (dict): Configuration data.
    """
    port = WAZUH_API_PORT
    protocol = "https"

    if test_configuration is not None and test_configuration.get("blocks") is not None:
        port = test_configuration["blocks"].get("port", WAZUH_API_PORT)
        if test_configuration["blocks"].get("https", {}).get("enabled", "yes") == "no":
            protocol = "http"

    api_url = f"{protocol}://127.0.0.1:{port}"
    MAX_RETRIES = 30
    RETRY_INTERVAL = 1

    for _ in range(MAX_RETRIES):
        try:
            requests.get(api_url, verify=False, timeout=2)
            break
        except requests.exceptions.RequestException:
            time.sleep(RETRY_INTERVAL)

    yield
