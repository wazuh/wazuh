"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import json
import os
import subprocess

import pytest

from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.utils import services
from wazuh_testing.utils.services import check_all_daemon_status
from time import sleep


@pytest.fixture
def restart_wazuh_expect_error() -> None:
    try:
        sleep(1)
        if any(v for _, v in check_all_daemon_status().items()):
            services.control_service("restart")
        else:
            services.control_service("start")
    except Exception:
        pass

    yield

    services.control_service("stop")


def _case_value_matches_effective(template_value, effective_value):
    """Compare a raw template string against the effective (native-typed) value the loader produced."""
    if isinstance(effective_value, list):
        expected = sorted(item.strip().lower() for item in str(template_value).split(','))
        return expected == sorted(str(item).lower() for item in effective_value)
    if isinstance(effective_value, bool):
        return str(template_value).lower() in (('yes', 'true') if effective_value else ('no', 'false'))
    return str(effective_value) == str(template_value)


@pytest.fixture
def get_real_configuration(test_configuration):
    """Effective `remote` section this test case must be served by the configuration API.

    Since 5.0 `GET /cluster/{node_id}/configuration` returns the effective document (schema
    defaults applied, native types), so the expectation is read from the same source of truth
    the daemons load: `bin/wazuh-manager-conf get remote`. Before handing it to
    compare_config_api_response, the case's own template parameters are asserted against it,
    so the test still pins this case's values and not just API == CLI.

    Returns None when the CLI rejects the configuration: the invalid-configuration tests
    request this fixture too, and there is no effective document to compare there.
    """
    cli = subprocess.run([os.path.join(WAZUH_PATH, 'bin', 'wazuh-manager-conf'), 'get', 'remote'],
                         capture_output=True, text=True)
    if cli.returncode != 0:
        return None

    effective = json.loads(cli.stdout)

    for element in test_configuration.get("sections", {})[0]["elements"]:
        for key, content in element.items():
            if key == "legacy":
                for child in content.get("elements", []):
                    for child_key, child_content in child.items():
                        template_value = child_content["value"]
                        assert child_key in effective["legacy"], \
                            f"'{child_key}' missing from the effective legacy block: {effective['legacy']}"
                        assert _case_value_matches_effective(template_value, effective["legacy"][child_key]), \
                            f"legacy.{child_key}: template '{template_value}' not reflected in " \
                            f"effective '{effective['legacy'][child_key]}'"
            else:
                template_value = content["value"]
                assert key in effective, f"'{key}' missing from the effective remote section: {effective}"
                assert _case_value_matches_effective(template_value, effective[key]), \
                    f"{key}: template '{template_value}' not reflected in effective '{effective[key]}'"

    return effective


@pytest.fixture
def protocols_list_to_str_upper_case(request, test_metadata):
    """convert valid_protocol list to comma separated uppercase string

    parameters: test_metadata
    Returns:
    protocol_string_upper: string protocols in uppercase
    """
    protocol_array = []
    protocol_string_upper = []
    for I in test_metadata["valid_protocol"]:
        protocol_array.append(I)
        protocol_array.sort()

    if len(test_metadata["valid_protocol"]) > 0:
        protocol_string = protocol_array[0]
        protocol_string_upper = protocol_string.upper()

    if len(protocol_array) > 1:
        protocol_string = protocol_array[0] + "," + protocol_array[1]
        protocol_string_upper = protocol_string.upper()

    return protocol_string_upper
