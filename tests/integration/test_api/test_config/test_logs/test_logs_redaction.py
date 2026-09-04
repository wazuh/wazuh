"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The API access log writes the body of every authenticated request it manages to parse into api.log and
       api.json. Sensitive fields must be masked before that happens, at any depth of the body, and whether or
       not the API went on to accept the request: the log entry is written after the response, and the OpenAPI
       validator runs below the security handler, so a body it rejected with a 400 has still been recorded
       against an authenticated caller.

components:
    - api

targets:
    - manager

daemons:
    - wazuh-manager-apid
    - wazuh-manager-modulesd
    - wazuh-manager-analysisd
    - wazuh-manager-db
    - wazuh-manager-remoted

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - CentOS 8
    - Ubuntu Focal
    - Debian Buster
    - Red Hat 8

references:
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#logs

tags:
    - api
    - logs
    - logging
"""
import pytest
import requests
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES, USERS_ROUTE
from wazuh_testing.constants.paths.api import WAZUH_API_CERTIFICATE
from wazuh_testing.constants.paths.logs import WAZUH_API_JSON_LOG_FILE_PATH, WAZUH_API_LOG_FILE_PATH
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]
# Value the API writes in place of a sensitive one
REDACTED_VALUE = '****'

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_logs_format.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_logs_redaction.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'all_daemons': True}


# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_logs_redaction(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                        daemons_handler):
    """
    description: Check that no secret carried by a request body reaches the API log files, whatever the depth
                 of the field that carries it and whatever field name it was sent under.

    wazuh_min_version: 4.4.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Send a request whose body carries a secret, which the API rejects
            - Read both log files and check that the secret was not written and the mask was
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files
            - Stop daemons defined in `daemons_handler_configuration` in this module

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration data from the test case.
        - test_metadata:
            type: dict
            brief: Metadata from the test case.
        - add_configuration:
            type: fixture
            brief: Add configuration to the Wazuh API configuration files.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.

    assertions:
        - Verify that the API rejected the request, so the body was logged without ever reaching a handler.
        - Verify that no secret in the body appears in api.log or api.json.
        - Verify that the mask appears in both files, so the body was logged and merely redacted rather
          than the whole entry going missing.

    input_description: The test gets the configuration from the YAML file, which contains the API
                       configuration, and the request body from the test case metadata.

    expected_output:
        - The secrets sent in the request body are absent from api.log and api.json
        - "****" is present in api.log and api.json
    """
    authentication_headers, _ = login()
    expected_code = test_metadata['expected_code']

    response = requests.post(f"{get_base_url()}{USERS_ROUTE}", json=test_metadata['body'],
                             headers=authentication_headers, verify=WAZUH_API_CERTIFICATE, timeout=10)

    assert response.status_code == expected_code, f"The status code was {response.status_code}." \
                                                  f"\nExpected: {expected_code}."

    for log_file in (WAZUH_API_LOG_FILE_PATH, WAZUH_API_JSON_LOG_FILE_PATH):
        content = Path(log_file).read_text(errors='replace')

        for secret in test_metadata['secrets']:
            assert secret not in content, f"The secret '{secret}' was written to {log_file} in cleartext."

        assert REDACTED_VALUE in content, f"The mask '{REDACTED_VALUE}' did not appear in {log_file}, so the " \
                                          'request body was not logged at all and this test would pass for ' \
                                          'the wrong reason.'
