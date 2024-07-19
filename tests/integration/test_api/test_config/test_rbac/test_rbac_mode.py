"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'rbac_mode' (Role-Based Access Control) setting of the API
       is working properly. This setting allows you to specify the operating mode between
       'whitelist mode' and 'blacklist mode'. The Wazuh API is an open source 'RESTful' API
       that allows for interaction with the Wazuh manager from a web browser, command line tool
       like 'cURL' or any script or program that can make web requests.

components:
    - api

suite: config

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

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#rbac-mode
    - https://en.wikipedia.org/wiki/Role-based_access_control

tags:
    - api
"""
import pytest
import requests
from pathlib import Path

from . import DB_SCHEMAS_FOLDER_PATH, CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES, MANAGER_INFORMATION_ROUTE
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import login, get_base_url
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[1]
test_user = 'test_user'

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_rbac_mode.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_rbac_mode.yaml')
add_user_sql_script = Path(DB_SCHEMAS_FOLDER_PATH, 'schema_add_user.sql')
delete_user_sql_script = Path(DB_SCHEMAS_FOLDER_PATH, 'schema_delete_user.sql')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_rbac_mode(test_configuration, test_metadata, add_configuration, add_user_in_rbac, truncate_monitored_files,
                   daemons_handler, wait_for_api_start):
    """
    description: Check if the 'RBAC' mode selected in 'api.yaml' is applied. This test creates a user
                 without any assigned permission. For this reason, when 'RBAC' is in 'white mode',
                 there is no endpoint that the user can execute, so the 'HTTP status code'
                 must be 403 ('forbidden'). On the other hand, when it is in 'black mode',
                 there is no endpoint that has it denied, so the status code must be 200 ('ok').

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Add user in the RBAC database
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Make a request to check the response status
            - Verify the response relying on how RBAC is configured
        - teardown:
            - Remove configuration and restore backup configuration
            - Remove user in the RBAC database
            - Truncate the log files
            - Stop daemons defined in `daemons_handler_configuration` in this module

    tier: 0

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
        - add_user_in_rbac:
            type: fixture
            brief: Add a new user in the RBAC database.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - wait_for_api_start:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.

    assertions:
        - Check that when the value of the 'rbac_mode' setting is set to 'white',
          the API forbids requests.
        - Verify that when the value of the 'rbac_mode' setting is set to 'black',
          the API requests are performed correctly.

    input_description: Different test cases are contained in an external YAML file which includes API configuration
                       parameters (rbac operation modes). Two 'SQL' scripts are also used to add (schema_add_user.sql)
                       and remove (schema_delete_user.sql) the testing user.

    expected_output:
        - 200 ('OK' HTTP status code if 'rbac_white == True')
        - 403 ('Forbidden' HTTP status code if 'rbac_white == False')

    tags:
        - rbac
    """
    expected_code = test_metadata['expected_code']
    authentication_headers, _ = login(user=test_user)
    url = get_base_url() + MANAGER_INFORMATION_ROUTE

    # Make a request to check the response status
    response = requests.get(url, headers=authentication_headers, verify=False)

    # Verify the response relying on how RBAC is configured
    assert response.status_code == expected_code, f"Expected status code was {expected_code}, " \
                                                  f"but {response.status_code} was returned. " \
                                                  f"\nFull response: {response.text}"
