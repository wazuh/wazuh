"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'drop_privileges' setting of the API is working properly.
       This setting allows the user who starts the 'wazuh-apid' daemon to be different from
       the 'root' user. The Wazuh API is an open source 'RESTful' API that allows for interaction
       with the Wazuh manager from a web browser, command line tool like 'cURL' or any script
       or program that can make web requests.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#drop-privileges

tags:
    - api
"""
import os
import pwd
import pytest
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.constants.paths.api import WAZUH_API_SCRIPT
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.services import search_process_by_command


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_drop_privileges.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_drop_privileges.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_drop_privileges(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                         daemons_handler, wait_for_api_start):
    """
    description: Check if 'drop_privileges' affects the user of the API process. In this test, the 'PID' of the API
                 process is obtained. After that, it gets the user ('root' or 'wazuh') and checks if it matches the
                 'drop_privileges' setting.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Search wazuh-apid process and verify that it is present
            - Get current user of the process
            - Check that the user is the expected
        - teardown:
            - Remove configuration and restore backup configuration
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
        - Verify that when 'drop_privileges' is enabled the user who has started the 'wazuh-apid' daemon is 'wazuh'.
        - Verify that when 'drop_privileges' is disabled the user who has started the 'wazuh-apid' daemon is 'root'.

    input_description: Different test cases are contained in an external YAML file (cases_drop_privileges.yaml)
                       which includes API configuration parameters.

    expected_output:
        - PID of the 'wazuh-apid' process.
        - wazuh (if drop_privileges is enabled)
        - root (if drop_privileges is disabled)
    """
    expected_user = test_metadata['expected_user']

    # Get wazuh-apid process info
    api_process = search_process_by_command(WAZUH_API_SCRIPT)
    assert api_process is not None, f"The process {WAZUH_API_SCRIPT} could not be found"

    # Get current user of the process
    process_stat_file = os.stat("/proc/%d" % api_process.pid)
    uid = process_stat_file.st_uid
    username = pwd.getpwuid(uid)[0]

    assert username == expected_user, f'Expected user was {expected_user}, but the current one is {username}'
