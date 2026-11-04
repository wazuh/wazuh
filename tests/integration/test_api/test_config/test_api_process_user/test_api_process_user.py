"""
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This test checks the user the 'wazuh-manager-apid' daemon runs as when the manager starts it.
       The daemon starts as root and switches to 'wazuh-manager'; only the '-r' command-line flag keeps
       root, and wazuh-manager-control never passes it. The unit tests cover the switch itself with
       mocked calls; this one covers the real start path.

components:
    - api

suite: config

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
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html

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
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_api_process_user.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_api_process_user.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'all_daemons': True}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_api_process_user(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                          daemons_handler, wait_for_api_start):
    """
    description: Check the user of the API process started by wazuh-manager-control. The 'PID' of the API
                 process is obtained, and its user must be 'wazuh-manager'.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup:
            - Append the default port to api.yaml (the fixtures need a configuration block)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Search wazuh-manager-apid process and verify that it is present
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
        - Verify that the 'wazuh-manager-apid' daemon runs as 'wazuh-manager'.

    input_description: Different test cases are contained in an external YAML file (cases_api_process_user.yaml)
                       which includes API configuration parameters.

    expected_output:
        - PID of the 'wazuh-manager-apid' process.
        - wazuh-manager
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

