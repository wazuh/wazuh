"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check that the 'drop_privileges' setting of the API is ignored.
       The 'wazuh-apid' daemon always runs as the 'wazuh' user unless it is started with '-r', and
       a warning is logged when the setting is present. The Wazuh API is an open source 'RESTful'
       API that allows for interaction with the Wazuh manager from a web browser, command line tool
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
from wazuh_testing.constants.paths.logs import WAZUH_API_LOG_FILE_PATH
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.services import search_process_by_command


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]
DROP_PRIVILEGES_IGNORED_MSG = r".*WARNING: 'drop_privileges' option is ignored.*"

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
    description: Check that 'drop_privileges' does not affect the user of the API process. In this test, the 'PID'
                 of the API process is obtained. After that, it checks that its user is 'wazuh' whatever the
                 'drop_privileges' setting is, and that a warning about the ignored setting is logged.

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
            - Check that the ignored setting warning is in the API log
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
        - Verify that the user of the 'wazuh-apid' daemon is 'wazuh' whether 'drop_privileges' is enabled or not.
        - Verify that the warning about the ignored 'drop_privileges' setting is logged.

    input_description: Different test cases are contained in an external YAML file (cases_drop_privileges.yaml)
                       which includes API configuration parameters.

    expected_output:
        - PID of the 'wazuh-apid' process.
        - wazuh
        - r".*WARNING: 'drop_privileges' option is ignored.*"
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

    monitor = file_monitor.FileMonitor(WAZUH_API_LOG_FILE_PATH)
    monitor.start(callback=generate_callback(DROP_PRIVILEGES_IGNORED_MSG))
    assert monitor.callback_result is not None, 'The drop_privileges ignored setting warning was not logged'
