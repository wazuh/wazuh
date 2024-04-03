"""
copyright: Copyright (C) 2015, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This test checks that API properly rotates the logs based by size.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html

tags:
    - api
    - logs
    - logging
"""

import pytest
from pathlib import Path
from datetime import datetime
import os

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from .utils import MONTHS_MAPPING_DICT
from wazuh_testing.constants.api import CONFIGURATION_TYPES
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_API_LOG_FILE_PATH
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.utils import file
from wazuh_testing.constants.paths.logs import BASE_LOGS_PATH
from wazuh_testing.modules.api.utils import login

# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_logs_rotation_config.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_log_rotate_by_size.yaml')

# Configurations
test_configuration, test_metadata, test_cases_id = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


@pytest.fixture
def delete_api_logs_folder_contents() -> None:
    """Deletes the API logs for the current year"""
    api_logs_folder = os.path.join(BASE_LOGS_PATH, "api", str(datetime.now().year))
    file.delete_path_recursively(api_logs_folder)

    yield

    file.delete_path_recursively(api_logs_folder)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_id)
def test_logs_rotate_to_expected_path(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                                      delete_api_logs_folder_contents, daemons_handler, wait_for_api_start):
    """
    description: Check if the log rotates based on the file size.

    wazuh_min_version: 4.6.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Delete api logs folders
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Log file is created in the correct path with the expected suffixes.
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files
            - Delete api logs folders
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
        - delete_api_logs_folder_contents:
            type: fixture
            brief: Deletes api logs folders.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - wait_for_api_start:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.

    input_description: The test gets the configuration from the YAML file, which contains the API configuration.

    assertions:
        - Verify that the log file is created in the correct path with the expected suffixes.
    """
    # Get metadata for the tests
    size_to_replicate = test_metadata['size_in_kb']

    # Fill the file until it reaches the required size
    total_size_in_kb = size_to_replicate * 1024
    file.write_file(WAZUH_API_LOG_FILE_PATH, [" " for _ in range(total_size_in_kb)])

    # Makes a request
    authentication_headers, _ = login()

    # Format the expected log file path
    year = datetime.now().year
    month = MONTHS_MAPPING_DICT[datetime.now().month]
    day = str(datetime.now().day).zfill(2)
    expected_file = f"/var/ossec/logs/api/{year}/{month}/api.log-{day}_1.gz"

    # Assert that the log file exists
    assert file.exists_and_is_file(expected_file)
