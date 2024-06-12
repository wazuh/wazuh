"""
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
from pathlib import Path

# Constants & base paths
TEST_DATA_PATH = Path(Path(__file__).parent, 'data')
TEST_CASES_FOLDER_PATH = Path(TEST_DATA_PATH, 'test_cases')
CONFIGURATIONS_FOLDER_PATH = Path(TEST_DATA_PATH, 'configuration_templates')
WAZUH_PYTHON_INTERPRETER_PATH = '/var/ossec/framework/python/lib/python3.10/site-packages'
MOCK_SERVER_PATH = Path(Path(__file__).parent, 'https_mock_server', 'env')
MOCK_SERVER_IMAGE = 'https_mock_server'
MOCK_SERVER_CONTAINER = 'https_mock_server_container'
