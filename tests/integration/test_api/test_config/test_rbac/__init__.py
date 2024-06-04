"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
from pathlib import Path


# Constants & base paths
TEST_DATA_PATH = Path(Path(__file__).parent, 'data')
TEST_CASES_FOLDER_PATH = Path(TEST_DATA_PATH, 'test_cases')
CONFIGURATIONS_FOLDER_PATH = Path(TEST_DATA_PATH, 'configuration_templates')
DB_SCHEMAS_FOLDER_PATH = Path(TEST_DATA_PATH, 'db_schemas')
