"""
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
from pathlib import Path
from datetime import datetime
import pytest
import os

from wazuh_testing.utils import file
from wazuh_testing.constants.paths.logs import BASE_LOGS_PATH

# Constants & base paths
TEST_DATA_PATH = Path(Path(__file__).parent, 'data')
TEST_CASES_FOLDER_PATH = Path(TEST_DATA_PATH, 'test_cases')
CONFIGURATIONS_FOLDER_PATH = Path(TEST_DATA_PATH, 'configuration_templates')
MONTHS_MAPPING_DICT = {
    1: 'Jan',
    2: 'Feb',
    3: 'Mar',
    4: 'Apr',
    5: 'May',
    6: 'Jun',
    7: 'Jul',
    8: 'Aug',
    9: 'Sep',
    10: 'Oct',
    11: 'Nov',
    12: 'Dec'
}


@pytest.fixture
def delete_api_logs_folder_contents() -> None:
    """Deletes the API logs for the current year"""
    api_logs_folder = os.path.join(BASE_LOGS_PATH, "api", str(datetime.now().year))
    file.delete_path_recursively(api_logs_folder)

    yield

    file.delete_path_recursively(api_logs_folder)
