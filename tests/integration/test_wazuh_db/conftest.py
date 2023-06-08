import os
import pytest

from wazuh_testing.utils.file import remove_file, recursive_directory_creation
from wazuh_testing.tools.manager_handler import create_group, delete_group
from wazuh_testing.constants.paths import BACKUPS_PATH

@pytest.fixture()
def create_groups(test_case):
    if 'pre_required_group' in test_case:
        groups = test_case['pre_required_group'].split(',')

        for group in groups:
            create_group(group)

    yield

    if 'pre_required_group' in test_case:
        groups = test_case['pre_required_group'].split(',')

        for group in groups:
            delete_group(group)

@pytest.fixture()
def remove_backups(backups_path=BACKUPS_PATH):
    "Creates backups folder in case it does not exist."
    remove_file(backups_path)
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)
    yield
    remove_file(backups_path)
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)