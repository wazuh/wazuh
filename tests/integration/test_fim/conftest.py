from pathlib import Path
from typing import Any
import pytest

from wazuh_testing.utils import file


@pytest.fixture()
def file_to_monitor(test_metadata: dict) -> Any:
    path = test_metadata.get('file_to_monitor')
    file.write_file(path) if path else None

    yield

    file.remove_file(path) if path else None


@pytest.fixture()
def folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    file.create_folder(folder_to_monitor) if path else None

    yield

    file.delete_path_recursively(path) if path else None


@pytest.fixture()
def path_to_monitor(test_metadata: dict) -> None:
    # Get the folder to monitor
    path = test_metadata.get('path_to_monitor')
    file.create_folder(path)

    # If it is a specific file, get and create it.
    # if file_path := test_metadata.get('file_to_monitor'):
    #     file_path = Path(path, file_path)
    #     file.write_file(file_path)

    yield path

    # file.remove_file(file_path) if file_path else None
    file.delete_path_recursively(path)
