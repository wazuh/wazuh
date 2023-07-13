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
    file.create_folder(path) if path else None

    yield

    file.delete_path_recursively(path) if path else None
