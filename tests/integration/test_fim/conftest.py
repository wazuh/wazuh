from typing import Any
import pytest

from wazuh_testing.utils import file


@pytest.fixture()
def file_to_monitor(test_metadata: dict) -> Any:
    path = test_metadata['file_to_monitor']
    file.write_file(path)
    
    yield
    
    file.remove_file(path)

@pytest.fixture()
def folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata['folder_to_monitor']
    file.create_folder(folder_to_monitor)
    
    yield
    
    file.delete_path_recursively(path)
