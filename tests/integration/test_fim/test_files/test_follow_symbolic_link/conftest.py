from pathlib import Path

import pytest

from wazuh_testing.utils import file


@pytest.fixture
def file_symlink(test_metadata: dict, file_to_monitor: str) -> str:
    symlink_path = test_metadata.get('file_symlink')
    Path(symlink_path).symlink_to(file_to_monitor)

    yield symlink_path

    file.remove_file(symlink_path)
