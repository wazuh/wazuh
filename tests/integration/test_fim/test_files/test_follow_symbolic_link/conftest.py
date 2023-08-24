from pathlib import Path

import pytest

from wazuh_testing.utils import file


@pytest.fixture
def file_symlink(test_metadata: dict) -> str:
    symlink_path = test_metadata.get('symlink')
    target = test_metadata.get('symlink_target')

    file.write_file(target)
    Path(symlink_path).symlink_to(target)

    yield symlink_path

    file.remove_file(symlink_path)
    file.remove_file(target)
