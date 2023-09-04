from pathlib import Path

import pytest

from wazuh_testing.utils import file


@pytest.fixture
def symlink_target(test_metadata: dict) -> str:
    target = test_metadata.get('symlink_target')

    if not '.' in target:
        file.create_folder(target)
    else:
        file.write_file(target)

    yield Path(target)

    file.remove_file(target)


@pytest.fixture
def file_symlink(symlink_target: Path, test_metadata: dict) -> str:
    symlink_path = test_metadata.get('symlink')

    Path(symlink_path).symlink_to(symlink_target)

    yield Path(symlink_path)

    file.remove_file(symlink_path)


@pytest.fixture
def symlink_new_target(test_metadata: dict) -> Path:
    target = test_metadata.get('symlink_new_target')

    if not '.' in target:
        file.create_folder(target)
    else:
        file.write_file(target)

    yield Path(target)

    file.remove_file(target)
