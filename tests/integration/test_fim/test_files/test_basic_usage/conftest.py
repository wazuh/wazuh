from pathlib import Path

import pytest

from wazuh_testing.utils import file


@pytest.fixture()
def create_links_to_file(folder_to_monitor: str, file_to_monitor: str, test_metadata: dict) -> None:
    hardlink_amount = test_metadata.get('hardlink_amount', 0)
    symlink_amount = test_metadata.get('symlink_amount', 0)

    def hardlink(i: int):
        Path(folder_to_monitor, f'test_h{i}').symlink_to(file_to_monitor)

    def symlink(i: int):
        Path(folder_to_monitor, f'test_s{i}').hardlink_to(file_to_monitor)

    [hardlink(i) for i in range(hardlink_amount)]
    [symlink(i) for i in range(symlink_amount)]

    yield

    [file.remove_file( f'test_h{i}') for i in range(hardlink_amount)]
    [file.remove_file( f'test_s{i}') for i in range(symlink_amount)]
