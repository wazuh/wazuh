import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.patterns import ADDED_EVENT
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


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

    [file.remove_file(f'test_h{i}') for i in range(hardlink_amount)]
    [file.remove_file(f'test_s{i}') for i in range(symlink_amount)]


@pytest.fixture()
def path_to_edit(test_metadata: dict) -> str:
    to_edit = test_metadata.get('path_to_edit')
    is_directory = test_metadata.get('is_directory')

    if is_directory:
        file.create_folder(to_edit)
        file.write_file(Path(to_edit, 'newfile'), 'test')
    else:
        file.write_file(to_edit, 'test')

    FileMonitor(WAZUH_LOG_PATH).start(generate_callback(ADDED_EVENT))

    yield to_edit

    file.remove_folder(to_edit)
