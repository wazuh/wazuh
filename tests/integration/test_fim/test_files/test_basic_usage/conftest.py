import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture()
def path_to_edit(test_metadata: dict) -> str:
    to_edit = test_metadata.get('path_to_edit')
    is_directory = test_metadata.get('is_directory')

    if is_directory:
        file.create_folder(to_edit)
        file.write_file(Path(to_edit, 'newfile'), 'test')
    else:
        file.write_file(to_edit, 'test')

    FileMonitor(WAZUH_LOG_PATH).start(generate_callback(EVENT_TYPE_ADDED))

    yield to_edit

    file.remove_folder(to_edit)
