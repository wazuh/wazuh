import os
from pathlib import Path
import subprocess
import pytest
from wazuh_testing.constants.paths.binaries import ACTIVE_RESPONSE_BIN_PATH
from wazuh_testing.constants.paths.logs import ALERTS_LOG_PATH
from wazuh_testing.tools.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture(scope='module')
def prepare_ar_files(request: pytest.FixtureRequest) -> None:
    if not hasattr(request.module, 'custom_ar_script'):
        raise AttributeError('No `custom_ar_script` defined in module.')
    if not hasattr(request.module, 'monitored_file'):
        raise AttributeError('No `monitored_file` defined in module.')

    monitored_file = getattr(request.module, 'monitored_file')
    file.write_file(monitored_file, '')

    ar_script = getattr(request.module, 'custom_ar_script')
    destination_ar_script = Path(ACTIVE_RESPONSE_BIN_PATH, 'custom-ar.sh')

    script_data = file.read_file(ar_script)
    file.write_file(destination_ar_script, script_data)
    os.chmod(destination_ar_script, 0o777)

    yield

    file.remove_file(destination_ar_script)
    file.remove_file(monitored_file)    


@pytest.fixture()
def fill_monitored_file(request: pytest.FixtureRequest, test_metadata: dict) -> None:
    # Validate the input to get the message from exists.
    if test_metadata.get('input') is None:
        raise AttributeError('No `input` key in `test_metadata`.')
    if not hasattr(request.module, 'monitored_file'):
        raise AttributeError('No `monitored_file` defined in module.')
    if not hasattr(request.module, 'file_created_by_script'):
        raise AttributeError('No `file_created_by_script` defined in module.')

    input = test_metadata['input']
    monitored_file = getattr(request.module, 'monitored_file')

    subprocess.Popen(f"echo '{input}' >> {monitored_file}", shell=True)

    yield

    file.delete_file(getattr(request.module, 'file_created_by_script'))


