import os
import pytest
import sys
import subprocess
from pathlib import Path

from wazuh_testing.constants.paths.ruleset import CIS_RULESET_PATH
from wazuh_testing.utils.file import copy, remove_file, copy_files_in_folder, delete_path_recursively
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.sca import patterns
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths import TEMP_FILE_PATH
from wazuh_testing.utils import callbacks
from wazuh_testing.constants.platforms import WINDOWS

from . import TEST_DATA_PATH

# Fixtures
@pytest.fixture()
def wait_for_sca_enabled():
    '''
    Wait for the sca module to start.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCA_ENABLED), timeout=60 if sys.platform == WINDOWS else 10)
    assert log_monitor.callback_result


@pytest.fixture()
def prepare_cis_policies_file(test_metadata):
    '''
    Copies policy file from named by metadata into agent's ruleset path. Deletes file after test.
    Args:
        test_metadata (dict): contains the test metadata. Must contain policy_file key with file name.
    '''
    files_to_restore = copy_files_in_folder(src_folder=CIS_RULESET_PATH, dst_folder=TEMP_FILE_PATH)
    filename = test_metadata['policy_file']
    filepath = Path(TEST_DATA_PATH, 'policies_samples', filename)
    copy(filepath, CIS_RULESET_PATH)
    yield
    copy_files_in_folder(src_folder=TEMP_FILE_PATH, dst_folder=CIS_RULESET_PATH, files_to_move=files_to_restore)
    remove_file(Path(CIS_RULESET_PATH, filename))


@pytest.fixture()
def prepare_remediation_test(folder_path='/testfile', mode=0o666):
    '''
    Creates folder with a given mode or modifies the user lockout duration in Windows.
    Args:
        folder_path (str): path for the folder to create
        mode (int): mode to be used for folder creation.
    '''

    duration = ''
    if sys.platform == WINDOWS:
        p = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "net accounts"],
                           capture_output=True, text=True)
        duration = p.stdout.splitlines()[6].split(':')[1].replace(" ", "")
        subprocess.call('net accounts /lockoutduration:30', shell=True)
    else:
        os.makedirs(folder_path, mode, exist_ok=True)

    yield


    if sys.platform == WINDOWS:
        subprocess.call('net accounts /lockoutduration:' + duration, shell=True)
    else:
        delete_path_recursively(folder_path)
