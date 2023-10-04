import os
import pytest

from wazuh_testing import LOG_FILE_PATH, CIS_RULESET_PATH
from wazuh_testing.modules import sca
from wazuh_testing.modules.sca import event_monitor as evm
from wazuh_testing.tools.file import copy, delete_file, copy_files_in_folder, delete_path_recursively
from wazuh_testing.tools.monitoring import FileMonitor


# Variables
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# Fixtures
@pytest.fixture()
def wait_for_sca_enabled():
    '''
    Wait for the sca module to start.
    '''
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)
    evm.check_sca_enabled(wazuh_monitor)


@pytest.fixture()
def prepare_cis_policies_file(metadata):
    '''
    Copies policy file from named by metadata into agent's ruleset path. Deletes file after test.
    Args:
        metadata (dict): contains the test metadata. Must contain policy_file key with file name.
    '''
    files_to_restore = copy_files_in_folder(src_folder=CIS_RULESET_PATH, dst_folder=sca.TEMP_FILE_PATH)
    filename = metadata['policy_file']
    filepath = os.path.join(TEST_DATA_PATH, 'policies', filename)
    copy(filepath, CIS_RULESET_PATH)
    yield
    copy_files_in_folder(src_folder=sca.TEMP_FILE_PATH, dst_folder=CIS_RULESET_PATH, files_to_move=files_to_restore)
    delete_file(os.path.join(CIS_RULESET_PATH, filename))


@pytest.fixture()
def prepare_test_folder(folder_path='/testfile', mode=0o666):
    '''
    Creates folder with a given mode.
    Args:
        folder_path (str): path for the folder to create
        mode (int): mode to be used for folder creation.
    '''
    os.makedirs(folder_path, mode, exist_ok=True)

    yield

    delete_path_recursively(folder_path)
