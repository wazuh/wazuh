import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG
from wazuh_testing.modules.fim.patterns import MONITORING_PATH, WHODATA_ADDED_EVENT, WHODATA_DELETED_EVENT
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.syscheck.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_delete_multiple_files.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_basic.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_delete_multiple_files(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                               folder_to_monitor, fill_folder_to_monitor, truncate_monitored_files, daemons_handler):
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    files_amount = test_metadata.get('files_amount')
    # Wait folder is monitored
    wazuh_log_monitor.start(generate_callback(fr'{MONITORING_PATH}{folder_to_monitor}.*'))

    file.remove_folder(folder_to_monitor)
    wazuh_log_monitor.start(generate_callback(WHODATA_DELETED_EVENT), accumulations=files_amount)
    assert wazuh_log_monitor.callback_result
    assert wazuh_log_monitor.matches == files_amount
