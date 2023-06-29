import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH
from wazuh_testing.tools.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH, CUSTOM_SCRIPTS_PATH, RULES_SAMPLE_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Path to cases data.
cases_path = Path(TEST_CASES_PATH, 'cases_trigger_active_response.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_trigger_active_response.yaml')
# Test metadata, configuration and ids.
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(
    config_path, test_configuration, test_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# File that will be created by the custom script
custom_ar_script = Path(CUSTOM_SCRIPTS_PATH, 'custom-ar.sh')
file_created_by_script = '/tmp/file-ar.txt'
monitored_file = '/tmp/file_to_monitor.log'


# Test function
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_overwritten_rules_triggers_ar(test_configuration, test_metadata, truncate_monitored_files,set_wazuh_configuration,
                                       prepare_ar_files, prepare_custom_rules_file, daemons_handler, fill_monitored_file):
    alerts_monitor = FileMonitor(ALERTS_JSON_PATH)
    alerts_monitor.start(generate_callback(rf".*{monitored_file}.*"))

    assert test_metadata['input'] in alerts_monitor.callback_result
    assert file.exists_and_is_file(file_created_by_script)
