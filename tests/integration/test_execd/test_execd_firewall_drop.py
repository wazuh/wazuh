import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import OSSEC_LOG_PATH
from wazuh_testing.modules.execd import EXECD_DEBUG_CONFIG
from wazuh_testing.tools import file_monitor
from wazuh_testing.utils import config, callbacks

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'config_execd.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_execd_firewall_drop.yaml')

# Test configurations.
config_parameters, metadata, cases_ids = config.get_test_cases_data(cases_path)
configuration = config.load_configuration_template(configs_path, config_parameters, metadata)

# Test internal options.
local_internal_options = EXECD_DEBUG_CONFIG

# Test Active Response configuration
active_response_configuration = '''restart-wazuh0 - restart-wazuh - 0\n
                                   restart-wazuh0 - restart-wazuh.exe - 0\n
                                   firewall-drop0 - firewall-drop - 0\n
                                   firewall-drop5 - firewall-drop - 5'''

# Test function.
@pytest.mark.parametrize('configuration, metadata', zip(configuration, metadata), ids=cases_ids)
def test_execd_firewall_drop(configuration, metadata, configure_local_internal_options, set_active_response_configuration):
    '''
    description: Check if 'firewall-drop' command of 'active response' is executed correctly.
                 For this purpose, a simulated agent is used and the 'active response'
                 is sent to it. This response includes an IP address that must be added
                 and removed from 'iptables', the Linux firewall.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_debug_mode:
            type: fixture
            brief: Set the 'wazuh-execd' daemon in debug mode.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - test_version:
            type: fixture
            brief: Validate the Wazuh version.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - remove_ip_from_iptables:
            type: fixture
            brief: Remove the testing IP address from 'iptables' if it exists.
        - start_agent:
            type: fixture
            brief: Create 'wazuh-remoted' and 'wazuh-authd' simulators, register agent and start it.
        - set_ar_conf_mode:
            type: fixture
            brief: Configure the 'active responses' used in the test.

    assertions:
        - Verify that the testing IP address is added to 'iptables'.
        - Verify that the testing IP address is removed from 'iptables'.

    input_description: Different use cases are found in the test module and include
                       parameters for 'firewall-drop' command and the expected result.

    expected_output:
        - r'DEBUG: Received message'
        - r'Starting'
        - r'active-response/bin/firewall-drop'
        - r'Ended'
        - r'Cannot read 'srcip' from data' (If the 'active response' fails)

    tags:
        - simulator
    '''
    pass