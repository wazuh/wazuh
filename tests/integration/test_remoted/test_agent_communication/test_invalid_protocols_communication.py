"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_invalid_protocols_communication.yaml')
config_path = Path(CONFIGS_PATH, 'config_invalid_protocols_communication.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_invalid_protocols_communication(test_configuration, test_metadata, configure_local_internal_options,
                                         truncate_monitored_files, set_wazuh_configuration, daemons_handler,
                                         simulate_agents, validate_agent_manager_protocol_communication):
    '''
    description: Check that agent-manager communication with an invalid protocol does not deliver
                 events to the engine. When the manager is configured for TCP only, UDP packets are
                 dropped at the network layer. When configured for UDP only, TCP connections are
                 refused. In both cases no alert should be generated.

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration applied to ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all monitored log files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - daemons_handler:
            type: fixture
            brief: Restart all wazuh services once the test finishes.
        - simulate_agents:
            type: fixture
            brief: Create simulated agents.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - validate_agent_manager_protocol_communication:
            type: fixture
            brief: Send event via the specified protocol and verify it does not generate an alert.
    '''
    protocol = test_metadata['protocol']
    manager_port = test_metadata['port']

    validate_agent_manager_protocol_communication(simulate_agents, protocol, manager_port)
