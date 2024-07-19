'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon receives the log messages and compares them to the rules.
       It then creates an alert when a log message matches an applicable rule.
       Specifically, these tests will check if the 'wazuh-analysisd' daemon generates alerts
       using custom rules that contains the 'mitre' field to enrich those alerts with
       MITREs IDs, techniques and tactics.

components:
    - analysisd

suite: mitre

targets:
    - manager

daemons:
    - wazuh-analysisd
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html
    - https://attack.mitre.org/

tags:
    - events
    - mitre
'''
import os
import json
import jsonschema
import pytest

from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH
from wazuh_testing.modules.analysisd import patterns, utils
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks

from . import RULES_SAMPLE_PATH

pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Test variables.
configurations = []
invalid_configurations = []

for i in range(1, 15):
    file_test = os.path.join(RULES_SAMPLE_PATH, f"test{i}.xml")
    configurations.append(file_test)
    if i in range(5, 9):
        invalid_configurations.append(file_test)


# Test function.
@pytest.mark.parametrize('test_configuration', configurations)
def test_mitre_check_alert(test_configuration, truncate_monitored_files, configure_local_rules, daemons_handler):
    '''
    description: Check if MITRE alerts are syntactically and semantically correct.
                 For this purpose, customized rules with MITRE fields are inserted,
                 so that the alerts generated include this information which
                 will be finally validated.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_configuration:
            type: fixture
            brief: Configuration from the module.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_rules:
            type: fixture
            brief: Configure a custom rule in 'local_rules.xml' for testing.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that the MITRE alerts are generated and are correct.

    input_description: Different test cases that are contained in an external XML files ('data' directory)
                       that include both valid and invalid rules for detecting MITRE events.

    expected_output:
        - Multiple messages (mitre alert logs) corresponding to each test case,
          located in the external input data file.

    tags:
        - alerts
        - man_in_the_middle
        - wdb_socket
    '''
    wazuh_alert_monitor = file_monitor.FileMonitor(ALERTS_JSON_PATH)

    # Wait until Mitre's event is detected
    if test_configuration not in invalid_configurations:
        wazuh_alert_monitor.start(timeout=30, callback=callbacks.generate_callback(patterns.ANALYSISD_ALERT_STARTED))
        utils.validate_mitre_event(json.loads(wazuh_alert_monitor.callback_result))
    else:
        with pytest.raises(jsonschema.exceptions.ValidationError):
            wazuh_alert_monitor.start(timeout=30, callback=callbacks.generate_callback(patterns.ANALYSISD_ALERT_STARTED))
            utils.validate_mitre_event(json.loads(wazuh_alert_monitor.callback_result))
