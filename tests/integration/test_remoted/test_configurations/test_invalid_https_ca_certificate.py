"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

from . import CONFIGS_PATH, TEST_CASES_PATH

from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_invalid_https_ca_certificate.yaml')
config_path = Path(CONFIGS_PATH, 'config_remoted_https_ca_certificate.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_invalid_https_ca_certificate(test_configuration, test_metadata, configure_local_internal_options,
                                      truncate_monitored_files, set_wazuh_configuration, restart_wazuh_expect_error):

    '''
    description: Check that the manager refuses to start with an empty 'remote.https.ca_certificate' and
                 reports the schema verdict (1244, keyword minLength) in the log. For this purpose, the test
                 will set a configuration from the module test cases and check the log with a FileMonitor.

    parameters:
        - test_configuration
            type: dict
            brief: Configuration applied to wazuh-manager.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply the test configuration to wazuh-manager.conf and restore the original afterwards.
        - restart_wazuh_expect_error
            type: fixture
            brief: Restart service when expected error is None, once the test finishes stops the daemons.
    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # The schema requires remote.https.ca_certificate to be non-empty (minLength): the control script's
    # fail-fast surfaces the CLI verdict as 1244 with the JSON pointer as the subject and remoted never
    # starts. The keyword is asserted too: a manager without the option fails on the same pointer with
    # 'unknown option', which must NOT pass here.
    log_monitor.start(callback=generate_callback(test_metadata['invalid']))
    assert log_monitor.callback_result
