'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Validate FIM startup synchronization behavior on fresh installation and restart scenarios.
'''
import sys
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils import services

from . import TEST_CASES_PATH, CONFIGS_PATH


pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

cases_path = Path(TEST_CASES_PATH, 'cases_fim_disabled.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_basic.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS:
    local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})


@pytest.mark.parametrize('test_configuration, test_metadata', [(test_configuration[0], test_metadata[0])],
                         ids=['fim_first_sync_startup'])
def test_fim_first_sync_startup_behavior(test_configuration, test_metadata, set_wazuh_configuration,
                                         truncate_monitored_files, configure_local_internal_options,
                                         folder_to_monitor, clean_fim_db, clean_fim_sync_db, daemons_handler):
    '''
    description: Validate first-run and restart startup synchronization behavior for FIM.

    assertions:
        - Fresh install path skips the initial synchronization wait.
        - Restart path keeps the configured startup synchronization delay.
    '''
    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(generate_callback(r'.*First-run FIM synchronization detected.*skip startup delay.*'),
                      timeout=60 if sys.platform == WINDOWS else 30)
    assert log_monitor.callback_result, 'Fresh install path should be detected for FIM synchronization'

    log_monitor.start(generate_callback(r'.*Initial FIM synchronization wait skipped on first run.*'),
                      timeout=60 if sys.platform == WINDOWS else 30)
    assert log_monitor.callback_result, 'FIM should skip the first synchronization wait on fresh install'

    # Restart without cleaning DBs to validate legacy startup-delay behavior.
    services.control_service('stop')
    services.wait_expected_daemon_status(running_condition=False, timeout=180)
    services.control_service('start')

    restart_monitor = FileMonitor(WAZUH_LOG_PATH)
    restart_monitor.start(generate_callback(r'.*Existing FIM synchronization state detected.*Keeping startup delay.*'),
                          timeout=60 if sys.platform == WINDOWS else 30)
    assert restart_monitor.callback_result, 'FIM restart path should keep startup synchronization delay'
