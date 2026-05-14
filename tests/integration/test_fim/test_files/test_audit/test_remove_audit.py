'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-syscheckd' and 'auditd' daemons work together properly.
       In particular, it will be verified that when there is no 'auditd' package installed on
       the system, the directories monitored with 'who-data' mode are monitored with 'realtime'.
       The 'who-data' feature of the of the File Integrity Monitoring (FIM) system uses
       the Linux Audit subsystem to get the information about who made the changes in a monitored directory.
       These changes produce audit events that are processed by 'syscheck' and reported to the manager.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_audit

targets:
    - agent

daemons:
    - wazuh-syscheckd

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
    - https://man7.org/linux/man-pages/man8/auditd.8.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/auditing-whodata/who-linux.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_audit
'''
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG
from wazuh_testing.modules.fim.patterns import WHODATA_NOT_STARTED
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=1)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_remove_audit.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_remove_audit.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2,AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_remove_audit(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                      uninstall_audit, truncate_monitored_files, daemons_handler):
    '''
    description: Check if FIM switches the monitoring mode of the testing directories from 'who-data'
                 to 'realtime' when the 'auditd' package is not installed. For this purpose, the test
                 will monitor several folders using 'whodata' and uninstall the 'authd' package.
                 Once FIM starts, it will wait until the monitored directories using 'whodata'
                 are monitored with 'realtime' verifying that the proper FIM events are generated.
                 Finally, the test will install the 'auditd' package again.


    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Remove auditd
            - Truncate wazuh logs.
            - Restart wazuh to apply configuration changes.
        - test:
            - Check that whodata cannot start and monitoring of configured folder is changed to realtime mode.
        - teardown:
            - Install auditd
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Set local_internal_options.conf file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - uninstall_audit:
            type: fixture
            brief: Uninstall 'auditd' before the test and install it again after the test run.

    assertions:
        - Verify that FIM switches the monitoring mode of the testing directories from 'whodata' to 'realtime'
          if the 'authd' package is not installed.

    input_description: A test case is contained in external YAML file (configuration_remove_audit.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'.*Who-data engine could not start. Switching who-data to real-time.'

    tags:
        - who_data
    '''
    monitor = FileMonitor(WAZUH_LOG_PATH)
    monitor.start(callback=generate_callback(WHODATA_NOT_STARTED))

    assert monitor.callback_result
