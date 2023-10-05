import os
import sys
import re
import shutil

import pytest

from wazuh_testing.tools.wazuh_manager import create_group, delete_group
from wazuh_testing.utils import configuration as conf
from wazuh_testing import global_parameters
from wazuh_testing.utils.time import TimeMachine
from wazuh_testing.utils.services import control_service
from wazuh_testing.constants import paths
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils.file import truncate_file

@pytest.fixture(scope='function')
def create_groups(test_case):
    if 'pre_required_group' in test_case:
        groups = test_case['pre_required_group'].split(',')

        for group in groups:
            create_group(group)

    yield

    if 'pre_required_group' in test_case:
        groups = test_case['pre_required_group'].split(',')

        for group in groups:
            delete_group(group)


@pytest.fixture(scope='module')
def configure_environment(get_configuration, request):
    """Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration."""

    # Save current configuration
    backup_config = conf.get_wazuh_conf()

    # Configuration for testing
    test_config = conf.set_section_wazuh_conf(get_configuration.get('sections'))

    # Create test directories
    if hasattr(request.module, 'test_directories'):
        test_directories = getattr(request.module, 'test_directories')
        for test_dir in test_directories:
            os.makedirs(test_dir, exist_ok=True, mode=0o777)

    # Create test registry keys
    if sys.platform == 'win32':
        if hasattr(request.module, 'test_regs'):
            test_regs = getattr(request.module, 'test_regs')

            for reg in test_regs:
                match = re.match(r"(^HKEY_[a-zA-Z_]+)\\+(.+$)", reg)
                create_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_32KEY)
                create_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_64KEY)

    # Set new configuration
    conf.write_wazuh_conf(test_config)

    # Change Windows Date format to ensure TimeMachine will work properly
    if sys.platform == 'win32':
        subprocess.call('reg add "HKCU\\Control Panel\\International" /f /v sShortDate /t REG_SZ /d "dd/MM/yyyy" >nul',
                        shell=True)

    # Call extra functions before yield
    if hasattr(request.module, 'extra_configuration_before_yield'):
        func = getattr(request.module, 'extra_configuration_before_yield')
        func()

    # Set current configuration
    global_parameters.current_configuration = get_configuration

    yield

    TimeMachine.time_rollback()

    # Remove created folders (parents)
    if sys.platform == 'win32' and not hasattr(request.module, 'no_restart_windows_after_configuration_set'):
        control_service('stop')

    if hasattr(request.module, 'test_directories'):
        for test_dir in test_directories:
            shutil.rmtree(test_dir, ignore_errors=True)

    if sys.platform == 'win32':
        if hasattr(request.module, 'test_regs'):
            for reg in test_regs:
                match = re.match(r"(^HKEY_[a-zA-Z_]+)\\+(.+$)", reg)
                delete_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_32KEY)
                delete_registry(registry_parser[match.group(1)], match.group(2), KEY_WOW64_64KEY)

    if sys.platform == 'win32' and not hasattr(request.module, 'no_restart_windows_after_configuration_set'):
        control_service('start')

    # Restore previous configuration
    conf.write_wazuh_conf(backup_config)

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    if hasattr(request.module, 'force_restart_after_restoring'):
        if getattr(request.module, 'force_restart_after_restoring'):
            control_service('restart')


@pytest.fixture(scope='function')
def clear_logs(get_configuration, request):
    """Reset the ossec.log and start a new monitor"""
    truncate_file(paths.logs.WAZUH_LOG_PATH)
    log_monitor = file_monitor.FileMonitor(paths.logs.WAZUH_LOG_PATH)
    setattr(request.module, 'wazuh_log_monitor', log_monitor)