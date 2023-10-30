# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys
import shutil

from wazuh_testing.modules.logcollector import logcollector
from logtest import callback_logtest_started
from wazuh_testing.utils.services import control_service
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.file import truncate_file
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

from wazuh_testing.utils import configuration as conf
from wazuh_testing.global_parameters import GlobalParameters
from wazuh_testing.utils.time import TimeMachine

from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.logger import logger

@pytest.fixture(scope='module')
def restart_required_logtest_daemons():
    """Wazuh logtests daemons handler."""
    required_logtest_daemons = ['wazuh-analysisd', 'wazuh-db']

    for daemon in required_logtest_daemons:
        control_service('stop', daemon=daemon)

    truncate_file(WAZUH_LOG_PATH)

    for daemon in required_logtest_daemons:
        control_service('start', daemon=daemon)

    yield

    for daemon in required_logtest_daemons:
        control_service('stop', daemon=daemon)

@pytest.fixture(scope='module')
def wait_for_logtest_startup(request):
    """Wait until logtest has begun."""
    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callback_logtest_started, timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT)

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
    global_parameters = GlobalParameters()
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


@pytest.fixture()
def restart_wazuh(request):
    control_service('restart')


def connect_to_sockets(request):
    """Connect to the specified sockets for the test."""
    receiver_sockets_params = getattr(request.module, 'receiver_sockets_params')

    # Create the SocketControllers
    receiver_sockets = list()
    for address, family, protocol in receiver_sockets_params:
        receiver_sockets.append(SocketController(address=address, family=family, connection_protocol=protocol))

    setattr(request.module, 'receiver_sockets', receiver_sockets)

    return receiver_sockets

def close_sockets(receiver_sockets):
    """Close the sockets connection gracefully."""
    for socket in receiver_sockets:
        try:
            # We flush the buffer before closing the connection if the protocol is TCP:
            if socket.protocol == 1:
                socket.sock.settimeout(5)
                socket.receive()  # Flush buffer before closing connection
            socket.close()
        except OSError as e:
            if e.errno == 9:
                # Do not try to close the socket again if it was reused or closed already
                pass


@pytest.fixture(scope='function')
def connect_to_sockets_function(request):
    """Function scope version of connect_to_sockets."""
    receiver_sockets = connect_to_sockets(request)

    yield receiver_sockets

    close_sockets(receiver_sockets)


@pytest.fixture(scope='module')
def configure_local_internal_options_module(request):
    """Fixture to configure the local internal options file.

    It uses the test variable local_internal_options. This should be
    a dictionary wich keys and values corresponds to the internal option configuration, For example:
    local_internal_options = {'monitord.rotate_log': '0', 'syscheck.debug': '0' }
    """
    try:
        local_internal_options = request.param
    except AttributeError:
        try:
            local_internal_options = getattr(request.module, 'local_internal_options')
        except AttributeError:
            logger.debug('local_internal_options is not set')
            raise AttributeError('Error when using the fixture "configure_local_internal_options_module", no '
                                 'parameter has been passed explicitly, nor is the variable local_internal_options '
                                 'found in the module.') from AttributeError

    backup_local_internal_options = conf.get_local_internal_options_dict()

    logger.debug(f"Set local_internal_option to {str(local_internal_options)}")
    conf.set_local_internal_options_dict(local_internal_options)

    yield local_internal_options

    logger.debug(f"Restore local_internal_option to {str(backup_local_internal_options)}")
    conf.set_local_internal_options_dict(backup_local_internal_options)


@pytest.fixture(scope='function')
def file_monitoring(request):
    """Fixture to handle the monitoring of a specified file.

    It uses the variable `file_to_monitor` to determinate the file to monitor. Default `LOG_FILE_PATH`

    Args:
        request (fixture): Provide information on the executing test function.
    """
    if hasattr(request.module, 'file_to_monitor'):
        file_to_monitor = getattr(request.module, 'file_to_monitor')
    else:
        file_to_monitor = WAZUH_LOG_PATH

    logger.debug(f"Initializing file to monitor to {file_to_monitor}")

    file_monitor = FileMonitor(file_to_monitor)
    setattr(request.module, 'log_monitor', file_monitor)

    yield

    truncate_file(file_to_monitor)
    logger.debug(f"Trucanted {file_to_monitor}")
