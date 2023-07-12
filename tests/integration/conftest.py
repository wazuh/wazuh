"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
import subprocess
import pytest
import sys
from typing import List

from wazuh_testing import session_parameters
from wazuh_testing.constants import platforms
from wazuh_testing.constants.daemons import WAZUH_MANAGER, API_DAEMONS_REQUIREMENTS
from wazuh_testing.constants.paths import ROOT_PREFIX
from wazuh_testing.constants.paths.api import RBAC_DATABASE_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH, ALERTS_JSON_PATH, WAZUH_API_LOG_FILE_PATH, \
                                               WAZUH_API_JSON_LOG_FILE_PATH
from wazuh_testing.logger import logger
from wazuh_testing.tools import socket_controller
from wazuh_testing.tools.monitors import queue_monitor
from wazuh_testing.tools.simulators.agent_simulator import create_agents, connect
from wazuh_testing.tools.simulators.authd_simulator import AuthdSimulator
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import configuration, database, file, mocking, services
from wazuh_testing.utils.file import remove_file
from wazuh_testing.utils.manage_agents import remove_agents


#- - - - - - - - - - - - - - - - - - - - - - - - -Pytest configuration - - - - - - - - - - - - - - - - - - - - - - - - -


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add command-line options to the tests.

    Args:
        parser (pytest.Parser): Parser for command line arguments and ini-file values.
    """
    parser.addoption(
        "--tier",
        action="append",
        metavar="level",
        default=None,
        type=int,
        help="only run tests with a tier level equal to 'level'",
    )
    parser.addoption(
        "--tier-minimum",
        action="store",
        metavar="minimum_level",
        default=-1,
        type=int,
        help="only run tests with a tier level greater or equal than 'minimum_level'"
    )
    parser.addoption(
        "--tier-maximum",
        action="store",
        metavar="maximum_level",
        default=sys.maxsize,
        type=int,
        help="only run tests with a tier level less or equal than 'minimum_level'"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    """Deselect tests that do not match with the specified environment or tier.

    Args:
        config (pytest.Config): Access to configuration values, pluginmanager and plugin hooks.
        items (list): List of items where each item is a basic test invocation.
    """
    selected_tests = []
    deselected_tests = []
    _host_types = set(["server", "agent"])
    _platforms = set([platforms.LINUX,
                      platforms.WINDOWS,
                      platforms.MACOS,
                      platforms.SOLARIS])

    for item in items:
        supported_platforms = _platforms.intersection(
            mark.name for mark in item.iter_markers())
        plat = sys.platform

        selected = True
        if supported_platforms and plat not in supported_platforms:
            selected = False

        host_type = 'agent' if 'agent' in services.get_service() else 'server'
        supported_types = _host_types.intersection(
            mark.name for mark in item.iter_markers())
        if supported_types and host_type not in supported_types:
            selected = False
        # Consider only first mark
        levels = [mark.kwargs['level']
                  for mark in item.iter_markers(name="tier")]
        if levels and len(levels) > 0:
            tiers = item.config.getoption("--tier")
            if tiers is not None and levels[0] not in tiers:
                selected = False
            elif item.config.getoption("--tier-minimum") > levels[0]:
                selected = False
            elif item.config.getoption("--tier-maximum") < levels[0]:
                selected = False
        if selected:
            selected_tests.append(item)
        else:
            deselected_tests.append(item)

    config.hook.pytest_deselected(items=deselected_tests)
    items[:] = selected_tests


# - - - - - - - - - - - - - - - - - - - - - - -End of Pytest configuration - - - - - - - - - - - - - - - - - - - - - - -


@pytest.fixture(scope='session')
def load_wazuh_basic_configuration():
    """Load a new basic configuration to the manager"""
    # Load ossec.conf with all disabled settings
    minimal_configuration = configuration.get_minimal_configuration()

    # Make a backup from current configuration
    backup_ossec_configuration = configuration.get_wazuh_conf()

    # Write new configuration
    configuration.write_wazuh_conf(minimal_configuration)

    yield

    # Restore the ossec.conf backup
    configuration.write_wazuh_conf(backup_ossec_configuration)


@pytest.fixture()
def set_wazuh_configuration(test_configuration: dict) -> None:
    """Set wazuh configuration

    Args:
        test_configuration (dict): Configuration template data to write in the ossec.conf
    """
    # Save current configuration
    backup_config = configuration.get_wazuh_conf()

    # Configuration for testing
    test_config = configuration.set_section_wazuh_conf(test_configuration.get('sections'))

    # Set new configuration
    configuration.write_wazuh_conf(test_config)

    # Set current configuration
    session_parameters.current_configuration = test_config

    yield

    # Restore previous configuration
    configuration.write_wazuh_conf(backup_config)


def truncate_monitored_files_implementation() -> None:
    """Truncate all the log files and json alerts files before and after the test execution"""
    if services.get_service() == WAZUH_MANAGER:
        log_files = [WAZUH_LOG_PATH, ALERTS_JSON_PATH, WAZUH_API_LOG_FILE_PATH, WAZUH_API_JSON_LOG_FILE_PATH]
    else:
        log_files = [WAZUH_LOG_PATH]

    for log_file in log_files:
        if os.path.isfile(os.path.join(ROOT_PREFIX, log_file)):
            file.truncate_file(log_file)

    yield

    for log_file in log_files:
        if os.path.isfile(os.path.join(ROOT_PREFIX, log_file)):
            file.truncate_file(log_file)


@pytest.fixture()
def truncate_monitored_files() -> None:
    """Wrapper of `truncate_monitored_files_implementation` which contains the general implementation."""
    yield from truncate_monitored_files_implementation()


@pytest.fixture(scope='module')
def truncate_monitored_files_module() -> None:
    """Wrapper of `truncate_monitored_files_implementation` which contains the general implementation."""
    yield from truncate_monitored_files_implementation()


def daemons_handler_implementation(request: pytest.FixtureRequest) -> None:
    """Helper function to handle Wazuh daemons.

    It uses `daemons_handler_configuration` of each module in order to configure the behavior of the fixture.

    The  `daemons_handler_configuration` should be a dictionary with the following keys:
        daemons (list, optional): List with every daemon to be used by the module. In case of empty a ValueError
            will be raised
        all_daemons (boolean): Configure to restart all wazuh services. Default `False`.
        ignore_errors (boolean): Configure if errors in daemon handling should be ignored. This option is available
        in order to use this fixture along with invalid configuration. Default `False`

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    daemons = []
    ignore_errors = False
    all_daemons = False

    try:
        daemons_handler_configuration = getattr(request.module, 'daemons_handler_configuration')
        if 'daemons' in daemons_handler_configuration and not all_daemons:
            daemons = daemons_handler_configuration['daemons']
            if not daemons or (type(daemons) == list and len(daemons) == 0) or type(daemons) != list:
                logger.error('Daemons list is not set')
                raise ValueError

        if 'all_daemons' in daemons_handler_configuration:
            logger.debug(f"Wazuh control set to {daemons_handler_configuration['all_daemons']}")
            all_daemons = daemons_handler_configuration['all_daemons']

        if 'ignore_errors' in daemons_handler_configuration:
            logger.debug(f"Ignore error set to {daemons_handler_configuration['ignore_errors']}")
            ignore_errors = daemons_handler_configuration['ignore_errors']

    except AttributeError as daemon_configuration_not_set:
        logger.error('daemons_handler_configuration is not set')
        raise daemon_configuration_not_set

    try:
        if all_daemons:
            logger.debug('Restarting wazuh using wazuh-control')
            services.control_service('restart')
        else:
            for daemon in daemons:
                logger.debug(f"Restarting {daemon}")
                # Restart daemon instead of starting due to legacy used fixture in the test suite.
                services.control_service('restart', daemon=daemon)

    except ValueError as value_error:
        logger.error(f"{str(value_error)}")
        if not ignore_errors:
            raise value_error
    except subprocess.CalledProcessError as called_process_error:
        logger.error(f"{str(called_process_error)}")
        if not ignore_errors:
            raise called_process_error

    yield

    if all_daemons:
        logger.debug('Stopping wazuh using wazuh-control')
        services.control_service('stop')
    else:
        if daemons == API_DAEMONS_REQUIREMENTS: daemons.reverse() # Stop in reverse, otherwise the next start will fail
        for daemon in daemons:
            logger.debug(f"Stopping {daemon}")
            services.control_service('stop', daemon=daemon)


@pytest.fixture()
def daemons_handler(request: pytest.FixtureRequest) -> None:
    """Wrapper of `daemons_handler_implementation` which contains the general implementation.

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    yield from daemons_handler_implementation(request)


@pytest.fixture(scope='module')
def daemons_handler_module(request: pytest.FixtureRequest) -> None:
    """Wrapper of `daemons_handler_implementation` which contains the general implementation.

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    yield from daemons_handler_implementation(request)


@pytest.fixture(scope='module')
def configure_local_internal_options(request: pytest.FixtureRequest) -> None:
    """Configure the local internal options file.

    Takes the `local_internal_options` variable from the request.
    The `local_internal_options` is a dict with keys and values as the Wazuh `local_internal_options` format.
    E.g.: local_internal_options = {'monitord.rotate_log': '0', 'syscheck.debug': '0' }

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    try:
        local_internal_options = request.param
    except AttributeError:
        try:
            local_internal_options = getattr(request.module, 'local_internal_options')
        except AttributeError:
            raise AttributeError('Error when using the fixture "configure_local_internal_options", no '
                                 'parameter has been passed explicitly, nor is the variable local_internal_options '
                                 'found in the module.') from AttributeError

    backup_local_internal_options = configuration.get_local_internal_options_dict()

    configuration.set_local_internal_options_dict(local_internal_options)

    yield

    configuration.set_local_internal_options_dict(backup_local_internal_options)


@pytest.fixture(scope='module')
def configure_sockets_environment(request: pytest.FixtureRequest) -> None:
    """Configure environment for sockets and MITM.

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    monitored_sockets_params = getattr(request.module, 'monitored_sockets_params')

    # Stop wazuh-service and ensure all daemons are stopped
    services.control_service('stop')
    services.check_daemon_status(running_condition=False)

    monitored_sockets = list()
    mitm_list = list()

    # Start selected daemons and monitored sockets MITM
    for daemon, mitm, daemon_first in monitored_sockets_params:
        not daemon_first and mitm is not None and mitm.start()
        services.control_service('start', daemon=daemon, debug_mode=True)
        services.check_daemon_status(
            running_condition=True,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )
        daemon_first and mitm is not None and mitm.start()
        if mitm is not None:
            monitored_sockets.append(queue_monitor.QueueMonitor(monitored_object=mitm.queue))
            mitm_list.append(mitm)

    setattr(request.module, 'monitored_sockets', monitored_sockets)

    yield

    # Stop daemons and monitored sockets MITM
    for daemon, mitm, _ in monitored_sockets_params:
        mitm is not None and mitm.shutdown()
        services.control_service('stop', daemon=daemon)
        services.check_daemon_status(
            running_condition=False,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )

    # Delete all db
    database.delete_dbs()

    services.control_service('start')


def connect_to_sockets_implementation(request: pytest.FixtureRequest) -> None:
    """Connect to the specified sockets for the test.

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.

    Returns:
        receiver_sockets (list): List of SocketControllers.
    """
    receiver_sockets_params = getattr(request.module, 'receiver_sockets_params')

    # Create the SocketControllers
    receiver_sockets = list()
    for address, family, protocol in receiver_sockets_params:
        receiver_sockets.append(socket_controller.SocketController(address=address, family=family,
                                                                   connection_protocol=protocol))

    setattr(request.module, 'receiver_sockets', receiver_sockets)

    yield receiver_sockets

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


@pytest.fixture()
def connect_to_sockets(request: pytest.FixtureRequest) -> None:
    """Wrapper of `connect_to_sockets_implementation` which contains the general implementation.

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    yield from connect_to_sockets_implementation(request)


@pytest.fixture(scope='module')
def connect_to_sockets_module(request: pytest.FixtureRequest) -> None:
    """Wrapper of `connect_to_sockets_implementation` which contains the general implementation.

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    yield from connect_to_sockets_implementation(request)


@pytest.fixture(scope='module')
def mock_agent_module():
    """Fixture to create a mocked agent in wazuh databases"""
    agent_id = mocking.create_mocked_agent(name='mocked_agent')

    yield agent_id

    mocking.delete_mocked_agent(agent_id)


@pytest.fixture()
def remoted_simulator() -> RemotedSimulator:
    """
    Fixture for an RemotedSimulator instance.

    This fixture creates an instance of the RemotedSimulator and starts it.
    The simulator is yielded to the test function, allowing to interact
    with it. After the test function finishes, the simulator is shut down.

    Returns:
        RemotedSimulator: An instance of the RemotedSimulator.

    """
    remoted = RemotedSimulator()
    remoted.start()

    yield remoted

    remoted.shutdown()


@pytest.fixture()
def authd_simulator() -> AuthdSimulator:
    """
    Fixture for an AuthdSimulator instance.

    This fixture creates an instance of the AuthdSimulator and starts it.
    The simulator is yielded to the test function, allowing to interact
    with it. After the test function finishes, the simulator is shut down.

    Returns:
        AuthdSimulator: An instance of the AuthdSimulator.

    """
    authd = AuthdSimulator()
    authd.start()

    yield authd

    authd.shutdown()


@pytest.fixture
def prepare_test_files(request: pytest.FixtureRequest) -> None:
    """Create the files/directories required by the test, and then delete them to clean up the environment.

    The test module must define a variable called `test_files` which is a list of files (defined as str or os.PathLike)

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    files_required = request.module.test_files

    created_files = file.create_files(files_required)

    yield

    # Reverse to delete in the correct order
    file.delete_files(created_files.reverse())


@pytest.fixture
def simulate_agent():
    """Simulate an agent and remove it using the API."""
    agent = create_agents(1, 'localhost')[0]
    _, injector = connect(agent)

    yield agent

    # Stop and delete simulated agent
    injector.stop_receive()
    remove_agents(agent.id, 'api')


@pytest.fixture
def remove_test_file(request):
    """Remove a test file before and after the test execution."""
    remove_file(request.module.test_file)

    yield

    remove_file(request.module.test_file)


@pytest.fixture
def add_user_in_rbac(request):
    """Add a new user in the RBAC database."""

    database.run_sql_script(RBAC_DATABASE_PATH, request.module.add_user_sql_script)

    yield

    database.run_sql_script(RBAC_DATABASE_PATH, request.module.delete_user_sql_script)


@pytest.fixture(autouse=True)
def autostart_simulators(request: pytest.FixtureRequest) -> None:
    """
    Fixture for starting simulators in wazuh-agent executions.

    This fixture starts both Authd and Remoted simulators only in the cases where the service is not
    WAZUH_MANAGER, and when the test function is not already using the simulator fixture, if it does
    use one of them, only start the remaining simulator.

    This is required so all wazuh-agent instances are being tested with the wazuh-manager connection
    being mocked.
    """
    create_authd = 'authd_simulator' not in request.fixturenames
    create_remoted = 'remoted_simulator' not in request.fixturenames

    if services.get_service() is not WAZUH_MANAGER:
        authd = AuthdSimulator() if create_authd else None
        remoted = RemotedSimulator() if create_remoted else None

        authd.start() if create_authd else None
        remoted.start() if create_remoted else None

    yield

    if services.get_service() is not WAZUH_MANAGER:
        authd.shutdown() if create_authd else None
        remoted.shutdown() if create_remoted else None
