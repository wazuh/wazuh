import os
import pytest

from wazuh_testing.utils.file import remove_file, recursive_directory_creation,truncate_file
from wazuh_testing.utils.database import delete_dbs
from wazuh_testing.tools.file_monitor import FileMonitor
from wazuh_testing.tools.queue_monitor import QueueMonitor
from wazuh_testing.tools.manager_handler import create_group, delete_group
from wazuh_testing.utils.services import control_service,check_daemon_status
from wazuh_testing.constants.paths import BACKUPS_PATH
from wazuh_testing.constants.daemons import WAZUH_SERVICES_START,WAZUH_SERVICES_STOP

@pytest.fixture()
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

@pytest.fixture()
def remove_backups(backups_path=BACKUPS_PATH):
    "Creates backups folder in case it does not exist."
    remove_file(backups_path)
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)
    yield
    remove_file(backups_path)
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)

@pytest.fixture(scope='module')
def configure_sockets_environment(request):
    """Configure environment for sockets and MITM"""
    monitored_sockets_params = getattr(request.module, 'monitored_sockets_params')
    log_monitor_paths = getattr(request.module, 'log_monitor_paths')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service(WAZUH_SERVICES_STOP)
    check_daemon_status(running_condition=False)

    monitored_sockets = list()
    mitm_list = list()
    log_monitors = list()

    # Truncate logs and create FileMonitors
    for log in log_monitor_paths:
        truncate_file(log)
        log_monitors.append(FileMonitor(log))

    # Start selected daemons and monitored sockets MITM
    for daemon, mitm, daemon_first in monitored_sockets_params:
        not daemon_first and mitm is not None and mitm.start()
        control_service(WAZUH_SERVICES_START, daemon=daemon, debug_mode=True)
        check_daemon_status(
            running_condition=True,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )
        daemon_first and mitm is not None and mitm.start()
        if mitm is not None:
            monitored_sockets.append(QueueMonitor(queue_item=mitm.queue))
            mitm_list.append(mitm)

    setattr(request.module, 'monitored_sockets', monitored_sockets)
    setattr(request.module, 'log_monitors', log_monitors)

    yield

    # Stop daemons and monitored sockets MITM
    for daemon, mitm, _ in monitored_sockets_params:
        mitm is not None and mitm.shutdown()
        control_service(WAZUH_SERVICES_STOP, daemon=daemon)
        check_daemon_status(
            running_condition=False,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )

    # Delete all db
    delete_dbs()

    control_service(WAZUH_SERVICES_START)


@pytest.fixture()
def configure_sockets_environment_function(request):
    """Configure environment for sockets and MITM"""
    monitored_sockets_params = getattr(request.module, 'monitored_sockets_params')
    log_monitor_paths = getattr(request.module, 'log_monitor_paths')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service(WAZUH_SERVICES_STOP)
    check_daemon_status(running_condition=False)

    monitored_sockets = list()
    mitm_list = list()
    log_monitors = list()

    # Truncate logs and create FileMonitors
    for log in log_monitor_paths:
        truncate_file(log)
        log_monitors.append(FileMonitor(log))

    # Start selected daemons and monitored sockets MITM
    for daemon, mitm, daemon_first in monitored_sockets_params:
        not daemon_first and mitm is not None and mitm.start()
        control_service(WAZUH_SERVICES_START, daemon=daemon, debug_mode=True)
        check_daemon_status(
            running_condition=True,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )
        daemon_first and mitm is not None and mitm.start()
        if mitm is not None:
            monitored_sockets.append(QueueMonitor(queue_item=mitm.queue))
            mitm_list.append(mitm)

    setattr(request.module, 'monitored_sockets', monitored_sockets)
    setattr(request.module, 'log_monitors', log_monitors)

    yield

    # Stop daemons and monitored sockets MITM
    for daemon, mitm, _ in monitored_sockets_params:
        mitm is not None and mitm.shutdown()
        control_service(WAZUH_SERVICES_STOP, daemon=daemon)
        check_daemon_status(
            running_condition=False,
            target_daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else []
        )

    # Delete all db
    delete_dbs()

    control_service(WAZUH_SERVICES_START)
