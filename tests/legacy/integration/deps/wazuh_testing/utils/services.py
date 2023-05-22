# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import platform
import psutil
import subprocess
import sys

from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.sockets import WAZUH_SOCKETS

from .sockets import delete_sockets


def get_service() -> str:
    """
    Retrieves the name of the Wazuh service running on the current platform.

    Returns:
        str: The name of the Wazuh service. It can be either 'wazuh-manager'
             or 'wazuh-agent'.

    Raises:
        subprocess.CalledProcessError: If an error occurs while executing the
                                       subprocess to obtain the service name.

    """
    if platform.system() in ['Windows', 'win32']:
        return 'wazuh-agent'

    else:  # Linux, sunos5, darwin, aix...
        service = subprocess.check_output([
            WAZUH_CONTROL_PATH, "info", "-t"
        ], stderr=subprocess.PIPE).decode('utf-8').strip()

    return 'wazuh-manager' if service == 'server' else 'wazuh-agent'


def get_version() -> str:
    """
    Retrieves the version of the Wazuh software installed on the current platform.

    Returns:
        str: The version of the Wazuh software.

    Raises:
        FileNotFoundError: If the VERSION file cannot be found on Windows.
        subprocess.CalledProcessError: If an error occurs while executing the
                                       subprocess to obtain the version.
    """

    if platform.system() in ['Windows', 'win32']:
        with open(os.path.join(WAZUH_PATH, 'VERSION'), 'r') as f:
            version = f.read()
            return version[:version.rfind('\n')]

    else:  # Linux, sunos5, darwin, aix...
        return subprocess.check_output([
            WAZUH_CONTROL_PATH, "info", "-v"
        ], stderr=subprocess.PIPE).decode('utf-8').rstrip()


def control_service(action, daemon=None, debug_mode=False):
    """Perform the stop, start and restart operation with Wazuh.

    It takes care of the current OS to interact with the service and the type of installation (agent or manager).

    Args:
        action ({'stop', 'start', 'restart'}): Action to be done with the service/daemon.
        daemon (str, optional): Name of the daemon to be controlled. None for the whole Wazuh service. Default `None`.
        debug_mode (bool, optional) : Run the specified daemon in debug mode. Default `False`.
    Raises:
        ValueError: If `action` is not contained in {'start', 'stop', 'restart'}.
        ValueError: If the result is not equal to 0.
    """
    valid_actions = ('start', 'stop', 'restart')
    if action not in valid_actions:
        raise ValueError(f'action {action} is not one of {valid_actions}')

    if sys.platform == 'win32':
        if action == 'restart':
            control_service('stop')
            control_service('start')
            result = 0
        else:
            error_109_windows_retry = 3
            for _ in range(error_109_windows_retry):
                command = subprocess.run(
                    ["net", action, "WazuhSvc"], stderr=subprocess.PIPE)
                result = command.returncode
                if result != 0:
                    if action == 'stop' and 'The Wazuh service is not started.' in command.stderr.decode():
                        result = 0
                        break
                    if action == 'start' and 'The requested service has already been started.' \
                       in command.stderr.decode():
                        result = 0
                        break
                    elif "System error 109 has occurred" not in command.stderr.decode():
                        break
    else:  # Default Unix
        if daemon is None:
            if sys.platform == 'darwin' or sys.platform == 'sunos5':
                result = subprocess.run(
                    [WAZUH_CONTROL_PATH, action]).returncode
            else:
                result = subprocess.run(
                    ['service', get_service(), action]).returncode
            action == 'stop' and delete_sockets()
        else:
            if action == 'restart':
                control_service('stop', daemon=daemon)
                control_service('start', daemon=daemon)
            elif action == 'stop':
                processes = []

                for proc in psutil.process_iter():
                    try:
                        if daemon in ['wazuh-clusterd', 'wazuh-apid']:
                            for file in os.listdir(f'{WAZUH_PATH}/var/run'):
                                if daemon in file:
                                    pid = file.split("-")
                                    pid = pid[2][0:-4]
                                    if pid == str(proc.pid):
                                        processes.append(proc)
                        elif daemon in proc.name() or daemon in ' '.join(proc.cmdline()):
                            processes.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                try:
                    for proc in processes:
                        proc.terminate()

                    _, alive = psutil.wait_procs(processes, timeout=5)

                    for proc in alive:
                        proc.kill()
                except psutil.NoSuchProcess:
                    pass

                delete_sockets(WAZUH_SOCKETS[daemon])
            else:
                daemon_path = os.path.join(WAZUH_PATH, 'bin')
                start_process = [
                    f'{daemon_path}/{daemon}'] if not debug_mode else [f'{daemon_path}/{daemon}', '-dd']
                subprocess.check_call(start_process)
            result = 0

    if result != 0:
        raise ValueError(
            f"Error when executing {action} in daemon {daemon}. Exit status: {result}")
