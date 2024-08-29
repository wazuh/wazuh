# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess
from functools import lru_cache
from sys import exit


@lru_cache(maxsize=None)
def find_wazuh_path() -> str:
    """
    Get the Wazuh installation path.

    Returns
    -------
    str
        Path where Wazuh is installed or empty string if there is no framework in the environment.
    """
    abs_path = os.path.abspath(os.path.dirname(__file__))
    allparts = []
    while 1:
        parts = os.path.split(abs_path)
        if parts[0] == abs_path:  # sentinel for absolute paths
            allparts.insert(0, parts[0])
            break
        elif parts[1] == abs_path:  # sentinel for relative paths
            allparts.insert(0, parts[1])
            break
        else:
            abs_path = parts[0]
            allparts.insert(0, parts[1])

    wazuh_path = ''
    try:
        for i in range(0, allparts.index('wodles')):
            wazuh_path = os.path.join(wazuh_path, allparts[i])
    except ValueError:
        pass

    return wazuh_path


def call_wazuh_control(option: str) -> str:
    """
    Execute the wazuh-control script with the parameters specified.

    Parameters
    ----------
    option : str
        The option that will be passed to the script.

    Returns
    -------
    str
        The output of the call to wazuh-control.
    """
    wazuh_control = os.path.join(find_wazuh_path(), "bin", "wazuh-control")
    try:
        proc = subprocess.Popen([wazuh_control, option], stdout=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()
        return stdout.decode()
    except (OSError, ChildProcessError):
        print(f'ERROR: a problem occurred while executing {wazuh_control}')
        exit(1)


def get_wazuh_info(field: str) -> str:
    """
    Execute the wazuh-control script with the 'info' argument, filtering by field if specified.

    Parameters
    ----------
    field : str
        The field of the output that's being requested. Its value can be 'WAZUH_VERSION', 'WAZUH_REVISION' or
        'WAZUH_TYPE'.

    Returns
    -------
    str
        The output of the wazuh-control script.
    """
    wazuh_info = call_wazuh_control("info")
    if not wazuh_info:
        return "ERROR"

    if not field:
        return wazuh_info

    env_variables = wazuh_info.rsplit("\n")
    env_variables.remove("")
    wazuh_env_vars = dict()
    for env_variable in env_variables:
        key, value = env_variable.split("=")
        wazuh_env_vars[key] = value.replace("\"", "")

    return wazuh_env_vars[field]


@lru_cache(maxsize=None)
def get_wazuh_version() -> str:
    """
    Return the version of Wazuh installed.

    Returns
    -------
    str
        The version of Wazuh installed.
    """
    return get_wazuh_info("WAZUH_VERSION")


ANALYSISD = os.path.join(find_wazuh_path(), 'queue', 'sockets', 'queue')
# Max size of the event that ANALYSISID can handle
MAX_EVENT_SIZE = 65535
