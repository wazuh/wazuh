# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess
from functools import lru_cache


@lru_cache(maxsize=None)
def find_wazuh_path():
    """
    Gets the path where Wazuh is installed dinamically

    :return: str path where Wazuh is installed or empty string if there is no framework in the environment
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


def call_wazuh_control(option) -> str:
    wazuh_control = os.path.join(find_wazuh_path(), "bin", "wazuh-control")
    try:
        proc = subprocess.Popen([wazuh_control, option], stdout=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()
        return stdout.decode()
    except Exception:
        pass


def get_wazuh_info(field) -> str:
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
    return get_wazuh_info("WAZUH_VERSION")


ANALYSISD = os.path.join(find_wazuh_path(), 'queue', 'sockets', 'queue')
