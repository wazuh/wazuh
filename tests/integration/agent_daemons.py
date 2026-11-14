"""
Copyright (C) Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Which agent daemons run, and an enrolled agent to run them with, for the agent_control suite.
"""
import shutil
from pathlib import Path

import psutil
import pytest

from wazuh_testing.constants.daemons import WAZUH_AGENT_DAEMONS
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.utils.client_keys import add_client_keys_entry


def daemon_pids():
    """Map each agent daemon to its live PID, read from 'var/run/<daemon>-<pid>.pid' like
    wazuh-control does. A daemon with no live PID file is left out."""
    pids = {}
    for daemon in WAZUH_AGENT_DAEMONS:
        for pidfile in Path(VAR_RUN_PATH).glob(f'{daemon}-*.pid'):
            pid = int(pidfile.stem.rsplit('-', 1)[1])
            if psutil.pid_exists(pid):
                pids[daemon] = pid
    return pids


def all_daemons_running():
    """Return daemon_pids() when every agent daemon runs, None otherwise."""
    pids = daemon_pids()
    return pids if len(pids) == len(WAZUH_AGENT_DAEMONS) else None


@pytest.fixture()
def enrolled_keys(tmp_path):
    """Give the agent a client.keys entry, and put the original file back whatever happens.

    With an entry, wazuh-agentd starts as an enrolled agent, whether or not it reaches a manager (the
    Remoted and Authd simulators the suite's conftest starts may answer it), and every daemon starts
    and writes its PID file, which is all the service control under test needs. The copy lives in
    this test's own folder, so a failed run can't overwrite it.
    """
    keys = Path(WAZUH_CLIENT_KEYS_PATH)
    backup = tmp_path / keys.name
    shutil.copy2(keys, backup)
    try:
        add_client_keys_entry('001', 'agent-control-test')
        yield
    finally:
        shutil.copy2(backup, keys)
