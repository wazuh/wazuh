'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'systemctl restart wazuh-agent' restarts every agent daemon when it
       arrives while a 'systemctl reload wazuh-agent' is still running, which is what an agent
       does by itself after a shared configuration change. systemd merges such a restart into the
       running reload job, skips ExecStop and, with KillMode=process, only signals the main process
       (wazuh-agentd) and the reload script. Regression test for #41047: the daemons the reload had
       just started kept running, and wazuh-modulesd lost its socket to the new wazuh-agentd.

components:
    - agentd

suite: agent_control

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-execd
    - wazuh-logcollector
    - wazuh-modulesd
    - wazuh-syscheckd

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/41047

tags:
    - agent_control
'''
import shutil
from pathlib import Path

import psutil
import pytest

from unit_control import control_process_killed, journal_time, systemctl, unit_property, wait_for
from wazuh_testing.constants.daemons import AGENT_DAEMON, AGENT_MODULES_DAEMON, WAZUH_AGENT, WAZUH_AGENT_DAEMONS
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.utils.client_keys import add_client_keys_entry

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

UNIT = WAZUH_AGENT
START_TIMEOUT_SECONDS = 60
RELOAD_TIMEOUT_SECONDS = 30


def _daemon_pids():
    """Map each agent daemon to its live PID, read from 'var/run/<daemon>-<pid>.pid' like
    wazuh-control does. A daemon with no live PID file is left out."""
    pids = {}
    for daemon in WAZUH_AGENT_DAEMONS:
        for pidfile in Path(VAR_RUN_PATH).glob(f'{daemon}-*.pid'):
            pid = int(pidfile.stem.rsplit('-', 1)[1])
            if psutil.pid_exists(pid):
                pids[daemon] = pid
    return pids


def _all_daemons_running():
    pids = _daemon_pids()
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


@pytest.fixture()
def agent_running(enrolled_keys):
    """Run the agent under systemd with every daemon up, and stop it afterwards."""
    try:
        systemctl('restart', UNIT)
        yield wait_for(_all_daemons_running, START_TIMEOUT_SECONDS, 'not every agent daemon started')
    finally:
        systemctl('stop', UNIT, check=False)


def test_restart_during_reload_restarts_every_daemon(agent_running):
    '''
    description:
        A restart that lands while 'wazuh-control reload' holds its lock, after it has restarted
        every daemon but wazuh-agentd, must still stop and start all of them, wazuh-agentd included.

    test_phases:
        - setup:
            - Start the agent with a client.keys entry and wait for every daemon.
        - test:
            - Run 'systemctl reload --no-block wazuh-agent' and wait until the reload has started
              a new wazuh-modulesd.
            - While the unit is still reloading, run 'systemctl restart wazuh-agent'.
        - teardown:
            - Stop the agent and restore client.keys.

    assertions:
        - Every agent daemon is running after the restart.
        - Every daemon's PID changed, including the ones the reload had just started.
        - systemd tracks the new wazuh-agentd as the unit's main process.
        - systemd killed the reload's script, so the restart was merged into the reload rather than run
          after it.
    '''
    old_modulesd = agent_running[AGENT_MODULES_DAEMON]

    since = journal_time()
    systemctl('reload', '--no-block', UNIT)
    wait_for(lambda: unit_property(UNIT, 'SubState') == 'reload', RELOAD_TIMEOUT_SECONDS,
             'the unit never entered the reload state')

    # wazuh-control reload restarts every daemon but wazuh-agentd, wazuh-modulesd last, then keeps
    # its lock for two more seconds. A restart in that window used to leave them all running.
    def reloaded_modulesd():
        return _daemon_pids().get(AGENT_MODULES_DAEMON, old_modulesd) != old_modulesd

    wait_for(reloaded_modulesd, RELOAD_TIMEOUT_SECONDS, 'the reload did not start a new wazuh-modulesd')
    reloaded = _daemon_pids()
    assert unit_property(UNIT, 'SubState') == 'reload', 'the reload ended before the restart could reach it'

    systemctl('restart', UNIT)

    restarted = wait_for(_all_daemons_running, START_TIMEOUT_SECONDS,
                         'not every agent daemon is running after the restart')
    kept = sorted(daemon for daemon, pid in restarted.items() if reloaded.get(daemon) == pid)
    assert not kept, f'daemons the restart left running: {kept}'
    assert int(unit_property(UNIT, 'MainPID')) == restarted[AGENT_DAEMON]
    wait_for(lambda: control_process_killed(UNIT, since), RELOAD_TIMEOUT_SECONDS,
             'systemd ran the restart after the reload instead of merging it: the race was not exercised')
