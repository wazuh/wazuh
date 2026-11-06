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
import pytest

from agent_daemons import all_daemons_running, daemon_pids, enrolled_keys  # noqa: F401
from unit_control import control_process_killed, journal_time, systemctl, unit_property, wait_for
from wazuh_testing.constants.daemons import AGENT_DAEMON, AGENT_MODULES_DAEMON, WAZUH_AGENT

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

UNIT = WAZUH_AGENT
START_TIMEOUT_SECONDS = 60
RELOAD_TIMEOUT_SECONDS = 30


@pytest.fixture()
def agent_running(enrolled_keys):
    """Run the agent under systemd with every daemon up, and stop it afterwards."""
    try:
        systemctl('restart', UNIT)
        yield wait_for(all_daemons_running, START_TIMEOUT_SECONDS, 'not every agent daemon started')
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
        return daemon_pids().get(AGENT_MODULES_DAEMON, old_modulesd) != old_modulesd

    wait_for(reloaded_modulesd, RELOAD_TIMEOUT_SECONDS, 'the reload did not start a new wazuh-modulesd')
    reloaded = daemon_pids()
    assert unit_property(UNIT, 'SubState') == 'reload', 'the reload ended before the restart could reach it'

    systemctl('restart', UNIT)

    restarted = wait_for(all_daemons_running, START_TIMEOUT_SECONDS,
                         'not every agent daemon is running after the restart')
    kept = sorted(daemon for daemon, pid in restarted.items() if reloaded.get(daemon) == pid)
    assert not kept, f'daemons the restart left running: {kept}'
    assert int(unit_property(UNIT, 'MainPID')) == restarted[AGENT_DAEMON]
    wait_for(lambda: control_process_killed(UNIT, since), RELOAD_TIMEOUT_SECONDS,
             'systemd ran the restart after the reload instead of merging it: the race was not exercised')
