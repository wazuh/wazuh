'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'systemctl restart wazuh-manager' restarts every manager daemon when
       it arrives while a 'systemctl reload wazuh-manager' is still running. systemd merges such a
       restart into the running reload job, skips ExecStop and, with KillMode=process and no main
       process to track, only signals the reload script. Regression test for #41047: the start
       that followed found the daemons still up, so the restart was lost, and wazuh-manager-remoted,
       which a reload never restarts, kept running.

components:
    - manager_control

suite: manager_control

targets:
    - manager

daemons:
    - wazuh-manager-analysisd
    - wazuh-manager-apid
    - wazuh-manager-authd
    - wazuh-manager-clusterd
    - wazuh-manager-db
    - wazuh-manager-modulesd
    - wazuh-manager-remoted

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/41047

tags:
    - manager_control
'''
import re
from pathlib import Path

import psutil
import pytest

from unit_control import control_process_killed, journal_time, systemctl, unit_property, wait_for
from wazuh_testing.constants.daemons import REMOTE_DAEMON, WAZUH_MANAGER
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.utils.services import wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

UNIT = WAZUH_MANAGER
# Daemon PID files only: 'wazuh-manager-apid_auth-<pid>.pid' and the cluster children are helpers.
PIDFILE = re.compile(r'^(wazuh-manager-[a-z]+)-(\d+)\.pid$')
START_TIMEOUT_SECONDS = 180
RELOAD_TIMEOUT_SECONDS = 30
# Written by the reload once it holds the start-script lock, right before it stops the daemons.
RESTART_MARKER = Path(VAR_RUN_PATH, '.restart')


def _daemon_pids():
    """Map each manager daemon to its live PID, read from 'var/run/<daemon>-<pid>.pid' like
    wazuh-manager-control does. A daemon with no live PID file is left out."""
    pids = {}
    for pidfile in Path(VAR_RUN_PATH).iterdir():
        match = PIDFILE.match(pidfile.name)
        if match and psutil.pid_exists(int(match.group(2))):
            pids[match.group(1)] = int(match.group(2))
    return pids


def _reload_running():
    return unit_property(UNIT, 'SubState') == 'reload'


@pytest.fixture()
def manager_running():
    """Run the manager under systemd with every daemon up, and bring it back up afterwards,
    whatever state the test left it in."""
    systemctl('restart', UNIT)
    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)
    before = _daemon_pids()
    yield before
    # A start does nothing while the unit is still active with a daemon down (RemainAfterExit=yes).
    if not _daemon_pids().keys() >= before.keys():
        systemctl('restart', UNIT, check=False)
    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)


# 'checks': the restart lands while the reload still runs its configuration and credential checks,
# before it has touched any daemon. 'locked': it lands once the reload holds the start-script lock and
# is stopping or starting daemons, so the stop that follows has to take over a lock its dead owner
# left behind.
@pytest.mark.parametrize('stage', ['checks', 'locked'])
def test_restart_during_reload_restarts_every_daemon(manager_running, stage):
    '''
    description:
        A restart that lands while 'wazuh-manager-control reload' is running must stop and start
        every daemon, wazuh-manager-remoted included, and leave no restart in progress behind,
        whether the reload was still checking the configuration or already restarting daemons.

    test_phases:
        - setup:
            - Restart the manager and wait for every daemon.
        - test:
            - Run 'systemctl reload --no-block wazuh-manager', wait for the stage of the reload the
              case names and, while the unit is reloading, run 'systemctl restart wazuh-manager'.
        - teardown:
            - Restart the manager if a daemon is down, and wait for every daemon to be running again.

    assertions:
        - Every daemon that was running before is running after the restart, each with a new PID.
        - wazuh-manager-control reports no restart in progress ('var/run/.restart' is gone).
        - systemd killed the reload's script, so the restart was merged into the reload rather than run
          after it.
    '''
    before = manager_running
    assert REMOTE_DAEMON in before, f'wazuh-manager-remoted is not running: {sorted(before)}'
    assert not RESTART_MARKER.exists(), 'a restart is reported in progress before the test starts'

    since = journal_time()
    systemctl('reload', '--no-block', UNIT)
    wait_for(_reload_running, RELOAD_TIMEOUT_SECONDS, 'the unit never entered the reload state')
    if stage == 'locked':
        wait_for(RESTART_MARKER.exists, RELOAD_TIMEOUT_SECONDS, 'the reload never took the start-script lock')
    else:
        assert not RESTART_MARKER.exists(), 'the reload took the lock before the restart could reach its checks'
    assert _reload_running(), 'the reload ended before the restart could reach it'

    systemctl('restart', UNIT)

    def all_daemons_back():
        pids = _daemon_pids()
        return pids if pids.keys() >= before.keys() else None

    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)
    after = wait_for(all_daemons_back, START_TIMEOUT_SECONDS, 'not every manager daemon is running after the restart')
    kept = sorted(daemon for daemon in before if after[daemon] == before[daemon])
    assert not kept, f'daemons the restart left running: {kept}'
    assert not RESTART_MARKER.exists(), 'a restart is still reported in progress'
    wait_for(lambda: control_process_killed(UNIT, since), RELOAD_TIMEOUT_SECONDS,
             'systemd ran the restart after the reload instead of merging it: the race was not exercised')
