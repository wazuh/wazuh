'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that a manager started with 'wazuh-manager-control start' (outside
       wazuh-manager.service) is brought into the unit by 'systemctl start|restart wazuh-manager' and by
       the Server API's restart and reload: a start inside the unit first stops the daemons running
       outside it. The service-control path units are enabled at install and watch whether the manager
       unit is active or not; their helper ignores a request when no manager daemon runs.

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
    - https://github.com/wazuh/wazuh/issues/41419

tags:
    - manager_control
'''
import os
import re
import subprocess
from pathlib import Path

import psutil
import pytest
import requests

from unit_control import journal_time, systemctl, unit_property, wait_for
from wazuh_testing.constants.daemons import WAZUH_MANAGER
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.services import wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

UNIT = WAZUH_MANAGER
PATH_UNITS = ['wazuh-manager-service-control-restart.path', 'wazuh-manager-service-control-reload.path']
REMOTED = 'wazuh-manager-remoted'
# Daemon PID files only: 'wazuh-manager-apid_auth-<pid>.pid' and the cluster children are helpers.
PIDFILE = re.compile(r'^(wazuh-manager-[a-z]+)-(\d+)\.pid$')
START_TIMEOUT_SECONDS = 180
# The request unit's own budget (TimeoutStartSec of wazuh-manager-service-control@.service).
REQUEST_TIMEOUT_SECONDS = 420
REQUEST_DIR = Path(WAZUH_PATH, 'var', 'service-control')


def _daemon_pids():
    """Map each manager daemon to its live PID, read from 'var/run/<daemon>-<pid>.pid' like
    wazuh-manager-control does. A daemon with no live PID file is left out."""
    pids = {}
    for pidfile in Path(VAR_RUN_PATH).iterdir():
        match = PIDFILE.match(pidfile.name)
        if match and psutil.pid_exists(int(match.group(2))):
            pids[match.group(1)] = int(match.group(2))
    return pids


def _in_unit(pid):
    """Tell whether the process runs in wazuh-manager.service, by the rule wazuh-manager-control applies."""
    try:
        with open(f'/proc/{pid}/cgroup') as cgroup:
            return any(line.rstrip('\n').endswith(f'/{UNIT}.service') for line in cgroup)
    except OSError:
        return False


def _control(action):
    return subprocess.run([WAZUH_CONTROL_PATH, action], capture_output=True, text=True,
                          timeout=START_TIMEOUT_SECONDS)


def _replaced_inside_unit(before, kept=()):
    """Return the current PIDs once every daemon of before runs again inside the unit, with a new PID except
    for those in kept, which keep theirs. None while that is not the case."""
    after = _daemon_pids()
    if after.keys() != before.keys() or not all(_in_unit(pid) for pid in after.values()):
        return None
    if any((after[daemon] == before[daemon]) != (daemon in kept) for daemon in before):
        return None
    return after


def _request_journal(action, since):
    return subprocess.run(['journalctl', '-u', f'wazuh-manager-service-control@{action}', '--since', since,
                           '-o', 'cat', '--no-pager'], capture_output=True, text=True).stdout


def _api_put(endpoint):
    headers, _ = login()
    response = requests.put(f'{get_base_url()}{endpoint}', headers=headers, verify=False, timeout=60)
    assert response.status_code == 200, response.text
    return response


def _restore_unit():
    """Stop the manager however it runs, then run it under systemd again."""
    systemctl('stop', UNIT, check=False)
    _control('stop')
    systemctl('reset-failed', UNIT, check=False)
    systemctl('restart', UNIT)
    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)


@pytest.fixture()
def manager_outside_unit():
    """Stop the unit and start the manager with 'wazuh-manager-control start', outside it. Afterwards run the
    manager under systemd again."""
    systemctl('stop', UNIT)
    systemctl('reset-failed', UNIT, check=False)
    try:
        result = _control('start')
        assert result.returncode == 0, result.stdout + result.stderr
        wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)
        pids = _daemon_pids()
        assert pids and not any(_in_unit(pid) for pid in pids.values()), 'the hand start ran inside the unit'
        yield pids
    finally:
        _restore_unit()


@pytest.fixture()
def manager_stopped():
    """Stop the unit; afterwards run the manager under systemd again."""
    systemctl('stop', UNIT)
    try:
        yield
    finally:
        _restore_unit()


def test_path_units_watch_whatever_the_manager_state(manager_stopped):
    '''
    description:
        The service-control path units are enabled and running after install, while the manager unit is
        not enabled, and keep watching with the manager stopped.

    wazuh_min_version: 5.0.1

    test_phases:
        - setup:
            - Stop the unit.
        - test:
            - Read the path units' and the manager unit's enablement and state.
        - teardown:
            - Run the manager under systemd again.

    assertions:
        - Both path units are enabled and active; the manager unit is not enabled.

    input_description: A package installation.

    expected_output:
        - enabled, active

    tags:
        - manager_control
    '''
    for unit in PATH_UNITS:
        assert systemctl('is-enabled', unit, check=False).stdout.strip() == 'enabled', unit
        assert unit_property(unit, 'ActiveState') == 'active', unit
    assert systemctl('is-enabled', UNIT, check=False).stdout.strip() != 'enabled'


@pytest.mark.parametrize('action', ['start', 'restart'])
def test_systemctl_brings_a_hand_started_manager_into_the_unit(manager_outside_unit, action):
    '''
    description:
        A 'systemctl start' or 'restart' of a manager started with 'wazuh-manager-control start' stops the
        daemons running outside the unit and starts them inside it.

    wazuh_min_version: 5.0.1

    test_phases:
        - setup:
            - Stop the unit and start the manager with 'wazuh-manager-control start'.
        - test:
            - Run 'systemctl <action> wazuh-manager'.
        - teardown:
            - Run the manager under systemd again.

    assertions:
        - The unit is active and every daemon runs inside it with a new PID.

    input_description: A manager running outside its unit.

    expected_output:
        - ActiveState=active

    tags:
        - manager_control
    '''
    before = manager_outside_unit
    systemctl(action, UNIT)

    assert unit_property(UNIT, 'ActiveState') == 'active'
    wait_for(lambda: _replaced_inside_unit(before), START_TIMEOUT_SECONDS,
             f'systemctl {action} did not restart every daemon inside the unit')


def test_systemctl_start_brings_a_dead_daemon_back_inside_the_unit(manager_outside_unit):
    '''
    description:
        With a daemon of a hand-started manager dead, 'systemctl start' starts it and moves the rest into
        the unit.

    wazuh_min_version: 5.0.1

    test_phases:
        - setup:
            - Stop the unit and start the manager with 'wazuh-manager-control start'.
        - test:
            - Kill remoted, then run 'systemctl start wazuh-manager'.
        - teardown:
            - Run the manager under systemd again.

    assertions:
        - Every daemon runs again, inside the unit.

    input_description: A manager running outside its unit, with remoted dead.

    expected_output:
        - ActiveState=active

    tags:
        - manager_control
    '''
    before = manager_outside_unit
    psutil.Process(before[REMOTED]).kill()
    wait_for(lambda: not psutil.pid_exists(before[REMOTED]), START_TIMEOUT_SECONDS, 'remoted did not die')

    systemctl('start', UNIT)

    wait_for(lambda: _replaced_inside_unit(before), START_TIMEOUT_SECONDS,
             'systemctl start did not bring every daemon up inside the unit')


def test_systemctl_stop_right_after_a_hand_start_stops_nothing(manager_outside_unit):
    '''
    description:
        Right after a hand start the unit is inactive, so 'systemctl stop' leaves the daemons running.
        Documented behavior: asserted so that a change to it is noticed.

    wazuh_min_version: 5.0.1

    test_phases:
        - setup:
            - Stop the unit and start the manager with 'wazuh-manager-control start'.
        - test:
            - Run 'systemctl stop wazuh-manager'.
        - teardown:
            - Run the manager under systemd again.

    assertions:
        - The unit is inactive and every daemon still runs with the same PID.

    input_description: A manager running outside its unit.

    expected_output:
        - ActiveState=inactive

    tags:
        - manager_control
    '''
    before = manager_outside_unit
    systemctl('stop', UNIT)

    assert unit_property(UNIT, 'ActiveState') == 'inactive'
    assert _daemon_pids() == before


def test_api_restart_brings_a_hand_started_manager_into_the_unit(manager_outside_unit):
    '''
    description:
        The Server API's restart of a hand-started manager is served: the request unit restarts the
        manager unit, whose start moves every daemon inside it.

    wazuh_min_version: 5.0.1

    test_phases:
        - setup:
            - Stop the unit and start the manager with 'wazuh-manager-control start'.
        - test:
            - PUT /cluster/restart.
        - teardown:
            - Run the manager under systemd again.

    assertions:
        - Every daemon runs inside the unit with a new PID.
        - The request unit ended with result 'success'.

    input_description: A manager running outside its unit.

    expected_output:
        - Result=success

    tags:
        - manager_control
    '''
    before = manager_outside_unit
    _api_put('/cluster/restart')

    wait_for(lambda: _replaced_inside_unit(before), REQUEST_TIMEOUT_SECONDS,
             'the API restart did not restart every daemon inside the unit')
    request_unit = 'wazuh-manager-service-control@restart.service'
    wait_for(lambda: unit_property(request_unit, 'ActiveState') == 'inactive', REQUEST_TIMEOUT_SECONDS,
             'the restart request did not finish')
    assert unit_property(request_unit, 'Result') == 'success'


def test_api_reload_of_a_hand_started_manager_starts_the_unit(manager_outside_unit):
    '''
    description:
        The first Server API reload of a hand-started manager starts the unit: every daemon restarts once
        inside it, remoted included. A second reload, of the now active unit, keeps remoted.

    wazuh_min_version: 5.0.1

    test_phases:
        - setup:
            - Stop the unit and start the manager with 'wazuh-manager-control start'.
        - test:
            - PUT /cluster/reload, twice.
        - teardown:
            - Run the manager under systemd again.

    assertions:
        - After the first reload every daemon runs inside the unit with a new PID, and the helper logged
          that it starts the unit.
        - After the second reload every daemon but remoted has a new PID.

    input_description: A manager running outside its unit.

    expected_output:
        - starting the unit, which restarts every daemon inside it

    tags:
        - manager_control
    '''
    before = manager_outside_unit
    since = journal_time()
    _api_put('/cluster/reload')

    first = wait_for(lambda: _replaced_inside_unit(before), REQUEST_TIMEOUT_SECONDS,
                     'the first API reload did not restart every daemon inside the unit')
    assert 'starting the unit, which restarts every daemon inside it' in _request_journal('reload', since)

    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)
    wait_for(lambda: unit_property('wazuh-manager-service-control@reload.service', 'ActiveState') == 'inactive',
             REQUEST_TIMEOUT_SECONDS, 'the first reload request did not finish')
    _api_put('/cluster/reload')

    wait_for(lambda: _replaced_inside_unit(first, kept=(REMOTED,)), REQUEST_TIMEOUT_SECONDS,
             'the second API reload did not restart every daemon but remoted')


def test_request_for_a_stopped_manager_is_ignored(manager_stopped):
    '''
    description:
        A service-control request left while no manager daemon runs is ignored: the path unit still runs
        the helper, which starts nothing.

    wazuh_min_version: 5.0.1

    test_phases:
        - setup:
            - Stop the unit.
        - test:
            - Create var/service-control/restart as wazuh-manager.
        - teardown:
            - Run the manager under systemd again.

    assertions:
        - The helper logs that the request is ignored.
        - The unit stays inactive and no manager daemon runs.

    input_description: A stopped manager and a restart request.

    expected_output:
        - the manager is not running; restart request ignored

    tags:
        - manager_control
    '''
    assert not _daemon_pids(), 'a manager daemon still runs after systemctl stop'
    since = journal_time()
    subprocess.run(['runuser', '-u', 'wazuh-manager', '--', 'touch', os.path.join(REQUEST_DIR, 'restart')],
                   check=True)

    wait_for(lambda: 'the manager is not running; restart request ignored' in _request_journal('restart', since),
             START_TIMEOUT_SECONDS, 'the helper did not ignore the request')
    assert unit_property(UNIT, 'ActiveState') == 'inactive'
    assert not _daemon_pids()
