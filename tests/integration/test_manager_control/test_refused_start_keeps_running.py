'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that a 'systemctl restart wazuh-manager' refused by the configuration check
       leaves alone a manager that runs outside the unit. The unit's ExecStopPost stops the daemons a
       restart merged into a reload leaves behind; it is skipped when the start fails on its own
       (SERVICE_RESULT=exit-code), so a refused start no longer stops daemons it never touched.

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
import shutil
import subprocess
from pathlib import Path

import psutil
import pytest

from unit_control import systemctl, unit_property, wait_for
from wazuh_testing.constants.daemons import WAZUH_MANAGER
from wazuh_testing.constants.paths import MANAGER_CONF_DIR
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.utils.services import wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

UNIT = WAZUH_MANAGER
# Daemon PID files only: 'wazuh-manager-apid_auth-<pid>.pid' and the cluster children are helpers.
PIDFILE = re.compile(r'^(wazuh-manager-[a-z]+)-(\d+)\.pid$')
START_TIMEOUT_SECONDS = 180
CONF = Path(MANAGER_CONF_DIR, 'wazuh-manager.conf')
CONF_BACKUP = Path(MANAGER_CONF_DIR, 'wazuh-manager.conf.test-refused-start')
# A value the configuration check refuses: the listener port is not a number.
GOOD_PORT, BAD_PORT = '<port>1517</port>', '<port>not-a-port</port>'


def _daemon_pids():
    """Map each manager daemon to its live PID, read from 'var/run/<daemon>-<pid>.pid' like
    wazuh-manager-control does. A daemon with no live PID file is left out."""
    pids = {}
    for pidfile in Path(VAR_RUN_PATH).iterdir():
        match = PIDFILE.match(pidfile.name)
        if match and psutil.pid_exists(int(match.group(2))):
            pids[match.group(1)] = int(match.group(2))
    return pids


def _control(action):
    return subprocess.run([WAZUH_CONTROL_PATH, action], capture_output=True, text=True,
                          timeout=START_TIMEOUT_SECONDS)


@pytest.fixture()
def manager_outside_unit():
    """Stop the unit and start the manager with 'wazuh-manager-control start', outside it. Afterwards put the
    configuration back and run the manager under systemd again."""
    systemctl('stop', UNIT)
    result = _control('start')
    assert result.returncode == 0, result.stdout + result.stderr
    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)
    shutil.copy2(CONF, CONF_BACKUP)
    yield _daemon_pids()
    shutil.copy2(CONF_BACKUP, CONF)
    CONF_BACKUP.unlink()
    _control('stop')
    systemctl('reset-failed', UNIT, check=False)
    systemctl('restart', UNIT)
    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)


def test_refused_restart_keeps_a_manager_running_outside_the_unit(manager_outside_unit):
    '''
    description:
        A 'systemctl restart wazuh-manager' whose configuration check fails must leave a manager started
        with 'wazuh-manager-control start' running: its ExecStart fails with exit-code and the unit's
        ExecStopPost skips the stop for that result.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup:
            - Stop the unit and start the manager with 'wazuh-manager-control start'.
        - test:
            - Make the listener port in wazuh-manager.conf not a number and run
              'systemctl restart wazuh-manager'.
        - teardown:
            - Put the configuration back, stop the manager and restart it under systemd.

    assertions:
        - The restart fails and the unit ends failed with result 'exit-code'.
        - Every daemon that was running before is still running, with the same PID.

    input_description: A manager running outside its unit and a configuration the check refuses.

    expected_output:
        - Result=exit-code

    tags:
        - manager_control
    '''
    before = manager_outside_unit
    assert before, 'no manager daemon is running before the restart'
    text = CONF.read_text()
    assert text.count(GOOD_PORT) == 1, f"'{GOOD_PORT}' is not in {CONF} exactly once"
    CONF.write_text(text.replace(GOOD_PORT, BAD_PORT))

    result = systemctl('restart', UNIT, check=False)

    assert result.returncode != 0, 'systemctl restart accepted a configuration the check refuses'
    wait_for(lambda: unit_property(UNIT, 'ActiveState') == 'failed', START_TIMEOUT_SECONDS,
             'the unit did not end failed after the refused start')
    assert unit_property(UNIT, 'Result') == 'exit-code', unit_property(UNIT, 'Result')
    after = _daemon_pids()
    changed = sorted(daemon for daemon in before if after.get(daemon) != before[daemon])
    assert not changed, f'daemons the refused restart stopped or replaced: {changed}'
