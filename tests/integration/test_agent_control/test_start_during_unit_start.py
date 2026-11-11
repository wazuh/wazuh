'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'wazuh-control start' run while 'systemctl start wazuh-agent' is still
       starting waits for the unit instead of starting the daemons itself. Between the unit's
       ExecStartPre, which releases the start-script lock, and its ExecStart, which takes it, a start
       run here used to take the lock and bring the daemons up outside the unit: ExecStart found them
       running, systemd refused the PID file of a wazuh-agentd it did not start, and ExecStopPost
       stopped the agent. A drop-in adds a second ExecStartPre that sleeps, which holds that gap open.

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
import subprocess
import time
from pathlib import Path

import pytest

from agent_daemons import all_daemons_running, enrolled_keys  # noqa: F401
from unit_control import systemctl, unit_property, wait_for
from wazuh_testing.constants.daemons import AGENT_DAEMON, WAZUH_AGENT
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

UNIT = WAZUH_AGENT
START_TIMEOUT_SECONDS = 60
GAP_SECONDS = 5
DROPIN = Path('/etc/systemd/system', f'{UNIT}.service.d', 'zz-test-start-gap.conf')


def _in_unit(pid):
    """Tell whether the process runs in the unit's control group."""
    with open(f'/proc/{pid}/cgroup') as cgroup:
        return f'{UNIT}.service' in cgroup.read()


@pytest.fixture()
def unit_with_open_gap(enrolled_keys):
    """Stop the agent and add a drop-in whose ExecStartPre sleeps after the unit's own, so the unit stays
    activating between the lock release and ExecStart. Afterwards remove it and leave the agent running."""
    systemctl('stop', UNIT)
    subprocess.run([WAZUH_CONTROL_PATH, 'stop'], capture_output=True)
    systemctl('reset-failed', UNIT, check=False)
    DROPIN.parent.mkdir(parents=True, exist_ok=True)
    DROPIN.write_text(f'[Service]\nExecStartPre=/bin/sleep {GAP_SECONDS}\n')
    systemctl('daemon-reload')
    try:
        yield
    finally:
        DROPIN.unlink()
        systemctl('daemon-reload')
        systemctl('stop', UNIT, check=False)
        subprocess.run([WAZUH_CONTROL_PATH, 'stop'], capture_output=True)
        systemctl('reset-failed', UNIT, check=False)
        systemctl('start', UNIT)
        wait_for(all_daemons_running, START_TIMEOUT_SECONDS, 'not every agent daemon is back after the test')


def test_start_waits_for_a_unit_that_is_starting(unit_with_open_gap):
    '''
    description:
        A 'wazuh-control start' that runs while the unit is between ExecStartPre and ExecStart must wait for
        the unit's start and leave every daemon inside the unit, with the unit active.

    test_phases:
        - setup:
            - Stop the agent and add an ExecStartPre drop-in that sleeps 5 seconds.
        - test:
            - Run 'systemctl start --no-block wazuh-agent', wait until the unit runs the sleep, and run
              'wazuh-control start'.
        - teardown:
            - Remove the drop-in and start the agent under the unit.

    assertions:
        - 'wazuh-control start' reports that it waits for the unit, and succeeds.
        - The unit ends active, with wazuh-agentd as its main process.
        - Every agent daemon runs once, inside the unit's control group.
    '''
    systemctl('start', '--no-block', UNIT)
    # The unit's own ExecStartPre takes well under a second; the drop-in's sleep follows it.
    wait_for(lambda: unit_property(UNIT, 'ActiveState') == 'activating', START_TIMEOUT_SECONDS,
             'the unit never started activating')
    time.sleep(2)
    assert unit_property(UNIT, 'ActiveState') == 'activating', 'the unit left activating before the script ran'

    result = subprocess.run([WAZUH_CONTROL_PATH, 'start'], capture_output=True, text=True,
                            timeout=START_TIMEOUT_SECONDS + 100)

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    wait_for(lambda: unit_property(UNIT, 'ActiveState') != 'activating', START_TIMEOUT_SECONDS,
             'the unit is still activating')
    assert unit_property(UNIT, 'ActiveState') == 'active', \
        f"the unit ended {unit_property(UNIT, 'ActiveState')} ({unit_property(UNIT, 'Result')})"
    running = wait_for(all_daemons_running, START_TIMEOUT_SECONDS, 'not every agent daemon is running')
    outside = sorted(daemon for daemon, pid in running.items() if not _in_unit(pid))
    assert not outside, f'daemons running outside the unit: {outside}'
    assert int(unit_property(UNIT, 'MainPID')) == running[AGENT_DAEMON]
    assert 'waiting for it to finish' in output, output
