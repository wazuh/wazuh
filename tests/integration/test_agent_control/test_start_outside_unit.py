'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'systemctl start' and 'systemctl restart wazuh-agent' bring an agent
       started with 'wazuh-control start' under the unit. Its daemons run outside the unit, and
       systemd refuses the PID file of a wazuh-agentd it did not start, so the start failed and the
       unit's ExecStopPost stopped the agent. A restart a manager sends runs 'systemctl restart' too.

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

import pytest

from agent_daemons import all_daemons_running, enrolled_keys  # noqa: F401
from unit_control import systemctl, unit_property, wait_for
from wazuh_testing.constants.daemons import AGENT_DAEMON, WAZUH_AGENT
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

UNIT = WAZUH_AGENT
START_TIMEOUT_SECONDS = 60


def _in_unit(pid):
    """Tell whether the process runs in the unit's control group."""
    with open(f'/proc/{pid}/cgroup') as cgroup:
        return f'{UNIT}.service' in cgroup.read()


@pytest.fixture()
def agent_outside_unit(enrolled_keys):
    """Run the agent with 'wazuh-control start' while the unit is stopped, and stop it afterwards
    whichever way it ends up running."""
    systemctl('stop', UNIT)
    systemctl('reset-failed', UNIT, check=False)
    try:
        subprocess.run([WAZUH_CONTROL_PATH, 'start'], check=True, capture_output=True)
        yield wait_for(all_daemons_running, START_TIMEOUT_SECONDS, 'not every agent daemon started')
    finally:
        systemctl('stop', UNIT, check=False)
        subprocess.run([WAZUH_CONTROL_PATH, 'stop'], capture_output=True)
        systemctl('reset-failed', UNIT, check=False)


@pytest.mark.parametrize('action', ['start', 'restart'])
def test_systemctl_brings_an_agent_started_outside_the_unit_under_it(agent_outside_unit, action):
    '''
    description:
        A 'systemctl start' or 'restart' of an agent that 'wazuh-control start' started must stop
        those daemons and start every one again inside the unit.

    test_phases:
        - setup:
            - Stop the unit, start the agent with 'wazuh-control start' and wait for every daemon.
        - test:
            - Run 'systemctl start' or 'systemctl restart wazuh-agent'.
        - teardown:
            - Stop the agent and restore client.keys.

    assertions:
        - The systemctl command succeeds and the unit is active.
        - Every agent daemon runs, each with a new PID, inside the unit's control group.
        - systemd tracks the new wazuh-agentd as the unit's main process.

    parameters:
        - action:
            type: str
            brief: The systemctl action: start, or restart, which a manager's restart runs.
    '''
    assert not any(_in_unit(pid) for pid in agent_outside_unit.values()), 'the agent already runs in the unit'

    systemctl(action, UNIT)

    assert unit_property(UNIT, 'ActiveState') == 'active'
    running = wait_for(all_daemons_running, START_TIMEOUT_SECONDS,
                       f'not every agent daemon is running after systemctl {action}')
    kept = sorted(daemon for daemon, pid in running.items() if agent_outside_unit.get(daemon) == pid)
    assert not kept, f'daemons left running outside the unit: {kept}'
    outside = sorted(daemon for daemon, pid in running.items() if not _in_unit(pid))
    assert not outside, f'daemons running outside the unit: {outside}'
    assert int(unit_property(UNIT, 'MainPID')) == running[AGENT_DAEMON]
