'''
copyright: Copyright (C) Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: A restart the manager sends to the agent must not leave the agent stopped when its configuration is
       broken. The agent tests the configuration first, as a start does, and refuses the restart when the
       test fails. On Linux the control module runs each daemon's -t before 'systemctl restart'; on Windows
       'service-restart' runs the configuration readers before stopping the service.
components:
    - agentd
    - modulesd
targets:
    - agent
daemons:
    - wazuh-agentd
    - wazuh-modulesd
    - wazuh-manager-remoted
os_platform:
    - linux
    - windows
references:
    - https://github.com/wazuh/wazuh/issues/41420
tags:
    - agent_control
'''
import os
import sys
import time
import uuid
from pathlib import Path

import psutil
import pytest

from wazuh_testing.constants.paths.configurations import WAZUH_CONF_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.tools.simulators.remoted_simulator import DEFAULT_MANAGER_ENDPOINT_PREFIX, RemotedSimulator
from wazuh_testing.utils.configuration import load_configuration_template

from . import CONFIGS_PATH
from utils import _wait_for_pattern_since, log_position, wait_connect

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Configuration: the agent reports to a RemotedSimulator on 127.0.0.1:1517.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
test_metadata = [{}]
test_configuration = load_configuration_template(configs_path, [{}], test_metadata)

daemons_handler_configuration = {'all_daemons': True}
# wait_connect() waits for 'https_client startup accepted', which the agent logs at debug level.
local_internal_options = {AGENTD_WINDOWS_DEBUG if sys.platform == WINDOWS else AGENTD_DEBUG: '2'}

# The process whose PID tells whether the agent restarted. On Windows the service's own: the service-restart
# helper runs from the same wazuh-agent.exe.
AGENT_SERVICE = 'WazuhSvc'
AGENT_PROCESS = 'wazuh-agentd'
# On Linux the configuration test runs before 'systemctl restart' only; without systemd the agent restarts through
# wazuh-control, which tests the configuration itself and logs differently.
LINUX_WITHOUT_SYSTEMD = sys.platform != WINDOWS and not os.path.isdir('/run/systemd/system')
# execd's -t is the first to run on Linux, so a file that is not valid XML fails there.
# The callbacks match from the start of the line (re.match), hence the leading '.*'.
REFUSED_PATTERN = (r'.*Configuration test failed; the agent was not restarted\.' if sys.platform == WINDOWS
                   else r'.*Configuration test failed for wazuh-execd; the agent was not restarted\.')
# With agentd debug on, the line carries the pid and source location: 'wazuh-agentd[N] agentd.c:320 at ...'.
STARTED_PATTERN = r'.*wazuh-agent.*Started \(pid' if sys.platform == WINDOWS else r'.*wazuh-agentd.*Started \(pid'
# The agent picks a queued task up with its next notify; the restart then takes a few seconds.
TASK_TIMEOUT = 180
# The agent records each task id through agent-info before running the task, and drops the task when that module
# is not up yet, so tasks are only queued once it has started.
# With debug on, Windows logs '[pid] file:line at func():' between the tag and the level, as on STARTED_PATTERN.
AGENT_INFO_STARTED_PATTERN = r'.*wazuh-modulesd:agent-info.*INFO: Started'


def restart_task():
    # A fresh id per run: the agent drops a task id it has already seen.
    return {'task_id': f'41420-{uuid.uuid4()}', 'task_type': 'agent_restart', 'payload': {}}


def agent_pid():
    if sys.platform == WINDOWS:
        try:
            return psutil.win_service_get(AGENT_SERVICE).pid()
        except psutil.NoSuchProcess:
            return None
    for proc in psutil.process_iter(['name', 'pid']):
        if proc.info['name'] == AGENT_PROCESS:
            return proc.info['pid']
    return None


def wait_for_new_agent_process(old_pid, timeout=60):
    # The start is logged while the daemon forks, so the old process can still be the one found for a moment.
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = agent_pid()
        if pid not in (None, old_pid):
            return pid
        time.sleep(1)
    return None


def break_configuration():
    with open(WAZUH_CONF_PATH, 'a') as conf:
        conf.write('\n<ossec_config><client>\n')


@pytest.fixture()
def remoted_server():
    since = log_position()
    server = RemotedSimulator(prefix=DEFAULT_MANAGER_ENDPOINT_PREFIX)
    server.start()
    try:
        wait_connect(since=since)
        # From the start of ossec.log, which truncate_monitored_files empties before the daemons start: agent-info
        # may come up before the simulator does.
        assert _wait_for_pattern_since(AGENT_INFO_STARTED_PATTERN, timeout=TASK_TIMEOUT, since=0), \
            'agent-info did not start'
        yield server
    finally:
        server.shutdown()


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata))
def test_restart_with_valid_configuration(test_configuration, test_metadata, set_wazuh_configuration,
                                          configure_local_internal_options, truncate_monitored_files, clean_keys,
                                          add_keys, daemons_handler, remoted_server):
    '''
    description: An agent_restart task with a valid configuration restarts the agent, as before.
    wazuh_min_version: 5.0.0
    tier: 0
    assertions:
        - The agent logs a new start and runs with a new PID.
    '''
    pid_before = agent_pid()
    assert pid_before, 'The agent is not running before the restart'
    since = log_position()

    remoted_server.add_task(restart_task())

    assert _wait_for_pattern_since(STARTED_PATTERN, timeout=TASK_TIMEOUT, since=since), 'The agent did not restart'
    assert wait_for_new_agent_process(pid_before), 'The agent is not running with a new process after the restart'


@pytest.mark.skipif(LINUX_WITHOUT_SYSTEMD, reason='On Linux the configuration test runs before systemctl only')
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata))
def test_restart_with_broken_configuration_is_refused(test_configuration, test_metadata, set_wazuh_configuration,
                                                      configure_local_internal_options, truncate_monitored_files,
                                                      clean_keys, add_keys, daemons_handler, remoted_server):
    '''
    description: An agent_restart task with a broken ossec.conf leaves the agent running, untouched, and logs
                 why. Before the fix the restart stopped every daemon and the start refused the file, leaving
                 the agent stopped.
    wazuh_min_version: 5.0.0
    tier: 0
    assertions:
        - The agent logs that the configuration test failed and the restart was not done.
        - The agent keeps running with the same PID.
    '''
    pid_before = agent_pid()
    assert pid_before, 'The agent is not running before the restart'
    break_configuration()
    since = log_position()

    remoted_server.add_task(restart_task())

    assert _wait_for_pattern_since(REFUSED_PATTERN, timeout=TASK_TIMEOUT, since=since), \
        'The agent did not refuse the restart'
    assert agent_pid() == pid_before, 'The agent was restarted or stopped despite the broken configuration'
