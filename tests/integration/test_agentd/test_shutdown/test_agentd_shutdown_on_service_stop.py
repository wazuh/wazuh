'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       These tests verify that, on Windows, stopping the service ('net stop WazuhSvc') makes the
       'wazuh-agent.exe' process terminate promptly instead of lingering after the Service Control
       Manager reports SERVICE_STOPPED. A lingering process keeps open handles under the install
       directory, which delays/breaks MSI file removal (uninstall/upgrade) and slows shutdown for
       real users.

       Two scenarios are exercised, one per affected code path:
         - connected: the agent reached receiver_messages() and is blocked in select(); the stop
           handler must close the socket so the loop unblocks and returns.
         - never-connected: the agent never completed a handshake and is looping in start_agent();
           the stop handler must signal the retry loop so it aborts (this path is NOT covered by
           closing the socket, since there is no live connection).

       A dedicated "send blocked on SO_SNDTIMEO" scenario is intentionally omitted: a blocked
       send() is interrupted by the very same socket close exercised by the 'connected' case, so it
       shares its code path and would only add non-determinism (it requires the manager to stall
       reads until the socket buffer fills).

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd

os_platform:
    - windows

os_version:
    - Windows Server 2022
    - Windows Server 2019
    - Windows 10

tags:
    - shutdown
    - simulator
'''
import sys
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.services import check_if_process_is_running, control_service

from . import CONFIGS_PATH, TEST_CASES_PATH
from utils import wait_connect

# Marks: Windows-only; the prompt-shutdown logic under test is specific to the Windows service.
pytestmark = [pytest.mark.agent, pytest.mark.win32, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_shutdown.yaml')

config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

local_internal_options = {AGENTD_WINDOWS_DEBUG: '2', AGENTD_TIMEOUT: '5'}
daemons_handler_configuration = {'all_daemons': True}

# Name of the agent process as reported by psutil on Windows.
AGENT_PROCESS = 'wazuh-agent.exe'
# Maximum time wazuh-agent.exe may take to exit after 'net stop WazuhSvc' returns.
# The fix exits in ~1 s; the unfixed agent lingers up to SO_SNDTIMEO (30 s) or forever.
SHUTDOWN_GRACE = 10
# Seconds to let the agent settle into its loop (start_agent retry / receiver select) before stopping.
SETTLE_TIME = 5


def _wait_process_exit(process_name, timeout):
    '''Poll until `process_name` is gone, returning the elapsed seconds, or None on timeout.

    control_service('stop') on Windows runs `net stop WazuhSvc`, which returns as soon as the SCM
    reports SERVICE_STOPPED. It does NOT wait for, nor kill, the process; so a lingering agent is
    observable here as the process still running after the stop returned.
    '''
    start = time.time()
    while time.time() - start < timeout:
        if not check_if_process_is_running(process_name):
            return time.time() - start
        time.sleep(0.25)
    return None


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata),
                         ids=test_cases_ids)
def test_agentd_shutdown_on_service_stop(test_configuration, test_metadata, set_wazuh_configuration,
                                         configure_local_internal_options, truncate_monitored_files,
                                         clean_keys, add_keys, daemons_handler):
    '''
    description: Check that 'wazuh-agent.exe' terminates promptly when the Windows service is stopped,
                 both when the agent is connected to the manager and when it has never connected.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - test_configuration:
            type: data
            brief: Configuration loaded from the template.
        - test_metadata:
            type: data
            brief: Case metadata (selects the connected / never-connected scenario).
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - clean_keys:
            type: fixture
            brief: Cleans keys file content.
        - add_keys:
            type: fixture
            brief: Adds a key so the agent connects without enrollment.
        - daemons_handler:
            type: fixture
            brief: Starts the Wazuh agent service before the test and stops it on teardown.

    assertions:
        - Verify the agent process is running before the stop.
        - Verify wazuh-agent.exe exits within SHUTDOWN_GRACE seconds of 'net stop WazuhSvc' returning.

    expected_output:
        - wazuh-agent.exe no longer running shortly after the service stop.

    tags:
        - shutdown
    '''
    if sys.platform != WINDOWS:
        pytest.skip('The prompt-shutdown behaviour under test is Windows-specific.')

    remoted_server = None
    try:
        if test_metadata['connect_to_manager']:
            # Bring the agent to a connected state: blocked in receiver_messages() select().
            remoted_server = RemotedSimulator(protocol='tcp')
            remoted_server.start()
            wait_connect()
        else:
            # No manager: the agent stays looping in start_agent()'s connection retry.
            time.sleep(SETTLE_TIME)

        # Sanity: the agent must be alive right before we stop it.
        assert check_if_process_is_running(AGENT_PROCESS), \
            f'{AGENT_PROCESS} is not running before the service stop.'

        # Stop the service. net stop returns at SERVICE_STOPPED, without waiting for the process.
        control_service('stop')

        latency = _wait_process_exit(AGENT_PROCESS, SHUTDOWN_GRACE)
        assert latency is not None, (
            f'{AGENT_PROCESS} is still running {SHUTDOWN_GRACE}s after the service stopped '
            f'(scenario: connected={test_metadata["connect_to_manager"]}). The agent lingered '
            f'instead of exiting on service stop.')
    finally:
        if remoted_server is not None:
            remoted_server.destroy()
        # Make sure a lingering process (failed case) does not leak into the next test.
        if check_if_process_is_running(AGENT_PROCESS):
            import psutil
            for proc in psutil.process_iter():
                try:
                    if proc.name() == AGENT_PROCESS:
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
