'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       These tests will check if the content of the 'wazuh-agentd' daemon statistics file is valid.
       The statistics files are documents that show real-time information about the Wazuh environment.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-manager-remoted

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-agentd-state.html

tags:
    - stats_file
'''

import pytest
from pathlib import Path
import sys
import time

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.logger import logger
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.agentd.utils import parse_state_file
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH
from utils import wait_state_update

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'wazuh_state_config_tests.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

# Cases with a "remote" output block check agentd's state as seen from the manager's side.
# The legacy synchronous '#!-req ... agent getstate' request/response has no equivalent
# under the HTTPS client (wazuh/wazuh#37831); this now reads the same state document off the
# periodic /stats push instead (see wait_for_custom_message_response() below).
test_cases_params = [
    pytest.param(config, metadata)
    for config, metadata in zip(test_configuration, test_metadata)
]

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}

daemons_handler_configuration = {'all_daemons': True}


def start_remoted_server(test_metadata) -> None:
    """"Start RemotedSimulator if test case need it"""
    if 'remoted' in test_metadata and test_metadata['remoted']:
        remoted_server = RemotedSimulator()
        remoted_server.start()
    else:
        remoted_server = None
    return remoted_server


@pytest.mark.parametrize('test_configuration, test_metadata', test_cases_params, ids=test_cases_ids)
def test_agentd_state(test_configuration, test_metadata, set_wazuh_configuration, remove_state_file, configure_local_internal_options,
                      truncate_monitored_files, clean_keys, add_keys, daemons_handler):
    '''
    description: Check that the statistics file 'wazuh-agentd.state' is created automatically
                 and verify that the content of its fields is correct.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - remove_state_file:
            type: fixture
            brief: Removes the wazuh-agentd.state file
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - clean_keys:
            type: fixture
            brief: Cleans keys file content
        - add_keys:
            type: fixture
            brief: Adds keys to keys file
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that the 'wazuh-agentd.state' statistics file has been created.
        - Verify that the information stored in the 'wazuh-agentd.state' statistics file
          is consistent with the connection status to the 'wazuh-manager-remoted' daemon.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases that are contained in an external YAML file (wazuh_state_tests.yaml)
                       that includes the parameters and their expected responses.

    expected_output:
        - r'pending'
        - r'connected'
    '''

    # Start RemotedSimulator if test case need it
    remoted_server = start_remoted_server(test_metadata)

    try:
        # Check fields for every expected output type
        for expected_output in test_metadata['output']:
            check_fields(expected_output, remoted_server)

    finally:
        # Shutdown simulator
        if remoted_server:
            remoted_server.destroy()

def wait_for_custom_message_response(expected_status: str, remoted_server: RemotedSimulator, timeout: int = 120):
    """Get the agent's live state via the periodic /stats push.

    There is no manager-initiated, on-demand state query under the HTTPS client (the legacy
    '#!-req ... agent getstate' request/response was a synchronous, persistent-connection
    mechanism with no equivalent here) -- but the same data (w_agentd_state_get(), agcom.c's
    "getallstats") rides the periodic /stats push (wazuh/wazuh#37843) under modules.agent, so
    this waits for a fresh push instead of sending a request.

    Since wazuh/wazuh@72ace94e97 "modules" is an object keyed by module name (e.g.
    {"modules": {"agent": {...}, "logcollector": {...}}}), not an array of {"module":,
    "stats":} entries, counters nested as messages.count/tasks.*.total, and last_ack is gone
    entirely -- confirmed against a fresh local build after that commit landed (git show
    72ace94e97 -- src/client-agent/src/agent_report.c), and against the raw request bodies
    RemotedSimulator actually received locally. UPDATE_ACK (state.c) has had no caller
    anywhere in client-agent since the HTTPS migration, so the field is dead in the product
    itself, not just missing from this one push -- see the "file" case in
    wazuh_state_config_tests.yaml, which does not check it either for the same reason.

    Args:
        parameters:
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator (kept for signature
                compatibility with the 'file' path; the value itself is read from /stats).
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance
        - timeout:
            type: int
            brief: Timeout to wait for a fresh /stats push carrying modules.agent
    Returns:
        dict with state info (legacy flat field names, 'last_ack' always None -- kept only so
        callers can index it without a KeyError), or None if no fresh push with a
        modules.agent entry arrived in time
    """
    # A push already received before this call (e.g. from an earlier field check in the same
    # test) may predate whatever just happened on the remote path (no precondition runs
    # there, see check_fields() below) -- only a push that lands from here on is guaranteed
    # to reflect it.
    remoted_server.last_stats = None
    deadline = time.time() + timeout

    while time.time() < deadline:
        stats = remoted_server.last_stats
        if isinstance(stats, dict):
            modules = stats.get('modules')
            if isinstance(modules, dict):
                agent_stats = modules.get('agent')
                if isinstance(agent_stats, dict):
                    messages = agent_stats.get('messages')
                    if isinstance(messages, dict):
                        return {
                            'status': agent_stats.get('status'),
                            'last_keepalive': agent_stats.get('last_keepalive'),
                            'msg_count': messages.get('count'),
                            # Dead field in the product (no caller of UPDATE_ACK left in
                            # client-agent) -- present so check_last_ack() can index it, but a
                            # remote check for it always misses.
                            'last_ack': None,
                        }
                    logger.warning(f"wait_for_custom_message_response: modules.agent.messages "
                                    f"was not a dict: {messages!r}")
                elif agent_stats is not None:
                    logger.warning(f"wait_for_custom_message_response: modules.agent was not "
                                    f"a dict: {agent_stats!r}")
            elif modules is not None:
                logger.warning(f"wait_for_custom_message_response: 'modules' was not a dict: "
                                f"{modules!r}")
        elif stats is not None:
            logger.warning(f"wait_for_custom_message_response: last_stats was not a dict: {stats!r}")
        time.sleep(1)

    return None


def check_fields(expected_output, remoted_server):
    """Check every field agains expected data

    Args:
        - expected_output:
            type: dict
            brief: expected output block
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance
    """
    # wait_keepalive()/wait_ack() watch for legacy log lines ("Sending keep alive",
    # "Received message: '#!-agent ack") that have no caller left anywhere in
    # client-agent/src (dead since the HTTPS migration, wazuh/wazuh#37831) -- both
    # preconditions are replaced with wait_state_update(), which is still live
    # (state.c's periodic refresh loop) and serves the same "a fresh round of state
    # has happened" purpose regardless of transport.
    checks = {
        'last_ack': {'handler': check_last_ack, 'precondition': [wait_state_update]},
        'last_keepalive': {'handler': check_last_keepalive, 'precondition': [wait_state_update]},
        'msg_count': {'handler': check_msg_count, 'precondition': [wait_state_update]},
        'status': {'handler': check_status, 'precondition': []}
    }

    if expected_output['type'] == 'file':
        get_state_callback = parse_state_file
    else:
        get_state_callback = wait_for_custom_message_response

    for field, expected_value in expected_output['fields'].items():
        # Check if expected value is valiable and mandatory
        if expected_value != '':
            # wait_state_update() ties to state.c's file-writing loop, which some cases
            # (e.g. "Only_remote_request_available") disable outright via
            # agent.state_interval=0 to force the remote-only path -- it would never fire
            # there. The remote path's own handler (wait_for_custom_message_response())
            # already synchronizes on a fresh /stats push, so it needs no separate wait here.
            if get_state_callback == parse_state_file:
                for precondition in checks[field].get('precondition'):
                    precondition()
            assert checks[field].get('handler')(expected_value, get_state_callback, expected_output['fields']['status'], remoted_server)


def check_last_ack(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `last_ack` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise asserts the test
    """
    if get_state_callback == parse_state_file:
        wait_state_update()
        current_value = get_state_callback()['last_ack']
    else:
        # No further wait on a miss: some remote-only cases disable the file-writing loop
        # wait_state_update() ties to (agent.state_interval=0), and the callback above
        # already synchronizes on a fresh /stats push on its own.
        current_value = get_state_callback(expected_status, remoted_server)
        if current_value:
            current_value = current_value['last_ack']
    if expected_value == '':
        return expected_value == current_value

    return current_value is not None


def check_last_keepalive(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `last_keepalive` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise the test asserts
    """
    if get_state_callback == parse_state_file:
        wait_state_update()
        current_value = get_state_callback()['last_keepalive']
    else:
        # No further wait on a miss: some remote-only cases disable the file-writing loop
        # wait_state_update() ties to (agent.state_interval=0), and the callback above
        # already synchronizes on a fresh /stats push on its own.
        current_value = get_state_callback(expected_status, remoted_server)
        if current_value:
            current_value = current_value['last_keepalive']
    if expected_value == '':
        return expected_value == current_value

    return current_value is not None


def check_msg_count(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `msg_count` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise the test asserts
    """
    if get_state_callback == parse_state_file:
        wait_state_update()
        current_value = get_state_callback()['msg_count']
    else:
        current_value = get_state_callback(expected_status, remoted_server)
        if current_value:
            current_value = current_value['msg_count']
    if expected_value == '':
        return expected_value == current_value

    # wait_agent_notification() used to cross-validate msg_count against a legacy "Sending
    # agent notification" log line -- dead since the HTTPS migration (msg_count now
    # increments per forwarded /stateless event, EventForward()/event-forward.c, with no
    # comparable per-increment log). Just confirm a value was actually retrieved.
    return current_value is not None


def check_status(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `status` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise the test asserts
    """
    current_value = None

    if expected_value != 'pending':
        if get_state_callback == parse_state_file:
            # Poll across state-file refresh cycles (agent.state_interval, 5s by default)
            # until status catches up, instead of assuming 2 fixed cycles are always enough --
            # this check can run right after start_remoted_server(), before the agent has
            # necessarily finished enrollment/connecting, and a fixed ~10s budget was observed
            # to flake under CI load (status still "pending" when read).
            wait_state_update()
            current_value = get_state_callback()['status']
            deadline = time.time() + 60
            while current_value != expected_value and time.time() < deadline:
                wait_state_update()
                current_value = get_state_callback()['status']
        else:
            # No wait_state_update() here: some remote-only cases disable the file-writing
            # loop entirely (agent.state_interval=0) that log ties to. The callback below
            # already synchronizes on a fresh /stats push on its own.
            current_value = get_state_callback(expected_status, remoted_server)
            if current_value:
                current_value = current_value['status']
            else:
                # No /stats push with the "agent" module arrived within the timeout --
                # unlike the other fields, status is the one thing this test exists to
                # confirm, so a miss here is a real failure, not a silent pass.
                return False
    else:
        # Sleep while file is updated
        time.sleep(5)
        wait_state_update()
        current_value = get_state_callback()['status']

    return expected_value == current_value
