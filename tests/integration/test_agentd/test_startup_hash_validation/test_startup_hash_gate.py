'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Validate startup hash gate behavior in wazuh-agentd startup and shared configuration update flows.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-execd
    - wazuh-logcollector
    - wazuh-syscheckd
    - wazuh-modulesd

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/34329
'''

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.services import check_if_process_is_running
from wazuh_testing.utils.sockets import send_request_socket

from . import CONFIGS_PATH, TEST_CASES_PATH
from utils import wait_connect


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]


# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_startup_hash_gate.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

local_internal_options = {
    AGENTD_DEBUG: '2',
    AGENTD_TIMEOUT: '5'
}

daemons_handler_configuration = {'all_daemons': True}

AGENT_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'agent')
SHARED_MERGED_PATH = os.path.join(WAZUH_PATH, 'etc', 'shared', 'merged.mg')

MODULE_DAEMONS = ('wazuh-modulesd', 'wazuh-syscheckd', 'wazuh-logcollector', 'wazuh-execd')

_DEFAULT_LIMITS_CONFIG = {
    'limits': {
        'fim': {
            'file': 0,
            'registry_key': 0,
            'registry_value': 0
        },
        'syscollector': {
            'hotfixes': 0,
            'packages': 0,
            'processes': 0,
            'ports': 0,
            'network_iface': 0,
            'network_protocol': 0,
            'network_address': 0,
            'hardware': 0,
            'os_info': 0,
            'users': 0,
            'groups': 0,
            'services': 0,
            'browser_extensions': 0
        },
        'sca': {
            'checks': 0
        }
    },
    'cluster_name': 'wazuh-cluster',
    'cluster_node': 'wazuh-node-01',
    'agent_groups': ['default']
}


def _build_limits_config(merged_sum=None):
    limits_config = json.loads(json.dumps(_DEFAULT_LIMITS_CONFIG))

    if merged_sum:
        limits_config['merged_sum'] = merged_sum

    return limits_config


def _calculate_md5(content):
    return hashlib.md5(content).hexdigest()


def _write_merged_mg(content):
    os.makedirs(os.path.dirname(SHARED_MERGED_PATH), exist_ok=True)

    with open(SHARED_MERGED_PATH, 'wb') as merged_file:
        merged_file.write(content)


def _build_valid_merged_content():
    agent_conf = (
        '<agent_config>\n'
        '<client>\n'
        '<notify_time>1</notify_time>\n'
        '</client>\n'
        '</agent_config>\n'
    ).encode()

    header = f'!{len(agent_conf)} agent.conf\n'.encode()
    return header + agent_conf


def _get_startup_gate_status():
    response = send_request_socket(query='getstartupgate', socket_path=AGENT_SOCKET_PATH)

    if not response:
        raise RuntimeError('Empty startup gate response received from agentd.')

    decoded = response.decode(errors='ignore')

    if not decoded.startswith('ok '):
        raise RuntimeError(f'Unexpected startup gate response: {decoded}')

    return json.loads(decoded[3:])


def _wait_startup_gate_status(expected_ready, expected_reason, timeout=90):
    status = None
    last_error = None
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            status = _get_startup_gate_status()
            last_error = None
        except Exception as exc:
            last_error = exc
            time.sleep(0.5)
            continue

        if status.get('ready') is expected_ready and status.get('reason') == expected_reason:
            return status

        time.sleep(0.5)

    if last_error:
        raise AssertionError(f'Could not read startup gate status after {timeout}s: {last_error}')

    raise AssertionError(
        f"Unexpected startup gate status after {timeout}s. "
        f"Expected ready={expected_ready}, reason='{expected_reason}'. Last status={status}"
    )


def _wait_keepalive_hash(remoted_server: RemotedSimulator, expected_hash, timeout=90):
    start_time = time.time()

    while time.time() - start_time < timeout:
        last_message = remoted_server.last_message_ctx.get('message', '')

        if expected_hash in last_message and '"merged_sum"' in last_message:
            return

        time.sleep(0.5)

    raise AssertionError(f"Keepalive with merged_sum '{expected_hash}' was not observed within {timeout}s")


def _send_custom_message_and_wait(remoted_server: RemotedSimulator, message, timeout=60):
    remoted_server.send_custom_message(message)

    start_time = time.time()

    while time.time() - start_time < timeout:
        if getattr(remoted_server, 'custom_message_sent', False):
            return

        time.sleep(0.2)

    raise AssertionError('Custom message was not delivered to the agent in time.')


def _send_merged_update(remoted_server: RemotedSimulator, merged_content, merged_hash):
    header = f'#!-up file {merged_hash} merged.mg\n'

    _send_custom_message_and_wait(remoted_server, header)

    for offset in range(0, len(merged_content), 900):
        _send_custom_message_and_wait(remoted_server, merged_content[offset:offset + 900])

    _send_custom_message_and_wait(remoted_server, '#!-close file ')


@pytest.fixture()
def preserve_merged_mg():
    merged_exists = os.path.exists(SHARED_MERGED_PATH)
    original_content = b''

    if merged_exists:
        with open(SHARED_MERGED_PATH, 'rb') as merged_file:
            original_content = merged_file.read()

    yield original_content if merged_exists else None

    if merged_exists:
        _write_merged_mg(original_content)
    elif os.path.exists(SHARED_MERGED_PATH):
        os.remove(SHARED_MERGED_PATH)


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_startup_hash_gate_scenarios(test_configuration, test_metadata, set_wazuh_configuration,
                                     configure_local_internal_options, truncate_monitored_files,
                                     clean_keys, add_keys, daemons_handler, preserve_merged_mg):
    '''
    description: Validate startup hash gate states for legacy, hash match and hash mismatch/update scenarios.

    wazuh_min_version: 4.12.0

    parameters:
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Startup gate scenario and expected behavior.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the ossec.log file and start a new monitor.
        - clean_keys:
            type: fixture
            brief: Cleans keys file content.
        - add_keys:
            type: fixture
            brief: Adds keys to keys file.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Startup gate reaches the expected state for each handshake scenario.
        - Hash mismatch keeps modules blocked until merged.mg update is delivered.
        - Gate unblocks after update and keepalive reports the new merged_sum.
    '''
    scenario = test_metadata['scenario']
    remoted_server = None

    _wait_startup_gate_status(False, 'waiting_handshake')

    limits_config = None
    expected_hash = None
    merged_update_content = None

    if scenario == 'legacy':
        limits_config = None
    elif scenario == 'hash_match':
        local_merged_content = b'startup-hash-validation-hash-match\n'
        _write_merged_mg(local_merged_content)
        expected_hash = _calculate_md5(local_merged_content)
        limits_config = _build_limits_config(expected_hash)
    elif scenario == 'hash_mismatch_update':
        stale_merged_content = b'stale-merged-content-for-mismatch\n'
        _write_merged_mg(stale_merged_content)

        merged_update_content = _build_valid_merged_content()
        expected_hash = _calculate_md5(merged_update_content)
        limits_config = _build_limits_config(expected_hash)
    else:
        raise ValueError(f'Unknown startup gate scenario: {scenario}')

    try:
        remoted_server = RemotedSimulator(protocol='tcp', limits_config=limits_config)
        remoted_server.start()

        wait_connect()

        if scenario == 'legacy':
            _wait_startup_gate_status(True, 'legacy_handshake')
            return

        if scenario == 'hash_match':
            _wait_startup_gate_status(True, 'hash_match')
            return

        _wait_startup_gate_status(False, 'waiting_hash_match')

        for daemon_name in MODULE_DAEMONS:
            assert check_if_process_is_running(daemon_name), f"Daemon '{daemon_name}' is not running while gate is blocked"

        blocking_monitor = FileMonitor(WAZUH_LOG_PATH)
        blocking_monitor.start(
            callback=callbacks.generate_callback(
                r".*Startup hash gate is blocking 'wazuh-(modulesd|syscheckd|logcollector|execd)' \(waiting_hash_match\)\."
            ),
            timeout=60
        )
        assert blocking_monitor.callback_result, 'No startup hash blocking log was observed for hash mismatch scenario.'

        reload_monitor = FileMonitor(WAZUH_LOG_PATH)
        _send_merged_update(remoted_server, merged_update_content, expected_hash)

        reload_monitor.start(
            callback=callbacks.generate_callback(r'.*Agent is reloading due to shared configuration changes\.'),
            timeout=90
        )
        assert reload_monitor.callback_result, 'Agent reload was not triggered after merged.mg update.'

        _wait_startup_gate_status(True, 'hash_match', timeout=90)
        _wait_keepalive_hash(remoted_server, expected_hash, timeout=90)

    finally:
        if remoted_server:
            remoted_server.destroy()
