'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Validate startup hash gate behavior in wazuh-agentd.
       Modules call startup_gate_wait_for_ready() at startup and remain
       blocked until the handshake merged_sum matches the local merged.mg
       hash.

       Architecture note: The agent command socket (queue/sockets/agent) used
       to query gate status is created by the agcom thread, which only starts
       after the handshake completes (start_agent() returns). Therefore, gate
       status can only be queried after the agent connects to the simulator.

       Test cases validate:
       - Modules unblock and start when hashes match.
       - Modules remain blocked when hashes mismatch.
       - Appropriate logging occurs for hash validation events.

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
    - https://github.com/wazuh/wazuh/issues/34509
    - https://github.com/wazuh/wazuh/issues/34329
'''

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from wazuh_testing.constants import platforms
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.configurations import SHARED_CONFIGURATIONS_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks
from wazuh_testing.utils import file as file_utils
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.services import check_if_process_is_running, control_service
from wazuh_testing.utils.sockets import send_request_socket

from . import CONFIGS_PATH, TEST_CASES_PATH
from utils import wait_connect

WAZUH_MERGED_MG_PATH = os.path.join(SHARED_CONFIGURATIONS_PATH, 'merged.mg')


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

MODULE_DAEMONS = ('wazuh-modulesd', 'wazuh-syscheckd', 'wazuh-logcollector', 'wazuh-execd')
ALL_DAEMONS = ('wazuh-agentd',) + MODULE_DAEMONS

# Log patterns emitted by the startup gate C code.
GATE_BLOCKING_PATTERN = (
    r".*Startup hash gate is blocking "
    r"'wazuh-(modulesd|syscheckd|logcollector|execd)' \(waiting_hash_match\)\."
)
GATE_RELEASED_PATTERN = (
    r".*Startup hash gate released for "
    r"'wazuh-(modulesd|syscheckd|logcollector|execd)' \(hash_match\)\."
)

# YAML template paths for merged.mg and handshake JSON.
HANDSHAKE_JSON_PATH = Path(CONFIGS_PATH, "handshake_json.yaml")
MERGED_MG_PATH = Path(CONFIGS_PATH, "merged_mg.yaml")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_merged_mg_from_yaml(yaml_path):
    """Build merged.mg binary content from a YAML template.

    The YAML defines files to merge. Each file becomes a section:
        !<size> <filename>\n<content>

    Returns:
        bytes: The merged.mg file content.
    """
    data = file_utils.read_yaml(yaml_path)
    parts = []
    for entry in data["files"]:
        content = entry["content"].encode()
        header = f"!{len(content)} {entry['name']}\n".encode()
        parts.append(header + content)
    return b"".join(parts)


def _load_limits_config_from_yaml(yaml_path):
    """Load handshake JSON base config from YAML template.

    The returned dict does NOT include merged_sum; the RemotedSimulator
    auto-computes and injects it from the merged_mg_content parameter.

    Returns:
        dict: The base limits_config for RemotedSimulator.
    """
    return file_utils.read_yaml(yaml_path)


def _get_startup_gate_status():
    """Query the agent socket for the current startup gate status.

    Returns:
        dict: ``{"ready": bool, "reason": str}``
    """
    response = send_request_socket(query='getstartupgate', socket_path=AGENT_SOCKET_PATH)

    if not response:
        raise RuntimeError('Empty startup gate response received from agentd.')

    decoded = response.decode(errors='ignore')

    if not decoded.startswith('ok '):
        raise RuntimeError(f'Unexpected startup gate response: {decoded}')

    return json.loads(decoded[3:])


def _wait_startup_gate_status(expected_ready, expected_reason, timeout=90):
    """Poll startup gate status until it matches expectations or times out."""
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


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_startup_hash_gate_scenarios(test_configuration, test_metadata, set_wazuh_configuration,
                                     configure_local_internal_options, truncate_monitored_files,
                                     clean_keys, add_keys, clean_merged_mg, daemons_handler):
    '''
    description: Validate startup hash gate blocking and unblocking for hash match/mismatch scenarios.

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
        - clean_merged_mg:
            type: fixture
            brief: Remove merged.mg so the agent starts with no local file.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Modules unblock and start normally when hashes match.
        - Modules remain blocked when hashes mismatch.
        - Appropriate log messages are emitted for hash validation events.
    '''
    scenario = test_metadata['scenario']
    remoted_server = None

    # Build merged.mg content from YAML template (used by all scenarios).
    merged_content = _build_merged_mg_from_yaml(MERGED_MG_PATH)
    limits_config = _load_limits_config_from_yaml(HANDSHAKE_JSON_PATH)

    try:
        if scenario == "hash_match":
            # Write merged.mg to disk so the hash matches on handshake.
            # clean_merged_mg removed the file; we recreate it from the YAML
            # template with correct permissions so agentd can read it.
            os.makedirs(os.path.dirname(WAZUH_MERGED_MG_PATH), exist_ok=True)
            with open(WAZUH_MERGED_MG_PATH, 'wb') as f:
                f.write(merged_content)
            if sys.platform != platforms.WINDOWS:
                os.chmod(WAZUH_MERGED_MG_PATH, 0o660)
                try:
                    import grp
                    wazuh_gid = grp.getgrnam('wazuh').gr_gid
                    os.chown(WAZUH_MERGED_MG_PATH, -1, wazuh_gid)
                except (KeyError, PermissionError):
                    pass

            # Set merged_sum to match the file on disk; no file push needed.
            limits_config["merged_sum"] = hashlib.md5(merged_content).hexdigest()

            remoted_server = RemotedSimulator(
                protocol="tcp",
                limits_config=limits_config,
            )
            remoted_server.start()
            wait_connect()

            # Gate should transition to ready with hash_match reason.
            _wait_startup_gate_status(True, "hash_match")

            # All module daemons must be running and unblocked.
            for daemon_name in MODULE_DAEMONS:
                assert check_if_process_is_running(daemon_name), (
                    f"Daemon '{daemon_name}' is not running after hash match"
                )

            # Verify the released log message was emitted.
            released_monitor = FileMonitor(WAZUH_LOG_PATH)
            released_monitor.start(
                callback=callbacks.generate_callback(GATE_RELEASED_PATTERN), timeout=60
            )
            assert released_monitor.callback_result, (
                "Expected startup hash gate released log was not observed after hash match."
            )

        elif scenario == "hash_mismatch":
            # Override merged_sum with a bogus value so it never matches.
            limits_config["merged_sum"] = "a" * 32

            # No file push -> gate stays blocked forever.
            remoted_server = RemotedSimulator(
                protocol="tcp", limits_config=limits_config
            )
            remoted_server.start()
            wait_connect()

            # Gate should remain blocked with waiting_hash_match reason.
            _wait_startup_gate_status(False, "waiting_hash_match")

            # Module daemons are running (processes exist) but blocked inside
            # startup_gate_wait_for_ready().
            for daemon_name in MODULE_DAEMONS:
                assert check_if_process_is_running(daemon_name), (
                    f"Daemon '{daemon_name}' is not running while gate is blocked"
                )

            # Verify the blocking log message was emitted.
            blocking_monitor = FileMonitor(WAZUH_LOG_PATH)
            blocking_monitor.start(
                callback=callbacks.generate_callback(GATE_BLOCKING_PATTERN), timeout=60
            )
            assert blocking_monitor.callback_result, (
                "Expected startup hash gate blocking log was not observed for hash mismatch."
            )

        elif scenario == "push_after_delay":
            push_delay = 10

            # Simulator will push merged.mg after delay.
            # merged_sum is auto-computed, but no file on disk yet -> gate blocks until push arrives.
            remoted_server = RemotedSimulator(
                protocol="tcp",
                limits_config=limits_config,
                merged_mg_content=merged_content,
                merged_mg_send_delay=push_delay,
            )
            remoted_server.start()
            wait_connect()

            # Gate blocked during delay.
            _wait_startup_gate_status(False, "waiting_hash_match")

            # Modules running but blocked.
            for daemon_name in MODULE_DAEMONS:
                assert check_if_process_is_running(daemon_name), (
                    f"Daemon '{daemon_name}' is not running while gate is blocked"
                )

            # Blocking log emitted.
            blocking_monitor = FileMonitor(WAZUH_LOG_PATH)
            blocking_monitor.start(
                callback=callbacks.generate_callback(GATE_BLOCKING_PATTERN), timeout=60
            )
            assert blocking_monitor.callback_result, (
                "Expected startup hash gate blocking log was not observed during push delay."
            )

            # Wait for push -> gate opens.
            # The file push triggers an agent reload; after the reload the
            # gate transitions directly to hash_match during re-handshake.
            _wait_startup_gate_status(True, "hash_match", timeout=push_delay + 60)

        else:
            raise ValueError(f"Unknown startup gate scenario: {scenario}")

    finally:
        # Stop each daemon individually via psutil terminate+kill so that
        # stuck processes (e.g. agentd reconnecting to a dead simulator, or
        # modules blocked on the startup gate) are forcefully killed.
        for daemon_name in ALL_DAEMONS:
            try:
                control_service('stop', daemon=daemon_name)
            except Exception:
                pass

        if remoted_server:
            remoted_server.destroy()
