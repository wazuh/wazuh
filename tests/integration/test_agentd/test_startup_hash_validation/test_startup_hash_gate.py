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
    - https://github.com/wazuh/wazuh/issues/36239
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
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
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
    AGENTD_TIMEOUT: '5',
    MODULESD_DEBUG: '1'
}

daemons_handler_configuration = {'all_daemons': True}

AGENT_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'agent')

MODULE_DAEMONS = ('wazuh-modulesd', 'wazuh-syscheckd', 'wazuh-logcollector', 'wazuh-execd')
ALL_DAEMONS = ('wazuh-agentd',) + MODULE_DAEMONS

# Log patterns emitted by the startup gate C code.
GATE_BLOCKING_PATTERN = (
    r".*Startup hash gate is blocking "
    r"'wazuh-(modulesd|syscheckd|logcollector|execd)' "
    r"\((waiting_hash_match|waiting for agentd startup gate status)\)\."
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

        elif scenario == "reload_chain_fails_gate_still_releases":
            # Regression for issue #36239. When the simulator pushes merged.mg,
            # receiver.c calls reloadAgent() to propagate the new config via
            # the modulesd control socket. If that socket isn't reachable, the
            # call exhausts its 30 retries. Before the fix, the gate stayed at
            # waiting_hash_match forever (only an agentd restart recovered).
            # After the fix, the gate is released by receive_msg() once
            # reloadAgent() reports failure (i.e. the reload chain definitively
            # cannot run), so modules can still start without a full restart.
            #
            # We force the failure by stopping wazuh-modulesd between the
            # handshake and the merged.mg push, so its CONTROL_SOCK is gone
            # by the time reloadAgent() runs.
            push_delay = 10

            remoted_server = RemotedSimulator(
                protocol="tcp",
                limits_config=limits_config,
                merged_mg_content=merged_content,
                merged_mg_send_delay=push_delay,
            )
            remoted_server.start()
            wait_connect()

            # Handshake done, merged.mg not yet pushed -> blocked.
            _wait_startup_gate_status(False, "waiting_hash_match")

            # Kill modulesd: queue/sockets/control now disappears, so the
            # reloadAgent() call triggered by the upcoming push will fail.
            control_service('stop', daemon='wazuh-modulesd')

            # The push arrives during the delay. reloadAgent() spends ~30s
            # retrying the now-dead socket, returns false, and the fallback
            # in receive_msg() releases the gate inline. Allow generous slack
            # on top of the retry window.
            _wait_startup_gate_status(True, "hash_match", timeout=push_delay + 90)

            # Sanity: confirm the reload chain actually failed in this run,
            # so we know the test exercised the fix path and not the normal
            # one. Without this assertion a future change that, say, started
            # modulesd back up automatically would silently turn this into a
            # happy-path test.
            reload_fail_monitor = FileMonitor(WAZUH_LOG_PATH)
            reload_fail_monitor.start(
                callback=callbacks.generate_callback(
                    r".*Could not auto-reload agent\..*after 30 attempts\."
                ),
                timeout=30,
            )
            assert reload_fail_monitor.callback_result, (
                "Expected 'Could not auto-reload agent ... after 30 attempts.' "
                "log line was not observed; the test did not exercise the "
                "broken-reload-chain path."
            )

        elif scenario == "no_premature_module_start_during_reload":
            # Regression caught on 2026-05-22: an earlier iteration of the
            # #36239 fix released the gate inline BEFORE reloadAgent() got to
            # dispatch. Module daemons that were already polling the gate
            # (syscheckd, rootcheck, etc.) would unblock immediately, finish
            # their startup, run scans, and then be killed when the reload
            # chain restarted them — duplicated work and partial scans.
            #
            # This scenario reproduces the normal-reload path (push delayed,
            # reload chain succeeds) and asserts that modules do NOT start
            # before the reload chain dispatches. Concretely: the first
            # "wazuh-syscheckd: INFO: Started (pid: ..." log line in the run
            # must come AFTER modulesd's "Executing 'reload' on wazuh-agent"
            # log line.
            push_delay = 10

            remoted_server = RemotedSimulator(
                protocol="tcp",
                limits_config=limits_config,
                merged_mg_content=merged_content,
                merged_mg_send_delay=push_delay,
            )
            remoted_server.start()
            wait_connect()

            # Gate blocked while waiting for the push.
            _wait_startup_gate_status(False, "waiting_hash_match")

            # Wait for the push -> reload chain -> SIGUSR1 -> gate released.
            _wait_startup_gate_status(True, "hash_match", timeout=push_delay + 60)

            # Wait until both events have hit the log: the reload chain
            # dispatching ("Executing 'reload' on wazuh-agent") and the
            # post-reload syscheckd finishing startup. Polling for both
            # avoids a race where we read the log before syscheckd's
            # startup log line is flushed.
            deadline = time.time() + 60
            exec_reload_idx = None
            sys_started_idx = None
            while time.time() < deadline:
                with open(WAZUH_LOG_PATH, 'r') as log_file:
                    log_lines = log_file.readlines()
                exec_reload_idx = next(
                    (i for i, line in enumerate(log_lines)
                     if "Executing 'reload' on wazuh-agent" in line),
                    None,
                )
                sys_started_idx = next(
                    (i for i, line in enumerate(log_lines)
                     if "wazuh-syscheckd: INFO: Started" in line),
                    None,
                )
                if exec_reload_idx is not None and sys_started_idx is not None:
                    break
                time.sleep(1)

            assert exec_reload_idx is not None, (
                "Reload chain log line 'Executing reload on wazuh-agent' not "
                "found within timeout; the test did not exercise the reload "
                "path."
            )
            assert sys_started_idx is not None, (
                "wazuh-syscheckd never logged 'Started' within timeout; the "
                "agent did not come up as expected."
            )

            # If syscheckd's first 'Started' line appears before the reload
            # chain dispatch, modules unblocked during the reloadAgent retry
            # window — the regression we're guarding against.
            assert sys_started_idx > exec_reload_idx, (
                f"REGRESSION: wazuh-syscheckd logged 'Started' (log line "
                f"{sys_started_idx + 1}) BEFORE the reload chain dispatched "
                f"(log line {exec_reload_idx + 1}). Modules started during "
                f"the reloadAgent retry window, indicating the startup hash "
                f"gate was released prematurely."
            )

        elif scenario == "stale_local_merged_mg_no_premature_module_start":
            # Regression observed on 2026-05-26: real-world flow where the
            # bug surfaces is a group reassignment while the agent is
            # stopped. On restart, the local merged.mg still has the OLD
            # group's hash; the manager handshake declares the NEW hash;
            # the gate detects the mismatch and waits; the manager pushes
            # the new merged.mg; the reload chain runs.
            #
            # During the gate-blocking window the agent must hold back
            # EVERY module — not just wazuh-syscheckd's own startup, but
            # also wazuh-rootcheck (which is statically linked into
            # wazuh-syscheckd and historically logged "Started" from
            # rootcheck_init() before the gate was queried). The user's
            # field report showed exactly that:
            #
            #     wazuh-agentd ... receiver.c: INFO: Agent is reloading...
            #     wazuh-agentd ... reload_agent.c: ... attempt 1/30
            #     wazuh-rootcheck: INFO: Started (pid: 32440).   <-- BUG
            #     wazuh-agentd ... reload_agent.c: ... attempt 2/30
            #     ...
            #     wazuh-modulesd ... main.c: INFO: Started (pid: 32465).
            #
            # This scenario reproduces that flow and asserts that, for
            # every agent module ("wazuh-rootcheck", "wazuh-syscheckd",
            # "wazuh-logcollector", "wazuh-execd"), the first
            # "<module>: INFO: Started" log line appears AFTER the reload
            # chain dispatches ("Executing 'reload' on wazuh-agent" log
            # emitted by wm_control).
            push_delay = 15

            # Pre-create a local merged.mg with a DIFFERENT payload (and
            # therefore a different MD5) than what the manager is going to
            # advertise. This mirrors the "agent had group A, was stopped,
            # then reassigned to group B server-side" condition: the local
            # cache is stale relative to the manager's view.
            stale_merged_content = (
                b"!23 stale-agent.conf\n"
                b"<agent_config></agent_config>"
            )
            assert (
                hashlib.md5(stale_merged_content).hexdigest()
                != hashlib.md5(merged_content).hexdigest()
            ), (
                "Test setup error: stale merged.mg content must hash to a "
                "different value than the simulator's merged_sum, otherwise "
                "the gate would release immediately and the scenario would "
                "not exercise the reload chain."
            )
            os.makedirs(os.path.dirname(WAZUH_MERGED_MG_PATH), exist_ok=True)
            with open(WAZUH_MERGED_MG_PATH, 'wb') as f:
                f.write(stale_merged_content)
            if sys.platform != platforms.WINDOWS:
                os.chmod(WAZUH_MERGED_MG_PATH, 0o660)
                try:
                    import grp
                    wazuh_gid = grp.getgrnam('wazuh').gr_gid
                    os.chown(WAZUH_MERGED_MG_PATH, -1, wazuh_gid)
                except (KeyError, PermissionError):
                    pass

            # Simulator advertises the NEW group's hash and pushes the
            # matching merged.mg after a delay (simulating the manager
            # finishing its per-agent recompute).
            remoted_server = RemotedSimulator(
                protocol="tcp",
                limits_config=limits_config,
                merged_mg_content=merged_content,
                merged_mg_send_delay=push_delay,
            )
            remoted_server.start()
            wait_connect()

            # Handshake done, local hash is stale -> blocked.
            _wait_startup_gate_status(False, "waiting_hash_match")

            # Wait for the push -> reload chain -> SIGUSR1 -> gate released.
            _wait_startup_gate_status(True, "hash_match", timeout=push_delay + 60)

            # Poll the log until the reload chain dispatched AND every
            # module daemon has logged "Started" — only then is it
            # meaningful to compare line orders. Polling avoids a race
            # where we read the log before slower modules' "Started"
            # lines are flushed.
            module_started_patterns = {
                "wazuh-rootcheck": "wazuh-rootcheck: INFO: Started",
                "wazuh-syscheckd": "wazuh-syscheckd: INFO: Started",
                "wazuh-logcollector": "wazuh-logcollector: INFO: Started",
                "wazuh-execd": "wazuh-execd: INFO: Started",
            }
            deadline = time.time() + 90
            exec_reload_idx = None
            module_started_indices = {}
            while time.time() < deadline:
                with open(WAZUH_LOG_PATH, 'r') as log_file:
                    log_lines = log_file.readlines()
                exec_reload_idx = next(
                    (i for i, line in enumerate(log_lines)
                     if "Executing 'reload' on wazuh-agent" in line),
                    None,
                )
                module_started_indices = {
                    module: next(
                        (i for i, line in enumerate(log_lines) if needle in line),
                        None,
                    )
                    for module, needle in module_started_patterns.items()
                }
                if exec_reload_idx is not None and all(
                    idx is not None for idx in module_started_indices.values()
                ):
                    break
                time.sleep(1)

            assert exec_reload_idx is not None, (
                "Reload chain log line 'Executing reload on wazuh-agent' not "
                "found within timeout; the test did not exercise the reload "
                "path."
            )

            # Build a single combined failure message rather than asserting
            # one module at a time, so a failing run pinpoints every
            # premature-start in one shot instead of one per re-run.
            premature_starts = []
            missing_starts = []
            for module, idx in module_started_indices.items():
                if idx is None:
                    missing_starts.append(module)
                elif idx < exec_reload_idx:
                    premature_starts.append((module, idx + 1))

            assert not missing_starts, (
                "Module(s) never logged 'Started' within timeout: "
                f"{missing_starts}. The agent did not come up as expected; "
                "the assertions below cannot be made."
            )

            assert not premature_starts, (
                "REGRESSION (issue 36239 follow-up): the following "
                "module(s) logged 'Started' BEFORE the reload chain "
                "dispatched at log line "
                f"{exec_reload_idx + 1} ('Executing reload on "
                "wazuh-agent'):\n  "
                + "\n  ".join(
                    f"{module} at log line {line_num}"
                    for module, line_num in premature_starts
                )
                + "\nThis means at least one agent module bypassed the "
                "startup hash gate during the gate-blocking window. Only "
                "modulesd's control thread is allowed to run before the "
                "gate releases."
            )

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
