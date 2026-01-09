'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Test that the Wazuh agent service can be stopped during syscollector scan
       without service control errors (deadlock detection).

components:
    - syscollector

suite: service_reliability

targets:
    - agent

daemons:
    - wazuh-agentd

os_platform:
    - windows

os_version:
    - Windows Server 2016
    - Windows Server 2019
    - Windows 10
    - Windows 11
'''
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.agentd.patterns import AGENTD_CONNECTED_TO_SERVER
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.modulesd.syscollector.patterns import CB_SCAN_STARTED, CB_SYNC_STARTED
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.utils.file import truncate_file
from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


pytestmark = [pytest.mark.agent, pytest.mark.win32, pytest.mark.tier(level=1)]

if sys.platform != WINDOWS:
    pytest.skip("Windows-specific test", allow_module_level=True)

# Enable debug logging for agent, modules (syscollector), and dbsync
local_internal_options = {
    AGENTD_WINDOWS_DEBUG: '2',
    MODULESD_DEBUG: '2',
    'dbsync.debug': '2',
}

tcp_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_tcp.yaml')
udp_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_udp.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_multiple_resets.yaml')

_, test_metadata, test_ids = configuration.get_test_cases_data(test_cases_path)

MAX_STOP_TIME = 30  # Seconds - stops taking longer indicate a problem
STOP_COMMAND_TIMEOUT = 60  # Timeout for the net stop command itself
CONNECTION_TIMEOUT = 60  # Timeout waiting for agent to connect
SCAN_TIMEOUT = 120  # Timeout waiting for syscollector scan to start


def load_yaml_template(path):
    with open(path) as f:
        return yaml.safe_load(f)


def apply_protocol_config(protocol):
    """Apply TCP or UDP configuration."""
    config_path = tcp_config_path if protocol == 'tcp' else udp_config_path
    template = load_yaml_template(config_path)
    sections = template[0].get('sections', [])
    current_conf = configuration.get_wazuh_conf()
    new_conf = configuration.set_section_wazuh_conf(sections, current_conf)
    configuration.write_wazuh_conf(new_conf)


def stop_service():
    """Stop the Wazuh service and return (success, duration, error_code, output)."""
    start_time = time.time()
    try:
        result = subprocess.run(
            ['net', 'stop', 'WazuhSvc'],
            capture_output=True,
            text=True,
            timeout=STOP_COMMAND_TIMEOUT
        )
        duration = time.time() - start_time
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        return False, duration, 'TIMEOUT', f'Command timed out after {STOP_COMMAND_TIMEOUT}s'

    error_code = None
    success = True

    # Check for error codes in output
    output_lower = output.lower()
    if '2186' in output or 'not responding' in output_lower:
        error_code = 2186
        success = False
    elif '109' in output:
        error_code = 109
        success = False
    elif result.returncode != 0:
        error_code = result.returncode
        success = False

    # Also fail if stop took too long (indicates deadlock)
    if duration > MAX_STOP_TIME:
        if error_code is None:
            error_code = f'SLOW({duration:.1f}s)'
        success = False

    return success, duration, error_code, output


def start_service():
    """Start the Wazuh service."""
    result = subprocess.run(['net', 'start', 'WazuhSvc'], capture_output=True, text=True, timeout=120)
    return result.returncode == 0


def ensure_stopped():
    """Ensure service is stopped."""
    subprocess.run(['net', 'stop', 'WazuhSvc'], capture_output=True, timeout=120)
    time.sleep(1)


def wait_for_agent_connection(timeout=CONNECTION_TIMEOUT):
    """Wait for agent to connect to manager using log monitoring.

    Returns:
        bool: True if connected, False if timeout.
    """
    try:
        wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
        wazuh_log_monitor.start(
            callback=callbacks.generate_callback(AGENTD_CONNECTED_TO_SERVER),
            timeout=timeout,
            only_new_events=True
        )
        return wazuh_log_monitor.callback_result is not None
    except Exception as e:
        print(f"[WARN] Error waiting for connection: {e}")
        return False


def wait_for_syscollector_scan(timeout=SCAN_TIMEOUT):
    """Wait for syscollector scan to start using log monitoring.

    Returns:
        bool: True if scan started, False if timeout.
    """
    try:
        wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
        wazuh_log_monitor.start(
            callback=callbacks.generate_callback(CB_SCAN_STARTED),
            timeout=timeout,
            only_new_events=True
        )
        return wazuh_log_monitor.callback_result is not None
    except Exception as e:
        print(f"[WARN] Error waiting for scan: {e}")
        return False


def wait_for_sync_started(timeout=30):
    """Wait for syscollector sync to start using log monitoring.

    Returns:
        bool: True if sync started, False if timeout.
    """
    try:
        wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
        wazuh_log_monitor.start(
            callback=callbacks.generate_callback(CB_SYNC_STARTED),
            timeout=timeout,
            only_new_events=True
        )
        return wazuh_log_monitor.callback_result is not None
    except Exception as e:
        print(f"[WARN] Error waiting for sync: {e}")
        return False


def check_for_db_init_error():
    """Check if there's a DB initialization error in recent logs.

    Returns:
        bool: True if DB error found (should skip this cycle), False otherwise.
    """
    db_error_patterns = [
        'Error deleting old db file',
        'Unable to initialize database',
        'wdb_open',
    ]
    try:
        with open(WAZUH_LOG_PATH, 'r', encoding='utf-8', errors='replace') as f:
            # Read last 100 lines
            lines = f.readlines()[-100:]
            for line in lines:
                for pattern in db_error_patterns:
                    if pattern.lower() in line.lower():
                        return True
    except Exception:
        pass
    return False


@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_ids)
def test_multiple_resets(test_metadata, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Test service reliability by stopping the agent during active syscollector scan.
                 The test waits for the agent to connect and syscollector to start scanning,
                 then immediately stops the service to detect potential deadlocks.

    wazuh_min_version: 4.14.2

    tier: 1

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata with n_restarts and delay values.
        - configure_local_internal_options:
            type: fixture
            brief: Configure debug options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate log files.

    assertions:
        - Agent connects to manager (RemotedSimulator).
        - Syscollector scan starts.
        - Service stops without errors (no deadlock).

    expected_output:
        - All restart cycles complete successfully with fast stop times.
    '''
    n_restarts = test_metadata.get('n_restarts', 20)
    delay = test_metadata.get('delay', 1)

    stop_times = []
    failures = []
    connection_count = 0
    scan_count = 0
    sync_count = 0
    db_error_skips = 0

    print(f"\n{'='*60}")
    print(f"[TEST START] Syscollector Deadlock Detection")
    print(f"{'='*60}")
    print(f"  Parameters:")
    print(f"    - Restarts: {n_restarts}")
    print(f"    - Delay after scan detected: {delay}s")
    print(f"    - Max stop time: {MAX_STOP_TIME}s")
    print(f"    - Connection timeout: {CONNECTION_TIMEOUT}s")
    print(f"    - Scan timeout: {SCAN_TIMEOUT}s")
    print(f"{'='*60}")

    # Start RemotedSimulator to accept agent connections
    print(f"[INIT] Starting RemotedSimulator on 127.0.0.1:1514...")
    remoted_server = RemotedSimulator(server_ip='127.0.0.1', port=1514, protocol='tcp')
    remoted_server.start()
    print(f"[INIT] RemotedSimulator started (TCP mode)")

    try:
        ensure_stopped()
        print(f"[INIT] Service stopped, starting test cycles...")

        test_start_time = time.time()

        for i in range(1, n_restarts + 1):
            cycle_start = time.time()

            # Truncate log file for clean monitoring
            truncate_file(WAZUH_LOG_PATH)

            # Apply TCP config and start service
            apply_protocol_config('tcp')
            if not start_service():
                print(f"[{i}/{n_restarts}] WARNING - Failed to start service, skipping cycle")
                continue

            # ASSERT 1: Wait for agent to connect to manager
            print(f"[{i}/{n_restarts}] Waiting for agent connection...")
            connected = wait_for_agent_connection(timeout=CONNECTION_TIMEOUT)
            if connected:
                connection_count += 1
                print(f"[{i}/{n_restarts}] CONNECTED to manager")
            else:
                print(f"[{i}/{n_restarts}] WARNING - Agent did not connect within {CONNECTION_TIMEOUT}s")
                # Still continue to try the stop

            # Check for DB init errors (skip this cycle if present)
            if check_for_db_init_error():
                db_error_skips += 1
                print(f"[{i}/{n_restarts}] DB init error detected, stopping and skipping cycle")
                stop_service()
                continue

            # ASSERT 2: Wait for syscollector scan to start
            print(f"[{i}/{n_restarts}] Waiting for syscollector scan to start...")
            scan_started = wait_for_syscollector_scan(timeout=SCAN_TIMEOUT)
            if scan_started:
                scan_count += 1
                print(f"[{i}/{n_restarts}] SCAN STARTED")
            else:
                print(f"[{i}/{n_restarts}] WARNING - Scan not detected within {SCAN_TIMEOUT}s")
                # Still continue to try the stop

            # Optional: Check if sync started (indicates rsync activity)
            sync_started = wait_for_sync_started(timeout=10)
            if sync_started:
                sync_count += 1
                print(f"[{i}/{n_restarts}] SYNC STARTED")

            # Wait the configured delay after scan is detected
            if delay > 0:
                time.sleep(delay)

            # NOW STOP - this is where deadlock would occur
            print(f"[{i}/{n_restarts}] Stopping service during scan...")
            success, duration, error_code, output = stop_service()
            stop_times.append(duration)
            cycle_time = time.time() - cycle_start

            if not success:
                failures.append({
                    'cycle': i,
                    'error': error_code,
                    'duration': duration,
                    'output': output,
                    'connected': connected,
                    'scan_started': scan_started,
                })
                print(f"[{i}/{n_restarts}] FAILED - Error: {error_code}, Stop time: {duration:.2f}s")
                print(f"[FAIL FAST] First failure detected at cycle {i}, stopping test early.")
                break
            else:
                print(f"[{i}/{n_restarts}] OK - Stop time: {duration:.2f}s, Cycle time: {cycle_time:.2f}s")

        # Report statistics
        cycles_completed = len(stop_times)
        print(f"\n{'='*60}")
        print(f"[TEST RESULTS]")
        print(f"{'='*60}")

        total_test_time = time.time() - test_start_time
        print(f"  Total test duration: {total_test_time:.2f}s")
        print(f"  Cycles completed: {cycles_completed}/{n_restarts}" + (" (stopped early)" if failures else ""))
        print(f"  DB error skips: {db_error_skips}")

        print(f"\n  Connection/Scan Statistics:")
        print(f"    - Agent connected: {connection_count}/{cycles_completed}")
        print(f"    - Scan detected: {scan_count}/{cycles_completed}")
        print(f"    - Sync detected: {sync_count}/{cycles_completed}")

        if stop_times:
            avg_time = sum(stop_times) / len(stop_times)
            min_time = min(stop_times)
            max_time = max(stop_times)
            print(f"\n  Stop Time Statistics:")
            print(f"    - Min: {min_time:.2f}s")
            print(f"    - Max: {max_time:.2f}s")
            print(f"    - Avg: {avg_time:.2f}s")

            slow_stops = [t for t in stop_times if t > 5]
            if slow_stops:
                print(f"    - Slow stops (>5s): {len(slow_stops)}")

        print(f"\n  Failure Summary:")
        print(f"    - Total failures: {len(failures)}/{n_restarts}")

        if failures:
            print(f"\n  Failure Details:")
            for f in failures:
                print(f"    Cycle {f['cycle']}: Error={f['error']}, Duration={f['duration']:.2f}s")
                print(f"      Connected: {f['connected']}, Scan started: {f['scan_started']}")

        print(f"{'='*60}")
        print(f"[TEST END] Result: {'FAILED' if failures else 'PASSED'}")
        print(f"{'='*60}\n")

        # Final assertions
        assert connection_count > 0, "Agent never connected to manager - test setup issue"
        assert scan_count > 0, "Syscollector scan never started - test setup issue"
        assert len(failures) == 0, f"Service stop failed at cycle {failures[0]['cycle']}. Error: {failures[0]['error']}, Duration: {failures[0]['duration']:.2f}s"

    finally:
        # Clean up RemotedSimulator
        print(f"[CLEANUP] Stopping RemotedSimulator...")
        remoted_server.destroy()
        print(f"[CLEANUP] RemotedSimulator stopped")
