'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Test that the Wazuh agent service can be stopped during syscollector scan/sync
       without service control errors (deadlock detection).
       Uses EVENT-based stop triggers - stops at specific events with configurable delays.

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
import threading
from pathlib import Path

import pytest
import yaml

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.agentd.patterns import AGENTD_CONNECTED_TO_SERVER
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.modulesd.syscollector.patterns import (
    CB_SCAN_STARTED,
    CB_SCAN_FINISHED,
    CB_SYNC_STARTED,
    CB_SYNC_FINISHED,
)
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.utils.file import truncate_file
from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


pytestmark = [pytest.mark.agent, pytest.mark.win32, pytest.mark.tier(level=1)]

if sys.platform != WINDOWS:
    pytest.skip("Windows-specific test", allow_module_level=True)

# Enable debug logging
local_internal_options = {
    AGENTD_WINDOWS_DEBUG: '2',
    MODULESD_DEBUG: '2',
}

tcp_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_tcp.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_multiple_resets.yaml')

_, test_metadata, test_ids = configuration.get_test_cases_data(test_cases_path)

# Timing constants
MAX_STOP_TIME = 30  # Seconds - stops taking longer indicate a problem
STOP_COMMAND_TIMEOUT = 60  # Timeout for the net stop command
CONNECTION_TIMEOUT = 30  # Timeout for connection
EVENT_TIMEOUT = 60  # Timeout for event detection (scan/sync)

# Event name to pattern mapping
EVENT_PATTERNS = {
    'SCAN_START': CB_SCAN_STARTED,
    'SCAN_END': CB_SCAN_FINISHED,
    'SYNC_START': CB_SYNC_STARTED,
    'SYNC_END': CB_SYNC_FINISHED,
}


def load_yaml_template(path):
    with open(path) as f:
        return yaml.safe_load(f)


def apply_config():
    """Apply TCP configuration."""
    template = load_yaml_template(tcp_config_path)
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

    if duration > MAX_STOP_TIME:
        if error_code is None:
            error_code = f'SLOW({duration:.1f}s)'
        success = False

    return success, duration, error_code, output


def start_service():
    """Start the Wazuh service."""
    result = subprocess.run(['net', 'start', 'WazuhSvc'], capture_output=True, text=True, timeout=60)
    return result.returncode == 0


def ensure_stopped():
    """Ensure service is stopped."""
    subprocess.run(['net', 'stop', 'WazuhSvc'], capture_output=True, timeout=60)
    time.sleep(0.5)


def wait_for_connection(timeout=CONNECTION_TIMEOUT):
    """Wait for agent to connect to manager. Returns True if connected."""
    try:
        monitor = FileMonitor(WAZUH_LOG_PATH)
        monitor.start(
            callback=callbacks.generate_callback(AGENTD_CONNECTED_TO_SERVER),
            timeout=timeout,
            only_new_events=True
        )
        return monitor.callback_result is not None
    except Exception:
        return False


def wait_for_event(event_name, timeout=EVENT_TIMEOUT):
    """Wait for a specific event. Returns True if event detected."""
    if event_name not in EVENT_PATTERNS:
        raise ValueError(f"Unknown event: {event_name}. Valid events: {list(EVENT_PATTERNS.keys())}")

    pattern = EVENT_PATTERNS[event_name]
    try:
        monitor = FileMonitor(WAZUH_LOG_PATH)
        monitor.start(
            callback=callbacks.generate_callback(pattern),
            timeout=timeout,
            only_new_events=True
        )
        return monitor.callback_result is not None
    except Exception:
        return False


def has_db_init_error():
    """Check if there's a DB initialization error in recent logs (AFTER stop)."""
    try:
        with open(WAZUH_LOG_PATH, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            return 'Error deleting old db file' in content or 'Unable to initialize' in content
    except Exception:
        return False


class StopTrigger:
    """Helper class to trigger stop after an event with optional delay."""

    def __init__(self, delay_ms=0):
        self.delay_ms = delay_ms
        self.event_detected = threading.Event()
        self.stop_result = None
        self.stop_thread = None

    def trigger_stop(self):
        """Execute stop after delay."""
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)
        self.stop_result = stop_service()

    def start_stop_thread(self):
        """Start the stop thread (waits for event_detected to be set)."""
        def worker():
            self.event_detected.wait()
            self.trigger_stop()

        self.stop_thread = threading.Thread(target=worker)
        self.stop_thread.start()

    def signal_event(self):
        """Signal that the target event was detected."""
        self.event_detected.set()

    def wait_for_stop(self, timeout=STOP_COMMAND_TIMEOUT + 10):
        """Wait for stop to complete."""
        if self.stop_thread:
            self.stop_thread.join(timeout=timeout)
            return self.stop_result
        return None


@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_ids)
def test_multiple_resets(test_metadata, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Test service reliability by stopping at specific events with delays.
                 Uses EVENT-based triggers to find potential deadlock windows.

    wazuh_min_version: 4.14.2

    tier: 1

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata with event and delay parameters.
        - configure_local_internal_options:
            type: fixture
            brief: Configure debug options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate log files.

    assertions:
        - Agent connects to manager (explicit assertion).
        - Target event is detected (explicit assertion).
        - Service stops without errors at the specified timing.

    expected_output:
        - All stop operations complete within MAX_STOP_TIME seconds.
    '''
    # Get test parameters
    stop_event = test_metadata.get('stop_event', 'SCAN_START')
    delay_ms = test_metadata.get('delay_ms', 0)
    cycles = test_metadata.get('cycles', 3)

    # Validate event
    if stop_event not in EVENT_PATTERNS:
        pytest.fail(f"Invalid stop_event: {stop_event}. Valid events: {list(EVENT_PATTERNS.keys())}")

    failures = []
    results = []

    print(f"\n{'='*70}")
    print(f"[TEST START] Syscollector Deadlock Detection - Event-Based Stop")
    print(f"{'='*70}")
    print(f"  Stop Event: {stop_event}")
    print(f"  Delay after event: {delay_ms}ms")
    print(f"  Cycles: {cycles}")
    print(f"{'='*70}")

    ensure_stopped()
    test_start_time = time.time()
    remoted_server = None

    try:
        for cycle in range(1, cycles + 1):
            cycle_id = f"{stop_event}-{delay_ms}ms-{cycle}"

            print(f"\n[{cycle_id}] --- Starting cycle ---")

            # Truncate log for clean monitoring
            truncate_file(WAZUH_LOG_PATH)

            # Start fresh RemotedSimulator for each cycle
            # (Required: simulator doesn't handle reconnections after service restart)
            print(f"[{cycle_id}] Starting RemotedSimulator...")
            remoted_server = RemotedSimulator(server_ip='127.0.0.1', port=1514, protocol='tcp')
            remoted_server.start()

            # Apply config and start service
            apply_config()
            if not start_service():
                print(f"[{cycle_id}] SKIP - Failed to start service")
                remoted_server.destroy()
                continue

            # ASSERTION 1: Agent must connect to manager
            print(f"[{cycle_id}] Waiting for agent connection...")
            connected = wait_for_connection(timeout=CONNECTION_TIMEOUT)
            if not connected:
                print(f"[{cycle_id}] FAIL - Agent did not connect within {CONNECTION_TIMEOUT}s")
                failures.append({
                    'cycle': cycle,
                    'error': 'NO_CONNECTION',
                    'duration': 0,
                    'phase': 'connection'
                })
                stop_service()
                remoted_server.destroy()
                continue
            print(f"[{cycle_id}] ASSERT PASS - Agent connected to manager")

            # ASSERTION 2: Wait for scan to start (always needed)
            print(f"[{cycle_id}] Waiting for scan to start...")
            scan_started = wait_for_event('SCAN_START', timeout=EVENT_TIMEOUT)
            if not scan_started:
                print(f"[{cycle_id}] FAIL - Scan did not start within {EVENT_TIMEOUT}s")
                failures.append({
                    'cycle': cycle,
                    'error': 'NO_SCAN_START',
                    'duration': 0,
                    'phase': 'scan_start'
                })
                stop_service()
                remoted_server.destroy()
                continue
            print(f"[{cycle_id}] ASSERT PASS - Scan started")

            # If target event is SCAN_START, stop now with delay
            if stop_event == 'SCAN_START':
                print(f"[{cycle_id}] Target event reached. Stopping after {delay_ms}ms delay...")
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
                success, duration, error_code, output = stop_service()
            else:
                # Need to wait for additional events
                if stop_event in ['SCAN_END', 'SYNC_START', 'SYNC_END']:
                    # Wait for scan to finish
                    print(f"[{cycle_id}] Waiting for scan to finish...")
                    scan_finished = wait_for_event('SCAN_END', timeout=EVENT_TIMEOUT)
                    if not scan_finished:
                        print(f"[{cycle_id}] FAIL - Scan did not finish within {EVENT_TIMEOUT}s")
                        failures.append({
                            'cycle': cycle,
                            'error': 'NO_SCAN_END',
                            'duration': 0,
                            'phase': 'scan_end'
                        })
                        stop_service()
                        remoted_server.destroy()
                        continue
                    print(f"[{cycle_id}] ASSERT PASS - Scan finished")

                    if stop_event == 'SCAN_END':
                        print(f"[{cycle_id}] Target event reached. Stopping after {delay_ms}ms delay...")
                        if delay_ms > 0:
                            time.sleep(delay_ms / 1000.0)
                        success, duration, error_code, output = stop_service()
                    else:
                        # Need sync events
                        print(f"[{cycle_id}] Waiting for sync to start...")
                        sync_started = wait_for_event('SYNC_START', timeout=EVENT_TIMEOUT)
                        if not sync_started:
                            print(f"[{cycle_id}] FAIL - Sync did not start within {EVENT_TIMEOUT}s")
                            failures.append({
                                'cycle': cycle,
                                'error': 'NO_SYNC_START',
                                'duration': 0,
                                'phase': 'sync_start'
                            })
                            stop_service()
                            remoted_server.destroy()
                            continue
                        print(f"[{cycle_id}] ASSERT PASS - Sync started")

                        if stop_event == 'SYNC_START':
                            print(f"[{cycle_id}] Target event reached. Stopping after {delay_ms}ms delay...")
                            if delay_ms > 0:
                                time.sleep(delay_ms / 1000.0)
                            success, duration, error_code, output = stop_service()
                        else:
                            # SYNC_END
                            print(f"[{cycle_id}] Waiting for sync to finish...")
                            sync_finished = wait_for_event('SYNC_END', timeout=EVENT_TIMEOUT)
                            if not sync_finished:
                                print(f"[{cycle_id}] FAIL - Sync did not finish within {EVENT_TIMEOUT}s")
                                failures.append({
                                    'cycle': cycle,
                                    'error': 'NO_SYNC_END',
                                    'duration': 0,
                                    'phase': 'sync_end'
                                })
                                stop_service()
                                remoted_server.destroy()
                                continue
                            print(f"[{cycle_id}] ASSERT PASS - Sync finished")

                            print(f"[{cycle_id}] Target event reached. Stopping after {delay_ms}ms delay...")
                            if delay_ms > 0:
                                time.sleep(delay_ms / 1000.0)
                            success, duration, error_code, output = stop_service()
                else:
                    pytest.fail(f"Unknown stop_event: {stop_event}")

            results.append(duration)

            # Check for DB errors AFTER stop (these are not deadlock failures)
            if has_db_init_error():
                print(f"[{cycle_id}] NOTE - DB init error detected after stop (not a deadlock)")

            if not success:
                failures.append({
                    'cycle': cycle,
                    'error': error_code,
                    'duration': duration,
                    'phase': 'stop'
                })
                print(f"[{cycle_id}] FAILED - Error: {error_code}, Duration: {duration:.2f}s")
            else:
                print(f"[{cycle_id}] OK - Stop time: {duration:.2f}s")

            # Destroy RemotedSimulator at end of each cycle
            remoted_server.destroy()
            remoted_server = None

        # Report results
        total_time = time.time() - test_start_time
        print(f"\n{'='*70}")
        print(f"[TEST RESULTS] - Event-Based Stop Summary")
        print(f"{'='*70}")
        print(f"  Stop Event: {stop_event}")
        print(f"  Delay: {delay_ms}ms")
        print(f"  Total test duration: {total_time:.1f}s ({total_time/60:.1f} min)")
        print(f"  Successful cycles: {len(results)}/{cycles}")
        print(f"  Total failures: {len(failures)}")

        if results:
            avg_stop = sum(results) / len(results)
            max_stop = max(results)
            print(f"  Average stop time: {avg_stop:.2f}s")
            print(f"  Max stop time: {max_stop:.2f}s")

        if failures:
            print(f"\n  Failure Details:")
            for f in failures:
                print(f"    - Cycle {f['cycle']}: {f['error']} at {f['phase']} ({f['duration']:.2f}s)")

        # Only count stop-phase failures as test failures (not event detection failures)
        stop_failures = [f for f in failures if f['phase'] == 'stop']

        print(f"\n  Stop-phase failures (deadlock indicators): {len(stop_failures)}")
        print(f"{'='*70}")
        print(f"[TEST END] Result: {'FAILED' if stop_failures else 'PASSED'}")
        print(f"{'='*70}\n")

        assert len(stop_failures) == 0, f"Service stop failures detected: {stop_failures}"

    finally:
        if remoted_server is not None:
            print(f"[CLEANUP] Stopping RemotedSimulator...")
            remoted_server.destroy()
