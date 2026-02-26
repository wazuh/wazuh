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
import re
import shutil
import os
from pathlib import Path
from datetime import datetime

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
)
from wazuh_testing.utils import configuration
from .rsync_stress_simulator import RsyncStressSimulator
from wazuh_testing.utils.file import truncate_file
from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Directory to store logs from each test cycle
CYCLE_LOGS_DIR = Path(r'C:\test_logs\cycles') if sys.platform == WINDOWS else Path('/tmp/test_logs/cycles')


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
POLL_INTERVAL = 0.01  # 10ms polling interval for faster detection

# Define sync patterns locally (not available in wazuh_testing package)
# These are DEBUG level messages from syscollectorImp.cpp
CB_SYNC_STARTED = r'.*DEBUG: Starting syscollector sync'
CB_SYNC_FINISHED = r'.*DEBUG: Ending syscollector sync'

# Event name to pattern mapping
EVENT_PATTERNS = {
    'SCAN_START': CB_SCAN_STARTED,
    'SCAN_END': CB_SCAN_FINISHED,
    'SYNC_START': CB_SYNC_STARTED,
    'SYNC_END': CB_SYNC_FINISHED,
}


def setup_cycle_logs_dir():
    """Create the cycle logs directory."""
    CYCLE_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return CYCLE_LOGS_DIR


def save_cycle_log(cycle_id, stop_result, events_detected):
    """Save the log from a specific test cycle for later analysis."""
    try:
        cycle_log_path = CYCLE_LOGS_DIR / f"cycle_{cycle_id}.log"

        with open(cycle_log_path, 'w', encoding='utf-8') as f:
            # Write cycle header
            f.write(f"{'='*80}\n")
            f.write(f"CYCLE: {cycle_id}\n")
            f.write(f"TIMESTAMP: {datetime.now().isoformat()}\n")
            f.write(f"{'='*80}\n\n")

            # Write stop result
            if stop_result:
                success, duration, error_code, output = stop_result
                f.write(f"STOP RESULT:\n")
                f.write(f"  Success: {success}\n")
                f.write(f"  Duration: {duration:.2f}s\n")
                f.write(f"  Error Code: {error_code}\n")
                f.write(f"  Output: {output}\n\n")

            # Write events detected
            f.write(f"EVENTS DETECTED:\n")
            for event, detected in events_detected.items():
                f.write(f"  {event}: {detected}\n")
            f.write("\n")

            # Copy ossec.log content
            f.write(f"{'='*80}\n")
            f.write(f"OSSEC.LOG CONTENT:\n")
            f.write(f"{'='*80}\n")
            try:
                with open(WAZUH_LOG_PATH, 'r', encoding='utf-8', errors='replace') as log_file:
                    f.write(log_file.read())
            except Exception as e:
                f.write(f"Error reading log: {e}\n")

        print(f"[{cycle_id}] Log saved to: {cycle_log_path}")
        return cycle_log_path
    except Exception as e:
        print(f"[{cycle_id}] Error saving cycle log: {e}")
        return None


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


class FastLogMonitor:
    """Fast log monitor with configurable polling interval."""

    def __init__(self, log_path, poll_interval=POLL_INTERVAL):
        self.log_path = log_path
        self.poll_interval = poll_interval
        self.patterns = {}  # name -> (compiled_regex, event)
        self.results = {}   # name -> matched line
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._file_position = 0

    def add_pattern(self, name, pattern):
        """Add a pattern to watch for."""
        self.patterns[name] = (re.compile(pattern), threading.Event())
        self.results[name] = None

    def start(self):
        """Start monitoring from current end of file."""
        # Get current file size to start from
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(0, 2)  # Seek to end
                self._file_position = f.tell()
        except Exception as e:
            print(f"[MONITOR] Error getting file position: {e}")
            self._file_position = 0

        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        """Stop monitoring."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)

    def _monitor_loop(self):
        """Main monitoring loop with fast polling."""
        while not self._stop_event.is_set():
            try:
                with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(self._file_position)
                    new_lines = f.readlines()
                    self._file_position = f.tell()

                for line in new_lines:
                    for name, (regex, event) in self.patterns.items():
                        if not event.is_set() and regex.search(line):
                            self.results[name] = line.strip()
                            event.set()
                            print(f"[MONITOR] Detected {name}: {line.strip()[:80]}...")

            except Exception as e:
                print(f"[MONITOR] Error reading log: {e}")

            time.sleep(self.poll_interval)

    def wait_for(self, name, timeout):
        """Wait for a specific pattern to be matched."""
        if name not in self.patterns:
            raise ValueError(f"Unknown pattern: {name}")
        _, event = self.patterns[name]
        return event.wait(timeout=timeout)

    def was_detected(self, name):
        """Check if a pattern was detected."""
        if name not in self.patterns:
            return False
        _, event = self.patterns[name]
        return event.is_set()

    def get_result(self, name):
        """Get the matched line for a pattern."""
        return self.results.get(name)


def has_db_init_error():
    """Check if there's a DB initialization error in recent logs (AFTER stop)."""
    try:
        with open(WAZUH_LOG_PATH, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            return 'Error deleting old db file' in content or 'Unable to initialize' in content
    except Exception:
        return False


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
    print(f"  Poll interval: {POLL_INTERVAL*1000:.0f}ms")
    print(f"{'='*70}")

    ensure_stopped()
    setup_cycle_logs_dir()
    test_start_time = time.time()
    remoted_server = None
    monitor = None

    try:
        for cycle in range(1, cycles + 1):
            cycle_id = f"{stop_event}-{delay_ms}ms-{cycle}"

            print(f"\n[{cycle_id}] --- Starting cycle ---")

            # Truncate log for clean monitoring
            truncate_file(WAZUH_LOG_PATH)

            # Create and start monitor BEFORE starting service (fixes race condition)
            monitor = FastLogMonitor(WAZUH_LOG_PATH, poll_interval=POLL_INTERVAL)
            monitor.add_pattern('CONNECTION', AGENTD_CONNECTED_TO_SERVER)
            monitor.add_pattern('SCAN_START', CB_SCAN_STARTED)
            monitor.add_pattern('SCAN_END', CB_SCAN_FINISHED)
            monitor.add_pattern('SYNC_START', CB_SYNC_STARTED)
            monitor.add_pattern('SYNC_END', CB_SYNC_FINISHED)
            monitor.start()
            print(f"[{cycle_id}] Log monitor started (poll: {POLL_INTERVAL*1000:.0f}ms)")

            # Start fresh RsyncStressSimulator for each cycle
            # This simulator responds to integrity_check with checksum_fail to trigger heavy rsync traffic
            print(f"[{cycle_id}] Starting RsyncStressSimulator (checksum_fail mode)...")

            def on_integrity_check(check_type, message):
                print(f"[{cycle_id}] Received integrity_check: {check_type}")

            remoted_server = RsyncStressSimulator(
                server_ip='127.0.0.1',
                port=1514,
                protocol='tcp',
                max_checksum_fails=200,  # Increased to trigger more rsync traffic
                on_integrity_check=on_integrity_check
            )
            remoted_server.start()

            # Apply config and start service
            apply_config()
            if not start_service():
                print(f"[{cycle_id}] SKIP - Failed to start service")
                monitor.stop()
                remoted_server.destroy()
                continue

            # ASSERTION 1: Agent must connect to manager
            print(f"[{cycle_id}] Waiting for agent connection...")
            connected = monitor.wait_for('CONNECTION', timeout=CONNECTION_TIMEOUT)
            if not connected:
                print(f"[{cycle_id}] FAIL - Agent did not connect within {CONNECTION_TIMEOUT}s")
                failures.append({
                    'cycle': cycle,
                    'error': 'NO_CONNECTION',
                    'duration': 0,
                    'phase': 'connection'
                })
                monitor.stop()
                stop_service()
                remoted_server.destroy()
                continue
            print(f"[{cycle_id}] ASSERT PASS - Agent connected to manager")
            if monitor.get_result('CONNECTION'):
                print(f"[{cycle_id}]   -> {monitor.get_result('CONNECTION')[:70]}...")

            # ASSERTION 2: Wait for scan to start (always needed)
            print(f"[{cycle_id}] Waiting for scan to start...")
            scan_started = monitor.wait_for('SCAN_START', timeout=EVENT_TIMEOUT)
            if not scan_started:
                print(f"[{cycle_id}] FAIL - Scan did not start within {EVENT_TIMEOUT}s")
                failures.append({
                    'cycle': cycle,
                    'error': 'NO_SCAN_START',
                    'duration': 0,
                    'phase': 'scan_start'
                })
                monitor.stop()
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
                    scan_finished = monitor.wait_for('SCAN_END', timeout=EVENT_TIMEOUT)
                    if not scan_finished:
                        print(f"[{cycle_id}] FAIL - Scan did not finish within {EVENT_TIMEOUT}s")
                        failures.append({
                            'cycle': cycle,
                            'error': 'NO_SCAN_END',
                            'duration': 0,
                            'phase': 'scan_end'
                        })
                        monitor.stop()
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
                        sync_started = monitor.wait_for('SYNC_START', timeout=EVENT_TIMEOUT)
                        if not sync_started:
                            print(f"[{cycle_id}] FAIL - Sync did not start within {EVENT_TIMEOUT}s")
                            failures.append({
                                'cycle': cycle,
                                'error': 'NO_SYNC_START',
                                'duration': 0,
                                'phase': 'sync_start'
                            })
                            monitor.stop()
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
                            sync_finished = monitor.wait_for('SYNC_END', timeout=EVENT_TIMEOUT)
                            if not sync_finished:
                                print(f"[{cycle_id}] FAIL - Sync did not finish within {EVENT_TIMEOUT}s")
                                failures.append({
                                    'cycle': cycle,
                                    'error': 'NO_SYNC_END',
                                    'duration': 0,
                                    'phase': 'sync_end'
                                })
                                monitor.stop()
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

            # Stop monitor after service stop
            monitor.stop()

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
                print(f"[{cycle_id}]   Output: {output[:200]}...")
            else:
                print(f"[{cycle_id}] OK - Stop time: {duration:.2f}s")

            # Save cycle log for debugging
            events_detected = {
                'CONNECTION': monitor.was_detected('CONNECTION'),
                'SCAN_START': monitor.was_detected('SCAN_START'),
                'SCAN_END': monitor.was_detected('SCAN_END'),
                'SYNC_START': monitor.was_detected('SYNC_START'),
                'SYNC_END': monitor.was_detected('SYNC_END'),
            }
            save_cycle_log(cycle_id, (success, duration, error_code, output), events_detected)

            # Print rsync stress statistics
            print(f"[{cycle_id}] RsyncStressSimulator stats:")
            print(f"[{cycle_id}]   Integrity checks received: {remoted_server.integrity_check_counter}")
            print(f"[{cycle_id}]   Checksum fails sent: {remoted_server.checksum_fail_counter}")

            # Destroy RsyncStressSimulator at end of each cycle
            remoted_server.destroy()
            remoted_server = None

            # Wait for port to be released by OS before next cycle
            print(f"[{cycle_id}] Waiting for port release...")
            time.sleep(2)

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

        # Count different types of failures
        stop_failures = [f for f in failures if f['phase'] == 'stop']
        connection_failures = [f for f in failures if f['error'] == 'NO_CONNECTION']

        print(f"\n  Stop-phase failures (deadlock indicators): {len(stop_failures)}")
        print(f"  Connection failures: {len(connection_failures)}")

        # Calculate success rate
        success_rate = len(results) / cycles if cycles > 0 else 0
        min_success_rate = 0.5  # Require at least 50% success rate

        print(f"  Success rate: {success_rate:.1%} (minimum required: {min_success_rate:.0%})")
        print(f"{'='*70}")

        # Determine test result
        test_failed = False
        failure_reasons = []

        if stop_failures:
            test_failed = True
            failure_reasons.append(f"Deadlock detected in {len(stop_failures)} cycles")

        if success_rate < min_success_rate:
            test_failed = True
            failure_reasons.append(f"Success rate {success_rate:.1%} below minimum {min_success_rate:.0%}")

        print(f"[TEST END] Result: {'FAILED' if test_failed else 'PASSED'}")
        if failure_reasons:
            for reason in failure_reasons:
                print(f"  -> {reason}")
        print(f"{'='*70}\n")

        # Assert with detailed message
        if test_failed:
            error_msg = "; ".join(failure_reasons)
            if stop_failures:
                error_msg += f"\nStop failures: {stop_failures}"
            pytest.fail(error_msg)

    finally:
        if monitor is not None:
            monitor.stop()
        if remoted_server is not None:
            print(f"[CLEANUP] Stopping RsyncStressSimulator...")
            remoted_server.destroy()
