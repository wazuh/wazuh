'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Test that the Wazuh agent service can be stopped and started multiple times
       with TCP/UDP configuration changes without service control errors.

components:
    - agentd

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
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import configuration
from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


pytestmark = [pytest.mark.agent, pytest.mark.win32, pytest.mark.tier(level=1)]

if sys.platform != WINDOWS:
    pytest.skip("Windows-specific test", allow_module_level=True)

# Enable debug logging for both agent and modules (syscollector)
local_internal_options = {
    AGENTD_WINDOWS_DEBUG: '2',
    MODULESD_DEBUG: '2',
}

tcp_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_tcp.yaml')
udp_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_udp.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_multiple_resets.yaml')

_, test_metadata, test_ids = configuration.get_test_cases_data(test_cases_path)

MAX_STOP_TIME = 30  # Seconds - stops taking longer indicate a problem
STOP_COMMAND_TIMEOUT = 60  # Timeout for the net stop command itself

# Patterns for log analysis - errors to IGNORE (not related to deadlock during scan)
IGNORABLE_ERROR_PATTERNS = [
    'wdb_open',
    'Unable to open',
    'Unable to initialize database',
    'Cannot open',
    'SQLite',
    'Error deleting old db file',  # DB init errors during fast restarts
    'No valid server IP',  # Config race conditions
    'No client configured',  # Config race conditions
    'Lost connection with manager',  # Expected during restarts
    'SSL read',  # Network errors during restarts
    'Agent verification',  # Network errors during restarts
    'Error initializing EVP',  # Crypto init errors
]


def load_yaml_template(path):
    with open(path) as f:
        return yaml.safe_load(f)


def wait_for_agent_connection(remoted_server, timeout=30):
    """Wait for the agent to connect to the RemotedSimulator.

    Returns:
        bool: True if connection established, False if timeout.
    """
    start = time.time()
    while time.time() - start < timeout:
        if remoted_server.request_counter > 0:
            return True
        time.sleep(0.5)
    return False


def check_log_for_patterns(log_path, patterns, since_time=None):
    """Check if any of the patterns appear in the log file.

    Args:
        log_path: Path to the log file.
        patterns: List of regex patterns or strings to search for.
        since_time: Only check entries after this time.

    Returns:
        dict: {pattern: [matching_lines]} for patterns found.
    """
    found = {p: [] for p in patterns}
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                # Check timestamp if since_time provided
                if since_time:
                    match = re.match(r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                    if match:
                        try:
                            log_time = time.mktime(time.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'))
                            if log_time < since_time:
                                continue
                        except ValueError:
                            continue

                for pattern in patterns:
                    if pattern.lower() in line.lower():
                        found[pattern].append(line.strip())
    except Exception as e:
        print(f"[LOG] Warning: Could not read log file: {e}")
    return found


def wait_for_syscollector_scan(log_path, timeout=60):
    """Wait for syscollector to start scanning.

    Returns:
        bool: True if scan started, False if timeout.
    """
    start = time.time()
    scan_patterns = ['Starting evaluation', 'Syscollector started', 'Starting syscollector scan']

    while time.time() - start < timeout:
        found = check_log_for_patterns(log_path, scan_patterns, since_time=start)
        for pattern, matches in found.items():
            if matches:
                return True
        time.sleep(1)
    return False


def get_connection_status(log_path, since_time):
    """Get connection status from logs.

    Returns:
        dict with connection info.
    """
    patterns = [
        'Connected to',
        'Sending keep alive',
        'Received ack',
        'Sending agent notification',
        'syscollector',
        'Starting evaluation',
        'Sync started',
        'rsync',
    ]
    return check_log_for_patterns(log_path, patterns, since_time)


def get_log_errors_since(log_path, since_time):
    """Read ERROR entries from log file since a given timestamp.

    Args:
        log_path: Path to the log file.
        since_time: Only return entries after this time (time.time() format).

    Returns:
        List of (timestamp_str, error_line) tuples.
    """
    errors = []
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if 'ERROR:' not in line:
                    continue
                # Parse timestamp from log line (format: 2024/01/15 10:30:45)
                match = re.match(r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                if match:
                    timestamp_str = match.group(1)
                    try:
                        log_time = time.mktime(time.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S'))
                        if log_time >= since_time:
                            errors.append((timestamp_str, line.strip()))
                    except ValueError:
                        continue
    except Exception as e:
        print(f"[LOG] Warning: Could not read log file: {e}")
    return errors


def is_ignorable_error(error_line):
    """Check if an error should be ignored (not related to deadlock during scan)."""
    error_lower = error_line.lower()
    return any(pattern.lower() in error_lower for pattern in IGNORABLE_ERROR_PATTERNS)


def categorize_errors(errors):
    """Categorize errors into ignorable errors and significant errors.

    Returns:
        (ignorable_errors, significant_errors) tuple of lists.
    """
    ignorable = []
    significant = []
    for ts, line in errors:
        if is_ignorable_error(line):
            ignorable.append((ts, line))
        else:
            significant.append((ts, line))
    return ignorable, significant


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

    # Check for error codes in output (both stdout and stderr)
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

    # Also fail if stop took too long (indicates deadlock even without explicit error)
    if duration > MAX_STOP_TIME:
        if error_code is None:
            error_code = f'SLOW({duration:.1f}s)'
        success = False

    return success, duration, error_code, output


def start_service():
    """Start the Wazuh service and wait for it to be running."""
    result = subprocess.run(['net', 'start', 'WazuhSvc'], capture_output=True, text=True, timeout=120)
    time.sleep(0.5)  # Brief wait for service to initialize
    return result.returncode == 0


def ensure_stopped():
    """Ensure service is stopped."""
    subprocess.run(['net', 'stop', 'WazuhSvc'], capture_output=True, timeout=120)
    time.sleep(1)


@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_ids)
def test_multiple_resets(test_metadata, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Test service reliability under repeated start/stop cycles with configuration changes.
                 Uses RemotedSimulator to enable rsync communication which is needed to trigger
                 deadlocks during syscollector scan/sync operations.

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
        - No service control errors (2186, 109) occur during stop operations.
        - All stop operations complete within MAX_STOP_TIME seconds.

    expected_output:
        - All restart cycles complete successfully.
    '''
    n_restarts = test_metadata.get('n_restarts', 20)
    delay = test_metadata.get('delay', 1)
    wait_for_scan = test_metadata.get('wait_for_scan', False)

    stop_times = []
    failures = []
    all_log_errors = []  # Collect all ERROR logs across cycles
    scan_detected_count = 0  # Track how many times we detected scan starting

    print(f"\n{'='*60}")
    print(f"[TEST START] Multiple Resets Test - Syscollector Deadlock Detection")
    print(f"{'='*60}")
    print(f"  Parameters:")
    print(f"    - Restarts: {n_restarts}")
    print(f"    - Delay: {delay}s")
    print(f"    - Wait for scan: {wait_for_scan}")
    print(f"    - Max stop time: {MAX_STOP_TIME}s")
    print(f"    - Stop command timeout: {STOP_COMMAND_TIMEOUT}s")
    print(f"    - Syscollector interval: 10s")
    print(f"    - Syscollector scan_on_start: yes")
    print(f"    - Debug logging: windows.debug=2, wazuh_modules.debug=2")
    print(f"    - Log path: {WAZUH_LOG_PATH}")
    print(f"{'='*60}")

    # Start RemotedSimulator to accept agent connections and enable rsync
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

            # Apply TCP config and start
            apply_protocol_config('tcp')
            if not start_service():
                print(f"[{i}/{n_restarts}] WARNING - Failed to start service, skipping cycle")
                continue

            # Wait for agent to connect to RemotedSimulator
            connected = wait_for_agent_connection(remoted_server, timeout=15)
            if connected:
                print(f"[{i}/{n_restarts}] Agent connected (requests: {remoted_server.request_counter})")
            else:
                print(f"[{i}/{n_restarts}] WARNING - Agent did not connect within timeout")

            # If wait_for_scan is enabled, wait for syscollector to start scanning
            if wait_for_scan:
                scan_started = wait_for_syscollector_scan(WAZUH_LOG_PATH, timeout=30)
                if scan_started:
                    scan_detected_count += 1
                    print(f"[{i}/{n_restarts}] Syscollector scan STARTED - now waiting {delay}s before stop")
                else:
                    print(f"[{i}/{n_restarts}] WARNING - Syscollector scan not detected within timeout")

            # Check connection status in logs
            conn_status = get_connection_status(WAZUH_LOG_PATH, cycle_start)
            conn_info = []
            for pattern, matches in conn_status.items():
                if matches:
                    conn_info.append(f"{pattern}: {len(matches)}")
            if conn_info:
                print(f"[{i}/{n_restarts}] Log status: {', '.join(conn_info)}")

            time.sleep(delay)

            # Apply UDP config (triggers config reload)
            apply_protocol_config('udp')
            time.sleep(delay)

            # Stop and measure
            success, duration, error_code, output = stop_service()
            stop_times.append(duration)
            cycle_time = time.time() - cycle_start

            # Capture log errors from this cycle
            cycle_errors = get_log_errors_since(WAZUH_LOG_PATH, cycle_start)
            if cycle_errors:
                all_log_errors.extend(cycle_errors)
                ignorable_errors, significant_errors = categorize_errors(cycle_errors)
                if significant_errors:
                    print(f"[{i}/{n_restarts}] SIGNIFICANT LOG ERRORS: {len(significant_errors)}")
                    for ts, line in significant_errors[:3]:  # Show first 3
                        print(f"    {line[:150]}")

            if not success:
                failures.append({
                    'cycle': i,
                    'error': error_code,
                    'duration': duration,
                    'output': output,
                    'log_errors': cycle_errors
                })
                print(f"[{i}/{n_restarts}] FAILED - Error: {error_code}, Stop time: {duration:.2f}s, Cycle time: {cycle_time:.2f}s")
                # Fail fast on first error
                print(f"\n[FAIL FAST] First failure detected at cycle {i}, stopping test early.")
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
        if wait_for_scan:
            print(f"  Scans detected: {scan_detected_count}/{cycles_completed}")

        if stop_times:
            avg_time = sum(stop_times) / len(stop_times)
            min_time = min(stop_times)
            max_time = max(stop_times)
            print(f"\n  Stop Time Statistics:")
            print(f"    - Min: {min_time:.2f}s")
            print(f"    - Max: {max_time:.2f}s")
            print(f"    - Avg: {avg_time:.2f}s")

            # Count slow stops (> 5s is suspicious even if < 30s)
            slow_stops = [t for t in stop_times if t > 5]
            if slow_stops:
                print(f"    - Slow stops (>5s): {len(slow_stops)}")

        # Log error analysis
        if all_log_errors:
            ignorable_errors, significant_errors = categorize_errors(all_log_errors)
            print(f"\n  Log Error Analysis:")
            print(f"    - Total ERROR entries: {len(all_log_errors)}")
            print(f"    - Ignorable errors (init/network): {len(ignorable_errors)}")
            print(f"    - Significant errors: {len(significant_errors)}")

            if significant_errors:
                print(f"\n  Significant Error Details (first 10):")
                for ts, line in significant_errors[:10]:
                    print(f"    [{ts}] {line[:200]}")

            if ignorable_errors:
                print(f"\n  Ignorable Errors (first 5, for reference):")
                for ts, line in ignorable_errors[:5]:
                    print(f"    [{ts}] {line[:200]}")

        print(f"\n  Failure Summary:")
        print(f"    - Total failures: {len(failures)}/{n_restarts}")

        if failures:
            print(f"\n  Failure Details:")
            for f in failures:
                print(f"    Cycle {f['cycle']}: Error={f['error']}, Duration={f['duration']:.2f}s")
                if f.get('output'):
                    # Clean up output for logging
                    clean_output = f['output'].replace('\n', ' ').strip()[:300]
                    print(f"      Output: {clean_output}")
                if f.get('log_errors'):
                    print(f"      Log errors in cycle: {len(f['log_errors'])}")

        print(f"{'='*60}")
        print(f"[TEST END] Result: {'FAILED' if failures else 'PASSED'}")
        print(f"{'='*60}\n")

        assert len(failures) == 0, f"Service control error at cycle {failures[0]['cycle']}/{n_restarts}. Error: {failures[0]['error']}, Stop time: {failures[0]['duration']:.2f}s"

    finally:
        # Clean up RemotedSimulator
        print(f"[CLEANUP] Stopping RemotedSimulator...")
        remoted_server.destroy()
        print(f"[CLEANUP] RemotedSimulator stopped")
