'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Test that the Wazuh agent service can be stopped during syscollector scan
       without service control errors (deadlock detection).
       Uses a timing sweep approach - tries stopping at different delays after scan starts.

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
from wazuh_testing.modules.modulesd.syscollector.patterns import CB_SCAN_STARTED
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

MAX_STOP_TIME = 30  # Seconds - stops taking longer indicate a problem
STOP_COMMAND_TIMEOUT = 60  # Timeout for the net stop command
CONNECTION_TIMEOUT = 30  # Reduced timeout for connection
SCAN_TIMEOUT = 30  # Reduced timeout for scan detection


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
    result = subprocess.run(['net', 'start', 'WazuhSvc'], capture_output=True, text=True, timeout=120)
    return result.returncode == 0


def ensure_stopped():
    """Ensure service is stopped."""
    subprocess.run(['net', 'stop', 'WazuhSvc'], capture_output=True, timeout=120)
    time.sleep(0.5)


def wait_for_connection(timeout=CONNECTION_TIMEOUT):
    """Wait for agent to connect to manager."""
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


def wait_for_scan_start(timeout=SCAN_TIMEOUT):
    """Wait for syscollector scan to start."""
    try:
        monitor = FileMonitor(WAZUH_LOG_PATH)
        monitor.start(
            callback=callbacks.generate_callback(CB_SCAN_STARTED),
            timeout=timeout,
            only_new_events=True
        )
        return monitor.callback_result is not None
    except Exception:
        return False


def has_db_init_error():
    """Check if there's a DB initialization error in recent logs."""
    try:
        with open(WAZUH_LOG_PATH, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            return 'Error deleting old db file' in content or 'Unable to initialize' in content
    except Exception:
        return False


@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_ids)
def test_multiple_resets(test_metadata, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Test service reliability by stopping at various delays after scan starts.
                 Uses a timing sweep approach to find potential deadlock windows.

    wazuh_min_version: 4.14.2

    tier: 1

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata with timing sweep parameters.
        - configure_local_internal_options:
            type: fixture
            brief: Configure debug options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate log files.

    assertions:
        - Service stops without errors at all timing delays.

    expected_output:
        - All stop operations complete within MAX_STOP_TIME seconds.
    '''
    # Timing sweep parameters
    delay_start_ms = test_metadata.get('delay_start_ms', 0)
    delay_end_ms = test_metadata.get('delay_end_ms', 1000)
    delay_increment_ms = test_metadata.get('delay_increment_ms', 50)
    cycles_per_delay = test_metadata.get('cycles_per_delay', 3)

    # Generate delay values
    delays_ms = list(range(delay_start_ms, delay_end_ms + 1, delay_increment_ms))

    failures = []
    results = {}  # delay_ms -> list of stop times

    print(f"\n{'='*70}")
    print(f"[TEST START] Syscollector Deadlock Detection - Timing Sweep")
    print(f"{'='*70}")
    print(f"  Delay range: {delay_start_ms}ms to {delay_end_ms}ms (increment: {delay_increment_ms}ms)")
    print(f"  Cycles per delay: {cycles_per_delay}")
    print(f"  Total delays to test: {len(delays_ms)}")
    print(f"  Total cycles: {len(delays_ms) * cycles_per_delay}")
    print(f"{'='*70}")

    # Start RemotedSimulator
    print(f"[INIT] Starting RemotedSimulator...")
    remoted_server = RemotedSimulator(server_ip='127.0.0.1', port=1514, protocol='tcp')
    remoted_server.start()

    try:
        ensure_stopped()
        test_start_time = time.time()

        for delay_ms in delays_ms:
            delay_sec = delay_ms / 1000.0
            results[delay_ms] = []

            for cycle in range(1, cycles_per_delay + 1):
                cycle_id = f"{delay_ms}ms-{cycle}"

                # Truncate log for clean monitoring
                truncate_file(WAZUH_LOG_PATH)

                # Apply config and start
                apply_config()
                if not start_service():
                    print(f"[{cycle_id}] SKIP - Failed to start service")
                    continue

                # Wait for connection (short timeout)
                connected = wait_for_connection(timeout=CONNECTION_TIMEOUT)
                if not connected:
                    print(f"[{cycle_id}] SKIP - No connection within {CONNECTION_TIMEOUT}s")
                    stop_service()
                    continue

                # Check for DB init error
                if has_db_init_error():
                    print(f"[{cycle_id}] SKIP - DB init error")
                    stop_service()
                    continue

                # Wait for scan to start
                scan_started = wait_for_scan_start(timeout=SCAN_TIMEOUT)
                if not scan_started:
                    print(f"[{cycle_id}] SKIP - Scan not detected within {SCAN_TIMEOUT}s")
                    stop_service()
                    continue

                # NOW: Wait the specific delay and stop
                if delay_sec > 0:
                    time.sleep(delay_sec)

                success, duration, error_code, output = stop_service()
                results[delay_ms].append(duration)

                if not success:
                    failures.append({
                        'delay_ms': delay_ms,
                        'cycle': cycle,
                        'error': error_code,
                        'duration': duration,
                    })
                    print(f"[{cycle_id}] FAILED - Error: {error_code}, Duration: {duration:.2f}s")
                    # Don't fail fast - continue to test other delays
                else:
                    print(f"[{cycle_id}] OK - Stop time: {duration:.2f}s")

        # Report results
        total_time = time.time() - test_start_time
        print(f"\n{'='*70}")
        print(f"[TEST RESULTS] - Timing Sweep Summary")
        print(f"{'='*70}")
        print(f"  Total test duration: {total_time:.1f}s ({total_time/60:.1f} min)")
        print(f"  Total failures: {len(failures)}")

        # Show results per delay
        print(f"\n  Results by delay:")
        print(f"  {'Delay':>8} | {'Cycles':>6} | {'Avg Stop':>10} | {'Max Stop':>10} | {'Status'}")
        print(f"  {'-'*8}-+-{'-'*6}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}")

        for delay_ms in delays_ms:
            times = results.get(delay_ms, [])
            if times:
                avg_t = sum(times) / len(times)
                max_t = max(times)
                failed = any(f['delay_ms'] == delay_ms for f in failures)
                status = "FAILED" if failed else "OK"
                print(f"  {delay_ms:>6}ms | {len(times):>6} | {avg_t:>8.2f}s | {max_t:>8.2f}s | {status}")
            else:
                print(f"  {delay_ms:>6}ms | {0:>6} | {'N/A':>10} | {'N/A':>10} | SKIPPED")

        if failures:
            print(f"\n  Failure Details:")
            for f in failures:
                print(f"    - {f['delay_ms']}ms cycle {f['cycle']}: {f['error']} ({f['duration']:.2f}s)")

        print(f"{'='*70}")
        print(f"[TEST END] Result: {'FAILED' if failures else 'PASSED'}")
        print(f"{'='*70}\n")

        assert len(failures) == 0, f"Failures at delays: {set(f['delay_ms'] for f in failures)}ms"

    finally:
        print(f"[CLEANUP] Stopping RemotedSimulator...")
        remoted_server.destroy()
