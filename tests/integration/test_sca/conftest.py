"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import psutil
import pytest
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from wazuh_testing.constants.daemons import AGENT_DAEMON, WAZUH_AGENT_WIN
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.modulesd.sca import patterns
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, services
from wazuh_testing.utils.services import control_service


SCA_DB_DIR = Path(WAZUH_PATH, 'queue', 'sca', 'db')

_WAZUH_AGENT_PROCESS_NAMES = {AGENT_DAEMON, WAZUH_AGENT_WIN, 'WazuhSvc.exe'}


def _wait_for_agent_gone(timeout: int = 60, raise_on_timeout: bool = False) -> None:
    """Block until no wazuh-agent process is alive or timeout expires.

    Windows SCM reports STOPPED before the process fully exits. Starting a new
    service instance while the old process is alive causes both to compete for
    the same IPC endpoint used by the SCA C++ module, preventing the scan from
    starting (Phase 4 deadlock).

    Args:
        timeout: Maximum seconds to wait.
        raise_on_timeout: If True, raises TimeoutError when the deadline is
            exceeded. Use True in setup contexts where a timeout is a real
            blocker. Use False (default) in teardown contexts where the wait
            is best-effort.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        alive = [p.info['name'] for p in psutil.process_iter(attrs=['name'])
                 if (p.info.get('name') or '') in _WAZUH_AGENT_PROCESS_NAMES]
        if not alive:
            return
        time.sleep(0.5)
    if raise_on_timeout:
        raise TimeoutError(
            f"Wazuh agent process still alive after {timeout}s: {alive}. "
            f"IPC endpoint will collide with the next service start."
        )


@pytest.fixture
def wait_for_agent_gone():
    """Expose the agent-exit wait helper to child conftests and tests."""
    return _wait_for_agent_gone


# Patterns that distinguish a healthy SCA startup from the known
# "getdoclimits handshake stall" failure mode. If Phase 3 times out with a
# high count for 'AGCOM Module limits not configured' (or 'Failed to query
# agentd via agcom_dispatch') and zero for 'Module limits received from
# manager', it is not a test flake: the agent's handshake with the manager
# never produced a 'limits.sca' block, so SCA stays forever in the loop at
# src/wazuh_modules/src/wm_sca.c:590-601 waiting for agent_module_limits.
# limits_received to flip to true (src/client-agent/src/start_agent.c:142).
_SCA_STARTUP_HIGHLIGHTS = {
    'SCA tagged lines': r':sca\b',
    'SCA module enabled (DEBUG)': r'SCA module enabled',
    'SCA module running (INFO)': r'SCA module running',
    'Starting SCA module': r'Starting SCA module',
    'agcom_dispatch failure': r'Failed to query agentd via agcom_dispatch',
    'AGCOM limits not configured': r'AGCOM Module limits not configured',
    'AGCOM err response': r'Agentd returned error',
    'Handshake JSON parsed': r'Module limits received from manager',
    'Handshake JSON absent': r'No handshake JSON after ACK',
    'Handshake retry': r'Error parsing handshake JSON',
    'Policy file not found': r'Policy file.*not found',
    'Ruleset folder open fail': r'Could not open the default SCA ruleset folder',
    'Policy scan started': r'Starting Policy checks evaluation',
}


def _wait_service_running(timeout: int) -> None:
    """Poll until the Wazuh service reports RUNNING.

    On Windows, delegates to ``wait_expected_daemon_status`` which queries
    SCM (no socket validation). On Linux, polls ``wazuh-control status``
    directly, checking only that every daemon line says "is running…" —
    without validating that sockets exist on disk (which fails on agents
    that don't create manager-only sockets like ``download`` / ``control``).
    """
    if sys.platform == WINDOWS:
        services.wait_expected_daemon_status(running_condition=True, timeout=timeout)
        return

    from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            proc = subprocess.run(
                [WAZUH_CONTROL_PATH, 'status'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            lines = [l for l in proc.stdout.decode(errors='ignore').splitlines() if l.strip()]
            if lines and all('is running...' in l for l in lines):
                return
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError(f"Service did not reach RUNNING within {timeout}s")


def _format_diagnostics(diag: dict) -> str:
    """Render a diagnostics dict from collect_service_diagnostics as a block."""
    sections = [
        f"Service state: {diag.get('service_state')}",
        f"Wazuh processes: {diag.get('processes')}",
        "--- service query raw ---",
        diag.get('service_raw', '').strip(),
    ]
    highlights = diag.get('highlights')
    if highlights:
        sections.append("--- log highlights (counts across full ossec.log) ---")
        for label, entry in highlights.items():
            count = entry['count']
            sections.append(f"[{count:>4}] {label}")
            if entry['first']:
                sections.append(f"       first: {entry['first']}")
            if entry['last'] and entry['last'] != entry['first']:
                sections.append(f"        last: {entry['last']}")
    if 'log_tail' in diag:
        sections.extend(["--- ossec.log tail ---", diag['log_tail']])
    return "\n".join(sections)


# Fixtures

@pytest.fixture()
def clean_sca_db():
    '''Stop the agent, remove SCA database files, and seed first_sync_completed.

    The agent must be stopped first to release NTFS file locks on Windows.
    daemons_handler (which runs after this fixture) will restart the agent.

    Seeding first_sync_completed ensures PushStateful() logs "Stateful event
    queued" during the scan (Path A) instead of relying on
    synchronizeDatabaseSnapshot (Path B) which blocks on synchronizeModule.
    '''
    try:
        control_service('stop')
    except Exception:
        pass

    _wait_for_agent_gone(timeout=60, raise_on_timeout=True)

    for attempt in range(3):
        if SCA_DB_DIR.exists():
            for f in SCA_DB_DIR.iterdir():
                try:
                    f.unlink()
                except (PermissionError, OSError):
                    pass
        else:
            SCA_DB_DIR.mkdir(parents=True, exist_ok=True)

        try:
            db_path = str(SCA_DB_DIR / 'sca.db')
            conn = sqlite3.connect(db_path)
            conn.execute(
                'CREATE TABLE IF NOT EXISTS sca_metadata (key TEXT PRIMARY KEY, value INTEGER)')
            conn.execute(
                "INSERT OR REPLACE INTO sca_metadata (key, value) VALUES ('first_sync_completed', 1)")
            conn.commit()
            cursor = conn.execute(
                "SELECT value FROM sca_metadata WHERE key = 'first_sync_completed'")
            row = cursor.fetchone()
            conn.close()
            if row and row[0] == 1:
                break
        except Exception:
            pass

    yield


@pytest.fixture(autouse=True)
def _wait_agent_exit_after_test():
    """After each test, wait for the agent process to fully exit on Windows.

    daemons_handler stops the service but SCM reports STOPPED before the process
    terminates. Without this wait, the next test's clean_sca_db or daemons_handler
    starts a new instance while the old process still holds the SCA IPC endpoint,
    causing Phase 4 deadlock (scan thread never initialises).
    """
    yield
    if sys.platform == WINDOWS:
        _wait_for_agent_gone(timeout=60)


@pytest.fixture()
def wait_for_sca_enabled():
    '''
    Four-phase gate on the SCA module being up and scanning. Each phase has
    its own timeout and failure message so a CI failure points at the exact
    stage that broke, instead of a single opaque 180s timeout.

      Phase 1 — Service RUNNING:
          Poll the platform authority (SCM via sc query on Windows,
          wazuh-control on Linux) until the service is RUNNING. On Linux
          this checks only process status, not socket existence (agent
          builds don't create manager-only sockets). Starting a
          FileMonitor before the service is ready burns timeout budget
          watching a file nobody is writing to.

      Phase 2 — SCA_ENABLED (DEBUG):
          wm_sca_main emits "SCA module enabled." at the very start, BEFORE
          loading the SCA shared object, resolving symbols, registering
          callbacks or doing any C++ setup. If this log never appears, the
          native wm_sca entrypoint is not being reached — the problem is
          upstream of the SCA module itself (config load, module registry).

      Phase 3 — SCA_RUNNING (INFO):
          SecurityConfigurationAssessment::Run() emits "SCA module running."
          once the C++ implementation has finished initialising (sync manager,
          policy loader, scan loop). If Phase 2 passes but Phase 3 times out,
          the hang is inside the C++ init path — not in wm_sca, not in the
          service itself.

      Phase 4 — First scan started:
          Waits for "Starting Policy checks evaluation" to appear, confirming
          the initial scan is underway. Tests that read from file position 0
          (only_new_events=False) are then guaranteed to find scan patterns
          already in the log, avoiding races on slow CI machines.

    On timeout each phase raises AssertionError with a snapshot of service
    state, Wazuh process list and the tail of ossec.log, so CI failures are
    self-diagnosing.
    '''
    service_timeout = 90 if sys.platform == WINDOWS else 30
    enabled_timeout = 60 if sys.platform == WINDOWS else 30
    running_timeout = 90 if sys.platform == WINDOWS else 30

    # Phase 1 — service must reach RUNNING before we look at the log
    try:
        _wait_service_running(service_timeout)
    except TimeoutError:
        diag = services.collect_service_diagnostics(
            log_path=WAZUH_LOG_PATH, highlight_patterns=_SCA_STARTUP_HIGHLIGHTS)
        raise AssertionError(
            f"[Phase 1] Wazuh service did not reach RUNNING within {service_timeout}s.\n"
            f"{_format_diagnostics(diag)}"
        )

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Phase 2 — wm_sca_main entered (pre-C++-init anchor)
    log_monitor.start(
        callback=callbacks.generate_callback(patterns.SCA_ENABLED),
        timeout=enabled_timeout,
        only_new_events=False
    )
    if not log_monitor.callback_result:
        diag = services.collect_service_diagnostics(
            log_path=WAZUH_LOG_PATH, highlight_patterns=_SCA_STARTUP_HIGHLIGHTS)
        raise AssertionError(
            f"[Phase 2] SCA module did not emit '{patterns.SCA_ENABLED}' within {enabled_timeout}s. "
            f"Service is RUNNING but wm_sca_main was never reached — the hang is upstream of SCA "
            f"(module registry, config load, or the SCA debug level is not applied).\n"
            f"{_format_diagnostics(diag)}"
        )

    # Phase 3 — SCA::Run() entered (C++ init finished)
    log_monitor.start(
        callback=callbacks.generate_callback(patterns.SCA_RUNNING),
        timeout=running_timeout,
        only_new_events=False
    )
    if not log_monitor.callback_result:
        diag = services.collect_service_diagnostics(
            log_path=WAZUH_LOG_PATH, highlight_patterns=_SCA_STARTUP_HIGHLIGHTS)
        raise AssertionError(
            f"[Phase 3] SCA module did not emit '{patterns.SCA_RUNNING}' within {running_timeout}s. "
            f"wm_sca_main started (SCA_ENABLED seen) but SCA::Run() was never reached — the hang "
            f"is inside the C++ init path (shared object load, symbol resolution, Setup(), sync "
            f"manager initialise).\n"
            f"{_format_diagnostics(diag)}"
        )

    # Phase 4 — First scan has actually begun
    # SCA_RUNNING fires before the scan loop starts.  On slow CI machines
    # (especially Windows) the test's FileMonitor may open the file before
    # the first scan-start line is written.  Waiting here guarantees scan
    # patterns are present in the log when the test reads from position 0.
    scan_start_timeout = 60 if sys.platform == WINDOWS else 30
    log_monitor.start(
        callback=callbacks.generate_callback(patterns.SCA_SCAN_STARTED_CHECK),
        timeout=scan_start_timeout,
        only_new_events=False
    )
    if not log_monitor.callback_result:
        diag = services.collect_service_diagnostics(
            log_path=WAZUH_LOG_PATH, highlight_patterns=_SCA_STARTUP_HIGHLIGHTS)
        raise AssertionError(
            f"[Phase 4] SCA scan did not start within {scan_start_timeout}s. "
            f"SCA module is running but no policy scan was triggered.\n"
            f"{_format_diagnostics(diag)}"
        )

    yield log_monitor
