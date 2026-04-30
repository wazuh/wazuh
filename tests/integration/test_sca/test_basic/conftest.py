"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
import pytest
import psutil
import sqlite3
import sys
import subprocess
import time
from pathlib import Path

from wazuh_testing.constants.paths.ruleset import CIS_RULESET_PATH
from wazuh_testing.utils.file import copy, remove_file, copy_files_in_folder, delete_path_recursively
from wazuh_testing.constants.paths import TEMP_FILE_PATH, WAZUH_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.utils.services import control_service

from . import TEST_DATA_PATH

SCA_DB_DIR = Path(WAZUH_PATH, 'queue', 'sca', 'db')

_WAZUH_AGENT_PROCESS_NAMES = {'wazuh-agent.exe', 'WazuhSvc.exe', 'wazuh-agentd'}


def _wait_for_agent_gone(timeout: int = 30, raise_on_timeout: bool = False) -> None:
    """Block until no wazuh-agent process is alive or timeout expires.

    Windows SCM reports STOPPED before the process fully exits. Starting a new
    service instance while the old process is still alive causes both processes
    to compete for the same IPC endpoint used by the SCA C++ module, preventing
    the scan from starting (Phase 4 deadlock).

    Args:
        timeout: Maximum seconds to wait.
        raise_on_timeout: If True, raises TimeoutError when the deadline is
            exceeded. Use True in setup contexts where a timeout is a real
            blocker. Use False (default) in teardown contexts where the wait
            is best-effort.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        alive = [
            p.info['name']
            for p in psutil.process_iter(attrs=['name'])
            if (p.info.get('name') or '') in _WAZUH_AGENT_PROCESS_NAMES
        ]
        if not alive:
            return
        time.sleep(0.5)
    if raise_on_timeout:
        raise TimeoutError(
            f"Wazuh agent process still alive after {timeout}s: {alive}. "
            f"IPC endpoint will collide with the next service start."
        )


@pytest.fixture()
def daemons_handler():
    """SCA-specific override: separate stop + start instead of restart.

    The global daemons_handler calls control_service('restart'), which internally
    does stop-then-start.  If the service is already stopped (e.g. by
    clean_sca_database), the stop raises and start never executes.

    This override tolerates an already-stopped service so it always reaches start,
    and waits for the old process to fully exit before starting a new one to
    prevent IPC endpoint conflicts that stall the SCA scan thread.
    """
    try:
        control_service('stop')
    except Exception:
        pass
    _wait_for_agent_gone(timeout=30, raise_on_timeout=True)
    control_service('start')
    yield
    try:
        control_service('stop')
    except Exception:
        pass


@pytest.fixture()
def clean_sca_database():
    '''
    Stops the agent, wipes SCA database contents, and seeds first_sync_completed.

    PR #35305 gates stateful event publication on PushStateful() behind
    m_allowStatefulMessages, which is only true when first_sync_completed is set
    in the sca_metadata table.  Without a real manager the initial sync never
    completes, so that flag would never be set on a clean DB.

    Without the flag the agent falls back to synchronizeDatabaseSnapshot() which
    also logs "Stateful event queued" — but it does so right before calling
    synchronizeModule(Mode::FULL) which blocks waiting for a manager response.
    The log messages can stay in the write-buffer and never reach disk before
    the test's FileMonitor times out.

    Seeding first_sync_completed forces PushStateful() (Path A) which logs
    events *during* the scan — no blocking, immediate flush.
    '''
    try:
        control_service('stop')
    except Exception:
        pass

    _wait_for_agent_gone(timeout=30, raise_on_timeout=True)

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

        if sys.platform == WINDOWS:
            time.sleep(2)


@pytest.fixture()
def prepare_cis_policies_file(test_metadata):
    '''
    Copies policy file from named by metadata into agent's ruleset path. Deletes file after test.
    Args:
        test_metadata (dict): contains the test metadata. Must contain policy_file key with file name.
    '''
    files_to_restore = copy_files_in_folder(
        src_folder=CIS_RULESET_PATH, dst_folder=TEMP_FILE_PATH
    )
    filename = test_metadata['policy_file']
    filepath = Path(TEST_DATA_PATH, 'policies_samples', filename)
    copy(filepath, CIS_RULESET_PATH)
    yield
    copy_files_in_folder(
        src_folder=TEMP_FILE_PATH,
        dst_folder=CIS_RULESET_PATH,
        files_to_move=files_to_restore
    )
    remove_file(Path(CIS_RULESET_PATH, filename))


@pytest.fixture()
def prepare_remediation_test(folder_path='/testfile', mode=0o666):
    '''
    Creates folder with a given mode or modifies the user lockout duration in Windows.
    Args:
        folder_path (str): path for the folder to create
        mode (int): mode to be used for folder creation.
    '''

    duration = ''
    if sys.platform == WINDOWS:
        p = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "net accounts"],
                           capture_output=True, text=True)
        duration = p.stdout.splitlines()[6].split(':')[1].replace(" ", "")
        subprocess.call('net accounts /lockoutduration:30', shell=True)
    else:
        os.makedirs(folder_path, mode, exist_ok=True)

    yield

    if sys.platform == WINDOWS:
        subprocess.call('net accounts /lockoutduration:' + duration, shell=True)
    else:
        delete_path_recursively(folder_path)
