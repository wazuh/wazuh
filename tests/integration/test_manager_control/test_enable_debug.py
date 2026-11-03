'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'wazuh-manager-control enable debug' and 'disable debug' reach
       'wazuh-manager-analysisd' (the engine). 'enable debug' stores DEBUG_CLI="-d" in
       'bin/.process_list', and the start loop of src/init/wazuh-server.sh passes it to every
       daemon. The engine is started by a different function (get_wazuh_engine_pid()), which
       used to run the binary without arguments, so after 'enable debug' and a restart the
       other daemons logged '[<pid>] <file>:<line> at <function>():' after the tag and the
       engine did not. Regression tests for #40436.

components:
    - manager

suite: manager_control

targets:
    - manager

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/40436

tags:
    - manager_control
'''
import os
import re
import subprocess
import time
from pathlib import Path

import psutil
import pytest

from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.services import wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

# enable() and disable() only ever append to this file, and the script sources it, so the last
# DEBUG_CLI assignment wins. It sits next to the control script.
PROCESS_LIST = Path(WAZUH_CONTROL_PATH).parent / '.process_list'
ENGINE_NAME = 'wazuh-manager-analysisd'

# Margin for the whole start loop (the engine is waited on until its API answers) and for the
# daemons to report running; wall-clock time, not CPU time.
STATUS_TIMEOUT_SECONDS = 120
# The engine writes its first debug lines at start; this is how long to wait for them to be
# flushed to the log before concluding there are none.
LOG_TIMEOUT_SECONDS = 30
# Time to let a restarted engine write something before checking that it wrote no debug lines.
QUIET_PERIOD_SECONDS = 10


def _control(*args):
    """Run 'wazuh-manager-control' directly and wait for it to finish.

    Not control_service(): on Linux that goes through 'service wazuh-manager', whose unit stays
    active while any daemon is alive, so a restart could be skipped. The control script itself
    stops and starts every daemon.
    """
    subprocess.run([WAZUH_CONTROL_PATH, *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _restart():
    _control('restart')
    wait_expected_daemon_status(timeout=STATUS_TIMEOUT_SECONDS)


def _engine_processes():
    """Live engine processes, ignoring the short-lived '-t' configuration check the script runs."""
    found = []
    for proc in psutil.process_iter(attrs=['pid', 'cmdline']):
        cmdline = proc.info['cmdline'] or []
        if cmdline and os.path.basename(cmdline[0]) == ENGINE_NAME and '-t' not in cmdline[1:]:
            found.append(proc)
    return found


def _engine():
    """The single running engine process, or a failure if there is not exactly one."""
    found = _engine_processes()
    assert len(found) == 1, f"Expected one running '{ENGINE_NAME}', found {[p.pid for p in found]}"
    return found[0]


def _debug_lines(pid, offset):
    """Lines of the manager log, written after 'offset', that the engine process 'pid' wrote in the
    debug format: '<tag>[<pid>] <file>:<line> at <function>():'. Lines of other pids are ignored on
    purpose: a restart also logs the shutdown of the previous engine process in its previous mode."""
    marker = re.compile(rf'{re.escape(ENGINE_NAME)}\[{pid}\] \S+:\d+ at \S+\(\):')
    with open(WAZUH_LOG_PATH, 'r', errors='replace') as log:
        log.seek(offset)
        return [line for line in log if marker.search(line)]


def _wait_debug_lines(pid, offset, timeout=LOG_TIMEOUT_SECONDS):
    deadline = time.time() + timeout
    lines = _debug_lines(pid, offset)
    while not lines and time.time() < deadline:
        time.sleep(1)
        lines = _debug_lines(pid, offset)
    return lines


@pytest.fixture()
def process_list_restored():
    """Leave 'bin/.process_list' exactly as found, and the manager running in the mode it records."""
    original = PROCESS_LIST.read_bytes() if PROCESS_LIST.exists() else None
    yield
    if original is None:
        PROCESS_LIST.unlink(missing_ok=True)
    else:
        # Written in place: the control helper requires the file to stay root-owned, so keep the inode.
        with open(PROCESS_LIST, 'wb') as plist:
            plist.write(original)
    _restart()


def test_enable_debug_reaches_engine(process_list_restored):
    '''
    description:
        Enables debug mode through 'wazuh-manager-control', restarts the manager and checks that the
        engine was started with '-d' and writes its log lines in the debug format.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Save 'bin/.process_list' ('process_list_restored' fixture).
        - test:
            - Run 'wazuh-manager-control enable debug' and 'wazuh-manager-control restart'.
            - Find the running engine process and read its command line.
            - Look in the manager log, after the restart, for lines written by that engine pid in
              the '<tag>[<pid>] <file>:<line> at <function>():' format.
        - teardown:
            - Restore 'bin/.process_list' and restart the manager ('process_list_restored' fixture).

    parameters:
        - process_list_restored:
            type: fixture
            brief: Restores 'bin/.process_list' and the manager mode after the test.

    assertions:
        - The engine command line contains '-d'.
        - The engine pid writes at least one debug-format line after the restart.

    input_description:
        No external test cases. The engine pid is read from the process started by this test's own
        restart.

    expected_output:
        - r'wazuh-manager-analysisd\\[<pid>\\] \\S+:\\d+ at \\S+\\(\\):'

    tags:
        - manager_control
    '''
    _control('enable', 'debug')
    offset = os.path.getsize(WAZUH_LOG_PATH)
    _restart()

    engine = _engine()
    assert '-d' in engine.cmdline()[1:], (
        f"'enable debug' did not reach '{ENGINE_NAME}': it runs as {engine.cmdline()} - #40436 regression")
    assert _wait_debug_lines(engine.pid, offset), (
        f"'{ENGINE_NAME}' (pid {engine.pid}) started with -d wrote no debug-format line to '{WAZUH_LOG_PATH}'")


def test_disable_debug_restores_engine_level(process_list_restored):
    '''
    description:
        Enables debug mode, then disables it, restarts the manager and checks that the engine is
        back to its normal level: no '-d' and no debug-format lines from the new engine process.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Save 'bin/.process_list' ('process_list_restored' fixture).
        - test:
            - Run 'wazuh-manager-control enable debug', then 'wazuh-manager-control disable debug',
              and 'wazuh-manager-control restart'.
            - Find the running engine process and read its command line.
            - Wait a few seconds and look in the manager log, after the restart, for lines written
              by that engine pid in the debug format.
        - teardown:
            - Restore 'bin/.process_list' and restart the manager ('process_list_restored' fixture).

    parameters:
        - process_list_restored:
            type: fixture
            brief: Restores 'bin/.process_list' and the manager mode after the test.

    assertions:
        - The engine command line does not contain '-d'.
        - The engine pid writes no debug-format line after the restart.

    input_description:
        No external test cases.

    expected_output:
        - No line matching r'wazuh-manager-analysisd\\[<pid>\\] \\S+:\\d+ at \\S+\\(\\):' for the new pid.

    tags:
        - manager_control
    '''
    _control('enable', 'debug')
    _control('disable', 'debug')
    offset = os.path.getsize(WAZUH_LOG_PATH)
    _restart()

    engine = _engine()
    assert '-d' not in engine.cmdline()[1:], (
        f"'disable debug' left '{ENGINE_NAME}' running with -d: {engine.cmdline()}")
    time.sleep(QUIET_PERIOD_SECONDS)
    lines = _debug_lines(engine.pid, offset)
    assert not lines, (
        f"'{ENGINE_NAME}' (pid {engine.pid}) wrote debug-format lines after 'disable debug', "
        f"first one: {lines[0].rstrip()}")
