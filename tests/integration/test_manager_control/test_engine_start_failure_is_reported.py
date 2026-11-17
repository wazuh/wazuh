'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'wazuh-manager-control start' reports a startup failure of the engine
       with the engine's own cause. Without '-f' the engine daemonizes, and it used to leave its
       launcher with status 0 and an empty stderr whatever happened next, so the script could only
       guess at the outcome from the PID file and the readiness probes. The engine now keeps the
       launching process alive on a pipe until it reports ready or failed, and
       launch_wazuh_engine() in src/init/wazuh-server.sh consumes that status before the PID lookup.
       Regression test for #40439: the C++ suite covers the startup channel, but not the script
       ignoring its result, which is how the failure reached operators as 'Failed to obtain PID for
       wazuh-manager-analysisd' or 'wazuh-manager-analysisd died during the readiness check.'
       instead of the real reason.

       The failure has to be one the start checks let through: 'start' runs
       'wazuh-manager-analysisd -t' first, so anything -t rejects (a malformed internal option, for
       one) never reaches the launch and would test testconfig() instead. The engine's store is read
       while the modules are initialised, after the fork and after the PID file is written, so
       taking it away exercises the whole path: report, status, and the cleanup of the daemon the
       failed launch leaves behind.

components:
    - manager_control

suite: manager_control

targets:
    - manager

daemons:
    - wazuh-manager-analysisd

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/40439

tags:
    - manager_control
'''
import shutil
import subprocess
from pathlib import Path

import pytest

from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.utils.services import wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

START_TIMEOUT_SECONDS = 180
# Read while the modules are initialised: past -t, past the fork and past the PID file.
STORE = Path(WAZUH_PATH, 'data', 'store')
STORE_MOVED = STORE.with_name('store.test-engine-start-failure')
# What the engine itself prints, what the script adds to it, and what it used to print instead.
ENGINE_CAUSE = 'An error occurred while initializing the modules'
LAUNCH_FAILURE = 'wazuh-manager-analysisd failed to start (exit status'
TESTCONFIG_REFUSAL = 'Configuration error. Exiting'
PID_LOOKUP_FAILURE = 'Failed to obtain PID for wazuh-manager-analysisd'
READINESS_FAILURE = 'wazuh-manager-analysisd died during the readiness check.'


def _control(*args):
    return subprocess.run([WAZUH_CONTROL_PATH, *args], capture_output=True, text=True,
                          timeout=START_TIMEOUT_SECONDS)


def _engine_pid_files():
    return sorted(Path(VAR_RUN_PATH).glob('wazuh-manager-analysisd-*.pid'))


@pytest.fixture()
def engine_store_taken_away():
    """Stop the manager and move the engine's store aside, so the engine fails while it initialises
    its modules. Afterwards put the store back and leave the manager running, as the test found it."""
    _control('stop')
    assert STORE.is_dir(), f'{STORE} is not the engine store directory'
    STORE.rename(STORE_MOVED)

    yield

    if STORE_MOVED.is_dir():
        if STORE.is_dir():
            shutil.rmtree(STORE)
        STORE_MOVED.rename(STORE)
    for pidfile in _engine_pid_files():
        pidfile.unlink(missing_ok=True)
    assert _control('start').returncode == 0, 'the manager did not start again after the test'
    wait_expected_daemon_status(timeout=START_TIMEOUT_SECONDS)


def test_engine_start_failure_is_reported_with_its_own_cause(engine_store_taken_away):
    '''
    description:
        A 'wazuh-manager-control start' whose engine fails to start must exit non-zero and show the
        engine's own cause, not a PID lookup or readiness failure. The engine reports the failure
        through the startup channel it keeps open until it is ready, and the script checks that
        status before it looks for the PID file.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup:
            - Stop the manager and move the engine's store directory aside.
        - test:
            - Run 'wazuh-manager-control start'.
        - teardown:
            - Put the store back and start the manager again.

    assertions:
        - The start exits 1 and the start checks did not refuse it, so the launch really ran.
        - The engine's own cause is in the combined output, with the launch's status line.
        - Neither 'Failed to obtain PID' nor 'died during the readiness check.' is reported.
        - No engine PID file outlives the failed start.

    input_description: A stopped manager whose engine store is missing.

    expected_output:
        - An error occurred while initializing the modules

    tags:
        - manager_control
    '''
    result = _control('start')
    output = result.stdout + result.stderr

    assert result.returncode == 1, f'start exited {result.returncode}, expected 1\n{output}'
    # Without this the test would pass on a start the -t check refused, never reaching the launch.
    assert TESTCONFIG_REFUSAL not in output, f'the start checks refused it before the launch\n{output}'
    assert LAUNCH_FAILURE in output, f'the launch status was not reported\n{output}'
    assert ENGINE_CAUSE in output, f"the engine's cause is not in the output\n{output}"
    assert PID_LOOKUP_FAILURE not in output, f'the failure was reported as a PID lookup one\n{output}'
    assert READINESS_FAILURE not in output, f'the failure was reported as a readiness one\n{output}'
    # A failed launch that leaves its PID file behind makes the next start's pstatus() read the
    # engine as already running and skip it.
    assert not _engine_pid_files(), f'the failed start left {_engine_pid_files()} behind'
