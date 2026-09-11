'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check that 'wazuh-manager-apid' survives a restart after an unclean stop
       when a stale pidfile left behind by the previous instance names the exact PID the kernel
       hands to the freshly started process. Regression test for #38695: before the fix,
       'clean_pid_files()' (framework/wazuh/core/utils.py) killed any live process matching a
       stale pidfile's PID and whose cmdline contained the daemon name, without checking whether
       that live process was actually the one that wrote the file — so a daemon whose own new
       instance recycled a stale PID killed itself mid-startup.

components:
    - api

suite: manager_control

targets:
    - manager

daemons:
    - wazuh-manager-apid

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/38695

tags:
    - manager_control
'''
import os
import subprocess
import time

import psutil
import pytest

from wazuh_testing.constants.daemons import API_DAEMON
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.utils.services import check_all_daemon_status, wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

# The API daemon's own startup script (api/scripts/wazuh_manager_apid.py). Both the real daemon
# and the '-t' config-validation invocation wazuh-manager-control also launches match this
# substring, so callers must filter out '-t' themselves.
APID_SCRIPT_MARKER = 'wazuh_manager_apid.py'

# Generous margin for the restarted apid process to appear and for wazuh-manager-control's own
# per-daemon startup loop to finish; this is wall-clock, not CPU, time.
RACE_TIMEOUT_SECONDS = 20
STATUS_TIMEOUT_SECONDS = 30


def _control_start():
    """Run 'wazuh-manager-control start' directly and wait for its launch loop to finish.

    Not control_service('start'): on Linux that goes through 'service wazuh-manager start', and
    the unit (Type=forking, KillMode=process) stays active while any daemon is alive, so systemd
    treats the start as a no-op and a single killed daemon is never relaunched. The control
    script itself starts whatever is not running and reports 'already running' for the rest.
    """
    subprocess.run([WAZUH_CONTROL_PATH, 'start'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _kill_apid_family_uncleanly():
    """SIGKILL every live process whose cmdline names the apid script, leaving their pidfiles.

    A graceful stop (SIGTERM) runs wazuh_manager_apid.py's own exit_handler, which deletes its
    pidfile itself (exit_handler in api/scripts/wazuh_manager_apid.py). SIGKILL skips that handler,
    which is the actual precondition from #38695: an unclean stop (docker kill, OOM, a crash)
    leaves the pidfile behind for the next start to find.

    Returns
    -------
    list of int
        PIDs that were killed.
    """
    victims = [
        proc for proc in psutil.process_iter(attrs=['pid', 'cmdline'])
        if APID_SCRIPT_MARKER in ' '.join(proc.info['cmdline'] or [])
    ]
    for proc in victims:
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(victims, timeout=5)
    return [proc.pid for proc in victims]


def _race_and_plant_collision(before_pids, timeout=RACE_TIMEOUT_SECONDS):
    """Detect the freshly (re)started apid main process and plant a stale pidfile on its own PID.

    Reproduces the exact precondition from #38695: a stale '.pid' names a PID number that the
    kernel later hands to the daemon's own new instance. Detected by diffing the live PID set
    against 'before_pids' (captured right before triggering the restart), filtered to the
    process whose cmdline contains the apid script but skipping the '-t' config-validation
    invocation the control script also launches ahead of the real one (it exits almost
    immediately and is never the long-running daemon).

    This is a race against wazuh_manager_apid.py's own startup: the plant must land before that
    process reaches its own 'clean_pid_files()' call. In practice this window is generous (the
    API daemon does non-trivial import and setup work first), but this is still timing-sensitive
    by nature, not a fixed sequence — that is the actual bug being tested for.

    Parameters
    ----------
    before_pids : set of int
        PIDs alive right before the restart was triggered.
    timeout : int
        Seconds to keep looking before giving up.

    Returns
    -------
    tuple of (int or None, str or None)
        The colliding PID and the pidfile path written for it, or (None, None) on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        for proc in psutil.process_iter(attrs=['pid', 'cmdline']):
            if proc.info['pid'] in before_pids:
                continue
            cmdline = proc.info['cmdline'] or []
            if APID_SCRIPT_MARKER not in ' '.join(cmdline):
                continue
            if '-t' in cmdline:
                continue

            collision_file = os.path.join(VAR_RUN_PATH, f'wazuh-manager-apid_auth-{proc.pid}.pid')
            with open(collision_file, 'w') as fp:
                fp.write(f'{proc.pid}\n')
            return proc.pid, collision_file
        # A tight busy-loop here would peg a CPU core for up to 'timeout' seconds and could
        # itself starve the apid process this is racing against of the CPU time it needs to
        # reach its own clean_pid_files() call. 10ms still gives ~100 checks/second, far more
        # resolution than this race needs.
        time.sleep(0.01)
    return None, None


@pytest.fixture()
def wazuh_running():
    """Ensure every daemon is up before the test, and leave the manager fully running after."""
    _control_start()
    wait_expected_daemon_status(timeout=STATUS_TIMEOUT_SECONDS)
    yield
    # The test may have left apid down (that is the failure mode under test); bring everything
    # back up regardless of the outcome so later tests in the suite start from a clean state.
    # Mirrors the setup above: _control_start() returning only means the control script's own
    # launch loop finished, not that every daemon is actually up yet -- without this wait, a
    # still-initializing manager can bleed into whatever runs next.
    _control_start()
    wait_expected_daemon_status(timeout=STATUS_TIMEOUT_SECONDS)


def test_apid_survives_pid_collision_after_unclean_stop(wazuh_running):
    '''
    description:
        Simulates an unclean stop of 'wazuh-manager-apid' that leaves its pidfile behind, then
        forces the freshly restarted instance to collide with that stale PID, and checks that it
        starts anyway instead of killing itself.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Ensure every manager daemon is running ('wazuh_running' fixture).
        - test:
            - SIGKILL every live 'wazuh_manager_apid.py' process, leaving pidfiles on disk.
            - Trigger 'wazuh-manager-control start' in the background.
            - Race to detect the freshly started apid process and plant a stale pidfile naming
              its own PID, before it reaches its own pidfile cleanup.
            - Wait for 'wazuh-manager-apid' to report running.
        - teardown:
            - Bring every daemon back up ('wazuh_running' fixture), regardless of outcome.

    parameters:
        - wazuh_running:
            type: fixture
            brief: Ensures the manager is fully up before the test and after it.

    assertions:
        - The restarted 'wazuh-manager-apid' process is not killed by 'clean_pid_files()' due to
          the planted PID collision.
        - The planted pidfile no longer exists afterwards, proving 'clean_pid_files()' actually
          processed it. If the plant lost its race against the restart (apid was not observed in
          time, or it passed its cleanup before the file landed) the run is skipped, since it
          exercised nothing: only a running apid with the plant still present skips, anything
          else stays a failure.

    input_description:
        No external test cases. The collision target is the real PID of the process spawned by
        this test's own restart, detected at runtime.

    expected_output:
        - r'wazuh-manager-apid is running...' (from 'wazuh-manager-control status')

    tags:
        - manager_control
    '''
    killed_pids = _kill_apid_family_uncleanly()
    assert killed_pids, "Precondition failed: no 'wazuh_manager_apid.py' process was running to kill"

    before_pids = {proc.pid for proc in psutil.process_iter()}
    collision_file = None
    try:
        start = subprocess.Popen([WAZUH_CONTROL_PATH, 'start'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            collided_pid, collision_file = _race_and_plant_collision(before_pids)
            start.wait(timeout=60)
        finally:
            # A wait() timeout (or any other failure in this block) must not leave
            # 'wazuh-manager-control start' running in the background: it holds the control
            # script's own start-script-lock and would race the 'wazuh_running' fixture's
            # teardown, which also calls 'wazuh-manager-control start'.
            if start.poll() is None:
                start.kill()
                start.wait()

        # The plant races apid's own startup, so losing that race says nothing about the fix.
        # Still, apid must be up before skipping: a missing apid here is a real failure, and
        # wait_expected_daemon_status() raises TimeoutError on it.
        wait_expected_daemon_status(target_daemon=API_DAEMON, running_condition=True,
                                     timeout=STATUS_TIMEOUT_SECONDS)
        if collided_pid is None:
            pytest.skip("Lost the race: the restarted 'wazuh-manager-apid' was not observed in time to "
                        "plant a PID collision; nothing was exercised")

        status = check_all_daemon_status()
        assert status.get(API_DAEMON) is True, (
            f"'{API_DAEMON}' did not survive the PID collision with its own stale pidfile "
            f"(collided PID {collided_pid}, planted at '{collision_file}') — #38695 regression: {status}"
        )

        if os.path.exists(collision_file):
            pytest.skip(f"Lost the race: planted pidfile '{collision_file}' was never processed by "
                        "'clean_pid_files()' (apid passed its cleanup first); nothing was exercised")
    finally:
        # Any assertion above can fail before 'clean_pid_files()' gets a chance to remove the
        # plant itself, which would otherwise leave a root-owned stale pidfile naming a PID that
        # was live when it was written -- the exact precondition #38695 needs, left behind by
        # the test instead of deliberately reproduced by it.
        if collision_file and os.path.exists(collision_file):
            os.remove(collision_file)


def test_apid_spares_unrelated_process_with_recycled_pid(wazuh_running):
    '''
    description:
        Plants a stale pidfile that names the PID of an unrelated live decoy process (not
        'wazuh-manager-apid' itself), backdated so the decoy's own creation time is after the
        file's mtime -- a recycled PID, the general case 'clean_pid_files()' docstring describes.
        Restarts 'wazuh-manager-apid' after an unclean stop and checks the decoy survives.

        This targets the 'predates_file' half of the fix specifically: 'test_apid_survives_pid_
        collision_after_unclean_stop' can only ever collide a stale pidfile against the
        restarted launcher's own PID, which is spared by the separate 'own_pid' check regardless
        of what 'predates_file' computes. Here the colliding PID belongs to a different process,
        so only a correct 'predates_file' result keeps it alive.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Ensure every manager daemon is running ('wazuh_running' fixture).
        - test:
            - SIGKILL every live 'wazuh_manager_apid.py' process, leaving pidfiles on disk.
            - Spawn a decoy process whose cmdline names the apid script but is not apid.
            - Plant a stale pidfile naming the decoy's PID, with its mtime backdated by an hour
              so the decoy (created just now) reads as having recycled that PID.
            - Trigger 'wazuh-manager-control start' and wait for 'wazuh-manager-apid' to report
              running.
            - Assert the decoy is still alive and the planted pidfile was removed.
        - teardown:
            - Kill the decoy process.
            - Bring every daemon back up ('wazuh_running' fixture), regardless of outcome.

    parameters:
        - wazuh_running:
            type: fixture
            brief: Ensures the manager is fully up before the test and after it.

    assertions:
        - 'clean_pid_files()' does not kill a live, unrelated process just because its PID
          matches a stale pidfile and its cmdline happens to name the daemon.
        - The planted pidfile no longer exists afterwards, proving 'clean_pid_files()' actually
          evaluated it instead of the restart finishing before it was ever read.

    input_description:
        No external test cases. The collision target is a decoy process this test spawns itself.

    expected_output:
        - r'wazuh-manager-apid is running...' (from 'wazuh-manager-control status')

    tags:
        - manager_control
    '''
    killed_pids = _kill_apid_family_uncleanly()
    assert killed_pids, "Precondition failed: no 'wazuh_manager_apid.py' process was running to kill"

    decoy = subprocess.Popen(
        ['python3', '-c', 'import time; time.sleep(120)', APID_SCRIPT_MARKER],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    collision_file = None
    try:
        collision_file = os.path.join(VAR_RUN_PATH, f'wazuh-manager-apid_auth-{decoy.pid}.pid')
        with open(collision_file, 'w') as fp:
            fp.write(f'{decoy.pid}\n')

        backdated = time.time() - 3600
        os.utime(collision_file, (backdated, backdated))

        _control_start()
        wait_expected_daemon_status(target_daemon=API_DAEMON, running_condition=True,
                                     timeout=STATUS_TIMEOUT_SECONDS)

        assert decoy.poll() is None, (
            f"Decoy process {decoy.pid} was killed: 'predates_file' wrongly treated a live, "
            "unrelated process as the stale pidfile's owner"
        )
        assert not os.path.exists(collision_file), (
            f"Planted pidfile '{collision_file}' was never processed by 'clean_pid_files()' "
            "— this run did not actually test the recycled-PID case"
        )
    finally:
        decoy.kill()
        decoy.wait()
        if collision_file and os.path.exists(collision_file):
            os.remove(collision_file)
