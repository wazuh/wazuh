'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check the stale-lock recovery of 'wazuh-manager-control' (lock() in
       src/init/wazuh-server.sh). The script serializes start/stop/status with a mkdir-based
       mutex, 'var/start-script-lock', and records the owner's pid in a file inside it in a
       separate step. Regression tests for #39114: a lock left behind without that pid file
       (the owner died between the two steps) was never reclaimed, so every later 'start' and
       'status' failed with 'Another instance is locking this process' until the directory was
       removed by hand. They also pin the guards the recovery relies on: a lock whose owner has
       not written its pid yet is live, not stale, and the exclusive marker that serializes the
       recovery itself is only force-removed after several consecutive busy rounds.

components:
    - manager

suite: manager_control

targets:
    - manager

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/39114

tags:
    - manager_control
'''
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.variables import VAR_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

LOCK = Path(VAR_PATH, 'start-script-lock')
LOCK_PID = LOCK / 'pid'
RECLAIM_MARKER = Path(f'{LOCK}.reclaim')
LOCK_ERROR = 'Another instance is locking this process'

# lock() retries once per second. A pid-less lock is reclaimed after 3 consecutive rounds, a
# leaked reclaim marker is force-removed after 5 consecutive busy rounds, and the caller gives up
# after MAX_ITERATION (40) rounds.
RECLAIM_BUDGET_SECONDS = 20
# Long enough for the pid-less gate (3 rounds) to have opened several times over if a guard were
# missing, short enough not to sit through the whole 40-round give-up.
STEAL_WINDOW_SECONDS = 10


def _status(timeout):
    """Run 'wazuh-manager-control status' and return (CompletedProcess, elapsed seconds).

    'status' takes the same lock as 'start' and 'stop' and is what the container healthchecks
    run, so it exercises lock() without touching any daemon.
    """
    started = time.monotonic()
    result = subprocess.run([WAZUH_CONTROL_PATH, 'status'], capture_output=True, text=True,
                            timeout=timeout)
    return result, time.monotonic() - started


def _dead_pid():
    """Return the pid of a process that has already exited."""
    proc = subprocess.Popen(['true'])
    proc.wait()
    return proc.pid


def _remove_lock_state():
    shutil.rmtree(LOCK, ignore_errors=True)
    if RECLAIM_MARKER.is_dir():
        RECLAIM_MARKER.rmdir()


@pytest.fixture()
def free_lock():
    """Start from no lock at all and leave none behind, whatever the test did.

    Another control invocation may still be finishing (the previous test's teardown runs
    'wazuh-manager-control start'); wait for it to release the lock instead of planting on top
    of a live owner.
    """
    deadline = time.monotonic() + 60
    while LOCK.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert not LOCK.exists(), 'another wazuh-manager-control invocation still holds the lock'
    _remove_lock_state()
    yield
    _remove_lock_state()


@pytest.fixture()
def live_owner():
    """A process standing in for a control script that holds, or is acquiring, the lock."""
    owner = subprocess.Popen(['sleep', '300'])
    yield owner
    owner.kill()
    owner.wait()


@pytest.mark.parametrize('leaked_marker', [False, True], ids=['no_marker', 'leaked_marker'])
def test_pidless_lock_is_reclaimed(free_lock, leaked_marker):
    '''
    description:
        A lock directory with no pid file is what an owner leaves behind when it dies between
        'mkdir ${LOCK}' and writing its pid. It must be reclaimed within a few retry rounds,
        also when the previous reclaimer died holding the exclusive reclaim marker, so 'status'
        (the container healthcheck) never reports the lock error. Regression for #39114.

    test_phases:
        - setup:
            - Create the lock directory empty, optionally with a leaked reclaim marker next to it.
        - test:
            - Run 'wazuh-manager-control status' and check it neither fails on the lock nor takes
              the full 40-round give-up.
        - teardown:
            - Remove any lock state.

    assertions:
        - The lock error is not printed.
        - The lock is reclaimed well before the 40-round give-up.
        - Neither the lock nor the reclaim marker is left behind.
    '''
    LOCK.mkdir()
    if leaked_marker:
        RECLAIM_MARKER.mkdir()

    result, elapsed = _status(timeout=60)

    assert LOCK_ERROR not in result.stdout, result.stdout
    assert elapsed < RECLAIM_BUDGET_SECONDS, f'reclaim took {elapsed:.1f}s'
    assert not LOCK.exists()
    assert not RECLAIM_MARKER.exists()


def test_dead_pid_lock_is_reclaimed(free_lock):
    '''
    description:
        A lock whose recorded pid no longer exists is stale right away, without the consecutive
        rounds a pid-less lock needs, and must be reclaimed on the first round it is seen.

    test_phases:
        - setup:
            - Create the lock directory with a pid file naming an exited process.
        - test:
            - Run 'wazuh-manager-control status'.
        - teardown:
            - Remove any lock state.

    assertions:
        - The lock error is not printed.
        - The lock is reclaimed on the first rounds.
        - Neither the lock nor the reclaim marker is left behind.
    '''
    LOCK.mkdir()
    LOCK_PID.write_text(f'{_dead_pid()}\n')

    result, elapsed = _status(timeout=60)

    assert LOCK_ERROR not in result.stdout, result.stdout
    assert elapsed < 5, f'reclaim of a dead pid took {elapsed:.1f}s'
    assert not LOCK.exists()
    assert not RECLAIM_MARKER.exists()


def test_leaked_marker_is_only_removed_after_consecutive_busy_rounds(free_lock):
    '''
    description:
        The reclaim marker is force-removed only after 5 consecutive rounds of finding it busy;
        that budget must start over every time, or a marker held by a live reclaimer is deleted
        on sight once a caller has force-removed one before.

    test_phases:
        - setup:
            - Create the lock directory empty with a leaked reclaim marker, and recreate the marker
              once, the moment the caller force-removes it.
        - test:
            - Run 'wazuh-manager-control status' and measure how long the reclaim takes.
        - teardown:
            - Remove any lock state.

    assertions:
        - The recreated marker costs the caller 5 more busy rounds, not 1.
        - The lock is still reclaimed, with nothing left behind.
    '''
    LOCK.mkdir()
    RECLAIM_MARKER.mkdir()

    def recreate_marker_once():
        while RECLAIM_MARKER.exists():
            time.sleep(0.05)
        RECLAIM_MARKER.mkdir()

    threading.Thread(target=recreate_marker_once, daemon=True).start()

    result, elapsed = _status(timeout=60)

    assert LOCK_ERROR not in result.stdout, result.stdout
    # 3 rounds to open the gate, 5 busy rounds per marker, twice.
    assert elapsed >= 12, f'the recreated marker was removed on sight ({elapsed:.1f}s)'
    assert elapsed < RECLAIM_BUDGET_SECONDS, f'reclaim took {elapsed:.1f}s'
    assert not LOCK.exists()
    assert not RECLAIM_MARKER.exists()


def test_lock_mid_acquisition_is_not_stolen(free_lock, live_owner):
    '''
    description:
        Between 'mkdir ${LOCK}' and writing its pid, a live owner's lock looks exactly like an
        orphaned one. A caller must wait several consecutive pid-less rounds before reclaiming,
        so an owner that records its pid in time keeps its lock.

    test_phases:
        - setup:
            - Create the lock directory empty and record a live process as its owner 1.5 s later.
        - test:
            - Run 'wazuh-manager-control status' for longer than the pid-less gate.
        - teardown:
            - Stop the owner and remove any lock state.

    assertions:
        - 'status' is still waiting after the gate would have opened.
        - The lock still belongs to the owner.
    '''
    LOCK.mkdir()
    threading.Timer(1.5, lambda: LOCK_PID.write_text(f'{live_owner.pid}\n')).start()

    with pytest.raises(subprocess.TimeoutExpired):
        _status(timeout=STEAL_WINDOW_SECONDS)

    assert LOCK_PID.read_text().strip() == str(live_owner.pid)
    assert not RECLAIM_MARKER.exists()


def test_dead_pid_rounds_do_not_open_the_pidless_gate(free_lock, live_owner):
    '''
    description:
        The consecutive-round gate protecting a pid-less lock must count pid-less rounds only.
        Rounds spent on a dead pid while another caller holds the reclaim marker say nothing
        about the lock that caller is about to recreate, so once the marker is released and a
        new owner is mid-acquisition, that owner's lock must not be taken on the first sight
        of it.

    test_phases:
        - setup:
            - Create the lock directory with a dead pid and a busy reclaim marker.
            - After 3.5 s, stand in for the marker holder: release the marker, recreate the lock
              empty and record a live owner in it 1.5 s later.
        - test:
            - Run 'wazuh-manager-control status' for longer than the pid-less gate.
        - teardown:
            - Stop the owner and remove any lock state.

    assertions:
        - 'status' is still waiting after the gate would have opened.
        - The lock still belongs to the new owner.
    '''
    LOCK.mkdir()
    LOCK_PID.write_text(f'{_dead_pid()}\n')
    RECLAIM_MARKER.mkdir()

    def hand_over_to_new_owner():
        RECLAIM_MARKER.rmdir()
        shutil.rmtree(LOCK)
        LOCK.mkdir()
        time.sleep(1.5)
        LOCK_PID.write_text(f'{live_owner.pid}\n')

    threading.Timer(3.5, hand_over_to_new_owner).start()

    with pytest.raises(subprocess.TimeoutExpired):
        _status(timeout=STEAL_WINDOW_SECONDS)

    assert LOCK_PID.read_text().strip() == str(live_owner.pid)
    assert not RECLAIM_MARKER.exists()
