"""
Copyright (C) Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Tests of the start-script lock that wazuh-control (agent, src/init/wazuh-client.sh) and
wazuh-manager-control (src/init/wazuh-server.sh) share: lock() serializes start, stop and status with a
mkdir-based mutex, 'var/start-script-lock', whose owner records its pid in a file inside it, and
reclaims a lock whose owner is gone through an exclusive marker, 'var/start-script-lock.reclaim', that
records its holder's pid the same way. The suites that test each script (test_agent_control,
test_manager_control) import these tests, so both run them against their own control script.
"""
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.variables import VAR_PATH

LOCK = Path(VAR_PATH, 'start-script-lock')
LOCK_PID = LOCK / 'pid'
RECLAIM_MARKER = Path(f'{LOCK}.reclaim')
RECLAIM_PID = RECLAIM_MARKER / 'pid'
LOCK_ERROR = 'Another instance is locking this process'

# lock() retries once per second. A pid-less lock is reclaimed after 3 consecutive rounds and one more
# second of grace, a pid-less reclaim marker is force-removed after 5 consecutive rounds, one whose
# holder is dead right away, and the caller gives up after MAX_ITERATION (40) rounds.
RECLAIM_BUDGET_SECONDS = 20
# Long enough for the pid-less gates (3 and 5 rounds) to have opened several times over if a guard
# were missing, short enough not to sit through the whole 40-round give-up.
STEAL_WINDOW_SECONDS = 10


def _status(timeout):
    """Run the control script's 'status' and return (CompletedProcess, elapsed seconds).

    'status' takes the same lock as 'start' and 'stop', so it exercises lock() without touching any
    daemon.
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
    shutil.rmtree(RECLAIM_MARKER, ignore_errors=True)


@pytest.fixture()
def free_lock():
    """Start from no lock at all and leave none behind, whatever the test did.

    Another control invocation may still be finishing (a previous test's teardown may start the
    service); wait for it to release the lock instead of planting on top of a live owner.
    """
    deadline = time.monotonic() + 60
    while LOCK.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert not LOCK.exists(), 'another control script invocation still holds the lock'
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
        also when the previous reclaimer died holding the exclusive reclaim marker before it wrote
        its own pid, so 'status' never reports the lock error. Regression for #39114.

    test_phases:
        - setup:
            - Create the lock directory empty, optionally with a pid-less reclaim marker next to it.
        - test:
            - Run the control script's 'status' and check it neither fails on the lock nor takes
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
            - Run the control script's 'status'.
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
        A reclaim marker with no pid is force-removed only after 5 consecutive rounds of finding it
        busy; that budget must start over every time, or a marker whose holder has just created it
        is deleted on sight once a caller has force-removed one before.

    test_phases:
        - setup:
            - Create the lock directory empty with a pid-less reclaim marker, and recreate the
              marker once, the moment the caller force-removes it.
        - test:
            - Run the control script's 'status' and measure how long the reclaim takes.
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


def test_marker_of_a_live_reclaimer_is_kept(free_lock, live_owner):
    '''
    description:
        The reclaim marker records the pid of the run holding it. While that run is alive the
        marker is its own, however long it holds it, and must not be removed: another caller would
        then reclaim the lock as well, and both would go ahead.

    test_phases:
        - setup:
            - Create the lock directory with a dead pid, and the reclaim marker with the pid of a
              live process.
        - test:
            - Run the control script's 'status' for longer than the 5 rounds after which a
              pid-less marker is removed.
        - teardown:
            - Stop the process and remove any lock state.

    assertions:
        - 'status' is still waiting.
        - The marker still belongs to the live process.
    '''
    LOCK.mkdir()
    LOCK_PID.write_text(f'{_dead_pid()}\n')
    RECLAIM_MARKER.mkdir()
    RECLAIM_PID.write_text(f'{live_owner.pid}\n')

    with pytest.raises(subprocess.TimeoutExpired):
        _status(timeout=STEAL_WINDOW_SECONDS)

    assert RECLAIM_PID.read_text().strip() == str(live_owner.pid)


def test_marker_of_a_dead_reclaimer_is_removed(free_lock):
    '''
    description:
        A reclaim marker whose recorded pid no longer exists was left by a caller that died holding
        it. It is removed on sight, without the rounds a pid-less marker needs, and the lock is
        reclaimed.

    test_phases:
        - setup:
            - Create the lock directory and the reclaim marker, each with a pid file naming an
              exited process.
        - test:
            - Run the control script's 'status'.
        - teardown:
            - Remove any lock state.

    assertions:
        - The lock error is not printed.
        - The lock is reclaimed within the first rounds.
        - Neither the lock nor the reclaim marker is left behind.
    '''
    LOCK.mkdir()
    LOCK_PID.write_text(f'{_dead_pid()}\n')
    RECLAIM_MARKER.mkdir()
    RECLAIM_PID.write_text(f'{_dead_pid()}\n')

    result, elapsed = _status(timeout=60)

    assert LOCK_ERROR not in result.stdout, result.stdout
    assert elapsed < 5, f'reclaim past a dead marker took {elapsed:.1f}s'
    assert not LOCK.exists()
    assert not RECLAIM_MARKER.exists()


# Rounds come once a second. An owner that writes its pid at 2.5 s is only saved by the 3-round gate;
# one that writes it at 3.5 s, after the gate opened at 3 s, only by the second of grace before the
# lock is replaced.
@pytest.mark.parametrize('owner_delay', [2.5, 3.5], ids=['within_the_gate', 'within_the_grace'])
def test_lock_mid_acquisition_is_not_stolen(free_lock, live_owner, owner_delay):
    '''
    description:
        Between 'mkdir ${LOCK}' and writing its pid, a live owner's lock looks exactly like an
        orphaned one. A caller must wait several consecutive pid-less rounds, and then a second
        more, before reclaiming, so an owner that records its pid in time keeps its lock.

    test_phases:
        - setup:
            - Create the lock directory empty and record a live process as its owner 2.5 s later,
              or 3.5 s later.
        - test:
            - Run the control script's 'status' for longer than the pid-less gate.
        - teardown:
            - Stop the owner and remove any lock state.

    assertions:
        - 'status' is still waiting after the gate would have opened.
        - The lock still belongs to the owner.
    '''
    LOCK.mkdir()
    threading.Timer(owner_delay, lambda: LOCK_PID.write_text(f'{live_owner.pid}\n')).start()

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
            - Create the lock directory with a dead pid and a pid-less reclaim marker.
            - After 3.5 s, stand in for the marker holder: release the marker, recreate the lock
              empty and record a live owner in it 2 s later, past the point where the 3 dead-pid
              rounds would have opened the gate had they been counted.
        - test:
            - Run the control script's 'status' for longer than the pid-less gate.
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
        time.sleep(2)
        LOCK_PID.write_text(f'{live_owner.pid}\n')

    threading.Timer(3.5, hand_over_to_new_owner).start()

    with pytest.raises(subprocess.TimeoutExpired):
        _status(timeout=STEAL_WINDOW_SECONDS)

    assert LOCK_PID.read_text().strip() == str(live_owner.pid)
    assert not RECLAIM_MARKER.exists()
