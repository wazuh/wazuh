'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'wazuh-manager-apid' survives a transient conflict on its own port
       instead of giving up permanently. Regression test for #39231: the bind used to happen
       inside 'uvicorn.run()' (api/scripts/wazuh_manager_apid.py), which turns a failed bind into
       its own 'sys.exit(1)', so a port that was busy for a moment left apid down until someone
       restarted it by hand. The launcher now binds the sockets itself with a bounded, backed-off
       retry and hands them to uvicorn. Also covers the two behaviours that only show up in a
       live process: a stop issued while a retry is still waiting must actually stop apid, and the
       'Listening on' line must never be logged before a real bind exists.

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
    - https://github.com/wazuh/wazuh/issues/39231

tags:
    - manager_control
'''
import contextlib
import os
import signal
import socket
import subprocess
import time

import psutil
import pytest
import yaml

from wazuh_testing.constants.daemons import API_DAEMON
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.logs import WAZUH_API_LOG_FILE_PATH
from wazuh_testing.constants.paths.api import WAZUH_API_CONFIGURATION_FOLDER_PATH
from wazuh_testing.utils.services import check_all_daemon_status, wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

# The API daemon's own startup script. Both the real daemon and the '-t' config-validation
# invocation wazuh-manager-control also launches match this substring, so callers must filter out
# '-t' themselves. Same marker and reasoning as test_pid_collision_recovery.py.
APID_SCRIPT_MARKER = 'wazuh_manager_apid.py'

DEFAULT_API_PORT = 55000

# The retry budget in api/scripts/wazuh_manager_apid.py: BIND_MAX_RETRIES=5 retries on top of the
# first attempt, with a BIND_BACKOFF_BASE_SECONDS=2 exponential backoff, i.e. ~62s of waiting in
# the worst case. Releasing the port well inside that leaves several attempts to spare.
FIRST_BACKOFF_SECONDS = 2
TOTAL_BIND_BUDGET_SECONDS = 62

STATUS_TIMEOUT_SECONDS = 30
LOG_TIMEOUT_SECONDS = 30
STOP_TIMEOUT_SECONDS = 10

RETRY_WARNING = 'Could not bind'
LISTENING_MESSAGE = 'Listening on'


def _api_port():
    """Return the port apid binds, taken from the installed api.yaml or its packaged default."""
    config_file = os.path.join(WAZUH_API_CONFIGURATION_FOLDER_PATH, 'api.yaml')
    try:
        with open(config_file) as fp:
            config = yaml.safe_load(fp) or {}
    except FileNotFoundError:
        return DEFAULT_API_PORT
    return config.get('port', DEFAULT_API_PORT)


def _apid_processes():
    """Return the live apid daemon processes, skipping the short-lived '-t' config check."""
    found = []
    for proc in psutil.process_iter(attrs=['pid', 'cmdline']):
        cmdline = proc.info['cmdline'] or []
        if APID_SCRIPT_MARKER in ' '.join(cmdline) and '-t' not in cmdline:
            found.append(proc)
    return found


def _stop_apid():
    """Stop apid with SIGTERM and wait for it to go, the same signal the control script sends."""
    victims = _apid_processes()
    for proc in victims:
        with contextlib.suppress(psutil.NoSuchProcess):
            proc.send_signal(signal.SIGTERM)
    psutil.wait_procs(victims, timeout=STOP_TIMEOUT_SECONDS)
    for proc in _apid_processes():
        with contextlib.suppress(psutil.NoSuchProcess):
            proc.kill()


def _control_start_background():
    """Start whatever is not running via wazuh-manager-control, without waiting for it to finish.

    apid spends its whole retry window inside its own startup here, so the control script's launch
    loop cannot be waited on before the test has released the port.
    """
    return subprocess.Popen([WAZUH_CONTROL_PATH, 'start'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@contextlib.contextmanager
def _occupy(port):
    """Hold a listening socket on 'port' so apid's own bind gets EADDRINUSE.

    The socket listens: two sockets can share a port with SO_REUSEADDR only while neither is
    listening, which is not the conflict this reproduces.
    """
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(('0.0.0.0', port))  # nosec B104
    blocker.listen(1)
    try:
        yield blocker
    finally:
        blocker.close()


def _log_size():
    """Return the current size of api.log, used as the offset for everything read afterwards."""
    try:
        return os.path.getsize(WAZUH_API_LOG_FILE_PATH)
    except FileNotFoundError:
        return 0


def _log_since(offset):
    """Return the api.log content written after 'offset' bytes."""
    try:
        with open(WAZUH_API_LOG_FILE_PATH, errors='replace') as fp:
            fp.seek(offset)
            return fp.read()
    except FileNotFoundError:
        return ''


def _wait_for_log(offset, message, timeout=LOG_TIMEOUT_SECONDS):
    """Wait until 'message' shows up in api.log after 'offset'. Return the content or None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        content = _log_since(offset)
        if message in content:
            return content
        time.sleep(0.2)
    return None


@pytest.fixture()
def apid_stopped():
    """Stop apid for the test and leave the whole manager running afterwards.

    Every test here needs apid's port free before it can occupy it itself, and needs apid to be
    the process that races for it on the next start.
    """
    _stop_apid()
    yield
    start = _control_start_background()
    try:
        start.wait(timeout=TOTAL_BIND_BUDGET_SECONDS + STATUS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        start.kill()
        start.wait()
    wait_expected_daemon_status(timeout=STATUS_TIMEOUT_SECONDS)


def test_apid_recovers_from_transient_bind_conflict(apid_stopped):
    '''
    description:
        Occupies apid's port before starting the manager, releases it while apid is still inside
        its bind-retry window, and checks apid ends up running instead of staying down for good.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Stop 'wazuh-manager-apid' and leave its port free ('apid_stopped' fixture).
        - test:
            - Occupy the API port with a listening socket of this test's own.
            - Trigger 'wazuh-manager-control start' in the background.
            - Wait for apid to log at least one bind-retry warning.
            - Release the port.
            - Wait for 'wazuh-manager-apid' to report running.
        - teardown:
            - Bring every daemon back up ('apid_stopped' fixture), regardless of outcome.

    parameters:
        - apid_stopped:
            type: fixture
            brief: Stops apid before the test and restores the whole manager after it.

    assertions:
        - A busy port produces retry warnings rather than a single fatal error.
        - apid binds and reports running once the port is released, with no manual restart.
        - Exactly one 'Listening on' line is logged, i.e. only the successful bind announces one.

    input_description:
        No external test cases. The conflict is a socket this test binds itself.

    expected_output:
        - r'Could not bind .*: \\[Errno 98\\] Address already in use' (from 'api.log')
        - r'Listening on' (from 'api.log')
        - r'wazuh-manager-apid is running...' (from 'wazuh-manager-control status')

    tags:
        - manager_control
    '''
    port = _api_port()
    offset = _log_size()
    start = None
    try:
        with _occupy(port):
            start = _control_start_background()
            content = _wait_for_log(offset, RETRY_WARNING)
            assert content is not None, (
                f"'{RETRY_WARNING}' never appeared in api.log: apid did not retry the busy port "
                f'(#39231 regression). Log since the start:\n{_log_since(offset)}'
            )

        wait_expected_daemon_status(target_daemon=API_DAEMON, running_condition=True,
                                    timeout=TOTAL_BIND_BUDGET_SECONDS)
        status = check_all_daemon_status()
        assert status.get(API_DAEMON) is True, (
            f"'{API_DAEMON}' did not recover after the port was released: {status}"
        )

        content = _wait_for_log(offset, LISTENING_MESSAGE)
        assert content is not None, f'apid is running but never logged a {LISTENING_MESSAGE!r} line'
        assert content.count(LISTENING_MESSAGE) == 1, (
            f'expected exactly one {LISTENING_MESSAGE!r} line, one per successful bind, '
            f'got {content.count(LISTENING_MESSAGE)}:\n{content}'
        )
    finally:
        if start is not None and start.poll() is None:
            # 'wazuh-manager-control start' holds the control script's own start lock and would
            # race the fixture's teardown, which starts the manager again.
            start.kill()
            start.wait()


def test_apid_stop_during_retry_actually_stops(apid_stopped):
    '''
    description:
        Checks that a stop issued while apid is still waiting to retry a busy port actually ends
        the process, instead of deleting its pidfiles and leaving it retrying unseen for the rest
        of its backoff budget.

        'exit_handler' only removes pidfiles; it never unwinds the process. The retry wait is
        therefore backed by a 'threading.Event' the handler also sets, and that wiring is easy to
        get subtly wrong (waiting on a different event instance, or checking it after the wait
        instead of through the wait's own return value) in a way unit tests would not catch.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Stop 'wazuh-manager-apid' and leave its port free ('apid_stopped' fixture).
        - test:
            - Occupy the API port and keep it occupied for the whole test.
            - Trigger 'wazuh-manager-control start' in the background.
            - Wait for apid to log a bind-retry warning, i.e. it is inside a retry wait.
            - Send SIGTERM to the apid process, the signal the control script's stop sends.
            - Assert the process is gone well before its retry budget would have run out.
        - teardown:
            - Bring every daemon back up ('apid_stopped' fixture), regardless of outcome.

    parameters:
        - apid_stopped:
            type: fixture
            brief: Stops apid before the test and restores the whole manager after it.

    assertions:
        - The apid process itself exits during a retry wait, not only its pidfiles.

    input_description:
        No external test cases. The conflict is a socket this test binds itself.

    expected_output:
        - r'Shutdown requested while waiting to retry the bind' (from 'api.log')

    tags:
        - manager_control
    '''
    port = _api_port()
    offset = _log_size()
    start = None
    try:
        with _occupy(port):
            start = _control_start_background()
            assert _wait_for_log(offset, RETRY_WARNING) is not None, (
                'Precondition failed: apid never logged a bind-retry warning, so nothing was '
                f'waiting to be interrupted. Log since the start:\n{_log_since(offset)}'
            )

            retrying = _apid_processes()
            assert retrying, 'Precondition failed: no apid process was alive to signal'

            # SIGTERM is exactly what 'wazuh-manager-control stop' sends apid. It is sent
            # directly here because a concurrent control 'stop' would contend with the control
            # 'start' still in flight above for the start-script lock.
            for proc in retrying:
                proc.send_signal(signal.SIGTERM)

            gone, alive = psutil.wait_procs(retrying, timeout=STOP_TIMEOUT_SECONDS)
            assert not alive, (
                f'apid kept running {STOP_TIMEOUT_SECONDS}s after SIGTERM: the bind-retry wait '
                f'is not interruptible, so a stop during a retry leaves apid alive with its '
                f'pidfiles already deleted (PIDs still up: {[proc.pid for proc in alive]})'
            )
    finally:
        if start is not None and start.poll() is None:
            start.kill()
            start.wait()


def test_listening_on_message_reflects_a_real_bind(apid_stopped):
    '''
    description:
        Checks that the 'Listening on' line is only logged once a socket is really bound. It is
        emitted from the ASGI lifespan startup hook (api/api/signals.py), which uvicorn runs
        before it would open a socket of its own, so before this fix the line was logged even on
        a start that never managed to bind. The integration environment's own readiness check
        greps api.log for this exact string.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Stop 'wazuh-manager-apid' and leave its port free ('apid_stopped' fixture).
        - test:
            - Occupy the API port and keep it occupied past the first retry interval.
            - Trigger 'wazuh-manager-control start' in the background.
            - Assert no 'Listening on' line is logged while the port is still occupied.
            - Release the port and assert the line appears only then.
        - teardown:
            - Bring every daemon back up ('apid_stopped' fixture), regardless of outcome.

    parameters:
        - apid_stopped:
            type: fixture
            brief: Stops apid before the test and restores the whole manager after it.

    assertions:
        - 'Listening on' is absent from api.log for as long as the bind keeps failing.
        - 'Listening on' appears after the port is released and the bind succeeds.

    input_description:
        No external test cases. The conflict is a socket this test binds itself.

    expected_output:
        - r'Listening on' (from 'api.log', only after the port is released)

    tags:
        - manager_control
    '''
    port = _api_port()
    offset = _log_size()
    start = None
    try:
        with _occupy(port):
            start = _control_start_background()
            assert _wait_for_log(offset, RETRY_WARNING) is not None, (
                'Precondition failed: apid never logged a bind-retry warning. Log since the '
                f'start:\n{_log_since(offset)}'
            )
            # Stay busy past the first backoff so at least one further attempt has failed by the
            # time the assertion below runs.
            time.sleep(FIRST_BACKOFF_SECONDS * 2)
            content = _log_since(offset)
            assert LISTENING_MESSAGE not in content, (
                f'{LISTENING_MESSAGE!r} was logged while the port was still occupied, so it does '
                f'not mean the API is reachable:\n{content}'
            )

        assert _wait_for_log(offset, LISTENING_MESSAGE, timeout=TOTAL_BIND_BUDGET_SECONDS) is not None, (
            f'{LISTENING_MESSAGE!r} never appeared after the port was released:\n{_log_since(offset)}'
        )
        wait_expected_daemon_status(target_daemon=API_DAEMON, running_condition=True,
                                    timeout=STATUS_TIMEOUT_SECONDS)
    finally:
        if start is not None and start.poll() is None:
            start.kill()
            start.wait()
