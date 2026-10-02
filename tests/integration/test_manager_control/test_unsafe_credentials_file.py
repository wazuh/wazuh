'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'wazuh-manager-control' refuses to start (or restart) the manager when
       the shared credentials file is unsafe, and that it says so. checkcredentials() in
       src/init/wazuh-server.sh runs the credentials resolver in '--check' mode before anything
       else: a file that is not a regular 0600 root:root file, a base directory or an ancestor that
       is group- or world-writable, or a symbolic link, must produce the resolver's line, the
       'Unsafe credentials file. Exiting' message (or, with '-j', the JSON error 22), a non-zero
       exit code, no daemon started and, on 'restart', no daemon stopped. Regression tests for
       #39852: the refusal used to surface as an unrelated "Invalid configuration" error, or
       not at all. The credentials directory is redirected with WAZUH_BASE_DIR to a private tree
       under /root, so the real /etc/wazuh is never touched.

components:
    - manager

suite: manager_control

targets:
    - manager

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/39852

tags:
    - manager_control
'''
import json
import os
import pwd
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.variables import VAR_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

try:
    pwd.getpwnam('daemon')
    HAS_DAEMON_USER = True
except KeyError:
    HAS_DAEMON_USER = False

RUN_DIR = Path(VAR_PATH, 'run')
SHARED_HELPER = Path(VAR_PATH).parent / 'lib' / 'wazuh-credentials.sh'
MANAGER_LOG = Path(WAZUH_LOG_PATH)
CREDENTIALS_CONTENT = "WAZUH_INDEXER_MANAGER_PASSWORD='Unused.Value01'\n"
UNSAFE_MESSAGE = 'Unsafe credentials file. Exiting'
RESOLVER_VERDICT = 'resolve-credentials: UNSAFE'
RESOLVER_RULE = 'it must be a regular file, 0600 root:root'
LOG_ERROR = 'wazuh-manager-control: ERROR: unsafe credentials file'
INVALID_CONFIG = 'Invalid configuration at'
JSON_ERROR = {'error': 22, 'message': 'Unsafe credentials file.'}
START_TIMEOUT = 300
STOP_TIMEOUT = 120
PLAIN_ENV_DROP = ('WAZUH_BASE_DIR', 'WAZUH_MANAGER_API_PASSWORD', 'WAZUH_MANAGER_WUI_PASSWORD',
                  'WAZUH_INDEXER_MANAGER_PASSWORD')

# case -> expected line of the shared library, in stderr. '{base}' and '{tmp}' are filled per tree.
UNSAFE_CASES = {
    'owner': 'file must be owned by root:root',
    'group': 'file must be owned by root:root',
    'mode': 'must have mode 600 (found 640)',
    'symlink': 'refusing symbolic-link file',
    'base': 'directory must not be group- or world-writable: {base}',
    'ancestor': 'directory must not be group- or world-writable: {tmp}',
    'base_no_file': 'directory must not be group- or world-writable: {base}',
}


def _plain_env():
    """Environment of the installed manager: no redirection and no credential variables."""
    return {k: v for k, v in os.environ.items() if k not in PLAIN_ENV_DROP}


# Set when an action that starts daemons succeeded under a private WAZUH_BASE_DIR: those daemons carry
# the private tree in their environment, so the finalizer must restart them with the plain one rather
# than leave a manager that "is running" pointed at a tree about to be deleted.
_STARTED_WITH_PRIVATE_BASE = {'value': False}


def _control(*args, env=None, timeout=START_TIMEOUT):
    result = subprocess.run([WAZUH_CONTROL_PATH, *args], env=env if env is not None else _plain_env(),
                            capture_output=True, text=True, timeout=timeout)
    if (env is not None and 'WAZUH_BASE_DIR' in env and result.returncode == 0
            and any(action in args for action in ('start', 'restart', 'reload'))):
        _STARTED_WITH_PRIVATE_BASE['value'] = True
    return result


def _pids():
    """Return {pid file name: pid} of every daemon pid file."""
    found = {}
    for pid_file in RUN_DIR.glob('*.pid'):
        try:
            found[pid_file.name] = int(pid_file.stem.rsplit('-', 1)[1])
        except (ValueError, IndexError):
            continue
    return found


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _alive_pids():
    return {name: pid for name, pid in _pids().items() if _alive(pid)}


def _wait_for_no_daemons(seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _alive_pids():
            return True
        time.sleep(1)
    return not _alive_pids()


def _all_running():
    result = _control('status', timeout=STOP_TIMEOUT)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return bool(lines) and all(' is running' in line for line in lines), result.stdout


def _ensure_running_plain():
    """Leave the manager running with the plain environment."""
    running, _ = _all_running()
    if not running:
        _control('stop', timeout=STOP_TIMEOUT)
        _control('start')
    running, output = _all_running()
    assert running, f"The manager is not fully running after the test:\n{output}"


def _stop_plain():
    result = _control('stop', timeout=STOP_TIMEOUT)
    assert result.returncode == 0, f"Could not stop the manager: {result.stderr}"
    assert _wait_for_no_daemons(), f"Daemons still alive after stop: {_alive_pids()}"


def _restore_moved_helper():
    """Put back a shared helper an interrupted run of test_refuses_when_the_check_cannot_run left aside."""
    aside = SHARED_HELPER.with_name(SHARED_HELPER.name + '.moved-by-test')
    if aside.exists() and not SHARED_HELPER.exists():
        aside.rename(SHARED_HELPER)


def _build_tree(case=None):
    """Create tmp/base/credentials.env (0600 root:root) and break the one rule 'case' names.

    Returns (tmp, base).
    """
    parent = os.stat('/root')
    if (parent.st_uid, parent.st_gid) != (0, 0) or parent.st_mode & 0o022:
        pytest.skip('/root must be root:root and not group- or world-writable: the shared helper validates every '
                    'ancestor of the tree')
    tmp = Path(tempfile.mkdtemp(dir='/root'))
    tmp.chmod(0o700)
    base = tmp / 'base'
    base.mkdir()
    base.chmod(0o700)
    cred = base / 'credentials.env'
    cred.write_text(CREDENTIALS_CONTENT)
    cred.chmod(0o600)
    os.chown(cred, 0, 0)

    if case == 'owner':
        shutil.chown(cred, user='daemon')
    elif case == 'group':
        shutil.chown(cred, group='daemon')
    elif case == 'mode':
        cred.chmod(0o640)
    elif case == 'symlink':
        real = tmp / 'real-credentials.env'
        real.write_text(CREDENTIALS_CONTENT)
        real.chmod(0o600)
        cred.unlink()
        cred.symlink_to(real)
    elif case == 'base':
        base.chmod(0o770)
    elif case == 'ancestor':
        tmp.chmod(0o770)
    elif case == 'base_no_file':
        cred.unlink()
        base.chmod(0o770)
    elif case == 'absent':
        cred.unlink()
    return tmp, base


def _remove_tree(tmp):
    try:
        tmp.chmod(0o700)
    except OSError:
        pass
    shutil.rmtree(tmp, ignore_errors=True)


def _env_for(base, extra=None):
    env = _plain_env()
    env['WAZUH_BASE_DIR'] = str(base)
    if extra:
        env.update(extra)
    return env


def _assert_refused(result, case, tmp, base):
    expected = UNSAFE_CASES[case].format(base=base, tmp=tmp)
    assert result.returncode != 0, f"Unsafe '{case}' was accepted:\n{result.stdout}\n{result.stderr}"
    assert expected in result.stderr, f"Missing '{expected}' in stderr:\n{result.stderr}"
    assert RESOLVER_VERDICT in result.stderr, f"Missing '{RESOLVER_VERDICT}' in stderr:\n{result.stderr}"
    assert RESOLVER_RULE in result.stderr, f"Missing '{RESOLVER_RULE}' in stderr:\n{result.stderr}"
    assert UNSAFE_MESSAGE in result.stdout, f"Missing '{UNSAFE_MESSAGE}' in stdout:\n{result.stdout}"
    assert INVALID_CONFIG not in result.stdout + result.stderr


@pytest.fixture
def tree_factory():
    """Build trees on demand, remove them all and leave the manager running with the plain env."""
    trees = []

    def make(case=None):
        tmp, base = _build_tree(case)
        trees.append(tmp)
        return tmp, base

    _restore_moved_helper()
    try:
        yield make
    finally:
        for tmp in trees:
            _remove_tree(tmp)
        if _STARTED_WITH_PRIVATE_BASE['value']:
            _STARTED_WITH_PRIVATE_BASE['value'] = False
            _stop_plain()
            _control('start')
        _restore_moved_helper()
        _ensure_running_plain()


@pytest.mark.parametrize('case', list(UNSAFE_CASES))
def test_start_refuses_unsafe_file(case, tree_factory):
    '''
    description: Check that 'start' refuses an unsafe credentials file, one broken rule at a time.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and build a tree whose credentials file or directories break one rule.
        - test: Run 'start' with WAZUH_BASE_DIR pointing to that tree.
        - teardown: Remove the tree and start the manager with the plain environment.

    assertions:
        - The exit code is not zero and no daemon is alive.
        - stderr has the library's line for the rule and the resolver's 'UNSAFE' verdict.
        - stdout has the 'Unsafe credentials file. Exiting' message.
        - No 'Invalid configuration at' error is reported.

    input_description: One tree per rule - owner, group, mode, symbolic link, base directory,
                       ancestor directory and base directory without file.

    expected_output:
        - 'file must be owned by root:root'
        - 'must have mode 600 (found 640)'
        - 'refusing symbolic-link file'
        - 'directory must not be group- or world-writable: <path>'
        - 'Unsafe credentials file. Exiting'

    tags:
        - manager_control
    '''
    if case in ('owner', 'group') and not HAS_DAEMON_USER:
        pytest.skip("no 'daemon' user to own the file")
    tmp, base = tree_factory(case)
    _stop_plain()

    result = _control('start', env=_env_for(base))

    _assert_refused(result, case, tmp, base)
    assert not _alive_pids(), f"A daemon was started: {_alive_pids()}"


def test_restart_refuses_before_stopping(tree_factory):
    '''
    description: Check that 'restart' refuses an unsafe file before it stops anything.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: With the manager running, build a tree whose credentials file has mode 0640.
        - test: Run 'restart' with WAZUH_BASE_DIR pointing to that tree.
        - teardown: Remove the tree.

    assertions:
        - The exit code is not zero.
        - The daemons that were running are the same processes afterwards.
        - The manager log gained the control script's error and the library's line.

    input_description: A credentials file with mode 0640.

    expected_output:
        - 'wazuh-manager-control: ERROR: unsafe credentials file'
        - 'must have mode 600 (found 640)'

    tags:
        - manager_control
    '''
    _ensure_running_plain()
    tmp, base = tree_factory('mode')
    before = _alive_pids()
    assert before, 'The manager is not running'
    offset = MANAGER_LOG.stat().st_size

    result = _control('restart', env=_env_for(base))

    assert result.returncode != 0, f"restart was accepted:\n{result.stdout}\n{result.stderr}"
    assert 'must have mode 600 (found 640)' in result.stderr
    assert RESOLVER_VERDICT in result.stderr, result.stderr
    assert UNSAFE_MESSAGE in result.stdout, result.stdout
    assert _alive_pids() == before, 'The daemons changed during a refused restart'
    with open(MANAGER_LOG, 'rb') as log:
        log.seek(offset)
        gained = log.read().decode(errors='replace')
    assert LOG_ERROR in gained, f"Missing '{LOG_ERROR}' in the log:\n{gained}"
    assert 'must have mode 600 (found 640)' in gained


def test_refusal_clears_stale_failed_markers(tree_factory):
    '''
    description: Check that a refused start clears the 'failed' markers of earlier runs.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and seed a 'wazuh-manager-db.failed' marker.
        - test: Run an unsafe 'start', then 'status' and '-j status' with the plain environment.
        - teardown: Remove the marker, if left, and start the manager.

    assertions:
        - 'status' says 'not running' and never 'refused its configuration'.
        - '-j status' has no '"failed"'.

    input_description: A credentials file with mode 0640 and a stale marker containing 'refused'.

    expected_output:
        - 'not running'

    tags:
        - manager_control
    '''
    tmp, base = tree_factory('mode')
    _stop_plain()
    marker = RUN_DIR / 'wazuh-manager-db.failed'
    marker.write_text('refused')
    try:
        result = _control('start', env=_env_for(base))
        assert result.returncode != 0

        status = _control('status', timeout=STOP_TIMEOUT)
        assert 'wazuh-manager-db not running' in status.stdout, status.stdout
        assert 'refused its configuration' not in status.stdout + status.stderr
        status_json = _control('-j', 'status', timeout=STOP_TIMEOUT)
        assert '"failed"' not in status_json.stdout, status_json.stdout
    finally:
        marker.unlink(missing_ok=True)


@pytest.mark.parametrize('action', ['start', 'restart', 'reload'])
def test_json_reports_error_22(action, tree_factory):
    '''
    description: Check that '-j' reports the refusal as a single JSON document with error 22.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Build an unsafe tree. For 'start', stop the manager; for 'restart', keep it running.
        - test: Run 'wazuh-manager-control -j <action>' with WAZUH_BASE_DIR pointing to that tree.
        - teardown: Remove the tree and leave the manager running.

    assertions:
        - The exit code is not zero.
        - stdout is exactly one JSON document with error 22.
        - On 'restart', the daemons are the same processes afterwards.

    input_description: A credentials file with mode 0640.

    expected_output:
        - '{"error":22,"message":"Unsafe credentials file."}'

    tags:
        - manager_control
    '''
    tmp, base = tree_factory('mode')
    if action == 'start':
        _stop_plain()
    else:
        _ensure_running_plain()
    before = _alive_pids()

    result = _control('-j', action, env=_env_for(base))

    assert result.returncode != 0
    assert json.loads(result.stdout) == JSON_ERROR, result.stdout
    assert result.stdout.strip() == json.dumps(JSON_ERROR, separators=(',', ':'))
    if action != 'start':
        assert _alive_pids() == before, 'The daemons changed during a refused restart'
    else:
        assert not _alive_pids()


@pytest.mark.parametrize('case', ['absent', 'safe'])
def test_start_accepts_absent_or_safe_file(case, tree_factory):
    '''
    description: Check that 'start' accepts a base without credentials file and a safe file.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and build a 0700 tree, with no file or with a 0600 root:root file.
        - test: Run 'start' with WAZUH_BASE_DIR pointing to that tree.
        - teardown: Stop the manager, start it with the plain environment and remove the tree.

    assertions:
        - The exit code is zero.
        - Every daemon is running.

    input_description: A tree without credentials file, and a tree with a safe one.

    expected_output:
        - 'is running'

    tags:
        - manager_control
    '''
    tmp, base = tree_factory(case)
    _stop_plain()

    result = _control('start', env=_env_for(base))

    assert result.returncode == 0, f"start failed:\n{result.stdout}\n{result.stderr}"
    running, output = _all_running()
    assert running, output
    # The fixture finalizer starts the manager again with the plain environment, but the daemons
    # must not keep the custom WAZUH_BASE_DIR: restart them here, before the tree disappears.
    _stop_plain()
    _control('start')


def test_environment_does_not_exempt(tree_factory):
    '''
    description: Check that credentials supplied in the environment do not exempt the file check.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and build a tree whose credentials file has mode 0640.
        - test: Run 'start' with the manager's password variables in the environment.
        - teardown: Remove the tree and start the manager with the plain environment.

    assertions:
        - The exit code is not zero and no daemon is alive.
        - The refusal is the same as without the variables.

    input_description: WAZUH_MANAGER_API_PASSWORD, WAZUH_MANAGER_WUI_PASSWORD and
                       WAZUH_INDEXER_MANAGER_PASSWORD set, and an unsafe file.

    expected_output:
        - 'must have mode 600 (found 640)'
        - 'Unsafe credentials file. Exiting'

    tags:
        - manager_control
    '''
    tmp, base = tree_factory('mode')
    _stop_plain()
    extra = {'WAZUH_MANAGER_API_PASSWORD': 'Dummy.Value01',
             'WAZUH_MANAGER_WUI_PASSWORD': 'Dummy.Value01',
             'WAZUH_INDEXER_MANAGER_PASSWORD': 'Dummy.Value01'}

    result = _control('start', env=_env_for(base, extra))

    _assert_refused(result, 'mode', tmp, base)
    assert not _alive_pids()


@pytest.mark.parametrize('action', ['start', 'restart', 'reload'])
def test_check_runs_before_configuration_validation(action, tree_factory):
    '''
    description: Check that the credentials file is refused before the configuration is validated, so a
                 refusal is never reported as a configuration error (the symptom of #39852).
    wazuh_min_version: 5.0.0
    test_phases:
        - setup: Build a tree whose credentials file has mode 0640; stop the manager for 'start'.
        - test: Run the action with WAZUH_CONF naming a file that does not exist, which the
                configuration validator would refuse.
        - teardown: Remove the tree and leave the manager running with the plain environment.
    assertions:
        - The exit code is not zero and the resolver's 'UNSAFE' verdict is reported.
        - No 'Configuration error' is reported.
        - On 'restart', the daemons that were running are the same processes afterwards.
    input_description: A credentials file with mode 0640 and a missing configuration file.
    expected_output:
        - 'resolve-credentials: UNSAFE'
    tags:
        - manager_control
    '''
    tmp, base = tree_factory('mode')
    if action == 'start':
        _stop_plain()
    else:
        _ensure_running_plain()
    before = _alive_pids()

    result = _control(action, env=_env_for(base, {'WAZUH_CONF': 'missing-for-this-test.conf'}))

    assert result.returncode != 0, f"{action} was accepted:\n{result.stdout}\n{result.stderr}"
    assert RESOLVER_VERDICT in result.stderr, result.stderr
    assert 'Configuration error' not in result.stdout + result.stderr, result.stdout + result.stderr
    if action != 'start':
        assert _alive_pids() == before, 'The daemons changed during a refused restart'



@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_refuses_when_the_check_cannot_run(json_output, tree_factory):
    '''
    description: Check that a start is refused, and reported as such, when the credentials check itself cannot
                 run: the verdict is not "unsafe", but a check that did not answer is no reason to start.
    wazuh_min_version: 5.0.0
    test_phases:
        - setup: Stop the manager and move the installed shared credentials helper aside.
        - test: Run 'start' (or '-j start') with the plain environment.
        - teardown: Put the helper back and start the manager with the plain environment.
    assertions:
        - The exit code is not zero and no daemon is alive.
        - The output says 'Cannot check the credentials file', never 'Unsafe credentials file'.
        - The manager log gained the control script's error and the resolver's reason.
    input_description: A manager whose lib/wazuh-credentials.sh is missing.
    expected_output:
        - 'Cannot check the credentials file. Exiting'
        - 'wazuh-manager-control: ERROR: cannot check the credentials file'
        - 'resolve-credentials: cannot find wazuh-credentials.sh'
        - '{"error":22,"message":"Cannot check the credentials file."}'
    tags:
        - manager_control
    '''
    _stop_plain()
    aside = SHARED_HELPER.with_name(SHARED_HELPER.name + '.moved-by-test')
    offset = MANAGER_LOG.stat().st_size
    SHARED_HELPER.rename(aside)
    try:
        args = ('-j', 'start') if json_output else ('start',)
        result = _control(*args)
        with open(MANAGER_LOG, 'rb') as log:
            log.seek(offset)
            gained = log.read().decode(errors='replace')
        assert 'wazuh-manager-control: ERROR: cannot check the credentials file' in gained, gained
        assert 'cannot find wazuh-credentials.sh' in gained, gained
        assert result.returncode != 0, f"start was accepted:\n{result.stdout}\n{result.stderr}"
        if json_output:
            assert json.loads(result.stdout) == {'error': 22, 'message': 'Cannot check the credentials file.'}
        else:
            assert 'Cannot check the credentials file. Exiting' in result.stdout, result.stdout
        assert UNSAFE_MESSAGE not in result.stdout
        assert not _alive_pids(), f"A daemon was started: {_alive_pids()}"
    finally:
        aside.rename(SHARED_HELPER)
