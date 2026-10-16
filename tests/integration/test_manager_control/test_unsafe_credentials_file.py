'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that 'wazuh-manager-control' refuses to start (or restart, or reload) the manager when
       the credentials it would start with cannot be trusted, and that it says why. checkcredentials() in
       src/init/wazuh-server.sh runs the credential resolver in '--check' mode once the configuration file
       itself has been validated, and before the validator checks the files the configuration names. An entry
       root may not trust (local.env not a regular root file without group or other write, a file in certs/
       that root does not own) must produce the resolver's 'UNSAFE <path>' line and 'Unsafe credentials.
       Exiting'; something in place that is wrong (a malformed local.env line) 'INVALID <path>' and 'Invalid
       credentials. Exiting'; a check that cannot run 'Cannot check the credentials. Exiting'. With '-j' the
       answer is one JSON document with error 22. Nothing is started and, on 'restart', nothing is stopped.
       Regression tests for #39852: the refusal used to surface as an unrelated "Invalid configuration"
       error, or not at all. The one exception is indexer material that only the clock refuses (expired, not
       valid yet): it is a warning, written to the manager log, and the start goes on.

       The resolver's configuration directory is fixed by design (there is no variable to move it), so each
       case breaks one entry of the real /etc/wazuh-manager and puts it back exactly as it was - bytes, owner
       and mode, or absent - before the next one.

components:
    - manager

suite: manager_control

targets:
    - manager

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/39852
    - https://github.com/wazuh/wazuh/issues/40339

tags:
    - manager_control
'''
import datetime
import grp
import json
import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from wazuh_testing.constants.paths import MANAGER_CONF_DIR
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.variables import VAR_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

ACCOUNT = 'wazuh-manager'
CONF_DIR = Path(MANAGER_CONF_DIR)
LOCAL_ENV = CONF_DIR / 'local.env'
PLANTED_CERT = CONF_DIR / 'certs' / 'planted-by-test.pem'
CONF_COPY = CONF_DIR / 'wazuh-manager.copy-by-test.conf'
RUN_DIR = Path(VAR_PATH, 'run')
INDEXER_TRUST = [CONF_DIR / 'certs' / name for name in ('indexer-ca.pem', 'indexer-connector.pem',
                                                        'indexer-connector-key.pem')]
INDEXER_IMPORT_MARKERS = [CONF_DIR / 'certs' / name for name in ('.indexer-ca.imported', '.indexer-connector.imported')]
RESOLVER =Path(VAR_PATH).parent / 'bin' / 'wazuh-manager-resolve-credentials'
RESOLVER_ASIDE = RESOLVER.with_name(RESOLVER.name + '.moved-by-test')
MANAGER_LOG = Path(WAZUH_LOG_PATH)
INVALID_CONFIG = 'Invalid configuration at'
START_TIMEOUT = 300
STOP_TIMEOUT = 120

# What each refusal prints: the control script's message on stdout, its JSON error with '-j', its log line, and
# the start of the resolver's own line on stderr.
VERDICTS = {
    'unsafe': ('Unsafe credentials. Exiting', {'error': 22, 'message': 'Unsafe credentials.'},
               'wazuh-manager-control: ERROR: unsafe credentials', 'UNSAFE '),
    'invalid': ('Invalid credentials. Exiting', {'error': 22, 'message': 'Invalid credentials.'},
                'wazuh-manager-control: ERROR: invalid credentials', 'INVALID '),
    'cannot': ('Cannot check the credentials. Exiting', {'error': 22, 'message': 'Cannot check the credentials.'},
               'wazuh-manager-control: ERROR: cannot check the credentials', None),
}

# One broken entry per case, and the path the resolver names for it.
UNSAFE_CASES = {
    'local_env_owner': LOCAL_ENV,
    'local_env_group_writable': LOCAL_ENV,
    'local_env_symlink': LOCAL_ENV,
    'local_env_directory': LOCAL_ENV,
    'certs_foreign_entry': PLANTED_CERT,
}

DAEMONS = ('wazuh-manager-clusterd', 'wazuh-manager-modulesd', 'wazuh-manager-remoted', 'wazuh-manager-analysisd',
           'wazuh-manager-db', 'wazuh-manager-authd', 'wazuh-manager-apid')
PLAIN_ENV_DROP = ('WAZUH_MANAGER_API_PASSWORD', 'WAZUH_MANAGER_WUI_PASSWORD', 'WAZUH_INDEXER_MANAGER_PASSWORD',
                  'WAZUH_CONF')


def _plain_env():
    """Environment of the installed manager: no credential variables."""
    return {k: v for k, v in os.environ.items() if k not in PLAIN_ENV_DROP}


def _control(*args, env=None, timeout=START_TIMEOUT):
    return subprocess.run([WAZUH_CONTROL_PATH, *args], env=env if env is not None else _plain_env(),
                          capture_output=True, text=True, timeout=timeout)


def _pids():
    """Return {pid file name: pid} of the daemons' own pid files (auxiliary ones excluded)."""
    found = {}
    for pid_file in RUN_DIR.glob('*.pid'):
        try:
            daemon, pid = pid_file.stem.rsplit('-', 1)
            if daemon not in DAEMONS:
                continue
            found[pid_file.name] = int(pid)
        except ValueError:
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


def _ensure_running():
    running, _ = _all_running()
    if not running:
        _control('stop', timeout=STOP_TIMEOUT)
        _control('start')
    running, output = _all_running()
    assert running, f"The manager is not fully running after the test:\n{output}"


def _stop():
    result = _control('stop', timeout=STOP_TIMEOUT)
    assert result.returncode == 0, f"Could not stop the manager: {result.stderr}"
    assert _wait_for_no_daemons(), f"Daemons still alive after stop: {_alive_pids()}"


def _log_since(offset):
    with open(MANAGER_LOG, 'rb') as log:
        log.seek(offset)
        return log.read().decode(errors='replace')


class _Snapshot:
    """An entry as it was before a case broke it: absent, or a regular file with its bytes, owner and mode."""

    def __init__(self, path):
        self.path = path
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            self.content = None
            return
        assert Path(path).is_file() and not Path(path).is_symlink(), f"{path} is not a regular file to snapshot"
        self.content = Path(path).read_bytes()
        self.owner = (st.st_uid, st.st_gid)
        self.mode = st.st_mode & 0o7777

    def restore(self):
        path = Path(self.path)
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        if self.content is not None:
            path.write_bytes(self.content)
            os.chown(path, *self.owner)
            path.chmod(self.mode)


def _write_local_env(text):
    LOCAL_ENV.write_text(text)
    os.chown(LOCAL_ENV, 0, 0)
    LOCAL_ENV.chmod(0o600)


def _break(case):
    """Break the one entry 'case' names. The original local.env, when there is one, keeps its values."""
    account = pwd.getpwnam(ACCOUNT)
    original = LOCAL_ENV.read_text() if LOCAL_ENV.is_file() else ''
    if case == 'local_env_owner':
        _write_local_env(original)
        os.chown(LOCAL_ENV, account.pw_uid, account.pw_gid)
    elif case == 'local_env_group_writable':
        _write_local_env(original)
        LOCAL_ENV.chmod(0o660)
    elif case == 'local_env_symlink':
        if LOCAL_ENV.exists():
            LOCAL_ENV.unlink()
        LOCAL_ENV.symlink_to(CONF_DIR / 'wazuh-manager-internal-options.conf')
    elif case == 'local_env_directory':
        if LOCAL_ENV.exists():
            LOCAL_ENV.unlink()
        LOCAL_ENV.mkdir(mode=0o700)
    elif case == 'certs_foreign_entry':
        PLANTED_CERT.write_text('planted\n')
        os.chown(PLANTED_CERT, account.pw_uid, account.pw_gid)
        PLANTED_CERT.chmod(0o640)
    elif case == 'invalid':
        _write_local_env(original + 'not a pair\n')
    elif case == 'absent':
        if LOCAL_ENV.exists():
            LOCAL_ENV.unlink()
    elif case == 'safe':
        _write_local_env(original)
    else:
        raise ValueError(case)


def _restore_moved_resolver():
    """Put back a resolver an interrupted run of test_refuses_when_the_check_cannot_run left aside."""
    if RESOLVER_ASIDE.exists():
        if RESOLVER.exists():
            RESOLVER.unlink()
        RESOLVER_ASIDE.rename(RESOLVER)


def _assert_refused(result, verdict, path=None):
    message, _, _, resolver_line = VERDICTS[verdict]
    output = result.stdout + result.stderr
    assert result.returncode != 0, f"The start was accepted:\n{output}"
    assert message in result.stdout, f"Missing '{message}' in stdout:\n{result.stdout}"
    if resolver_line is not None:
        expected = f"{resolver_line}{path}" if path is not None else resolver_line
        assert expected in result.stderr, f"Missing '{expected}' in stderr:\n{result.stderr}"
    assert INVALID_CONFIG not in output, output


@pytest.fixture
def breaker():
    """Break entries of the real configuration directory on demand; put every one back and leave the manager
    running, whatever the test did."""
    _restore_moved_resolver()
    snapshots = [_Snapshot(LOCAL_ENV), _Snapshot(PLANTED_CERT), _Snapshot(CONF_COPY)]
    try:
        yield _break
    finally:
        for snapshot in snapshots:
            snapshot.restore()
        _restore_moved_resolver()
        _ensure_running()


@pytest.mark.parametrize('case', list(UNSAFE_CASES))
def test_start_refuses_unsafe_entry(case, breaker):
    '''
    description: Check that 'start' refuses an entry root may not trust, one at a time.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and break one entry of /etc/wazuh-manager.
        - test: Run 'start'.
        - teardown: Put the entry back and start the manager.

    assertions:
        - The exit code is not zero and no daemon is alive.
        - stderr has the resolver's 'UNSAFE <path>' line for that entry.
        - stdout has 'Unsafe credentials. Exiting'; no 'Invalid configuration at' error.

    input_description: local.env owned by the service account, group-writable, a symbolic link or a directory;
                       a file owned by the service account in certs/.

    expected_output:
        - 'UNSAFE /etc/wazuh-manager/local.env'
        - 'UNSAFE /etc/wazuh-manager/certs/planted-by-test.pem'
        - 'Unsafe credentials. Exiting'

    tags:
        - manager_control
    '''
    _stop()
    breaker(case)

    result = _control('start')

    _assert_refused(result, 'unsafe', UNSAFE_CASES[case])
    assert not _alive_pids(), f"A daemon was started: {_alive_pids()}"


def test_start_refuses_invalid_local_env(breaker):
    '''
    description: Check that 'start' refuses a malformed local.env as invalid, not as unsafe and not as a
                 failure to check.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and append a line that is not NAME=value to local.env.
        - test: Run 'start'.
        - teardown: Put local.env back and start the manager.

    assertions:
        - The exit code is not zero and no daemon is alive.
        - stderr has 'INVALID <CONF>/local.env:<line>'; stdout has 'Invalid credentials. Exiting'.

    input_description: A local.env with one malformed line.

    expected_output:
        - 'INVALID /etc/wazuh-manager/local.env:'
        - 'Invalid credentials. Exiting'

    tags:
        - manager_control
    '''
    _stop()
    breaker('invalid')

    result = _control('start')

    _assert_refused(result, 'invalid', f"{LOCAL_ENV}:")
    assert 'Unsafe credentials' not in result.stdout
    assert not _alive_pids(), f"A daemon was started: {_alive_pids()}"


def test_restart_refuses_before_stopping(breaker):
    '''
    description: Check that 'restart' refuses an unsafe entry before it stops anything.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: With the manager running, make local.env group-writable.
        - test: Run 'restart'.
        - teardown: Put local.env back.

    assertions:
        - The exit code is not zero.
        - The daemons that were running are the same processes afterwards.
        - The manager log gained the control script's error and the resolver's line.

    input_description: A group-writable local.env.

    expected_output:
        - 'wazuh-manager-control: ERROR: unsafe credentials'
        - 'UNSAFE /etc/wazuh-manager/local.env'

    tags:
        - manager_control
    '''
    _ensure_running()
    breaker('local_env_group_writable')
    before = _alive_pids()
    assert before, 'The manager is not running'
    offset = MANAGER_LOG.stat().st_size

    result = _control('restart')

    _assert_refused(result, 'unsafe', LOCAL_ENV)
    assert _alive_pids() == before, 'The daemons changed during a refused restart'
    gained = _log_since(offset)
    assert VERDICTS['unsafe'][2] in gained, f"Missing '{VERDICTS['unsafe'][2]}' in the log:\n{gained}"
    assert f"UNSAFE {LOCAL_ENV}" in gained, gained


def test_refusal_clears_stale_failed_markers(breaker):
    '''
    description: Check that a refused start clears the 'failed' markers of earlier runs.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager, seed a 'wazuh-manager-db.failed' marker and make local.env group-writable.
        - test: Run 'start', then 'status' and '-j status'.
        - teardown: Remove the marker, if left, put local.env back and start the manager.

    assertions:
        - 'status' says 'not running' and never 'refused its configuration'.
        - '-j status' has no '"failed"'.

    input_description: A group-writable local.env and a stale marker containing 'refused'.

    expected_output:
        - 'not running'

    tags:
        - manager_control
    '''
    _stop()
    breaker('local_env_group_writable')
    marker = RUN_DIR / 'wazuh-manager-db.failed'
    marker.write_text('refused')
    try:
        result = _control('start')
        assert result.returncode != 0

        status = _control('status', timeout=STOP_TIMEOUT)
        assert 'wazuh-manager-db not running' in status.stdout, status.stdout
        assert 'refused its configuration' not in status.stdout + status.stderr
        status_json = _control('-j', 'status', timeout=STOP_TIMEOUT)
        assert '"failed"' not in status_json.stdout, status_json.stdout
    finally:
        marker.unlink(missing_ok=True)


@pytest.mark.parametrize('action', ['start', 'restart', 'reload'])
def test_json_reports_error_22(action, breaker):
    '''
    description: Check that '-j' reports the refusal as a single JSON document with error 22.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: For 'start', stop the manager; otherwise keep it running. Make local.env group-writable.
        - test: Run 'wazuh-manager-control -j <action>'.
        - teardown: Put local.env back and leave the manager running.

    assertions:
        - The exit code is not zero.
        - stdout is exactly one JSON document with error 22.
        - On 'restart' and 'reload', the daemons are the same processes afterwards.

    input_description: A group-writable local.env.

    expected_output:
        - '{"error":22,"message":"Unsafe credentials."}'

    tags:
        - manager_control
    '''
    if action == 'start':
        _stop()
    else:
        _ensure_running()
    breaker('local_env_group_writable')
    before = _alive_pids()

    result = _control('-j', action)

    expected = VERDICTS['unsafe'][1]
    assert result.returncode != 0
    assert json.loads(result.stdout) == expected, result.stdout
    assert result.stdout.strip() == json.dumps(expected, separators=(',', ':'))
    if action == 'start':
        assert not _alive_pids()
    else:
        assert _alive_pids() == before, f"The daemons changed during a refused {action}"


@pytest.mark.parametrize('case', ['absent', 'safe'])
def test_start_accepts_absent_or_safe_local_env(case, breaker):
    '''
    description: Check that 'start' accepts a configuration directory without local.env, and with a safe one.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager; remove local.env, or rewrite it as a 0600 root:root file.
        - test: Run 'start'.
        - teardown: Put local.env back as it was.

    assertions:
        - The exit code is zero.
        - Every daemon is running.

    input_description: No local.env (every credential already resolved), and a safe local.env.

    expected_output:
        - 'is running'

    tags:
        - manager_control
    '''
    _stop()
    breaker(case)

    result = _control('start')

    assert result.returncode == 0, f"start failed:\n{result.stdout}\n{result.stderr}"
    running, output = _all_running()
    assert running, output


def test_environment_does_not_exempt(breaker):
    '''
    description: Check that credentials supplied in the environment do not exempt local.env from the check.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and make local.env group-writable.
        - test: Run 'start' with the manager's password variables in the environment.
        - teardown: Put local.env back and start the manager.

    assertions:
        - The exit code is not zero and no daemon is alive.
        - The refusal is the same as without the variables.

    input_description: WAZUH_MANAGER_API_PASSWORD, WAZUH_MANAGER_WUI_PASSWORD and WAZUH_INDEXER_MANAGER_PASSWORD
                       set, and a group-writable local.env.

    expected_output:
        - 'UNSAFE /etc/wazuh-manager/local.env'
        - 'Unsafe credentials. Exiting'

    tags:
        - manager_control
    '''
    _stop()
    breaker('local_env_group_writable')
    env = _plain_env()
    env.update({'WAZUH_MANAGER_API_PASSWORD': 'Dummy.Value01',
                'WAZUH_MANAGER_WUI_PASSWORD': 'Dummy.Value01',
                'WAZUH_INDEXER_MANAGER_PASSWORD': 'Dummy.Value01'})

    result = _control('start', env=env)

    _assert_refused(result, 'unsafe', LOCAL_ENV)
    assert not _alive_pids()


def _prepare(action):
    """Stop the manager for 'start', make sure it runs for 'restart' and 'reload'."""
    if action == 'start':
        _stop()
    else:
        _ensure_running()


def _env_with_config_copy(old, new):
    """An environment whose WAZUH_CONF names a copy of the installed configuration with 'old' replaced by 'new'.
    The control script validates WAZUH_CONF; the resolver always reads the installed wazuh-manager.conf."""
    text = (CONF_DIR / 'wazuh-manager.conf').read_text()
    assert text.count(old) == 1, f"'{old}' is not in the installed configuration exactly once"
    CONF_COPY.write_text(text.replace(old, new))
    os.chown(CONF_COPY, 0, grp.getgrnam(ACCOUNT).gr_gid)
    CONF_COPY.chmod(0o640)
    env = _plain_env()
    env['WAZUH_CONF'] = CONF_COPY.name
    return env


@pytest.mark.parametrize('action', ['start', 'restart', 'reload'])
def test_check_runs_before_the_file_checks(action, breaker):
    '''
    description: Check that the credentials are refused before the configuration validator checks the files the
                 configuration names, so a credentials refusal is never reported as a missing file (the symptom
                 of #39852).

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Make local.env group-writable; stop the manager for 'start'.
        - test: Run the action with WAZUH_CONF naming a copy of the configuration whose listener certificate does
                not exist, which the validator refuses ('file not found') once it checks the files.
        - teardown: Put local.env back, remove the copy and leave the manager running.

    assertions:
        - The exit code is not zero and the resolver's 'UNSAFE' line is reported.
        - Neither 'Configuration error' nor the validator's 'Invalid configuration at' is reported.
        - On 'restart' and 'reload', the daemons that were running are the same processes afterwards.

    input_description: A group-writable local.env and a configuration naming a missing certificate.

    expected_output:
        - 'UNSAFE /etc/wazuh-manager/local.env'

    tags:
        - manager_control
    '''
    _prepare(action)
    breaker('local_env_group_writable')
    before = _alive_pids()
    env = _env_with_config_copy(f'<certificate>{CONF_DIR}/certs/remoted.pem</certificate>',
                                f'<certificate>{CONF_DIR}/certs/missing-for-this-test.pem</certificate>')

    result = _control(action, env=env)

    output = result.stdout + result.stderr
    assert result.returncode != 0, f"{action} was accepted:\n{output}"
    assert f"UNSAFE {LOCAL_ENV}" in result.stderr, result.stderr
    assert 'Configuration error' not in output and INVALID_CONFIG not in output, output
    if action != 'start':
        assert _alive_pids() == before, f"The daemons changed during a refused {action}"


@pytest.mark.parametrize('action', ['start', 'restart', 'reload'])
def test_configuration_is_validated_before_the_credentials(action, breaker):
    '''
    description: Check that a configuration the validator refuses is reported as such, with its 1244 verdict,
                 before the credentials are checked: the resolver reads the TLS file names from the configuration
                 and cannot from a file the validator refuses.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Make local.env group-writable; stop the manager for 'start'.
        - test: Run the action with WAZUH_CONF naming a copy of the configuration whose listener port is not a
                number.
        - teardown: Put local.env back, remove the copy and leave the manager running.

    assertions:
        - The exit code is not zero and 'Configuration error' is reported.
        - The validator's '(1244): Invalid configuration at '/remote/https/port'' is written to the manager log.
        - No credentials verdict ('UNSAFE', 'Unsafe credentials') is reported.
        - On 'restart' and 'reload', the daemons that were running are the same processes afterwards.

    input_description: A group-writable local.env and a configuration with a wrong value type.

    expected_output:
        - "(1244): Invalid configuration at '/remote/https/port'"

    tags:
        - manager_control
    '''
    _prepare(action)
    breaker('local_env_group_writable')
    before = _alive_pids()
    env = _env_with_config_copy('<port>1517</port>', '<port>not-a-port</port>')
    offset = MANAGER_LOG.stat().st_size

    result = _control(action, env=env)

    output = result.stdout + result.stderr
    assert result.returncode != 0, f"{action} was accepted:\n{output}"
    assert 'Configuration error' in result.stdout, result.stdout
    expected = "wazuh-manager-control: ERROR: (1244): Invalid configuration at '/remote/https/port'"
    assert expected in _log_since(offset), _log_since(offset)
    assert 'UNSAFE' not in output and 'Unsafe credentials' not in output, output
    if action != 'start':
        assert _alive_pids() == before, f"The daemons changed during a refused {action}"


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_refuses_when_the_check_cannot_run(json_output, breaker):
    '''
    description: Check that a start is refused, and reported as such, when the credentials check itself cannot
                 run: the verdict is neither unsafe nor invalid, but a check that did not answer is no reason
                 to start.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and replace the installed resolver with a program that exits 2 and says
                 nothing.
        - test: Run 'start' (or '-j start').
        - teardown: Put the resolver back and start the manager.

    assertions:
        - The exit code is not zero and no daemon is alive.
        - The output says 'Cannot check the credentials', never 'Unsafe' or 'Invalid credentials'.
        - The manager log gained the control script's error.

    input_description: A resolver that fails without a verdict.

    expected_output:
        - 'Cannot check the credentials. Exiting'
        - 'wazuh-manager-control: ERROR: cannot check the credentials'
        - '{"error":22,"message":"Cannot check the credentials."}'

    tags:
        - manager_control
    '''
    _stop()
    offset = MANAGER_LOG.stat().st_size
    st = RESOLVER.stat()
    RESOLVER.rename(RESOLVER_ASIDE)
    RESOLVER.write_text('#!/bin/sh\nexit 2\n')
    os.chown(RESOLVER, st.st_uid, st.st_gid)
    RESOLVER.chmod(st.st_mode & 0o7777)

    args = ('-j', 'start') if json_output else ('start',)
    result = _control(*args)

    gained = _log_since(offset)
    assert VERDICTS['cannot'][2] in gained, gained
    assert result.returncode != 0, f"start was accepted:\n{result.stdout}\n{result.stderr}"
    if json_output:
        assert json.loads(result.stdout) == VERDICTS['cannot'][1], result.stdout
    else:
        assert VERDICTS['cannot'][0] in result.stdout, result.stdout
    assert 'Unsafe credentials' not in result.stdout and 'Invalid credentials' not in result.stdout
    assert not _alive_pids(), f"A daemon was started: {_alive_pids()}"


def _stage_indexer_trust(leaf_days, key_mismatch=False):
    """Replace the indexer CA and client pair in certs/ with a throwaway CA and a pair it issued, valid between
    `leaf_days` (days from now), owned and moded as the installer leaves them."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test-indexer-ca')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=90)).not_valid_after(now + datetime.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ACCOUNT)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now + datetime.timedelta(days=leaf_days[0]))
            .not_valid_after(now + datetime.timedelta(days=leaf_days[1]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    if key_mismatch:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    contents = (ca.public_bytes(serialization.Encoding.PEM),
                leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM),
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    gid = pwd.getpwnam(ACCOUNT).pw_gid
    for path, data in zip(INDEXER_TRUST, contents):
        if path.exists():
            path.unlink()
        path.write_bytes(data)
        os.chown(path, 0, gid)
        path.chmod(0o640)
    # Without its import marker the material is the operator's: validated, never replaced from the indexer's export.
    # With one, an indexer on this host whose export differs would have it re-imported over the test's files.
    for marker in INDEXER_IMPORT_MARKERS:
        if marker.exists():
            marker.unlink()


@pytest.fixture
def indexer_trust():
    """Swap the indexer CA and client pair for test material, staged (no import marker); put the originals and their
    markers back and restart on them."""
    snapshots = [_Snapshot(path) for path in (*INDEXER_TRUST, *INDEXER_IMPORT_MARKERS)]
    try:
        yield _stage_indexer_trust
    finally:
        for snapshot in snapshots:
            snapshot.restore()
        _control('restart')
        _ensure_running()


def test_start_warns_on_expired_indexer_pair(indexer_trust):
    '''
    description: Check that an indexer client pair whose only defect is that it expired does not refuse the start:
                 the resolver warns, the warning reaches the manager log, and every daemon starts. The connection
                 to the indexer fails until the pair is renewed; nothing else depends on it.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and stage an indexer CA with a client pair it issued that expired yesterday.
        - test: Run 'start'.
        - teardown: Put the original indexer files back and restart the manager.

    assertions:
        - The exit code is zero and every daemon is running.
        - stderr has the resolver's 'WARNING' line for the pair.
        - The manager log gained 'wazuh-manager-control: WARNING: <pair>: expired on'.

    input_description: An expired indexer client pair under a valid indexer CA.

    expected_output:
        - 'wazuh-manager-control: WARNING: /etc/wazuh-manager/certs/indexer-connector.pem: expired on'

    tags:
        - manager_control
    '''
    _stop()
    indexer_trust((-60, -1))
    offset = MANAGER_LOG.stat().st_size

    result = _control('start')

    assert result.returncode == 0, f"start failed:\n{result.stdout}\n{result.stderr}"
    running, output = _all_running()
    assert running, output
    pair = INDEXER_TRUST[1]
    assert f"resolve-credentials: WARNING: {pair}: expired on " in result.stderr, result.stderr
    gained = _log_since(offset)
    assert f"wazuh-manager-control: WARNING: {pair}: expired on " in gained, gained


def test_start_refuses_indexer_pair_with_another_key(indexer_trust):
    '''
    description: Check that an indexer client pair whose key does not match still refuses the start: only the
                 validity window is relaxed.

    wazuh_min_version: 5.0.0

    test_phases:
        - setup: Stop the manager and stage an indexer CA with a valid client pair whose key is another one.
        - test: Run 'start'.
        - teardown: Put the original indexer files back and restart the manager.

    assertions:
        - The exit code is not zero and no daemon is alive.
        - stderr has 'INVALID <pair>'; stdout has 'Invalid credentials. Exiting'.

    input_description: An indexer client pair whose key does not match its certificate.

    expected_output:
        - 'INVALID /etc/wazuh-manager/certs/indexer-connector.pem: its key does not match it'
        - 'Invalid credentials. Exiting'

    tags:
        - manager_control
    '''
    _stop()
    indexer_trust((-1, 365), key_mismatch=True)

    result = _control('start')

    _assert_refused(result, 'invalid', INDEXER_TRUST[1])
    assert 'its key does not match it' in result.stderr, result.stderr
    assert not _alive_pids(), f"A daemon was started: {_alive_pids()}"
