'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that the configuration check of 'wazuh-manager-control' refuses an invalid
       indexer client option of the engine, so a 'restart' with one does not stop the manager.
       'wazuh-manager-analysisd -t' validates the 'analysisd.indexer_client_*' internal options and the
       queue of the engine's 'events' and 'raw' buckets as a start does; before, it accepted them, the
       restart stopped every daemon and the engine then refused to start.

components:
    - manager_control

suite: manager_control

targets:
    - manager

daemons:
    - wazuh-manager-analysisd
    - wazuh-manager-apid
    - wazuh-manager-authd
    - wazuh-manager-clusterd
    - wazuh-manager-db
    - wazuh-manager-modulesd
    - wazuh-manager-remoted

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/pull/41230

tags:
    - manager_control
'''
import json
import re
import subprocess
from pathlib import Path

import pytest

from wazuh_testing.constants.paths import MANAGER_CONF_DIR
from wazuh_testing.constants.paths.binaries import WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH
from wazuh_testing.utils.services import wait_expected_daemon_status

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]

CONTROL_TIMEOUT_SECONDS = 180
INTERNAL_OPTIONS = Path(MANAGER_CONF_DIR, 'wazuh-manager-internal-options.conf')
# Daemon PID files only: 'wazuh-manager-apid_auth-<pid>.pid' and the cluster children are helpers.
DAEMON_PID_FILE = re.compile(r'^(wazuh-manager-[a-z]+)-(\d+)\.pid$')
CONFIGURATION_ERROR_CODE = 20

# An internal options line the engine's start refuses, and what its reason names.
invalid_options = [
    ('analysisd.indexer_client_netwrok_threads=2', 'analysisd.indexer_client_netwrok_threads'),
    ('analysisd.indexer_client_cpu_threads=65', 'analysisd.indexer_client_cpu_threads'),
    ('analysisd.indexer_client_request_timeout_ms=abc', 'analysisd.indexer_client_request_timeout_ms'),
    ('analysisd.indexer_queue_max_bytes=1024', 'analysisd.indexer_queue_max_bytes'),
]
option_ids = ['unknown_key', 'out_of_range', 'not_a_number', 'queue_below_one_bulk']


def _control(*args):
    return subprocess.run([WAZUH_CONTROL_PATH, *args], capture_output=True, text=True,
                          timeout=CONTROL_TIMEOUT_SECONDS)


def _daemon_pids():
    """Map each manager daemon to the PID in the name of its 'var/run/<daemon>-<pid>.pid' file."""
    matches = (DAEMON_PID_FILE.match(path.name) for path in Path(VAR_RUN_PATH).iterdir())
    return {match.group(1): int(match.group(2)) for match in matches if match}


@pytest.fixture()
def invalid_engine_option(request):
    """Append one invalid line to the internal options of a running manager. Afterwards restore the
    file and leave the manager running, as the test found it."""
    wait_expected_daemon_status(timeout=CONTROL_TIMEOUT_SECONDS)
    original = INTERNAL_OPTIONS.read_bytes()
    with INTERNAL_OPTIONS.open('ab') as options:
        options.write(b'\n' + request.param[0].encode() + b'\n')

    yield request.param

    INTERNAL_OPTIONS.write_bytes(original)
    if len(_daemon_pids()) == 0:
        assert _control('start').returncode == 0, 'the manager did not start again after the test'
    wait_expected_daemon_status(timeout=CONTROL_TIMEOUT_SECONDS)


@pytest.mark.parametrize('invalid_engine_option', invalid_options, ids=option_ids, indirect=True)
def test_check_refuses_an_invalid_indexer_client_option(invalid_engine_option):
    '''
    description:
        An invalid 'analysisd.indexer_client_*' internal option, or an engine indexer queue that
        cannot hold one bulk, must be refused by 'wazuh-manager-control check' with the reason the
        engine's start would give, and a 'restart' with it must leave the running manager alone.

    wazuh_min_version: 5.0.0

    parameters:
        - invalid_engine_option:
            type: fixture
            brief: Append an invalid line to the internal options and restore the file afterwards.

    test_phases:
        - setup:
            - Append the invalid line to wazuh-manager-internal-options.conf of a running manager.
        - test:
            - Run 'wazuh-manager-control -j check'.
            - Run 'wazuh-manager-control restart'.
        - teardown:
            - Restore the internal options.

    assertions:
        - The check exits 1 with error 20 and names the engine and the offending option.
        - The restart exits 1 for the same reason.
        - Every daemon keeps the PID it had before the restart.

    input_description: A running manager and one invalid line in its internal options.

    expected_output:
        - 'Error loading configuration: indexer client: .* (invalid_config)'

    tags:
        - manager_control
    '''
    _, named_option = invalid_engine_option
    pids_before = _daemon_pids()
    assert pids_before, 'the manager is not running'

    check = _control('-j', 'check')
    check_output = check.stdout + check.stderr
    assert check.returncode == 1, f'check exited {check.returncode}, expected 1\n{check_output}'
    assert json.loads(check.stdout)['error'] == CONFIGURATION_ERROR_CODE, check_output
    assert 'wazuh-manager-analysisd' in check.stdout, check_output
    assert 'indexer client' in check_output and named_option in check_output, check_output
    assert '(invalid_config)' in check_output, check_output

    restart = _control('restart')
    restart_output = restart.stdout + restart.stderr
    assert restart.returncode == 1, f'restart exited {restart.returncode}, expected 1\n{restart_output}'
    assert named_option in restart_output, restart_output
    assert _daemon_pids() == pids_before, f'the refused restart touched the daemons\n{restart_output}'
