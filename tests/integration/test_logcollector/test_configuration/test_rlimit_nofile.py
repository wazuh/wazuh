'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: The 'wazuh-logcollector' daemon raises its own soft file descriptor limit to
       'logcollector.rlimit_nofile' at start. These tests check that the value it reports for that
       option ('getconfig internal', the same object the agent's configuration report carries) is the
       configured one, whatever soft and hard limits the daemon inherited, and that a limit in force
       below the option is reported through warnings rather than through the reported value.
components:
    - logcollector
suite: configuration
targets:
    - agent
daemons:
    - wazuh-logcollector
os_platform:
    - linux
os_version:
    - Ubuntu Jammy
    - Ubuntu Noble
    - Red Hat 9
references:
    - https://github.com/wazuh/wazuh/issues/39613
tags:
    - logcollector_configuration
'''
import json
import re
import subprocess
from os.path import join as path_join

import psutil
import pytest

from wazuh_testing.constants.daemons import LOGCOLLECTOR_DAEMON
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.sockets import LOGCOLLECTOR_SOCKET_PATH
from wazuh_testing.modules.logcollector import utils
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, sockets

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# Configured value in every case. Above the 1024 most runners start with, below every inherited
# limit the 'inherited_above' case uses, so the three ways the limit in force can relate to it
# are all exercised.
CONFIGURED_NOFILE = 2048

local_internal_options = {'logcollector.debug': '2'}

test_metadata = [
    {
        # The soft limit inherited is already above the option: the daemon keeps it (it never lowers
        # a soft limit), and the report must still say 2048, not 8192.
        'inherited': (8192, 8192),
        'expected_in_force': 8192,
        'local_internal_options': {'logcollector.rlimit_nofile': str(CONFIGURED_NOFILE)},
        'warnings': [],
    },
    {
        # The daemon raises its soft limit from 1024 to the option.
        'inherited': (1024, 8192),
        'expected_in_force': CONFIGURED_NOFILE,
        'local_internal_options': {'logcollector.rlimit_nofile': str(CONFIGURED_NOFILE)},
        'warnings': [],
    },
    {
        # The hard limit caps the raise at 1500, and 1450 monitored files no longer leave 100 spare
        # descriptors: both are logged, and the report still says 2048.
        'inherited': (1024, 1500),
        'expected_in_force': 1500,
        'local_internal_options': {'logcollector.rlimit_nofile': str(CONFIGURED_NOFILE),
                                   'logcollector.max_files': '1450'},
        'warnings': [
            r".*File descriptor limit is 1500, below the 2048 requested by 'logcollector.rlimit_nofile'.*",
            r".*Definition 'logcollector.max_files' \(1450\) leaves fewer than 100 spare descriptors under the file "
            r"descriptor limit in force \(1500\).*",
        ],
    },
]
test_cases_ids = ['inherited_above', 'raised_to_option', 'capped_by_hard_limit']

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


def start_logcollector_with_limits(soft, hard):
    """Start wazuh-logcollector the way control_service() does, under the given RLIMIT_NOFILE."""
    import resource  # POSIX only; imported here so the module still collects on Windows

    def set_limits():
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    subprocess.check_call([path_join(WAZUH_PATH, 'bin', LOGCOLLECTOR_DAEMON)], preexec_fn=set_limits)


def get_logcollector_process():
    """Return the running wazuh-logcollector process (its comm name is truncated to 15 characters)."""
    for proc in psutil.process_iter(['name', 'exe']):
        if proc.info['name'] == LOGCOLLECTOR_DAEMON[:15] or (proc.info['exe'] or '').endswith(LOGCOLLECTOR_DAEMON):
            return proc
    raise AssertionError(f'{LOGCOLLECTOR_DAEMON} is not running')


@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_cases_ids)
def test_rlimit_nofile_reports_configured_value(test_metadata, configure_local_internal_options,
                                                daemons_handler_module, stop_logcollector):
    '''
    description: Check that 'wazuh-logcollector' reports 'logcollector.rlimit_nofile' as configured.
                 For this purpose, the test starts the daemon under a given soft and hard
                 RLIMIT_NOFILE, confirms the limit actually in force, and queries
                 'getconfig internal' on its command socket.
    wazuh_min_version: 5.0.1
    tier: 0
    parameters:
        - test_metadata:
            type: data
            brief: Inherited limits, expected limit in force and expected warnings.
        - configure_local_internal_options:
            type: fixture
            brief: Set 'logcollector.rlimit_nofile' (and 'logcollector.max_files' when needed).
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.
        - stop_logcollector:
            type: fixture
            brief: Stop logcollector and truncate the log, so it can be started with custom limits.
    assertions:
        - Verify that the soft limit in force is the expected one, so no case passes vacuously.
        - Verify that 'getconfig internal' reports the configured 'rlimit_nofile'.
        - Verify that a limit in force below the option is reported through warnings, and that none is
          logged when the limit in force covers the option.
    input_description: Three cases defined in the module: inherited soft limit above the option,
                       raised to the option, and capped by the hard limit.
    expected_output:
        - r"File descriptor limit is .*, below the .* requested by 'logcollector.rlimit_nofile'"
        - r"Definition 'logcollector.max_files' .* leaves fewer than 100 spare descriptors"
    tags:
        - rlimit_nofile
    '''
    soft, hard = test_metadata['inherited']
    start_logcollector_with_limits(soft, hard)
    utils.check_logcollector_socket(timeout=60)

    in_force, _ = get_logcollector_process().rlimit(psutil.RLIMIT_NOFILE)
    assert in_force == test_metadata['expected_in_force'], \
        f'Soft limit in force is {in_force}, expected {test_metadata["expected_in_force"]}'

    response = sockets.send_request_socket(query='getconfig internal', socket_path=LOGCOLLECTOR_SOCKET_PATH)
    assert response[:2] == b'ok', f'getconfig internal failed: {response}'
    reported = json.loads(response[3:])['internal']['logcollector']['rlimit_nofile']
    assert reported == CONFIGURED_NOFILE, \
        f'logcollector.rlimit_nofile reported as {reported}, configured {CONFIGURED_NOFILE}'

    if not test_metadata['warnings']:
        with open(WAZUH_LOG_PATH, errors='replace') as log:
            unexpected = [line for line in log
                          if re.search(r"wazuh-logcollector.*(File descriptor limit is|'logcollector.max_files')", line)]
        assert not unexpected, f'Unexpected descriptor limit warnings: {unexpected}'

    for warning in test_metadata['warnings']:
        log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
        log_monitor.start(callback=callbacks.generate_callback(warning), timeout=10)
        assert log_monitor.callback_result, f'Expected warning not logged: {warning}'
