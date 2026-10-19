"""
 Copyright (C) Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import os
import stat
import time

import pytest

from pathlib import Path
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import services
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH

# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids. Both suites share the template (explicit certificate and key paths, so the
# JSON pointer and the files the fixture touches are the same the daemons resolve).
config_path = Path(CONFIGS_PATH, 'config_https_cert_missing.yaml')

missing_cases_path = Path(TEST_CASES_PATH, 'cases_https_cert_missing.yaml')
missing_configuration, missing_metadata, missing_ids = get_test_cases_data(missing_cases_path)
missing_configuration = load_configuration_template(config_path, missing_configuration, missing_metadata)

unreadable_cases_path = Path(TEST_CASES_PATH, 'cases_https_cert_unreadable.yaml')
unreadable_configuration, unreadable_metadata, unreadable_ids = get_test_cases_data(unreadable_cases_path)
unreadable_configuration = load_configuration_template(config_path, unreadable_configuration, unreadable_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

# Same directory as the certificate: the rename keeps the ownership and never crosses a mount.
ASIDE_SUFFIX = '.aside'



def _unreadable_copy(source, target):
    '''
    Create `target` as a root-owned 0600 copy of `source` and remove it afterwards.

    The files the credential resolver manages (the listener pair, root-ca.pem) keep their names and
    modes, so the start reaches the layer the case is about; a root-owned file of another name in certs/ is
    left alone by the resolver. The name is owned by the case: a regular file left there by an aborted run
    (killed before the `finally`) is removed; anything else is not ours to delete.
    '''
    if os.path.islink(target):
        pytest.fail(f'{target} is a symbolic link, not a leftover of this test: remove it by hand '
                    'or point the case at a free name, then rerun')
    if os.path.isfile(target):
        os.remove(target)
    assert not os.path.lexists(target), f'{target} exists and is not a regular file: remove it by hand, then rerun'
    with open(source, 'rb') as original:
        content = original.read()
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as copy:
            copy.write(content)
        os.chown(target, 0, 0)
        os.chmod(target, 0o600)
        yield
    finally:
        os.remove(target)


@pytest.fixture
def break_listener_tls_files(test_metadata):
    '''
    Stop the manager and apply the case's mutation to the listener's TLS files, then restore them exactly.

    Two families of cases. On the listener pair the credential resolver manages (remoted.pem,
    remoted-key.pem), `missing_certificate` moves the certificate aside (same directory) and
    `unreadable_key` makes the key root-owned 0600: `wazuh-manager-control` runs the resolver's read-only
    check before anything else, so the resolver's verdict is what refuses the start. To reach the layers
    behind it, the other cases point the configuration at files the resolver does not manage:
    `absent_file` checks that the configured name does not exist (the configuration validator answers),
    and `unreadable_copy` creates the configured name as a root-owned 0600 copy of `copy_from` (remoted
    answers, after dropping privileges). Ownership and mode are read before touching anything and
    restored in `finally` (a copy is removed), whatever the test outcome.
    '''
    services.control_service('stop')
    # A manager started outside the service unit is not always stopped by the unit's stop: wait until
    # every daemon is really gone, otherwise the mutation would hit files a running remoted has already
    # loaded and the start below would be a no-op.
    deadline = time.time() + 30
    while any(services.check_all_daemon_status().values()) and time.time() < deadline:
        time.sleep(1)
    assert not any(services.check_all_daemon_status().values()), 'the manager did not stop before the mutation'

    certificate = os.path.join(WAZUH_PATH, test_metadata['certificate'])
    key = os.path.join(WAZUH_PATH, test_metadata['key'])
    mutation = test_metadata['mutation']

    if mutation == 'missing_certificate':
        aside = certificate + ASIDE_SUFFIX
        os.rename(certificate, aside)
        try:
            yield
        finally:
            os.rename(aside, certificate)
    elif mutation == 'unreadable_key':
        original = os.stat(key)
        os.chown(key, 0, 0)
        os.chmod(key, 0o600)
        try:
            yield
        finally:
            os.chown(key, original.st_uid, original.st_gid)
            os.chmod(key, stat.S_IMODE(original.st_mode))
    elif mutation == 'absent_file':
        target = os.path.join(WAZUH_PATH, test_metadata['target'])
        assert not os.path.lexists(target), f'{target} exists: the case needs a name nothing provides'
        yield
    elif mutation == 'unreadable_copy':
        yield from _unreadable_copy(os.path.join(WAZUH_PATH, test_metadata['copy_from']),
                                    os.path.join(WAZUH_PATH, test_metadata['target']))
    else:
        raise ValueError(f'unknown mutation {mutation!r}')


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(missing_configuration, missing_metadata),
                         ids=missing_ids)
def test_https_cert_missing(test_configuration, test_metadata, configure_local_internal_options,
                            truncate_monitored_files, set_wazuh_configuration, break_listener_tls_files,
                            restart_wazuh_expect_error):
    '''
    description: Check that the manager refuses to start when the HTTPS agent listener's certificate is
                 missing, and that the verdict names the file. The credential resolver's check follows the
                 configured remote.https names and runs before the configuration validator checks the
                 files, so it answers in both cases: with the configuration pointing at a certificate name
                 nothing provides, and with the installed /etc/wazuh-manager/certs/remoted.pem moved aside,
                 it refuses the key left without its certificate ('INVALID … half a pair'). The test starts
                 the service and checks the manager log with a FileMonitor; no daemon starts in either case.

    parameters:
        - test_configuration
            type: dict
            brief: Configuration applied to wazuh-manager.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply the test configuration to wazuh-manager.conf and restore the original afterwards.
        - break_listener_tls_files:
            type: fixture
            brief: Stop the manager, apply the case's mutation and undo it afterwards.
        - restart_wazuh_expect_error
            type: fixture
            brief: Start the service tolerating the failure, once the test finishes stops the daemons.
    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=generate_callback(test_metadata['expected_error']), timeout=60)
    assert log_monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(unreadable_configuration, unreadable_metadata),
                         ids=unreadable_ids)
def test_https_cert_unreadable_by_service_user(test_configuration, test_metadata, configure_local_internal_options,
                                               truncate_monitored_files, set_wazuh_configuration,
                                               break_listener_tls_files, restart_wazuh_expect_error):
    '''
    description: Check that the manager refuses to start when a TLS file the HTTPS agent listener opens
                 exists but the service user cannot read it. The credential resolver's check follows the
                 configured remote.https names and holds the listener's files, under any name, to
                 root:wazuh-manager 0640, so it refuses each case before anything starts ('UNSAFE … group is
                 root, not wazuh-manager'): a root-owned 0600 copy of the private key or of the CA
                 certificate remoted publishes on /cacerts named in the configuration, and the installed
                 /etc/wazuh-manager/certs/remoted-key.pem itself made root-owned 0600. The test starts the
                 service and checks the manager log with a FileMonitor.

    parameters:
        - test_configuration
            type: dict
            brief: Configuration applied to wazuh-manager.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply the test configuration to wazuh-manager.conf and restore the original afterwards.
        - break_listener_tls_files:
            type: fixture
            brief: Stop the manager, apply the case's mutation and undo it afterwards.
        - restart_wazuh_expect_error
            type: fixture
            brief: Start the service tolerating the failure, once the test finishes stops the daemons.
    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=generate_callback(test_metadata['expected_error']), timeout=60)
    assert log_monitor.callback_result
