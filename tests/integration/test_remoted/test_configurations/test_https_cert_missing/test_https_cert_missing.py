"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import os
import re
import stat
import subprocess
import time

import pytest

from pathlib import Path
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.utils import services
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


@pytest.fixture
def break_listener_tls_files(test_metadata):
    '''
    Stop the manager and apply the case's mutation to the listener's TLS files, then restore them exactly.

    Whatever the mutation removes has to be put back by hand: `missing_certificate` moves the certificate
    aside (same directory), `unreadable_key` makes the private key root-owned 0600 so only the validator
    (root) can read it. Ownership and mode are read before touching anything and restored in `finally`,
    whatever the test outcome. Yields the journal cursor taken before the start, so a test can read only
    what that start logged.
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
    cursor = subprocess.run(['journalctl', '--show-cursor', '-n', '0', '-q'], capture_output=True,
                            text=True).stdout.rpartition('cursor: ')[2].strip()

    if mutation == 'missing_certificate':
        aside = certificate + ASIDE_SUFFIX
        os.rename(certificate, aside)
        try:
            yield cursor
        finally:
            os.rename(aside, certificate)
    elif mutation == 'unreadable_key':
        original = os.stat(key)
        os.chown(key, 0, 0)
        os.chmod(key, 0o600)
        try:
            yield cursor
        finally:
            os.chown(key, original.st_uid, original.st_gid)
            os.chmod(key, stat.S_IMODE(original.st_mode))
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
                 missing and the host holds no CA key to reissue it. For this purpose, the test moves
                 etc/certs/remoted.pem aside, starts the service and checks the unit's journal for the
                 verdict of the credential resolver.

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
            brief: Stop the manager, move the listener certificate aside and put it back afterwards.
        - restart_wazuh_expect_error
            type: fixture
            brief: Start the service tolerating the failure, once the test finishes stops the daemons.
    '''
    expected = re.compile(test_metadata['expected_error'])
    deadline = time.time() + 60
    journal = ''
    while time.time() < deadline:
        journal = subprocess.run(['journalctl', '-u', 'wazuh-manager', '--no-pager', '-q',
                                  f'--after-cursor={break_listener_tls_files}'],
                                 capture_output=True, text=True).stdout
        if any(expected.match(line) for line in journal.splitlines()):
            break
        time.sleep(1)
    assert any(expected.match(line) for line in journal.splitlines()), journal[-2000:]


@pytest.mark.parametrize('test_configuration, test_metadata', zip(unreadable_configuration, unreadable_metadata),
                         ids=unreadable_ids)
def test_https_cert_unreadable_by_service_user(test_configuration, test_metadata, configure_local_internal_options,
                                               truncate_monitored_files, set_wazuh_configuration,
                                               break_listener_tls_files, restart_wazuh_expect_error):
    '''
    description: Check that the manager refuses to start when the HTTPS agent listener's private key exists
                 but the service user cannot read it. For this purpose, the test makes
                 etc/certs/remoted-key.pem root-owned 0600, starts the service and checks the unit's journal
                 for the verdict of the credential resolver, which validates the listener pair's ownership
                 before the configuration validator and before any daemon -- so the key is refused there and
                 remoted never reaches its own preflight. Nothing comes up without the HTTPS transport.

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
            brief: Stop the manager, make the listener key unreadable by the service user and restore its
                   ownership and mode afterwards.
        - restart_wazuh_expect_error
            type: fixture
            brief: Start the service tolerating the failure, once the test finishes stops the daemons.
    '''

    # The journal, not WAZUH_LOG_PATH: the resolver runs before any daemon and writes to stderr, which
    # systemd captures under the unit. Nothing has opened the manager log at that point.
    expected = re.compile(test_metadata['expected_error'])
    deadline = time.time() + 60
    journal = ''
    while time.time() < deadline:
        journal = subprocess.run(['journalctl', '-u', 'wazuh-manager', '--no-pager', '-q',
                                  f'--after-cursor={break_listener_tls_files}'],
                                 capture_output=True, text=True).stdout
        if any(expected.match(line) for line in journal.splitlines()):
            break
        time.sleep(1)
    assert any(expected.match(line) for line in journal.splitlines()), journal[-2000:]
