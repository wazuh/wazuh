"""
 Copyright (C) 2015-2024, Wazuh Inc.
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


@pytest.fixture
def break_listener_tls_files(test_metadata):
    '''
    Stop the manager and apply the case's mutation to the listener's TLS files, then restore them exactly.

    The manager does not generate certificates, so whatever the mutation removes has to be put back by
    hand: `missing_certificate` moves the certificate aside (same directory), `unreadable_key` makes the
    private key root-owned 0600 so only the validator (root) can read it. Ownership and mode are read
    before touching anything and restored in `finally`, whatever the test outcome.
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
                 missing, and that the verdict tells the operator the manager does not generate certificates.
                 For this purpose, the test moves etc/certs/remoted.pem aside, starts the service and checks
                 the manager log with a FileMonitor for the 1244 verdict wazuh-manager-control dumps there
                 (pointer '/remote/https/certificate', 'file not found' with the resolved path, and the
                 provisioning hint). No daemon starts: the validator runs before all of them.

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

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=generate_callback(test_metadata['expected_error']), timeout=60)
    assert log_monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(unreadable_configuration, unreadable_metadata),
                         ids=unreadable_ids)
def test_https_cert_unreadable_by_service_user(test_configuration, test_metadata, configure_local_internal_options,
                                               truncate_monitored_files, set_wazuh_configuration,
                                               break_listener_tls_files, restart_wazuh_expect_error):
    '''
    description: Check that remoted refuses to start when the HTTPS agent listener's private key exists but
                 the service user cannot read it. For this purpose, the test makes etc/certs/remoted-key.pem
                 root-owned 0600 -- the configuration validator, which runs as root, still passes -- starts
                 the service and checks the manager log with a FileMonitor for remoted's preflight error,
                 which names the key and says it is missing or unreadable by the service user. remoted exits
                 instead of coming up without the HTTPS transport.

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

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=generate_callback(test_metadata['expected_error']), timeout=60)
    assert log_monitor.callback_result
