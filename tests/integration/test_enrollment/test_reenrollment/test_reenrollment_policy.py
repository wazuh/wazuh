'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Verifies the agent's re-enrollment policy (wazuh/wazuh#39064): which `401` failure classes
       cost an agent its identity, which ones it must survive without re-enrolling, when it stops
       retrying an enrollment the manager has already refused, and that a re-enrollment presents
       the agent's own stored secret rather than a fleet-wide password.

       The agent used to re-enroll on ANY `401`. Every case below exists because that behaviour is
       wrong in a specific way: a clock skew, a worker still syncing its token replica, or a
       manager that simply could not read its own password would each throw away a working
       identity. Only `unknown_agent` -- the manager saying it has never heard of this agent -- is
       supposed to.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - CentOS 8
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal

tags:
    - enrollment
    - reenrollment
'''
import os
import time

import pytest

from pathlib import Path

from wazuh_testing.constants.paths.configurations import DEFAULT_AUTHD_PASS_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import CONTROL_ENDPOINT, ENROLL_ENDPOINT
from wazuh_testing.utils import jwt_enroll
from wazuh_testing.utils.callbacks import make_callback
from wazuh_testing.utils.configuration import load_configuration_template

from . import CONFIGS_PATH
from .conftest import AGENT_ID, AGENT_REENROLL_SECRET, bearer_kid, stored_agent_id, stored_secret

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# One configuration for the whole suite: what varies between cases is the manager's behaviour,
# not the agent's settings.
config_path = Path(CONFIGS_PATH, 'config_reenrollment.yaml')
test_configuration = load_configuration_template(config_path, [{}], [{}])

# How long to wait for something the agent does on its own schedule. The agent notifies every
# 3 seconds under this configuration, and the re-enrollment ramp starts at its retry_delta.
SETTLE = 25
QUIET = 12


def wait_for(predicate, timeout=SETTLE, interval=0.2):
    """Poll until true or the timeout elapses; return what it last saw."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def enroll_requests(manager):
    return manager.get_requests(ENROLL_ENDPOINT)


def expect_log(message, timeout=SETTLE):
    """Assert that `message` reaches ossec.log within `timeout`."""
    monitor = FileMonitor(WAZUH_LOG_PATH)
    monitor.start(timeout=timeout, callback=make_callback(message, prefix='.*', escape=True))
    assert monitor.callback_result is not None, f'Not logged: {message!r}'


# ------------------------------------------------------------------ the classes that must NOT cost an identity

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
@pytest.mark.parametrize('failure_class', ['stale_token', 'invalid_signature', 'invalid_request'])
def test_a_401_that_is_not_unknown_agent_never_triggers_a_re_enrollment(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, failure_class, restart_agentd):
    '''
    description: Drive the control channel with each `401` class that is NOT `unknown_agent` and
                 confirm the agent keeps the identity it has. Before #39064 every one of these
                 threw the identity away: a clock skew, a manager that could not read its own
                 password, and a request the manager could not parse all looked identical to
                 "this agent no longer exists".

    assertions:
        - No POST /enroll is ever sent.
        - client.keys still holds the original id.
        - The agent says it is keeping the identity and retrying.
    '''
    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = failure_class

    assert wait_for(lambda: manager.get_requests(CONTROL_ENDPOINT), timeout=SETTLE), \
        'The agent never reached /control'

    # Stay wrong for a while: the point is that this does not escalate no matter how often it
    # happens, which a single check immediately after the first 401 would not establish.
    time.sleep(QUIET)

    assert enroll_requests(manager) == [], \
        f'A {failure_class} 401 provoked a re-enrollment: {enroll_requests(manager)}'
    assert stored_agent_id() == AGENT_ID
    assert stored_secret() == AGENT_REENROLL_SECRET


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_an_unclassified_401_keeps_the_identity(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, restart_agentd):
    '''
    description: A `401` whose class this build does not recognise -- an older manager, or an
                 intermediary that replaced the body -- must be treated as "keep the identity".
                 A manager that cannot say why it refused has not told the agent to throw its
                 credential away.

    assertions:
        - No POST /enroll is sent for a 401 carrying an unknown class.
    '''
    manager.mode = 'REJECT_AUTH'
    # Set past the property's validation deliberately: what is under test is a class no build
    # knows, which the setter exists to keep a test from choosing by accident.
    manager._auth_force_class = 'a_class_from_the_future'

    assert wait_for(lambda: manager.get_requests(CONTROL_ENDPOINT), timeout=SETTLE)
    time.sleep(QUIET)

    assert enroll_requests(manager) == []
    assert stored_agent_id() == AGENT_ID


# ------------------------------------------------------------------ the class that does

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_unknown_agent_re_enrolls_with_the_stored_secret_and_keeps_the_id(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, restart_agentd):
    '''
    description: The one class that costs an identity. The agent must re-enroll, and it must do so
                 with the secret it stored -- presenting a bearer whose `kid` is its own id --
                 rather than falling back to a fleet-wide password it no longer has.

    assertions:
        - Exactly one POST /enroll follows the escalation.
        - Its bearer's `kid` is the agent's own id (so the stored secret was used).
        - The id survives; the key and the secret are both rotated.
    '''
    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = 'unknown_agent'

    assert wait_for(lambda: enroll_requests(manager), timeout=SETTLE), \
        'unknown_agent did not provoke a re-enrollment'
    expect_log('https_client: credential rejected (401); re-enrolling.')

    request = enroll_requests(manager)[0]
    assert bearer_kid(request) == AGENT_ID, \
        'The re-enrollment did not present the stored secret under the agent id'

    assert wait_for(lambda: stored_secret() not in (None, AGENT_REENROLL_SECRET), timeout=SETTLE), \
        'The rotated secret was never stored'
    assert stored_agent_id() == AGENT_ID, 'The agent id changed across a re-enrollment'

    # The manager's half rotated with it: the old secret can no longer produce a valid bearer.
    assert manager.reenroll_secret_for(AGENT_ID) == stored_secret()
    assert manager.reenroll_secret_for(AGENT_ID) != AGENT_REENROLL_SECRET


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_an_agent_whose_secret_is_also_refused_stops_and_says_so(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, restart_agentd):
    '''
    description: The manager refuses the control channel with `unknown_agent` AND refuses the
                 re-enrollment the same way. The stored secret is dead, there is no password to
                 fall back on, and the agent has to stop asking -- the behaviour #39064 exists to
                 introduce, in place of a loop that re-asked at the top of the ramp for ever.

    assertions:
        - The agent shreds the dead secret.
        - It logs that operator action is required and gives up.
        - It does not keep sending /enroll after that.
    '''
    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = 'unknown_agent'
    manager.enroll_force_auth_class = 'unknown_agent'

    assert wait_for(lambda: enroll_requests(manager), timeout=SETTLE)
    expect_log('This agent has no enrollment credential left to fall back on.')
    expect_log('https_client: re-enrollment cannot succeed; giving up')

    assert stored_secret() is None, 'The dead re-enrollment secret was not shredded'

    attempted = len(enroll_requests(manager))
    time.sleep(QUIET)
    assert len(enroll_requests(manager)) == attempted, 'The agent kept retrying after giving up'


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_a_dead_secret_falls_back_to_the_configured_password(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, restart_agentd):
    '''
    description: Same refusal, but this agent still has an authd.pass. Shredding the dead secret
                 must leave it able to enroll with the password instead of stopping -- otherwise
                 an agent that was purged on the manager could never come back on its own.

    assertions:
        - The agent announces the fallback and enrolls again.
        - The second attempt carries no `kid` (it is a password bearer, not the dead secret).
    '''
    password = 'FallbackEnrollmentSecret'
    with open(DEFAULT_AUTHD_PASS_PATH, 'w') as handle:
        handle.write(password + '\n')
    manager.enroll_password = password

    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = 'unknown_agent'
    manager.enroll_force_auth_class = 'unknown_agent'

    assert wait_for(lambda: enroll_requests(manager), timeout=SETTLE)
    expect_log('Falling back to the configured enrollment credential.')

    # Let the fallback attempt happen, then stop refusing so it can succeed.
    assert wait_for(lambda: any(bearer_kid(request) is None for request in enroll_requests(manager)),
                    timeout=SETTLE), 'The agent never fell back to the password credential'


# ------------------------------------------------------------------ enrollments the manager refuses

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
@pytest.mark.parametrize('forced, code', [('authd_token_not_found', 9022),
                                          ('authd_token_expired', 9023),
                                          ('authd_token_exhausted', 9024)])
def test_a_403_on_enroll_stops_immediately_and_names_the_code(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, forced, code, restart_agentd):
    '''
    description: authd's verdict on a bearer whose signature the manager already verified. A `403`
                 and not a `401` precisely because re-signing fixes nothing: only a new enrollment
                 token can, so the agent must stop rather than climb the retry ramp.

    assertions:
        - The agent logs the numeric code and that retrying will not help.
        - It sends no further /enroll.
    '''
    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = 'unknown_agent'
    manager.enroll_force_error = forced

    assert wait_for(lambda: enroll_requests(manager), timeout=SETTLE)
    expect_log(f'Enrollment token refused by the manager (code {code})')
    expect_log('https_client: re-enrollment cannot succeed; giving up')

    attempted = len(enroll_requests(manager))
    time.sleep(QUIET)
    assert len(enroll_requests(manager)) == attempted, 'A 403 did not stop the retry loop'


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_a_token_unknown_401_is_retried_until_the_manager_catches_up(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, restart_agentd):
    '''
    description: The worker sync window. A worker whose replica of the token store lags the master
                 answers `token_unknown` for a token that is perfectly valid; the agent must keep
                 trying rather than treat it as final. This is why `token_expired` and
                 `token_revoked` arriving as a 401 are also retryable, while authd's own 403 is not.

    assertions:
        - The agent retries the enrollment more than once.
        - It succeeds once the manager stops refusing, without having been restarted.
    '''
    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = 'unknown_agent'
    manager.enroll_force_auth_class = 'token_unknown'

    assert wait_for(lambda: len(enroll_requests(manager)) >= 2, timeout=SETTLE), \
        'A token_unknown 401 was not retried'
    expect_log('Enrollment rejected by the manager: token_unknown')

    manager.enroll_force_auth_class = None
    manager.mode = 'ACCEPT'

    assert wait_for(lambda: stored_secret() not in (None, AGENT_REENROLL_SECRET), timeout=SETTLE), \
        'The agent never recovered once the manager caught up'
    assert stored_agent_id() == AGENT_ID


# ------------------------------------------------------------------ the fleet-wide password

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_a_successful_enrollment_removes_the_fleet_wide_password(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, restart_agentd):
    '''
    description: Once this endpoint holds a per-agent secret, the shared password has no reason to
                 remain on it. The agent removes the file itself, which is what actually retires
                 the fleet-wide secret from the estate -- a package upgrade never does.

    assertions:
        - authd.pass is gone after an enrollment that returned a reenroll_secret.
        - The agent says so, naming the path.
    '''
    password = 'FleetWideEnrollmentSecret'
    with open(DEFAULT_AUTHD_PASS_PATH, 'w') as handle:
        handle.write(password + '\n')
    manager.enroll_password = password
    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = 'unknown_agent'

    assert wait_for(lambda: enroll_requests(manager), timeout=SETTLE)
    assert wait_for(lambda: not os.path.exists(DEFAULT_AUTHD_PASS_PATH), timeout=SETTLE), \
        'The fleet-wide enrollment password survived an enrollment that stored a secret'
    expect_log('has been removed: this agent now holds its own re-enrollment secret')


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_a_manager_that_issues_no_secret_leaves_the_password_alone(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, enrolled_agent,
        manager, restart_agentd):
    '''
    description: The upgrade order that matters: an agent on 5.0 talking to a manager that does not
                 issue re-enrollment secrets yet. Removing its password there would strand it with
                 no credential at all.

    assertions:
        - authd.pass is still on disk after a successful enrollment.
    '''
    password = 'FleetWideEnrollmentSecret'
    with open(DEFAULT_AUTHD_PASS_PATH, 'w') as handle:
        handle.write(password + '\n')
    manager.enroll_password = password
    manager.issue_reenroll_secret = False
    manager.mode = 'REJECT_AUTH'
    manager.auth_force_class = 'unknown_agent'

    assert wait_for(lambda: enroll_requests(manager), timeout=SETTLE)
    time.sleep(QUIET)

    assert os.path.exists(DEFAULT_AUTHD_PASS_PATH), \
        'The password was removed even though the manager issued no re-enrollment secret'


# ------------------------------------------------------------------ a fresh identity

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['reenrollment'])
def test_an_agent_with_no_keys_enrolls_and_stores_the_secret(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        restart_agentd):
    '''
    description: The first enrollment an agent ever performs. Deliberately without the
                 `enrolled_agent` fixture: nothing is seeded, so this is the path a freshly
                 installed endpoint takes, and it is what puts the secret on disk in the first
                 place.

    assertions:
        - The enrollment succeeds and the returned secret is stored.
        - It is stored under the id the manager assigned.
    '''
    assert wait_for(lambda: enroll_requests(manager), timeout=SETTLE), 'The agent never enrolled'

    assert wait_for(lambda: stored_secret() is not None, timeout=SETTLE), \
        'The reenroll_secret the manager returned was never stored'

    agent_id = stored_agent_id()
    assert manager.reenroll_secret_for(agent_id) == stored_secret()

    # The stored pair really is usable: it derives the key a re-enrollment bearer would be
    # signed with, which no assertion about the file's contents alone would show.
    assert jwt_enroll.derive_reenroll_key(stored_secret()) == \
        jwt_enroll.derive_reenroll_key(manager.reenroll_secret_for(agent_id))
