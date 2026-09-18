'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Verifies that an agent adopts the CA bundle publications its manager advertises
       (wazuh/wazuh#39321): which advertisements arm a refresh and which are inaction, what the
       agent refuses to install, and that a rotation carries it onto a certificate signed by the
       new CA without it ever losing the manager.

       A 5.x agent used to fetch the manager's CA once, at enrollment, and pin it forever. When
       that CA expired the agent could not even reach /cacerts to repair itself, because that
       route travels over the TLS that had just failed -- an entire fleet needing an operator on
       every endpoint. The manager now stamps each version of its bundle with a publication, a
       monotonic integer advertised on every notify and returned with the bundle itself, and the
       agent replaces its trust store wholesale: only over a channel it already trusts, only with
       the publication it was told to expect, and only upward.

       Each of those three qualifiers is a way the feature could go wrong, and each has its own
       case below. The refusals matter more than the adoptions: an agent that installs the wrong
       bundle has lost its manager permanently, which is the failure the feature exists to
       prevent rather than cause.

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
    - agentd
    - enrollment
'''
import time

import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.https_server import generate_ca_certificate, generate_leaf_certificate
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import CACERTS_ENDPOINT, CONTROL_ENDPOINT
from wazuh_testing.utils.callbacks import make_callback
from wazuh_testing.utils.configuration import load_configuration_template

from . import CONFIGS_PATH
from .conftest import (UNKNOWN_PUBLICATION, certificate_count, render_publication, runtime_uid,
                       store_bytes, store_owner, store_publication, wait_for, write_anchor)

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# One configuration for nearly the whole suite: what varies between cases is what the manager
# publishes, not how the agent is set up. The one exception is the disabled-verification case,
# which needs a posture the anchor alone cannot produce.
config_path = Path(CONFIGS_PATH, 'config_ca_rotation.yaml')
test_configuration = load_configuration_template(config_path, [{}], [{}])

unverified_path = Path(CONFIGS_PATH, 'config_ca_rotation_unverified.yaml')
unverified_configuration = load_configuration_template(unverified_path, [{}], [{}])

# How long to wait for something the agent does on its own schedule. The agent notifies every 3
# seconds under this configuration and the fetcher waits a uniform 0-9s (JITTER_INTERVALS, three
# keepalives) before its first attempt, so an adoption can legitimately take well over ten
# seconds to begin. QUIET is what a case waits to establish that something did NOT happen: it has
# to outlast that same window, or it proves only that the agent was still jittering.
SETTLE = 40
QUIET = 20

# The publications these cases move between. Timestamp-shaped, like the manager's own, and
# ordered so that "the next one" and "an older one" are both expressible.
FIRST = 1789000010
SECOND = 1789000011
THIRD = 1789000012


def cacerts_fetches(manager):
    return manager.get_requests(CACERTS_ENDPOINT)


def notifies(manager):
    return manager.get_requests(CONTROL_ENDPOINT)


def expect_log(message, timeout=SETTLE):
    """Assert that `message` reaches ossec.log within `timeout`."""
    monitor = FileMonitor(WAZUH_LOG_PATH)
    monitor.start(timeout=timeout, callback=make_callback(message, prefix='.*', escape=True))
    assert monitor.callback_result is not None, f'Not logged: {message!r}'


def expect_no_log(message, timeout=5):
    """Assert that `message` does NOT reach ossec.log within `timeout`.

    FileMonitor.start() returns rather than raising when the pattern never arrives, so the
    absence of a match has to be read off callback_result -- wrapping it in try/except would make
    the failure unconditional instead of conditional.
    """
    monitor = FileMonitor(WAZUH_LOG_PATH)
    monitor.start(timeout=timeout, callback=make_callback(message, prefix='.*', escape=True))
    assert monitor.callback_result is None, f'Logged, and should not have been: {message!r}'


def wait_for_adoption(manager, generation, timeout=SETTLE):
    """Wait until the trust store records `generation`, and report what it holds."""
    assert wait_for(lambda: store_publication() == generation, timeout=timeout), \
        f'The agent never adopted publication {generation} ' \
        f'(store records {store_publication()}, {len(cacerts_fetches(manager))} fetches)'


def publish(manager, generation, bundle=None):
    """Advertise `generation`, optionally serving a new bundle with it.

    Order matters and is the reason this is a function: the body has to be in place before the
    publication naming it is advertised. The other way round, the agent can fetch in the gap and
    legitimately refuse what it gets, which looks exactly like the bug these cases hunt for.
    """
    if bundle is not None:
        manager.cacerts_certificate = bundle
    manager.ca_generation = generation


# ------------------------------------------------------------------ what arms a refresh

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_an_agent_that_has_recorded_no_publication_adopts_the_first_one_advertised(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: The upgrade case, and the one every existing install starts from. An agent
                 anchored before #39321 holds a trust store with no publication recorded in it;
                 that is not the same as holding publication 0, and the agent must re-anchor on
                 the first publication it is offered rather than treat an unknown local value as
                 "nothing to do" forever.

                 This case also proves the repair: the fixture seeds the anchor in its pre-#39321
                 shape, root-owned under a 0750 directory, where the unprivileged agent could not
                 replace it. It can only install here because agentd corrected that on startup.

    assertions:
        - The store records no publication before the manager advertises one.
        - One GET /cacerts follows, and the store then records the advertised publication.
        - The installed bytes are the ones the route served, under the agent's own block.
        - The store ends up owned by the runtime user, at 0640.
    '''
    assert store_publication() == UNKNOWN_PUBLICATION, \
        'The seeded anchor already recorded a publication; the case proves nothing'
    assert wait_for(lambda: notifies(manager), timeout=SETTLE), \
        'The agent never reached /control, so it never verified this manager'

    publish(manager, FIRST)

    wait_for_adoption(manager, FIRST)
    expect_log(f'Manager advertises CA bundle publication {FIRST}; the agent holds 0.')
    expect_log(f'Adopted CA bundle publication {FIRST}.')

    assert len(cacerts_fetches(manager)) == 1, \
        f'One publication took {len(cacerts_fetches(manager))} fetches'
    assert store_bytes() == render_publication(FIRST) + manager.cacerts_pem, \
        'The installed store is not the block plus exactly the bytes the route served'

    uid, _, mode = store_owner()
    assert (uid, mode) == (runtime_uid(), 0o640), \
        f'The replaced store is {uid}:{oct(mode)}, which the agent could not replace again'


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_a_higher_publication_replaces_the_trust_store_wholesale(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: The ordinary rotation step: the manager publishes a bundle carrying a second CA,
                 and the agent ends up trusting both. Wholesale replacement, not a merge -- the
                 store must be the served bundle and nothing else, because an agent that
                 accumulated every CA it was ever shown could never be made to stop trusting one.

    assertions:
        - The agent adopts the new publication and the store holds both certificates.
        - The store is byte-for-byte the block plus the served bundle, with nothing merged in.
    '''
    publish(manager, FIRST)
    wait_for_adoption(manager, FIRST)
    assert certificate_count() == 1

    second_ca, _ = generate_ca_certificate(common_name='Wazuh Rotation CA B')
    publish(manager, SECOND, bundle=manager.cacerts_pem + second_ca)

    wait_for_adoption(manager, SECOND)
    assert certificate_count() == 2, 'The published second CA was not installed'
    assert store_bytes() == render_publication(SECOND) + manager.cacerts_pem, \
        'The store is not exactly the bundle that was served'
    assert second_ca in store_bytes()


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_the_publication_the_agent_already_holds_is_never_fetched(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: The steady state, and by far the most common one: the manager advertises the
                 same publication on every keepalive for as long as nothing rotates. The decision
                 is a comparison against a cached integer precisely so this costs nothing -- a
                 fleet that re-fetched its CA every ten seconds would be a denial of service its
                 own manager could not survive.

    assertions:
        - No GET /cacerts is ever sent.
        - The store is untouched, publication included.
    '''
    write_anchor(manager.cacerts_pem, generation=FIRST)
    before = store_bytes()

    manager.ca_generation = FIRST

    assert wait_for(lambda: len(notifies(manager)) >= 3, timeout=SETTLE), \
        'The agent did not settle into a keepalive cadence'
    time.sleep(QUIET)

    assert cacerts_fetches(manager) == [], \
        'The agent re-fetched a bundle it already holds'
    assert store_bytes() == before


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_a_node_advertising_an_older_publication_is_ignored(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: Adoption is upward only. Behind a load balancer an agent reaches a different node
                 on every connection, and a node whose bundle has not caught up advertises a lower
                 publication than the agent already holds. Following it would walk the agent
                 backwards onto a CA that is being retired -- and, since the nodes disagree only
                 while a rotation is in flight, would do it at exactly the worst moment.

    assertions:
        - No GET /cacerts follows an advertisement below what the agent holds.
        - The store still records the higher publication.
    '''
    write_anchor(manager.cacerts_pem, generation=SECOND)
    before = store_bytes()

    manager.ca_generation = FIRST

    assert wait_for(lambda: len(notifies(manager)) >= 3, timeout=SETTLE)
    time.sleep(QUIET)

    assert cacerts_fetches(manager) == [], \
        'The agent followed a node that had fallen behind it'
    assert store_publication() == SECOND
    assert store_bytes() == before


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_a_manager_that_advertises_nothing_never_arms_a_refresh(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: The compatibility case: a manager predating #39321 does not mention
                 ca_generation at all. Absent is not zero and neither is a reason to act, but they
                 say different things -- the first says nothing about CA bundles, the second says
                 there is a bundle nobody has published -- and an agent that guessed a publication
                 out of silence would fetch from a route that may not even exist.

    assertions:
        - No GET /cacerts is sent, and the agent never says a refresh is due.
        - The store is untouched.
    '''
    before = store_bytes()

    assert wait_for(lambda: len(notifies(manager)) >= 3, timeout=SETTLE)
    time.sleep(QUIET)

    assert cacerts_fetches(manager) == [], \
        'The agent fetched a bundle no manager had advertised'
    expect_no_log('A refresh is due')
    assert store_bytes() == before


# ------------------------------------------------------------------ what the agent refuses to install

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_a_bundle_stamped_with_another_publication_is_refused(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: The case the Wazuh-CA-Generation header exists for. The agent asks the load
                 balancer for the publication one node advertised and reaches a different node,
                 which answers with a bundle of its own. Installing it would put content on disk
                 that the publication being adopted never named. The agent keeps what it has and
                 stays armed, so the next attempt can reach a node that has caught up.

    assertions:
        - The agent names both publications and installs neither.
        - The store is byte-identical, and still records what it recorded before.
        - It keeps trying, rather than dropping the target it could not satisfy.
    '''
    publish(manager, FIRST)
    wait_for_adoption(manager, FIRST)
    before = store_bytes()

    # The body a lagging node would serve, under the publication it is still on.
    manager.cacerts_generation = FIRST
    manager.ca_generation = SECOND

    expect_log(f'CA bundle refresh expected publication {SECOND} but the node served {FIRST}; '
               'not installing it.')
    assert store_bytes() == before, 'A mismatched bundle reached the trust store'
    assert store_publication() == FIRST

    attempted = len(cacerts_fetches(manager))
    assert wait_for(lambda: len(cacerts_fetches(manager)) > attempted, timeout=SETTLE), \
        'The agent dropped a publication it had not satisfied'

    # It recovers unaided the moment a node serves what was advertised: no restart, no operator.
    manager.follow_ca_generation()
    wait_for_adoption(manager, SECOND)


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_a_bundle_served_without_a_publication_is_refused(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: A node that serves a bundle and vouches for nothing about it -- one predating the
                 feature, or one whose bundle carries no valid publication. The advertisement came
                 from somewhere, so the agent is right to ask; what comes back is content nothing
                 names, and adopting it would record a publication the served bytes never claimed.

    assertions:
        - The agent refuses, naming the publication it was trying to adopt.
        - The store is byte-identical.
    '''
    before = store_bytes()

    manager.cacerts_generation = None
    manager.ca_generation = FIRST

    expect_log(f'CA bundle refresh for publication {FIRST} came back without a publication of '
               'its own; not installing it.')
    assert store_bytes() == before
    assert store_publication() == UNKNOWN_PUBLICATION


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_a_body_that_is_not_a_certificate_bundle_is_refused(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: A body that is PEM-shaped but is not certificates. The agent validates what it
                 fetched by parsing the whole thing, from the temporary file rather than from the
                 buffer, so what is judged is exactly what would be installed -- and it is judged
                 before anything reaches the path the agent verifies against. A store that failed
                 to parse would leave the agent unable to reach its manager at all, which is the
                 one outcome no refusal may produce.

    assertions:
        - The agent reports that the body is not a bundle it can parse.
        - The store is byte-identical and still holds a usable certificate.
    '''
    before = store_bytes()

    garbage = (b'-----BEGIN CERTIFICATE-----\n'
               b'this is not a certificate, and must never become one\n'
               b'-----END CERTIFICATE-----\n')
    publish(manager, FIRST, bundle=garbage)

    expect_log(f'CA bundle: the body served for publication {FIRST} is not a certificate bundle '
               'this agent can parse; the trust store is unchanged.')
    assert store_bytes() == before, 'A body that is not certificates reached the trust store'
    assert certificate_count() == 1


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
@pytest.mark.parametrize('outcome', ['not_found', 'ca_mismatch'])
def test_a_refused_route_leaves_the_trust_store_byte_identical(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, outcome, restart_agentd):
    '''
    description: A node with no bundle (404) and a node whose bundle does not sign the certificate
                 it is serving (503). Neither is a reason to touch the trust store, and neither is
                 fatal: the publication stays armed and the agent comes back to it.

    assertions:
        - The agent asks, and the store is untouched afterwards.
        - It keeps asking rather than giving up on the publication.
        - It adopts as soon as the route answers.
    '''
    before = store_bytes()

    manager.cacerts_force_error = outcome
    manager.ca_generation = FIRST

    assert wait_for(lambda: cacerts_fetches(manager), timeout=SETTLE), \
        'The agent never asked for the advertised publication'
    assert store_bytes() == before

    attempted = len(cacerts_fetches(manager))
    assert wait_for(lambda: len(cacerts_fetches(manager)) > attempted, timeout=SETTLE), \
        f'The agent stopped retrying after a {outcome}'
    assert store_bytes() == before, 'A refused route still changed the trust store'

    manager.cacerts_force_error = None
    wait_for_adoption(manager, FIRST)


@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_a_rate_limited_refresh_is_deferred_and_then_adopted(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: wazuh/wazuh#39280 rate-limits /cacerts, and a fleet rotating at once is exactly
                 what meets that limit -- so a 429 is an expected part of a successful rotation,
                 not a failure of one. The agent keeps the store it has, defers by Retry-After,
                 and comes back. Retry-After is honoured only up to MAX_AGENT_DELAY (one minute):
                 the value arrives from the network, and because a refused target stays armed
                 rather than being dropped, an unbounded delay would not postpone the refresh so
                 much as end it.

    assertions:
        - The store survives the rate limit untouched.
        - The agent retries and adopts once the limit lifts, unaided.
    '''
    before = store_bytes()

    manager.cacerts_force_error = 'rate_limited'
    manager.ca_generation = FIRST

    assert wait_for(lambda: cacerts_fetches(manager), timeout=SETTLE), \
        'The agent never asked for the advertised publication'

    attempted = len(cacerts_fetches(manager))
    assert wait_for(lambda: len(cacerts_fetches(manager)) > attempted, timeout=SETTLE), \
        'The agent did not come back after being rate limited'
    assert store_bytes() == before, 'A 429 changed the trust store'

    manager.cacerts_force_error = None
    wait_for_adoption(manager, FIRST)


@pytest.mark.parametrize('test_configuration', unverified_configuration, ids=['no_verification'])
def test_a_refresh_is_never_issued_when_verification_is_disabled(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: Verification is the entire basis for trusting the answer, so there is no refresh
                 without it. Under 'none' there is nothing to verify the served bundle against;
                 fetching anyway would let whoever answered the connection choose what the agent
                 trusts from then on -- turning a feature that repairs trust into the means of
                 replacing it.

    assertions:
        - The agent confirms it is running with an anchor it has been told to ignore.
        - No GET /cacerts is sent, however loudly the manager advertises.
        - The store is untouched.
    '''
    before = store_bytes()

    # The posture really is 'none': the agent holds an anchor and has been told not to use it.
    expect_log('is ignored')

    manager.ca_generation = FIRST

    assert wait_for(lambda: len(notifies(manager)) >= 3, timeout=SETTLE)
    time.sleep(QUIET)

    assert cacerts_fetches(manager) == [], \
        'The agent fetched a CA bundle it had no way to verify'
    assert store_bytes() == before


# ------------------------------------------------------------------ the rotation, end to end

@pytest.mark.parametrize('test_configuration', test_configuration, ids=['ca_rotation'])
def test_the_agent_follows_its_manager_onto_a_certificate_signed_by_the_new_ca(
        test_configuration, set_wazuh_configuration, truncate_monitored_files, manager,
        anchored_agent, restart_agentd):
    '''
    description: The runbook the whole feature exists for, in the order an operator performs it:
                 publish a bundle carrying the new CA alongside the old; reissue the manager's
                 certificate under the new CA; publish again, dropping the old. Every other case
                 here checks one decision -- this one checks that the decisions compose into a
                 rotation an agent survives.

                 The overlap is what makes it survivable, and doing it in the wrong order is the
                 mistake this case would catch: a manager that reissued before publishing would
                 present a certificate signed by a CA no agent yet trusts, and every agent in the
                 fleet would be locked out of the route that could have fixed it.

    assertions:
        - The agent trusts both CAs while the overlap lasts.
        - It keeps reaching the manager after the certificate is reissued under the new CA.
        - It then drops the old CA, and is left verifying against the new one alone.
    '''
    publish(manager, FIRST)
    wait_for_adoption(manager, FIRST)
    original_ca = manager.cacerts_pem

    # Step 1: publish the new CA alongside the one in force.
    new_ca, new_ca_key = generate_ca_certificate(common_name='Wazuh Rotation CA B')
    publish(manager, SECOND, bundle=original_ca + new_ca)
    wait_for_adoption(manager, SECOND)
    assert certificate_count() == 2, 'The overlap bundle was not adopted'

    # Step 2: reissue the manager's certificate under the new CA. Assigning after start() takes
    # effect on the next one, so the listener is restarted -- which is what an operator does too.
    manager.tls_certificate = generate_leaf_certificate(new_ca, new_ca_key,
                                                        ip_addresses=('127.0.0.1',))
    manager.shutdown()
    manager.clear()
    manager.start()

    assert wait_for(lambda: notifies(manager), timeout=SETTLE), \
        'The agent never came back after the manager was reissued under the new CA'

    # Step 3: retire the old CA. The agent is verifying against the new certificate by now, so
    # dropping the CA that signed the old one costs it nothing.
    publish(manager, THIRD, bundle=new_ca)
    wait_for_adoption(manager, THIRD)

    assert certificate_count() == 1, 'The retired CA was left in the trust store'
    assert original_ca not in store_bytes(), 'The agent kept trusting a CA that was withdrawn'
    assert new_ca in store_bytes()

    # And it is still talking to the manager, verified against the new CA alone.
    reached = len(notifies(manager))
    assert wait_for(lambda: len(notifies(manager)) > reached, timeout=SETTLE), \
        'The agent stopped reaching the manager once the old CA was dropped'
