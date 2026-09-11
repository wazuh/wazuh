# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The agent upgrade routes, driven over the real socket.

These cover what a unit test structurally cannot. The headline claim of this subsystem — that a
fleet-wide upgrade costs ONE repository index fetch and ONE download rather than one of each per
agent — is a claim about how many HTTP requests left the process, and only a real repository on the
other end can count them. The same goes for the shutdown guarantee: that every parked request is
answered rather than left for the transport to 503, which needs a real request in flight when the
process is asked to stop.
"""

import threading
import time
from pathlib import Path

import pytest

from conftest import ModuleUnderTest, wait_until

UBUNTU = {'os_platform': 'ubuntu', 'os_major': '22', 'os_minor': '04',
          'os_arch': 'x86_64', 'version': 'v4.14.0'}
CENTOS = {'os_platform': 'centos', 'os_major': '9', 'os_arch': 'x86_64', 'version': 'v4.14.0'}
WINDOWS = {'os_platform': 'windows', 'os_arch': 'x86_64', 'version': 'v4.14.0'}

DEB_DIR = '/linux/deb/amd64/'
RPM_DIR = '/linux/rpm/x86_64/'
WIN_DIR = '/windows/'


def recent_time() -> int:
    """A request_time inside the module's accept window, [now - 1 year, now + 60 s].

    Never write a literal epoch into these tests. The module runs against the real clock here --
    unlike the unit tests, which inject one -- so a hardcoded timestamp is a time bomb that starts
    failing a year after it is written, with the misleading verdict "invalid parameter".
    """
    return int(time.time())

DEB_WPK = 'wazuh_agent_v5.0.0_linux_amd64.deb.wpk'
RPM_WPK = 'wazuh_agent_v5.0.0_linux_x86_64.rpm.wpk'
WIN_WPK = 'wazuh_agent_v5.0.0_windows.wpk'

# Big enough that a truncated or still-growing file would be visible, small enough to stay fast.
WPK_BODY = b'WPK' + b'\0' * 65536


def agent_id(number: int) -> str:
    """The zero-padded form both remoted pollers look tasks up by."""
    return f'{number:03d}'


def test_a_whole_fleet_costs_one_fetch_and_one_download(upgrade_module, wpk_repository):
    """THE TEST THIS SUBSYSTEM EXISTS FOR.

    The retired implementation fetched the repository index and re-hashed the WPK once per AGENT,
    in series, under one global mutex -- so this same request made 200 HTTPS round trips for the
    index alone. There is no way to assert that from inside the process.
    """
    agents = list(range(1, 201))
    upgrade_module.script_agents({n: UBUNTU for n in agents})
    wpk_repository.publish_wpk(DEB_DIR, 'v5.0.0', DEB_WPK, WPK_BODY)
    upgrade_module.start()

    with upgrade_module.client() as client:
        response = client.upgrade(agents)

    assert response.status_code == 200
    assert client.agent_errors(response) == [0] * len(agents)

    assert wpk_repository.count(f'{DEB_DIR}versions') == 1
    assert wpk_repository.count(f'{DEB_DIR}{DEB_WPK}') == 1


def test_a_mixed_fleet_costs_one_of_each_per_platform(upgrade_module, wpk_repository):
    rows = {}
    rows.update({n: UBUNTU for n in range(1, 21)})
    rows.update({n: CENTOS for n in range(21, 41)})
    rows.update({n: WINDOWS for n in range(41, 61)})
    upgrade_module.script_agents(rows)

    for directory, name in ((DEB_DIR, DEB_WPK), (RPM_DIR, RPM_WPK), (WIN_DIR, WIN_WPK)):
        wpk_repository.publish_wpk(directory, 'v5.0.0', name, WPK_BODY)
    upgrade_module.start()

    with upgrade_module.client() as client:
        response = client.upgrade(list(rows))

    assert client.agent_errors(response) == [0] * len(rows)
    # Three platforms, three of each -- not sixty.
    assert wpk_repository.total() == 6


def test_the_task_reaches_the_agent_through_the_normal_pending_route(upgrade_module, wpk_repository):
    """The upgrade path's whole output is an agent task, read by the same route as any other."""
    upgrade_module.script_agents({5: UBUNTU})
    digest = wpk_repository.publish_wpk(DEB_DIR, 'v5.0.0', DEB_WPK, WPK_BODY)
    upgrade_module.start()

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade([5])) == [0]

        tasks = client.take_pending(agent_id(5)).json()['tasks']

    assert len(tasks) == 1
    assert tasks[0]['task_type'] == 'remote_upgrade'

    payload = tasks[0]['payload']
    # A BARE file name: both delivery paths join it to the upgrade directory.
    assert payload['wpk_file'] == DEB_WPK
    assert payload['wpk_sha1'] == digest
    assert payload['installer'] == 'upgrade.sh'


def test_the_wpk_lands_complete_and_verified_on_disk(upgrade_module, wpk_repository):
    """Staged, verified, then renamed -- never served while it is still growing.

    remoted's download endpoint carries explicit defensive code against exactly that, because the
    retired downloader wrote straight to the final path.
    """
    upgrade_module.script_agents({5: UBUNTU})
    wpk_repository.publish_wpk(DEB_DIR, 'v5.0.0', DEB_WPK, WPK_BODY)
    upgrade_module.start()

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade([5])) == [0]

    served = upgrade_module.upgrade_dir / DEB_WPK
    assert served.read_bytes() == WPK_BODY
    # Nothing partial left behind either.
    assert not list((upgrade_module.upgrade_dir / '.staging').glob('*.part'))


def test_the_same_request_twice_creates_the_task_once(upgrade_module, wpk_repository):
    """Idempotency across cluster nodes, which all broadcast the same request.

    Every node derives the same task id from the same request_time, so a second identical request
    is the same task rather than a duplicate upgrade.
    """
    upgrade_module.script_agents({5: UBUNTU})
    wpk_repository.publish_wpk(DEB_DIR, 'v5.0.0', DEB_WPK, WPK_BODY)
    upgrade_module.start()

    # One value, sampled once and reused: it is the shared request_time that makes both requests
    # derive the same task id. What matters is that the two agree, not what the number is.
    request_time = recent_time()

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade([5], create_time=request_time)) == [0]
        assert client.agent_errors(client.upgrade([5], create_time=request_time)) == [0]

        assert len(client.take_pending(agent_id(5)).json()['tasks']) == 1


def test_one_agents_verdict_does_not_affect_the_others(upgrade_module, wpk_repository):
    upgrade_module.script_agents({
        1: UBUNTU,
        2: dict(UBUNTU, version='v5.0.0'),   # Already at the target.
        3: dict(UBUNTU, os_platform='solaris'),  # No WPK exists for it.
        # 4 is absent from the table entirely: not in the database.
    })
    wpk_repository.publish_wpk(DEB_DIR, 'v5.0.0', DEB_WPK, WPK_BODY)
    upgrade_module.start()

    with upgrade_module.client() as client:
        codes = client.agent_errors(client.upgrade([1, 2, 3, 4]))

    assert codes == [
        0,   # success
        10,  # current agent version is greater or equal
        7,   # the WPK for this platform is not available
        6,   # agent information not found in database
    ]

    # And the one that succeeded really did get a task.
    with upgrade_module.client() as client:
        assert len(client.take_pending(agent_id(1)).json()['tasks']) == 1


def test_an_unreachable_repository_is_reported_as_such(upgrade_module, wpk_repository):
    """Not "that version does not exist" -- the operator needs to be pointed at the URL."""
    upgrade_module.script_agents({1: UBUNTU})
    wpk_repository.fail(f'{DEB_DIR}versions', status=503)
    upgrade_module.start()

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade([1])) == [12]  # the repository is not reachable


def test_a_repository_serving_an_error_page_is_still_unreachable(upgrade_module, wpk_repository):
    """A proxy answering 200 with HTML used to parse as a version entry.

    The retired parser accepted any line containing a space, so `<html>404 not found</html>` became
    an entry, matched nothing, and reported "the version does not exist in the repository" -- the
    wrong cause, and cached under it.
    """
    upgrade_module.script_agents({1: UBUNTU})
    wpk_repository.publish(f'{DEB_DIR}versions', b'<html>404 not found</html>\n')
    upgrade_module.start()

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade([1])) == [12]


def test_a_version_the_repository_does_not_publish(upgrade_module, wpk_repository):
    upgrade_module.script_agents({1: UBUNTU})
    wpk_repository.publish(f'{DEB_DIR}versions', b'v4.14.0 aaaa1111\n')
    upgrade_module.start()

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade([1])) == [13]  # not in the repository

    # Nothing was downloaded, because there was nothing to download.
    assert wpk_repository.count(f'{DEB_DIR}{DEB_WPK}') == 0


def test_a_wpk_whose_digest_does_not_match_is_refused_and_not_served(upgrade_module, wpk_repository):
    """The digest and the body come from the same repository, so a mismatch means it served
    something other than what its own index claims."""
    upgrade_module.script_agents({1: UBUNTU})
    wpk_repository.publish(f'{DEB_DIR}versions', b'v5.0.0 ' + b'0' * 40 + b'\n')
    wpk_repository.publish(f'{DEB_DIR}{DEB_WPK}', WPK_BODY)
    upgrade_module.start()

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade([1])) == [15]  # sha1 is not valid

    assert not (upgrade_module.upgrade_dir / DEB_WPK).exists()


def test_the_legacy_gate_refuses_an_undeliverable_upgrade(testtool_path, tmp_path, consumer,
                                                          wpk_repository):
    """A pre-v5 agent with remote.legacy.enabled false can never be reached.

    Refusing beats creating a task that provably cannot be delivered.
    """
    module = ModuleUnderTest(testtool_path, tmp_path, tmp_path / 'consumer.sock')
    upgrade_dir = tmp_path / 'upgrade'
    upgrade_dir.mkdir()
    module.upgrade_dir = upgrade_dir
    module.with_upgrade_options(
        upgrade_dir=f'{upgrade_dir}/',
        wpk_repository=wpk_repository.base_url,
        manager_version='v5.0.0',
        remoted_legacy=0,
        remoted_verification=0,
    )
    module.script_agents({1: UBUNTU})
    wpk_repository.publish_wpk(DEB_DIR, 'v5.0.0', DEB_WPK, WPK_BODY)
    module.start()

    try:
        with module.client() as client:
            assert client.agent_errors(client.upgrade([1])) == [18]  # legacy delivery disabled
    finally:
        module.stop()


# ---- custom WPK ------------------------------------------------------------------------------


def test_a_custom_wpk_is_verified_once_and_downloads_nothing(upgrade_module, wpk_repository):
    upgrade_module.script_agents({n: UBUNTU for n in range(1, 11)})
    upgrade_module.start()

    wpk = upgrade_module.upgrade_dir / 'wazuh_agent_v5.0.0_linux_x86_64.wpk'
    wpk.write_bytes(WPK_BODY)

    with upgrade_module.client() as client:
        response = client.upgrade_custom(list(range(1, 11)), file_path=str(wpk))
        assert client.agent_errors(response) == [0] * 10

        payload = client.take_pending(agent_id(1)).json()['tasks'][0]['payload']

    assert payload['wpk_file'] == wpk.name
    # The operator supplied the file, so its digest is COMPUTED rather than compared.
    assert len(payload['wpk_sha1']) == 40
    assert wpk_repository.total() == 0


def test_a_custom_wpk_outside_the_upgrade_directory_is_refused(upgrade_module, tmp_path):
    """Not new hardening -- a bug fix.

    The task payload has always carried only the basename, and both delivery paths join it to the
    upgrade directory. A path pointing anywhere else already produced a task naming a file that was
    not there; now it is refused at admission instead.
    """
    upgrade_module.script_agents({1: UBUNTU})
    upgrade_module.start()

    outside = tmp_path / 'elsewhere.wpk'
    outside.write_bytes(WPK_BODY)

    with upgrade_module.client() as client:
        assert client.agent_errors(client.upgrade_custom([1], file_path=str(outside))) == [14]


def test_a_custom_installer_overrides_the_platform_default(upgrade_module):
    upgrade_module.script_agents({1: UBUNTU})
    upgrade_module.start()

    wpk = upgrade_module.upgrade_dir / 'wazuh_agent_v5.0.0_linux_x86_64.wpk'
    wpk.write_bytes(WPK_BODY)

    with upgrade_module.client() as client:
        assert client.agent_errors(
            client.upgrade_custom([1], file_path=str(wpk), installer='my-installer.sh')) == [0]

        payload = client.take_pending(agent_id(1)).json()['tasks'][0]['payload']

    assert payload['installer'] == 'my-installer.sh'


# ---- the response contract -------------------------------------------------------------------


# TS is substituted with recent_time() below, so the parametrize ids stay stable and readable while
# the bodies stay inside the module's accept window. These cases are meant to fail on the agent
# list, not on a stale timestamp.
@pytest.mark.parametrize('body, expected', [
    ('{not json', 1),                            # could not parse
    ('{"request_time": TS}', 2),                 # no agents
    ('{"agents": [], "request_time": TS}', 2),   # empty agents
    ('{"agents": [1]}', 3),                      # no request_time
    ('{"agents": ["x"], "request_time": TS}', 3),  # agent id not recognized
])
def test_a_bad_request_is_still_a_200_with_a_per_agent_envelope(upgrade_module, body, expected):
    """Every answer is 200, including for a body that would not parse.

    The Server API's HTTP client raises on ANY non-2xx, which would replace a precise per-agent
    message with a generic transport error. The framed socket these routes replace had no status
    code at all; the envelope carried everything, and still does.
    """
    upgrade_module.script_agents({1: UBUNTU})
    upgrade_module.start()

    body = body.replace('TS', str(recent_time()))

    with upgrade_module.client() as client:
        response = client._client.post('http://localhost/v1/agents/upgrade', content=body,
                                       headers={'Content-Type': 'application/json'})

    assert response.status_code == 200
    assert client.agent_errors(response) == [expected]


def test_a_disabled_module_refuses_every_agent_explicitly(testtool_path, tmp_path, consumer):
    """The retired module expressed "disabled" by never binding its socket.

    With the socket shared there is nothing to leave unbound, so the refusal has to be said out
    loud -- once per agent, so the caller can reconcile against what it sent.
    """
    module = ModuleUnderTest(testtool_path, tmp_path, Path(consumer.socket_path))
    module.with_upgrade_options(upgrade_enabled=0)
    module.start()

    try:
        with module.client() as client:
            response = client.upgrade([1, 2, 3])
            assert response.status_code == 200
            assert client.agent_errors(response) == [17] * 3  # upgrade procedure could not start
    finally:
        module.stop()


def test_shutdown_answers_a_request_rather_than_dropping_it(upgrade_module, wpk_repository):
    """THE SHUTDOWN GUARANTEE.

    A dropped responder becomes a transport 503, and the Server API raises on a 503 rather than
    halving the chunk and retrying -- so a shutdown during a fleet upgrade would lose a whole chunk
    of 500 agents instead of having it retried smaller. Every parked request is answered.
    """
    upgrade_module.script_agents({n: UBUNTU for n in range(1, 51)})
    # The repository never answers this path, so the batch is still working when SIGTERM lands.
    wpk_repository.publish(f'{DEB_DIR}versions', b'v5.0.0 ' + b'0' * 40 + b'\n')
    upgrade_module.start()

    answers = []

    def issue():
        with upgrade_module.client() as client:
            try:
                answers.append(client.upgrade(list(range(1, 51))))
            except Exception as exc:  # noqa: BLE001 - recorded, then asserted on below
                answers.append(exc)

    caller = threading.Thread(target=issue)
    caller.start()

    # Wait for the batch to actually be IN FLIGHT before stopping, rather than sleeping and hoping.
    # A request for the repository index proves it is past parsing and into the work -- which is the
    # only state where the shutdown path has a parked responder to answer.
    wait_until(lambda: wpk_repository.count(f'{DEB_DIR}versions') > 0, timeout=15)
    upgrade_module.stop(graceful=True)
    caller.join(timeout=40)

    assert len(answers) == 1, 'the request was never answered'
    response = answers[0]
    assert not isinstance(response, Exception), f'the request failed instead of being answered: {response}'
    assert response.status_code == 200

    # One entry per agent, so the caller can reconcile -- and never a dropped connection.
    body = response.json()
    assert len(body['data']) == 50
