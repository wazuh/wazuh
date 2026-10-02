# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from wazuh.core.cluster import registry_publisher
from wazuh.core.cluster.registry_publisher import RegistryPublisher
from wazuh.core.engine_http import RemotedAdminHTTPError
from wazuh.core.exception import WazuhInternalError

INVALIDATE_1 = {'invalidate': [1]}
INVALIDATE_2 = {'invalidate': [2, 4]}
INVALIDATE_3 = {'invalidate': [3]}
COUNTS = {'invalidated': 1, 'skipped': 0}


class FakeClient:
    """Stands in for AsyncRemotedHTTPClient: records every publication and answers from a script."""

    def __init__(self, outcomes=None):
        self.posted = []
        self.outcomes = list(outcomes or [])
        self.close = AsyncMock()

    async def post_agent_groups(self, publication):
        self.posted.append(publication)
        outcome = self.outcomes.pop(0) if self.outcomes else COUNTS
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def make_publisher(clients, maxsize=registry_publisher.REGISTRY_PUBLISH_QUEUE_MAX):
    """A publisher whose client factory hands out `clients` in turn, with a mock logger."""
    factory = MagicMock(side_effect=clients)
    return RegistryPublisher(logger=MagicMock(), client_factory=factory, maxsize=maxsize), factory


async def run_until(publisher, done):
    """Run the consumer until `done()` holds (bounded), then cancel it as a lost connection would."""
    task = asyncio.create_task(publisher.run())
    for _ in range(400):
        if done():
            break
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert done(), 'the consumer did not get there in time'


async def test_publishes_in_order():
    """One consumer posts the publications of an apply in the order they were queued."""
    client = FakeClient()
    publisher, _ = make_publisher([client])

    publisher.enqueue([INVALIDATE_1, INVALIDATE_3])
    publisher.enqueue([INVALIDATE_2])
    await run_until(publisher, lambda: len(client.posted) == 3)

    assert client.posted == [INVALIDATE_1, INVALIDATE_3, INVALIDATE_2]
    publisher.logger.warning.assert_not_called()


async def test_client_errors_are_logged_throttled_and_do_not_stop():
    """A transport error drops that publication, rebuilds the client and warns once per window; later ones go out."""
    first = FakeClient([WazuhInternalError(2031)])
    second = FakeClient([WazuhInternalError(2030)])
    third = FakeClient()
    publisher, factory = make_publisher([first, second, third])

    publisher.enqueue([INVALIDATE_1, INVALIDATE_2, INVALIDATE_3])
    await run_until(publisher, lambda: third.posted == [INVALIDATE_3])

    assert (first.posted, second.posted) == ([INVALIDATE_1], [INVALIDATE_2])  # each lost, never retried
    first.close.assert_awaited_once()
    second.close.assert_awaited_once()
    assert factory.call_count == 3
    assert publisher.logger.warning.call_count == 1  # two failures inside one throttle window


async def test_404_warns_once():
    """An older remoted that lacks the route is reported once, then at debug level."""
    client = FakeClient([RemotedAdminHTTPError(404), RemotedAdminHTTPError(404), RemotedAdminHTTPError(404)])
    publisher, factory = make_publisher([client])

    publisher.enqueue([INVALIDATE_1, INVALIDATE_2, INVALIDATE_3])
    await run_until(publisher, lambda: len(client.posted) == 3)

    assert client.posted == [INVALIDATE_1, INVALIDATE_2, INVALIDATE_3]
    assert publisher.logger.warning.call_count == 1
    assert '404' in publisher.logger.warning.call_args[0][0]
    assert publisher.logger.debug.call_count == 2
    # A refusal is not a transport error: the client is kept.
    assert factory.call_count == 1


async def test_refusal_is_warned_and_the_client_kept():
    """A 400 from remoted (a publication it refused) warns, throttled, and keeps the client."""
    client = FakeClient([RemotedAdminHTTPError(400, extra_message='bad'), COUNTS])
    publisher, factory = make_publisher([client])

    publisher.enqueue([INVALIDATE_1, INVALIDATE_2])
    await run_until(publisher, lambda: len(client.posted) == 2)

    assert client.posted == [INVALIDATE_1, INVALIDATE_2]
    assert publisher.logger.warning.call_count == 1
    assert factory.call_count == 1


def test_queue_full_drops_and_warns():
    """Over the queue bound, publications are dropped and counted, with one warning per window; never an error."""
    publisher, _ = make_publisher([], maxsize=1)

    publisher.enqueue([INVALIDATE_1, INVALIDATE_2, INVALIDATE_3])

    assert publisher._queue.qsize() == 1
    assert publisher.dropped == 2
    assert publisher.logger.warning.call_count == 1


def test_empty_publications_are_skipped():
    """Nothing to invalidate is never queued -- a publication carrying only groups too: remoted applies none."""
    publisher, _ = make_publisher([])

    publisher.enqueue([{}, {'set': [{'id': 1, 'groups': ['default']}]}, {'invalidate': []}, INVALIDATE_1])

    assert publisher._queue.qsize() == 1


async def test_cancel_keeps_the_queue():
    """Cancelling the consumer (a lost connection) keeps what is still queued, in order, for the next one."""
    gate = asyncio.Event()

    class BlockingClient(FakeClient):
        async def post_agent_groups(self, publication):
            self.posted.append(publication)
            await gate.wait()
            return COUNTS

    client = BlockingClient()
    publisher, _ = make_publisher([client])

    publisher.enqueue([INVALIDATE_1, INVALIDATE_2, INVALIDATE_3])
    await run_until(publisher, lambda: client.posted == [INVALIDATE_1])

    # INVALIDATE_1 was in flight and is lost; the rest wait for the next consumer, still in order.
    assert client.posted == [INVALIDATE_1]
    assert [publisher._queue.get_nowait(), publisher._queue.get_nowait()] == [INVALIDATE_2, INVALIDATE_3]


def test_warn_throttle_reports_the_suppressed_count():
    """The throttle logs once per interval and reports how many it held back."""
    now = [0.0]
    throttle = registry_publisher._WarnThrottle(interval=60, clock=lambda: now[0])
    logger = MagicMock()

    throttle.warn(logger, 'first')
    throttle.warn(logger, 'held')
    throttle.warn(logger, 'held')
    now[0] = 61.0
    throttle.warn(logger, 'again')

    assert [c[0][0] for c in logger.warning.call_args_list] == [
        'first', 'again (2 similar warning(s) suppressed in the last 60s)']
