# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Publish the agent-group memberships a worker applied to its local wazuh-manager-db to the local remoted.

remoted authorizes configuration downloads against an in-memory registry of agent memberships. On a worker, the
master's agent-group memberships reach the local wazuh-manager-db in chunks; after each applied chunk, clusterd tells
the local remoted what it wrote (`POST /_internal/agents/groups` on remoted's admin socket), so a revoked group stops
being served at once instead of when remoted's cached membership expires. Publication is best effort by design: it
never blocks or delays the apply, and a publication that cannot be delivered is dropped -- remoted then follows the
database when the membership expires.
"""

import asyncio
import contextlib
import logging
import time
from typing import Callable, Iterable, Optional

from wazuh.core.engine_http import AsyncRemotedHTTPClient, RemotedAdminHTTPError
from wazuh.core.exception import WazuhException

# Publications waiting for the consumer; each carries one chunk (a few hundred agents at most), so this holds a full
# resync of a very large fleet. Over it, publications are dropped (and counted).
REGISTRY_PUBLISH_QUEUE_MAX = 1024
# Seconds between two warnings of the same kind; the ones in between are counted into the next.
REGISTRY_PUBLISH_WARN_INTERVAL = 60
# Errors after which the client is rebuilt: creation failed, or the connection itself is suspect.
_CLIENT_RESET_ERRORS = {2013, 2028, 2030, 2031}


class _WarnThrottle:
    """At most one warning per interval; the suppressed ones are reported with the next."""

    def __init__(self, interval: float = REGISTRY_PUBLISH_WARN_INTERVAL,
                 clock: Callable[[], float] = time.monotonic):
        self._interval = interval
        self._clock = clock
        self._last: Optional[float] = None
        self._suppressed = 0

    def warn(self, logger: logging.Logger, message: str) -> None:
        """Log `message` as a warning unless one was logged less than an interval ago.

        Parameters
        ----------
        logger : logging.Logger
            Logger to use.
        message : str
            Warning to log.
        """
        now = self._clock()
        if self._last is not None and now - self._last < self._interval:
            self._suppressed += 1
            return
        if self._suppressed:
            message = f'{message} ({self._suppressed} similar warning(s) suppressed in the last ' \
                      f'{self._interval}s)'
        logger.warning(message)
        self._last = now
        self._suppressed = 0


class RegistryPublisher:
    """FIFO of membership publications for the local remoted, drained by one task.

    Owned by the `Worker`, so the queue survives reconnections to the master: the consumer task, like every other
    cluster task, is cancelled when the connection is lost and started again with the next one, and continues with
    the publications still queued, in order. The one being posted when the task is cancelled is lost.
    """

    def __init__(self, logger: logging.Logger, client_factory: Callable = AsyncRemotedHTTPClient,
                 maxsize: int = REGISTRY_PUBLISH_QUEUE_MAX):
        """Class constructor.

        Parameters
        ----------
        logger : logging.Logger
            Logger to use.
        client_factory : callable
            Builds the client the publications are posted with.
        maxsize : int
            Maximum number of queued publications.
        """
        self.logger = logger
        self._client_factory = client_factory
        self._client = None
        self._queue = asyncio.Queue(maxsize=maxsize)
        self._error_throttle = _WarnThrottle()
        self._overflow_throttle = _WarnThrottle()
        self._missing_route_warned = False
        self.dropped = 0

    def enqueue(self, publications: Iterable[dict]) -> None:
        """Queue the publications of one apply, in order. Never blocks and never raises.

        Parameters
        ----------
        publications : iterable of dict
            One publication per applied chunk, in the chunk order: `{"set": [...]}` or `{"invalidate": [...]}`.
        """
        for publication in publications:
            if not publication.get('set') and not publication.get('invalidate'):
                continue
            try:
                self._queue.put_nowait(publication)
            except asyncio.QueueFull:
                self.dropped += 1
                self._overflow_throttle.warn(
                    self.logger, f'The queue of agent-groups publications for the local remoted is full '
                                 f'({self._queue.maxsize}); a publication was dropped ({self.dropped} in total). '
                                 f'remoted will read those agents\' groups from wazuh-manager-db when its cached '
                                 f'membership expires.')

    async def run(self) -> None:
        """Post the queued publications to the local remoted, one at a time, in order."""
        while True:
            publication = await self._queue.get()
            await self._publish(publication)

    async def _publish(self, publication: dict) -> None:
        """Post one publication. A failure is logged and the publication dropped: never raised."""
        try:
            if self._client is None:
                self._client = self._client_factory()
            counts = await self._client.post_agent_groups(publication)
        except RemotedAdminHTTPError as exc:
            if exc.status_code == 404:
                # An older remoted: nothing to do until it is upgraded, so say it once.
                if not self._missing_route_warned:
                    self._missing_route_warned = True
                    self.logger.warning('The local remoted does not accept agent-groups publications (404): it '
                                        'predates them. Its cached memberships follow wazuh-manager-db on expiry.')
                else:
                    self.logger.debug('Agent-groups publication not accepted by the local remoted (404).')
                return
            self._error_throttle.warn(self.logger, f'The local remoted refused an agent-groups publication: {exc}')
            return
        except WazuhException as exc:
            if exc.code in _CLIENT_RESET_ERRORS:
                await self._reset_client()
            self._error_throttle.warn(self.logger, f'Could not publish agent groups to the local remoted: {exc}')
            return
        except Exception as exc:
            await self._reset_client()
            self._error_throttle.warn(self.logger, f'Unexpected error publishing agent groups to the local remoted: '
                                                   f'{exc}')
            return

        counts = counts if isinstance(counts, dict) else {}
        self.logger.debug(f'Published agent groups to the local remoted: updated={counts.get("updated")}, '
                          f'invalidated={counts.get("invalidated")}, skipped={counts.get("skipped")}.')

    async def _reset_client(self) -> None:
        """Drop the current client so the next publication builds a new one."""
        client, self._client = self._client, None
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()
