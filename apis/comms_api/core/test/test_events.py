from unittest.mock import AsyncMock, patch

import pytest

from comms_api.core.events import create_stateful_events, send_stateless_events
from comms_api.models.events import StatelessEvents
from wazuh.core.engine import Engine
from wazuh.core.engine.models.events import StatelessEvent
from wazuh.core.indexer import Indexer
from wazuh.core.indexer.models.events import StatefulEvents, SCAEvent

INDEXER = Indexer(host='host', user='wazuh', password='wazuh')


@pytest.mark.asyncio
@patch('wazuh.core.indexer.create_indexer', return_value=INDEXER)
@patch('wazuh.core.indexer.events.EventsIndex.create')
async def test_create_stateful_events(events_create_mock, create_indexer_mock):
    """Check that the `create_stateful_events` function works as expected."""
    events = StatefulEvents(events=[SCAEvent()])
    await create_stateful_events(events)

    create_indexer_mock.assert_called_once()
    events_create_mock.assert_called_once_with(events)


@pytest.mark.asyncio
@patch('wazuh.core.engine.events.EventsModule.send', new_callable=AsyncMock)
async def test_send_stateless_events(events_send_mock):
    """Check that the `send_stateless_events` function works as expected."""
    events = StatelessEvents(events=[StatelessEvent(data='data')])
    await send_stateless_events(events)

    events_send_mock.assert_called_once_with(events.events)
