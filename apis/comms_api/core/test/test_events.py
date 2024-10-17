import pytest
from unittest.mock import patch, AsyncMock

from comms_api.core.events import create_stateful_events, send_stateless_events
from comms_api.models.events import StatefulEvents, StatelessEvents
from wazuh.core.engine.models.events import StatelessEvent
from wazuh.core.indexer import Indexer
from wazuh.core.indexer.models.events import SCAEvent, TaskResult

INDEXER = Indexer(host='host', user='wazuh', password='wazuh')


@pytest.mark.asyncio
@patch('wazuh.core.engine.events.EventsModule.send', new_callable=AsyncMock)
async def test_send_stateless_events(events_send_mock):
    """Check that the `send_stateless_events` function works as expected."""
    events = StatelessEvents(events=[StatelessEvent(data='data')])
    await send_stateless_events(events)

    events_send_mock.assert_called_once_with(events.events)


@pytest.mark.asyncio
@patch('wazuh.core.indexer.create_indexer', return_value=AsyncMock())
async def test_create_stateful_events(create_indexer_mock):
    """Check that the `create_stateful_events` function works as expected."""
    expected = [
        TaskResult(id='1', result='created', status=201),
        TaskResult(id='2', result='created', status=201),
    ]
    create_indexer_mock.return_value.events.create.return_value = expected
    batcher_queue = AsyncMock()

    events = StatefulEvents(events=[SCAEvent(), SCAEvent()])
    result = await create_stateful_events(events, batcher_queue)

    create_indexer_mock.assert_called_once()
    create_indexer_mock.return_value.events.create.assert_called_once()
    assert result == expected
