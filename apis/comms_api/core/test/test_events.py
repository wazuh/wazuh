from unittest.mock import patch

import pytest

from comms_api.core.events import create_stateful_events
from wazuh.core.indexer import Indexer
from wazuh.core.indexer.models.events import Events, SCAEvent

INDEXER = Indexer(host='host', user='wazuh', password='wazuh')


@pytest.mark.asyncio
@patch('wazuh.core.indexer.create_indexer', return_value=INDEXER)
@patch('wazuh.core.indexer.events.EventsIndex.create')
async def test_create_stateful_events(events_create_mock, create_indexer_mock):
    events = Events(events=[SCAEvent()])
    await create_stateful_events(events)

    create_indexer_mock.assert_called_once()
    events_create_mock.assert_called_once_with(events)
