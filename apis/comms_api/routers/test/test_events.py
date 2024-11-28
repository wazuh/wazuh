from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from fastapi import Request, status
from fastapi.applications import FastAPI

from comms_api.models.events import StatefulEventsResponse
from comms_api.routers.events import post_stateful_events, post_stateless_events
from comms_api.routers.exceptions import HTTPError
from wazuh.core.exception import WazuhEngineError, WazuhError
from wazuh.core.indexer.models.events import TaskResult


@pytest.mark.asyncio
@patch('comms_api.routers.events.send_stateful_events')
@patch('comms_api.routers.events.parse_stateful_events')
async def test_post_stateful_events(parse_stateful_events_mock, send_stateful_events_mock):
    """Verify that the `post_stateful_events` handler works as expected."""
    request = Request(scope={
        'type': 'http',
        'app': FastAPI()
    })
    request.app.state.batcher_queue = AsyncMock()

    results = [TaskResult(id='123', result='created', status=201)]
    events = []
    parse_stateful_events_mock.return_value = events
    send_stateful_events_mock.return_value = results

    response = await post_stateful_events(request)

    parse_stateful_events_mock.assert_called_once_with(request)
    send_stateful_events_mock.assert_called_once_with(events, request.app.state.batcher_queue)

    assert isinstance(response, StatefulEventsResponse)
    assert response.results == results


@pytest.mark.asyncio
async def test_post_stateful_events_ko():
    """Verify that the `post_stateful_events` handler catches exceptions successfully."""
    request = MagicMock()
    request.app.state.batcher_queue = AsyncMock()  # Mock the batcher_queue

    code = status.HTTP_400_BAD_REQUEST
    exception = WazuhError(2200)

    with patch('comms_api.routers.events.parse_stateful_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=f'{code}: {exception.message}'):
            await post_stateful_events(request)


@pytest.mark.asyncio
@patch('comms_api.routers.events.send_stateless_events')
async def test_post_stateless_events(send_stateless_events_mock):
    """Verify that the `post_stateless_events` handler works as expected."""
    events = b'events'
    request = MagicMock()
    request._body = events
    response = await post_stateless_events(request)

    send_stateless_events_mock.assert_called_once_with(request)
    assert response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
async def test_post_stateless_events_ko():
    """Verify that the `post_stateless_events` handler catches exceptions successfully."""
    exception = WazuhEngineError(2802)

    with patch('comms_api.routers.events.send_stateless_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{exception.code}: {exception.message}'):
            _ = await post_stateless_events(MagicMock())
