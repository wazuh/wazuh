from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from fastapi import status

from comms_api.models.events import StatefulEventsResponse
from comms_api.routers.events import post_stateful_events, post_stateless_events
from comms_api.routers.exceptions import HTTPError
from wazuh.core.exception import WazuhEngineError, WazuhError
from wazuh.core.indexer.models.events import AgentMetadata, TaskResult


@pytest.mark.asyncio
@patch('comms_api.routers.events.create_stateful_events')
@patch('comms_api.routers.events.decode_token')
async def test_post_stateful_events(decode_token_mock, create_stateful_events_mock):
    """Verify that the `post_stateful_events` handler works as expected."""
    request = MagicMock()
    request.app.state.batcher_queue = AsyncMock()  # Mock the batcher_queue

    events = [{"example": 1}]
    results = [TaskResult(id='123', result='created', status=201)]
    create_stateful_events_mock.return_value = results

    agent_id = '01929571-49b5-75e8-a3f6-1d2b84f4f71a'
    decode_token_mock.return_value = {'uuid': agent_id}
    token = 'token'
    user_agent = 'test endpoint v5.0.0'
    agent_groups = 'group1,group2'
    agent_metadata = AgentMetadata(
        id=agent_id,
        groups=['group1', 'group2'],
        name='test',
        type='endpoint',
        version='v5.0.0'
    )

    response = await post_stateful_events(token, user_agent, request, events, agent_groups)

    create_stateful_events_mock.assert_called_once_with(agent_metadata, events, request.app.state.batcher_queue)

    assert isinstance(response, StatefulEventsResponse)
    assert response.results == results


@pytest.mark.asyncio
@patch('comms_api.routers.events.decode_token')
async def test_post_stateful_events_ko(decode_token_mock):
    """Verify that the `post_stateful_events` handler catches exceptions successfully."""
    request = MagicMock()
    request.app.state.batcher_queue = AsyncMock()  # Mock the batcher_queue
    events = [{"example": 1}]

    code = status.HTTP_400_BAD_REQUEST
    exception = WazuhError(2200)

    with patch('comms_api.routers.events.create_stateful_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=f'{code}: {exception.message}'):
            await post_stateful_events('', 'test endpoint v5.0.0', request, events)


@pytest.mark.asyncio
@patch('comms_api.routers.events.send_stateless_events')
async def test_post_stateless_events(send_stateless_events_mock):
    """Verify that the `post_stateless_events` handler works as expected."""
    events = []
    response = await post_stateless_events(events)

    send_stateless_events_mock.assert_called_once_with(events)
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_post_stateless_events_ko():
    """Verify that the `post_stateless_events` handler catches exceptions successfully."""
    exception = WazuhEngineError(2802)

    with patch('comms_api.routers.events.send_stateless_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{exception.code}: {exception.message}'):
            _ = await post_stateless_events('')
