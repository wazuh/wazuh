from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from fastapi import status

from comms_api.models.events import StatefulEvents, StatefulEventsResponse
from comms_api.routers.events import post_stateful_events, post_stateless_events
from comms_api.routers.exceptions import HTTPError
from wazuh.core.exception import WazuhEngineError, WazuhError
from wazuh.core.indexer.bulk import Operation
from wazuh.core.indexer.models.agent import Host, OS
from wazuh.core.indexer.models.events import AgentMetadata, TaskResult, StatefulEvent, Module, ModuleName, \
    CommandResult, Result


@pytest.mark.asyncio
@patch('comms_api.routers.events.create_stateful_events')
async def test_post_stateful_events(create_stateful_events_mock):
    """Verify that the `post_stateful_events` handler works as expected."""
    request = MagicMock()
    request.app.state.batcher_queue = AsyncMock()  # Mock the batcher_queue

    agent_id = '01929571-49b5-75e8-a3f6-1d2b84f4f71a'
    agent_metadata = AgentMetadata(
        id=agent_id,
        groups=['group1', 'group2'],
        type='endpoint',
        version='5.0.0',
        host=Host(
            architecture='x86_64',
            ip='127.0.0.1',
            os=OS(
                full='Debian 12',
                platform='Linux'
            )
        ),
    )
    events = StatefulEvents(agent=agent_metadata, events=[
        StatefulEvent(
            document_id='1',
            operation=Operation.CREATE,
            data=CommandResult(result=Result(
                code=200,
                message='',
                data=''
            )),
            module=Module(name=ModuleName.COMMAND),
        ),
    ])
    results = [TaskResult(id='123', result='created', status=201)]
    create_stateful_events_mock.return_value = results

    response = await post_stateful_events(request, events)

    create_stateful_events_mock.assert_called_once_with(events, request.app.state.batcher_queue)

    assert isinstance(response, StatefulEventsResponse)
    assert response.results == results


@pytest.mark.asyncio
async def test_post_stateful_events_ko():
    """Verify that the `post_stateful_events` handler catches exceptions successfully."""
    request = MagicMock()
    request.app.state.batcher_queue = AsyncMock()  # Mock the batcher_queue
    agent_id = '01929571-49b5-75e8-a3f6-1d2b84f4f71a'
    agent_metadata = AgentMetadata(
        id=agent_id,
        groups=['group1', 'group2'],
        type='endpoint',
        version='5.0.0',
        host=Host(
            architecture='x86_64',
            ip='127.0.0.1',
            os=OS(
                full='Debian 12',
                platform='Linux'
            )
        ),
    )
    events = StatefulEvents(document_id='', operation=Operation.CREATE, agent=agent_metadata, events=[])

    code = status.HTTP_400_BAD_REQUEST
    exception = WazuhError(2200)

    with patch('comms_api.routers.events.create_stateful_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=f'{code}: {exception.message}'):
            await post_stateful_events(request, events)


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
