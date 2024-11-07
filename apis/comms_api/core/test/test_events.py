import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from fastapi import FastAPI, Request
from starlette.requests import ClientDisconnect

from comms_api.core.events import create_stateful_events, send_stateless_events, send_events, parse_stateful_events, \
    parse_tasks_results
from comms_api.models.events import StatefulEvents
from wazuh.core.batcher.client import BatcherClient
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.bulk import Operation
from wazuh.core.indexer.models.agent import Host, OS
from wazuh.core.indexer.models.events import Agent, AgentMetadata, CommandResult, SCAEvent, TaskResult, StatefulEvent, \
    Header, Module, Result


@patch('wazuh.core.engine.events.EventsModule.send', new_callable=AsyncMock)
async def test_send_stateless_events(events_send_mock):
    """Check that the `send_stateless_events` function works as expected."""
    request = Request(scope={
        'type': 'http',
        'app': FastAPI(),
        'headers': [(b'content-type', b'application/json'), (b'transfer-encoding', b'chunked')]
    })
    stream_mock = MagicMock()
    request.stream = stream_mock

    await send_stateless_events(request=request)

    events_send_mock.assert_called_once_with(stream_mock())


@patch('wazuh.core.engine.events.EventsModule.send', side_effect=ClientDisconnect)
async def test_send_stateless_events_ko(events_send_mock):
    """Verify that the `send_stateless_events` function fails on a client disconnection."""
    request = Request(scope={
        'type': 'http',
        'app': FastAPI(),
    })
    stream_mock = MagicMock()
    request.stream = stream_mock

    with pytest.raises(WazuhError, match=r'2708'):
        await send_stateless_events(request=request)


@pytest.mark.asyncio
@patch('comms_api.core.events.BatcherClient')
@patch('comms_api.core.events.send_events')
async def test_create_stateful_events(send_events_mock, batcher_client_mock):
    """Check that the `create_stateful_events` function works as expected."""
    expected = [
        TaskResult(id='1', result='created', status=201),
        TaskResult(id='2', result='created', status=201),
    ]
    agent_metadata = AgentMetadata(
        id='ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
        groups=[],
        name='test',
        type='endpoint',
        version='v5.0.0'
    )
    batcher_queue = AsyncMock()
    batcher_client = BatcherClient(batcher_queue)
    batcher_client_mock.return_value = batcher_client
    send_events_mock.return_value = expected

    events = StatefulEvents(
        agent_metadata=AgentMetadata(agent=Agent(
            id='ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
            name='test',
            groups=[],
            type='endpoint',
            version='5.0.0',
            host=Host(
                architecture='x86_64',
                ip='127.0.0.1',
                os=OS(
                    name='Debian 12',
                    platform='Linux'
                )
            ),
        )),
        headers=[
            Header(
                id='1',
                operation=Operation.CREATE,
                module=Module.COMMAND
            ),
            Header(
                id='2',
                operation=Operation.UPDATE,
                module=Module.SCA
            ),
        ],
        events=[
            StatefulEvent(
                data=CommandResult(result=Result(
                    code=200,
                    message='',
                    data=''
                )),
            ),
            StatefulEvent(
                data=SCAEvent(),
            )
        ]
    )
    result = await create_stateful_events(events, batcher_queue)

    send_events_mock.assert_called_once_with(agent_metadata, events.events, batcher_client)
    assert result == expected


async def test_parse_stateful_events():
    """Verify that the `parse_stateful_events` function works as expected."""
    request = Request(scope={
        'type': 'http',
        'app': FastAPI(),
        'headers': [(b'content-type', b'application/json'), (b'transfer-encoding', b'chunked')]
    })
    request.app.state.batcher_queue = AsyncMock()

    agent_metadata = AgentMetadata(agent=Agent(
        id='01929571-49b5-75e8-a3f6-1d2b84f4f71a',
        name='test',
        groups=['group1', 'group2'],
        type='endpoint',
        version='5.0.0',
        host=Host(
            architecture='x86_64',
            hostname='wazuh-agent',
            ip=['127.0.0.1'],
            os=OS(
                name='Debian 12',
                platform='Linux'
            )
        ),
    ))
    header = Header(id='1', module=Module.COMMAND, operation=Operation.CREATE)
    event = StatefulEvent(data=CommandResult(result=Result(code=200, message='', data='')))
    events = StatefulEvents(
        agent_metadata=agent_metadata,
        headers=[header],
        events=[event],
    )
    request._body = '\n'.join([
        agent_metadata.model_dump_json(), 
        header.model_dump_json(),
        event.data.model_dump_json(),
    ]).encode()

    result = await parse_stateful_events(request)
    assert result == events


@pytest.mark.parametrize('disconnect_client, expected_code', [
    (True, 2708),
    (False, 2709)
])
async def test_parse_stateful_events_ko(disconnect_client, expected_code):
    """Verify that the `parse_stateful_events` function fails on an invalid request."""
    request = Request(scope={
        'type': 'http',
        'app': FastAPI(),
    })
    request.app.state.batcher_queue = AsyncMock()
    request._body = '\n'.join([
        '{"id": "123"}', 
    ]).encode()

    if disconnect_client:
        with patch('fastapi.Request.stream', side_effect=ClientDisconnect()):
            with pytest.raises(WazuhError, match=rf'{expected_code}'):
                await parse_stateful_events(request)
    else:
        with pytest.raises(WazuhError, match=rf'{expected_code}'):
                await parse_stateful_events(request)


@pytest.mark.asyncio
@patch('comms_api.core.events.BatcherClient')
@patch('comms_api.core.events.parse_tasks_results')
@patch('asyncio.create_task')
@patch('asyncio.gather', new_callable=AsyncMock)
async def test_send_events(gather_mock, create_task_mock, parse_tasks_results_mock, batcher_client_mock):
    """Check that the `send_events` function works as expected."""
    agent_metadata = AgentMetadata(
        id='ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
        groups=[],
        name='test',
        type='endpoint',
        version='v5.0.0'
    )

    events = StatefulEvents(events=[
        StatefulEvent(data=SCAEvent(), module=Module.SCA),
        StatefulEvent(data=SCAEvent(), module=Module.SCA)
    ])
    await send_events(agent_metadata, events, batcher_client_mock)

    create_task_mock.assert_called()
    gather_mock.assert_called_once()
    batcher_client_mock.send_event.assert_called_once_with(agent_metadata, ('events', list(events.events)))
    parse_tasks_results_mock.assert_called_once()


def test_parse_tasks_results():
    """Check that the `parse_tasks_results` function works as expected."""
    tasks_results = [
        {
            '_id': '1',
            'status': 201,
            'result': 'created',
        },
        {
            '_id': '2',
            'status': 200,
            'result': 'updated',

        },
        {
            'status': 400,
            'error': {
                'reason': 'invalid field `scan_time`'
            },
        }
    ]
    expected = [
        TaskResult(id='1', result='created', status=201),
        TaskResult(id='2', result='updated', status=200),
        TaskResult(id='', result='invalid field `scan_time`', status=400),
    ]
    results = parse_tasks_results(tasks_results)

    assert results == expected
