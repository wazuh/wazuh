import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from fastapi import FastAPI, Request

from comms_api.core.events import create_stateful_events, send_stateless_events, parse_stateful_events
from comms_api.models.events import StatefulEvents
from wazuh.core.exception import WazuhError
from wazuh.core.indexer import Indexer
from wazuh.core.indexer.bulk import Operation
from wazuh.core.indexer.models.agent import Host, OS
from wazuh.core.indexer.models.events import Agent, AgentMetadata, CommandResult, SCAEvent, TaskResult, StatefulEvent, \
    Header, Module, Result

INDEXER = Indexer(host='host', user='wazuh', password='wazuh')


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


async def test_send_stateless_events_ko():
    """Verify that the `send_stateless_events` function fails on an invalid request."""
    request = Request(scope={
        'type': 'http',
        'app': FastAPI(),
        'headers': [(b'content-type', b'application/json')]
    })

    with pytest.raises(WazuhError, match=r'2708'):
        await send_stateless_events(request=request)


@patch('wazuh.core.indexer.create_indexer', return_value=AsyncMock())
async def test_create_stateful_events(create_indexer_mock):
    """Check that the `create_stateful_events` function works as expected."""
    expected = [
        TaskResult(id='1', result='created', status=201),
        TaskResult(id='2', result='created', status=201),
    ]
    create_indexer_mock.return_value.events.send.return_value = expected
    batcher_queue = AsyncMock()

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

    create_indexer_mock.assert_called_once()
    create_indexer_mock.return_value.events.send.assert_called_once()
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


@pytest.mark.parametrize('headers, expected_code', [
    ([], 2708),
    ([(b'content-type', b'application/json')], 2708),
    ([(b'content-type', b'application/json'), (b'transfer-encoding', b'chunked')], 2709)
])
async def test_parse_stateful_events_ko(headers, expected_code):
    """Verify that the `parse_stateful_events` function fails on an invalid request."""
    request = Request(scope={
        'type': 'http',
        'app': FastAPI(),
        'headers': headers
    })
    request.app.state.batcher_queue = AsyncMock()
    request._body = '\n'.join([
        '{"id": "123"}', 
    ]).encode()

    with pytest.raises(WazuhError, match=rf'{expected_code}'):
        await parse_stateful_events(request)
