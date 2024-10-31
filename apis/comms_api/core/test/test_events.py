import pytest
from unittest.mock import patch, AsyncMock

from comms_api.core.events import create_stateful_events, send_stateless_events, parse_agent_metadata
from comms_api.models.events import StatefulEvents, StatelessEvents
from wazuh.core.engine.models.events import StatelessEvent, Event, WazuhLocation
from wazuh.core.indexer import Indexer
from wazuh.core.indexer.models.events import AgentMetadata, SCAEvent, TaskResult, StatefulEvent, ModuleName

INDEXER = Indexer(host='host', user='wazuh', password='wazuh')


@pytest.mark.asyncio
@patch('wazuh.core.engine.events.EventsModule.send', new_callable=AsyncMock)
async def test_send_stateless_events(events_send_mock):
    """Check that the `send_stateless_events` function works as expected."""
    events = [
        StatelessEvent(
            wazuh=WazuhLocation(queue=50, location="[003] (agent-name) any->/tmp/syslog.log"),
            event=Event(original="original message, recollected from the agent")
        )
    ]
    await send_stateless_events(StatelessEvents(events=events))

    events_send_mock.assert_called_once_with(events)


@pytest.mark.asyncio
@patch('wazuh.core.indexer.create_indexer', return_value=AsyncMock())
async def test_create_stateful_events(create_indexer_mock):
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
    create_indexer_mock.return_value.events.create.return_value = expected
    batcher_queue = AsyncMock()

    events = StatefulEvents(events=[
        StatefulEvent(data=SCAEvent(), module=ModuleName.SCA),
        StatefulEvent(data=SCAEvent(), module=ModuleName.SCA)
    ])
    result = await create_stateful_events(agent_metadata, events, batcher_queue)

    create_indexer_mock.assert_called_once()
    create_indexer_mock.return_value.events.create.assert_called_once()
    assert result == expected


@pytest.mark.parametrize('agent_id, user_agent, agent_groups, expected', [
    (
        'ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
        'test endpoint v5.0.0',
        '',
        AgentMetadata(
            id='ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
            groups=[],
            name='test',
            type='endpoint',
            version='v5.0.0'
        )
    ),
    (
        'ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
        'test2 lambda v5.0.1',
        'default,group1,group2',
        AgentMetadata(
            id='ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
            groups=['default', 'group1', 'group2'],
            name='test2',
            type='lambda',
            version='v5.0.1'
        )
    ),
])
def test_parse_agent_metadata(agent_id, user_agent, agent_groups, expected):
    """Check that the `parse_agent_metadata` function works as expected."""
    agent_metadata = parse_agent_metadata(agent_id, user_agent, agent_groups)

    assert agent_metadata == expected
