from unittest.mock import patch, AsyncMock, call

import pytest

from framework.wazuh.core.batcher.client import BatcherClient, Packet
from wazuh.core.indexer.bulk import Operation
from wazuh.core.indexer.models.agent import Host, OS
from wazuh.core.indexer.models.events import Agent, AgentMetadata, Header, Module


@patch("wazuh.core.batcher.mux_demux.MuxDemuxQueue")
def test_send_event(queue_mock):
    """Check that the `send_event` method works as expected."""
    batcher = BatcherClient(queue=queue_mock)
    agent_metadata = AgentMetadata(agent=Agent(
        id='01929571-49b5-75e8-a3f6-1d2b84f4f71a',
        name='test',
        groups=['group1', 'group2'],
        type='endpoint',
        version='5.0.0',
        host=Host(
            architecture='x86_64',
            ip=['127.0.0.1'],
            os=OS(
                name='Debian 12',
                type='Linux'
            )
        ),
    ))
    header = Header(id='1234', module=Module.SCA, operation=Operation.CREATE)
    data = {
        'value': 1
    }

    packet = Packet()
    packet.build_and_add_item(agent_metadata, header, data)
    batcher.send_event(packet)
    queue_mock.send_to_mux.assert_called_once()


@pytest.mark.asyncio
@patch("wazuh.core.batcher.mux_demux.MuxDemuxQueue")
async def test_get_response(queue_mock):
    """Check that the `get_response` method works as expected."""
    batcher = BatcherClient(queue=queue_mock)

    event = {"data": "test event"}
    expected_uid = 1234

    queue_mock.is_response_pending.return_value = False
    queue_mock.receive_from_demux.return_value = event

    result = await batcher.get_response(expected_uid)

    queue_mock.is_response_pending.assert_called_once_with(expected_uid)
    assert result == event


@pytest.mark.asyncio
@patch("wazuh.core.batcher.mux_demux.MuxDemuxQueue")
@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_get_response_wait(sleep_mock, queue_mock):
    """Check that the `get_response` method works as expected with no response."""
    batcher = BatcherClient(queue=queue_mock)

    event = {"data": "test event"}
    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"

    queue_mock.is_response_pending.side_effect = [True, False]
    queue_mock.receive_from_demux.return_value = event

    result = await batcher.get_response(expected_uid)

    queue_mock.is_response_pending.assert_has_calls([call(expected_uid), call(expected_uid)])
    sleep_mock.assert_awaited()
    assert result == event
