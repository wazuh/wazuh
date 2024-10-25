from unittest.mock import patch, AsyncMock, call

import pytest

from framework.wazuh.core.batcher.client import BatcherClient
from wazuh.core.indexer.models.events import SCAEvent


@patch("wazuh.core.batcher.mux_demux.MuxDemuxQueue")
@patch("builtins.id")
def test_send_event(id_mock, queue_mock):
    """Check that the `send_event` method works as expected."""
    batcher = BatcherClient(queue=queue_mock)
    event = SCAEvent()
    expected_item_id = 1234

    id_mock.return_value = expected_item_id

    item_id = batcher.send_event(event)
    assert item_id == expected_item_id
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
