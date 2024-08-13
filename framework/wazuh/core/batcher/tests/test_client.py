import pytest
from unittest.mock import patch, AsyncMock, call

from framework.wazuh.core.batcher.client import BatcherClient


@patch("wazuh.core.batcher.mux_demux.MuxDemuxQueue")
def test_send_event(queue_mock):
    """
    Test sending an event through the BatcherClient.
    Ensures that the event is sent to the mux queue with a unique identifier.
    """
    batcher = BatcherClient(queue=queue_mock)

    event = {"data": "test event"}
    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"

    queue_mock.send_to_mux.return_value = expected_uid

    result_uid = batcher.send_event(expected_uid, event)
    queue_mock.send_to_mux.assert_called_once_with(result_uid, event)


@pytest.mark.asyncio
@patch("wazuh.core.batcher.mux_demux.MuxDemuxQueue")
async def test_get_response(queue_mock):
    """
    Test getting a response asynchronously through the BatcherClient.
    Ensures that the response is retrieved correctly after waiting.
    """
    batcher = BatcherClient(queue=queue_mock)

    event = {"data": "test event"}
    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"

    queue_mock.is_response_pending.return_value = False
    queue_mock.receive_from_demux.return_value = event

    result = await batcher.get_response(expected_uid)

    queue_mock.is_response_pending.assert_called_once_with(expected_uid)
    assert result == event


@pytest.mark.asyncio
@patch("wazuh.core.batcher.mux_demux.MuxDemuxQueue")
@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_get_response_wait(sleep_mock, queue_mock):
    """
    Test getting a response when the response is pending.
    Test that it is awaited and then returned the correct response
    """

    batcher = BatcherClient(queue=queue_mock)

    event = {"data": "test event"}
    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"

    queue_mock.is_response_pending.side_effect = [True, False]
    queue_mock.receive_from_demux.return_value = event

    result = await batcher.get_response(expected_uid)

    queue_mock.is_response_pending.assert_has_calls([call(expected_uid), call(expected_uid)])
    sleep_mock.assert_awaited()
    assert result == event
