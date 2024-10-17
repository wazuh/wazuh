from queue import Queue
from unittest.mock import call, patch, Mock

from framework.wazuh.core.batcher.mux_demux import MuxDemuxQueue, Item, MuxDemuxManager


def test_send_to_mux():
    """Check that the `send_to_mux` method works as expected."""
    mux_queue = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        mux_queue=mux_queue,
        demux_queue=Queue()
    )

    expected_item_id = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_content = "test"

    queue.send_to_mux(Item(expected_item_id, expected_content))

    assert not mux_queue.empty()
    result = mux_queue.get()

    assert result.id == expected_item_id
    assert result.content == expected_content


def test_receive_from_mux():
    """Check that the `receive_from_mux` method works as expected."""
    mux_queue = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        mux_queue=mux_queue,
        demux_queue=Queue()
    )

    expected_id = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_content = "test"

    mux_queue.put(Item(expected_id, expected_content))

    result = queue.receive_from_mux()

    assert mux_queue.empty()
    assert result.id == expected_id
    assert result.content == expected_content


def test_send_to_demux():
    """Check that the `send_to_demux` method works as expected."""
    demux_queue = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        mux_queue=Queue(),
        demux_queue=demux_queue
    )

    expected_id = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_content = "test"

    queue.send_to_demux(Item(expected_id, expected_content))

    assert not demux_queue.empty()
    result = demux_queue.get()

    assert result.id == expected_id
    assert result.content == expected_content


def test_is_response_pending():
    """Check that the `is_response_pending` method works as expected."""
    dict_test = dict()
    queue = MuxDemuxQueue(
        proxy_dict=dict_test,
        mux_queue=Queue(),
        demux_queue=Queue()
    )

    example_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    dict_test[example_uid] = "test"

    assert not queue.is_response_pending(example_uid)


def test_receive_from_demux():
    """Check that the `receive_from_demux` method works as expected."""
    dict_test = dict()
    queue = MuxDemuxQueue(
        proxy_dict=dict_test,
        mux_queue=Queue(),
        demux_queue=Queue()
    )

    example_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    example_value = "test"
    dict_test[example_uid] = example_value

    result = queue.receive_from_demux(example_uid)

    assert result is not None
    assert result == example_value
    assert example_uid not in dict_test


def test_get_response_from_demux():
    """Check that the `internal_response_from_demux` method works as expected."""
    demux_queue = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        mux_queue=Queue(),
        demux_queue=demux_queue
    )

    expected_id = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_content = "test"

    demux_queue.put(Item(expected_id, expected_content))

    result = queue._get_response_from_demux()

    assert demux_queue.empty()
    assert result.id == expected_id
    assert result.content == expected_content


def test_store_response():
    """Check that the `internal_store_response` method works as expected."""
    dict_test = dict()
    queue = MuxDemuxQueue(
        proxy_dict=dict_test,
        mux_queue=Queue(),
        demux_queue=Queue()
    )

    example_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    example_value = "test"

    queue._store_response(Item(example_uid, example_value))

    assert example_uid in dict_test
    assert dict_test[example_uid] == example_value


@patch('framework.wazuh.core.batcher.mux_demux.SyncManager')
@patch('framework.wazuh.core.batcher.mux_demux.MuxDemuxRunner')
def test_mux_demux_manager_initialization(mux_demux_runner_mock, sync_manager_mock):
    """Check that the `MuxDemuxManager.__init___` method works as expected."""
    manager_mock = Mock()
    sync_manager_mock.return_value = manager_mock

    runner_mock = Mock()
    mux_demux_runner_mock.return_value = runner_mock

    MuxDemuxManager()

    manager_mock.assert_has_calls([
        call.start(),
        call.dict(),
        call.Queue(),
        call.Queue(),
        call.MuxDemuxQueue(manager_mock.dict(), manager_mock.Queue(), manager_mock.Queue()),
    ])
    runner_mock.assert_has_calls([
        call.start(),
    ])


@patch('framework.wazuh.core.batcher.mux_demux.SyncManager')
@patch('framework.wazuh.core.batcher.mux_demux.MuxDemuxRunner')
def test_mux_demux_manager_shutdown(mux_demux_runner_mock, sync_manager_mock):
    """Check that the `shutdown` method works as expected."""
    manager_mock = Mock()
    sync_manager_mock.return_value = manager_mock

    runner_mock = Mock()
    mux_demux_runner_mock.return_value = runner_mock

    manager = MuxDemuxManager()
    manager.shutdown()

    manager_mock.assert_has_calls([
        call.start(),
        call.dict(),
        call.Queue(),
        call.Queue(),
        call.MuxDemuxQueue(manager_mock.dict(), manager_mock.Queue(), manager_mock.Queue()),
        call.shutdown()
    ])
    runner_mock.assert_has_calls([
        call.start(),
        call.terminate()
    ])
