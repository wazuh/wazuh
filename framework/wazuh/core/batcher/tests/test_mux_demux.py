import pytest
from queue import Queue
from multiprocessing import Process
from multiprocessing.managers import SyncManager

from ..mux_demux import MuxDemuxQueue, Message, MuxDemuxManager


def test_send_to_mux():
    """
    Test sending a message to the mux queue.
    Ensures that the message is correctly placed in the queue.
    """
    q_mux = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        q_mux=q_mux,
        q_demux=Queue()
    )

    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_msg = "test message"

    queue.send_to_mux(expected_uid, expected_msg)

    assert not q_mux.empty()
    result = q_mux.get()

    assert result.uid == expected_uid
    assert result.msg == expected_msg


def test_receive_from_mux():
    """
    Test receiving a message from the mux queue.
    Ensures that the message is correctly retrieved from the queue.
    """
    q_mux = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        q_mux=q_mux,
        q_demux=Queue()
    )

    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_msg = "test message"

    q_mux.put(Message(expected_uid, expected_msg))

    result = queue.receive_from_mux()

    assert q_mux.empty()
    assert result.uid == expected_uid
    assert result.msg == expected_msg


def test_send_to_demux():
    """
    Test sending a message to the demux queue.
    Ensures that the message is correctly placed in the queue.
    """
    q_demux = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        q_mux=Queue(),
        q_demux=q_demux
    )

    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_msg = "test message"

    queue.send_to_demux(Message(expected_uid, expected_msg))

    assert not q_demux.empty()
    result = q_demux.get()

    assert result.uid == expected_uid
    assert result.msg == expected_msg


def test_is_response_pending():
    """
    Test if a response is pending for a given UID.
    Ensures that the response pending status is correctly determined.
    """
    dict_test = dict()
    queue = MuxDemuxQueue(
        proxy_dict=dict_test,
        q_mux=Queue(),
        q_demux=Queue()
    )

    example_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    dict_test[example_uid] = "test"

    assert not queue.is_response_pending(example_uid)


def test_receive_from_demux():
    """
    Test receiving a response from the demux queue.
    Ensures that the response is correctly retrieved and removed from the dictionary.
    """
    dict_test = dict()
    queue = MuxDemuxQueue(
        proxy_dict=dict_test,
        q_mux=Queue(),
        q_demux=Queue()
    )

    example_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    example_value = "test"
    dict_test[example_uid] = example_value

    result = queue.receive_from_demux(example_uid)

    assert result is not None
    assert result == example_value
    assert example_uid not in dict_test


def test_get_response_from_demux():
    """
    Test getting a response from the demux queue.
    Ensures that the response is correctly retrieved from the queue.
    """
    q_demux = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        q_mux=Queue(),
        q_demux=q_demux
    )

    expected_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_msg = "test message"

    q_demux.put(Message(expected_uid, expected_msg))

    result = queue._get_response_from_demux()

    assert q_demux.empty()
    assert result.uid == expected_uid
    assert result.msg == expected_msg


def test_store_response():
    """
    Test storing a response in the dictionary.
    Ensures that the response is correctly stored.
    """
    dict_test = dict()
    queue = MuxDemuxQueue(
        proxy_dict=dict_test,
        q_mux=Queue(),
        q_demux=Queue()
    )

    example_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    example_value = "test"

    queue._store_response(Message(example_uid, example_value))

    assert example_uid in dict_test
    assert dict_test[example_uid] == example_value


def test_mux_demux_manager_initialization():
    """
    Test the initialization of the MuxDemuxManager.
    Ensures that the manager and router process are correctly set up and running.
    """
    manager = MuxDemuxManager()
    assert isinstance(manager.get_manager(), SyncManager)
    assert isinstance(manager.get_router_process(), Process)

    assert manager.get_router_process().is_alive()


def test_mux_demux_manager_shutdown():
    """
    Test the shutdown of the MuxDemuxManager.
    Ensures that the router process is terminated and the manager is shut down.
    """
    manager = MuxDemuxManager()
    manager.shutdown()

    assert not manager.get_router_process().is_alive()
    with pytest.raises(AssertionError) as err:
        manager.get_manager().list()
    assert str(err.value) == "server not yet started"
