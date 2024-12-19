import sys
from queue import Queue
from unittest.mock import call, patch, Mock

from framework.wazuh.core.batcher.mux_demux import MuxDemuxQueue, Item, MuxDemuxManager, Packet
from wazuh.core.indexer.bulk import Operation
from wazuh.core.indexer.models.agent import Host, OS
from wazuh.core.indexer.models.events import Agent, AgentMetadata, Header, Module, get_module_index_name


def test_packet_initialization():
    """Check that the `__init__` method works as expected."""
    packet = Packet()

    assert packet.id is None
    assert packet.items == []

    example_item = Item(1, 'create')
    initialized_packet = Packet(1, [example_item])
    assert initialized_packet.id == 1
    assert initialized_packet.items == [example_item]


def test_packet_has_item():
    """Check that the `has_item` method works as expected."""
    packet = Packet()
    packet.add_item(Item(1, 'create'))

    assert packet.has_item(1)
    assert not packet.has_item(2)


def test_packet_get_len():
    """Check that the `get_len` method works as expected."""
    packet = Packet()
    packet.add_item(Item(1, 'create'))
    packet.add_item(Item(2, 'create'))

    assert packet.get_len() == 2


def test_packet_get_size():
    """Check that the `get_size` method works as expected."""
    packet = Packet()
    item = Item(1, 'create', {'example': 'data'})
    packet.add_item(item)
    packet.add_item(item)

    size_of_msg = sys.getsizeof(item.content)
    assert packet.get_size() == size_of_msg * 2


def test_packet_build_and_add_item():
    """Check that the `build_and_add_item` method works as expected."""
    agent_metadata = AgentMetadata(agent=Agent(
        id='01929571-49b5-75e8-a3f6-1d2b84f4f71a',
        name='test',
        groups=['group1', 'group2'],
        type='endpoint',
        version='5.0.0',
        host=Host(
            architecture='x86_64',
            ip='127.0.0.1',
            os=OS(
                name='Debian 12',
                type='Linux'
            )
        ),
    ))
    header = Header(id='1234', module=Module.SCA, operation=Operation.CREATE)

    packet = Packet()
    packet.build_and_add_item(agent_metadata, header)

    assert packet.items[0].id == header.id
    assert packet.items[0].operation == header.operation
    assert packet.items[0].content is None
    assert packet.items[0].index_name == get_module_index_name(header.module, header.type)


def test_packet_add_item():
    """Check that the `add_item` method works as expected."""
    packet = Packet()
    item = Item(1, 'create', {'example': 'data'})
    packet.add_item(item)

    assert packet.get_len() == 1
    assert packet.id == item.id

    second_item = Item(2, 'create', {'example': 'data'})
    packet.add_item(second_item)

    assert packet.get_len() == 2
    assert packet.id == item.id


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

    queue.send_to_mux(Item(id=expected_item_id, content=expected_content, operation='create'))

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

    mux_queue.put(Item(id=expected_id, content=expected_content, operation='create'))

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

    queue.send_to_demux(Item(id=expected_id, content=expected_content, operation='create'))

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


def test_internal_get_response_from_demux():
    """Check that the `internal_get_response_from_demux` method works as expected."""
    demux_queue = Queue()
    queue = MuxDemuxQueue(
        proxy_dict=dict(),
        mux_queue=Queue(),
        demux_queue=demux_queue
    )

    expected_id = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    expected_content = "test"

    demux_queue.put(Item(id=expected_id, content=expected_content, operation='create'))

    result = queue.internal_get_response_from_demux()

    assert demux_queue.empty()
    assert result.id == expected_id
    assert result.content == expected_content


def test_internal_store_response():
    """Check that the `internal_store_response` method works as expected."""
    dict_test = dict()
    queue = MuxDemuxQueue(
        proxy_dict=dict_test,
        mux_queue=Queue(),
        demux_queue=Queue()
    )

    example_uid = "ac5f7bed-363a-4095-bc19-5c1ebffd1be0"
    example_value = "test"
    packet = Packet()
    packet.add_item(Item(id=example_uid, content=example_value, operation='create'))

    queue.internal_store_response(packet)

    assert example_uid in dict_test
    assert dict_test[example_uid] == packet


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
