import sys
from framework.wazuh.core.batcher.buffer import Buffer
from framework.wazuh.core.batcher.mux_demux import Item


def test_add_item():
    """Check that the `add_item` method works as expected."""
    buffer = Buffer(max_elements=10, max_size=10)
    buffer.add_item(Item(id='1', operation='create', content={}))

    assert len(buffer._buffer) == 1


def test_add_item_exceeds_count_limit():
    """Check that the `add_item` method count limit works as expected."""
    buffer = Buffer(max_elements=1, max_size=10)
    buffer.add_item(Item(id='1', operation='create', content={}))
    assert len(buffer._buffer) == 1

    result = buffer.add_item(Item(id='2', operation='create', content={}))
    assert result is False
    assert len(buffer._buffer) == 1


def test_add_item_exceeds_size_limit():
    """Check that the `add_item` method size limit works as expected."""
    buffer = Buffer(max_elements=10, max_size=5)

    buffer.add_item(Item(id='1', operation='create', content={'content': 'abcde'}))
    assert len(buffer._buffer) == 1

    result = buffer.add_item(Item(id='2', operation='create', content={'content': 'abcde'}))
    assert result is False
    assert len(buffer._buffer) == 1


def test_add_item_within_limits():
    """Check that the `add_item` method size and count limit works as expected."""
    buffer = Buffer(max_elements=5, max_size=3000)
    items = [Item(id=str(i), operation='update', content={'content': 'msg'}) for i in range(3)]

    for msg in items:
        assert buffer.add_item(msg) is True

    assert len(buffer._buffer) == 3


def test_get_length():
    """Check that the `get_length` method works as expected."""
    buffer = Buffer(max_elements=10, max_size=10)

    assert buffer.get_length() == 0
    buffer.add_item(Item(id='1', operation='create', content={}))
    assert buffer.get_length() == 1


def test_check_count_limit_false():
    """Check that the `check_count_limit` method works as expected with an empty buffer."""
    buffer = Buffer(max_elements=2, max_size=10)
    buffer.add_item(Item(id='1', operation='create', content={}))

    assert not buffer.check_count_limit()


def test_check_count_limit_reached():
    """Check that the `check_count_limit` method works as expected with a full buffer."""
    buffer = Buffer(max_elements=2, max_size=100)
    buffer.add_item(Item(id='1', operation='create', content={}))

    assert not buffer.check_count_limit()

    buffer.add_item(Item(id='2', operation='create', content={}))
    assert buffer.check_count_limit()


def test_check_size_limit_false():
    """Check that the `check_size_limit` method works as expected with an empty buffer."""
    item = Item(id='1', operation='create', content={"example": "example"})
    size_of_msg = sys.getsizeof(item.content)

    buffer = Buffer(max_elements=2, max_size=size_of_msg * 2)
    buffer.add_item(item)

    assert not buffer.check_size_limit()


def test_check_size_limit_reached():
    """Check that the `check_size_limit` method works as expected with a full buffer."""
    item = Item(id='1', operation='create', content={"example": "example"})
    size_of_msg = sys.getsizeof(item.content)

    buffer = Buffer(max_elements=2, max_size=size_of_msg * 2)
    buffer.add_item(item)
    assert not buffer.check_size_limit()

    buffer.add_item(item)
    assert buffer.check_size_limit()


def test_copy():
    """Check that the `copy` method works as expected."""
    msg = Item(id='1', operation='create', content={"example": "example"})
    list_of_msg = [msg for _ in range(4)]

    buffer = Buffer(max_elements=4, max_size=1000)
    for n in list_of_msg:
        buffer.add_item(n)
    copy_buffer_content = buffer.copy()

    for i in range(4):
        assert copy_buffer_content[i] == list_of_msg[i]


def test_reset():
    """Check that the `reset` method works as expected."""
    msg = Item(id='1', operation='create', content={"example": "example"})
    list_of_msg = [msg for _ in range(4)]

    buffer = Buffer(max_elements=4, max_size=100)
    for n in list_of_msg:
        buffer.add_item(n)

    buffer.reset()
    assert buffer.get_length() == 0
    assert not buffer.check_size_limit()
    assert not buffer.check_count_limit()
