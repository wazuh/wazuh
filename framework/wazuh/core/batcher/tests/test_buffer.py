import sys
from framework.wazuh.core.batcher.buffer import Buffer
from framework.wazuh.core.batcher.mux_demux import Message


def test_add_message():
    """Check that the `add_message` method works as expected."""
    buffer = Buffer(max_elements=10, max_size=10)
    buffer.add_message(Message("1", {}))

    assert len(buffer._buffer) == 1


def test_add_message_exceeds_count_limit():
    """Check that the `add_message` method count limit works as expected."""
    buffer = Buffer(max_elements=1, max_size=10)
    buffer.add_message(Message("1", {}))
    assert len(buffer._buffer) == 1

    result = buffer.add_message(Message("2", {}))
    assert result is False
    assert len(buffer._buffer) == 1


def test_add_message_exceeds_size_limit():
    """Check that the `add_message` method size limit works as expected."""
    buffer = Buffer(max_elements=10, max_size=5)

    buffer.add_message(Message("1", {'content': 'abcde'}))
    assert len(buffer._buffer) == 1

    result = buffer.add_message(Message("2", {'content': 'abcde'}))
    assert result is False
    assert len(buffer._buffer) == 1


def test_add_message_within_limits():
    """Check that the `add_message` method size and count limit works as expected."""
    buffer = Buffer(max_elements=5, max_size=3000)
    messages = [Message(str(i), {'content': 'msg'}) for i in range(3)]

    for msg in messages:
        assert buffer.add_message(msg) is True

    assert len(buffer._buffer) == 3


def test_get_length():
    """Check that the `get_length` method works as expected."""
    buffer = Buffer(max_elements=10, max_size=10)

    assert buffer.get_length() == 0
    buffer.add_message(Message("1", {}))
    assert buffer.get_length() == 1


def test_check_count_limit_false():
    """Check that the `check_count_limit` method works as expected with an empty buffer."""
    buffer = Buffer(max_elements=2, max_size=10)
    buffer.add_message(Message("1", {}))

    assert not buffer.check_count_limit()


def test_check_count_limit_reached():
    """Check that the `check_count_limit` method works as expected with a full buffer."""
    buffer = Buffer(max_elements=2, max_size=100)
    buffer.add_message(Message("1", {}))

    assert not buffer.check_count_limit()

    buffer.add_message(Message("2", {}))
    assert buffer.check_count_limit()


def test_check_size_limit_false():
    """Check that the `check_size_limit` method works as expected with an empty buffer."""
    msg = Message("1", {"example": "example"})
    size_of_msg = sys.getsizeof(msg.msg)

    buffer = Buffer(max_elements=2, max_size=size_of_msg * 2)
    buffer.add_message(msg)

    assert not buffer.check_size_limit()


def test_check_size_limit_reached():
    """Check that the `check_size_limit` method works as expected with a full buffer."""
    msg = Message("1", {"example": "example"})
    size_of_msg = sys.getsizeof(msg.msg)

    buffer = Buffer(max_elements=2, max_size=size_of_msg * 2)
    buffer.add_message(msg)
    assert not buffer.check_size_limit()

    buffer.add_message(msg)
    assert buffer.check_size_limit()


def test_copy():
    """Check that the `copy` method works as expected."""
    msg = Message("1", {"example": "example"})
    list_of_msg = [msg for _ in range(4)]

    buffer = Buffer(max_elements=4, max_size=1000)
    for n in list_of_msg:
        buffer.add_message(n)
    copy_buffer_content = buffer.copy()

    for i in range(4):
        assert copy_buffer_content[i] == list_of_msg[i]


def test_reset():
    """Check that the `reset` method works as expected."""
    msg = Message("1", {"example": "example"})
    list_of_msg = [msg for _ in range(4)]

    buffer = Buffer(max_elements=4, max_size=100)
    for n in list_of_msg:
        buffer.add_message(n)

    buffer.reset()
    assert buffer.get_length() == 0
    assert not buffer.check_size_limit()
    assert not buffer.check_count_limit()
