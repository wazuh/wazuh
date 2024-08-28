import sys
from framework.wazuh.core.batcher.buffer import Buffer
from framework.wazuh.core.batcher.mux_demux import Message


def test_add_message():
    """Tests that a message is correctly added to the buffer."""
    buffer = Buffer(max_elements=10, max_size=10)
    buffer.add_message(Message("1", {}))

    assert len(buffer._buffer) == 1


def test_get_length():
    """Tests the get_length method to ensure it returns the correct buffer size."""
    buffer = Buffer(max_elements=10, max_size=10)

    assert buffer.get_length() == 0
    buffer.add_message(Message("1", {}))
    assert buffer.get_length() == 1


def test_check_count_limit_false():
    """Tests that check_count_limit returns False when the buffer has not reached its maximum number of elements."""
    buffer = Buffer(max_elements=2, max_size=10)
    buffer.add_message(Message("1", {}))

    assert not buffer.check_count_limit()


def test_check_count_limit_reached():
    """Tests that check_count_limit returns True when the buffer reaches its maximum number of elements."""
    buffer = Buffer(max_elements=2, max_size=10)
    buffer.add_message(Message("1", {}))

    assert not buffer.check_count_limit()

    buffer.add_message(Message("2", {}))
    assert buffer.check_count_limit()


def test_check_size_limit_false():
    """Tests that check_size_limit returns False when the buffer size is below the maximum limit."""
    msg = Message("1", {"example": "example"})
    size_of_msg = sys.getsizeof(msg.msg)

    buffer = Buffer(max_elements=2, max_size=size_of_msg * 2)
    buffer.add_message(msg)

    assert not buffer.check_size_limit()


def test_check_size_limit_reached():
    """Tests that check_size_limit returns True when the buffer size reaches the maximum limit."""
    msg = Message("1", {"example": "example"})
    size_of_msg = sys.getsizeof(msg.msg)

    buffer = Buffer(max_elements=2, max_size=size_of_msg * 2)
    buffer.add_message(msg)
    assert not buffer.check_size_limit()

    buffer.add_message(msg)
    assert buffer.check_size_limit()


def test_copy():
    """Tests that the copy method returns an accurate copy of the buffer's content."""
    msg = Message("1", {"example": "example"})
    list_of_msg = [msg for _ in range(4)]

    buffer = Buffer(max_elements=4, max_size=100)
    for n in list_of_msg:
        buffer.add_message(n)
    copy_buffer_content = buffer.copy()

    for i in range(4):
        assert copy_buffer_content[i] == list_of_msg[i]


def test_reset():
    """Tests that the reset method correctly clears the buffer and resets all limits."""
    msg = Message("1", {"example": "example"})
    list_of_msg = [msg for _ in range(4)]

    buffer = Buffer(max_elements=4, max_size=100)
    for n in list_of_msg:
        buffer.add_message(n)

    buffer.reset()
    assert buffer.get_length() == 0
    assert not buffer.check_size_limit()
    assert not buffer.check_count_limit()
