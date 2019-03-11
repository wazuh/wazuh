# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest
import itertools

from wazuh import exception
from wazuh.wdb import WazuhDBConnection


def test_failed_connection():
    """
    Tests an exception is properly raised when it's not possible to connect to wdb
    """
    # tests the socket path doesn't exists
    with patch('wazuh.common.wdb_socket_path', '/this/path/doesnt/exist'):
        with pytest.raises(exception.WazuhException, match=".* 2005 .*"):
            WazuhDBConnection()
    # tests an exception is properly raised when a connection error is raised
    with patch('socket.socket') as socket_patch:
        with pytest.raises(exception.WazuhException, match=".* 2005 .*"):
            socket_patch.return_value.connect.side_effect = ConnectionError
            WazuhDBConnection()


@patch('socket.socket')
def test_wrong_character_encodings_wdb(socket_mock):
    """
    Tests receiving a text with a bad character encoding from wazuh db
    """
    def recv_mock(size_to_receive):
        bad_string = b' {"bad": "\x96bad"}'
        return bytes(len(bad_string)) if size_to_receive == 4 else bad_string

    socket_mock.return_value.recv.side_effect = recv_mock
    mywdb = WazuhDBConnection()
    received = mywdb._send("test")
    assert received == {"bad": "bad"}


@patch('socket.socket')
def test_receive_long_message(socket_mock):
    """
    Tests receiving a message so big it can't be sliced and, therefore an exception will be raised.
    """
    # return as many wrong JSON items as needed using itertools.cycle
    socket_mock.return_value.recv.side_effect = itertools.chain([b'0001 ', b'ok [{"count(*)":1000}]'],
                                                                itertools.cycle([b'1234', b'ok [{"long": "long"']))
    with pytest.raises(exception.WazuhException, match=".* 2007 .*"):
        mywdb = WazuhDBConnection()
        received = mywdb.execute("agent 000 sql select * from test")

    # 5 calls to setup the socket (create object, connect, make count(*) request...) +
    # 8 failed requests (180, 90, 45, 22, 11, 5, 2 and 1) * 3 necessary calls per request
    # (send, recv size and recv data)
    assert len(socket_mock.mock_calls) == 5 + 3 * 8


@patch('socket.socket')
def test_slice_message(socket_mock):
    """
    Tests receiving a message so big it can't be sliced the first time, but after requesting half of elements
    its correctly returned
    """
    socket_mock.return_value.recv.side_effect = itertools.chain([b'0001 ', b'ok [{"count(*)":1000}]',
                                                                 b'1234', b'ok [{"long": "long"'],
                                                                itertools.cycle([b'1234', b'ok [{"long": "long"}]']))

    mywdb = WazuhDBConnection()
    received = mywdb.execute("agent 000 sql select * from test")
    # 1000 elements / 180 step -> 5.5 -> 6 + 1 element from the double failed request (the one returning the
    # incomplete JSON).
    assert received == [{"long": "long"}]*7

    # 5 calls to setup the socket (create object, connect, make count(*) request...) +
    # 6 requests (1000 elements sliced in 180 items per request) + 1 failed request
    # + 2 extra request consequence of the failed one
    assert len(socket_mock.mock_calls) == 5 + (6 + 2) * 3
