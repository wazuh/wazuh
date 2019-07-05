# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

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


@patch("socket.socket.connect")
@patch("socket.socket.send")
def test_wrong_character_encodings_wdb(send_mock, connect_mock):
    """
    Tests receiving a text with a bad character encoding from wazuh db
    """
    def recv_mock(size_to_receive):
        bad_string = b' {"bad": "\x96bad"}'
        return bytes(len(bad_string)) if size_to_receive == 4 else bad_string

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        received = mywdb._send("test")
        assert received == {"bad": "bad"}


@patch("socket.socket.connect")
@patch("socket.socket.send")
def test_null_values_are_removed(send_mock, connect_mock):
    """
    Tests '(null)' values are removed from the resulting dictionary
    """
    def recv_mock(size_to_receive):
        nulls_string = b' {"a": "a", "b": "(null)", "c": [1, 2, 3], "d": {"e": "(null)"}}'
        return bytes(len(nulls_string)) if size_to_receive == 4 else nulls_string

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        received = mywdb._send("test")
        assert received == {"a": "a", "c": [1, 2, 3], "d": {}}


@patch("socket.socket.connect")
@patch("socket.socket.send")
def test_failed_send_private(send_mock, connect_mock):
    """
        Tests an exception is properly raised when it's not possible to send a msg to the wdb socket
    """
    def recv_mock(size_to_receive):
        error_string = b'err {"agents": {"001": "Error"}}'
        return bytes(len(error_string)) if size_to_receive == 4 else error_string

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        with pytest.raises(exception.WazuhException, match=".* 2003 .*"):
            mywdb._send('test_msg')


@pytest.mark.parametrize('content', [
    b'ok {"agents": {"001": "Ok"}}',
    b'ok {"agents": {"0ad": "Invalid agent ID"}}',
    b'ok {"agents": {"001": "DB waiting for deletion"}}',
    b'ok {"agents": {"001": "DB not found"}}'
])
@patch("socket.socket.connect")
@patch("socket.socket.send")
def test_remove_agents_database(send_mock, connect_mock, content):
    """
    Tests delete_agents_db method handle exceptions properly
    """
    def recv_mock(size_to_receive):
        return bytes(len(content)) if size_to_receive == 4 else content

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        received = mywdb.delete_agents_db(['001', '002'])
        assert(isinstance(received, dict))
        assert("agents" in received)

@pytest.mark.parametrize('error_query', [
    'agent sql select test',
    'error sql select test',
    'agent bad_digit sql select test',
    'agent 000 sql sql_sentence',
    'global sql delete test ;'
])
@patch("socket.socket.connect")
@patch("socket.socket.send")
def test_query_input_validation_private(send_mock, connect_mock, error_query):
    mywdb = WazuhDBConnection()
    with pytest.raises(exception.WazuhException, match=".* 2004 .*"):
        mywdb.execute(error_query)



@pytest.mark.parametrize('error_query', [
    'agent sql select test',
    'error sql select test',
    'agent bad_digit sql select test',
    'agent 000 sql sql_sentence',
    'global sql delete test ;'
])
@patch("socket.socket.connect")
@patch("socket.socket.send")
def test_query_lower_private(send_mock, connect_mock, error_query):
    mywdb = WazuhDBConnection()
    with pytest.raises(exception.WazuhException, match=".* 2004 .*"):
        mywdb.__