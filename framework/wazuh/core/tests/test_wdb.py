# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from struct import pack
from unittest.mock import patch

import pytest

from wazuh.core import exception
from wazuh.core.wdb import WazuhDBConnection
from wazuh.core.common import MAX_SOCKET_BUFFER_SIZE


def format_msg(msg):
    return pack('<I', len(bytes(msg)))


def test_failed_connection():
    """
    Tests an exception is properly raised when it's not possible to connect to wdb
    """
    # wazuh-db daemon is not running
    with pytest.raises(exception.WazuhError, match=".* 1017 .*"):
        WazuhDBConnection()
    with patch('wazuh.core.manager.check_wazuh_status'):
        # Tests the socket path doesn't exists
        with patch('wazuh.core.common.WDB_SOCKET', '/this/path/doesnt/exist'):
            with pytest.raises(exception.WazuhException, match=".* 2005 .*"):
                WazuhDBConnection()
        # Tests an exception is properly raised when a connection error is raised
        with patch('socket.socket') as socket_patch:
            with pytest.raises(exception.WazuhException, match=".* 2005 .*"):
                socket_patch.return_value.connect.side_effect = ConnectionError
                WazuhDBConnection()


@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_wrong_character_encodings_wdb(send_mock, wazuh_status_mock, connect_mock):
    """
    Tests receiving a text with a bad character encoding from wazuh db
    """
    def recv_mock(size_to_receive):
        bad_string = b' {"bad": "\x96bad"}'
        return format_msg(bad_string) if size_to_receive == 4 else bad_string

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        received = mywdb._send("test")
        assert received == {"bad": "bad"}


@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_null_values_are_removed(send_mock, wazuh_status_mock, connect_mock):
    """
    Tests '(null)' values are removed from the resulting dictionary
    """
    def recv_mock(size_to_receive):
        nulls_string = b' [{"a": "a", "b": "(null)", "c": [1, 2, 3], "d": {"e": "(null)"}}]'
        return format_msg(nulls_string) if size_to_receive == 4 else nulls_string

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        received = mywdb._send("test")
        assert received == [{"a": "a", "c": [1, 2, 3], "d": {}}]


@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_failed_send_private(send_mock, wazuh_status_mock, connect_mock):
    """
        Tests an exception is properly raised when it's not possible to send a msg to the wdb socket
    """
    def recv_mock(size_to_receive):
        error_string = b'err {"agents": {"001": "Error"}}'
        return format_msg(error_string) if size_to_receive == 4 else error_string

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        with pytest.raises(exception.WazuhException, match=".* 2003 .*"):
            mywdb._send('test_msg')

    with patch('socket.socket.recv', return_value=b'a' * (MAX_SOCKET_BUFFER_SIZE + 1)):
        mywdb = WazuhDBConnection()
        with pytest.raises(exception.WazuhException, match=".* 2009 .*"):
            mywdb._send('test_msg')


@pytest.mark.parametrize('content', [
    b'ok {"agents": {"001": "Ok"}}',
    b'ok {"agents": {"0ad": "Invalid agent ID"}}',
    b'ok {"agents": {"001": "DB waiting for deletion"}}',
    b'ok {"agents": {"001": "DB not found"}}'
])
@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_remove_agents_database(send_mock, wazuh_status_mock, connect_mock, content):
    """
    Tests delete_agents_db method handle exceptions properly
    """
    def recv_mock(size_to_receive):
        return format_msg(content) if size_to_receive == 4 else content

    with patch('socket.socket.recv', side_effect=recv_mock):
        mywdb = WazuhDBConnection()
        received = mywdb.delete_agents_db(['001', '002'])
        assert(isinstance(received, dict))
        assert("agents" in received)


@pytest.mark.parametrize('error_query', [
    'Agent sql select test',
    'error sql select test',
    'agent bad_digit sql select test',
    'agent 000 sql sql_sentence',
    'global sql delete test ;'
])
@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_query_input_validation_private(send_mock, wazuh_status_mock, connect_mock, error_query):
    mywdb = WazuhDBConnection()
    with pytest.raises(exception.WazuhException, match=".* 2004 .*"):
        mywdb.execute(error_query)


@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_query_lower_private(send_mock, wazuh_status_mock, connect_mock):
    mywdb = WazuhDBConnection()
    with pytest.raises(exception.WazuhException, match=".* 2004 .*"):
        mywdb.execute("Agent sql select 'test'")


@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.connect")
def test_run_wdb_command(connect_mock, wazuh_status_mock):
    """Test `WazuhDBConnection.run_wdb_command` method."""
    send_result = ('status', '["data"]')
    command = "any wdb command"

    wdb_con = WazuhDBConnection()
    with patch('wazuh.core.wdb.WazuhDBConnection._send', return_value=send_result) as wdb_send_mock:
        result = wdb_con.run_wdb_command(command)
        wdb_send_mock.assert_called_once_with(command, raw=True)

    assert result == send_result, 'Expected command response does not match'


@pytest.mark.parametrize('wdb_response', [
    ('err', 'Extra custom test message'),
    ('err', )
])
@patch("socket.socket.connect")
def test_run_wdb_command_ko(connect_mock, wdb_response):
    """Test `WazuhDBConnection.run_wdb_command` method expected exceptions."""
    with patch('wazuh.core.wdb.WazuhDBConnection._send', return_value=wdb_response):
        wdb_con = WazuhDBConnection(check_daemon=False)
        with pytest.raises(exception.WazuhInternalError, match=".* 2007 .*") as expected_exc:
            wdb_con.run_wdb_command("global sync-agent-info-get ")

        if len(wdb_response) > 1:
            assert wdb_response[1] in expected_exc.value.message, 'Extra message was not added to exception'


@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
@patch("wazuh.core.wdb.WazuhDBConnection._send")
def test_execute(send_mock, socket_send_mock, wazuh_status_mock, connect_mock):
    def send_mock(obj, msg, raw=False):
        return ['ok', '{"total": 5}'] if raw else [{"total": 5}]

    mywdb = WazuhDBConnection()
    mywdb.execute('agent 000 sql delete from test', delete=True)
    mywdb.execute("agent 000 sql update test set value = 'test' where key = 'test'", update=True)
    with patch("wazuh.core.wdb.WazuhDBConnection._send", new=send_mock):
        mywdb.execute("agent 000 sql select test from test offset 1 limit 1")
        mywdb.execute("agent 000 sql select test from test offset 1 limit 1", count=True)
        mywdb.execute("agent 000 sql select test from test offset 1 count")


@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_execute_pagination(socket_send_mock, wazuh_status_mock, connect_mock):
    mywdb = WazuhDBConnection()

    # Test pagination
    with patch("wazuh.core.wdb.WazuhDBConnection._send",
               side_effect=[[{'total': 5}], exception.WazuhInternalError(2009), ['ok', '{"total": 5}'],
                            ['ok', '{"total": 5}']]):
        mywdb.execute("agent 000 sql select test from test offset 1 limit 500")

    # Test pagination error
    with patch("wazuh.core.wdb.WazuhDBConnection._send",
               side_effect=[[{'total': 5}], exception.WazuhInternalError(2009)]):
        with pytest.raises(exception.WazuhInternalError, match=".* 2009 .*"):
            mywdb.execute("agent 000 sql select test from test offset 1 limit 1")


@pytest.mark.parametrize('error_query, error_type, expected_exception, delete, update', [
    ('agent 000 sql delete test', None, 2004, True, False),
    ('agent 000 sql update test', None, 2004, False, True),
    ('agent 000 sql select test from test offset 1 limit 1', ValueError, 2006, False, False),
    ('agent 000 sql select test from test offset 1 limit 1', Exception, 2007, False, False)
])
@patch("socket.socket.connect")
@patch('wazuh.core.manager.check_wazuh_status')
@patch("socket.socket.send")
def test_failed_execute(send_mock, wazuh_status_mock, connect_mock, error_query, error_type, expected_exception, delete,
                        update):
    mywdb = WazuhDBConnection()
    if not error_type:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            mywdb.execute(error_query, delete=delete, update=update)
    else:
        with patch("wazuh.core.wdb.WazuhDBConnection._send", return_value=[{'total': 5}]):
            with patch("wazuh.core.wdb.min", side_effect=error_type):
                with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
                    mywdb.execute(error_query, delete=delete, update=update)


@pytest.mark.parametrize('string', [
    '[{"key1": "value1"}]',
    '[{"key1": "value1"}, {"invalid": "(null)"}]',
])
def test_WazuhDBConnection_loads(string):
    """Test that the `loads` method from the class `WazuhDBConnection` cleans empty objects from the result."""
    result = WazuhDBConnection.loads(string)
    assert len(result) == 1
    assert result[0] == {"key1": "value1"}
