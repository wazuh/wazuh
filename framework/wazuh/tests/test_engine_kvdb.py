import pytest
from unittest.mock import MagicMock, patch

from wazuh import engine_kvdb
from wazuh.core.exception import WazuhNotAcceptable, WazuhResourceNotFound, WazuhInternalError


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ("Database 'aaaagents_host_data' already exists", WazuhNotAcceptable, 9011),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_create_db_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_kvdb.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_kvdb.create_db(name='name', path='path')

            assert e._code == expected_code


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ("Database 'aaaagents_host_data' not found or could not be loaded", WazuhResourceNotFound, 9011),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_delete_db_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_kvdb.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_kvdb.delete_db(name='name')

            assert e._code == expected_code


@pytest.mark.parametrize(
    'name,key,expected_command',
    [
        ('name', None, 'kvdb.manager/dump'),
        ('name', 'key', 'kvdb.db/get')
    ]
)
def test_get_entries_use_correct_command(name, key, expected_command):
    mock_socket = MagicMock()
    mock_socket.send = MagicMock()
    mock_socket.receive.return_value = {'status': 'OK', 'value': {}, 'entries': []}

    with patch('wazuh.engine_kvdb.WazuhSocketJSON', return_value=mock_socket):
        engine_kvdb.get_db_entries(name=name, key=key)
        assert mock_socket.send.call_args[0][0]['command'] == expected_command


@pytest.mark.parametrize(
    'name,key',
    [
        ('name', None),
        ('name', 'key')
    ]
)
def test_get_entries_allways_returns_a_list(name, key):
    mock_socket = MagicMock()
    mock_socket.send = MagicMock()
    mock_socket.receive.return_value = {'status': 'OK', 'value': {}, 'entries': []}

    with patch('wazuh.engine_kvdb.WazuhSocketJSON', return_value=mock_socket):
        result = engine_kvdb.get_db_entries(name=name, key=key)
        assert isinstance(result['data'], list)


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ("Database 'in_security_categories' not found or could not be loaded", WazuhResourceNotFound, 9009),
        ("Cannot read value: 'NotFound: '", WazuhResourceNotFound, 9010),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_get_entries_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_kvdb.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_kvdb.get_db_entries(name='name')

            assert e._code == expected_code


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ("Database 'aaaagents_host_data' not found or could not be loaded", WazuhResourceNotFound, 9011),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_delete_db_entry_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_kvdb.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_kvdb.delete_db_entry(name='name', key="key")

            assert e._code == expected_code