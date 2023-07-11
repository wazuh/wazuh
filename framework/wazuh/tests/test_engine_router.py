import pytest
from unittest.mock import MagicMock, patch

from wazuh import engine_router
from wazuh.core.exception import WazuhNotAcceptable, WazuhResourceNotFound, WazuhInternalError


@pytest.mark.parametrize(
    'name,expected_command',
    [
        (None, 'router.table/get'),
        ('name', 'router.route/get')
    ]
)
def test_get_route_uses_correct_command(name, expected_command):
    mock_socket = MagicMock()
    mock_socket.send = MagicMock()
    mock_socket.receive.return_value = {'status': 'OK', 'rute': {}, 'table': {}}

    with patch('wazuh.engine_router.WazuhSocketJSON', return_value=mock_socket):
        engine_router.get_routes(limit=10, name=name)
        assert mock_socket.send.call_args[0][0]['command'] == expected_command


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ('Route not found', WazuhResourceNotFound, 9004),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_get_routes_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_router.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_router.get_routes(limit=10, name='name')

            assert e._code == expected_code


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ("Route 'name' already exists", WazuhNotAcceptable, 9006),
        ("Priority '255' already taken", WazuhNotAcceptable, 9005),
        ("Policy 'policy/wazuh/0' already exists", WazuhNotAcceptable, 9007),
        ("Invalid policy name: 'policy/wazuh/0'", WazuhNotAcceptable, 9008),
        ("Invalid policy name: '{}', the expected format is: \"policy/<policy-name>/<version>\"", WazuhNotAcceptable, 9008),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_create_route_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_router.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_router.create_route('name', 'filter/allow-all/0', 'policy/wazuh/0', 255)

            assert e._code == expected_code


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ('Route not found', WazuhResourceNotFound, 9004),
        ("Priority '100' already taken", WazuhNotAcceptable, 9005),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_update_route_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_router.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_router.update_route('name', 100)

            assert e._code == expected_code


@pytest.mark.parametrize(
    'error_msg, expected_error, expected_code',
    [
        ('Route not found', WazuhResourceNotFound, 9004),
        ('Internal error', WazuhInternalError, 9002)
    ]
)
def test_delete_route_raises_error(error_msg, expected_error, expected_code):
    mock_socket = MagicMock()
    mock_socket.send.return_value = None  # Set the return value of send() method
    mock_socket.receive.return_value = {'status': 'ERROR', 'error': error_msg}

    with patch('wazuh.engine_router.WazuhSocketJSON', return_value=mock_socket):
        with pytest.raises(expected_error) as e:
            engine_router.delete_route('name')

            assert e._code == expected_code
