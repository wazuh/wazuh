import pytest
from unittest.mock import patch
from pydantic import ValidationError
from pathlib import PosixPath

from wazuh.core.common import ENGINE_SOCKET
from wazuh.core.config.models.engine import EngineClientConfig, EngineConfig

valid_socket_path = '/var/wazuh/queue/example.sock'
valid_retries = 5
valid_timeout = 20.0


@pytest.mark.parametrize('init_values, expected', [
    ({'api_socket_path': valid_socket_path, 'retries': valid_retries, 'timeout': valid_timeout},
     {'api_socket_path': valid_socket_path, 'retries': valid_retries, 'timeout': valid_timeout}),
    ({}, {'api_socket_path': ENGINE_SOCKET, 'retries': 3, 'timeout': 10.0}),
])
@patch('pathlib.Path.is_file', return_value=True)
def test_engine_client_config_default_values(mock_is_file, init_values, expected):
    """Check the correct initialization of the `EngineClientConfig` class."""
    client_config = EngineClientConfig(**init_values)

    assert client_config.api_socket_path == PosixPath(expected['api_socket_path'])
    assert client_config.retries == expected['retries']
    assert client_config.timeout == expected['timeout']


@pytest.mark.parametrize('init_values', [
    {'api_socket_path': 'invalid_path', 'retries': 3, 'timeout': 10.0},
    {'api_socket_path': valid_socket_path, 'retries': -1, 'timeout': 10.0},
    {'api_socket_path': valid_socket_path, 'retries': 3, 'timeout': -5.0},
])
def test_engine_client_config_invalid_values(init_values):
    """Check the correct behavior of the `EngineClientConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = EngineClientConfig(**init_values)


@pytest.mark.parametrize('init_values, expected', [
    ({'tzdv_automatic_update': True, 'client': {'api_socket_path': valid_socket_path, 'retries': valid_retries, 'timeout': valid_timeout}},
     {'tzdv_automatic_update': True, 'client': {'api_socket_path': valid_socket_path, 'retries': valid_retries, 'timeout': valid_timeout}}),
    ({}, {'tzdv_automatic_update': False, 'client': {}}),
])
@patch('pathlib.Path.is_file', return_value=True)
def test_engine_config_default_values(mock_is_file, init_values, expected):
    """Check the correct initialization of the `EngineConfig` class."""
    engine_config = EngineConfig(**init_values)

    assert engine_config.tzdv_automatic_update == expected['tzdv_automatic_update']
    assert engine_config.client == EngineClientConfig(**expected['client'])


@pytest.mark.parametrize('invalid_values', [
    {'client': {'api_socket_path': 'invalid_path'}},
    {'client': {'retries': -1}},
    {'client': {'timeout': -5.0}},
])
def test_engine_config_invalid_values(invalid_values):
    """Check the correct behavior of the `EngineConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = EngineConfig(**invalid_values)
