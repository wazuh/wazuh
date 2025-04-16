from unittest.mock import MagicMock, mock_open, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from framework.wazuh.core.authentication import (
    get_keypair,
)


@pytest.fixture
def mock_private_key_pem():
    """Return a PEM-encoded mock private key.

    Returns
    -------
    str
        PEM-encoded private key.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')


def setup_function():
    """Avoid the `lru_cache` decorator to cause tests that interfere with one another."""
    get_keypair.cache_clear()


@patch('wazuh.core.authentication.CentralizedConfig.get_management_api_config')
def test_get_keypair(get_management_api_config_mock, mock_private_key_pem):
    """Verify that get_keypair correctly reads the private key file and retrieves the public key."""
    # Setup a fake configuration
    open_mock = mock_open(read_data=mock_private_key_pem)
    config_mock = MagicMock()
    get_management_api_config_mock.return_value = config_mock

    with patch('builtins.open', open_mock):
        private_key, public_key = get_keypair()

    # Check that open was called with the private key path
    open_mock.assert_called_once_with(config_mock.ssl.key, mode='r')
    # Verify that the returned values match the expected ones
    assert 'BEGIN PRIVATE KEY' in private_key
    assert 'BEGIN PUBLIC KEY' in public_key


@patch('wazuh.core.authentication.CentralizedConfig.get_management_api_config')
def test_get_keypair_ko(get_management_api_config_mock):
    """Verify function `get_keypair` raises FileNotFoundError when private key file is missing."""
    open_mock = mock_open()
    open_mock.side_effect = FileNotFoundError

    get_management_api_config_mock.ssl.key = 'non_existent_path'

    with patch('builtins.open', open_mock):
        with pytest.raises(FileNotFoundError):
            get_keypair()
