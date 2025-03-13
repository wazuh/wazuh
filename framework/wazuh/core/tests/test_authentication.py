from unittest.mock import MagicMock, mock_open, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from framework.wazuh.core.authentication import (
    derive_public_key,
    get_keypair,
    load_jwt_keys,
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


@patch('wazuh.core.authentication.CentralizedConfig.get_server_config')
@patch('builtins.open', new_callable=mock_open, read_data='dummy_private_key_content')
def test_get_keypair(mock_open_obj, get_server_config_mock):
    """Verify that get_keypair correctly reads the private key file and retrieves the public key."""
    # Setup a fake configuration
    config_mock = MagicMock()
    config_mock.jwt.private_key = 'dummy_private_key_path'
    config_mock.jwt.get_public_key.return_value = 'dummy_public_key'
    get_server_config_mock.return_value = config_mock

    private_key, public_key = get_keypair()

    # Check that open was called with the private key path
    mock_open_obj.assert_called_once_with('dummy_private_key_path', mode='r')
    # Verify that the returned values match the expected ones
    assert private_key == 'dummy_private_key_content'
    assert public_key == 'dummy_public_key'


def test_load_jwt_keys_already_configured():
    """Verify no key generation occurs if JWT keys are already configured."""
    mock_api_config = MagicMock()
    mock_config = MagicMock()
    mock_config.jwt.private_key = 'some_private_key'
    mock_config.jwt.public_key = 'some_public_key'

    with (
        patch(
            'wazuh.core.config.client.CentralizedConfig.get_server_config',
            return_value=mock_config,
        ) as mock_get_config,
        patch('framework.wazuh.core.authentication.derive_public_key') as mock_generate,
    ):
        load_jwt_keys(mock_api_config)

        mock_get_config.assert_called_once()
        mock_generate.assert_not_called()


def test_load_jwt_keys_generate_when_missing():
    """Verify key generation occurs if JWT keys are missing."""
    mock_api_config = MagicMock()
    mock_api_config.ssl.key = 'ssl_private_key_path'
    mock_config = MagicMock()
    # Initially, keys are missing.
    mock_config.jwt.private_key = None
    mock_config.jwt.public_key = None

    # Patch derive_public_key to return a dummy public key.
    with (
        patch(
            'wazuh.core.config.client.CentralizedConfig.get_server_config',
            return_value=mock_config,
        ) as mock_get_config,
        patch(
            'framework.wazuh.core.authentication.derive_public_key',
            return_value='generated_public_key',
        ) as mock_generate,
    ):
        load_jwt_keys(mock_api_config)

        assert mock_config.jwt.private_key == 'ssl_private_key_path'
        # Verify that set_public_key was called with the generated public key.
        mock_config.jwt.set_public_key.assert_called_once_with('generated_public_key')
        mock_generate.assert_called_once_with('ssl_private_key_path')


def test_derive_public_key(mock_private_key_pem):
    """Verify that derive_public_key opens the file correctly and returns a valid public key."""
    m_open = mock_open(read_data=mock_private_key_pem)
    with patch('builtins.open', m_open):
        public_key = derive_public_key('dummy_private_key_path')
        m_open.assert_called_once_with('dummy_private_key_path', mode='r')
        # Verify that the returned public key contains the PEM header.
        assert 'BEGIN PUBLIC KEY' in public_key


def test_derive_public_key_read_error():
    """Verify function raises FileNotFoundError when private key file is missing."""
    m_open = mock_open()
    m_open.side_effect = FileNotFoundError

    with patch('builtins.open', m_open):
        with pytest.raises(FileNotFoundError):
            derive_public_key('non_existent_path')
