import pytest
from unittest.mock import MagicMock, call, patch, mock_open
from framework.wazuh.core.authentication import check_jwt_keys, generate_jwt_public_key, JWT_PUBLIC_KEY_PATH
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import authentication


@pytest.fixture
def mock_private_key_pem():
    """Return a PEM-encoded mock private key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")



@patch('wazuh.core.authentication.CentralizedConfig.get_server_config')
@patch('builtins.open')
def test_get_keypair(mock_open, get_server_config_mock):
    """Verify correct params when calling open method inside get_keypair."""
    private_key = 'private_key'
    public_key = 'public_key'
    config_mock = MagicMock(**{'jwt.private_key': private_key, 'jwt.public_key': public_key})
    get_server_config_mock.return_value = config_mock
    authentication.get_keypair()
    calls = [call(private_key, mode='r'), call(public_key, mode='r')]
    mock_open.assert_has_calls(calls, any_order=True)


def test_check_jwt_keys_already_configured():
    """Verify no key generation occurs if JWT keys are already configured."""
    mock_api_config = MagicMock()
    mock_config = MagicMock()
    mock_config.jwt.private_key = "some_private_key"
    mock_config.jwt.public_key = "some_public_key"

    with patch("wazuh.core.config.client.CentralizedConfig.get_server_config", return_value=mock_config) as mock_get_config, \
         patch("framework.wazuh.core.authentication.generate_jwt_public_key") as mock_generate:

        check_jwt_keys(mock_api_config)

        mock_get_config.assert_called_once()
        mock_generate.assert_not_called()


def test_check_jwt_keys_generate_when_missing():
    """Verify key generation occurs if JWT keys are missing."""
    mock_api_config = MagicMock()
    mock_api_config.ssl.key = "ssl_private_key_path"
    mock_config = MagicMock()
    mock_config.jwt.private_key = None
    mock_config.jwt.public_key = None

    with patch("wazuh.core.config.client.CentralizedConfig.get_server_config", return_value=mock_config) as mock_get_config, \
         patch("framework.wazuh.core.authentication.generate_jwt_public_key") as mock_generate:

        check_jwt_keys(mock_api_config)

        assert mock_config.jwt.private_key == "ssl_private_key_path"
        assert mock_config.jwt.public_key == JWT_PUBLIC_KEY_PATH
        mock_generate.assert_called_once_with(JWT_PUBLIC_KEY_PATH, "ssl_private_key_path")


def test_generate_jwt_public_key(mock_private_key_pem):
    """Verify correct params when calling open method inside generate_jwt_public_key."""
    m_open = mock_open(read_data=mock_private_key_pem)
    with patch("builtins.open", m_open), \
         patch("wazuh.core.common.wazuh_uid", return_value=1000), \
         patch("wazuh.core.common.wazuh_gid", return_value=1000), \
         patch("os.chown") as mock_chown, \
         patch("os.chmod") as mock_chmod:

        generate_jwt_public_key("path/to/public.pem", "path/to/private.pem")

        m_open.assert_any_call("path/to/private.pem", mode="r")
        m_open.assert_any_call("path/to/public.pem", mode="w")
        assert mock_chown.call_count == 2
        assert mock_chmod.call_count == 2


def test_generate_jwt_public_key_read_error():
    """Verify function raises FileNotFoundError when private key is missing."""
    m_open = mock_open()
    m_open.side_effect = FileNotFoundError

    with patch("builtins.open", m_open):
        with pytest.raises(FileNotFoundError):
            generate_jwt_public_key("public.pem", "private.pem")
