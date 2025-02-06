from unittest.mock import MagicMock, call, patch

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import authentication

@patch('wazuh.core.authentication.CentralizedConfig.get_server_config')
@patch('builtins.open')
def test_get_keypair(mock_open, get_server_config_mock):
    """Verify correct params when calling open method inside get_keypair."""
    private_key = 'private_key'
    public_key = 'public_key'
    config_mock = MagicMock(**{"jwt.private_key": private_key, "jwt.public_key": public_key})
    get_server_config_mock.return_value = config_mock
    authentication.get_keypair()
    calls = [call(private_key, mode='r'), call(public_key, mode='r')]
    mock_open.assert_has_calls(calls, any_order=True)
