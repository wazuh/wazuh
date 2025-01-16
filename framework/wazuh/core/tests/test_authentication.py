from unittest.mock import patch, call, MagicMock

import pytest

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


@patch('os.chmod')
@patch('os.chown')
@patch('builtins.open')
def test_generate_keypair(mock_open, mock_chown, mock_chmod):
    """Verify correct params when calling open method inside generate_keypair."""
    result = authentication.generate_keypair()
    assert isinstance(result[0], str)
    assert isinstance(result[1], str)

    mock_open.assert_has_calls([
        call(authentication._private_key_path, mode='w'),
        call(authentication._public_key_path, mode='w')
    ], any_order=True)
    mock_chown.assert_has_calls([
        call(authentication._private_key_path, authentication.wazuh_uid(), authentication.wazuh_gid()),
        call(authentication._public_key_path, authentication.wazuh_uid(), authentication.wazuh_gid())
    ])
    mock_chmod.assert_has_calls([
        call(authentication._private_key_path, 0o640),
        call(authentication._public_key_path, 0o640)
    ])


@pytest.mark.parametrize("exists", [True, False])
def test_keypair_exists(exists):
    """Verify that `keypair_exists` works as expected."""
    with patch('os.path.exists', return_value=exists):
        assert authentication.keypair_exists() == exists
