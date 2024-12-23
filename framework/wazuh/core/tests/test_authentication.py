from unittest.mock import call, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import authentication
        from wazuh.core.exception import WazuhInternalError


@patch('builtins.open')
def test_get_keypair(mock_open):
    """Verify correct params when calling open method inside get_keypair."""
    with patch('wazuh.core.authentication.keypair_exists', return_value=True):
        authentication.get_keypair()
        calls = [call(authentication._private_key_path, mode='r'), call(authentication._public_key_path, mode='r')]
        mock_open.assert_has_calls(calls, any_order=True)


def test_get_keypair_ko():
    """Verify an exception is raised when there's no key pair."""
    with patch('wazuh.core.authentication.keypair_exists', return_value=False):
        with pytest.raises(WazuhInternalError, match='.*6003*.'):
            authentication.get_keypair()


@patch('os.chmod')
@patch('os.chown')
@patch('builtins.open')
def test_generate_keypair(mock_open, mock_chown, mock_chmod):
    """Verify correct params when calling open method inside generate_keypair."""
    result = authentication.generate_keypair()
    assert isinstance(result[0], str)
    assert isinstance(result[1], str)

    mock_open.assert_has_calls(
        [call(authentication._private_key_path, mode='w'), call(authentication._public_key_path, mode='w')],
        any_order=True,
    )
    mock_chown.assert_has_calls(
        [
            call(authentication._private_key_path, authentication.wazuh_uid(), authentication.wazuh_gid()),
            call(authentication._public_key_path, authentication.wazuh_uid(), authentication.wazuh_gid()),
        ]
    )
    mock_chmod.assert_has_calls(
        [call(authentication._private_key_path, 0o640), call(authentication._public_key_path, 0o640)]
    )


@pytest.mark.parametrize('exists', [True, False])
def test_keypair_exists(exists):
    """Verify that `keypair_exists` works as expected."""
    with patch('os.path.exists', return_value=exists):
        assert authentication.keypair_exists() == exists
