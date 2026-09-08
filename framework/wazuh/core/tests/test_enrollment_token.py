# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import enrollment_token
        from wazuh.core.exception import WazuhError, WazuhException, WazuhResourceNotFound

TOKEN_ID = 'AAECAwQFBgcICQoLDA0ODw'
# What authd's `token_create` answers (os_auth/src/enrollment_token_store.c, etoken_store_create()).
CREATED = {'token': 'eyJ2ZXIiOjF9', 'id': TOKEN_ID, 'adr': 'wazuh-master', 'expires': 1700003600, 'pin_hex': 'ab' * 32}
# One `token_list` record (etoken_store_list()): never the token text, never the secret.
LISTED = {'id': TOKEN_ID, 'adr': 'wazuh-master', 'created': 1700000000, 'expires': 1700003600, 'max_uses': 0,
          'uses': 2, 'revoked': 0, 'credential': 1, 'description': None}


@pytest.mark.parametrize('kwargs, expected_arguments', [
    # Only the address: authd applies its own defaults (30 days, unlimited uses, credential, pin).
    ({'address': 'wazuh-master'}, {'address': 'wazuh-master'}),
    # Every option: the ttl travels in seconds, the flags only when set.
    ({'address': 'wazuh-master', 'port': 1517, 'prefix': '/wazuh-manager/', 'ttl': '2h', 'max_uses': 3,
      'description': 'web tier', 'embed_ca': True, 'no_credential': True},
     {'address': 'wazuh-master', 'port': 1517, 'prefix': '/wazuh-manager/', 'ttl': 7200, 'max_uses': 3,
      'description': 'web tier', 'embed_ca': True, 'no_credential': True}),
    # Plain seconds are a timeframe too; false flags are not sent.
    ({'address': '10.0.0.5', 'ttl': '90', 'embed_ca': False, 'no_credential': False},
     {'address': '10.0.0.5', 'ttl': 90}),
])
@patch('wazuh.core.enrollment_token.WazuhSocketJSON')
def test_create_token(mock_socket, kwargs, expected_arguments):
    """create_token() sends authd exactly the `token_create` the CLI would, and normalizes the answer."""
    mock_socket.return_value.receive.return_value = dict(CREATED)

    result = enrollment_token.create_token(**kwargs)

    mock_socket.return_value.send.assert_called_once_with({'function': 'token_create', 'arguments': expected_arguments})
    mock_socket.return_value.close.assert_called_once()
    assert result == {'token': CREATED['token'], 'id': TOKEN_ID, 'address': 'wazuh-master',
                      'expires': datetime(2023, 11, 14, 23, 13, 20, tzinfo=timezone.utc), 'pin_hex': CREATED['pin_hex']}


@patch('wazuh.core.enrollment_token.WazuhSocketJSON')
def test_create_token_invalid_ttl(mock_socket):
    """A ttl that is not a timeframe is refused before authd is asked."""
    with pytest.raises(WazuhError, match='.* 1411 .*'):
        enrollment_token.create_token('wazuh-master', ttl='soon')

    mock_socket.return_value.send.assert_not_called()


@patch('wazuh.core.enrollment_token.WazuhSocketJSON')
def test_list_tokens(mock_socket):
    """list_tokens() renames `adr`, turns epochs into UTC datetimes and booleans into booleans."""
    mock_socket.return_value.receive.return_value = [dict(LISTED)]

    tokens = enrollment_token.list_tokens()

    mock_socket.return_value.send.assert_called_once_with({'function': 'token_list'})
    assert tokens == [{'id': TOKEN_ID, 'address': 'wazuh-master',
                       'created': datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc),
                       'expires': datetime(2023, 11, 14, 23, 13, 20, tzinfo=timezone.utc),
                       'max_uses': 0, 'uses': 2, 'revoked': False, 'credential': True, 'description': None}]
    assert 'token' not in tokens[0] and 'secret' not in tokens[0]


@patch('wazuh.core.enrollment_token.WazuhSocketJSON')
def test_revoke_token(mock_socket):
    """revoke_token() sends `token_revoke` with the id and returns nothing."""
    mock_socket.return_value.receive.return_value = {}

    assert enrollment_token.revoke_token(TOKEN_ID) is None

    mock_socket.return_value.send.assert_called_once_with({'function': 'token_revoke', 'arguments': {'id': TOKEN_ID}})


@pytest.mark.parametrize('authd_code, authd_message, expected_class, expected_code, expected_detail', [
    (9022, 'Enrollment token not found or revoked', WazuhResourceNotFound, 1767, None),
    (9025, "Enrollment token refused: address 'evil' is not in the listener certificate", WazuhError, 1768,
     "address 'evil' is not in the listener certificate"),
    (9004, 'No such argument', WazuhError, 1768, 'the address is required'),
    (9015, 'Cannot execute this request on a worker node', WazuhError, 1769, None),
    # Anything else is authd's own error, untouched.
    (9001, 'Internal error', WazuhException, 9001, None),
])
@patch('wazuh.core.enrollment_token.WazuhSocketJSON')
def test_authd_errors(mock_socket, authd_code, authd_message, expected_class, expected_code, expected_detail):
    """authd's codes become the API's: 9022 -> 1767, 9025 -> 1768 (with authd's detail), 9015 -> 1769."""
    mock_socket.return_value.receive.side_effect = WazuhException(authd_code, authd_message, cmd_error=True)

    with pytest.raises(expected_class) as exc:
        enrollment_token.create_token('evil')

    assert exc.value.code == expected_code
    if expected_detail:
        assert expected_detail in exc.value.message
        assert 'Enrollment token refused: address' not in exc.value.message.replace(
            'Enrollment token refused: ', '', 1) or expected_code != 1768


@patch('wazuh.core.enrollment_token.WazuhSocketJSON')
def test_revoke_unknown_token_names_the_id(mock_socket):
    """A DELETE of an unknown id is a 1767 that names the id."""
    mock_socket.return_value.receive.side_effect = WazuhException(9022, 'Enrollment token not found or revoked',
                                                                  cmd_error=True)

    with pytest.raises(WazuhResourceNotFound, match='.* 1767 .*') as exc:
        enrollment_token.revoke_token('AAAAAAAAAAAAAAAAAAAAAA')

    assert 'AAAAAAAAAAAAAAAAAAAAAA' in exc.value.message
