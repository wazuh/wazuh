from copy import deepcopy
from datetime import datetime
from unittest.mock import patch

import pytest
from freezegun import freeze_time

from api.authentication import INVALID_TOKEN, JWT_ISSUER
from comms_api.authentication.authentication import decode_token, generate_token, JWT_AUDIENCE, JWT_EXPIRATION

payload = {
    'iss': JWT_ISSUER,
    'aud': JWT_AUDIENCE,
    'iat': 0,
    'exp': 0 + JWT_EXPIRATION,
    'uuid': '019113d7-d428-725e-a87a-a7661cf5f641'
}


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1))
@patch('comms_api.authentication.authentication.encode', return_value='test_token')
@patch('comms_api.authentication.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                            '-----BEGIN PUBLIC KEY-----'))
async def test_generate_token(mock_generate_keypair, mock_encode):
    """Verify that the `generate_token()` function works as expected"""
    result = generate_token(uuid=payload['uuid'])
    assert result == 'test_token'

    # Check all functions are called with expected params
    mock_generate_keypair.assert_called_once()
    mock_encode.assert_called_once_with(payload, '-----BEGIN PRIVATE KEY-----', algorithm='ES256')


@freeze_time(datetime(1970, 1, 1))
@patch('comms_api.authentication.authentication.decode')
@patch('comms_api.authentication.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                                                 '-----BEGIN PUBLIC KEY-----'))
def test_decode_token(mock_generate_keypair, mock_decode):
    """Verify that the `decode_token()` function works as expected."""
    mock_decode.return_value = deepcopy(payload)

    decoded_token = decode_token(token='test_token')

    assert decoded_token == decoded_token
    mock_generate_keypair.assert_called_once()


@patch('comms_api.authentication.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                                                 '-----BEGIN PUBLIC KEY-----'))
def test_decode_token_ko(mock_generate_keypair):
    """Assert exceptions are handled as expected inside decode_token()"""
    with pytest.raises(Exception) as exc:
        _ = decode_token(token='test_token')
        assert str(exc) == INVALID_TOKEN

    mock_generate_keypair.assert_called_once()
