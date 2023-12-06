# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import hashlib
import json
import os
import sys
from copy import deepcopy
from unittest.mock import patch, MagicMock, ANY, call

from connexion.exceptions import Unauthorized

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.results import WazuhResult

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        from api import authentication

        del sys.modules['wazuh.rbac.orm']

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')

security_conf = WazuhResult({
    'auth_token_exp_timeout': 900,
    'rbac_mode': 'black'
})
decoded_payload = {
    "iss": 'wazuh',
    "aud": 'Wazuh API REST',
    "nbf": 0,
    "exp": security_conf['auth_token_exp_timeout'],
    "sub": '001',
    "rbac_policies": {'value': 'test', 'rbac_mode': security_conf['rbac_mode']},
    "rbac_roles": [1],
    'run_as': False
}

original_payload = {
    "iss": "wazuh",
    "aud": "Wazuh API REST",
    "nbf": 0,
    "exp": security_conf['auth_token_exp_timeout'],
    "sub": "001",
    "run_as": False,
    "rbac_roles": [1],
    "rbac_mode": security_conf['rbac_mode']
}


def test_check_user_master():
    result = authentication.check_user_master('test_user', 'test_pass')
    assert result == {'result': True}


@pytest.mark.asyncio
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
async def test_check_user(mock_raise_if_exc, mock_distribute_function, mock_dapi):
    """Verify if result is as expected"""
    result = authentication.check_user('test_user', 'test_pass')

    assert result == {'sub': 'test_user', 'active': True}, 'Result is not as expected'
    mock_dapi.assert_called_once_with(f=ANY, f_kwargs={'user': 'test_user', 'password': 'test_pass'},
                                      request_type='local_master', is_async=False, wait_for_complete=False, logger=ANY)
    mock_distribute_function.assert_called_once_with()
    mock_raise_if_exc.assert_called_once()


@patch('api.authentication.change_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                          '-----BEGIN PUBLIC KEY-----'))
@patch('os.chmod')
@patch('os.chown')
@patch('builtins.open')
def test_generate_keypair(mock_open, mock_chown, mock_chmod, mock_change_keypair):
    """Verify correct params when calling open method inside generate_keypair"""
    result = authentication.generate_keypair()
    assert result == ('-----BEGIN PRIVATE KEY-----',
                      '-----BEGIN PUBLIC KEY-----')

    calls = [call(authentication._private_key_path, authentication.wazuh_uid(), authentication.wazuh_gid()),
             call(authentication._public_key_path, authentication.wazuh_uid(), authentication.wazuh_gid())]
    mock_chown.assert_has_calls(calls)
    calls = [call(authentication._private_key_path, 0o640),
             call(authentication._public_key_path, 0o640)]
    mock_chmod.assert_has_calls(calls)

    with patch('os.path.exists', return_value=True):
        authentication.generate_keypair()
        calls = [call(authentication._private_key_path, mode='r'),
                 call(authentication._public_key_path, mode='r')]
        mock_open.assert_has_calls(calls, any_order=True)


def test_generate_keypair_ko():
    """Verify expected exception is raised when IOError"""
    with patch('builtins.open'):
        with patch('os.chmod'):
            with patch('os.chown', side_effect=PermissionError):
                assert authentication.generate_keypair()


@patch('builtins.open')
def test_change_keypair(mock_open):
    """Verify correct params when calling open method inside change_keypair"""
    result = authentication.change_keypair()
    assert isinstance(result[0], str)
    assert isinstance(result[1], str)
    calls = [call(authentication._private_key_path, mode='w'),
             call(authentication._public_key_path, mode='w')]
    mock_open.assert_has_calls(calls, any_order=True)


def test_get_security_conf():
    """Check that returned object is as expected"""
    result = authentication.get_security_conf()
    assert isinstance(result, dict)
    assert all(x in result.keys() for x in ('auth_token_exp_timeout', 'rbac_mode'))


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_context', [{'name': 'initial_auth'}, None])
@patch('api.authentication.jwt.encode', return_value='test_token')
@patch('api.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                            '-----BEGIN PUBLIC KEY-----'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
async def test_generate_token(mock_raise_if_exc, mock_distribute_function, mock_dapi, mock_generate_keypair,
                        mock_encode, auth_context):
    """Verify if result is as expected"""

    class NewDatetime:
        def timestamp(self) -> float:
            return 0

    mock_raise_if_exc.return_value = security_conf
    with patch('api.authentication.core_utils.get_utc_now', return_value=NewDatetime()):
        result = authentication.generate_token(user_id='001', data={'roles': [1]}, auth_context=auth_context)
    assert result == 'test_token', 'Result is not as expected'

    # Check all functions are called with expected params
    mock_dapi.assert_called_once_with(f=ANY, request_type='local_master', is_async=False, wait_for_complete=False,
                                      logger=ANY)
    mock_distribute_function.assert_called_once_with()
    mock_raise_if_exc.assert_called_once()
    mock_generate_keypair.assert_called_once()
    expected_payload = original_payload | (
        {"hash_auth_context": hashlib.blake2b(json.dumps(auth_context).encode(),
                                              digest_size=16).hexdigest(), "run_as": True} if auth_context is not None else {})
    mock_encode.assert_called_once_with(expected_payload, '-----BEGIN PRIVATE KEY-----', algorithm='ES512')


@patch('api.authentication.TokenManager')
def test_check_token(mock_tokenmanager):
    result = authentication.check_token(username='wazuh_user', roles=tuple([1]), token_nbf_time=3600, run_as=False,
                                        origin_node_type='master')
    assert result == {'valid': ANY, 'policies': ANY}


@pytest.mark.asyncio
@patch('api.authentication.jwt.decode')
@patch('api.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                            '-----BEGIN PUBLIC KEY-----'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', return_value=True)
@patch('api.authentication.raise_if_exc', side_effect=None)
async def test_decode_token(mock_raise_if_exc, mock_distribute_function, mock_dapi, mock_generate_keypair,
                      mock_decode):
    
    mock_decode.return_value = deepcopy(original_payload)
    mock_raise_if_exc.side_effect = [WazuhResult({'valid': True, 'policies': {'value': 'test'}}),
                                     WazuhResult(security_conf)]

    result = authentication.decode_token('test_token')
    assert result == decoded_payload

    # Check all functions are called with expected params
    calls = [call(f=ANY, f_kwargs={'username': original_payload['sub'], 'token_nbf_time': original_payload['nbf'],
                                   'run_as': False, 'roles': tuple(original_payload['rbac_roles']),
                                   'origin_node_type': 'master'},
                  request_type='local_master', is_async=False, wait_for_complete=False, logger=ANY),
             call(f=ANY, request_type='local_master', is_async=False, wait_for_complete=False, logger=ANY)]
    mock_dapi.assert_has_calls(calls)
    mock_generate_keypair.assert_called_once()
    mock_decode.assert_called_once_with('test_token', '-----BEGIN PUBLIC KEY-----',
                                        algorithms=['ES512'],
                                        audience='Wazuh API REST')
    assert mock_distribute_function.call_count == 2
    assert mock_raise_if_exc.call_count == 2


@pytest.mark.asyncio
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
@patch('api.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                            '-----BEGIN PUBLIC KEY-----'))
async def test_decode_token_ko(mock_generate_keypair, mock_raise_if_exc, mock_distribute_function):
    """Assert exceptions are handled as expected inside decode_token()"""
    with pytest.raises(Unauthorized):
        authentication.decode_token(token='test_token')

    with patch('api.authentication.jwt.decode') as mock_decode:
        with patch('api.authentication.generate_keypair',
                   return_value=('-----BEGIN PRIVATE KEY-----',
                                 '-----BEGIN PUBLIC KEY-----')):
            with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None):
                with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function'):
                    with patch('api.authentication.raise_if_exc') as mock_raise_if_exc:
                        mock_decode.return_value = deepcopy(original_payload)

                        with pytest.raises(Unauthorized):
                            mock_raise_if_exc.side_effect = [WazuhResult({'valid': False})]
                            authentication.decode_token(token='test_token')

                        with pytest.raises(Unauthorized):
                            mock_raise_if_exc.side_effect = [
                                WazuhResult({'valid': True, 'policies': {'value': 'test'}}),
                                WazuhResult({'auth_token_exp_timeout': 900,
                                             'rbac_mode': 'white'})]
                            authentication.decode_token(token='test_token')
