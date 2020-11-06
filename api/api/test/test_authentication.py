# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock, ANY, call
from copy import deepcopy
from werkzeug.exceptions import Unauthorized

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.results import WazuhResult

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        from api import authentication

        del sys.modules['wazuh.rbac.orm']

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')

security_conf = WazuhResult({
    'auth_token_exp_timeout': 3600,
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
    "iss": 'wazuh',
    "aud": 'Wazuh API REST',
    "nbf": 0,
    "exp": security_conf['auth_token_exp_timeout'],
    "sub": '001',
    'run_as': False,
    "rbac_roles": [1],
    "rbac_mode": security_conf['rbac_mode']
}


def test_check_user_master():
    result = authentication.check_user_master('test_user', 'test_pass')
    assert result == {'result': True}


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('concurrent.futures.ThreadPoolExecutor.submit', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
def test_check_user(mock_raise_if_exc, mock_submit, mock_distribute_function, mock_dapi):
    """Verify if result is as expected"""
    result = authentication.check_user('test_user', 'test_pass')

    assert result == {'sub': 'test_user', 'active': True}, 'Result is not as expected'
    mock_dapi.assert_called_once_with(f=ANY, f_kwargs={'user': 'test_user', 'password': 'test_pass'},
                                      request_type='local_master', is_async=False, wait_for_complete=True, logger=ANY)
    mock_distribute_function.assert_called_once_with()
    mock_raise_if_exc.assert_called_once()


@patch('api.authentication.token_urlsafe', return_value='test_token')
@patch('os.chmod')
@patch('api.authentication.chown')
@patch('builtins.open')
def test_generate_secret(mock_open, mock_chown, mock_chmod, mock_token):
    """Check if result's length and type are as expected and mocked function are called with correct params"""
    result = authentication.generate_secret()
    assert isinstance(result, str)
    assert result == 'test_token'

    calls = [call(authentication._secret_file_path, mode='x')]
    mock_open.has_calls(calls)
    mock_chown.assert_called_once_with(authentication._secret_file_path, 'ossec', 'ossec')
    mock_chmod.assert_called_once_with(authentication._secret_file_path, 0o640)

    with patch('os.path.exists', return_value=True):
        authentication.generate_secret()

        calls.append(call(authentication._secret_file_path, mode='r'))
        mock_open.has_calls(calls)


def test_generate_secret_ko():
    """Verify expected exception is raised when IOError"""
    with patch('builtins.open'):
        with patch('os.chmod'):
            with patch('api.authentication.chown', side_effect=PermissionError):
                assert authentication.generate_secret()


@patch('api.authentication.token_urlsafe', return_value='test_token')
@patch('builtins.open')
def test_change_secret(mock_open, mock_token):
    """Verify correct params when calling open method inside change_secret"""
    authentication.change_secret()
    mock_open.assert_called_once_with(authentication._secret_file_path, mode='w')
    mock_open.return_value.__enter__().write.assert_called_once_with('test_token')


def test_get_security_conf():
    """Check that returned object is as expected"""
    result = authentication.get_security_conf()
    assert isinstance(result, dict)
    assert all(x in result.keys() for x in ('auth_token_exp_timeout', 'rbac_mode'))


@patch('api.authentication.time', return_value=0)
@patch('api.authentication.jwt.encode', return_value='test_token')
@patch('api.authentication.generate_secret', return_value='test_secret_token')
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('concurrent.futures.ThreadPoolExecutor.submit', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
def test_generate_token(mock_raise_if_exc, mock_submit, mock_distribute_function, mock_dapi, mock_generate_secret,
                        mock_encode, mock_time):
    """Verify if result is as expected"""
    mock_raise_if_exc.return_value = security_conf
    result = authentication.generate_token('001', {'roles': [1]})
    assert result == 'test_token', 'Result is not as expected'

    # Check all functions are called with expected params
    mock_dapi.assert_called_once_with(f=ANY, request_type='local_master', is_async=False, wait_for_complete=True,
                                      logger=ANY)
    mock_distribute_function.assert_called_once_with()
    mock_raise_if_exc.assert_called_once()
    mock_generate_secret.assert_called_once()
    mock_encode.assert_called_once_with(original_payload, 'test_secret_token', algorithm='HS256')


@patch('api.authentication.TokenManager')
def test_check_token(mock_tokenmanager):
    result = authentication.check_token(username='wazuh_user', roles=[1], token_nbf_time=3600, run_as=False)
    assert result == {'valid': ANY, 'policies': ANY}


@patch('api.authentication.jwt.decode')
@patch('api.authentication.generate_secret', return_value='test_secret_token')
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('concurrent.futures.ThreadPoolExecutor.submit', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
def test_decode_token(mock_raise_if_exc, mock_submit, mock_distribute_function, mock_dapi, mock_generate_secret,
                      mock_decode):
    mock_decode.return_value = deepcopy(original_payload)
    mock_raise_if_exc.side_effect = [WazuhResult({'valid': True, 'policies': {'value': 'test'}}),
                                     WazuhResult(security_conf)]

    result = authentication.decode_token('test_token')
    assert result == decoded_payload

    # Check all functions are called with expected params
    calls = [call(f=ANY, f_kwargs={'username': original_payload['sub'], 'token_nbf_time': original_payload['nbf'],
                                   'run_as': False, 'roles': original_payload['rbac_roles']},
                  request_type='local_master', is_async=False, wait_for_complete=True, logger=ANY),
             call(f=ANY, request_type='local_master', is_async=False, wait_for_complete=True, logger=ANY)]
    mock_dapi.assert_has_calls(calls)
    mock_generate_secret.assert_called_once()
    mock_decode.assert_called_once_with('test_token', 'test_secret_token', algorithms=['HS256'],
                                        audience='Wazuh API REST')
    assert mock_distribute_function.call_count == 2
    assert mock_raise_if_exc.call_count == 2


@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('concurrent.futures.ThreadPoolExecutor.submit', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
@patch('api.authentication.generate_secret', return_value='test_secret_token')
def test_decode_token_ko(mock_generate_secret, mock_raise_if_exc, mock_submit, mock_distribute_function):
    """Assert exceptions are handled as expected inside decode_token()"""
    with pytest.raises(Unauthorized):
        authentication.decode_token(token='test_token')

    with patch('api.authentication.jwt.decode') as mock_decode:
        with patch('api.authentication.generate_secret', return_value='test_secret_token'):
            with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None):
                with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function'):
                    with patch('api.authentication.raise_if_exc') as mock_raise_if_exc:
                        mock_decode.return_value = deepcopy(original_payload)

                        with pytest.raises(Unauthorized):
                            mock_raise_if_exc.side_effect = [WazuhResult({'valid': False})]
                            authentication.decode_token(token='test_token')

                        with pytest.raises(Unauthorized):
                            mock_raise_if_exc.side_effect = [WazuhResult({'valid': True, 'policies': {'value': 'test'}}),
                                                             WazuhResult({'auth_token_exp_timeout': 3600,
                                                                          'rbac_mode': 'white'})]
                            authentication.decode_token(token='test_token')
