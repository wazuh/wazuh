# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
import logging
import os
from unittest.mock import MagicMock, call, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from api import alogging

REQUEST_HEADERS_TEST = {'authorization': 'Basic d2F6dWg6cGFzc3dvcmQxMjM='}  # wazuh:password123
AUTH_CONTEXT_TEST = {'auth_context': 'example'}
HASH_AUTH_CONTEXT_TEST = '020efd3b53c1baf338cf143fad7131c3'

def test_accesslogger_log_credentials():
    """Check AccessLogger is hiding confidential data from logs"""
    class MockedRequest(dict):
        query = {'password': 'password_value'
                 }
        path = '/agents'
        remote = 'remote_value'
        method = 'method_value'

        def __init__(self):
            self['body'] = {'password': 'password_value',
                            'key': 'key_value'}
            self['user'] = 'wazuh'

    with patch('logging.Logger.info') as mock_logger_info:
        test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
        test_access_logger.log(request=MockedRequest(), response=MagicMock(), time=0.0)

        assert mock_logger_info.call_count == 2

        json_call = mock_logger_info.call_args_list[1][0][0]
        log_call = mock_logger_info.call_args_list[0][0][0]

        assert json_call['parameters'] == {"password": "****"}
        assert json_call['body'] == {"password": "****", "key": "****"}
        assert 'parameters {"password": "****"} and body {"password": "****", "key": "****"}' in log_call

        assert mock_logger_info.call_args_list[1][1]['extra'] == {'log_type': 'json'}
        assert mock_logger_info.call_args_list[0][1]['extra'] == {'log_type': 'log'}


@pytest.mark.parametrize('side_effect, user', [
    ('unknown', ''),
    (None, ''),
    (None, 'wazuh')
])
@patch('api.alogging.json.dumps')
def test_accesslogger_log_user(mock_dumps, side_effect, user):
    """Test that the user is logged properly when using log().

    Parameters
    ----------
    side_effect : function
        Side effect used in the decode_token mock.
    user : str
        User returned by the request.get function of alogging.py, which is mocked using a class.
    """

    # Create a class with a mocked get method for request
    class MockedRequest(MagicMock):
        headers = REQUEST_HEADERS_TEST if side_effect is None else {}

        def get(self, *args, **kwargs):
            return user
    # Mock decode_token and logger.info
    with patch('logging.Logger.info') as mock_logger_info:

        # Create an AccessLogger object and log a mocked call
        test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
        test_access_logger.log(request=MockedRequest(), response=MagicMock(), time=0.0)

        json_call = mock_logger_info.call_args_list[1][0][0]
        log_call = mock_logger_info.call_args_list[0][0][0]

        # If not user, decode_token must be called to get the user and logger.info must be called with the user
        # if we have token_info or UNKNOWN_USER if not
        if not user:
            expected_user = 'wazuh' if side_effect is None else alogging.UNKNOWN_USER_STRING
            assert json_call['user'] == expected_user
            assert log_call.split(" ")[0] == expected_user
        # If user, logger.info must be called with the user
        else:
            assert json_call['user'] == user
            assert log_call.split(" ")[0] == user


@pytest.mark.parametrize('request_path, token_info, request_body', [
    ('/agents', {'hash_auth_context': HASH_AUTH_CONTEXT_TEST}, {}),  # Test a normal request logs the auth context hash
    ('/security/user/authenticate/run_as', {'other_key': 'other_value'},
     AUTH_CONTEXT_TEST),  # Test a login request generates and logs the auth context hash
    ('/security/user/authenticate', None, {})  # Test any other call without auth context does not log the hash
])
def test_accesslogger_log_hash_auth_context(request_path, token_info, request_body):
    """Test that the authorization context hash is logged properly when using log().

    Parameters
    ----------
    request_path : str
        Path used in the custom request.
    token_info : dict
        Dictionary corresponding to the token information. If token_info is None, we simulate that no token was given.
    request_body : dict
        Request body used in the custom request.
    """

    # Create a class with custom methods for request
    class CustomRequest:
        def __init__(self):
            self.request_dict = {'token_info': token_info} if token_info else {}
            self.path = request_path
            self.body = request_body
            self.query = {'q': 'test'}
            self.remote = 'test'
            self.method = 'test'
            self.user = 'test'

        def __contains__(self, key):
            return key in self.request_dict

        def __getitem__(self, key):
            return self.request_dict[key]

        def get(self, *args, **kwargs):
            return getattr(self, args[0]) if args[0] in self.__dict__.keys() else args[1]

    # Mock logger.info
    with patch('logging.Logger.info') as mock_logger_info:
        # Create an AccessLogger object and log a mocked call
        request = CustomRequest()
        test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
        test_access_logger.log(request=request, response=MagicMock(), time=0.0)

        message_api_log = mock_logger_info.call_args_list[0][0][0].split(" ")
        message_api_json = mock_logger_info.call_args_list[1][0][0]

        # Test authorization context hash is being logged
        if (token_info and token_info.get('hash_auth_context')) or \
                (request_path == "/security/user/authenticate/run_as" and request_body):
            assert message_api_log[1] == f"({HASH_AUTH_CONTEXT_TEST})"
            assert message_api_json.get('hash_auth_context') == HASH_AUTH_CONTEXT_TEST
        else:
            assert message_api_log[1] == request.remote
            assert 'hash_auth_context' not in message_api_json


@pytest.mark.parametrize('request_path,request_body,log_level,log_key,json_key', [
    ('/events', {"events": ["foo", "bar"]}, 20, 'body', 'body'),
    ('/events', {"events": ["foo", "bar"]}, 5, 'body', 'body'),
    ('/agents', {}, 20, 'body', 'body'),
    ('/agents', {}, 5, 'body', 'body')
])
@patch('logging.Logger.info')
@patch('logging.Logger.debug')
def test_accesslogger_log_events_correctly(
    mock_logger_debug, mock_logger_info, request_path, request_body, log_level, log_key, json_key
):
    """Test that the authorization context hash is logged properly when using log().

    Parameters
    ----------
    request_path : str
        Path used in the custom request.
    request_body : dict
        Request body used in the custom request.
    log_level: int
        Log level used un the custom request.
    """

    # Create a class with custom methods for request
    class CustomRequest:
        def __init__(self):
            self.request_dict = {}
            self.path = request_path
            self.body = request_body
            self.query = {}
            self.remote = 'test'
            self.method = 'test'
            self.user = 'test'

        def __contains__(self, key):
            return key in self.request_dict

        def __getitem__(self, key):
            return self.request_dict[key]

        def get(self, *args, **kwargs):
            return getattr(self, args[0]) if args[0] in self.__dict__.keys() else args[1]

    # Create an AccessLogger object and log a mocked call
    request = CustomRequest()
    test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
    test_access_logger.logger.setLevel(log_level)
    test_access_logger.log(request=request, response=MagicMock(), time=0.0)

    message_api_log = mock_logger_info.call_args_list[0][0][0]
    message_api_json = mock_logger_info.call_args_list[1][0][0]

    assert log_key in message_api_log
    assert json_key in message_api_json

    if log_level >= 20 and request_path == '/events':
        formatted_log = {"events": len(request_body["events"])}
        assert json.dumps(formatted_log) in message_api_log
        assert formatted_log == message_api_json[json_key]
    else:
        assert json.dumps(request_body) in message_api_log
        assert request_body == message_api_json[json_key]


@pytest.mark.parametrize('json_log', [
    False,
    True
])
@patch('wazuh.core.wlogging.WazuhLogger.__init__')
def test_apilogger_init(mock_wazuhlogger, json_log):
    """Check parameters are as expected when calling __init__ method.

    Parameters
    ----------
    json_log : boolean
        Boolean used to define the log file format.
    """
    log_name = 'testing.json' if json_log else 'testing.log'
    current_logger_path = os.path.join(os.path.dirname(__file__), log_name)
    alogging.APILogger(log_path=current_logger_path, foreground_mode=False, debug_level='info',
                       logger_name='wazuh')

    assert mock_wazuhlogger.call_args.kwargs['log_path'] == current_logger_path
    assert not mock_wazuhlogger.call_args.kwargs['foreground_mode']
    assert mock_wazuhlogger.call_args.kwargs['debug_level'] == 'info'
    assert mock_wazuhlogger.call_args.kwargs['logger_name'] == 'wazuh'
    if json_log:
        assert mock_wazuhlogger.call_args.kwargs['custom_formatter'] == alogging.WazuhJsonFormatter
    else:
        assert mock_wazuhlogger.call_args.kwargs['custom_formatter'] is None

    os.path.exists(current_logger_path) and os.remove(current_logger_path)


@pytest.mark.parametrize('debug_level, expected_level', [
    ('info', logging.INFO),
    ('debug2', 5),
    ('debug', logging.DEBUG),
    ('critical', logging.CRITICAL),
    ('error', logging.ERROR),
    ('warning', logging.WARNING),
])
@patch('api.alogging.logging.Logger.setLevel')
def test_apilogger_setup_logger(mock_logger, debug_level, expected_level):
    """Check loggin level is as expected.

    Parameters
    ----------
    debug_level : str
        Value used to configure the debug level of the logger.
    expected_level : int
        Expeced value of the debug level.
    """
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing')
    logger = alogging.APILogger(log_path=current_logger_path, foreground_mode=False, debug_level=debug_level,
                                logger_name='wazuh')
    logger.setup_logger()
    assert mock_logger.call_args == call(expected_level)

    os.path.exists(current_logger_path) and os.remove(current_logger_path)


@pytest.mark.parametrize('message, dkt', [
    (None, {'k1': 'v1'}),
    ('message_value', {'exc_info': 'traceback_value'}),
    ('message_value', {})
])
def test_wazuhjsonformatter(message, dkt):
    """Check wazuh json formatter is working as expected.

    Parameters
    ----------
    message : str
        Value used as a log record message.
    dkt : dict
        Dictionary used as a request or exception information.
    """
    with patch('api.alogging.logging.LogRecord') as mock_record:
        mock_record.message = message
        wjf = alogging.WazuhJsonFormatter()
        log_record = {}
        wjf.add_fields(log_record, mock_record, dkt)
        assert 'timestamp' in log_record.keys()
        assert 'data' in log_record.keys()
        assert 'levelname' in log_record.keys()
        tb = dkt.get('exc_info')
        if tb is not None:
            assert log_record['data']['payload'] == f'{message}. {tb}'
        elif message is None:
            assert log_record['data']['payload'] == dkt
        else:
            assert log_record['data']['payload'] == message
        assert isinstance(log_record, dict)
