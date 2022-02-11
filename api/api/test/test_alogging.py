# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import logging
import os
from unittest.mock import MagicMock, call, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from api import alogging


@pytest.mark.parametrize('json_log', [
    False,
    True
])
def test_accesslogger_log_credentials(json_log):
    """Check AccessLogger is hiding confidential data from logs"""
    class MockedRequest(dict):
        query = {'password': 'password_value'
                 }
        path = '/agents'
        remote = 'remote_value'
        method = 'method_value'

        def __init__(self):
            super().__setitem__('body', {'password': 'password_value',
                                         'key': 'key_value'})
            super().__setitem__('user', 'wazuh')

    with patch('api.alogging.JSON_LOG', json_log):
        with patch('logging.Logger.info') as mock_logger_info:
            test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
            test_access_logger.log(request=MockedRequest(), response=MagicMock(), time=0.0)

            if json_log:
                assert mock_logger_info.call_args.args[0]['parameters'] == {"password": "****"}
                assert mock_logger_info.call_args.args[0]['body'] == {"password": "****", "key": "****"}
            else:
                assert 'parameters {"password": "****"} and body {"password": "****", "key": "****"}' \
                    in mock_logger_info.call_args.args[0]


@pytest.mark.parametrize('side_effect, user, json_log', [
    ('unknown', '', True),
    (None, '', False),
    (None, 'wazuh', True),
    (None, 'wazuh', False)
])
@patch('api.alogging.json.dumps')
def test_accesslogger_log(mock_dumps, side_effect, user, json_log):
    """Test expected methods are called when using log().

    Parameters
    ----------
    side_effect : function
        Side effect used in the decode_token mock.
    user : str
        User returned by the request.get function of alogging.py, which is mocked using a class.
    """

    # Create a class with a mocked get method for request
    class MockedRequest(MagicMock):
        # wazuh:password123
        headers = {'authorization': 'Basic d2F6dWg6cGFzc3dvcmQxMjM='} if side_effect is None else {}

        def get(self, *args, **kwargs):
            return user
    with patch('api.alogging.JSON_LOG', json_log):
        # Mock decode_token and logger.info
        with patch('logging.Logger.info') as mock_logger_info:

            # Create an AccessLogger object and log a mocked call
            test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
            test_access_logger.log(request=MockedRequest(), response=MagicMock(), time=0.0)

            # If not user, decode_token must be called to get the user and logger.info must be called with the user
            # if we have token_info or UNKNOWN_USER if not
            if not user:
                expected_user = 'wazuh' if side_effect is None else alogging.UNKNOWN_USER_STRING
                if json_log:
                    assert mock_logger_info.call_args.args[0]['user'] == expected_user
                else:
                    assert mock_logger_info.call_args.args[0].split(" ")[0] == expected_user
            # If user, logger.info must be called with the user
            else:
                if json_log:
                    assert mock_logger_info.call_args.args[0]['user'] == user
                else:
                    assert mock_logger_info.call_args.args[0].split(" ")[0] == user


@pytest.mark.parametrize('json_log', [
    False,
    True
])
@patch('wazuh.core.wlogging.WazuhLogger.__init__')
def test_apilogger_init(mock_wazuhlogger, json_log):
    log_name = 'testing.json' if json_log else 'testing.log'
    current_logger_path = os.path.join(os.path.dirname(__file__), log_name)
    alogging.APILogger(log_path=current_logger_path, foreground_mode=False, debug_level='info',
                       logger_name='wazuh')

    assert mock_wazuhlogger.call_args.kwargs['log_path'] == current_logger_path
    assert not mock_wazuhlogger.call_args.kwargs['foreground_mode']
    assert mock_wazuhlogger.call_args.kwargs['debug_level'] == 'info'
    assert mock_wazuhlogger.call_args.kwargs['logger_name'] == 'wazuh'
    if json_log:
        assert mock_wazuhlogger.call_args.kwargs['tag'] is None
        assert mock_wazuhlogger.call_args.kwargs['custom_formatter'] == alogging.WazuhJsonFormatter
    else:
        assert mock_wazuhlogger.call_args.kwargs['tag'] == '%(asctime)s %(levelname)s: %(message)s'
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
    """Check loggin level is as expected"""
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
    """Check wazuh json formatter is working as expected"""
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
