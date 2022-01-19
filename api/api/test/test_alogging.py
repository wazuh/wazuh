# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import logging
import os
import sys
from unittest.mock import patch, MagicMock, call

import pytest
from werkzeug.exceptions import Unauthorized

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from api import alogging


@pytest.mark.parametrize('side_effect, user', [
    ('unknown', ''),
    (None, ''),
    (None, 'wazuh')
])
@patch('api.alogging.json.dumps')
def test_accesslogger_log(mock_dumps, side_effect, user):
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

    # Mock decode_token and logger.info
    with patch('logging.Logger.info') as mock_logger_info:

        # Create an AccessLogger object and log a mocked call
        test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
        test_access_logger.log(request=MockedRequest(), response=MagicMock(), time=0.0)

        # If not user, decode_token must be called to get the user and logger.info must be called with the user
        # if we have token_info or UNKNOWN_USER if not
        if not user:
            expected_user = 'wazuh' if side_effect is None else alogging.UNKNOWN_USER_STRING
            assert mock_logger_info.call_args.args[0].split(" ")[0] == expected_user

        # If user, logger.info must be called with the user
        else:
            assert mock_logger_info.call_args.args[0].split(" ")[0] == user


@patch('wazuh.core.wlogging.WazuhLogger.__init__')
def test_apilogger_init(mock_wazuhlogger):
    """Check parameters are as expected when calling __init__ method"""
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing.log')
    alogging.APILogger(log_path=current_logger_path, foreground_mode=False, debug_level='info',
                       logger_name='wazuh')

    assert mock_wazuhlogger.call_args.kwargs['log_path'] == current_logger_path
    assert not mock_wazuhlogger.call_args.kwargs['foreground_mode']
    assert mock_wazuhlogger.call_args.kwargs['debug_level'] == 'info'
    assert mock_wazuhlogger.call_args.kwargs['logger_name'] == 'wazuh'
    assert mock_wazuhlogger.call_args.kwargs['tag'] == '{asctime} {levelname}: {message}'

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
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing.log')
    logger = alogging.APILogger(log_path=current_logger_path, foreground_mode=False, debug_level=debug_level,
                                logger_name='wazuh')
    logger.setup_logger()
    assert mock_logger.call_args == call(expected_level)

    os.path.exists(current_logger_path) and os.remove(current_logger_path)
