# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import logging
import os
from unittest.mock import patch, MagicMock, call

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from api import alogging


@patch('api.alogging.logging.Logger')
def test_accesslogger_log(mock_logger_info):
    """Tests expected methods are called when using log()"""
    request = MagicMock()
    alogging.AccessLogger.log(MagicMock(), request=request, response=MagicMock(), time=0.0)

    assert request.method_calls[0] == call.get('user', 'unknown_user')


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
