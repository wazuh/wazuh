# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from wazuh import WazuhError
from wazuh.core.wazuh_socket import create_wazuh_socket_message

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.logtest import run_logtest, end_logtest_session


def send_logtest_msg_mock(**kwargs):
    socket_response = create_wazuh_socket_message(command=kwargs['command'], parameters=kwargs['parameters'])
    socket_response['error'] = 0
    return socket_response


@pytest.mark.parametrize('logtest_param_values', [
    [None, 'event_value', 'log_format_value', 'location_value'],
    ['token_value', 'event_value', 'log_format_value', 'location_value'],
])
def test_get_logtest_output(logtest_param_values):
    """Test `run_logtest` function from module logtest.

    Parameters
    ----------
    logtest_param_values : list of str
        List of values for every kwarg.
    """
    kwargs_keys = ['token', 'event', 'log_format', 'location']
    kwargs = {key: value for key, value in zip(kwargs_keys, logtest_param_values)}
    with patch('wazuh.logtest.send_logtest_msg') as send_mock:
        send_mock.side_effect = send_logtest_msg_mock
        result = run_logtest(**kwargs)
        assert result
        # Remove error field. It was mocked
        del result['error']

        assert result['command'] == 'log_processing'
        assert result['parameters'].items() <= kwargs.items()


def test_get_logtest_output_ko():
    """Test `run_logtest` exceptions."""
    with patch('wazuh.logtest.send_logtest_msg') as send_mock:
        send_mock.return_value = {'error': 1}
        try:
            run_logtest()
        except WazuhError as e:
            assert e.code == 7000


@pytest.mark.parametrize('token', [
    'thisisarandomtoken123',
    'anotherrandomtoken321'
])
def test_end_logtest_session(token):
    """Test `end_logtest_session_ko` function from module logtest.

    Parameters
    ----------
    token : str
        Logtest session token.
    """
    with patch('wazuh.logtest.send_logtest_msg') as send_mock:
        send_mock.side_effect = send_logtest_msg_mock
        result = end_logtest_session(token=token)
        assert result['command'] == 'remove_session'
        assert result['parameters'] == {'token': token}


def test_end_logtest_session_ko():
    """Test `end_logtest_session_ko` exceptions."""
    with patch('wazuh.logtest.send_logtest_msg') as send_mock:
        send_mock.return_value = {'error': 1}
        try:
            end_logtest_session(token='whatever')
        except WazuhError as e:
            assert e.code == 7000

    try:
        end_logtest_session()
    except WazuhError as e:
        assert e.code == 7001
