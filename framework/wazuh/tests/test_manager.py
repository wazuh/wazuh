#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import operator
import os
import socket
import sys
from unittest.mock import MagicMock, patch

import pytest
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.server import ValidateFilePathMixin
from wazuh.tests.util import get_default_configuration

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = get_default_configuration()
            CentralizedConfig._config = default_config

            sys.modules['wazuh.rbac.orm'] = MagicMock()
            import wazuh.rbac.decorators
            from wazuh.tests.util import RBAC_bypasser

            del sys.modules['wazuh.rbac.orm']
            wazuh.rbac.decorators.expose_resources = RBAC_bypasser

            from wazuh.core.manager import LoggingFormat
            from wazuh.core.tests.test_manager import get_logs
            from wazuh.manager import *

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture(scope='module', autouse=True)
def mock_wazuh_path():
    with patch('wazuh.core.common.WAZUH_PATH', new=test_data_path):
        yield


class InitManager:
    def __init__(self):
        """Sets up necessary environment to test manager functions."""
        # path for temporary API files
        self.api_tmp_path = os.path.join(test_data_path, 'tmp')


@pytest.fixture(scope='module')
def test_manager():
    # Set up
    test_manager = InitManager()
    return test_manager


manager_status = {
    'wazuh-agentlessd': 'running',
    'wazuh-analysisd': 'running',
    'wazuh-authd': 'running',
    'wazuh-csyslogd': 'running',
    'wazuh-dbd': 'running',
    'wazuh-monitord': 'running',
    'wazuh-execd': 'running',
    'wazuh-integratord': 'running',
    'wazuh-logcollector': 'running',
    'wazuh-maild': 'running',
    'wazuh-remoted': 'running',
    'wazuh-reportd': 'running',
    'wazuh-syscheckd': 'running',
    'wazuh-clusterd': 'running',
    'wazuh-modulesd': 'running',
    'wazuh-db': 'running',
    'wazuh-server-management-apid': 'running',
    'wazuh-comms-apid': 'running',
}


@patch('wazuh.core.manager.status', return_value=manager_status)
def test_get_status(mock_status):
    """Tests get_status() function works."""
    result = get_status()

    # Assert there are no errors and type returned
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


@pytest.mark.parametrize(
    'tag, level, total_items, sort_by, sort_ascending',
    [
        (None, None, 13, None, None),
        ('wazuh-modulesd:database', None, 2, None, None),
        ('wazuh-modulesd:syscollector', None, 2, None, None),
        ('wazuh-modulesd:syscollector', None, 2, None, None),
        ('wazuh-modulesd:aws-s3', None, 5, None, None),
        ('wazuh-execd', None, 1, None, None),
        ('wazuh-csyslogd', None, 2, None, None),
        ('random', None, 0, ['timestamp'], True),
        (None, 'info', 7, ['timestamp'], False),
        (None, 'error', 2, ['level'], True),
        (None, 'debug', 2, ['level'], False),
        (None, None, 13, ['tag'], True),
        (None, 'random', 0, None, True),
        (None, 'warning', 2, None, False),
    ],
)
@patch('wazuh.core.manager.get_wazuh_active_logging_format', return_value=LoggingFormat.plain)
@patch('wazuh.core.manager.exists', return_value=True)
def test_ossec_log(mock_exists, mock_active_logging_format, tag, level, total_items, sort_by, sort_ascending):
    """Test reading ossec.log file contents.

    Parameters
    ----------
    level : str
        Filters by log type: all, error or info.
    tag : str
        Filters by log category (i.e. wazuh-remoted).
    total_items : int
        Expected items to be returned after calling ossec_log.
    sort_by : list
        Fields to sort the items by.
    sort_ascending : boolean
        Sort in ascending (true) or descending (false) order.
    """
    with patch('wazuh.core.manager.tail') as tail_patch:
        # Return ossec_log_file when calling tail() method
        ossec_log_file = get_logs()
        tail_patch.return_value = ossec_log_file.splitlines()

        result = ossec_log(level=level, tag=tag, sort_by=sort_by, sort_ascending=sort_ascending)

        # Assert type, number of items and presence of trailing characters
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_affected_items'] == total_items
        assert all(log['description'][-1] != '\n' for log in result.render()['data']['affected_items'])
        if tag is not None and level != 'wazuh-modulesd:syscollector':
            assert all('\n' not in log['description'] for log in result.render()['data']['affected_items'])
        if sort_by:
            reversed_result = ossec_log(level=level, tag=tag, sort_by=sort_by, sort_ascending=not sort_ascending)
            for i in range(total_items):
                assert (
                    result.render()['data']['affected_items'][i][sort_by[0]]
                    == reversed_result.render()['data']['affected_items'][total_items - 1 - i][sort_by[0]]
                )


@pytest.mark.parametrize(
    'q, field, operation, values',
    [
        ('level=debug,level=error', 'level', 'OR', 'debug, error'),
        ('timestamp=2019/03/26 19:49:15', 'timestamp', '=', '2019/03/26T19:49:15Z'),
        ('timestamp<2019/03/26 19:49:14', 'timestamp', '<', '2019/03/26T19:49:15Z'),
    ],
)
@patch('wazuh.core.manager.get_wazuh_active_logging_format', return_value=LoggingFormat.plain)
@patch('wazuh.core.manager.exists', return_value=True)
def test_ossec_log_q(mock_exists, mock_active_logging_format, q, field, operation, values):
    """Check that the 'q' parameter is working correctly.

    Parameters
    ----------
    q : str
        Query to execute.
    field : str
        Field affected by the query.
    operation : str
        Operation type to be performed in the query.
    values : str
        Values used for the comparison.
    """
    with patch('wazuh.core.manager.tail') as tail_patch:
        ossec_log_file = get_logs()
        tail_patch.return_value = ossec_log_file.splitlines()

        result = ossec_log(q=q)

        if operation != 'OR':
            operators = {'=': operator.eq, '!=': operator.ne, '<': operator.lt, '>': operator.gt}
            assert all(operators[operation](log[field], values) for log in result.render()['data']['affected_items'])
        else:
            assert all(log[field] in values for log in result.render()['data']['affected_items'])


@patch('wazuh.core.manager.get_wazuh_active_logging_format', return_value=LoggingFormat.plain)
@patch('wazuh.core.manager.exists', return_value=True)
def test_ossec_log_summary(mock_exists, mock_active_logging_format):
    """Tests ossec_log_summary function works and returned data match with expected."""
    expected_result = {
        'wazuh-csyslogd': {'all': 2, 'info': 2, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0},
        'wazuh-execd': {'all': 1, 'info': 0, 'error': 1, 'critical': 0, 'warning': 0, 'debug': 0},
        'wazuh-modulesd:aws-s3': {'all': 5, 'info': 2, 'error': 1, 'critical': 0, 'warning': 2, 'debug': 0},
        'wazuh-modulesd:database': {'all': 2, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 2},
        'wazuh-modulesd:syscollector': {'all': 2, 'info': 2, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0},
        'wazuh-rootcheck': {'all': 1, 'info': 1, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0},
    }

    logs = get_logs().splitlines()
    with patch('wazuh.core.manager.tail', return_value=logs):
        result = ossec_log_summary()

        # Assert data match what was expected and type of the result.
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_affected_items'] == 6
        assert all(
            all(value == expected_result[key] for key, value in item.items())
            for item in result.render()['data']['affected_items']
        )


@patch('socket.socket')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('wazuh.core.cluster.utils.open')
@patch('os.path.exists', return_value=True)
def test_restart_ok(mock_exists, mock_path, mock_fcntl, mock_socket):
    """Tests restarting a manager."""
    result = restart()

    # Assert there are no errors and type of the result.
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


@patch('wazuh.core.cluster.utils.open')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('os.path.exists', return_value=False)
def test_restart_ko_socket(mock_exists, mock_fcntl, mock_open):
    """Tests restarting a manager exceptions."""
    # Socket path not exists
    with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
        restart()

    # Socket error
    with patch('os.path.exists', return_value=True):
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhInternalError, match='.* 1902 .*'):
                restart()

        with patch('socket.socket.connect'):
            with patch('socket.socket.send', side_effect=socket.error):
                with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                    restart()


@pytest.mark.parametrize(
    'error_flag, error_msg',
    [
        (0, ''),
        (
            1,
            '2019/02/27 11:30:07 wazuh-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: '
            'Unspecified key',
        ),
        (
            1,
            '2019/02/27 11:30:24 wazuh-authd: ERROR: (1230): Invalid element in the configuration: '
            "'use_source_i'.\n2019/02/27 11:30:24 wazuh-authd: ERROR: (1202): Configuration error at "
            "'/var/ossec/etc/ossec.conf'.",
        ),
    ],
)
@patch('wazuh.core.manager.exists', return_value=True)
def test_validation(mock_exists, error_flag, error_msg):
    """Test validation() method works as expected.

    Tests configuration validation function with multiple scenarios:
        * No errors found in configuration
        * Error found in cluster configuration
        * Error found in any other configuration

    Parameters
    ----------
    error_flag : int
        Error flag to be mocked in the socket response.
    error_msg : str
        Error message to be mocked in the socket response.
    """
    with patch('wazuh.core.manager.WazuhSocket') as sock:
        # Mock sock response
        json_response = json.dumps({'error': error_flag, 'message': error_msg}).encode()
        sock.return_value.receive.return_value = json_response
        result = validation()

        # Assert if error was returned
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_failed_items'] == error_flag


@pytest.mark.parametrize('exception', [WazuhInternalError(1013), WazuhError(1013)])
@patch('wazuh.manager.validate_ossec_conf')
def test_validation_ko(mock_validate, exception):
    mock_validate.side_effect = exception

    if isinstance(exception, WazuhInternalError):
        with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
            validation()
    else:
        result = validation()
        assert not result.affected_items
        assert result.total_failed_items == 1


@patch('builtins.open')
def test_get_basic_info(mock_open):
    """Tests get_basic_info() function works as expected."""
    result = get_basic_info()

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0
