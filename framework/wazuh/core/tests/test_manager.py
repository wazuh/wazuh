#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from datetime import timezone, datetime
from unittest.mock import patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.manager import *
        from wazuh.core.exception import WazuhException

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'manager')
ossec_log_path = '{0}/ossec_log.log'.format(test_data_path)
ossec_log_json_path = '{0}/ossec_log.log'.format(test_data_path)


class InitManager:
    def __init__(self):
        """Sets up necessary environment to test manager functions"""
        # path for temporary API files
        self.api_tmp_path = os.path.join(test_data_path, 'tmp')


@pytest.fixture(scope='module')
def test_manager():
    # Set up
    test_manager = InitManager()
    return test_manager


def get_logs(json_log: bool = False):
    with open(ossec_log_json_path if json_log else ossec_log_path) as f:
        return f.read()


@pytest.mark.parametrize('process_status', [
    'running',
    'stopped',
    'failed',
    'restarting',
    'starting'
])
@patch('os.path.exists')
@patch('wazuh.core.cluster.utils.glob')
def test_get_status(manager_glob, manager_exists, test_manager, process_status):
    """Tests core.manager.status()

    Tests manager.status() function in two cases:
        * PID files are created and processed are running,
        * No process is running and therefore no PID files have been created

    Parameters
    ----------
    manager_glob : mock
        Mock of glob.glob function.
    manager_exists : mock
        Mock of os.path.exists function.
    process_status : str
        Status to test (valid values: running/stopped/failed/restarting).
    """

    def mock_glob(path_to_check):
        return [path_to_check.replace('*', '0234')] if process_status == 'running' else []

    def mock_exists(path_to_check):
        if path_to_check == '/proc/0234':
            return process_status == 'running'
        else:
            return path_to_check.endswith(f'.{process_status.replace("ing", "").replace("re", "")}') or \
                   path_to_check.endswith(f'.{process_status.replace("ing", "")}')

    manager_glob.side_effect = mock_glob
    manager_exists.side_effect = mock_exists
    manager_status = status()
    assert isinstance(manager_status, dict)
    assert all(process_status == x for x in manager_status.values())
    if process_status == 'running':
        manager_exists.assert_any_call("/proc/0234")


def test_get_wazuh_log_fields():
    """Test get_wazuh_log_fields() method returns a tuple"""
    result = get_wazuh_log_fields('2020/07/14 06:10:40 rootcheck: INFO: Ending rootcheck scan.')
    assert isinstance(result, tuple), 'The result is not a tuple'
    assert result[0] == datetime(2020, 7, 14, 6, 10, 40, tzinfo=timezone.utc)
    assert result[1] == 'wazuh-rootcheck'
    assert result[2] == 'info'
    assert result[3] == ' Ending rootcheck scan.'


def test_get_wazuh_log_fields_ko():
    """Test get_wazuh_log_fields() method returns None when nothing matches """
    result = get_wazuh_log_fields('DEBUG')
    assert not result


@pytest.mark.parametrize("log_format", [
    LoggingFormat.plain, LoggingFormat.json
])
def test_get_wazuh_logs(log_format):
    """Test get_wazuh_logs() method returns result with expected information"""
    logs = get_logs(json_log=log_format == LoggingFormat.json).splitlines()

    with patch("wazuh.core.manager.get_wazuh_active_logging_format", return_value=log_format):
        with pytest.raises(WazuhInternalError, match=".*1020.*"):
            get_wazuh_logs()

        with patch('wazuh.core.manager.exists', return_value=True):
            with patch('wazuh.core.manager.tail', return_value=logs):
                result = get_wazuh_logs()
                assert all(key in log for key in ('timestamp', 'tag', 'level', 'description') for log in result)


@patch("wazuh.core.manager.get_wazuh_active_logging_format", return_value=LoggingFormat.plain)
@patch('wazuh.core.manager.exists', return_value=True)
def test_get_logs_summary(mock_exists, mock_active_logging_format):
    """Test get_logs_summary() method returns result with expected information"""
    logs = get_logs().splitlines()
    with patch('wazuh.core.manager.tail', return_value=logs):
        result = get_logs_summary()
        assert all(key in log for key in ('all', 'info', 'error', 'critical', 'warning', 'debug')
                   for log in result.values())
        assert result['wazuh-manager-modulesd:database'] == {'all': 2, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0,
                                                     'debug': 2}


@patch('wazuh.core.manager.exists', return_value=True)
@patch('wazuh.core.manager.load_wazuh_xml')
def test_validate_ossec_conf(mock_load_xml, mock_exists):
    """Test that validate_ossec_conf validates XML configuration successfully."""
    # Mock successful XML load
    mock_load_xml.return_value = None

    result = validate_ossec_conf()

    assert result == {'status': 'OK'}
    mock_exists.assert_called_with(common.OSSEC_CONF)
    mock_load_xml.assert_called_once_with(xml_path=common.OSSEC_CONF)


@patch('wazuh.core.manager.load_wazuh_xml')
@patch("wazuh.core.manager.exists")
def test_validation_ko(mock_exists, mock_load_xml):
    """Test that validate_ossec_conf handles errors correctly."""

    # Configuration file not exists
    mock_exists.return_value = False
    with pytest.raises(WazuhInternalError, match='.* 1020 .*'):
        validate_ossec_conf()

    # XML validation error
    mock_exists.return_value = True
    mock_load_xml.side_effect = WazuhError(1113, 'Invalid XML syntax')
    with pytest.raises(WazuhError, match='.* 1113 .*'):
        validate_ossec_conf()

    # Other exception wrapped as validation error
    mock_load_xml.side_effect = Exception('Unexpected error')
    with pytest.raises(WazuhError, match='.* 1908 .*'):
        validate_ossec_conf()



@patch('wazuh.core.manager.configuration.api_conf', new={'max_upload_size': 0})
def test_get_api_config():
    """Checks that get_api_config method is returning current api_conf dict."""
    result = get_api_conf()
    assert result == {'max_upload_size': 0}
