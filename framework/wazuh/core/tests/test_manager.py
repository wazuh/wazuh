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
@patch('wazuh.core.configuration.load_manager_conf', return_value={
    'cluster': {'name': 'wazuh', 'node_name': 'node01', 'node_type': 'master',
                'key': '9d273b53510fef702b54a92e9cffc82e', 'port': 1516, 'bind_addr': '127.0.0.1',
                'nodes': ['127.0.0.1'], 'hidden': False},
    'logging': {'log_format': ['plain']}})
def test_get_status(manager_conf_mock, manager_glob, manager_exists, test_manager, process_status):
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


class _Completed:
    def __init__(self, returncode, stderr='', stdout=''):
        self.returncode, self.stderr, self.stdout = returncode, stderr, stdout


@patch('wazuh.core.manager.exists', return_value=True)
@patch('wazuh.core.manager.subprocess.run', return_value=_Completed(0))
def test_validate_manager_conf(mock_run, mock_exists):
    """validate_manager_conf() delegates to bin/wazuh-manager-conf validate and reports OK on exit 0."""
    assert validate_manager_conf() == {'status': 'OK'}

    mock_exists.assert_called_with(common.MANAGER_CONF)
    command = mock_run.call_args[0][0]
    assert command[0] == os.path.join(common.WAZUH_PATH, 'bin', 'wazuh-manager-conf')
    assert command[1:] == ['-H', common.WAZUH_PATH, '-f', common.MANAGER_CONF, 'validate']

    validate_manager_conf('/tmp/other.yml')
    assert mock_run.call_args[0][0][-2:] == ['/tmp/other.yml', 'validate']


@patch('wazuh.core.manager.subprocess.run')
@patch('wazuh.core.manager.exists')
def test_validate_manager_conf_ko(mock_exists, mock_run):
    """validate_manager_conf() maps the CLI outcome to the framework error codes."""
    # Configuration file does not exist
    mock_exists.return_value = False
    with pytest.raises(WazuhInternalError, match='.* 1020 .*'):
        validate_manager_conf()

    # Invalid configuration: the CLI exits 1 and names the offending option
    mock_exists.return_value = True
    mock_run.return_value = _Completed(1, stderr="(1244): Invalid configuration at '/etc/wazuh-manager.conf': "
                                                 "/vulnerability-detection/pageSize: does not satisfy 'minimum'.\n")
    with pytest.raises(WazuhError, match='.* 1130 .*') as exc:
        validate_manager_conf()
    assert '/vulnerability-detection/pageSize' in str(exc.value)

    # The validator itself failed (usage error, crash)
    mock_run.return_value = _Completed(2, stdout='unknown option')
    with pytest.raises(WazuhError, match='.* 1908 .*'):
        validate_manager_conf()

    mock_run.side_effect = OSError('No such file or directory')
    with pytest.raises(WazuhError, match='.* 1908 .*'):
        validate_manager_conf()


@patch('wazuh.core.manager.configuration.api_conf', new={'max_upload_size': 0})
def test_get_api_config():
    """Checks that get_api_config method is returning current api_conf dict."""
    result = get_api_conf()
    assert result == {'max_upload_size': 0}
