#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.manager import *
        from wazuh.core.exception import WazuhException

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'manager')
ossec_log_path = '{0}/ossec_log.log'.format(test_data_path)


class InitManager:
    def __init__(self):
        """Sets up necessary environment to test manager functions"""
        # path for temporary API files
        self.api_tmp_path = os.path.join(test_data_path, 'tmp')
        # rules
        self.input_rules_file = 'test_rules.xml'
        self.output_rules_file = 'uploaded_test_rules.xml'
        # decoders
        self.input_decoders_file = 'test_decoders.xml'
        self.output_decoders_file = 'uploaded_test_decoders.xml'
        # CDB lists
        self.input_lists_file = 'test_lists'
        self.output_lists_file = 'uploaded_test_lists'


@pytest.fixture(scope='module')
def test_manager():
    # Set up
    test_manager = InitManager()
    return test_manager


def get_logs():
    with open(ossec_log_path) as f:
        return f.read()

@pytest.mark.parametrize('process_status', [
    'running',
    'stopped',
    'failed',
    'restarting',
    'starting'
])
@patch('wazuh.core.cluster.utils.exists')
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
            return path_to_check.endswith(f'.{process_status.replace("ing","").replace("re", "")}') or \
                   path_to_check.endswith(f'.{process_status.replace("ing","")}')

    manager_glob.side_effect = mock_glob
    manager_exists.side_effect = mock_exists
    manager_status = status()
    assert isinstance(manager_status, dict)
    assert all(process_status == x for x in manager_status.values())
    if process_status == 'running':
        manager_exists.assert_any_call("/proc/0234")


def test_get_ossec_log_fields():
    """Test get_ossec_log_fields() method returns a tuple"""
    result = get_ossec_log_fields('2020/07/14 06:10:40 rootcheck: INFO: Ending rootcheck scan.')
    assert isinstance(result, tuple), 'The result is not a tuple'
    assert result[0] == datetime(2020, 7, 14, 6, 10, 40)
    assert result[1] == 'ossec-rootcheck'
    assert result[2] == 'info'
    assert result[3] == ' Ending rootcheck scan.'


def test_get_ossec_log_fields_ko():
    """Test get_ossec_log_fields() method returns None when nothing matches """
    result = get_ossec_log_fields('DEBUG')
    assert not result


def test_get_ossec_logs():
    """Test get_ossec_logs() method returns result with expected information"""
    logs = get_logs().splitlines()

    with patch('wazuh.core.manager.tail', return_value=logs):
        result = get_ossec_logs()
        assert all(key in log for key in ('timestamp', 'tag', 'level', 'description') for log in result)


def test_get_logs_summary():
    """Test get_logs_summary() method returns result with expected information"""
    logs = get_logs().splitlines()
    with patch('wazuh.core.manager.tail', return_value=logs):
        result = get_logs_summary()
        assert all(key in log for key in ('all', 'info', 'error', 'critical', 'warning', 'debug')
                   for log in result.values())
        assert result['wazuh-modulesd:database'] == {'all': 2, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0,
                                                     'debug': 2}


@pytest.mark.parametrize('error_flag, error_msg', [
    (0, ""),
    (1, "2019/02/27 11:30:07 wazuh-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: "
        "Unspecified key"),
    (1, "2019/02/27 11:30:24 ossec-authd: ERROR: (1230): Invalid element in the configuration: "
        "'use_source_i'.\n2019/02/27 11:30:24 ossec-authd: ERROR: (1202): Configuration error at "
        "'/var/ossec/etc/ossec.conf'.")
])
@patch('wazuh.core.manager.open')
@patch('wazuh.core.manager.fcntl')
@patch("wazuh.core.manager.exists", return_value=True)
@patch("wazuh.core.manager.remove", return_value=True)
def test_validate_ossec_conf(mock_remove, mock_exists, mock_fcntl, mock_open, error_flag, error_msg):
    with patch('socket.socket') as sock:
        # Mock sock response
        json_response = json.dumps({'error': 0, 'message': ""}).encode()
        sock.return_value.recv.return_value = json_response
        result = validate_ossec_conf()

        assert result == {'status': 'OK'}
        assert mock_fcntl.lockf.call_count == 2
        mock_remove.assert_called_with(join(common.ossec_path, 'queue', 'alerts', 'execa'))
        mock_exists.assert_called_with(join(common.ossec_path, 'queue', 'alerts', 'execa'))
        mock_open.assert_called_once_with(join(common.ossec_path, "var", "run", ".api_execq_lock"), 'a+')


@patch('wazuh.core.manager.open')
@patch('wazuh.core.manager.fcntl')
@patch("wazuh.core.manager.exists", return_value=True)
def test_validation_ko(mosck_exists, mock_lockf, mock_open):
    # Remove api_socket raise OSError
    with patch('wazuh.core.manager.remove', side_effect=OSError):
        with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
            validate_ossec_conf()

    with patch('wazuh.core.manager.remove'):
        # Socket creation raise socket.error
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
                validate_ossec_conf()

        with patch('socket.socket.bind'):
            # Socket connection raise socket.error
            with patch('socket.socket.connect', side_effect=socket.error):
                with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
                    validate_ossec_conf()

            # execq_socket_path not exists
            with patch("wazuh.core.manager.exists", return_value=False):
                 with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
                    validate_ossec_conf()

            with patch('socket.socket.connect'):
                # Socket send raise socket.error
                with patch('socket.socket.send', side_effect=socket.error):
                    with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                        validate_ossec_conf()

                with patch('socket.socket.send'):
                    # Socket recv raise socket.error
                    with patch('socket.socket.recv', side_effect=socket.timeout):
                        with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                            validate_ossec_conf()

                    # _parse_execd_output raise KeyError
                    with patch('socket.socket.recv'):
                        with patch('wazuh.core.manager.parse_execd_output', side_effect=KeyError):
                            with pytest.raises(WazuhInternalError, match='.* 1904 .*'):
                                validate_ossec_conf()


@pytest.mark.parametrize('error_flag, error_msg', [
    (0, ""),
    (1, "2019/02/27 11:30:07 wazuh-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: "
        "Unspecified key"),
    (1, "2019/02/27 11:30:24 ossec-authd: ERROR: (1230): Invalid element in the configuration: "
        "'use_source_i'.\n2019/02/27 11:30:24 ossec-authd: ERROR: (1202): Configuration error at "
        "'/var/ossec/etc/ossec.conf'.")
])
def test_parse_execd_output(error_flag, error_msg):
    """Test parse_execd_output function works and returns expected message.

    Parameters
    ----------
    error_flag : int
        Indicate if there is an error found.
    error_msg
        Error message to be sent.
    """
    json_response = json.dumps({'error': error_flag, 'message': error_msg}).encode()
    if not error_flag:
        result = parse_execd_output(json_response)
        assert result['status'] == 'OK'
    else:
        with pytest.raises(WazuhException, match=f'.* 1908 .*'):
            parse_execd_output(json_response)


@patch('wazuh.core.manager.configuration.api_conf', new={'experimental_features': True})
def test_get_api_config():
    """Checks that get_api_config method is returning current api_conf dict."""
    result = get_api_conf()
    assert result == {'experimental_features': True}
