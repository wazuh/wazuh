#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import socket
import sys
from unittest.mock import patch, MagicMock, mock_open, ANY
import json

import pytest


with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.manager import *
        from wazuh.core.tests.test_manager import get_logs

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture(scope='module', autouse=True)
def mock_ossec_path():
    with patch('wazuh.core.common.ossec_path', new=test_data_path):
        yield


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


manager_status = {'ossec-agentlessd': 'running', 'ossec-analysisd': 'running', 'ossec-authd': 'running',
 'ossec-csyslogd': 'running', 'ossec-dbd': 'running', 'ossec-monitord': 'running',
 'ossec-execd': 'running', 'ossec-integratord': 'running', 'ossec-logcollector': 'running',
 'ossec-maild': 'running', 'ossec-remoted': 'running', 'ossec-reportd': 'running',
 'ossec-syscheckd': 'running', 'wazuh-clusterd': 'running', 'wazuh-modulesd': 'running',
 'wazuh-db': 'running', 'wazuh-apid': 'running'}


@patch('wazuh.core.manager.status', return_value=manager_status)
def test_get_status(mock_status):
    """Tests get_status() function works"""
    result = get_status()

    # Assert there are no errors and type returned
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


@pytest.mark.parametrize('tag, level, total_items, sort_by, sort_ascending, q', [
    (None, None, 13, None, None, ''),
    (None, None, 4, None, None, 'level=debug,level=error'),
    ('wazuh-modulesd:database', None, 2, None, None, ''),
    ('wazuh-modulesd:syscollector', None, 2, None, None, ''),
    ('wazuh-modulesd:syscollector', None, 2, None, None, ''),
    ('wazuh-modulesd:aws-s3', None, 5, None, None, ''),
    ('ossec-execd', None, 1, None, None, ''),
    ('ossec-csyslogd', None, 2, None, None, ''),
    ('random', None, 0, ['timestamp'], True, ''),
    (None, 'info', 7, ['timestamp'], False, ''),
    (None, 'error', 2, ['level'], True, ''),
    (None, 'debug', 2, ['level'], False, ''),
    (None, None, 13, ['tag'], True, ''),
    (None, 'random', 0, None, True, ''),
    (None, 'warning', 2, None, False, '')
])
def test_ossec_log(tag, level, total_items, sort_by, sort_ascending, q):
    """Test reading ossec.log file contents.

    Parameters
    ----------
    level : str
        Filters by log type: all, error or info.
    tag : str
        Filters by log category (i.e. ossec-remoted).
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

        result = ossec_log(level=level, tag=tag, sort_by=sort_by, sort_ascending=sort_ascending, q=q)

        # Assert type, number of items and presence of trailing characters
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_affected_items'] == total_items
        assert all(log['description'][-1] != '\n' for log in result.render()['data']['affected_items'])
        if tag is not None and level != 'wazuh-modulesd:syscollector':
            assert all('\n' not in log['description'] for log in result.render()['data']['affected_items'])
        if sort_by:
            reversed_result = ossec_log(level=level, tag=tag, sort_by=sort_by, sort_ascending=not sort_ascending, q=q)
            for i in range(total_items):
                assert result.render()['data']['affected_items'][i][sort_by[0]] == \
                       reversed_result.render()['data']['affected_items'][total_items - 1 - i][sort_by[0]]


def test_ossec_log_summary():
    """Tests ossec_log_summary function works and returned data match with expected"""
    logs = get_logs().splitlines()
    with patch('wazuh.core.manager.tail', return_value=logs):
        result = ossec_log_summary()

        # Assert data match what was expected and type of the result.
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_affected_items'] == 6
        assert result.render()['data']['affected_items'][0]['ossec-csyslogd']['all'] == 2
        assert result.render()['data']['affected_items'][0]['ossec-csyslogd']['info'] == 2
        assert result.render()['data']['affected_items'][0]['ossec-csyslogd']['error'] == 0
        assert result.render()['data']['affected_items'][0]['ossec-csyslogd']['critical'] == 0
        assert result.render()['data']['affected_items'][0]['ossec-csyslogd']['warning'] == 0
        assert result.render()['data']['affected_items'][0]['ossec-csyslogd']['debug'] == 0


@pytest.mark.parametrize('path, overwrite', [
    ('test.xml', False),
    ('test_rules.xml', True),
    ('etc/lists', False),
])
@patch('wazuh.manager.delete_file')
@patch('wazuh.manager.upload_xml')
@patch('wazuh.manager.upload_list')
def test_upload_file(mock_list, mock_xml, mock_delete, path, overwrite):
    """Tests uploading a file to the manager

    Parameters
    ----------
    path : str
        Path of destination of the new file.
    overwrite : boolean
        True for updating existing files, False otherwise.
    """
    result = upload_file(path, 'test', overwrite=overwrite)

    # Assert data match what was expected, type of the result and correct parameters in delete() method.
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['affected_items'][0] == path, 'Expected item not found'
    if re.match(r'^etc/lists', path):
        mock_list.assert_called_once_with('test', path)
    else:
        mock_xml.assert_called_once_with('test', path)
    if overwrite:
        mock_delete.assert_called_once_with(path=path), 'delete_file method not called with expected parameter'


@patch('wazuh.manager.delete_file')
@patch('wazuh.manager.upload_xml')
@patch('wazuh.manager.upload_list')
def test_upload_file_ko(mock_list, mock_xml, mock_delete):
    """Tests uploading a file to the manager"""
    # Error when file exists and overwrite is not True
    result = upload_file('test_rules.xml', 'test', overwrite=False)
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1905, 'Error code not expected.'

    # Error when content is empty
    result = upload_file('no_exist.xml', '', overwrite=False)
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1112, 'Error code not expected.'


@pytest.mark.parametrize('input_file', [
    'input_rules_file',
    'input_decoders_file',
    'input_lists_file'
])
def test_get_file(test_manager, input_file):
    """Tests get_file function works"""

    input_file = getattr(test_manager, input_file)
    input_path = os.path.join(test_data_path, input_file)
    with open(input_path) as f:
        xml_file = f.read()

    with patch('builtins.open', mock_open(read_data=xml_file)):
        result = get_file(input_path)

    # Assert xml returned
    assert result.render()["contents"] == xml_file


@patch('wazuh.manager.common.ossec_path', new=os.path.join(test_data_path, 'manager'))
def test_get_file_ko():
    """Tests get_file function works"""

    # Bad format CDB list
    with pytest.raises(WazuhError, match=f'.* 1800 .*'):
        get_file(['etc/lists/bad_format_file'], True)

    # Xml syntax error
    with patch('wazuh.manager.validate_cdb_list', return_value=True):
        with pytest.raises(WazuhError, match=f'.* 1113 .*'):
            get_file(['etc/lists/bad_format_file'], True)

    # Path does not exist error
    with pytest.raises(WazuhError, match=f'.* 1906 .*'):
        get_file(['does_not_exist'])

    # Open function raise IOError
    with patch('wazuh.manager.exists', return_value=True):
        with patch('wazuh.manager.open', side_effect=IOError):
            with pytest.raises(WazuhInternalError, match=f'.* 1005 .*'):
                get_file(['etc/lists/bad_format_file'])


def test_delete_file():
    """Tests delete_file function and all possible scenarios"""
    with patch('wazuh.manager.exists', return_value=True):
        # Assert returned type is AffectedItemsWazuhResult when everything is correct
        with patch('wazuh.manager.remove'):
            assert(isinstance(delete_file('/test/file'), AffectedItemsWazuhResult))
        # Assert error code when remove() method returns IOError
        with patch('wazuh.manager.remove', side_effect=IOError()):
            result = delete_file('/test/file')
            assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
            assert result.render()['data']['failed_items'][0]['error']['code'] == 1907, 'Error code not expected.'

    # Assert error code when exists() method returns False
    with patch('wazuh.manager.exists', return_value=False):
        result = delete_file('/test/file')
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1906, 'Error code not expected.'


def test_get_api_config():
    """Checks that get_api_config method is returning current api_conf dict."""
    result = get_api_config().render()

    assert 'node_api_config' in result['data']['affected_items'][0], 'node_api_config key not found in result'
    assert result['data']['affected_items'][0]['node_name'] == 'manager', 'Not expected node name'


@patch('wazuh.core.manager.yaml.dump')
@patch('wazuh.core.manager.open')
def test_update_api_config(mock_open, mock_yaml):
    """Checks that update_api_config method is updating current api_conf dict and returning expected result."""
    old_config = {'experimental_features': True}
    new_config = {'experimental_features': False}

    with patch('wazuh.core.manager.configuration.api_conf', new=old_config):
        result = update_api_config(updated_config=new_config)

        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type.'
        assert result.render()['data']['total_failed_items'] == 0, 'Total_failed_items should be 0.'
        assert old_config != new_config, 'Old configuration should be equal to new configuration.'
        mock_yaml.assert_called_once_with(new_config, ANY)


def test_update_api_config_ko():
    """Checks that update_api_config method is returning expected fail."""
    with patch('wazuh.core.manager.configuration.api_conf'):
        result = update_api_config()

        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type.'
        assert result.render()['data']['total_failed_items'] == 1, 'Total_failed_items should be 1.'


@patch('socket.socket')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('wazuh.core.cluster.utils.open')
@patch("wazuh.core.cluster.utils.exists", return_value=True)
def test_restart_ok(mock_exist, mock_path, mock_fcntl, mock_socket):
    """Tests restarting a manager"""
    result = restart()

    # Assert there are no errors and type of the result.
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


@patch('wazuh.core.cluster.utils.open')
@patch('wazuh.core.cluster.utils.fcntl')
@patch('wazuh.core.cluster.utils.exists', return_value=False)
def test_restart_ko_socket(mock_exist, mock_fcntl, mock_open):
    """Tests restarting a manager exceptions"""

    # Socket path not exists
    with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
        restart()

    # Socket error
    with patch("wazuh.core.cluster.utils.exists", return_value=True):
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhInternalError, match='.* 1902 .*'):
                restart()

        with patch('socket.socket.connect'):
            with patch('socket.socket.send', side_effect=socket.error):
                with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                    restart()


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
def test_validation(mock_remove, mock_exists, mock_fcntl, mock_open, error_flag, error_msg):
    """Test validation() method works as expected

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
    with patch('socket.socket') as sock:
        # Mock sock response
        json_response = json.dumps({'error': error_flag, 'message': error_msg}).encode()
        sock.return_value.recv.return_value = json_response
        result = validation()

        # Assert if error was returned
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['total_failed_items'] == error_flag


@patch('wazuh.core.manager.open')
@patch('wazuh.core.manager.fcntl')
@patch("wazuh.core.manager.exists", return_value=True)
def test_validation_ko(mosck_exists, mock_lockf, mock_open):
    # Remove api_socket raise OSError
    with patch('wazuh.core.manager.remove', side_effect=OSError):
        with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
            validation()

    with patch('wazuh.core.manager.remove'):
        # Socket creation raise socket.error
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
                validation()

        with patch('socket.socket.bind'):
            # Socket connection raise socket.error
            with patch('socket.socket.connect', side_effect=socket.error):
                with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
                    validation()

            # execq_socket_path not exists
            with patch("wazuh.core.manager.exists", return_value=False):
                 with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
                    validation()

            with patch('socket.socket.connect'):
                # Socket send raise socket.error
                with patch('socket.socket.send', side_effect=socket.error):
                    with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                        validation()

                with patch('socket.socket.send'):
                    # Socket recv raise socket.error
                    with patch('socket.socket.recv', side_effect=socket.timeout):
                        with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                            validation()

                    # _parse_execd_output raise KeyError
                    with patch('socket.socket.recv'):
                        with patch('wazuh.core.manager.parse_execd_output', side_effect=KeyError):
                            with pytest.raises(WazuhInternalError, match='.* 1904 .*'):
                                validation()

                    # _parse_execd_output raise WazuhError
                    with patch('socket.socket') as sock:
                        json_response = json.dumps({'error': 1, 'message': 'test_error'}).encode()
                        sock.return_value.recv.return_value = json_response
                        result = validation()
                        assert result.total_failed_items == 1


@patch('wazuh.core.configuration.get_active_configuration')
def test_get_config(mock_act_conf):
    """Tests get_config() method works as expected"""
    get_config('component', 'config')

    # Assert whether get_active_configuration() method receives the expected parameters.
    mock_act_conf.assert_called_once_with(agent_id='000', component='component', configuration='config')


def test_get_config_ko():
    """Tests get_config() function returns an error"""
    result = get_config()

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1307


def test_read_ossec_conf():
    """Tests read_ossec_conf() function works as expected"""
    result = read_ossec_conf()

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0


def test_read_ossec_con_ko():
    """Tests read_ossec_conf() function returns an error"""
    result = read_ossec_conf(section='test')

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1102

@patch('builtins.open')
def test_get_basic_info(mock_open):
    """Tests get_basic_info() function works as expected"""
    result = get_basic_info()

    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['total_failed_items'] == 0
