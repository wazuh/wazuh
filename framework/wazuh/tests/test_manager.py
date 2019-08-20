#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import pytest
from unittest.mock import patch, mock_open, MagicMock

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.exception import WazuhException, WazuhError
        from wazuh.manager import upload_file, get_file, restart, validation, status, delete_file, ossec_log
        from wazuh import common
        from wazuh.manager import *
        from wazuh.exception import WazuhException
        
from shutil import Error
from xml.parsers.expat import ExpatError
from datetime import datetime

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


class InitManager:
    def __init__(self):
        """
        Sets up necessary old_environment to test manager functions
        """
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


@pytest.mark.parametrize('process_status', [
    'running',
    'stopped',
    'failed',
    'restarting',
    'starting'
])
@patch('wazuh.cluster.utils.exists')
@patch('wazuh.cluster.utils.glob')
def test_status(manager_glob, manager_exists, test_manager, process_status):
    """
    Tests manager.status() function in two cases:
        * PID files are created and processed are running,
        * No process is running and therefore no PID files have been created
    :param manager_glob: mock of glob.glob function
    :param manager_exists: mock of os.path.exists function
    :param test_manager: pytest fixture
    :param process_status: status to test (valid values: running/stopped/failed/restarting).
    :return:
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


@pytest.mark.parametrize('input_file, output_file, content_type', [
    ('input_rules_file', 'output_rules_file', 'application/xml'),
    ('input_decoders_file', 'output_decoders_file', 'application/xml'),
    ('input_lists_file', 'output_lists_file', 'application/octet-stream')
])
@patch('wazuh.common.ossec_path', new=test_data_path)
@patch('wazuh.manager.common.ossec_path', new=test_data_path)
@patch('wazuh.manager.remove')
@patch('wazuh.manager.upload_xml')
@patch('wazuh.manager.upload_list')
def test_upload_file(list_mock, xml_mock, remove_mock, test_manager, input_file, output_file, content_type):
    """
    Tests uploading a file to the manager
    """
    input_file, output_file = getattr(test_manager, input_file), getattr(test_manager, output_file)

    with open(os.path.join(test_data_path, input_file)) as f:
        xml_file = f.read()
    m = mock_open(read_data=xml_file)
    with patch('builtins.open', m):
        result = upload_file(input_file, output_file, content_type)

    m.assert_any_call(os.path.join(test_data_path, input_file))
    remove_mock.assert_called_once_with(os.path.join(test_data_path, input_file))

    assert result == {"message": "File updated successfully"}


@patch('wazuh.manager.remove')
def test_upload_file_ko(mock_remove, test_manager):
    """Tests upload_file function exceptions works"""

    input_file, output_file = getattr(test_manager, 'input_rules_file'), getattr(test_manager, 'output_rules_file')

    with patch('wazuh.manager.remove'):
        # Overwrite is False and file exists
        with patch('wazuh.manager.exists', return_value=True):
            with pytest.raises(WazuhException, match='.* 1905 .*'):
                upload_file(input_file, output_file, 'application/xml')


        with patch('wazuh.manager.exists', return_value=False):
            # Open function raise IOError
            with patch('wazuh.manager.open', side_effect=IOError) as m:
                with pytest.raises(WazuhException, match='.* 1005 .*'):
                    upload_file(input_file, output_file, 'application/xml')

            # Open function raise Exception
            with patch('wazuh.manager.open', side_effect=Exception):
                with pytest.raises(WazuhException, match='.* 1000 .*'):
                    upload_file(input_file, output_file, 'application/xml')

            m.assert_any_call(os.path.join(common.ossec_path, input_file))

        # File open len == 0
        m = mock_open(read_data='')
        with patch('builtins.open', m):
            with pytest.raises(WazuhException, match='.* 1112 .*'):
                upload_file(input_file, output_file, 'application/xml')

            m.assert_any_call(os.path.join(common.ossec_path, input_file))

        # Content type != application/xml || application/octet-stream
        with open(os.path.join(test_data_path, input_file)) as f:
            xml_file = f.read()
        m = mock_open(read_data=xml_file)
        with patch('builtins.open', m):
            with pytest.raises(WazuhException, match='.* 1016 .*'):
                upload_file(input_file, output_file, 'bad_type')

    # Open function raise OSError
    with patch('wazuh.manager.remove', side_effect=OSError):
        with pytest.raises(WazuhException, match='.* 1903 .*'):
            upload_file(input_file, output_file, 'application/xml')


@patch('time.time', return_value=0)
@patch('random.randint', return_value=0)
@patch('wazuh.manager.chmod')
@patch('wazuh.manager.load_wazuh_xml')
@patch('wazuh.manager.safe_move')
@patch('wazuh.manager.common.ossec_path', new=test_data_path)
def test_upload_xml(mock_safe, mock_load_wazuh, mock_chmod, mock_random, mock_time, test_manager):
    """Tests upload_xml function works"""

    input_file, output_file = getattr(test_manager, 'input_rules_file'), getattr(test_manager, 'output_rules_file')

    with open(os.path.join(test_data_path, input_file)) as f:
        xml_file = f.read()
    m = mock_open(read_data=xml_file)
    with patch('builtins.open', m):
        result = upload_xml(xml_file, output_file)

    assert isinstance(result, str)
    mock_time.assert_called_once_with()
    mock_random.assert_called_once_with(0, 1000)
    m.assert_any_call(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.xml'), 'w')
    mock_chmod.assert_called_once_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.xml'),0o660)
    mock_load_wazuh.assert_called_once_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.xml'))
    mock_safe.assert_called_once_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.xml'),
                                      os.path.join(test_data_path, output_file),
                                      permissions=0o660)


@pytest.mark.parametrize('effect, expected_exception', [
    (IOError, 1005),
    (ExpatError, 1113),
    (Exception, 1000)
])
def test_upload_xml_open_ko(effect, expected_exception, test_manager):
    """Tests upload_xml function works when open function raise an exception"""

    input_file, output_file = getattr(test_manager, 'input_rules_file'), getattr(test_manager, 'output_rules_file')

    with patch('wazuh.manager.open', side_effect=effect):
        with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
            upload_xml(input_file, output_file)


@patch('time.time', return_value=0)
@patch('random.randint', return_value=0)
@patch('wazuh.manager.chmod')
@patch('wazuh.manager.remove')
@patch('wazuh.manager.common.ossec_path', new=test_data_path)
def test_upload_xml_ko(mock_remove, mock_chmod, mock_random, mock_time, test_manager):
    """Tests upload_xml function exception works"""

    input_file, output_file = getattr(test_manager, 'input_rules_file'), getattr(test_manager, 'output_rules_file')

    with open(os.path.join(test_data_path, input_file)) as f:
        xml_file = f.read()
    m = mock_open(read_data=xml_file)
    with patch('builtins.open', m):
        with patch('wazuh.manager.load_wazuh_xml', side_effect=Exception):
            with pytest.raises(WazuhException, match=f'.* 1113 .*'):
                upload_xml(xml_file, output_file)

        with patch('wazuh.manager.load_wazuh_xml'):
            with patch('wazuh.manager.safe_move', side_effect=Error):
                with pytest.raises(WazuhException, match=f'.* 1016 .*'):
                    upload_xml(xml_file, output_file)

            with patch('wazuh.manager.safe_move', side_effect=Exception):
                with pytest.raises(WazuhException, match=f'.* 1000 .*'):
                    upload_xml(xml_file, output_file)

    mock_time.assert_called_with()
    mock_random.assert_called_with(0, 1000)
    mock_chmod.assert_called_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.xml'), 0o660)
    mock_remove.assert_called_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.xml'))


@patch('time.time', return_value=0)
@patch('random.randint', return_value=0)
@patch('wazuh.manager.chmod')
@patch('wazuh.manager.safe_move')
@patch('wazuh.manager.common.ossec_path', new=test_data_path)
def test_upload_list(mock_safe, mock_chmod, mock_random, mock_time, test_manager):
    """Tests upload_list function works"""

    input_file, output_file = getattr(test_manager, 'input_rules_file'), getattr(test_manager, 'output_rules_file')

    m = mock_open(read_data=ossec_log_file)
    with patch('builtins.open', m):
        result = upload_list(ossec_log_file, output_file)

    assert isinstance(result, str)

    mock_time.assert_called_once_with()
    mock_random.assert_called_once_with(0, 1000)
    mock_chmod.assert_called_once_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.txt'), 0o640)
    mock_safe.assert_called_once_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.txt'),
                                      os.path.join(test_data_path, output_file),
                                      permissions=0o660)

@pytest.mark.parametrize('effect, expected_exception', [
    (IOError, 1005),
    (Exception, 1000)
])
def test_upload_list_open_ko(effect, expected_exception, test_manager):
    """Tests upload_list function works when open function raise an exception"""

    input_file, output_file = getattr(test_manager, 'input_rules_file'), getattr(test_manager, 'output_rules_file')

    with patch('wazuh.manager.open', side_effect=effect):
        with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
            upload_list(input_file, output_file)


@patch('time.time', return_value=0)
@patch('random.randint', return_value=0)
@patch('wazuh.manager.chmod')
@patch('wazuh.manager.common.ossec_path', new=test_data_path)
def test_upload_list_ko(mock_chmod, mock_random, mock_time, test_manager):
    """Tests upload_list function exception works"""

    input_file, output_file = getattr(test_manager, 'input_rules_file'), getattr(test_manager, 'output_rules_file')

    m = mock_open(read_data=ossec_log_file)
    with patch('builtins.open', m):
        with patch('wazuh.manager.safe_move', side_effect=Error):
            with pytest.raises(WazuhException, match=f'.* 1016 .*'):
                upload_list(ossec_log_file, output_file)

        with patch('wazuh.manager.safe_move', side_effect=Exception):
            with pytest.raises(WazuhException, match=f'.* 1000 .*'):
                upload_list(ossec_log_file, output_file)

        mock_time.assert_called_with()
        mock_random.assert_called_with(0, 1000)
        mock_chmod.assert_called_with(os.path.join(test_manager.api_tmp_path, 'api_tmp_file_0_0.txt'), 0o640)


@pytest.mark.parametrize('input_file', [
    'input_rules_file',
    'input_decoders_file',
    'input_lists_file'
])
@patch('wazuh.common.ossec_path', test_data_path)
def test_get_file(test_manager, input_file):
    """Tests get_file function works"""

    input_file = getattr(test_manager, input_file)
    with open(os.path.join(test_data_path, input_file)) as f:
        xml_file = f.read()

    with patch('builtins.open', mock_open(read_data=xml_file)):
        result = get_file(input_file)

    assert result == xml_file


def test_get_file_ko():
    """Tests get_file function works"""

    # Bad format CDB list
    with patch('wazuh.manager.validate_cdb_list', return_value=False):
        with patch('wazuh.manager.re.match', return_value=True):
            with pytest.raises(WazuhException, match=f'.* 1800 .*'):
                get_file('input_rules_file', True)

    # Xml syntax error
    with patch('wazuh.manager.validate_cdb_list', return_value=True):
        with patch('wazuh.manager.validate_xml', return_value=False):
            with pytest.raises(WazuhException, match=f'.* 1113 .*'):
                get_file('input_rules_file', True)

    # Open function raise IOError
    with patch('wazuh.manager.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=f'.* 1005 .*'):
            get_file('input_rules_file')


@pytest.mark.parametrize('input_file', [
    'input_rules_file',
    'input_decoders_file',
    'input_lists_file'
])
@patch('wazuh.common.ossec_path', test_data_path)
def test_validate_xml(test_manager, input_file):
    """Tests validate_xml function works"""

    input_file = getattr(test_manager, input_file)
    with open(os.path.join(test_data_path, input_file)) as f:
        xml_file = f.read()

    with patch('builtins.open', mock_open(read_data=xml_file)):
        result = validate_xml(input_file)

        assert result == True


def test_validate_xml_ko():
    """Tests validate_xml function exceptions works"""

    # Open function raise IOError
    with patch('wazuh.manager.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=f'.* 1005 .*'):
            validate_xml('test_path')

    # Open function raise ExpatError
    with patch('wazuh.manager.open', side_effect=ExpatError):
        result = validate_xml('test_path')

        assert result == False


@patch('wazuh.manager.re.match', return_value=True)
def test_validate_cdb_list(mock_match):
    """Tests validate_cdb function works"""

    m = mock_open(read_data=ossec_log_file)
    with patch('builtins.open', m):
        result = validate_cdb_list('path')

    assert result == True


@patch('wazuh.manager.re.match', return_value=False)
def test_validate_cdb_list_ko(mock_match):
    """Tests validate_cdb function exceptions works"""

    # Match error
    m = mock_open(read_data=ossec_log_file)
    with patch('wazuh.manager.open', m):
        result = validate_cdb_list('path')

    assert result ==False

    # Open function raise IOError
    with patch('wazuh.manager.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=f'.* 1005 .*'):
            validate_cdb_list('path')


def test_delete_file(test_manager):
    """Tests delete_file function and all possible scenarios"""

    with patch('wazuh.manager.exists', return_value=True):
        with patch('wazuh.manager.remove'):
            assert(isinstance(delete_file('/test/file'), str))
        with patch('wazuh.manager.remove', side_effect=IOError()):
            with pytest.raises(WazuhException, match='.* 1907 .*'):
                delete_file('/test/file')

    with patch('wazuh.manager.exists', return_value=False):
        with pytest.raises(WazuhException, match='.* 1906 .*'):
            delete_file('/test/file')


@patch('socket.socket')
@patch('wazuh.cluster.utils.execq_lockfile', return_value=os.path.join(test_data_path, "var", "run", ".api_execq_lock"))
@patch("wazuh.cluster.utils.exists", return_value=True)
def test_restart_ok(mock_exist, mock_path, mock_socket):
    """
    Tests restarting a manager
    """
    assert restart() == 'Restart request sent'


@patch('wazuh.cluster.utils.open')
@patch('wazuh.cluster.utils.fcntl.lockf')
@patch('wazuh.cluster.utils.exists', return_value=False)
def test_restart_ko_socket(mock_exist, mock_lockf, mock_open):
    """Tests restarting a manager exceptions"""

    # Socket path not exists
    with pytest.raises(WazuhException, match='.* 1901 .*'):
        restart()

    # Socket error
    with patch("wazuh.cluster.utils.exists", return_value=True):
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhException, match='.* 1902 .*'):
                restart()

        with patch('socket.socket.connect'):
            with patch('socket.socket.send', side_effect=socket.error):
                with pytest.raises(WazuhException, match='.* 1014 .*'):
                    restart()


@pytest.mark.parametrize('error_flag, error_msg', [
    (0, ""),
    (1, "2019/02/27 11:30:07 wazuh-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: "
        "Unspecified key"),
    (1, "2019/02/27 11:30:24 ossec-authd: ERROR: (1230): Invalid element in the configuration: "
        "'use_source_i'.\n2019/02/27 11:30:24 ossec-authd: ERROR: (1202): Configuration error at "
        "'/var/ossec/etc/ossec.conf'.")
])
@patch('wazuh.manager.execq_lockfile', return_value=os.path.join(common.ossec_path, "var", "run", ".api_execq_lock"))
@patch("wazuh.manager.exists", return_value=True)
@patch("wazuh.manager.remove", return_value=True)
def test_validation(mock_remove, mock_exists, mock_path, test_manager, error_flag, error_msg):
    """
    Tests configuration validation function with multiple scenarios:
        * No errors found in configuration
        * Error found in cluster configuration
        * Error found in any other configuration
    """
    with patch('socket.socket') as sock:
        try:
            json_response = json.dumps({'error': error_flag, 'message': error_msg}).encode()
            sock.return_value.recv.return_value = json_response
            expected_response = {'status': 'OK'}
            response = validation()
            assert error_flag == 0
            assert response, expected_response
        except WazuhError as e:
            assert error_flag == 1


def test_delete_file(test_manager):
    """
    Tests delete_file function and all possible scenarios
    """
    with patch('wazuh.manager.exists', return_value=True):
        with patch('wazuh.manager.remove'):
            assert(isinstance(delete_file('/test/file')['message'], str))
        with patch('wazuh.manager.remove', side_effect=IOError()):
            with pytest.raises(WazuhException, match='.* 1907 .*'):
                delete_file('/test/file')
    with patch('wazuh.manager.exists', return_value=False):
        with pytest.raises(WazuhException, match='.* 1906 .*'):
            delete_file('/test/file')


@patch('wazuh.manager.open')
@patch('wazuh.manager.fcntl.lockf')
@patch("wazuh.manager.exists", return_value=True)
def test_validation_ko(mosck_exists, mock_lockf, mock_open):

    # Remove api_socket raise OSError
    with patch('wazuh.manager.remove', side_effect=OSError):
        with pytest.raises(WazuhException, match='.* 1014 .*'):
            validation()


    with patch('wazuh.manager.remove'):
        # Socket creation raise socket.error
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhException, match='.* 1013 .*'):
                validation()

        with patch('socket.socket.bind'):
            # Socket connection raise socket.error
            with patch('socket.socket.connect', side_effect=socket.error):
                with pytest.raises(WazuhException, match='.* 1013 .*'):
                    validation()

            # execq_socket_path not exists
            with patch("wazuh.manager.exists", return_value=False):
                 with pytest.raises(WazuhException, match='.* 1901 .*'):
                    validation()

            with patch('socket.socket.connect'):
                # Socket send raise socket.error
                with patch('socket.socket.send', side_effect=socket.error):
                    with pytest.raises(WazuhException, match='.* 1014 .*'):
                        validation()

                with patch('socket.socket.send'):
                    # Socket recv raise socket.error
                    with patch('socket.socket.recv', side_effect=socket.timeout):
                        with pytest.raises(WazuhException, match='.* 1014 .*'):
                            validation()

                    # _parse_execd_output raise KeyError
                    with patch('socket.socket.recv'):
                        with patch('wazuh.manager._parse_execd_output', side_effect=KeyError):
                            with pytest.raises(WazuhException, match='.* 1904 .*'):
                                validation()

@patch('wazuh.configuration.get_active_configuration')
def test_get_config(mock_act_conf):
    get_config('component', 'config')

    mock_act_conf.assert_called_once_with(agent_id='000', component='component', configuration='config')


ossec_log_file = """2019/03/26 20:14:37 wazuh-modulesd:database[27799] wm_database.c:501 at wm_get_os_arch(): DEBUG: Detected architecture from Linux |ip-10-0-1-141.us-west-1.compute.internal |3.10.0-957.1.3.el7.x86_64 |#1 SMP Thu Nov 29 14:49:43 UTC 2018 |x86_64: x86_64
2019/02/26 20:14:37 wazuh-modulesd:database[27799] wm_database.c:695 at wm_sync_agentinfo(): DEBUG: wm_sync_agentinfo(4): 0.091 ms.
2019/03/27 10:42:06 wazuh-modulesd:syscollector: INFO: Starting evaluation.
2019/03/27 10:42:07 wazuh-modulesd:rootcheck: INFO: Starting evaluation.
2019/03/26 13:03:11 ossec-csyslogd: INFO: Remote syslog server not configured. Clean exit.
2019/03/26 19:49:15 ossec-execd: ERROR: (1210): Queue '/var/ossec/queue/alerts/execa' not accessible: 'No such file or directory'.
2019/03/26 17:07:32 wazuh-modulesd:aws-s3[13155] wmodules-aws.c:186 at wm_aws_read(): ERROR: Invalid bucket type 'inspector'. Valid ones are 'cloudtrail', 'config', 'custom', 'guardduty' or 'vpcflow'
2019/04/11 12:51:40 wazuh-modulesd:aws-s3: INFO: Executing Bucket Analysis: wazuh-aws-wodle
2019/04/11 12:53:37 wazuh-modulesd:aws-s3: WARNING: Bucket:  -  Returned exit code 7
2019/04/11 12:53:37 wazuh-modulesd:aws-s3: WARNING: Bucket:  -  Unexpected error querying/working with objects in S3: db_maintenance() got an unexpected keyword argument 'aws_account_id'

2019/04/11 12:53:37 wazuh-modulesd:aws-s3: INFO: Executing Bucket Analysis: wazuh-aws-wodle
2019/03/27 10:42:06 wazuh-modulesd:syscollector: INFO: This is a
multiline log
2019/03/26 13:03:11 ossec-csyslogd: INFO: Remote syslog server not configured. Clean exit."""


@pytest.mark.parametrize('category, type_log, totalItems, sort', [
    ('all', 'all', 12, None),
    ('wazuh-modulesd:database', 'all', 1, None),
    ('wazuh-modulesd:syscollector', 'all', 2, None),
    ('wazuh-modulesd:syscollector', 'all', 2, None),
    ('wazuh-modulesd:aws-s3', 'all', 5, None),
    ('ossec-execd', 'all', 1, None),
    ('ossec-csyslogd', 'all', 2, None),
    ('random', 'all', 0, {'order':'asc', 'fields':['timestamp']}),
    ('all', 'info', 7, {'order':'desc', 'fields':['timestamp']}),
    ('all', 'error', 2, {'order':'asc', 'fields':['level']}),
    ('all', 'debug', 1, {'order':'desc', 'fields':['level']}),
    ('all', 'random', 0, {'order':'asc', 'fields':None}),
    ('all', 'warning', 2, {'order':'desc', 'fields':None})
])
@patch("wazuh.manager.previous_month", return_value=datetime.strptime('2019-03-01 00:00:00', '%Y-%m-%d %H:%M:%S'))
def test_ossec_log(mock_month, test_manager, category, type_log, totalItems, sort):
    """
    Tests reading ossec.log file contents
    """
    with patch('wazuh.manager.tail') as tail_patch:
        tail_patch.return_value = ossec_log_file.splitlines()
        logs = ossec_log(category=category, type_log=type_log, sort=sort)
        assert logs['totalItems'] == totalItems
        assert all(log['description'][-1] != '\n' for log in logs['items'])
        if category != 'all' and category != 'wazuh-modulesd:syscollector':
            assert all('\n' not in log['description'] for log in logs['items'])


@patch('socket.socket')
def test_restart_ok(test_manager):
    """
    Tests restarting a manager
    """
    result = restart()
    assert result['message'] == 'Restarting manager'
