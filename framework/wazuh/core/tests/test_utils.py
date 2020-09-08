#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
from collections.abc import KeysView
from io import StringIO
from os.path import join, exists
from tempfile import TemporaryDirectory, NamedTemporaryFile
from unittest.mock import patch, MagicMock
from xml.etree import ElementTree

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.core.utils import *
        from wazuh.core import exception

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

# input data for testing q filter
input_array = [{"count": 3,
                "name": "default",
                "mergedSum": "a7d19a28cd5591eade763e852248197b",
                "configSum": "ab73af41699f13fdd81903b5f23d8d00"
                },
               {"count": 0,
                "name": "dmz",
                "mergedSum": "dd77862c4a41ae1b3854d67143f3d3e4",
                "configSum": "ab73af41699f13fdd81903b5f23d8d00"
                },
               {"count": 0,
                "name": "testsagentconf",
                "mergedSum": "2acdb385658097abb9528aa5ec18c490",
                "configSum": "297b4cea942e0b7d2d9c59f9433e3e97"
                },
               {"count": 0,
                "name": "testsagentconf2",
                "mergedSum": "391ae29c1b0355c610f45bf133d5ea55",
                "configSum": "297b4cea942e0b7d2d9c59f9433e3e97"
                }]


# MOCK DATA

class ClassTest(object):
    """__init__() functions as the class constructor"""

    def __init__(self, name=None, job=None):
        self.name = name
        self.job = job

    def to_dict(self):
        return {'name': self.name, 'job': self.job}


mock_array = [{'rx': {'bytes': 4005, 'packets': 30}, 'scan': {'id': 1999992193, 'time': '2019/05/29 07:25:26'},
               'mac': '02:42:ac:14:00:05', 'agent_id': '000'},
              {'rx': {'bytes': 447914, 'packets': 1077}, 'scan': {'id': 396115592, 'time': '2019/05/29 07:26:26'},
               'mac': '02:42:ac:14:00:01', 'agent_id': '003'}]
mock_sort_by = ['mac']
mock_array_order_by_mac = [
    {'rx': {'bytes': 447914, 'packets': 1077}, 'scan': {'id': 396115592, 'time': '2019/05/29 07:26:26'},
     'mac': '02:42:ac:14:00:01', 'agent_id': '003'},
    {'rx': {'bytes': 4005, 'packets': 30}, 'scan': {'id': 1999992193, 'time': '2019/05/29 07:25:26'},
     'mac': '02:42:ac:14:00:05', 'agent_id': '000'}]
mock_array_class = [ClassTest("Payne", "coach")]

mock_keys = ['rx_bytes', 'rx_packets', 'scan_id', 'scan_time', 'mac', 'agent_id']

mock_not_nested_dict = {
    "ram_free": "1669524",
    "board_serial": "BSS-0123456789",
    "cpu_name": "Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz",
    "cpu_cores": "4",
    "ram_total": "2045956",
    "cpu_mhz": "2394.464"
}

mock_nested_dict = {
    "ram": {
        "total": "2045956",
        "free": "1669524"
    },
    "cpu": {
        "cores": "4",
        "mhz": "2394.464",
        "name": "Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz"
    },
    "board_serial": "BSS-0123456789"
}

test_xml = '''
<!-- Local rules -->

<!-- Modify it at your will. -->

<!-- Example -->
'''


@pytest.mark.parametrize('month', [
    1,
    2,
    -1
])
def test_previous_moth(month):
    """Test previous_moth function."""
    result = previous_month(month)

    assert isinstance(result, datetime)


@pytest.mark.parametrize('string, substring, n, expected_index', [
    ("string_1_", "_", 1, 6),
    ("string_2_", "_", 2, 8),
    ("string_3_", "_", 3, -1),
    ("string4", "_", 1, -1)
])
def test_find_nth(string, substring, n, expected_index):
    """Test find_nth function."""
    result = find_nth(string, substring, n)

    assert result == expected_index


@patch('wazuh.core.utils.check_output', return_value='{"data": "Some data", "message": "Some message", "error":0}')
def test_execute(mock_output):
    """Test execute function."""
    result = execute('Command')

    assert isinstance(result, str)


@pytest.mark.parametrize('error_effect, expected_exception', [
    (CalledProcessError(returncode=1000, cmd='Unexpected error', output='{"data":"Some data", "message":"Error", '
                                                                       '"error":1000}'), 1000),
    (Exception, 1002),
    (CalledProcessError(returncode=1, cmd='Unexpected error', output={}), 1003),
    (CalledProcessError(returncode=1, cmd='Unexpected error', output='{"error":1000}'), 1004),
    (CalledProcessError(returncode=1, cmd='Unexpected error', output='{"data":"Some data", "message":"Error"}'), 1004)
])
def test_execute_ko(error_effect, expected_exception):
    """Test execute function for all exceptions.
    Cases:

        * Output_json error value different to 0
        * Check_output return Exception
        * Loads function return Exception
        * Data and message not exists into json
        * Error not exists into json
    """
    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        with patch('wazuh.core.utils.check_output', side_effect=error_effect):
            execute('Command')


@pytest.mark.parametrize('array, limit', [
    (['one', 'two', 'three'], 2),
    (['one', 'two', 'three'], None),
    ([], None),
    ([], 1)
])
@patch('wazuh.core.utils.common.maximum_database_limit', new=10)
def test_cut_array(array, limit):
    """Test cut_array function."""
    result = cut_array(array=array, limit=limit, offset=0)

    assert isinstance(result, list)


@pytest.mark.parametrize('array, limit, search_text, sort_by, q', [
    (['one', 'two', 'three'], 3, None, None, ''),
    (['one', 'two', 'three'], 2, 'one', [''], 'contains=one'),
    (['one', 'two', 'three'], 2, 'one', '+', 'two=two')
])
def test_process_array(array, limit, search_text, sort_by, q):
    """Test cut_array function."""
    result = process_array(array=array, limit=limit, offset=0, search_text=search_text, sort_by=sort_by, q=q)
    if search_text:
        array = search_array(array, search_text=search_text)
    if q:
        array = filter_array_by_query(q, array)
    if sort_by == ['']:
        array = sort_array(array)

    assert result == {'items': cut_array(array, offset=0, limit=limit), 'totalItems': len(array)}


@pytest.mark.parametrize('limit, offset, expected_exception', [
    (11, 0, 1405),
    (0, 0, 1406),
    (5, -1, 1400),
    (-1, 0, 1401)
])
@patch('wazuh.core.utils.common.maximum_database_limit', new=10)
def test_cut_array_ko(limit, offset, expected_exception):
    """Test cut_array function for all exceptions.

    Cases:

        * Limit is greater than maximum_database_limit
        * Limit is equal to 0
        * Offset is less than 0
        * Limit is less than 0
    """
    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        cut_array(array=['one', 'two', 'three'], limit=limit, offset=offset)


def test_sort_array_type():
    """Test sort_array function."""
    assert isinstance(sort_array(mock_array, mock_sort_by), list)
    assert isinstance(sort_array(mock_array, None), list)


@pytest.mark.parametrize('array, sort_by, order, expected_exception', [
    ([{'test': 'test'}], None, 'asc', 1402),
    ('{}', None, 'random', 1402),
    (mock_array, ['test'], False, 1403)
])
def test_sort_array_error(array, sort_by, order, expected_exception):
    """Tests sort_array function for all exceptions.

    Cases:

        * List with a dictionary and no sort parameter
        * Order type different to 'asc' or 'desc'
        * Sort parameter not allow
    """
    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        sort_array(array, sort_by, order)


@pytest.mark.parametrize('array, sort_by, order, allowed_sort_field, output', [
    ('', None, True, None, ''),
    ([4005, 4006, 4019, 36], None, True, None, [36, 4005, 4006, 4019]),
    ([4005, 4006, 4019, 36], None, False, None, [4019, 4006, 4005, 36]),
    (mock_array, mock_sort_by, True, mock_sort_by, mock_array_order_by_mac),
    (mock_array_class, ['name'], False, ['name'], mock_array_class)
])
def test_sort_array(array, sort_by, order, allowed_sort_field, output):
    """Test sort_array function.

    Cases:
        * Empty list
        * Sorted list with values
        * Sorted list with order parameter 'desc'
        * Sorted list with dict, sorted by one nester parameter
        * Sorted list with dict, sorted by different parameter
        * Sorted list with class
    """
    assert sort_array(array, sort_by, order, allowed_sort_field) == output


@pytest.mark.parametrize('object, fields', [
    ({'test': 'test'}, None),
    ({'test': 'test'}, ['test']),
    (['test', 'name'], None),
    (ClassTest("Payne", "coach"), None)
])
def test_get_values(object, fields):
    """Test get_values function."""
    result = get_values(o=object, fields=fields)

    assert isinstance(result, list)
    assert isinstance(result[0], str)


@pytest.mark.parametrize('array, text, negation, length', [
    (['test', 'name'], 'e', False, 2),
    (['test', 'name'], 'name', False, 1),
    (['test', 'name'], 'unknown', False, 0),
    (['test', 'name'], 'test', True, 1),
    (['test', 'name'], 'unknown', True, 2)
])
def test_search_array(array, text, negation, length):
    """Test search_array function."""
    result = search_array(array=array, search_text=text, complementary_search=negation)

    assert isinstance(result, list)
    assert len(result) == length


def test_filemode():
    """Test filemode function."""
    result = filemode(40960)

    assert isinstance(result, str)


def test_tail():
    """Test tail function."""
    result = tail(os.path.join(test_data_path, 'test_log.log'))

    assert isinstance(result, list)
    assert len(result) == 20


@patch('wazuh.core.utils.chmod')
def test_chmod_r(mock_chmod):
    """Tests chmod_r function."""
    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False)
        dummy_tmp = TemporaryDirectory(dir=tmpdirname)
        chmod_r(tmpdirname, 0o777)
        mock_chmod.assert_any_call(tmpdirname, 0o777)
        mock_chmod.assert_any_call(path.join(tmpdirname, tmpfile.name), 0o777)


@patch('wazuh.core.utils.chown')
def test_chown_r(mock_chown):
    """Test chown_r function."""
    with TemporaryDirectory() as tmp_dirname:
        tmp_file = NamedTemporaryFile(dir=tmp_dirname, delete=False)
        dummy_tmp = TemporaryDirectory(dir=tmp_dirname)
        chown_r(tmp_dirname, 'test_user', 'test_group')
        mock_chown.assert_any_call(tmp_dirname, 'test_user', 'test_group')
        mock_chown.assert_any_call(path.join(tmp_dirname, tmp_file.name), 'test_user', 'test_group')


@pytest.mark.parametrize('ownership, time, permissions',
                         [((1000, 1000), None, None),
                          ((1000, 1000), (12345, 12345), None),
                          ((1000, 1000), None, 0o660),
                          ((1000, 1000), (12345, 12345), 0o660)]
                         )
@patch('wazuh.core.utils.chown')
@patch('wazuh.core.utils.chmod')
@patch('wazuh.core.utils.utime')
def test_safe_move(mock_utime, mock_chmod, mock_chown, ownership, time, permissions):
    """Test safe_move function."""
    with TemporaryDirectory() as tmpdirname:
        tmp_file = NamedTemporaryFile(dir=tmpdirname, delete=False)
        target_file = join(tmpdirname, 'target')
        safe_move(tmp_file.name, target_file, ownership=ownership, time=time, permissions=permissions)
        assert (exists(target_file))
        mock_chown.assert_called_once_with(target_file, *ownership)
        if time is not None:
            mock_utime.assert_called_once_with(target_file, time)
        if permissions is not None:
            mock_chmod.assert_called_once_with(target_file, permissions)


@patch('wazuh.core.utils.chown')
@patch('wazuh.core.utils.chmod')
@patch('wazuh.core.utils.utime')
def test_safe_move_exception(mock_utime, mock_chmod, mock_chown):
    """Test safe_move function."""
    with TemporaryDirectory() as tmpdirname:
        tmp_file = NamedTemporaryFile(dir=tmpdirname, delete=False)
        target_file = join(tmpdirname, 'target')
        with patch('wazuh.core.utils.rename', side_effect=OSError(1)):
            safe_move(tmp_file.name, target_file, ownership=(1000, 1000), time=(12345, 12345), permissions=0o660)
        assert (exists(target_file))


@pytest.mark.parametrize('dir_name, path_exists', [
    ('/var/test_path', True),
    ('./var/test_path/', False)
])
@patch('wazuh.core.utils.chmod')
@patch('wazuh.core.utils.mkdir')
@patch('wazuh.core.utils.curdir', new='var')
def test_mkdir_with_mode(mock_mkdir, mock_chmod, dir_name, path_exists):
    """Test mkdir_with_mode function."""
    with patch('wazuh.core.utils.path.exists', return_value=path_exists):
        mkdir_with_mode(dir_name)
        mock_chmod.assert_any_call(dir_name, 0o770)
        mock_mkdir.assert_any_call(dir_name, 0o770)


@pytest.mark.parametrize('dir_name, exists', [
    ('/var/test_path', True),
    ('/var/test_path/', False)

])
@patch('wazuh.core.utils.mkdir', side_effect=OSError)
def test_mkdir_with_mode_ko(mock_mkdir, dir_name, exists):
    """Test mkdir_with_mode function errors work."""
    with patch('wazuh.core.utils.path.exists', return_value=exists):
        with pytest.raises(OSError):
            mkdir_with_mode(dir_name)


@patch('wazuh.core.utils.open')
@patch('wazuh.core.utils.iter', return_value=['1', '2'])
def test_md5(mock_iter, mock_open):
    """Test md5 function."""
    with patch('wazuh.core.utils.hashlib.md5') as md:
        md.return_value.update.side_effect = None
        result = md5('test')

        assert isinstance(result, MagicMock)
        assert isinstance(result.return_value, MagicMock)
        mock_open.assert_called_once_with('test', 'rb')


def test_protected_get_hashing_algorithm_ko():
    """Test _get_hashing_algorithm function exception."""
    with pytest.raises(exception.WazuhException, match=".* 1723 .*"):
        get_hash(filename='test_file', hash_algorithm='test')


@patch('wazuh.core.utils.open')
def test_get_hash(mock_open):
    """Test get_hash function."""
    with patch('wazuh.core.utils.iter', return_value=['1', '2']):
        with patch('wazuh.core.utils.hashlib.new') as md:
            md.return_value.update.side_effect = None
            result = get_hash(filename='test_file')

            assert isinstance(result, MagicMock)
            assert isinstance(result.return_value, MagicMock)
            mock_open.assert_called_once_with('test_file', 'rb')

    with patch('wazuh.core.utils.iter', return_value=[]):
        result = get_hash(filename='test_file', return_hex=False)

        assert type(result) == bytes


@patch('wazuh.core.utils.open')
@patch('wazuh.core.utils.iter', return_value=['1', '2'])
def test_get_hash_ko(mock_iter, mock_open):
    """Test get_hash function error work."""
    with patch('wazuh.core.utils.hashlib.new') as md:
        md.return_value.update.side_effect = IOError
        result = get_hash(filename='test_file')

        assert result is None
        mock_open.assert_called_once_with('test_file', 'rb')


def test_get_hash_str():
    """Test get_hash_str function work."""
    result = get_hash_str('test')

    assert isinstance(result, str)
    assert all(ord(char) < 128 for char in result)


def test_get_fields_to_nest():
    """Test get_fields_to_nest function."""
    result_nested, result_non_nested = get_fields_to_nest(mock_keys)

    assert isinstance(result_nested, list)
    assert isinstance(result_non_nested, set)
    assert result_nested[0][0] + '_' + list(result_nested[0][1])[0][0] == list(result_nested[0][1])[0][1]


def test_plain_dict_to_nested_dict():
    """Test plain_dict_to_nested_dict function work."""
    result = plain_dict_to_nested_dict(data=mock_not_nested_dict)

    assert isinstance(result, dict)
    assert result == mock_nested_dict


@patch('wazuh.core.utils.compile', return_value='Something')
def test_load_wazuh_xml(mock_compile):
    """Test load_wazuh_xml function."""
    with patch('wazuh.core.utils.open') as f:
        f.return_value.__enter__.return_value = StringIO(test_xml)
        result = load_wazuh_xml('test_file')

        assert isinstance(result, ElementTree.Element)


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.5.0', 'Wazuh v3.5.2'),
    ('Wazuh v3.6.1', 'Wazuh v3.6.3'),
    ('Wazuh v3.7.2', 'Wazuh v3.8.0'),
    ('Wazuh v3.8.0', 'Wazuh v3.8.1'),
    ('Wazuh v3.9.0', 'Wazuh v3.9.2'),
    ('Wazuh v3.9.10', 'Wazuh v3.9.14'),
    ('Wazuh v3.10.1', 'Wazuh v3.10.10'),
    ('Wazuh v4.10.10', 'Wazuh v4.11.0'),
    ('Wazuh v5.1.15', 'Wazuh v5.2.0'),
    ('v3.6.0', 'v3.6.1'),
    ('v3.9.1', 'v3.9.2'),
    ('v4.0.0', 'v4.0.1'),
    ('3.6.0', '3.6.1'),
    ('3.9.0', '3.9.2'),
    ('4.0.0', '4.0.1')
])
def test_version_ok(version1, version2):
    """Test WazuhVersion class."""
    current_version = WazuhVersion(version1)
    new_version = WazuhVersion(version2)

    assert current_version < new_version
    assert current_version <= new_version
    assert new_version > current_version
    assert new_version >= current_version
    assert current_version != new_version
    assert not (current_version == new_version)

    assert isinstance(current_version.to_array(), list)
    assert isinstance(new_version.to_array(), list)


@pytest.mark.parametrize('version1, version2', [
    ('v3.6.0', 'v.3.6.1'),
    ('Wazuh v4', 'Wazuh v5'),
    ('Wazuh v3.9', 'Wazuh v3.10'),
    ('ABC v3.10.1', 'ABC v3.10.12'),
    ('Wazuhv3.9.0', 'Wazuhv3.9.2'),
    ('3.9', '3.10'),
    ('3.9.0', '3.10'),
    ('3.10', '4.2'),
    ('3', '3.9.1')
])
def test_version_ko(version1, version2):
    """Test WazuhVersion class."""
    try:
        WazuhVersion(version1)
        WazuhVersion(version2)
    except ValueError:
        return


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.10.10', 'Wazuh v3.10.10'),
    ('Wazuh v5.1.15', 'Wazuh v5.1.15'),
    ('v3.6.0', 'v3.6.0'),
    ('v3.9.2', 'v3.9.2')
])
def test_same_version(version1, version2):
    """Test WazuhVersion class."""
    current_version = WazuhVersion(version1)
    new_version = WazuhVersion(version2)

    assert current_version == new_version
    assert not (current_version < new_version)
    assert current_version <= new_version
    assert not (new_version > current_version)
    assert new_version >= current_version
    assert not (current_version != new_version)

    assert isinstance(current_version.to_array(), list)
    assert isinstance(new_version.to_array(), list)


def test_WazuhVersion_to_array():
    """Test WazuhVersion.to_array function."""
    version = WazuhVersion('Wazuh v3.10.0-alpha4')

    assert isinstance(version.to_array(), list)


def test_WazuhVersion__str__():
    """Test WazuhVersion.__str__ function."""
    version = WazuhVersion('Wazuh v3.10.0-alpha4')

    assert isinstance(version.__str__(), str)


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.5.2', 'Wazuh v4.0.0'),
    ('Wazuh v3.10.0-alpha', 'Wazuh v3.10.0'),
    ('Wazuh v3.10.0-alpha4', 'Wazuh v3.10.0-beta4'),
    ('Wazuh v3.10.0-alpha3', 'Wazuh v3.10.0-alpha4'),
])
def test_WazuhVersion__ge__(version1, version2):
    """Test WazuhVersion.__ge__ function."""
    current_version = WazuhVersion(version1)
    new_version = WazuhVersion(version2)

    assert not current_version >= new_version


@pytest.mark.parametrize('time', [
    '10s',
    '20m',
    '30h',
    '5d',
    '10'
])
def test_get_timeframe_in_seconds(time):
    """Test get_timeframe_in_seconds function."""
    result = get_timeframe_in_seconds(time)

    assert isinstance(result, int)


def test_failed_test_get_timeframe_in_seconds():
    """Test get_timeframe_in_seconds function exceptions."""
    with pytest.raises(exception.WazuhException, match=".* 1411 .*"):
        get_timeframe_in_seconds('error')


@pytest.mark.parametrize('value', [
    True,
    False
])
@patch('sqlite3.connect')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery__init__(mock_socket_conn, mock_isfile, mock_sqli_conn, value):
    """Test WazuhDBQuery.__init__."""
    with patch('wazuh.core.utils.glob.glob', return_value=value):
        if value:
            WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None, filters=None,
                         fields={'1': None, '2': None}, default_sort_field=None,
                         default_sort_order='ASC', query=None,
                         backend=SQLiteBackend(common.database_path),
                         min_select_fields=1, count=5, get_data=None,
                         date_fields={'lastKeepAlive', 'dateAdd'},
                         extra_fields={'internal_key'})

            mock_sqli_conn.assert_called_once()

        else:
            with pytest.raises(exception.WazuhException, match=".* 1600 .*"):
                WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                             search=None, select=None, filters=None,
                             fields={'1': None, '2': None},
                             default_sort_field=None, default_sort_order='ASC',
                             query=None, get_data=None,
                             backend=SQLiteBackend(common.database_path),
                             min_select_fields=1, count=5,
                             date_fields={'lastKeepAlive', 'dateAdd'},
                             extra_fields={'internal_key'})


@pytest.mark.parametrize('query_filter, expected_query_filter, expected_wef', [
    ({'operator': 'LIKE', 'value': 'user\'s'}, {'operator': 'LIKE', 'value': 'user_s'}, set()),
    ({'operator': '=', 'value': 'user\'s', 'field': 'description'},
     {'operator': 'LIKE', 'value': 'user_s', 'field': 'description'}, {'description'}),
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.common.maximum_database_limit', new=10)
def test_WazuhDBQuery_protected_clean_filter(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob, query_filter,
                                             expected_query_filter, expected_wef):
    """Test WazuhDBQuery._clean_filter function."""
    query = WazuhDBQuery(offset=0, limit=500, table='agent', sort=None,
                         search=None, select=None, filters=None,
                         fields={'1': None, '2': None},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data=None)

    query._clean_filter(query_filter)
    assert query_filter == expected_query_filter, 'query_filter should have been updated, but it was not'
    assert query.wildcard_equal_fields == expected_wef


@pytest.mark.parametrize('limit, error, expected_exception', [
    (1, False, None),
    (0, True, 1406),
    (100, True, 1405),
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.common.maximum_database_limit', new=10)
def test_WazuhDBQuery_protected_add_limit_to_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob, limit, error,
                                                   expected_exception):
    """Test WazuhDBQuery._add_limit_to_query function."""
    query = WazuhDBQuery(offset=0, limit=limit, table='agent', sort=None,
                         search=None, select=None, filters=None,
                         fields={'1': None, '2': None},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._add_limit_to_query()
    else:
        query._add_limit_to_query()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_sort_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Tests WazuhDBQuery._sort_query function works"""

    query = WazuhDBQuery(offset=0, limit=1, table='agent',
                         sort={'order': 'asc'}, search=None, select=None,
                         filters=None, fields={'1': None, '2': None},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1), count=5,
                         get_data=None)

    assert isinstance(query._sort_query('1'), str)
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('sort, error, expected_exception', [
    (None, False, None),
    ({'order': 'asc', 'fields': None}, False, None),
    ({'order': 'asc', 'fields': ['1']}, False, None),
    ({'order': 'asc', 'fields': ['bad_field']}, True, 1403)
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_add_sort_to_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob, sort,
                                                  error, expected_exception):
    """Test WazuhDBQuery._add_sort_to_query function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=sort,
                         search=None, select=None, filters=None,
                         fields={'1': None, '2': None},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._add_sort_to_query()
    else:
        query._add_sort_to_query()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_add_search_to_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._add_search_to_query function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search={"negation": True, "value": "1"}, select=None,
                         filters=None, fields={'1': 'one', '2': 'two'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data=None)

    query._add_search_to_query()
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('selector_fields, error, expected_exception', [
    (None, False, None),
    (['1'], False, None),
    (['bad_field'], True, 1724)
])
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_parse_select_filter(mock_socket_conn, mock_isfile, mock_glob, mock_conn_db,
                                                    selector_fields, error, expected_exception):
    """Test WazuhDBQuery._parse_select_filter function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None, filters=None,
                         fields={'1': None, '2': None},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._parse_select_filter(selector_fields)
    elif not selector_fields:
        assert isinstance(query._parse_select_filter(selector_fields), KeysView)
    else:
        assert isinstance(query._parse_select_filter(selector_fields), set)

        mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._parse_select_filter')
def test_WazuhDBQuery_protected_add_select_to_query(mock_parse, mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._add_select_to_query function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent',
                         sort={'order': 'asc'}, search=None, select=None,
                         filters=None, fields={'1': None, '2': None},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data=None)

    query._add_select_to_query()
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('q, error, expected_exception', [
    ('os.name=ubuntu;os.version>12e', False, None),
    ('os.name=debian;os.version>12e),(os.name=ubuntu;os.version>12e)', False, None),
    ('bad_query', True, 1407),
    ('os.bad_field=ubuntu', True, 1408),
    ('os.name=!ubuntu', True, 1409)
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_parse_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob, q,
                                            error, expected_exception):
    """Test WazuhDBQuery._parse_query function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None, filters=None,
                         fields={'os.name': None, 'os.version': None},
                         default_sort_field=None, query=q,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._parse_query()
    else:
        # with patch('re.compile.return_value.findall', return_value=[True, 'os.name', '=', 'ubuntu', True, ';']):
        query._parse_query()

    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('filter_', [
    {'os.name': 'ubuntu,windows'},
    {'name': 'value1,value2'}
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_parse_legacy_filters(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob, filter_):
    """Test WazuhDBQuery._parse_legacy_filters function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None, filters=filter_,
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0),
                         count=5, get_data=None)

    query._parse_legacy_filters()

    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('filter, q', [
    ({'os.name': 'ubuntu,windows'}, 'os.name=ubuntu'),
    ({'name': 'value1,value2'}, 'os.version>12e')
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._parse_legacy_filters')
@patch('wazuh.core.utils.WazuhDBQuery._parse_query')
def test_WazuhDBQuery_parse_filters(mock_query, mock_filter, mock_socket_conn, mock_isfile, mock_conn_db, mock_glob,
                                    filter, q):
    """Test WazuhDBQuery._parse_filters function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search={"negation": True, "value": "1"}, select=None,
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=q,
                         backend=WazuhDBBackend(agent_id=0),
                         count=5, get_data=None)

    query._parse_legacy_filters()
    query._parse_query()

    mock_conn_db.assert_called_once_with()
    mock_query.assert_called_once_with()
    mock_filter.assert_called_once_with()


@pytest.mark.parametrize('field_name, field_filter, q_filter', [
    ('status', None, None),
    ('date1', None, {'value': '1', 'operator': None}),
    ('os.name', 'field', {'value': '2019-07-16 09:21:56', 'operator': 'LIKE', 'field': 'status$0'}),
    ('os.name', None, {'value': None, 'operator': 'LIKE', 'field': 'status$0'}),
    ('os.name', 'field', {'value': '2019-07-16 09:21:56', 'operator': 'LIKE', 'field': 'status$0'}),

])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._filter_status')
@patch('wazuh.core.utils.WazuhDBQuery._filter_date')
def test_WazuhDBQuery_protected_process_filter(mock_date, mock_status, mock_socket_conn, mock_isfile, mock_conn_db,
                                               mock_glob, field_name, field_filter, q_filter):
    """Tests WazuhDBQuery._process_filter."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None,
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0), count=5,
                         get_data=None, date_fields=['date1', 'date2'])

    query._process_filter(field_name, field_filter, q_filter)

    mock_conn_db.assert_called_once_with()
    if field_name == 'status':
        mock_status.assert_any_call(q_filter)
    elif field_name in ['date1', 'date2']:
        mock_date.assert_any_call(q_filter, field_name)


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._process_filter')
def test_WazuhDBQuery_protected_add_filters_to_query(mock_process, mock_socket_conn, mock_isfile,
                                                     mock_conn_db, mock_glob):
    """Test WazuhDBQuery._add_filters_to_query function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=['os.name'],
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query='os.name=ubuntu',
                         backend=WazuhDBBackend(agent_id=0), distinct=True,
                         count=5, get_data=None, filters={'os.name': 'ubuntu'},
                         date_fields=['date1', 'date2'])

    query.query_filters = [{'field': 'os.name', 'value': 'ubuntu', 'level': 0, 'separator': ';'}]
    query._add_filters_to_query()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_get_total_items(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._get_total_items function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None,
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0), count=5,
                         get_data=None, date_fields=['date1', 'date2'])

    query._add_select_to_query()
    query._get_total_items()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_get_total_items_mitre(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None,
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0, query_format='mitre'), count=5,
                         get_data=None, date_fields=['date1', 'date2'])

    query._add_select_to_query()
    query._get_total_items()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_substitute_params(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._get_total_items function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select=None,
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0), count=5,
                         get_data=None, date_fields=['date1', 'date2'])
    query.request = {'testing': 'testing'}

    query._add_select_to_query()
    query._get_total_items()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.SQLiteBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_get_data(mock_socket_conn, mock_isfile, mock_sqli_conn, mock_glob):
    """Test SQLiteBackend._get_data function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'fields': set(['os.name'])},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=SQLiteBackend(common.database_path), count=5,
                         get_data=None, min_select_fields=set(['os.version']))

    query.backend._get_data()

    mock_sqli_conn.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_format_data_into_dictionary(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._format_data_into_dictionary."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'fields': set(['os.name'])},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0), count=5,
                         get_data=None, min_select_fields=set(['os.version']))

    query._data = []

    query._format_data_into_dictionary()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_filter_status(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._filter_status function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'fields': set(['os.name'])},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0),
                         count=5, get_data=None,
                         min_select_fields=set(['os.version']))

    with pytest.raises(NotImplementedError):
        query._filter_status('status')

        mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('date_filter, filter_db_name, time, error', [
    ({'value': '7d', 'operator': '<', 'field': 'time'}, 'os.name', 10, False),
    ({'value': '2019-08-13', 'operator': '<', 'field': 'time'}, 'os.name', 10, False),
    ({'value': 'bad_value'}, 'os.name', 10, True)
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_filter_date(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob, date_filter,
                                            filter_db_name, time, error):
    """Test WazuhDBQuery._filter_date function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'fields': set(['os.name'])},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0), count=5,
                         get_data=None)

    query.request = {'time': None}

    with patch('wazuh.core.utils.get_timeframe_in_seconds', return_value=time):
        if error:
            with pytest.raises(exception.WazuhException, match=".* 1412 .*"):
                query._filter_date(date_filter, filter_db_name)
        else:
            query._filter_date(date_filter, filter_db_name)

        mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch("wazuh.core.database.isfile", return_value=True)
@patch('sqlite3.connect')
@patch('wazuh.core.utils.WazuhDBQuery._add_select_to_query')
@patch('wazuh.core.utils.WazuhDBQuery._add_filters_to_query')
@patch('wazuh.core.utils.WazuhDBQuery._add_search_to_query')
@patch('wazuh.core.utils.WazuhDBQuery._get_total_items')
@patch('wazuh.core.utils.WazuhDBQuery._add_sort_to_query')
@patch('wazuh.core.utils.WazuhDBQuery._add_limit_to_query')
@patch('wazuh.core.utils.WazuhDBQuery._format_data_into_dictionary')
@patch('wazuh.core.utils.SQLiteBackend._get_data')
def test_WazuhDBQuery_run(mock_data, mock_dict, mock_limit, mock_sort, mock_items, mock_search, mock_filters,
                          mock_select, mock_sqli_conn, mock_isfile, mock_glob):
    """Test WazuhDBQuery.run function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'os.name'},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None, count=5,
                         backend=SQLiteBackend(common.database_path),
                         get_data=True, min_select_fields={'os.version'})

    query.run()

    mock_sqli_conn.assert_called_once()
    mock_select.assert_called_once_with()
    mock_filters.assert_called_once_with()
    mock_search.assert_called_once_with()
    mock_items.assert_called_once_with()
    mock_sort.assert_called_once_with()
    mock_limit.assert_called_once_with()
    mock_data.assert_called_once_with()
    mock_dict.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._default_query')
def test_WazuhDBQuery_reset(mock_query, mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery.reset function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'os.name'},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=0),
                         count=5, get_data='data')

    query.reset()

    mock_conn_db.assert_called_once_with()
    mock_query.assert_called_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_default_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._default_query function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'fields': set(['os.name'])},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None, count=5,
                         backend=WazuhDBBackend(agent_id=1),
                         get_data='data')

    result = query._default_query()

    assert result == "SELECT {0} FROM " + query.table
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_default_count_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQuery._default_count_query function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'fields': set(['os.name'])},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data='data')

    result = query._default_count_query()

    assert result == "SELECT COUNT(*) FROM ({0})"
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('db_filter', [
    'all',
    'other_filter'
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_pass_filter(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob, db_filter):
    """Test WazuhDBQuery._pass_filter function."""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                         search=None, select={'fields': {'os.name'}},
                         fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                         default_sort_field=None, query=None,
                         backend=WazuhDBBackend(agent_id=1),
                         count=5, get_data='data')

    result = query._pass_filter(db_filter)

    assert isinstance(result, bool)
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQueryDistinct_protected_default_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQueryDistinct._default_query function."""
    query = WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                 query=None, select={'fields': ['name']},
                                 fields={'name': '`group`'}, count=True,
                                 get_data=True, default_sort_field='`group`',
                                 backend=WazuhDBBackend(agent_id=1),
                                 table='agent')

    result = query._default_query()

    assert isinstance(result, str)
    assert "SELECT DISTINCT {0} FROM" in result
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQueryDistinct_protected_default_count_query(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Test WazuhDBQueryDistinct._default_count_query function."""
    query = WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                 query=None, select={'name'},
                                 fields={'name': '`group`'}, count=True,
                                 get_data=True, default_sort_field='`group`',
                                 backend=WazuhDBBackend(agent_id=1),
                                 table='agent')

    result = query._default_count_query()

    assert isinstance(result, str)
    assert "COUNT (DISTINCT" in result
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._add_filters_to_query')
def test_WazuhDBQueryDistinct_protected_add_filters_to_query(mock_add, mock_socket_conn, mock_isfile, mock_conn_db,
                                                             mock_glob):
    """Test WazuhDBQueryDistinct._add_filters_to_query function."""
    query = WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                 query=None, select={'name'},
                                 fields={'name': '`group`'}, count=True,
                                 get_data=True, default_sort_field='`group`',
                                 backend=WazuhDBBackend(agent_id=1),
                                 table='agent')

    query._add_filters_to_query()

    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('select', [
    {'name'},
    {'name', 'ip'}
])
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._add_select_to_query')
def test_WazuhDBQueryDistinct_protected_add_select_to_query(mock_add, mock_socket_conn, mock_isfile, mock_conn_db,
                                                            mock_glob, select):
    """Test WazuhDBQueryDistinct._add_select_to_query function."""
    query = WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                 query=None, select=select,
                                 fields={'name': '`group`'},
                                 count=True, get_data=True,
                                 backend=WazuhDBBackend(agent_id=1),
                                 default_sort_field='`group`', table='agent')

    if len(select) > 1:
        with pytest.raises(exception.WazuhException, match=".* 1410 .*"):
            query._add_select_to_query()
    else:
        query._add_select_to_query()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQueryDistinct_protected_format_data_into_dictionary(mock_socket_conn, mock_isfile, mock_conn_db,
                                                                    mock_glob):
    """Test WazuhDBQueryDistinct._format_data_into_dictionary function."""
    query = WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                 query=None, select={'fields': ['name']},
                                 fields={'name': '`group`'}, count=True,
                                 get_data=True,
                                 backend=WazuhDBBackend(agent_id=1),
                                 default_sort_field='`group`',
                                 table='agent')

    query._data = []

    result = query._format_data_into_dictionary()

    assert isinstance(result, dict)
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQueryGroupBy__init__(mock_socket_conn, mock_isfile, mock_conn_db, mock_glob):
    """Tests WazuhDBQueryGroupBy.__init__ function works"""
    WazuhDBQueryGroupBy(filter_fields=None, offset=0, limit=1, table='agent',
                        sort=None, search=None, select={'fields': ['name']},
                        filters=None, fields={'name': '`group`'},
                        default_sort_field=None, default_sort_order='ASC',
                        query=None, min_select_fields=None, count=True,
                        backend=WazuhDBBackend(agent_id=0), get_data=None,
                        date_fields={'lastKeepAlive', 'dateAdd'},
                        extra_fields={'internal_key'})

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._get_total_items')
def test_WazuhDBQueryGroupBy_protected_get_total_items(mock_total, mock_socket_conn, mock_isfile, mock_conn_db,
                                                       mock_glob):
    """Test WazuhDBQueryGroupBy._get_total_items function."""
    query = WazuhDBQueryGroupBy(filter_fields={'fields': ['name']}, offset=0,
                                limit=1, table='agent', sort=None, search=None,
                                select={'name'}, filters=None,
                                fields={'name': '`group`'}, query=None,
                                default_sort_field=None, get_data=None,
                                default_sort_order='ASC',
                                min_select_fields=None, count=True,
                                backend=WazuhDBBackend(agent_id=0),
                                date_fields={'lastKeepAlive', 'dateAdd'},
                                extra_fields={'internal_key'})

    query._get_total_items()
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch("wazuh.core.database.isfile", return_value=True)
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._add_select_to_query')
@patch('wazuh.core.utils.WazuhDBQuery._parse_select_filter')
def test_WazuhDBQueryGroupBy_protected_add_select_to_query(mock_parse, mock_add, mock_socket_conn, mock_isfile,
                                                           mock_conn_db, mock_glob):
    """Test WazuhDBQueryGroupBy._add_select_to_query function."""
    query = WazuhDBQueryGroupBy(filter_fields={'fields': ['name']}, offset=0,
                                limit=1, table='agent', sort=None, search=None,
                                select={'name'}, filters=None,
                                fields={'name': '`group`'}, query=None,
                                default_sort_field=None,
                                default_sort_order='ASC',
                                min_select_fields=None,
                                count=True, get_data=None,
                                backend=WazuhDBBackend(agent_id=0),
                                date_fields={'lastKeepAlive', 'dateAdd'},
                                extra_fields={'internal_key'})

    query._add_select_to_query()
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('q, return_length', [
    ('name=firewall', 0),
    ('count=1', 0),
    ('name~a', 3),
    ('count<0', 0),
    ('count>3', 0),
    ('count=3;name~test', 0),
    ('count!=0;count!=3', 0),
    ('wrong_param=default', 0),
    ('wrong_param!=default', 0),
    ('wrong_param2~test', 0),
    ('name~test;mergedSum~2acdb', 1),
    ('name=dmz', 1),
    ('name~def', 1),
    ('count=3', 1),
    ('count>2', 1),
    ('count>0', 1),
    ('count!=0', 1),
    ('name~test;mergedSum~2acdb,name=dmz', 2),
    ('name=dmz,name=default', 2),
    ('name~test', 2),
    ('count<3;name~test', 2),
    ('name~d', 2),
    ('name!=dmz;name!=default', 2),
    ('count=0;name!=dmz', 2),
    ('count=0', 3),
    ('count<3', 3),
    ('count<1', 3),
    ('count!=3', 3),
    ('count>10,count<3', 3),
    ('configSum~29,count=3', 3),
    ('name~test,count>0', 3),
    ('count<4', 4),
    ('count>0,count<4', 4),
    ('name~def,count=0', 4),
    ('configSum~29,configSum~ab', 4),
    ('nameGfirewall', -1)
])
def test_filter_array_by_query(q, return_length):
    """Test filter by query in an array."""
    if return_length == -1:
        with pytest.raises(exception.WazuhError, match='.* 1407 .*'):
            filter_array_by_query(q='nameGfirewall', input_array=input_array)
        return

    result = filter_array_by_query(q, input_array)
    for item in result:
        # check fields returned in result
        item_keys = set(item.keys())
        assert (len(item_keys) == len(input_array[0]))
        assert (item_keys == set(input_array[0].keys()))

    assert (len(result) == return_length)


@pytest.mark.parametrize('select, required_fields, expected_result', [
    (['single_select', 'nested1.nested12.nested121'], {'required'}, {'required': None,
                                                                   'single_select': None,
                                                                   'nested1': {
                                                                       'nested12': {
                                                                           'nested121': None
                                                                       }
                                                                   }}),
    (['single_select', 'noexists'], None, None),
    (['required.noexists1.noexists2'], None, None)
])
def test_select_array(select, required_fields, expected_result):
    array = [
        {
            'required': None,
            'single_select': None,
            'nested1': {
                'nested12': {
                    'nested121': None
                }
            },
            'nested2': {
                'nested21': None
            }
        },
        {
            'required': None,
            'single_select': None,
            'nested1': {
                'nested12': {
                    'nested121': None
                }
            },
            'whatever': {
                'whatever1': None
            }
        },
    ]

    try:
        result = select_array(array, select=select, required_fields=required_fields)
        for element in result:
            assert element == expected_result
    except WazuhError as e:
        assert e.code == 1724

@patch('wazuh.common.ossec_path', new='/var/ossec')
@patch('wazuh.core.utils.glob.glob')
def test_get_files(mock_glob):
    """Test whether get_files() returns expected paths."""
    mock_glob.return_value = ['/var/ossec/etc/rules/test.yml',
                              '/var/ossec/etc/rules/test.xml',
                              '/var/ossec/etc/decoders/test.cdb',
                              '/var/ossec/etc/lists/test.yml.disabled']
    result = get_files()

    assert 'etc/ossec.conf' in result
    assert all('/var/ossec' not in x for x in result)
