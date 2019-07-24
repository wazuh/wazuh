#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import pytest

from wazuh.utils import *
from unittest.mock import patch, MagicMock
from wazuh import exception
from subprocess import CalledProcessError
from io import StringIO, BytesIO
import os
from xml.etree import ElementTree
from tempfile import TemporaryDirectory, NamedTemporaryFile
from os.path import join, exists

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

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

mock_keys=['rx_bytes', 'rx_packets', 'scan_id', 'scan_time', 'mac', 'agent_id']

mock_not_nested_dict={
       "ram_free": "1669524",
       "board_serial": "BSS-0123456789",
       "cpu_name": "Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz",
       "cpu_cores": "4",
       "ram_total": "2045956",
       "cpu_mhz": "2394.464"
    }

mock_nested_dict={
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


test_xml='''
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
    """Tests previous_moth function works"""

    result = previous_month(month)

    assert isinstance(result, datetime)


@patch('wazuh.utils.check_output', return_value='{"data":"Some data", "message":"Some message", "error":0}')
def test_execute(mock_output):
    """Tests execute function works"""

    result = execute('Command')

    assert isinstance(result, str)


@pytest.mark.parametrize('error_effect, expected_exception', [
    (CalledProcessError(returncode=10000, cmd='Unspected error', output='{"data":"Some data", "message":"Error", '
                                                                        '"error":10000}'), 10000),
    (Exception, 1002),
    (CalledProcessError(returncode=1, cmd='Unspected error', output={}), 1003),
    (CalledProcessError(returncode=1, cmd='Unspected error', output='{"error":10000}'), 1004),
    (CalledProcessError(returncode=1, cmd='Unspected error', output='{"data":"Some data", "message":"Error"}'), 1004)
])
def test_execute_ko(error_effect, expected_exception):
    """Tests execute function for all exceptions cases:

        * Output_json error value different to 0
        * Check_output return Exception
        * Loads function return Exception
        * Data and message not exists into json
        * Error not exists into json
    """

    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        with patch('wazuh.utils.check_output', side_effect=error_effect):
            execute('Command')


@pytest.mark.parametrize('array, limit', [
    (['one', 'two', 'three'], 2),
    (['one', 'two', 'three'], None),
    ([], None),
    ([], 1)
])
@patch('wazuh.utils.common.maximum_database_limit', new=10)
def test_cut_array(array, limit):
    """Tests cut_array function works"""

    result = cut_array(array=array, limit=limit, offset=0)

    assert isinstance(result, list)


@pytest.mark.parametrize('limit, offset, expected_exception', [
    (11, 0, 1405),
    (0, 0, 1406),
    (5, -1, 1400),
    (-1, 0, 1401)
])
@patch('wazuh.utils.common.maximum_database_limit', new=10)
def test_cut_array_ko(limit, offset, expected_exception):
    """Tests cut_array function for all exceptions cases:

        * Limit is greater than maximum_database_limit
        * Limit is equal to 0
        * Offset is less than 0
        * Limit is less than 0
    """

    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        cut_array(array=['one', 'two', 'three'], limit=limit, offset=offset)


def test_sort_array_type():
    """Tests sort_array function works"""

    assert isinstance(sort_array(mock_array, mock_sort_by), list)


@pytest.mark.parametrize('array, sort_by, order, expected_exception', [
    ([{'test':'test'}], None, 'asc', 1404),
    ('{}', None, 'ramdom', 1402),
    (mock_array, ['test'], 'asc', 1403)
])
def test_sort_array_error(array, sort_by, order, expected_exception):
    """Tests sort_array function for all exceptions cases:

        * List with a dictionary and no sort parameter
        * Order type different to 'asc' or 'desc'
        * Sort parameter not allow
    """

    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        sort_array(array, sort_by, order)


@pytest.mark.parametrize('array, sort_by, order, allowed_sort_field, output', [
    ('', None, 'asc', None, ''),
    ([4005, 4006, 4019, 36], None, 'asc', None, [36, 4005, 4006, 4019]),
    ([4005, 4006, 4019, 36], None, 'desc', None, [4019, 4006, 4005, 36]),
    (mock_array, mock_sort_by, 'asc', mock_sort_by, mock_array_order_by_mac),
    (mock_array_class, ['name'], 'desc', ['name'], mock_array_class)
])
def test_sort_array(array, sort_by, order, allowed_sort_field, output):
    """
    Tests sort_array function for different cases:
        * Empty list
        * Sorted list with values
        * Sorted list with order parameter 'desc'
        * Sorted list with dict, sorted by one nester parameter
        * Sorted list with dict, sorted by different parameter
        * Sorted list with class
    """

    assert sort_array(array, sort_by, order, allowed_sort_field) == output


@pytest.mark.parametrize('object, fields', [
    ({'test':'test'}, None),
    ({'test':'test'}, ['test']),
    (['test', 'name'], None),
    (ClassTest("Payne", "coach"), None)
])
def test_get_values(object, fields):
    """Tests get_values function works"""

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
    """Tests search_array function works"""

    result = search_array(array=array, text=text, negation=negation)

    assert isinstance(result, list)
    assert len(result) == length


def test_filemode():
    """Tests filemode function works"""

    result = filemode(40960)

    assert isinstance(result, str)


def test_tail():
    """Tests tail function works"""

    result = tail(os.path.join(test_data_path, 'test_log.log'))

    assert isinstance(result, list)
    assert len(result) == 20


@patch('wazuh.utils.chmod')
def test_chmod_r(mock_chmod):
    """Tests chmod_r function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False)
        tmpdir = TemporaryDirectory(dir=tmpdirname)
        chmod_r(tmpdirname, 0o777)
        mock_chmod.assert_any_call(tmpdirname, 0o777)
        mock_chmod.assert_any_call(path.join(tmpdirname, tmpfile.name), 0o777)


@patch('wazuh.utils.chown')
def test_chown_r(mock_chown):
    """Tests chown_r function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False)
        tmpdir = TemporaryDirectory(dir=tmpdirname)
        chown_r(tmpdirname, 'test_user', 'test_group')
        mock_chown.assert_any_call(tmpdirname, 'test_user', 'test_group')
        mock_chown.assert_any_call(path.join(tmpdirname, tmpfile.name), 'test_user', 'test_group')


@pytest.mark.parametrize('ownership, time, permissions',
    [((1000, 1000), None, None),
     ((1000, 1000), (12345, 12345), None),
     ((1000, 1000), None, 0o660),
     ((1000, 1000), (12345, 12345), 0o660)
     ]
)
@patch('wazuh.utils.chown')
@patch('wazuh.utils.chmod')
@patch('wazuh.utils.utime')
def test_safe_move(mock_utime, mock_chmod, mock_chown, ownership, time, permissions):
    """Tests safe_move function works"""

    with TemporaryDirectory() as tmpdirname:
        tmp_file = NamedTemporaryFile(dir=tmpdirname, delete=False)
        target_file = join(tmpdirname, 'target')
        safe_move(tmp_file.name, target_file, ownership=ownership, time=time, permissions=permissions)
        assert(exists(target_file))
        mock_chown.assert_called_once_with(target_file, *ownership)
        if time is not None:
            mock_utime.assert_called_once_with(target_file, time)
        if permissions is not None:
            mock_chmod.assert_called_once_with(target_file, permissions)


@pytest.mark.parametrize('dir_name, exists', [
    ('/var/test_path', True),
    ('./var/test_path/', False)
])
@patch('wazuh.utils.chmod')
@patch('wazuh.utils.mkdir')
@patch('wazuh.utils.curdir', new='var')
def test_mkdir_with_mode(mock_mkdir, mock_chmod, dir_name, exists):
    """Tests mkdir_with_mode function works"""

    with patch('wazuh.utils.path.exists', return_value=exists):
        mkdir_with_mode(dir_name)
        mock_chmod.assert_any_call(dir_name, 0o770)
        mock_mkdir.assert_any_call(dir_name, 0o770)


@pytest.mark.parametrize('dir_name, exists', [
    ('/var/test_path', True),
    ('/var/test_path/', False)

])
@patch('wazuh.utils.chmod')
@patch('wazuh.utils.mkdir', side_effect=OSError)
def test_mkdir_with_mode_ko(mock_mkdir, mock_chmod, dir_name, exists):
    with patch('wazuh.utils.path.exists', return_value=exists):
        """Tests mkdir_with_mode function errors works"""

        with pytest.raises(OSError):
            assert mkdir_with_mode(dir_name)
            mock_chmod.assert_any_call(dir_name, 0o770)
            mock_mkdir.assert_any_call(dir_name, 0o770)


@patch('wazuh.utils.open')
@patch('wazuh.utils.iter', return_value=['1','2'])
def test_md5(mock_iter, mock_open):
    """Tests md5 function works"""

    with patch('wazuh.utils.hashlib.md5') as md:
        md.return_value.update.side_effect = None
        result = md5('test')

        assert isinstance(result, MagicMock)
        assert isinstance(result.return_value, MagicMock)
        mock_open.assert_called_once_with('test', 'rb')


def test_protected_get_hashing_algorithm_ko():
    """Tests _get_hashing_algorithm function exception works"""

    with pytest.raises(exception.WazuhException, match=".* 1723 .*"):
        get_hash(filename='test_file', hash_algorithm='test')


@patch('wazuh.utils.open')
def test_get_hash(mock_open):
    """Tests get_hash function works"""

    with patch('wazuh.utils.iter', return_value=['1','2']):
        with patch('wazuh.utils.hashlib.new') as md:
            md.return_value.update.side_effect = None
            result = get_hash(filename='test_file')

            assert isinstance(result, MagicMock)
            assert isinstance(result.return_value, MagicMock)
            mock_open.assert_called_once_with('test_file', 'rb')

    with patch('wazuh.utils.iter', return_value=[]):
        result = get_hash(filename='test_file', return_hex=False)

        assert(result, bytes)

        #with patch('wazuh.utils.hashlib.set.__init__', side_effect = Exception):
            #mock.return_value.union.side_effect= Exception
            #result = get_hash(filename='test_file', return_hex=False)

            #assert(result, bytes)


@patch('wazuh.utils.open')
@patch('wazuh.utils.iter', return_value=['1','2'])
def test_get_hash_ko(mock_iter, mock_open):
    """Tests get_hash function error works"""

    with patch('wazuh.utils.hashlib.new') as md:
        md.return_value.update.side_effect = IOError
        result = get_hash(filename='test_file')

        assert result == None
        mock_open.assert_called_once_with('test_file', 'rb')


def test_get_hash_str():
    """Tests get_hash_str function works"""

    result = get_hash_str('test')

    assert isinstance(result, str)
    assert all(ord(char) < 128 for char in result)


def test_get_fields_to_nest():
    """Tests get_fields_to_nest function works"""

    result_nested, result_non_nested = get_fields_to_nest(mock_keys)

    assert isinstance(result_nested, list)
    assert isinstance(result_non_nested, set)
    assert result_nested[0][0] + '_' + list(result_nested[0][1])[0][0] == list(result_nested[0][1])[0][1]


def test_plain_dict_to_nested_dict():
    """Tests plain_dict_to_nested_dict function works"""

    result = plain_dict_to_nested_dict(data=mock_not_nested_dict)

    assert isinstance(result, dict)
    assert result == mock_nested_dict


@patch('wazuh.utils.compile', return_value='Something')
def test_load_wazuh_xml(mock_compile):
    """Tests load_wazuh_xml function works"""

    with patch('wazuh.utils.open') as f:
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
    """ Test WazuhVersion class """
    current_version = WazuhVersion(version1)
    new_version = WazuhVersion(version2)

    assert current_version < new_version
    assert current_version <= new_version
    assert new_version > current_version
    assert new_version >= current_version
    assert current_version != new_version
    assert not(current_version == new_version)

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
    """ Test WazuhVersion class """
    try:
        WazuhVersion(version1)
        WazuhVersion(version2)
    except ValueError:
        return

    raise Exception


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.10.10', 'Wazuh v3.10.10'),
    ('Wazuh v5.1.15', 'Wazuh v5.1.15'),
    ('v3.6.0', 'v3.6.0'),
    ('v3.9.2', 'v3.9.2')
])
def test_same_version(version1, version2):
    """ Test WazuhVersion class """
    current_version = WazuhVersion(version1)
    new_version = WazuhVersion(version2)

    assert current_version == new_version
    assert not(current_version < new_version)
    assert current_version <= new_version
    assert not(new_version > current_version)
    assert new_version >= current_version
    assert not(current_version != new_version)

    assert isinstance(current_version.to_array(), list)
    assert isinstance(new_version.to_array(), list)


def test_WazuhVersion_to_array():
    """Tests WazuhVersion.to_array function works"""

    version = WazuhVersion('Wazuh v3.10.0-alpha4')

    assert isinstance(version.to_array(), list)


def test_WazuhVersion__str__():
    """Tests WazuhVersion.__str__ function works"""

    version = WazuhVersion('Wazuh v3.10.0-alpha4')

    assert isinstance(version.__str__(), str)


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.5.2', 'Wazuh v4.0.0'),
    ('Wazuh v3.10.0-alpha', 'Wazuh v3.10.0'),
    ('Wazuh v3.10.0-alpha4', 'Wazuh v3.10.0-beta4'),
    ('Wazuh v3.10.0-alpha3', 'Wazuh v3.10.0-alpha4'),
])
def test_WazuhVersion__ge__(version1, version2):
    """Tests WazuhVersion.__ge__ function works"""

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
    """Tests get_timeframe_in_seconds function works"""

    result = get_timeframe_in_seconds(time)

    assert isinstance(result, int)


def test_failed_test_get_timeframe_in_seconds():
    """Tests get_timeframe_in_seconds function exceptions works"""

    with pytest.raises(exception.WazuhException, match=".* 1411 .*"):
        get_timeframe_in_seconds('error')


@pytest.mark.parametrize('value', [
    True,
    False
])
@patch('wazuh.utils.Connection')
def test_WazuhDBQuery__init__(mock_conn, value):
    """Tests WazuhDBQuery.__init__ function exceptions works"""

    with patch('wazuh.utils.glob.glob', return_value=value):
        if value:
            WazuhDBQuery(offset=0, limit=1, table='agent', sort=None, search=None, select=None, filters=None,
                         fields={'1':None,'2':None}, default_sort_field=None, default_sort_order='ASC', query=None,
                         db_path='db_path', min_select_fields=1, count=5, get_data=None,
                         date_fields={'lastKeepAlive','dateAdd'},extra_fields={'internal_key'})

            mock_conn.assert_called_once_with('db_path')

        else:
            with pytest.raises(exception.WazuhException, match=".* 1600 .*"):
                WazuhDBQuery(offset=0, limit=1, table='agent', sort=None, search=None, select=None, filters=None,
                             fields={'1': None, '2': None}, default_sort_field=None, default_sort_order='ASC',
                             query=None,
                             db_path='db_path', min_select_fields=1, count=5, get_data=None,
                             date_fields={'lastKeepAlive', 'dateAdd'}, extra_fields={'internal_key'})



@pytest.mark.parametrize('limit, error, expected_exception', [
    (1, False, None),
    (0, True, 1406),
    (100, True, 1405),
])
@patch('wazuh.utils.glob.glob', return_value=True)
@patch('wazuh.utils.Connection')
@patch('wazuh.utils.common.maximum_database_limit', new=10)
def test_protected_add_limit_to_query(mock_conn, mock_glob, limit, error, expected_exception):
    """Tests WazuhDBQuery._add_limit_to_query function works"""

    query = WazuhDBQuery(offset=0, limit=limit, table='agent', sort=None, search=None, select=None, filters=None,
                         fields={'1': None, '2': None}, default_sort_field=None, query=None,
                         db_path='db_path', count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._add_limit_to_query()
    else:
        query._add_limit_to_query()

    mock_conn.assert_called_once_with('db_path')


@patch('wazuh.utils.glob.glob', return_value=True)
@patch('wazuh.utils.Connection')
def test_protected_sort_query(mock_conn, mock_glob):
    """Tests WazuhDBQuery._sort_query function works"""

    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort={'order':'asc'}, search=None, select=None, filters=None,
                         fields={'1': None, '2': None}, default_sort_field=None, query=None,
                         db_path='db_path', count=5, get_data=None)

    assert isinstance(query._sort_query('1'), str)
    mock_conn.assert_called_once_with('db_path')



@pytest.mark.parametrize('sort, error, expected_exception', [
    (None, False, None),
    ({'order':'asc', 'fields':None}, False, None),
    ({'order':'asc', 'fields':['1']}, False, None),
    ({'order':'asc', 'fields':['bad_field']}, True, 1403)
])
@patch('wazuh.utils.glob.glob', return_value=True)
@patch('wazuh.utils.Connection')
def test_protected_add_sort_to_query(mock_conn, mock_glob, sort, error, expected_exception):
    """Tests WazuhDBQuery._add_sort_to_query function works"""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=sort, search=None, select=None, filters=None,
                         fields={'1': None, '2': None}, default_sort_field=None, query=None,
                         db_path='db_path', count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._add_sort_to_query()
    else:
        query._add_sort_to_query()

    mock_conn.assert_called_once_with('db_path')


@patch('wazuh.utils.glob.glob', return_value=True)
@patch('wazuh.utils.Connection')
def test_protected_add_search_to_query(mock_conn, mock_glob):
    """Tests WazuhDBQuery._add_search_to_query function works"""

    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None, search={"negation":True,"value":"1"}, select=None, filters=None,
                         fields={'1': 'one', '2': 'two'}, default_sort_field=None, query=None,
                         db_path='db_path', count=5, get_data=None)

    query._add_search_to_query()
    mock_conn.assert_called_once_with('db_path')


@pytest.mark.parametrize('selecter_fields, error, expected_exception', [
    (None, False, None),
    ({'fields': ['1']}, False, None),
    ({'fields': ['bad_field']}, True, 1724)
])
@patch('wazuh.utils.glob.glob', return_value=True)
@patch('wazuh.utils.Connection')
def test_protected_parse_select_filter(mock_conn, mock_glob, selecter_fields, error, expected_exception):
    """Tests WazuhDBQuery._parse_select_filter"""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None, search=None, select=None, filters=None,
                         fields={'1': None, '2': None}, default_sort_field=None, query=None,
                         db_path='db_path', count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._parse_select_filter(selecter_fields)
    else:
        assert isinstance(query._parse_select_filter(selecter_fields), dict)

    mock_conn.assert_called_once_with('db_path')


@patch('wazuh.utils.glob.glob', return_value=True)
@patch('wazuh.utils.Connection')
@patch('wazuh.utils.WazuhDBQuery._parse_select_filter')
def test_protected_add_select_to_query(mock_parse, mock_conn, mock_glob):
    """Tests WazuhDBQuery._add_select_to_query function works"""

    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort={'order':'asc'}, search=None, select=None, filters=None,
                         fields={'1': None, '2': None}, default_sort_field=None, query=None,
                         db_path='db_path', count=5, get_data=None)

    query._add_select_to_query()
    mock_parse.assert_called_once_with(None)


@pytest.mark.parametrize('q, error, expected_exception', [
    ('os.name=ubuntu;os.version>12e', False, None),
    ('bad_query', True, 1407),
    ('os.bad_field=ubuntu', True, 1408),
    ('os.name=!ubuntu', True, 1409),
])
@patch('wazuh.utils.glob.glob', return_value=True)
@patch('wazuh.utils.Connection')
def test_protected_parse_query(mock_conn, mock_glob, q, error, expected_exception):
    """Tests WazuhDBQuery._parse_query"""
    query = WazuhDBQuery(offset=0, limit=1, table='agent', sort=None, search=None, select=None, filters=None,
                         fields={'os.name': None, 'os.version': None}, default_sort_field=None, query=q,
                         db_path='db_path', count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._parse_query()
    else:
        #with patch('wazuh.utils.Pattern.findall', return_value=[True, 'os.name', '=', 'ubuntu', True, ';']):
        query._parse_query()

    mock_conn.assert_called_once_with('db_path')

    
#def test_failed_import():
    #del modules['wazuh.utils']
    #del modules['subprocess']
    #with patch.dict('sys.modules', {'subprocess.check_output': None}):
        #modules.items()
        #import wazuh.utils