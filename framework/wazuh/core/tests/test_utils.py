#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import os
from collections.abc import KeysView
from io import StringIO
from requests import exceptions
from shutil import copyfile, Error
from tempfile import TemporaryDirectory, NamedTemporaryFile
from unittest.mock import call, MagicMock, Mock, mock_open, patch, ANY
from xml.etree.ElementTree import Element
from wazuh.core.common import OSSEC_TMP_PATH

import pytest
from defusedxml.ElementTree import parse
from freezegun import freeze_time

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh import WazuhException
        from wazuh.core.agent import WazuhDBQueryAgents
        from wazuh.core import utils, exception
        from wazuh.core.common import WAZUH_PATH, AGENT_NAME_LEN_LIMIT
        from wazuh.core.results import WazuhResult

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_files_path = os.path.join(test_data_path, 'utils')
wazuh_cdb_list = "172.16.19.:\n172.16.19.:\n192.168.:"

# input data for testing q filter
input_array = [
    {
        "count": 3,
        "name": "default",
        "mergedSum": "a7d19a28cd5591eade763e852248197b",
        "configSum": "ab73af41699f13fdd81903b5f23d8d00"
    },
    {
        "count": 0,
        "name": "dmz",
        "mergedSum": "dd77862c4a41ae1b3854d67143f3d3e4",
        "configSum": "ab73af41699f13fdd81903b5f23d8d00"
    },
    {
        "count": 0,
        "name": "testsagentconf",
        "mergedSum": "2acdb385658097abb9528aa5ec18c490",
        "configSum": "297b4cea942e0b7d2d9c59f9433e3e97"
    },
    {
        "count": 0,
        "name": "testsagentconf2",
        "mergedSum": "391ae29c1b0355c610f45bf133d5ea55",
        "configSum": "297b4cea942e0b7d2d9c59f9433e3e97"
    },
    {
        "count": 0,
        "name": "test_nested1",
        "mergedSum": {
            "nestedSum1": "value"
        },
        "configSum": "0000000000000000000000000000000"
    },
    {
        "count": 0,
        "name": "test@nested2",
        "mergedSum": {
            "nestedSum1": "value"
        },
        "configSum": {
            "nestedSum1": {
                "nestedSum11": "value"
            },
            "nestedSum2": [
                {
                    "nestedSum21": "value1"
                },
                {
                    "nestedSum21": "value2"
                }

            ]
        }
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
mock_array_missing_key = [
    {
        "description": "GReAT. (2017, April 3). Lazarus Under the Hood. Retrieved April 17, 2019.",
        "id": "intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340",
    },
    {
        "description": "FireEye. (2018, October 03). APT38: Un-usual Suspects. Retrieved November 6, 2018.",
        "id": "intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340",
    },
    {
        "description": None,
        "id": "intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340",
    }]

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
    result = utils.previous_month(month)

    assert isinstance(result, utils.datetime)


@pytest.mark.parametrize('string, substring, n, expected_index', [
    ("string_1_", "_", 1, 6),
    ("string_2_", "_", 2, 8),
    ("string_3_", "_", 3, -1),
    ("string4", "_", 1, -1)
])
def test_find_nth(string, substring, n, expected_index):
    """Test find_nth function."""
    result = utils.find_nth(string, substring, n)

    assert result == expected_index


@pytest.mark.parametrize('array, limit', [
    (['one', 'two', 'three'], 2),
    (['one', 'two', 'three'], None),
    ([], None),
    ([], 1)
])
@patch('wazuh.core.utils.common.MAXIMUM_DATABASE_LIMIT', new=10)
def test_cut_array(array, limit):
    """Test cut_array function."""
    result = utils.cut_array(array=array, limit=limit, offset=0)

    assert isinstance(result, list)


@pytest.mark.parametrize('limit, offset, expected_exception', [
    (11, 0, 1405),
    (0, 0, 1406),
    (5, -1, 1400),
    (-1, 0, 1401)
])
@patch('wazuh.core.utils.common.MAXIMUM_DATABASE_LIMIT', new=10)
def test_cut_array_ko(limit, offset, expected_exception):
    """Test cut_array function for all exceptions.

    Cases:

        * Limit is greater than MAXIMUM_DATABASE_LIMIT
        * Limit is equal to 0
        * Offset is less than 0
        * Limit is less than 0
    """
    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        utils.cut_array(array=['one', 'two', 'three'], limit=limit, offset=offset)


@pytest.mark.parametrize(
    'array, q, filters, limit, search_text, select, sort_by, distinct, expected_items, expected_total_items',
    [
        # Test cases with queries
        ([{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'}],
         'datetime=2017-10-25T14:48:53.732000Z', None, None, None, None, None, False,
         [{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'}], 1),

        ([{'name': 'W', 'datetime': '2017-10-25T14:48:53.732000Z'},
          {'name': 'I', 'datetime': '2018-05-15T12:34:12.544000Z'}],
         '(name=W,name=I)', None, None, None, None, None, False,
         [{'name': 'W', 'datetime': '2017-10-25T14:48:53.732000Z'},
          {'name': 'I', 'datetime': '2018-05-15T12:34:12.544000Z'}], 2),

        ([{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'}],
         'datetime<2017-10-26', None, None, None, None, None, False,
         [{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'}], 1),

        ([{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'}],
         'datetime>2019-10-26,datetime<2017-10-26', None, None, None, None, None, False,
         [{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'}], 1),

        ([{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'}],
         'datetime>2017-10-26;datetime<2018-05-15T12:34:12.644000Z', None, None, None, None, None, False,
         [{'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'}], 1),

        ([{'item': 'value_2', 'datetime': '2017-10-25T14:48:53Z'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12Z'}],
         'datetime>2017-10-26;datetime<2018-05-15T12:34:12.001000Z', None, None, None, None, None, False,
         [{'item': 'value_1', 'datetime': '2018-05-15T12:34:12Z'}], 1),

        ([{'name': 'value_1', 'status': 'disabled'},
          {'name': 'value_2', 'status': 'enabled'},
          {'name': 'value_3', 'status': 'enabled'}],
         'status=enabled;(name=value_1,name=value_3)', None, None, None, None, None, False,
         [{'name': 'value_3', 'status': 'enabled'}], 1),

        # Test cases with filters, limit and search
        ([{'item': 'value_1', 'some': 't'}, {'item': 'value_2', 'some': 'a'}, {'item': 'value_3', 'some': 'b'}],
         None, {'item': 'value_1', 'some': 't'}, 1, None, None, None, False,
         [{'item': 'value_1', 'some': 't'}], 1),

        ([{'item': 'value_1'}, {'item': 'value_1'}, {'item': 'value_3'}],
         None, None, 1, 'e_1', None, None, False,
         [{'item': 'value_1'}], 2),

        ([{'item': 'value_1'}, {'item': 'value_1'}, {'item': 'value_3'}],
         None, None, 2, 'e_1', None, None, False,
         [{'item': 'value_1'}, {'item': 'value_1'}], 2),

        # Test cases with sort
        ([{'item': 'value_2'}, {'item': 'value_1'}, {'item': 'value_3'}],
         None, None, None, None, None, ['item'], False,
         [{'item': 'value_1'}, {'item': 'value_2'}, {'item': 'value_3'}], 3),

        # Test cases with distinct
        ([{'item': 'value_1', 'component': 'framework'},
           {'item': 'value_2', 'component': 'API'},
           {'item': 'value_1', 'component': 'framework'}],
         None, None, None, None, None, None, True,
         [{'item': 'value_1', 'component': 'framework'}, {'item': 'value_2', 'component': 'API'}], 2),
         (['framework', 'API', 'API'],
         None, None, None, None, None, None, True,
         ['framework', 'API'], 2),

        # Complex test cases
        ([{'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z', 'component': 'framework'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z', 'component': 'API'}],
         'datetime~2017', {'item': 'value_1'}, 1, 'frame', None, None, False,
         [{'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z',
           'component': 'framework'}], 1),

        ([{'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z', 'component': 'framework'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z', 'component': 'API'}],
         'datetime~2019', {'item': 'value_1'}, 1, None, None, None, False,
         [], 0),

        ([{'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z', 'component': 'framework'},
          {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z', 'component': 'API'}],
         'datetime~2017', {'item': 'value_1'}, 1, None, ['component', 'item'], None, False,
         [{'item': 'value_1', 'component': 'framework'}], 1),
    ])
def test_process_array(array, q, filters, limit, search_text, sort_by, select, distinct, expected_items,
                       expected_total_items):
    """Test that the process_array function is working properly with simple and complex examples.

    Parameters
    ----------
    array : list
        List of values on which to apply the processing.
    q : str
        Query used to filter the array.
    filters : dict
        Define the required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
    limit : int
        Maximum number of elements to return.
    search_text : str
        String representing the text to search in the array.
    select : list
        List of fields to select.
    sort_by : list
        List of fields to sort by.
    distinct: bool
        Look for distinct values.
    expected_items : list
        List of items expected after having applied the processing.
    expected_total_items : int
        Total items expected after having applied the processing.
    """
    result = utils.process_array(array=array, filters=filters, limit=limit, offset=0, search_text=search_text,
                                 select=select, sort_by=sort_by, q=q, distinct=distinct)

    assert result == {'items': expected_items, 'totalItems': expected_total_items}


@patch('wazuh.core.utils.len', return_value=1)
@patch('wazuh.core.utils.cut_array')
@patch('wazuh.core.utils.select_array', return_value=ANY)
@patch('wazuh.core.utils.filter_array_by_query', return_value=ANY)
@patch('wazuh.core.utils.search_array', return_value=ANY)
@patch('wazuh.core.utils.sort_array', return_value=ANY)
def test_process_array_ops_order(mock_sort_array, mock_search_array, mock_filter_array_by_query, mock_select_array,
                                 mock_cut_array, mock_len):
    """Test that the process_array function calls the sort, search, filter by query, select and cut operations in the
    expected order and with the expected parameters."""
    manager_mock = Mock()
    manager_mock.attach_mock(mock_sort_array, 'mock_sort_array')
    manager_mock.attach_mock(mock_search_array, 'mock_search_array')
    manager_mock.attach_mock(mock_filter_array_by_query, 'mock_filter_array_by_query')
    manager_mock.attach_mock(mock_select_array, 'mock_select_array')
    manager_mock.attach_mock(mock_cut_array, 'mock_cut_array')

    utils.process_array(array=[{'item': 'value_1'}, {'item': 'value_2'}, {'item': 'value_3'}],
                        filters={'item': 'value_1'}, limit=1, offset=0, search_text='e_1', select=['item'],
                        sort_by=['item'], q='item~value')

    # The array in the sort_array function parameter is the initial one after the filters
    # The array parameter of the other functions is ANY
    assert manager_mock.mock_calls == [
        call.mock_sort_array([{'item': 'value_1'}], sort_by=['item'], sort_ascending=True, allowed_sort_fields=None),
        call.mock_search_array(ANY, search_text='e_1', complementary_search=False, search_in_fields=None),
        call.mock_filter_array_by_query('item~value', ANY),
        call.mock_select_array(ANY, select=['item'], required_fields=None, allowed_select_fields=None),
        call.mock_cut_array(ANY, offset=0, limit=1)
    ]


def test_sort_array_type():
    """Test sort_array function."""
    assert isinstance(utils.sort_array(mock_array, mock_sort_by), list)
    assert isinstance(utils.sort_array(mock_array, None), list)


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
        utils.sort_array(array, sort_by, order)


@pytest.mark.parametrize('array, sort_by, order, allowed_sort_field, output', [
    ('', None, True, None, ''),
    ([4005, 4006, 4019, 36], None, True, None, [36, 4005, 4006, 4019]),
    ([4005, 4006, 4019, 36], None, False, None, [4019, 4006, 4005, 36]),
    (mock_array, mock_sort_by, True, mock_sort_by, mock_array_order_by_mac),
    (mock_array_class, ['name'], False, ['name'], mock_array_class),
    (mock_array_missing_key, ['description'], False, ['description'], mock_array_missing_key)
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
    assert utils.sort_array(array, sort_by, order, allowed_sort_field) == output


@pytest.mark.parametrize('object, fields', [
    ({'test': 'test'}, None),
    ({'test': 'test'}, ['test']),
    (['test', 'name'], None),
    (ClassTest("Payne", "coach"), None)
])
def test_get_values(object, fields):
    """Test get_values function."""
    result = utils.get_values(o=object, fields=fields)

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
    result = utils.search_array(array=array, search_text=text, complementary_search=negation)

    assert isinstance(result, list)
    assert len(result) == length


def test_filemode():
    """Test filemode function."""
    result = utils.filemode(40960)

    assert isinstance(result, str)


def test_tail():
    """Test tail function."""
    result = utils.tail(os.path.join(test_data_path, 'test_log.log'))

    assert isinstance(result, list)
    assert len(result) == 20


@patch('wazuh.core.utils.chmod')
def test_chmod_r(mock_chmod):
    """Tests chmod_r function."""
    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False)
        dummy_tmp = TemporaryDirectory(dir=tmpdirname)
        utils.chmod_r(tmpdirname, 0o777)
        mock_chmod.assert_any_call(tmpdirname, 0o777)
        mock_chmod.assert_any_call(os.path.join(tmpdirname, tmpfile.name), 0o777)


@patch('wazuh.core.utils.chown')
def test_chown_r(mock_chown):
    """Test chown_r function."""
    with TemporaryDirectory() as tmp_dirname:
        tmp_file = NamedTemporaryFile(dir=tmp_dirname, delete=False)
        dummy_tmp = TemporaryDirectory(dir=tmp_dirname)
        utils.chown_r(tmp_dirname, 'test_user', 'test_group')
        mock_chown.assert_any_call(tmp_dirname, 'test_user', 'test_group')
        mock_chown.assert_any_call(os.path.join(tmp_dirname, tmp_file.name), 'test_user', 'test_group')


@patch('wazuh.core.utils.common.WAZUH_PATH', new='/test/path')
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.remove')
def test_delete_wazuh_file(mock_remove, mock_exists):
    """Check delete_file calls functions with expected params"""
    assert utils.delete_wazuh_file('/test/path/etc/file')
    mock_remove.assert_called_once_with('/test/path/etc/file')


@patch('wazuh.core.utils.common.WAZUH_PATH', new='/test/path')
def test_delete_wazuh_file_ko():
    """Check delete_file calls functions with expected params"""
    with pytest.raises(utils.WazuhError, match=r'\b1907\b'):
        utils.delete_wazuh_file('/test/different_path/etc/file')

    with pytest.raises(utils.WazuhError, match=r'\b1907\b'):
        utils.delete_wazuh_file('/test/path/file/../../home')

    with patch('wazuh.core.utils.path.exists', return_value=False):
        with pytest.raises(utils.WazuhError, match=r'\b1906\b'):
            utils.delete_wazuh_file('/test/path/etc/file')

    with patch('wazuh.core.utils.path.exists', return_value=True):
        with pytest.raises(utils.WazuhError, match=r'\b1907\b'):
            utils.delete_wazuh_file('/test/path/etc/file')


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
        target_file = os.path.join(tmpdirname, 'target')
        utils.safe_move(tmp_file.name, target_file, ownership=ownership, time=time, permissions=permissions)
        assert (os.path.exists(target_file))

        tmp_path = os.path.join(os.path.dirname(tmp_file.name), ".target.tmp")
        mock_chown.assert_called_once_with(tmp_path, *ownership)
        if time is not None:
            mock_utime.assert_called_once_with(tmp_path, time)
        if permissions is not None:
            mock_chmod.assert_called_once_with(tmp_path, permissions)


@patch('wazuh.core.utils.chown')
@patch('wazuh.core.utils.chmod')
@patch('wazuh.core.utils.utime')
def test_safe_move_exception(mock_utime, mock_chmod, mock_chown):
    """Test safe_move function."""
    with TemporaryDirectory() as tmpdirname:
        tmp_file = NamedTemporaryFile(dir=tmpdirname, delete=False)
        target_file = os.path.join(tmpdirname, 'target')
        with patch('wazuh.core.utils.rename', side_effect=OSError(1)):
            utils.safe_move(tmp_file.name, target_file, ownership=(1000, 1000), time=(12345, 12345), permissions=0o660)
        assert (os.path.exists(target_file))


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
        utils.mkdir_with_mode(dir_name)
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
            utils.mkdir_with_mode(dir_name)


@patch('wazuh.core.utils.open')
@patch('wazuh.core.utils.iter', return_value=['1', '2'])
def test_md5(mock_iter, mock_open):
    """Test md5 function."""
    with patch('wazuh.core.utils.hashlib.md5') as md:
        md.return_value.update.side_effect = None
        result = utils.md5('test')

        assert isinstance(result, MagicMock)
        assert isinstance(result.return_value, MagicMock)
        mock_open.assert_called_once_with('test', 'rb')


@patch('wazuh.core.utils.open')
@patch('wazuh.core.utils.iter', return_value=['1', '2'])
def test_blake2b(mock_iter, mock_open):
    """Test md5 function."""
    with patch('wazuh.core.utils.hashlib.blake2b') as blake2b_mock:
        blake2b_mock.return_value.update.side_effect = None
        result = utils.blake2b('test')

        assert isinstance(result, MagicMock)
        assert isinstance(result.return_value, MagicMock)
        mock_open.assert_called_once_with('test', 'rb')


def test_protected_get_hashing_algorithm_ko():
    """Test _get_hashing_algorithm function exception."""
    with pytest.raises(exception.WazuhException, match=".* 1723 .*"):
        utils.get_hash(filename='test_file', hash_algorithm='test')


@patch('wazuh.core.utils.open')
def test_get_hash(mock_open):
    """Test get_hash function."""
    with patch('wazuh.core.utils.iter', return_value=['1', '2']):
        with patch('wazuh.core.utils.hashlib.new') as md:
            md.return_value.update.side_effect = None
            result = utils.get_hash(filename='test_file')

            assert isinstance(result, MagicMock)
            assert isinstance(result.return_value, MagicMock)
            mock_open.assert_called_once_with('test_file', 'rb')

    with patch('wazuh.core.utils.iter', return_value=[]):
        result = utils.get_hash(filename='test_file', return_hex=False)

        assert type(result) == bytes


@patch('wazuh.core.utils.open')
@patch('wazuh.core.utils.iter', return_value=['1', '2'])
def test_get_hash_ko(mock_iter, mock_open):
    """Test get_hash function error work."""
    with patch('wazuh.core.utils.hashlib.new') as md:
        md.return_value.update.side_effect = IOError
        result = utils.get_hash(filename='test_file')

        assert result is None
        mock_open.assert_called_once_with('test_file', 'rb')


def test_get_hash_str():
    """Test get_hash_str function work."""
    result = utils.get_hash_str('test')

    assert isinstance(result, str)
    assert all(ord(char) < AGENT_NAME_LEN_LIMIT for char in result)


def test_get_fields_to_nest():
    """Test get_fields_to_nest function."""
    result_nested, result_non_nested = utils.get_fields_to_nest(mock_keys)

    assert isinstance(result_nested, list)
    assert isinstance(result_non_nested, set)
    assert result_nested[0][0] + '_' + list(result_nested[0][1])[0][0] == list(result_nested[0][1])[0][1]


def test_plain_dict_to_nested_dict():
    """Test plain_dict_to_nested_dict function work."""
    result = utils.plain_dict_to_nested_dict(data=mock_not_nested_dict)

    assert isinstance(result, dict)
    assert result == mock_nested_dict


@pytest.mark.parametrize('data, allow_config, exceptions, should_raise', [
    ("<localfile><command>rm -rf /</command></localfile>",
     {'localfile': {'allow': False, 'exceptions': []},
      'wodle_command': {'allow': True, 'exceptions': []}},
     [], True),

    ("<localfile><command>echo test</command></localfile>",
     {'localfile': {'allow': False, 'exceptions': ['echo test']},
      'wodle_command': {'allow': True, 'exceptions': []}},
     [], False),

    ('<wodle name="command"><command>ls -la</command></wodle>',
     {'localfile': {'allow': True, 'exceptions': []},
      'wodle_command': {'allow': False, 'exceptions': []}},
     [], True),

    ('<wodle name="command"><command>test</command></wodle>',
     {'localfile': {'allow': True, 'exceptions': []},
      'wodle_command': {'allow': False, 'exceptions': ['test']}},
     [], False),

    ("<other><value>test</value></other>",
     {'localfile': {'allow': False, 'exceptions': []},
      'wodle_command': {'allow': False, 'exceptions': []}},
     [], False),
])
def test_check_remote_commands(data, allow_config, exceptions, should_raise):
    """Tests check_remote_commands with different remote command inputs."""
    api_conf = utils.configuration.api_conf
    api_conf['upload_configuration']['remote_commands'].update(allow_config)

    with patch('wazuh.core.utils.configuration.api_conf', new=api_conf):
        if should_raise:
            with pytest.raises(exception.WazuhError, match=r'.* 1124 .*'):
                utils.check_remote_commands(data)
        else:
            utils.check_remote_commands(data)


@patch('wazuh.core.utils.compile', return_value='Something')
def test_basic_load_wazuh_xml(mock_compile):
    """Test basic load_wazuh_xml functionality."""
    with patch('wazuh.core.utils.open') as f:
        f.return_value.__enter__.return_value = StringIO(test_xml)
        result = utils.load_wazuh_xml('test_file')

        assert isinstance(result, Element)


def test_load_wazuh_xml():
    """Test load_wazuh_xml function."""

    def elements_equal(e1, e2):
        if e1.tag != e2.tag: return False
        if e1.text != e2.text: return False
        if e1.attrib != e2.attrib: return False
        if len(e1) != len(e2): return False
        return all(elements_equal(c1, c2) for c1, c2 in zip(e1, e2))

    for rule_file in os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/test_load_wazuh_xml')):
        path = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/test_load_wazuh_xml'),
                            rule_file)
        original = parse(path).getroot()
        result = utils.load_wazuh_xml(path)

        assert elements_equal(original, result.find('dummy_tag'))

@pytest.mark.parametrize('expected_exception', [
    (1113)
])
def test_load_wazuh_xml_ko(expected_exception):
    """Test load_wazuh_xml fails gracefully when reading an invalid utf-8 character sequence"""
    file_path = os.path.join(test_data_path, 'test_load_wazuh_xml_ko/invalid_utf8.xml')
    with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
        utils.load_wazuh_xml(file_path)

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
    current_version = utils.WazuhVersion(version1)
    new_version = utils.WazuhVersion(version2)

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
        utils.WazuhVersion(version1)
        utils.WazuhVersion(version2)
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
    current_version = utils.WazuhVersion(version1)
    new_version = utils.WazuhVersion(version2)

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
    version = utils.WazuhVersion('Wazuh v3.10.0-alpha4')

    assert isinstance(version.to_array(), list)


def test_WazuhVersion__str__():
    """Test WazuhVersion.__str__ function."""
    version = utils.WazuhVersion('Wazuh v3.10.0-alpha4')

    assert isinstance(version.__str__(), str)


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.5.2', 'Wazuh v4.0.0'),
    ('Wazuh v3.10.0-alpha', 'Wazuh v3.10.0'),
    ('Wazuh v3.10.0-alpha4', 'Wazuh v3.10.0-beta4'),
    ('Wazuh v3.10.0-alpha3', 'Wazuh v3.10.0-alpha4'),
])
def test_WazuhVersion__ge__(version1, version2):
    """Test WazuhVersion.__ge__ function."""
    current_version = utils.WazuhVersion(version1)
    new_version = utils.WazuhVersion(version2)

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
    result = utils.get_timeframe_in_seconds(time)

    assert isinstance(result, int)


def test_failed_test_get_timeframe_in_seconds():
    """Test get_timeframe_in_seconds function exceptions."""
    with pytest.raises(exception.WazuhException, match=".* 1411 .*"):
        utils.get_timeframe_in_seconds('error')


@pytest.mark.parametrize('query_filter, expected_query_filter, expected_wef', [
    ({'operator': 'LIKE', 'value': 'user\'s'}, {'operator': 'LIKE', 'value': 'user_s'}, set()),
    ({'operator': '=', 'value': 'user\'s', 'field': 'description'},
     {'operator': 'LIKE', 'value': 'user_s', 'field': 'description'}, {'description'}),
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.common.MAXIMUM_DATABASE_LIMIT', new=10)
def test_WazuhDBQuery_protected_clean_filter(mock_socket_conn, mock_conn_db, mock_glob, mock_exists,
                                             query_filter, expected_query_filter, expected_wef):
    """Test WazuhDBQuery._clean_filter function."""
    query = utils.WazuhDBQuery(offset=0, limit=500, table='agent', sort=None,
                               search=None, select=None, filters=None,
                               fields={'1': None, '2': None},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data=None)

    query._clean_filter(query_filter)
    assert query_filter == expected_query_filter, 'query_filter should have been updated, but it was not'
    assert query.wildcard_equal_fields == expected_wef


@pytest.mark.parametrize('limit, error, expected_exception', [
    (1, False, None),
    (0, True, 1406),
    (100, True, 1405),
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.common.MAXIMUM_DATABASE_LIMIT', new=10)
def test_WazuhDBQuery_protected_add_limit_to_query(mock_socket_conn, mock_conn_db, mock_glob, mock_exists,
                                                   limit, error, expected_exception):
    """Test WazuhDBQuery._add_limit_to_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=limit, table='agent', sort=None,
                               search=None, select=None, filters=None,
                               fields={'1': None, '2': None},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._add_limit_to_query()
    else:
        query._add_limit_to_query()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_sort_query(mock_socket_conn, mock_conn_db, mock_glob, mock_exists):
    """Tests WazuhDBQuery._sort_query function works"""

    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent',
                               sort={'order': 'asc'}, search=None, select=None,
                               filters=None, fields={'1': None, '2': None},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1), count=5,
                               get_data=None)

    assert isinstance(query._sort_query('1'), str)
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('sort, expected_exception', [
    (None, None),
    ({'order': 'asc', 'fields': None}, None),
    ({'order': 'asc', 'fields': ['1']}, None),
    ({'order': 'asc', 'fields': ['bad_field']}, 1403),
    ({'order': 'asc', 'fields': ['1', '2', '3', '4']}, None),
    ({'order': 'asc', 'fields': ['internal_key']}, 1403)
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_add_sort_to_query(mock_socket_conn, mock_conn_db, mock_glob, mock_exists,
                                                  sort, expected_exception):
    """Test WazuhDBQuery._add_sort_to_query function."""
    fields = {'1': 'one', '2': 'two', '3': 'three', '4': 'four'}
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=sort,
                               search=None, select=None, filters=None,
                               fields=fields,
                               extra_fields={'internal_key'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data=None)

    if expected_exception:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._add_sort_to_query()
    else:
        query._add_sort_to_query()

    # Check the fields list maintains its original order after adding it to the query
    if not expected_exception and sort:
        sort_string_added = ','.join(f"{fields[field]} {sort['order']}" for field in sort['fields']) if sort['fields'] \
            else f"None {sort['order']}"
        assert query.query.endswith(f"ORDER BY {sort_string_added}")

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_add_search_to_query(mock_socket_conn, mock_conn_db, mock_glob,
                                                    mock_exists):
    """Test WazuhDBQuery._add_search_to_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search={"negation": True, "value": "1"}, select=None,
                               filters=None, fields={'1': 'one', '2': 'two'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data=None)

    query._add_search_to_query()
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('selector_fields, error, expected_exception', [
    (None, False, None),
    (['1'], False, None),
    (['bad_field'], True, 1724)
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_parse_select_filter(mock_socket_conn, mock_glob, mock_conn_db, mock_exists,
                                                    selector_fields, error, expected_exception):
    """Test WazuhDBQuery._parse_select_filter function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None, filters=None,
                               fields={'1': None, '2': None},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data=None)

    if error:
        with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
            query._parse_select_filter(selector_fields)
    elif not selector_fields:
        assert isinstance(query._parse_select_filter(selector_fields), KeysView)
    else:
        assert isinstance(query._parse_select_filter(selector_fields), set)

        mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._parse_select_filter')
def test_WazuhDBQuery_protected_add_select_to_query(mock_parse, mock_socket_conn, mock_conn_db, mock_glob,
                                                    mock_exists):
    """Test WazuhDBQuery._add_select_to_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent',
                               sort={'order': 'asc'}, search=None, select=None,
                               filters=None, fields={'1': None, '2': None},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data=None)

    query._add_select_to_query()
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('q, expected_query_filters', [
    # Simple cases
    ('os.name=ubuntu;os.version>12e',
     [{'value': 'ubuntu', 'operator': '=', 'field': 'os.name$0', 'separator': 'AND', 'level': 0},
      {'value': '12e', 'operator': '>', 'field': 'os.version$0', 'separator': '', 'level': 0}]),
    # Simple cases with brackets in values
    ('name=Mozilla Firefox 53.0 (x64 en-US)',
     [{'value': 'Mozilla Firefox 53.0 (x64 en-US)', 'operator': '=', 'field': 'name$0', 'separator': '', 'level': 0}]),
    ('name=(x64 en-US) Mozilla Firefox 53.0 (x64 en-US)',
     [{'value': '(x64 en-US) Mozilla Firefox 53.0 (x64 en-US)', 'operator': '=', 'field': 'name$0', 'separator': '',
       'level': 0}]),
    ('name=Mozilla Firefox 53.0 ()',
     [{'value': 'Mozilla Firefox 53.0 ()', 'operator': '=', 'field': 'name$0', 'separator': '', 'level': 0}]),
    ('name=Mozilla Firefox 53.0 (x64 en-US)()',
     [{'value': 'Mozilla Firefox 53.0 (x64 en-US)()', 'operator': '=', 'field': 'name$0', 'separator': '',
       'level': 0}]),
    # Simple cases with lists in values
    ('references=["https://example-link@<>=,%?"]',
     [{'value': '["https://example-link@<>=,%?"]', 'operator': '=', 'field': 'references$0', 'separator': '',
       'level': 0}]),
    # Complex cases
    ('(log=test,status=outstanding);cis=5.2 Debian Linux,pci_dss=2',
     [{'value': 'test', 'operator': '=', 'field': 'log$0', 'separator': 'OR', 'level': 1},
      {'value': 'outstanding', 'operator': '=', 'field': 'status$0', 'separator': 'AND', 'level': 0},
      {'value': '5.2 Debian Linux', 'operator': '=', 'field': 'cis$0', 'separator': 'OR', 'level': 0},
      {'value': '2', 'operator': '=', 'field': 'pci_dss$0', 'separator': '', 'level': 0}]),
    # Complex cases with brackets in values
    ('(name=Mozilla Firefox 53.0 (x64 en-US),version!=53.0);architecture=x64',
     [{'value': 'Mozilla Firefox 53.0 (x64 en-US)', 'operator': '=', 'field': 'name$0', 'separator': 'OR', 'level': 1},
      {'value': '53.0', 'operator': '!=', 'field': 'version$0', 'separator': 'AND', 'level': 0},
      {'value': 'x64', 'operator': '=', 'field': 'architecture$0', 'separator': '', 'level': 0}]),
    ('(log!=example,name=Mozilla Firefox 53.0 (x64 en-US) (test));cve_id<1000',
     [{'value': 'example', 'operator': '!=', 'field': 'log$0', 'separator': 'OR', 'level': 1},
      {'value': 'Mozilla Firefox 53.0 (x64 en-US) (test)', 'operator': '=', 'field': 'name$0', 'separator': 'AND',
       'level': 0},
      {'value': '1000', 'operator': '<', 'field': 'cve_id$0', 'separator': '', 'level': 0}]),
    # Complex cases with lists in values
    ('cve_id=CVE-2021-3996;(external_references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3996",'
     '"https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.37/v2.37.3-ReleaseNotes",'
     '"https://ubuntu.com/security/CVE-2021-3996","https://ubuntu.com/security/notices/USN-5279-1",'
     '"https://www.openwall.com/lists/oss-security/2022/01/24/2"],name~Kernel)',
     [{'value': 'CVE-2021-3996', 'operator': '=', 'field': 'cve_id$0', 'separator': 'AND', 'level': 0},
      {'value': '["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3996",'
                '"https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.37/v2.37.3-ReleaseNotes",'
                '"https://ubuntu.com/security/CVE-2021-3996","https://ubuntu.com/security/notices/USN-5279-1",'
                '"https://www.openwall.com/lists/oss-security/2022/01/24/2"]',
       'operator': '=', 'field': 'external_references$0', 'separator': 'OR', 'level': 1},
      {'value': 'Kernel', 'operator': 'LIKE', 'field': 'name$0', 'separator': '', 'level': 0}]),
    # Cases with $
    ('file=/test$/test.txt;(type=file,type=registry_key)',
     [
        {"value": "/test$/test.txt", "operator": "=", "field": "file$0", "separator": "AND", "level": 0},
        {"value": "file", "operator": "=", "field": "type$0", "separator": "OR", "level": 1},
        {"value": "registry_key", "operator": "=", "field": "type$1", "separator": "", "level": 0}
     ]),
    ('file=/$test/test.txt;(type=file,type=registry_key)',
     [
         {"value": "/$test/test.txt", "operator": "=", "field": "file$0", "separator": "AND", "level": 0},
         {"value": "file", "operator": "=", "field": "type$0", "separator": "OR", "level": 1},
         {"value": "registry_key", "operator": "=", "field": "type$1", "separator": "", "level": 0}
     ]),
    ('file=/tes$t/test.txt;(type=file,type=registry_key)',
     [
         {"value": "/tes$t/test.txt", "operator": "=", "field": "file$0", "separator": "AND", "level": 0},
         {"value": "file", "operator": "=", "field": "type$0", "separator": "OR", "level": 1},
         {"value": "registry_key", "operator": "=", "field": "type$1", "separator": "", "level": 0}
     ]),
    # Nested queries
    ('id!=000;(status=active;(group=default2,group=default3))',
     [{'value': '000', 'operator': '!=', 'field': 'id$0', 'separator': 'AND', 'level': 0},
      {'value': 'active', 'operator': '=', 'field': 'status$0', 'separator': 'AND', 'level': 1},
      {'value': 'default2', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 2},
      {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': '', 'level': 0}]),
    ('((group=default2,group=default3);id!=000);status=active',
     [{'value': 'default2', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 2},
      {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': 'AND', 'level': 1},
      {'value': '000', 'operator': '!=', 'field': 'id$0', 'separator': 'AND', 'level': 0},
      {'value': 'active', 'operator': '=', 'field': 'status$0', 'separator': '', 'level': 0}]),
    ('(status=active,(id!=000;(group=default,group=default3)))',
     [{'value': 'active', 'operator': '=', 'field': 'status$0', 'separator': 'OR', 'level': 1},
      {'value': '000', 'operator': '!=', 'field': 'id$0', 'separator': 'AND', 'level': 2},
      {'value': 'default', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 3},
      {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': '', 'level': 0}]),
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
def test_WazuhDBQuery_protected_parse_query_regex(mock_backend_connect, mock_exists, q, expected_query_filters):
    """Test WazuhDBQuery._parse_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None, filters=None,
                               fields={query_filter['field'].replace('$0', ''): None
                                       for query_filter in expected_query_filters},
                               default_sort_field=None, query=q,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data=None)
    query._parse_query()
    query_filters = query.query_filters
    assert query_filters == expected_query_filters, f"The query filters are {query_filters}. " \
                                                    f"Expected: {expected_query_filters}"


@pytest.mark.parametrize('q, error, expected_exception', [
    ('os.name=ubuntu;os.version>12e', False, None),
    ('os.name=debian;os.version>12e),(os.name=ubuntu;os.version>12e)', False, None),
    ('bad_query', True, 1407),
    ('os.bad_field=ubuntu', True, 1408),
    ('os.name=!ubuntu', True, 1409),
    ('internal_key=test', True, 1408)
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_parse_query(mock_socket_conn, mock_conn_db, mock_glob, mock_exists,
                                            q, error, expected_exception):
    """Test WazuhDBQuery._parse_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None, filters=None,
                               fields={'os.name': None, 'os.version': None, 'internal_key': None},
                               extra_fields={'internal_key'},
                               default_sort_field=None, query=q,
                               backend=utils.WazuhDBBackend(agent_id=1),
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
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_parse_legacy_filters(mock_socket_conn, mock_conn_db, mock_glob,
                                                     mock_exists, filter_):
    """Test WazuhDBQuery._parse_legacy_filters function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None, filters=filter_,
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0),
                               count=5, get_data=None)

    query._parse_legacy_filters()

    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('filter, q', [
    ({'os.name': 'ubuntu,windows'}, 'os.name=ubuntu'),
    ({'name': 'value1,value2'}, 'os.version>12e')
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._parse_legacy_filters')
@patch('wazuh.core.utils.WazuhDBQuery._parse_query')
def test_WazuhDBQuery_parse_filters(mock_query, mock_filter, mock_socket_conn, mock_conn_db, mock_glob,
                                    mock_exists, filter, q):
    """Test WazuhDBQuery._parse_filters function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search={"negation": True, "value": "1"}, select=None,
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=q,
                               backend=utils.WazuhDBBackend(agent_id=0),
                               count=5, get_data=None)

    query._parse_legacy_filters()
    query._parse_query()

    mock_conn_db.assert_called_once_with()
    mock_query.assert_called_once_with()
    mock_filter.assert_called_once_with()


@pytest.mark.parametrize('field_name, field_filter, q_filter', [
    ('status', 'field', {'value': 'active', 'operator': 'LIKE', 'field': 'status$0'}),
    ('date1', None, {'value': '1', 'operator': None}),
    ('os.name', 'field', {'value': '2019-07-16 09:21:56', 'operator': 'LIKE', 'field': 'status$0'}),
    ('os.name', None, {'value': None, 'operator': 'LIKE', 'field': 'status$0'}),
    ('os.name', 'field', {'value': '2019-07-16 09:21:56', 'operator': 'LIKE', 'field': 'status$0'})
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._filter_status')
@patch('wazuh.core.utils.WazuhDBQuery._filter_date')
def test_WazuhDBQuery_protected_process_filter(mock_date, mock_status, mock_socket_conn, mock_conn_db,
                                               mock_glob, mock_exists, field_name, field_filter, q_filter):
    """Tests WazuhDBQuery._process_filter."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None,
                               fields={'os.name': 'ubuntu', 'os.version': '18.04', 'status': 'active'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0), count=5,
                               get_data=None, date_fields=['date1', 'date2'])

    query._process_filter(field_name, field_filter, q_filter)

    mock_conn_db.assert_called_once_with()
    if field_name in ['date1', 'date2']:
        mock_date.assert_any_call(q_filter, field_name)


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._process_filter')
def test_WazuhDBQuery_protected_add_filters_to_query(mock_process, mock_socket_conn,
                                                     mock_conn_db, mock_glob, mock_exists):
    """Test WazuhDBQuery._add_filters_to_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=['os.name'],
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query='os.name=ubuntu',
                               backend=utils.WazuhDBBackend(agent_id=0), distinct=True,
                               count=5, get_data=None, filters={'os.name': 'ubuntu'},
                               date_fields=['date1', 'date2'])

    query.query_filters = [{'field': 'os.name', 'value': 'ubuntu', 'level': 0, 'separator': ';'}]
    query._add_filters_to_query()

    mock_conn_db.assert_called_once_with()

@pytest.mark.parametrize('filters, expected_query', [
    (
        [
            {'value': '000', 'operator': '!=', 'field': 'id$0', 'separator': 'AND', 'level': 0},
            {'value': 'active', 'operator': '=', 'field': 'status$0', 'separator': 'AND', 'level': 1},
            {'value': 'default2', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 2},
            {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': '', 'level': 0}
        ],
        'SELECT {0} FROM agent WHERE (id != :id$0 COLLATE NOCASE) AND ((status = :status$0 COLLATE ' + \
        'NOCASE) AND ((group = :group$0 COLLATE NOCASE) OR (group = :group$1 COLLATE NOCASE)))',
    ),
    (
        [
            {'value': 'default2', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 2},
            {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': 'AND', 'level': 1},
            {'value': '000', 'operator': '!=', 'field': 'id$0', 'separator': 'AND', 'level': 0},
            {'value': 'active', 'operator': '=', 'field': 'status$0', 'separator': '', 'level': 0}
        ],
        'SELECT {0} FROM agent WHERE (((group = :group$0 COLLATE NOCASE) OR (group = :group$1 COLLATE ' + \
        'NOCASE)) AND (id != :id$0 COLLATE NOCASE)) AND (status = :status$0 COLLATE NOCASE)',
    ),
    (
        [
            {'value': 'default2', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 3},
            {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': 'OR', 'level': 2},
            {'value': '001', 'operator': '=', 'field': 'id$0', 'separator': 'OR', 'level': 1},
            {'value': '000', 'operator': '!=', 'field': 'id$1', 'separator': 'AND', 'level': 0},
            {'value': 'active', 'operator': '=', 'field': 'status$0', 'separator': '', 'level': 0}
        ],
        'SELECT {0} FROM agent WHERE ((((group = :group$0 COLLATE NOCASE) OR (group = :group$1 COLLATE ' + \
        'NOCASE)) OR (id = :id$0 COLLATE NOCASE)) OR (id != :id$1 COLLATE NOCASE)) AND ' + \
        '(status = :status$0 COLLATE NOCASE)',
    ),
    (
        [
            {'value': 'default2', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 1},
            {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': '', 'level': 0},
        ],
        'SELECT {0} FROM agent WHERE ((group = :group$0 COLLATE NOCASE) OR (group = :group$1 COLLATE NOCASE))',
    ),
    (
        [
            {'value': 'active', 'operator': '=', 'field': 'status$0', 'separator': 'OR', 'level': 1},
            {'value': '000', 'operator': '!=', 'field': 'id$0', 'separator': 'AND', 'level': 2},
            {'value': 'default', 'operator': '=', 'field': 'group$0', 'separator': 'OR', 'level': 3},
            {'value': 'default3', 'operator': '=', 'field': 'group$1', 'separator': '', 'level': 0}
        ],
        'SELECT {0} FROM agent WHERE ((status = :status$0 COLLATE NOCASE) OR ((id != :id$0 COLLATE NOCASE) ' \
        'AND ((group = :group$0 COLLATE NOCASE) OR (group = :group$1 COLLATE NOCASE))))',
    ),
])
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('wazuh.core.utils.path.exists', return_value=True)
def test_WazuhDBQuery_protected_add_filters_to_query_final_query(mock_conn_db, mock_file_exists,
                                                                 filters, expected_query):
    """Test WazuhDBQuery._add_filters_to_query final query."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None, search=None, select=None,
                               fields={'id': 'id', 'status': 'status', 'group': 'group'},
                               default_sort_field=None, query='', backend=utils.WazuhDBBackend(agent_id=0),
                               count=5, get_data=None)

    query.query_filters = filters
    query._add_filters_to_query()

    assert query.query.rstrip(' ') == expected_query


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_get_total_items(mock_socket_conn, mock_conn_db, mock_glob, mock_exists):
    """Test WazuhDBQuery._get_total_items function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None,
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0), count=5,
                               get_data=None, date_fields=['date1', 'date2'])

    query._add_select_to_query()
    query._get_total_items()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_get_total_items_mitre(mock_socket_conn, mock_conn_db, mock_glob,
                                                      mock_exists):
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None,
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0, query_format='mitre'), count=5,
                               get_data=None, date_fields=['date1', 'date2'])

    query._add_select_to_query()
    query._get_total_items()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_substitute_params(mock_socket_conn, mock_conn_db, mock_glob, mock_exists):
    """Test utils.WazuhDBQuery._get_total_items function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select=None,
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0), count=5,
                               get_data=None, date_fields=['date1', 'date2'])
    query.request = {'testing': 'testing'}

    query._add_select_to_query()
    query._get_total_items()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_format_data_into_dictionary(mock_socket_conn, mock_conn_db, mock_glob,
                                                            mock_exists):
    """Test utils.WazuhDBQuery._format_data_into_dictionary."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select={'fields': set(['os.name'])},
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0), count=5,
                               get_data=None, min_select_fields=set(['os.version']))

    query._data = []

    query._format_data_into_dictionary()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_filter_status(mock_socket_conn, mock_conn_db, mock_glob, mock_exists):
    """Test utils.WazuhDBQuery._filter_status function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select={'fields': set(['os.name'])},
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0),
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
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_filter_date(mock_socket_conn, mock_conn_db, mock_glob, mock_exists,
                                            date_filter, filter_db_name, time, error):
    """Test utils.WazuhDBQuery._filter_date function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select={'fields': set(['os.name'])},
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0), count=5,
                               get_data=None)

    query.request = {'time': None}

    with patch('wazuh.core.utils.get_timeframe_in_seconds', return_value=time):
        if error:
            with pytest.raises(exception.WazuhException, match=".* 1412 .*"):
                query._filter_date(date_filter, filter_db_name)
        else:
            query._filter_date(date_filter, filter_db_name)

        mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('execute_value, expected_result', [
    ([{'id': 99}, {'id': 100}], {'items': [{'id': '099'}, {'id': '100'}], 'totalItems': 0}),
    ([{'id': 1}], {'items': [{'id': '001'}], 'totalItems': 0}),
    ([{'id': i} for i in range(30000)], {'items': [{'id': str(i).zfill(3)} for i in range(30000)], 'totalItems': 0})
])
@patch('socket.socket.connect')
def test_WazuhDBQuery_general_run(mock_socket_conn, execute_value, expected_result):
    """Test utils.WazuhDBQuery.general_run function."""
    with patch('wazuh.core.utils.WazuhDBBackend.execute', return_value=execute_value):
        query = WazuhDBQueryAgents(offset=0, limit=None, sort=None, search=None, select={'id'},
                                   query=None, count=False, get_data=True, remove_extra_fields=False)

        assert query.general_run() == expected_result


@pytest.mark.parametrize('execute_value, rbac_ids, negate, final_rbac_ids, expected_result', [
    ([{'id': 99}, {'id': 100}], ['001', '099', '101'], False, [{'id': 99}],
     {'items': [{'id': '099'}], 'totalItems': 1}),
    ([{'id': 1}], [], True, [{'id': 1}], {'items': [{'id': '001'}], 'totalItems': 1}),
    ([{'id': i} for i in range(30000)], [str(i).zfill(3) for i in range(15001)], True,
     [{'id': i} for i in range(15001, 30000)],
     {'items': [{'id': str(i).zfill(3)} for i in range(15001, 30000)], 'totalItems': 14999})
])
@patch('socket.socket.connect')
def test_WazuhDBQuery_oversized_run(mock_socket_conn, execute_value, rbac_ids, negate,
                                    final_rbac_ids, expected_result):
    """Test utils.WazuhDBQuery.oversized_run function."""
    with patch('wazuh.core.utils.WazuhDBBackend.execute', side_effect=[execute_value, final_rbac_ids]):
        query = WazuhDBQueryAgents(offset=0, limit=None, sort=None, search=None, select={'id'},
                                   query=None, count=True, get_data=True, remove_extra_fields=False)
        query.legacy_filters['rbac_ids'] = rbac_ids
        query.rbac_negate = negate

        assert query.oversized_run() == expected_result


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._default_query')
def test_WazuhDBQuery_reset(mock_query, mock_socket_conn, mock_conn_db, mock_glob, mock_exists):
    """Test utils.WazuhDBQuery.reset function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select={'os.name'},
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=0),
                               count=5, get_data='data')

    query.reset()

    mock_conn_db.assert_called_once_with()
    mock_query.assert_called_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_default_query(mock_socket_conn, mock_conn_db, mock_glob, mock_exists):
    """Test utils.WazuhDBQuery._default_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select={'fields': set(['os.name'])},
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None, count=5,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               get_data='data')

    result = query._default_query()

    assert result == "SELECT {0} FROM " + query.table
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_default_count_query(mock_socket_conn, mock_conn_db, mock_glob,
                                                    mock_exists):
    """Test utils.WazuhDBQuery._default_count_query function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select={'fields': set(['os.name'])},
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data='data')

    result = query._default_count_query()

    assert result == "SELECT COUNT(*) FROM ({0})"
    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('value', [
    'all',
    'other_filter'
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQuery_protected_pass_filter(mock_socket_conn, mock_conn_db, mock_glob, mock_exists,
                                            value):
    """Test utils.WazuhDBQuery._pass_filter function."""
    query = utils.WazuhDBQuery(offset=0, limit=1, table='agent', sort=None,
                               search=None, select={'fields': {'os.name'}},
                               fields={'os.name': 'ubuntu', 'os.version': '18.04'},
                               default_sort_field=None, query=None,
                               backend=utils.WazuhDBBackend(agent_id=1),
                               count=5, get_data='data')

    result = query._pass_filter('os.name', value)

    assert isinstance(result, bool)
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQueryDistinct_protected_default_query(mock_socket_conn, mock_conn_db, mock_glob,
                                                      mock_exists):
    """Test utils.WazuhDBQueryDistinct._default_query function."""
    query = utils.WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                       query=None, select={'fields': ['name']},
                                       fields={'name': '`group`'}, count=True,
                                       get_data=True, default_sort_field='`group`',
                                       backend=utils.WazuhDBBackend(agent_id=1),
                                       table='agent')

    result = query._default_query()

    assert isinstance(result, str)
    assert "SELECT DISTINCT {0} FROM" in result
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQueryDistinct_protected_default_count_query(mock_socket_conn, mock_conn_db, mock_glob,
                                                            mock_exists):
    """Test utils.WazuhDBQueryDistinct._default_count_query function."""
    query = utils.WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                       query=None, select={'name'},
                                       fields={'name': '`group`'}, count=True,
                                       get_data=True, default_sort_field='`group`',
                                       backend=utils.WazuhDBBackend(agent_id=1),
                                       table='agent')

    result = query._default_count_query()

    assert isinstance(result, str)
    assert "COUNT (DISTINCT" in result
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._add_filters_to_query')
def test_WazuhDBQueryDistinct_protected_add_filters_to_query(mock_add, mock_socket_conn, mock_conn_db,
                                                             mock_glob, mock_exists):
    """Test utils.WazuhDBQueryDistinct._add_filters_to_query function."""
    query = utils.WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                       query=None, select={'name'},
                                       fields={'name': '`group`'}, count=True,
                                       get_data=True, default_sort_field='`group`',
                                       backend=utils.WazuhDBBackend(agent_id=1),
                                       table='agent')

    query._add_filters_to_query()

    mock_conn_db.assert_called_once_with()


@pytest.mark.parametrize('select', [
    {'name'},
    {'name', 'ip'}
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._add_select_to_query')
def test_WazuhDBQueryDistinct_protected_add_select_to_query(mock_add, mock_socket_conn, mock_conn_db,
                                                            mock_glob, mock_exists, select):
    """Test utils.WazuhDBQueryDistinct._add_select_to_query function."""
    query = utils.WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                       query=None, select=select,
                                       fields={'name': '`group`'},
                                       count=True, get_data=True,
                                       backend=utils.WazuhDBBackend(agent_id=1),
                                       default_sort_field='`group`', table='agent')

    if len(select) > 1:
        with pytest.raises(exception.WazuhException, match=".* 1410 .*"):
            query._add_select_to_query()
    else:
        query._add_select_to_query()

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQueryDistinct_protected_format_data_into_dictionary(mock_socket_conn, mock_conn_db,
                                                                    mock_glob, mock_exists):
    """Test utils.WazuhDBQueryDistinct._format_data_into_dictionary function."""
    query = utils.WazuhDBQueryDistinct(offset=0, limit=1, sort=None, search=None,
                                       query=None, select={'fields': ['name']},
                                       fields={'name': '`group`'}, count=True,
                                       get_data=True,
                                       backend=utils.WazuhDBBackend(agent_id=1),
                                       default_sort_field='`group`',
                                       table='agent')

    query._data = []

    result = query._format_data_into_dictionary()

    assert isinstance(result, dict)
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
def test_WazuhDBQueryGroupBy__init__(mock_socket_conn, mock_conn_db, mock_glob, mock_exists):
    """Tests utils.WazuhDBQueryGroupBy.__init__ function works"""
    utils.WazuhDBQueryGroupBy(filter_fields=None, offset=0, limit=1, table='agent',
                              sort=None, search=None, select={'fields': ['name']},
                              filters=None, fields={'name': '`group`'},
                              default_sort_field=None, default_sort_order='ASC',
                              query=None, min_select_fields=None, count=True,
                              backend=utils.WazuhDBBackend(agent_id=0), get_data=None,
                              date_fields={'lastKeepAlive', 'dateAdd'},
                              extra_fields={'internal_key'})

    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._get_total_items')
def test_WazuhDBQueryGroupBy_protected_get_total_items(mock_total, mock_socket_conn, mock_conn_db,
                                                       mock_glob, mock_exists):
    """Test utils.WazuhDBQueryGroupBy._get_total_items function."""
    query = utils.WazuhDBQueryGroupBy(filter_fields={'fields': ['name']}, offset=0,
                                      limit=1, table='agent', sort=None, search=None,
                                      select={'name'}, filters=None,
                                      fields={'name': '`group`'}, query=None,
                                      default_sort_field=None, get_data=None,
                                      default_sort_order='ASC',
                                      min_select_fields=None, count=True,
                                      backend=utils.WazuhDBBackend(agent_id=0),
                                      date_fields={'lastKeepAlive', 'dateAdd'},
                                      extra_fields={'internal_key'})

    query._get_total_items()
    mock_conn_db.assert_called_once_with()


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.utils.glob.glob', return_value=True)
@patch('wazuh.core.utils.WazuhDBBackend.connect_to_db')
@patch('socket.socket.connect')
@patch('wazuh.core.utils.WazuhDBQuery._add_select_to_query')
@patch('wazuh.core.utils.WazuhDBQuery._parse_select_filter')
def test_WazuhDBQueryGroupBy_protected_add_select_to_query(mock_parse, mock_add, mock_socket_conn,
                                                           mock_conn_db, mock_glob, mock_exists):
    """Test utils.WazuhDBQueryGroupBy._add_select_to_query function."""
    query = utils.WazuhDBQueryGroupBy(filter_fields={'fields': ['name']}, offset=0,
                                      limit=1, table='agent', sort=None, search=None,
                                      select={'name'}, filters=None,
                                      fields={'name': '`group`'}, query=None,
                                      default_sort_field=None,
                                      default_sort_order='ASC',
                                      min_select_fields=None,
                                      count=True, get_data=None,
                                      backend=utils.WazuhDBBackend(agent_id=0),
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
    ('name~test', 4),
    ('count<3;name~test', 4),
    ('name~d', 4),
    ('name!=dmz;name!=default', 4),
    ('count=0;name!=dmz', 4),
    ('count=0', 5),
    ('count<3', 5),
    ('count<1', 5),
    ('count!=3', 5),
    ('count>10,count<3', 5),
    ('configSum~29,count=3', 3),
    ('name~test,count>0', 5),
    ('count<4', 6),
    ('count>0,count<4', 6),
    ('name~def,count=0', 6),
    ('configSum~29,configSum~ab', 4),
    ('nameGfirewall', -1),
    ('mergedSum.nestedSum1=value', 2),
    ('configSum.nestedSum1.nestedSum11=value', 1),
    ('configSum.nestedSum2.nestedSum21=value1', 1),
    ('configSum.nestedSum2.nestedSum21=value2', 1),
    ('name=test@nested2', 1),
])
def test_filter_array_by_query(q, return_length):
    """Test filter by query in an array."""
    if return_length == -1:
        with pytest.raises(exception.WazuhError, match='.* 1407 .*'):
            utils.filter_array_by_query(q='nameGfirewall', input_array=input_array)
        return

    result = utils.filter_array_by_query(q, input_array)
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
    (['single_select', 'noexists'], None, {'single_select': None}),
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
        result = utils.select_array(array, select=select, required_fields=required_fields)
        for element in result:
            assert element == expected_result
    except utils.WazuhError as e:
        assert e.code == 1724


@pytest.mark.parametrize('detail, value, attribs, details', [
    ('new', '4', {'attrib': 'attrib_value'}, {'actual': '3'}),
    ('actual', '4', {'new_attrib': 'attrib_value', 'new_attrib2': 'whatever'}, {'actual': {'pattern': '3'}}),
])
def test_add_dynamic_detail(detail, value, attribs, details):
    """Test add_dynamic_detail core rule function."""
    utils.add_dynamic_detail(detail, value, attribs, details)
    assert detail in details.keys()
    if detail == next(iter(details.keys())):
        assert details[detail]['pattern'].endswith(value)
    else:
        assert details[detail]['pattern'] == value
    for key, value in attribs.items():
        assert details[detail][key] == value


@patch('wazuh.core.utils.check_wazuh_limits_unchanged')
@patch('wazuh.core.utils.check_remote_commands')
@patch('wazuh.core.utils.check_agents_allow_higher_versions')
@patch('wazuh.core.utils.check_indexer')
@patch('wazuh.core.manager.common.WAZUH_PATH', new=test_files_path)
def test_validate_wazuh_xml(mock_check_indexer,
                            mock_agents_versions, mock_remote_commands, mock_unchanged_limits):
    """Test validate_wazuh_xml method works and methods inside are called with expected parameters"""

    with open(os.path.join(test_files_path, 'test_rules.xml')) as f:
        xml_file = f.read()

    m = mock_open(read_data=xml_file)

    with patch('builtins.open', m):
        utils.validate_wazuh_xml(xml_file)
    mock_remote_commands.assert_not_called()
    mock_agents_versions.assert_not_called()
    mock_check_indexer.assert_not_called()

    with patch('builtins.open', m):
        utils.validate_wazuh_xml(xml_file, config_file=True)
    mock_remote_commands.assert_called_once()
    mock_agents_versions.assert_called_once()
    mock_check_indexer.assert_called_once()


@pytest.mark.parametrize('effect, expected_exception', [
    (utils.ExpatError, 1113)
])
def test_validate_wazuh_xml_ko(effect, expected_exception):
    """Tests validate_wazuh_xml function works when open function raises an exception.
    Parameters
    ----------
    effect : Exception
        Exception to be triggered.
    expected_exception
        Expected code when triggering the exception.
    """
    input_file = os.path.join(test_files_path, 'test_rules.xml')

    with patch('wazuh.core.utils.load_wazuh_xml', side_effect=effect):
        with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
            utils.validate_wazuh_xml(input_file)


@patch('wazuh.core.utils.full_copy')
def test_delete_file_with_backup(mock_full_copy):
    """Test delete_file_with_backup function."""
    backup_file = 'backup'
    abs_path = 'testing/dir/subdir/file'
    delete_function = MagicMock()

    utils.delete_file_with_backup(backup_file, abs_path, delete_function)

    mock_full_copy.assert_called_with(abs_path, backup_file)
    delete_function.assert_called_once_with(filename=os.path.basename(abs_path))


@patch('wazuh.core.utils.full_copy', side_effect=IOError)
def test_delete_file_with_backup_ko(mock_copyfile):
    """Test delete_file_with_backup function exceptions."""
    with pytest.raises(utils.WazuhError, match='.* 1019 .*'):
        utils.delete_file_with_backup('test', 'test', str)


def test_to_relative_path():
    """Test to_relative_path function."""
    path = 'etc/ossec.conf'
    assert utils.to_relative_path(os.path.join(WAZUH_PATH, path)) == path

    assert utils.to_relative_path(path, prefix='etc') == os.path.basename(path)


def test_full_copy():
    """Test `full_copy` function.

    This function will copy a file with all its metadata.
    """
    test_file = os.path.join(test_data_path, 'test_file.txt')
    copied_test_file = os.path.join(test_data_path, 'test_file_copy.txt')
    non_copyable_attributes = {'st_atime', 'st_atime_ns', 'st_ctime', 'st_ctime_ns', 'st_ino'}
    try:
        with open(test_file, 'w') as f:
            f.write('test')

        os.chmod(test_file, 0o660)

        original_stat = os.stat(test_file)
        utils.full_copy(test_file, copied_test_file)
        copy_stat = os.stat(copied_test_file)

        for attribute in dir(original_stat):
            if attribute.startswith('st_') and attribute not in non_copyable_attributes:
                assert getattr(original_stat, attribute) == getattr(copy_stat, attribute), f'Attribute {attribute} ' \
                                                                                           'is not equal between' \
                                                                                           ' original and copy files'
    finally:
        os.path.exists(test_file) and os.remove(test_file)
        os.path.exists(copied_test_file) and os.remove(copied_test_file)


@patch('wazuh.core.utils.copy2', new=copyfile)
def test_full_copy_ko():
    """Test `full_copy` function using mutation testing."""
    with pytest.raises(AssertionError):
        test_full_copy()


@freeze_time('1970-01-01')
def test_get_date_from_timestamp():
    """Test if the result is the expected date."""

    date = utils.get_date_from_timestamp(0)
    assert date == datetime.datetime(1970, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)


@freeze_time('1970-01-01')
def test_get_utc_now():
    """Test if the result is the expected date."""

    date = utils.get_utc_now()
    assert date == datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)


@freeze_time('1970-01-01')
def test_get_utc_strptime():
    """Test if the result is the expected date."""
    mock_date = '1970-01-01'
    default_format = '%Y-%M-%d'

    date = utils.get_utc_strptime(mock_date, default_format)
    assert isinstance(date, datetime.datetime)
    assert date == datetime.datetime(1970, 1, 1, 0, 1, tzinfo=datetime.timezone.utc)


@pytest.mark.parametrize("new_conf, unchanged_limits_conf", [
    ("<ossec_config><global><limits><eps><maximum>300</maximum><timeframe>5</timeframe></eps></limits></global>"
     "</ossec_config>", False),
    ("<ossec_config><global><logall>no</logall></global><global><limits><eps><test>yes</test></eps></limits></global>"
     "</ossec_config>", False),
    ("<ossec_config><global><logall>yes</logall><limits><eps><maximum>300</maximum></eps></limits></global>"
     "</ossec_config>", True),
    ("<ossec_config><global><logall>yes</logall><limits><eps><maximum>300</maximum></eps></limits></global>"
     "</ossec_config><ossec_config><global><limits><eps><maximum>300</maximum></eps></limits></global></ossec_config>",
     False)
])
@pytest.mark.parametrize("original_conf", [
    "<ossec_config><global><limits><eps><maximum>300</maximum></eps></limits></global></ossec_config>"
])
@pytest.mark.parametrize("limits_conf", [
    ({'eps': {'allow': True}}),
    ({'eps': {'allow': False}})
])
def test_check_wazuh_limits_unchanged(new_conf, unchanged_limits_conf, original_conf, limits_conf):
    """Test if ossec.conf limits are protected by the API.

    When 'eps': {'allow': False} is set in the API configuration, the limits in ossec.conf cannot be changed.
    However, other configuration sections can be added, removed or modified.

    Parameters
    ----------
    new_conf : str
        New ossec.conf to be uploaded.
    unchanged_limits_conf : bool
        Whether the limits section in ossec.conf is the same as the original one.
    original_conf : str
        Original ossec.conf to be uploaded.
    limits_conf : dict
        API configuration for the limits section.
    """
    api_conf = utils.configuration.api_conf
    api_conf['upload_configuration']['limits'].update(limits_conf)

    with patch('wazuh.core.utils.configuration.api_conf', new=api_conf):
        if limits_conf['eps']['allow'] or unchanged_limits_conf:
            utils.check_wazuh_limits_unchanged(new_conf, original_conf)
        else:
            with pytest.raises(exception.WazuhError, match=".* 1127 .*"):
                utils.check_wazuh_limits_unchanged(new_conf, original_conf)


@pytest.mark.parametrize("new_conf", [
    ("<ossec_config><remote><agents><allow_higher_versions>yes</allow_higher_versions></agents></remote></ossec_config>"),
    ("<ossec_config><auth><agents><allow_higher_versions>yes</allow_higher_versions></agents></auth></ossec_config>"),
    ("<ossec_config><remote><agents><allow_higher_versions>no</allow_higher_versions></agents></remote></ossec_config>"),
    ("<ossec_config><auth><agents><allow_higher_versions>no</allow_higher_versions></agents></auth></ossec_config>"),
    ("<ossec_config><remote><agents><allow_higher_versions>yes</allow_higher_versions></agents></remote><auth>" \
     "<agents><allow_higher_versions>yes</allow_higher_versions></agents></auth></ossec_config>"),
     ("<ossec_config><remote><agents><allow_higher_versions>no</allow_higher_versions></agents></remote><auth>" \
     "<agents><allow_higher_versions>no</allow_higher_versions></agents></auth></ossec_config>"),
])
@pytest.mark.parametrize("agents_conf", [
    ({'allow_higher_versions': {'allow': True}}),
    ({'allow_higher_versions': {'allow': False}}),
])
def test_agents_allow_higher_versions(new_conf, agents_conf):
    """Check if ossec.conf agents versions are protected by the API.

    When 'allow_higher_versions': {'allow': False} is set in the API configuration, the agent versions in ossec.conf
    cannot be changed. However, other configuration sections can be added,
    removed or modified.

    Parameters
    ----------
    new_conf : str
        New ossec.conf to be uploaded.
    agents_conf : dict
        API configuration for the agents section.
    """
    api_conf = utils.configuration.api_conf
    api_conf['upload_configuration']['agents'].update(agents_conf)

    with patch('wazuh.core.utils.configuration.api_conf', new=api_conf):
        if agents_conf['allow_higher_versions']['allow'] or new_conf.find('no') != -1:
            utils.check_agents_allow_higher_versions(new_conf)
        else:
            with pytest.raises(exception.WazuhError, match=".* 1129 .*"):
                utils.check_agents_allow_higher_versions(new_conf)


@pytest.mark.parametrize("new_conf, original_conf, indexer_changed", [
    (
        "<ossec_config><indexer><enabled>yes</enabled></indexer></ossec_config>",
        "<ossec_config><indexer><enabled>no</enabled></indexer></ossec_config>",
        True,
     ),
    (
        "<ossec_config><indexer><enabled>no</enabled></indexer></ossec_config>",
        "<ossec_config><indexer><enabled>no</enabled></indexer></ossec_config>",
        False,
    ),
    (
        "<ossec_config><indexer><hosts><host>https://0.0.0.0:9200/</host></hosts></indexer></ossec_config>",
        "<ossec_config><indexer><hosts><host>https://127.0.0.1:9200/</host></hosts></indexer></ossec_config>",
        True,
    ),
    (
        "<ossec_config><indexer><enabled>yes</enabled><ssl><key>/etc/filebeat/certs/filebeat-key.pem</key></ssl>" \
        "</indexer></ossec_config>",
        "<ossec_config><indexer><enabled>yes</enabled></indexer></ossec_config>",
        True,
    ),
    (
        "<ossec_config><indexer><enabled>yes</enabled><ssl><key>/etc/filebeat/certs/filebeat-key.pem</key></ssl>" \
        "</indexer></ossec_config>",
        "<ossec_config><indexer><enabled>yes</enabled><ssl><key>filebeat-key.pem</key></ssl></indexer></ossec_config>",
        True,
    ),
    (
        "<ossec_config><auth><disabled>no</disabled></auth></ossec_config>",
        "<ossec_config><auth><disabled>yes</disabled></auth></ossec_config>",
        False,
    ),
])
@pytest.mark.parametrize("indexer_allowed", [
    True,
    False,
])
def test_check_indexer(new_conf, original_conf, indexer_changed, indexer_allowed):
    """Check if the ossec.conf indexer section is protected by the API.

    Parameters
    ----------
    new_conf : str
        New ossec.conf to be uploaded.
    original_conf : str
        Original ossec.conf.
    indexer_changed : bool
        Whether the indexer section of the original and new configurations is equal or not.
    indexer_allowed : bool
        Whether it is allowed to modify the indexer API configuration section.
    """
    api_conf = utils.configuration.api_conf
    api_conf['upload_configuration']['indexer']['allow'] = indexer_allowed

    with patch('wazuh.core.utils.configuration.api_conf', new=api_conf):
        if indexer_allowed:
            utils.check_indexer(new_conf, original_conf)
        elif indexer_changed:
            with pytest.raises(exception.WazuhError, match=".* 1127 .*"):
                utils.check_indexer(new_conf, original_conf)


@pytest.mark.parametrize(
    'chk_xml, content', [
        # basic test case
        (False, "Test"),
        # check_xml test case
        (True, "<Test>'+Tes't</Test>")]
)
@patch('wazuh.core.utils.tempfile.mkstemp',
        return_value=('handle', os.path.join(OSSEC_TMP_PATH, 'file.tmp')))
@patch('wazuh.core.utils.chmod')
@patch('wazuh.core.common.wazuh_gid')
@patch('wazuh.core.common.wazuh_uid')
def test_upload_file(mock_uid, mock_gid,
                     mock_chmod, mock_mks,
                     chk_xml, content):
    """Test upload_file function.

    Parameters
    ----------
    mock_uid: Mock
        mock of the wazuh.core.common.wazuh_uid function.
    mock_gid: Mock
        mock of the wazuh.core.common.wazuh_gid function.
    mock_chmod: Mock
        mock of the wazuh.core.utils.chmod function.
    mock_mks
        Mock of the wazuh.core.utils.tempfile.mkstemp function.
    chk_xml: bool
        check_xml_formula_value parameter passed to uploda_file.
    content: str
        content parameter passed to upload_file.
    """
    filename = "file.xml"
    mko = mock_open()
    handle = mko()

    with patch('wazuh.core.utils.open', mko):
        with patch('wazuh.core.utils.safe_move') as mock_safe_move:
            result = utils.upload_file(content, file_path=filename,
                                        check_xml_formula_values=chk_xml)
            assert isinstance(result, WazuhResult)
            handle.write.assert_called_once_with(content)
            tmp_path = os.path.join(OSSEC_TMP_PATH, 'file.tmp')
            file_path = os.path.join(WAZUH_PATH, filename)
            mock_safe_move.assert_called_once_with(tmp_path, file_path,
                                                    ownership=(mock_uid(), mock_gid()),
                                                    permissions=0o660)


@pytest.mark.parametrize(
    'sm_side_effect, w_side_effect, upload_error', [
        # IOError exception raised writing file
        (None, True, (utils.WazuhInternalError, 1005)),
        # safe_move raises an Error()
        (Error(), False, (utils.WazuhInternalError, 1016)),
        # safe_move raises a PermissionError()
        (PermissionError(), False, (utils.WazuhError, 1006))]
)
@patch('wazuh.core.utils.tempfile.mkstemp',
        return_value=('handle', os.path.join(OSSEC_TMP_PATH, 'file.tmp')))
@patch('wazuh.core.utils.chmod')
@patch('wazuh.core.common.wazuh_gid')
@patch('wazuh.core.common.wazuh_uid')
def test_upload_file_ko(mock_uid, mock_gid, mock_chmod, mock_mks,
                     sm_side_effect, w_side_effect, upload_error):
    """
    Parameters
    ----------
    mock_uid : Mock
        mock of the wazuh.core.common.wazuh_uid function.
    mock_gid : Mock
        mock of the wazuh.core.common.wazuh_gid function.
    mock_chmod: Mock
        mock of the wazuh.core.utils.chmod function.
    mock_mks : Mock
        Mock of the wazuh.core.utils.tempfile.mkstemp function.
    sm_side_effect : Exception
        Exception to raise in the safe_move mock as side_effect.
    w_side_effect : bool
        When this parameter is True, file.write function raises an IOError
        Exception when called.
    upload_error : tuple[ExceptionType, int]
        The function checks if the upload_file function raises the ExceptionType
        defined in the index 0 with the error_code defined in the index 1 of
        the tuple.
    """
    filename = "file.xml"
    mko = mock_open()
    handle = mko()
    if w_side_effect:
        handle.write.side_effect = IOError()

    with patch('wazuh.core.utils.open', mko):
        with patch('wazuh.core.utils.safe_move', side_effect=sm_side_effect) as mock_safe_move:
            with pytest.raises(upload_error[0], match=rf'\b{upload_error[1]}\b'):
                utils.upload_file("test", file_path=filename)


@pytest.mark.parametrize(
    "version_str, expected_result",
    [
        ("Wazuh v4.3.10", True),
        ("Wazuh v3.0.0", True),
        ("Wazuh v1.2.3", True),
        ("Wazuhv4.3.10", False),
        ("wazuh v4.3.10", False),
        ("Wazuh v4.3", False),
        ("Wazuh 4.3.10", False),
        ("Not a version", False),
    ]
)
def test_check_if_wazuh_agent_version(version_str, expected_result):
    """
    Test the check_if_wazuh_agent_version function.

    Parameters
    ----------
    version_str : str
        The version string to check.
    expected_result : bool
        Expected result from the function based on the input format.

    Asserts
    -------
    bool
        The function returns True for valid version formats and False otherwise.
    """
    assert utils.check_if_wazuh_agent_version(version_str) == expected_result


@pytest.mark.parametrize(
    "version_str, expected_tuple",
    [
        ("Wazuh v4.3.10", (4, 3, 10)),
        ("Wazuh v0.0.1", (0, 0, 1)),
    ]
)
def test_parse_wazuh_agent_version(version_str, expected_tuple):
    """
    Test the parse_wazuh_agent_version function.

    Parameters
    ----------
    version_str : str
        The version string to parse.
    expected_tuple : tuple
        Expected output tuple (X, Y, Z) extracted from the input string.

    Asserts
    -------
    tuple
        The function correctly parses the version string into a tuple of integers.
    """
    assert utils.parse_wazuh_agent_version(version_str) == expected_tuple
