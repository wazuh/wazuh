#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import os
from io import StringIO
from shutil import copyfile
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import ANY, MagicMock, Mock, call, patch

import pytest
import yaml
from freezegun import freeze_time

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh import WazuhException
        from wazuh.core import exception, utils

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

# input data for testing q filter
input_array = [
    {
        'count': 3,
        'name': 'default',
        'mergedSum': 'a7d19a28cd5591eade763e852248197b',
        'configSum': 'ab73af41699f13fdd81903b5f23d8d00',
    },
    {
        'count': 0,
        'name': 'dmz',
        'mergedSum': 'dd77862c4a41ae1b3854d67143f3d3e4',
        'configSum': 'ab73af41699f13fdd81903b5f23d8d00',
    },
    {
        'count': 0,
        'name': 'testsagentconf',
        'mergedSum': '2acdb385658097abb9528aa5ec18c490',
        'configSum': '297b4cea942e0b7d2d9c59f9433e3e97',
    },
    {
        'count': 0,
        'name': 'testsagentconf2',
        'mergedSum': '391ae29c1b0355c610f45bf133d5ea55',
        'configSum': '297b4cea942e0b7d2d9c59f9433e3e97',
    },
    {
        'count': 0,
        'name': 'test_nested1',
        'mergedSum': {'nestedSum1': 'value'},
        'configSum': '0000000000000000000000000000000',
    },
    {
        'count': 0,
        'name': 'test@nested2',
        'mergedSum': {'nestedSum1': 'value'},
        'configSum': {
            'nestedSum1': {'nestedSum11': 'value'},
            'nestedSum2': [{'nestedSum21': 'value1'}, {'nestedSum21': 'value2'}],
        },
    },
]


# MOCK DATA


class ClassTest(object):
    """__init__() functions as the class constructor."""

    def __init__(self, name=None, job=None):
        self.name = name
        self.job = job

    def to_dict(self):
        """Convert object into a dictionary.

        Returns
        -------
        dict
            Dictionary containing the key values.
        """
        return {'name': self.name, 'job': self.job}


mock_array = [
    {
        'rx': {'bytes': 4005, 'packets': 30},
        'scan': {'id': 1999992193, 'time': '2019/05/29 07:25:26'},
        'mac': '02:42:ac:14:00:05',
        'agent_id': '000',
    },
    {
        'rx': {'bytes': 447914, 'packets': 1077},
        'scan': {'id': 396115592, 'time': '2019/05/29 07:26:26'},
        'mac': '02:42:ac:14:00:01',
        'agent_id': '003',
    },
]
mock_sort_by = ['mac']
mock_array_order_by_mac = [
    {
        'rx': {'bytes': 447914, 'packets': 1077},
        'scan': {'id': 396115592, 'time': '2019/05/29 07:26:26'},
        'mac': '02:42:ac:14:00:01',
        'agent_id': '003',
    },
    {
        'rx': {'bytes': 4005, 'packets': 30},
        'scan': {'id': 1999992193, 'time': '2019/05/29 07:25:26'},
        'mac': '02:42:ac:14:00:05',
        'agent_id': '000',
    },
]
mock_array_class = [ClassTest('Payne', 'coach')]
mock_array_missing_key = [
    {
        'description': 'GReAT. (2017, April 3). Lazarus Under the Hood. Retrieved April 17, 2019.',
        'id': 'intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340',
    },
    {
        'description': 'FireEye. (2018, October 03). APT38: Un-usual Suspects. Retrieved November 6, 2018.',
        'id': 'intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340',
    },
    {
        'description': None,
        'id': 'intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340',
    },
]

test_yaml = """
key: value
"""


@pytest.mark.parametrize('exists', [True, False])
@patch('wazuh.core.utils.chown')
@patch('wazuh.core.common.wazuh_uid')
@patch('wazuh.core.common.wazuh_gid')
def test_create_wazuh_dir(mock_gid, mock_uid, mock_chown, exists):
    """Test create_wazuh_dir function."""
    dirpath = MagicMock()
    dirpath.exists = MagicMock(return_value=exists)

    utils.create_wazuh_dir(dirpath)

    dirpath.exists.assert_called_once()

    if not exists:
        dirpath.mkdir.assert_called_once()
        mock_chown.assert_called_once_with(dirpath, mock_uid(), mock_gid())
    else:
        dirpath.mkdir.assert_not_called()
        mock_chown.assert_not_called()


@patch('os.chown')
@patch('wazuh.core.common.wazuh_uid')
@patch('wazuh.core.common.wazuh_gid')
def test_assign_wazuh_ownership(mock_gid, mock_uid, mock_chown):
    """Test assign_wazuh_ownership function."""
    with TemporaryDirectory() as tmp_dirname:
        tmp_file = NamedTemporaryFile(dir=tmp_dirname, delete=False)
        filename = os.path.join(tmp_dirname, tmp_file.name)
        utils.assign_wazuh_ownership(filename)

        mock_chown.assert_called_once_with(filename, mock_uid(), mock_gid())


@patch('os.chown')
@patch('wazuh.core.common.wazuh_uid')
@patch('wazuh.core.common.wazuh_gid')
def test_assign_wazuh_ownership_write_file(mock_gid, mock_uid, mock_chown):
    """Test assign_wazuh_ownership function with a non-regular file."""
    with TemporaryDirectory() as tmp_dirname:
        tmp_file = NamedTemporaryFile(dir=tmp_dirname, delete=False)
        filename = os.path.join(tmp_dirname, tmp_file.name)

        with patch('os.path.isfile', return_value=False):
            with patch('builtins.open') as mock_open:
                utils.assign_wazuh_ownership(filename)
                mock_open.assert_called_once_with(filename, 'w')

            mock_chown.assert_called_once_with(filename, mock_uid(), mock_gid())


@pytest.mark.parametrize(
    'array, limit', [(['one', 'two', 'three'], 2), (['one', 'two', 'three'], None), ([], None), ([], 1)]
)
@patch('wazuh.core.utils.common.MAXIMUM_DATABASE_LIMIT', new=10)
def test_cut_array(array, limit):
    """Test cut_array function."""
    result = utils.cut_array(array=array, limit=limit, offset=0)

    assert isinstance(result, list)


@pytest.mark.parametrize(
    'limit, offset, expected_exception', [(11, 0, 1405), (0, 0, 1406), (5, -1, 1400), (-1, 0, 1401)]
)
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
        (
            [
                {'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'},
            ],
            'datetime=2017-10-25T14:48:53.732000Z',
            None,
            None,
            None,
            None,
            None,
            False,
            [{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'}],
            1,
        ),
        (
            [
                {'name': 'W', 'datetime': '2017-10-25T14:48:53.732000Z'},
                {'name': 'I', 'datetime': '2018-05-15T12:34:12.544000Z'},
            ],
            '(name=W,name=I)',
            None,
            None,
            None,
            None,
            None,
            False,
            [
                {'name': 'W', 'datetime': '2017-10-25T14:48:53.732000Z'},
                {'name': 'I', 'datetime': '2018-05-15T12:34:12.544000Z'},
            ],
            2,
        ),
        (
            [
                {'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'},
            ],
            'datetime<2017-10-26',
            None,
            None,
            None,
            None,
            None,
            False,
            [{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'}],
            1,
        ),
        (
            [
                {'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'},
            ],
            'datetime>2019-10-26,datetime<2017-10-26',
            None,
            None,
            None,
            None,
            None,
            False,
            [{'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'}],
            1,
        ),
        (
            [
                {'item': 'value_2', 'datetime': '2017-10-25T14:48:53.732000Z'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'},
            ],
            'datetime>2017-10-26;datetime<2018-05-15T12:34:12.644000Z',
            None,
            None,
            None,
            None,
            None,
            False,
            [{'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z'}],
            1,
        ),
        (
            [
                {'item': 'value_2', 'datetime': '2017-10-25T14:48:53Z'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12Z'},
            ],
            'datetime>2017-10-26;datetime<2018-05-15T12:34:12.001000Z',
            None,
            None,
            None,
            None,
            None,
            False,
            [{'item': 'value_1', 'datetime': '2018-05-15T12:34:12Z'}],
            1,
        ),
        (
            [
                {'name': 'value_1', 'status': 'disabled'},
                {'name': 'value_2', 'status': 'enabled'},
                {'name': 'value_3', 'status': 'enabled'},
            ],
            'status=enabled;(name=value_1,name=value_3)',
            None,
            None,
            None,
            None,
            None,
            False,
            [{'name': 'value_3', 'status': 'enabled'}],
            1,
        ),
        # Test cases with filters, limit and search
        (
            [{'item': 'value_1', 'some': 't'}, {'item': 'value_2', 'some': 'a'}, {'item': 'value_3', 'some': 'b'}],
            None,
            {'item': 'value_1', 'some': 't'},
            1,
            None,
            None,
            None,
            False,
            [{'item': 'value_1', 'some': 't'}],
            1,
        ),
        (
            [{'item': 'value_1'}, {'item': 'value_1'}, {'item': 'value_3'}],
            None,
            None,
            1,
            'e_1',
            None,
            None,
            False,
            [{'item': 'value_1'}],
            2,
        ),
        (
            [{'item': 'value_1'}, {'item': 'value_1'}, {'item': 'value_3'}],
            None,
            None,
            2,
            'e_1',
            None,
            None,
            False,
            [{'item': 'value_1'}, {'item': 'value_1'}],
            2,
        ),
        # Test cases with sort
        (
            [{'item': 'value_2'}, {'item': 'value_1'}, {'item': 'value_3'}],
            None,
            None,
            None,
            None,
            None,
            ['item'],
            False,
            [{'item': 'value_1'}, {'item': 'value_2'}, {'item': 'value_3'}],
            3,
        ),
        # Test cases with distinct
        (
            [
                {'item': 'value_1', 'component': 'framework'},
                {'item': 'value_2', 'component': 'API'},
                {'item': 'value_1', 'component': 'framework'},
            ],
            None,
            None,
            None,
            None,
            None,
            None,
            True,
            [{'item': 'value_1', 'component': 'framework'}, {'item': 'value_2', 'component': 'API'}],
            2,
        ),
        (['framework', 'API', 'API'], None, None, None, None, None, None, True, ['framework', 'API'], 2),
        # Complex test cases
        (
            [
                {'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z', 'component': 'framework'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z', 'component': 'API'},
            ],
            'datetime~2017',
            {'item': 'value_1'},
            1,
            'frame',
            None,
            None,
            False,
            [{'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z', 'component': 'framework'}],
            1,
        ),
        (
            [
                {'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z', 'component': 'framework'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z', 'component': 'API'},
            ],
            'datetime~2019',
            {'item': 'value_1'},
            1,
            None,
            None,
            None,
            False,
            [],
            0,
        ),
        (
            [
                {'item': 'value_1', 'datetime': '2017-10-25T14:48:53.732000Z', 'component': 'framework'},
                {'item': 'value_1', 'datetime': '2018-05-15T12:34:12.544000Z', 'component': 'API'},
            ],
            'datetime~2017',
            {'item': 'value_1'},
            1,
            None,
            ['component', 'item'],
            None,
            False,
            [{'item': 'value_1', 'component': 'framework'}],
            1,
        ),
    ],
)
def test_process_array(
    array, q, filters, limit, search_text, sort_by, select, distinct, expected_items, expected_total_items
):
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
    result = utils.process_array(
        array=array,
        filters=filters,
        limit=limit,
        offset=0,
        search_text=search_text,
        select=select,
        sort_by=sort_by,
        q=q,
        distinct=distinct,
    )

    assert result == {'items': expected_items, 'totalItems': expected_total_items}


@patch('wazuh.core.utils.len', return_value=1)
@patch('wazuh.core.utils.cut_array')
@patch('wazuh.core.utils.select_array', return_value=ANY)
@patch('wazuh.core.utils.filter_array_by_query', return_value=ANY)
@patch('wazuh.core.utils.search_array', return_value=ANY)
@patch('wazuh.core.utils.sort_array', return_value=ANY)
def test_process_array_ops_order(
    mock_sort_array, mock_search_array, mock_filter_array_by_query, mock_select_array, mock_cut_array, mock_len
):
    """Test that the process_array function calls the sort, search, filter by query, select and cut operations in the
    expected order and with the expected parameters.
    """
    manager_mock = Mock()
    manager_mock.attach_mock(mock_sort_array, 'mock_sort_array')
    manager_mock.attach_mock(mock_search_array, 'mock_search_array')
    manager_mock.attach_mock(mock_filter_array_by_query, 'mock_filter_array_by_query')
    manager_mock.attach_mock(mock_select_array, 'mock_select_array')
    manager_mock.attach_mock(mock_cut_array, 'mock_cut_array')

    utils.process_array(
        array=[{'item': 'value_1'}, {'item': 'value_2'}, {'item': 'value_3'}],
        filters={'item': 'value_1'},
        limit=1,
        offset=0,
        search_text='e_1',
        select=['item'],
        sort_by=['item'],
        q='item~value',
    )

    # The array in the sort_array function parameter is the initial one after the filters
    # The array parameter of the other functions is ANY
    assert manager_mock.mock_calls == [
        call.mock_sort_array([{'item': 'value_1'}], sort_by=['item'], sort_ascending=True, allowed_sort_fields=None),
        call.mock_search_array(ANY, search_text='e_1', complementary_search=False, search_in_fields=None),
        call.mock_filter_array_by_query('item~value', ANY),
        call.mock_select_array(ANY, select=['item'], required_fields=None, allowed_select_fields=None),
        call.mock_cut_array(ANY, offset=0, limit=1),
    ]


def test_sort_array_type():
    """Test sort_array function."""
    assert isinstance(utils.sort_array(mock_array, mock_sort_by), list)
    assert isinstance(utils.sort_array(mock_array, None), list)


@pytest.mark.parametrize(
    'array, sort_by, order, expected_exception',
    [([{'test': 'test'}], None, 'asc', 1402), ('{}', None, 'random', 1402), (mock_array, ['test'], False, 1403)],
)
def test_sort_array_error(array, sort_by, order, expected_exception):
    """Tests sort_array function for all exceptions.

    Cases:

        * List with a dictionary and no sort parameter
        * Order type different to 'asc' or 'desc'
        * Sort parameter not allow
    """
    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        utils.sort_array(array, sort_by, order)


@pytest.mark.parametrize(
    'array, sort_by, order, allowed_sort_field, output',
    [
        ('', None, True, None, ''),
        ([4005, 4006, 4019, 36], None, True, None, [36, 4005, 4006, 4019]),
        ([4005, 4006, 4019, 36], None, False, None, [4019, 4006, 4005, 36]),
        (mock_array, mock_sort_by, True, mock_sort_by, mock_array_order_by_mac),
        (mock_array_class, ['name'], False, ['name'], mock_array_class),
        (mock_array_missing_key, ['description'], False, ['description'], mock_array_missing_key),
    ],
)
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


@pytest.mark.parametrize(
    'object, fields',
    [
        ({'test': 'test'}, None),
        ({'test': 'test'}, ['test']),
        (['test', 'name'], None),
        (ClassTest('Payne', 'coach'), None),
    ],
)
def test_get_values(object, fields):
    """Test get_values function."""
    result = utils.get_values(o=object, fields=fields)

    assert isinstance(result, list)
    assert isinstance(result[0], str)


@pytest.mark.parametrize(
    'array, text, negation, length',
    [
        (['test', 'name'], 'e', False, 2),
        (['test', 'name'], 'name', False, 1),
        (['test', 'name'], 'unknown', False, 0),
        (['test', 'name'], 'test', True, 1),
        (['test', 'name'], 'unknown', True, 2),
    ],
)
def test_search_array(array, text, negation, length):
    """Test search_array function."""
    result = utils.search_array(array=array, search_text=text, complementary_search=negation)

    assert isinstance(result, list)
    assert len(result) == length


def test_tail():
    """Test tail function."""
    result = utils.tail(os.path.join(test_data_path, 'test_log.log'))

    assert isinstance(result, list)
    assert len(result) == 20


@pytest.mark.parametrize(
    'ownership, time, permissions',
    [
        ((1000, 1000), None, None),
        ((1000, 1000), (12345, 12345), None),
        ((1000, 1000), None, 0o660),
        ((1000, 1000), (12345, 12345), 0o660),
    ],
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
        assert os.path.exists(target_file)

        tmp_path = os.path.join(os.path.dirname(tmp_file.name), '.target.tmp')
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
        assert os.path.exists(target_file)


@pytest.mark.parametrize('dir_name, path_exists', [('/var/test_path', True), ('./var/test_path/', False)])
@patch('wazuh.core.utils.chmod')
@patch('wazuh.core.utils.mkdir')
@patch('wazuh.core.utils.curdir', new='var')
def test_mkdir_with_mode(mock_mkdir, mock_chmod, dir_name, path_exists):
    """Test mkdir_with_mode function."""
    with patch('wazuh.core.utils.path.exists', return_value=path_exists):
        utils.mkdir_with_mode(dir_name)
        mock_chmod.assert_any_call(dir_name, 0o770)
        mock_mkdir.assert_any_call(dir_name, 0o770)


@pytest.mark.parametrize('dir_name, exists', [('/var/test_path', True), ('/var/test_path/', False)])
@patch('wazuh.core.utils.mkdir', side_effect=OSError)
def test_mkdir_with_mode_ko(mock_mkdir, dir_name, exists):
    """Test mkdir_with_mode function errors work."""
    with patch('wazuh.core.utils.path.exists', return_value=exists):
        with pytest.raises(OSError):
            utils.mkdir_with_mode(dir_name)


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
    with pytest.raises(exception.WazuhException, match='.* 1723 .*'):
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

        assert type(result) is bytes


@patch('wazuh.core.utils.open')
@patch('wazuh.core.utils.iter', return_value=['1', '2'])
def test_get_hash_ko(mock_iter, mock_open):
    """Test get_hash function error work."""
    with patch('wazuh.core.utils.hashlib.new') as md:
        md.return_value.update.side_effect = IOError
        result = utils.get_hash(filename='test_file')

        assert result is None
        mock_open.assert_called_once_with('test_file', 'rb')


def test_basic_load_wazuh_yaml():
    """Test basic `load_wazuh_yaml` functionality."""
    with patch('wazuh.core.utils.open') as f:
        f.return_value.__enter__.return_value = StringIO(test_yaml)
        result = utils.load_wazuh_yaml('test_file')

        assert isinstance(result, dict)


def test_load_wazuh_yaml_read_ko():
    """Test `load_wazuh_yaml` fails gracefully when reading invalid files."""
    file_path = os.path.join(test_data_path, 'test_load_wazuh_yaml_ko', 'invalid_utf8.yaml')
    with pytest.raises(WazuhException, match=f'.*{1006}.*'):
        utils.load_wazuh_yaml(file_path)


@patch('wazuh.core.utils.yaml.safe_load', side_effect=yaml.YAMLError)
def test_load_wazuh_yaml_data_ko(safe_load_mock):
    """Test `load_wazuh_yaml` fails gracefully when parsing invalid data."""
    with pytest.raises(WazuhException, match=f'.*{1132}.*'):
        utils.load_wazuh_yaml('', data='1')


@patch('wazuh.core.common.WAZUH_GROUPS', new='/test')
def test_get_group_file_path():
    """Test `get_group_file_path` returns the corrrect path."""
    group_id = 'default'
    expected_path = '/test/default.yml'
    path = utils.get_group_file_path(group_id)

    assert path == expected_path


@pytest.mark.parametrize(
    'q, return_length',
    [
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
    ],
)
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
        assert len(item_keys) == len(input_array[0])
        assert item_keys == set(input_array[0].keys())

    assert len(result) == return_length


@pytest.mark.parametrize(
    'select, required_fields, expected_result',
    [
        (
            ['single_select', 'nested1.nested12.nested121'],
            {'required'},
            {'required': None, 'single_select': None, 'nested1': {'nested12': {'nested121': None}}},
        ),
        (['single_select', 'noexists'], None, {'single_select': None}),
        (['required.noexists1.noexists2'], None, None),
    ],
)
def test_select_array(select, required_fields, expected_result):
    """Test select_array functionality."""
    array = [
        {
            'required': None,
            'single_select': None,
            'nested1': {'nested12': {'nested121': None}},
            'nested2': {'nested21': None},
        },
        {
            'required': None,
            'single_select': None,
            'nested1': {'nested12': {'nested121': None}},
            'whatever': {'whatever1': None},
        },
    ]

    try:
        result = utils.select_array(array, select=select, required_fields=required_fields)
        for element in result:
            assert element == expected_result
    except utils.WazuhError as e:
        assert e.code == 1724


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
                assert getattr(original_stat, attribute) == getattr(copy_stat, attribute), (
                    f'Attribute {attribute} is not equal between original and copy files'
                )
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
    mock_date = '1970-01-01'
    default_format = '%Y-%M-%d'

    date = utils.get_utc_strptime(mock_date, default_format)
    assert isinstance(date, datetime.datetime)
    assert date == datetime.datetime(1970, 1, 1, 0, 1, tzinfo=datetime.timezone.utc)
