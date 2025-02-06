# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
from datetime import date, datetime
from unittest.mock import ANY, patch

import pytest
from connexion import ProblemException
from wazuh.core.exception import WazuhError, WazuhInternalError, WazuhPermissionError, WazuhResourceNotFound

from server_management_api import util


class TestClass:
    """Mock swagger type."""
    __test__ = False

    def __init__(self, origin=None):
        self.swagger_types = {
            'api_response': 'test_api_response',
            'data': str
        }
        self.attribute_map = {
            'api_response': 'api_response',
            'data': 'data'
        }
        self.__args__ = ['arg0', 'arg1', 'arg2']
        self.__origin__ = origin


@pytest.mark.parametrize('item, is_transformed', [
    (date.today(), False),
    (datetime.today(), True)
])
def test_serialize(item, is_transformed):
    """Assert serialize() function transform datetime as expected.

    Parameters
    ----------
    item : date
        Date object to be transformed
    is_transformed : bool
        Whether if the returned object should remain the same
    """
    result = util.serialize(item)

    if is_transformed:
        assert result != item
    else:
        assert result == item


@pytest.mark.parametrize('item, klass', [
    ('test', str),
    ('2020-06-24 17:02:53.034374', datetime)
])
def test_deserialize_primitive(item, klass):
    """Check that _deserialize_primitive function returns expected object."""
    result = util._deserialize_primitive(item, klass)
    assert result == item


@pytest.mark.parametrize('item', [
    'test', True, {'key': 'value'}
])
def test_deserialize_object(item):
    """Check that _deserialize_object function works as expected."""
    result = util._deserialize_object(item)
    assert result == item


def test_deserialize_date():
    """Check that _deserialize_date function transforms string into date."""
    result = util.deserialize_date('2020-06-24')
    assert isinstance(result, date)


@patch('dateutil.parser.parse', side_effect=ImportError)
def test_deserialize_date_ko(mock_import):
    """Check that _deserialize_date function correctly handles expected exceptions."""
    result = util.deserialize_date('2020-06-24')
    assert not isinstance(result, date)


def test_deserialize_datetime():
    """Check that _deserialize_datetime function transforms string into datetime."""
    result = util.deserialize_datetime('2020-06-24 17:02:53.034374')
    assert isinstance(result, datetime)


@patch('dateutil.parser.parse', side_effect=ImportError)
def test_deserialize_datetime_ko(mock_import):
    """Check that _deserialize_datetime function correctly handles expected exceptions."""
    result = util.deserialize_datetime('2020-06-24 17:02:53.034374')
    assert not isinstance(result, date)


def test_deserialize_model():
    """Check that _deserialize_model function transforms item into desired object."""
    test = {'data': 'test'}
    result = util.deserialize_model(test, TestClass)

    assert result.data == 'test'
    assert isinstance(result, TestClass)
    assert isinstance(result.attribute_map, dict)
    assert isinstance(result.swagger_types, dict)


def test_deserialize_list():
    """Check that _deserialize_list function transforms list of items into list of desired objects."""
    test = ['test1', 'test2']
    result = util._deserialize_list(test, TestClass)
    assert all(isinstance(x, TestClass) for x in result)


def test_deserialize_dict():
    """Check that _deserialize_dict function transforms dict of items into dict of desired objects."""
    test = {'key1': 'value', 'key2': 'value', 'key3': 'value'}
    result = util._deserialize_dict(test, TestClass)
    assert all(isinstance(x, TestClass) for x in result.values())


@patch('server_management_api.util._deserialize_primitive')
@patch('server_management_api.util._deserialize_object')
@patch('server_management_api.util.deserialize_date')
@patch('server_management_api.util.deserialize_datetime')
@patch('server_management_api.util._deserialize_list')
@patch('server_management_api.util._deserialize_dict')
@patch('server_management_api.util.deserialize_model')
def test_deserialize(mock_model, mock_dict, mock_list, mock_datetime, mock_date, mock_object, mock_primitive):
    """Check that _deserialize calls the expected function depending on the class."""
    assert util._deserialize(None, None) is None

    util._deserialize(30, int)
    mock_primitive.assert_called_once_with(30, int)

    test_object = TestClass(origin=list)
    util._deserialize(test_object, object)
    mock_object.assert_called_once_with(test_object)

    util._deserialize('test_date', date)
    mock_date.assert_called_once_with('test_date')

    util._deserialize('test_date', datetime)
    mock_datetime.assert_called_once_with('test_date')

    util._deserialize([0, 1, 2], test_object)
    mock_list.assert_called_once_with([0, 1, 2], 'arg0')

    test_object = TestClass(origin=dict)
    util._deserialize({'test_key': 'test_value'}, test_object)
    mock_dict.assert_called_once_with({'test_key': 'test_value'}, 'arg1')

    util._deserialize(['test'], list)
    mock_model.assert_called_once_with(['test'], list)


def test_remove_nones_to_dict():
    """Check that remove_nones_to_dict removes key:value when value is None."""
    result = util.remove_nones_to_dict({'key1': 'value1', 'key2': None, 'key3': 'value3'})
    assert 'key2' not in result.keys()


@pytest.mark.parametrize('param, param_type, expected_result', [
    (None, 'search', None),
    (None, 'sort', None),
    (None, 'random', None),
    ('ubuntu', 'search', {'value': 'ubuntu', 'negation': False}),
    ('-ubuntu', 'search', {'value': 'ubuntu', 'negation': True}),
    ('field1', 'sort', {'fields': ['field1'], 'order': 'asc'}),
    ('field1,field2', 'sort', {'fields': ['field1', 'field2'], 'order': 'asc'}),
    ('-field1,field2', 'sort', {'fields': ['field1', 'field2'], 'order': 'desc'}),
    ('random', 'random', 'random')
])
def test_parse_api_param(param, param_type, expected_result):
    """Check that parse_api_param returns the expected result."""
    assert util.parse_api_param(param, param_type) == expected_result


@patch('os.path.relpath')
def test_to_relative_path(mock_real_path):
    """Check that to_relative_path calls expected function with given params."""
    util.to_relative_path('api/conf/api.yaml')
    mock_real_path.assert_called_once_with('api/conf/api.yaml', ANY)


@pytest.mark.parametrize('exception_type, code, extra_fields, returned_code, returned_exception', [
    (ValueError, 100, None, ValueError(100), ValueError),
    (WazuhError, 1000, ['remediation', 'code'], 400, ProblemException),
    (WazuhPermissionError, 4000, ['remediation', 'code'], 403, ProblemException),
    (WazuhResourceNotFound, 1710, ['remediation', 'code'], 404, ProblemException),
    (WazuhInternalError, 1000, ['remediation', 'code'], 500, ProblemException)
])
def test_create_problem(exception_type, code, extra_fields, returned_code, returned_exception):
    """Check that _create_problem returns exception with expected data."""
    with pytest.raises(returned_exception) as exc_info:
        util._create_problem(exception_type(code))

    if returned_exception == ProblemException:
        assert exc_info.value.status == returned_code
    if extra_fields:
        assert all(x in exc_info.value.ext.keys() for x in extra_fields)
        assert None not in exc_info.value.ext.values()


@pytest.mark.parametrize('obj, code', [
    ((WazuhError(6001), ['value0', 'value1']), 429),
    ((WazuhInternalError(1000), ['value0', 'value1']), None),
    ((WazuhPermissionError(4000), ['value0', 'value1']), None),
    ((WazuhResourceNotFound(1710), ['value0', 'value1']), None)
])
@patch('server_management_api.util._create_problem')
def test_raise_if_exc(mock_create_problem, obj, code):
    """Check that raise_if_exc calls _create_problem when an exception is given."""
    result = util.raise_if_exc(obj)
    if isinstance(obj, Exception):
        mock_create_problem.assert_called_once_with(obj, code)
    else:
        assert result == obj


@pytest.mark.parametrize("dikt, f_kwargs, invalid_keys", [
    ({"key1": 0, "key2": 0}, {"key1": 0}, {"key2"}),
    ({
         "key1": 0,
         "key2": {
             "key21": 0,
             "key22": {
                 "key221": 0,
                 "key222": {
                     "key2221": 0
                 }
             }
         }
     },
     {
         "key2": {
             "key22": {
                 "key221": 0
             }
         }
     },
     {"key1", "key21", "key222"}),
    ({"key1": 0}, {"key1": 0, "key2": 0}, set())
])
def test_get_invalid_keys(dikt, f_kwargs, invalid_keys):
    """Check that `get_invalid_keys` return the correct invalid keys when comparing two dictionaries with more
    than one nesting level.
    """
    invalid = util.get_invalid_keys(dikt, f_kwargs)
    assert invalid == invalid_keys


@pytest.mark.parametrize('link', [
    '',
    'https://documentation.wazuh.com/current/user-manual/api/reference.html'
])
@pytest.mark.asyncio
async def test_deprecate_endpoint(link):
    """Check that `deprecate_endpoint` decorator adds valid deprecation headers."""
    class DummyObject:
        headers = {}

    @util.deprecate_endpoint(link=link)
    def dummy_func():
        future_response = asyncio.Future()
        future_response.set_result(DummyObject())
        return future_response

    response = await dummy_func()
    assert response.headers.pop('Deprecated') == 'true', 'No deprecation key in header'
    if link:
        assert response.headers.pop('Link') == f'<{link}>; rel="Deprecated"', 'No link was found'

    assert response.headers == {}, f'Unexpected deprecation headers were found: {response.headers}'


@patch('server_management_api.util.raise_if_exc')
@pytest.mark.asyncio
async def test_only_master_endpoint(mock_exc):
    """Test that only_master_endpoint decorator raise the correct exception when running_in_master_node is False."""

    @util.only_master_endpoint
    async def func_():
        return ret_val

    ret_val = 'foo'

    with patch('server_management_api.util.running_in_master_node', return_value=False):
        await func_()
        mock_exc.assert_called_once_with(WazuhResourceNotFound(902))
    with patch('server_management_api.util.running_in_master_node', return_value=True):
        assert await func_() == ret_val
