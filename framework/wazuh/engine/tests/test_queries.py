# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


from wazuh.engine import queries
from wazuh.core.exception import WazuhError
import pytest


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({}, {}, False),  # Empty params
        ({'select': None}, {}, False),   # Key exist in params but is None
        ({'select': 'select'}, {}, False),  # Key exists in params, data is a Dict
        ({'select': 'select'}, [{}, {}], True)  # Key exists in params, data is List[Dict]
    ])
def test_select_runs_when_valid(params, data, expected):
    """Test that FieldSelector.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldSelector.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'select': 'name'}, [{'name': 'example1', 'number': 1}, {'name': 'example2', 'number': 2}],
         [{'name': 'example1'}, {'name': 'example2'}]),  # Select applied to List[Dict]
        # Select a nested field applied to List[Dict]
        ({'select': 'data.name,version'},
         [
             {'data': {'name': 'some1', 'example': 'example1'}, 'version': 1},
             {'data': {'name': 'some2', 'example': 'example2'}, 'version': 2}],
         [{'data': {'name': 'some1'}, 'version': 1}, {'data': {'name': 'some2'}, 'version': 2}]),
        # Handle case when nest field is a list
        ({'select': 'name.list.name'}, [{'name': {'list': [1, 2, 3]}, 'number': 1}], [{}])

    ])
def test_selects_correct_fields(params, data, expected):
    """Test that the FieldSelector selects the correct fields"""

    selector = queries.FieldSelector(params)
    result = selector.apply_transformation(data)

    assert result == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({}, {}, False),  # Empty params
        ({'search': None}, {}, False),  # Key exist in params but is None
        ({'search': 'search'}, {}, False),  # Key exists in params, data is a Dict
        ({'search': 'search'}, [{}, {}], True)  # Key exists in params, data is List[Dict]
    ])
def test_search_runs_when_valid(params, data, expected):
    """Test that FieldSearch.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldSearch.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'search': 'ex'}, [{'name': 'example'}, {'name': 'some_name'}], [{'name': 'example'}]),  # Search case
        ({'search': 'es'}, [{'name': 'examples'}, {'name': 'some_names'}],
         [{'name': 'examples'}, {'name': 'some_names'}]),  # Search multiple case
        ({'search': '-ex'}, [{'name': 'example', 'version': '1'}, {'name': 'some_name', 'version': '2'}],
         [{'name': 'some_name', 'version': "2"}]),  # Search exclusion case
    ])
def test_search_correct_fields(params, data, expected):
    """Test that the FieldSearch applies the correct search"""

    searcher = queries.FieldSearch(params)
    result = searcher.apply_transformation(data)

    assert result == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({}, {}, False),  # Empty params
        ({'offset': None, 'limit': None}, {}, False),  # Key exist in params but is None
        ({'offset': None, 'limit': 10}, {}, False),  # One is valid but the other is not
        ({'offset': 1, 'limit': 20}, {}, False),  # Key exists in params, data is a Dict
        ({'offset': 1, 'limit': 20}, [{}, {}], True)   # Key exists in params, data is List[Dict]
    ])
def test_offset_limit_runs_when_valid(params, data, expected):
    """Test that FieldOffsetLimit.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldOffsetLimit.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'offset': 0, 'limit': 20}, list(range(0, 10)), list(range(0, 10))),
        ({'offset': 2, 'limit': 20}, list(range(0, 10)), list(range(2, 10))),
        ({'offset': 9, 'limit': 20}, list(range(0, 10)), list(range(9, 10)))
    ]
)
def test_offset_correct_elements(params, data, expected):
    """Test that the FieldOffsetLimit applies the correct offset"""

    transformation = queries.FieldOffsetLimit(params)
    result = transformation.apply_transformation(data)

    assert result == expected


@pytest.mark.parametrize("offset", [-20, -1])
def test_offset_raises_error_with_invalid_value(offset):
    """Test that the FieldOffsetLimit raises an error with an invalid offset value"""

    with pytest.raises(WazuhError) as error_info:
        queries.FieldOffsetLimit({'offset': offset})

    assert error_info.value.code == 1400


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'offset': 0, 'limit': 10}, list(range(0, 20)), list(range(0, 10))),
        ({'offset': 0, 'limit': 1}, list(range(2, 20)), list(range(2, 3)))
    ])
def test_limit_correct_elements(params, data, expected):
    """Test that the FieldOffsetLimit limits the number of elements"""

    limiter = queries.FieldOffsetLimit(params)
    result = limiter.apply_transformation(data)

    assert result == expected
    assert len(result) == params['limit']


@pytest.mark.parametrize("limit", [0, -2])
def test_limit_raises_error_with_invalid_value(limit):
    """Test that the FieldOffsetLimit raises an error with an invalid limit value"""

    with pytest.raises(WazuhError) as error_info:
        queries.FieldOffsetLimit({'offset': 0, 'limit': limit})

    assert error_info.value.code == 1401


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({}, {}, False),  # Empty params
        ({'sort': None}, {}, False),  # Key exist in params but is None
        ({'sort': "example"}, {}, False),  # Key exists in params, data is a Dict
        ({'sort': "example"}, [{}, {}], True)   # Key exists in params, data is List[Dict]
    ])
def test_sort_runs_when_valid(params, data, expected):
    """Test that FieldSort.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldSort.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'sort': '+key'}, [{'key': 5}, {'key': 1}, {'key': 2}],
         [{'key': 1}, {'key': 2}, {'key': 5}]),  # Sorting one key with numerical value and + option
        ({'sort': '-key'}, [{'key': 5}, {'key': 1}, {'key': 2}],
         [{'key': 5}, {'key': 2}, {'key': 1}]),  # Sorting one key with numerical value and - option
        (
                {'sort': '+key.v,+n'},
                [{'key': {'v': 10}, 'n': 2}, {'key': {'v': 2}, 'n': 1}, {'key': {'v': 4}, 'n': 3},
                 {'key': {'v': 10}, 'n': 4}],
                [{'key': {'v': 2}, 'n': 1}, {'key': {'v': 4}, 'n': 3}, {'key': {'v': 10}, 'n': 2},
                 {'key': {'v': 10}, 'n': 4}],
        ),  # Sorting two keys, one nested, the other not
        ({'sort': '+key'}, [{'key': 'z'}, {'key': 'j'}, {'key': 'b'}],
         [{'key': 'b'}, {'key': 'j'}, {'key': 'z'}]),  # Sorting with one key with string values
        # Sorting with one key with list values
        ({'sort': '+key'}, [{'key': [3, 1]}, {'key': [1, 2]}, {'key': [3, 2]}],
         [{'key': [1, 2]}, {'key': [3, 1]}, {'key': [3, 2]}])
    ]
)
def test_sort_correct_elements(params, data, expected):
    """Test that FieldSort sorts the elements as expected"""
    sort_transformation = queries.FieldSort(params)
    result = sort_transformation.apply_transformation(data)

    assert result == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({}, {}, False),  # Empty params
        ({'q': None}, {}, False),  # Key exist in params but is None
        ({'q': 'key=value'}, {}, False),  # Key exists in params, data is a Dict
        ({'q': 'key=value'}, [{}], True),   # Key exists in params, data is List[Dict]
    ]
)
def test_query_runs_when_valid(params, data, expected):
    """Test that FieldQuery.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldQuery.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params",
    [
        {'q': 'example'},
        {'q': 'example='},
        {'q': 'example!='},
        {'q': 'example!==value'}
    ]
)
def test_query_has_a_valid_string(params):
    """Test that FieldQuery raises error with invalid value"""
    with pytest.raises(WazuhError) as error_info:
        queries.FieldQuery(params).apply_transformation(data=[{}])

    assert error_info.value.code == 1407


@pytest.mark.parametrize(
    "params,data,expected",
    [
        # Handle query with one key
        ({'q': 'key=example'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': 2}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1}, {'key': 'example', 'n': 3}]),
        # Handle query with 2 keys
        ({'q': 'key=example;n=1'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': 2}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1}]),
        # Handle query with 2 keys even if one is a list
        ({'q': 'key=example;n=1'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1}]),
        # Handle > operator
        ({'q': 'key=example;n>2'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 3}]),
        # Handle < operator
        ({'q': 'key=example;n<2'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1}]),
        # Handle ~ operator
        ({'q': 'key~example'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}, {'key': 'example', 'n': 3}]),
        # Handle != operator
        ({'q': 'key!=example'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}, {'key': 'example', 'n': 3}],
         [{'key': 'not_example', 'n': [1, 2]}]),
        # Handle or
        ({'q': 'key!=example,n=1'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': [1, 2]}]),
    ]
)
def test_query_return_correct_elements(params, data, expected):
    """Test that FieldQuery query the elements as expected"""
    query_transformation = queries.FieldQuery(params)
    result = query_transformation.apply_transformation(data)

    assert result == expected


def test_sequence_runs_all_valid_queries():
    class QueyMock(queries.BaseQuery):
        """Mock implementation of a query for testing."""
        counter = 0

        def __init__(self, params):
            QueyMock.counter += 1

        def apply_transformation(self, data):
            data['counter'] = QueyMock.counter
            return data

        @staticmethod
        def can_i_run(params, data):
            return True

    list_of_queries = [QueyMock, QueyMock, QueyMock]
    transformation_sequence = queries.EngineQuery(list_of_queries)
    result = transformation_sequence.apply_sequence({}, {})

    assert result['counter'] == len(list_of_queries)
