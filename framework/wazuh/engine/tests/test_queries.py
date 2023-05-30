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
        ({'select': 'select'}, {}, True),  # Key exists in params, data is a Dict
        ({'select': 'select'}, [{}, {}], True)  # Key exists in params, data is List[Dict]
    ])
def test_select_runs_when_valid(params, data, expected):
    """Test that EngineFieldSelector.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldSelector.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'select': 'name'}, {'name': 'example', 'number': 1}, {'name': 'example'}),  # Select applied to Dict
        ({'select': 'name'}, [{'name': 'example1', 'number': 1}, {'name': 'example2', 'number': 2}],
         [{'name': 'example1'}, {'name': 'example2'}]),  # Select applied to List[Dict]
        ({'select': 'data.name'}, {'data': {'name': 'some', 'example': 'example'}, 'version': 1},
         {'data': {'name': 'some'}}),  # Select a nested field applied to Dict
        # Select a nested field applied to List[Dict]
        ({'select': 'data.name,version'},
         [
             {'data': {'name': 'some1', 'example': 'example1'}, 'version': 1},
             {'data': {'name': 'some2', 'example': 'example2'}, 'version': 2}],
         [{'data': {'name': 'some1'}, 'version': 1}, {'data': {'name': 'some2'}, 'version': 2}])

    ])
def test_selects_correct_fields(params, data, expected):
    """Test that the EngineFieldSelector selects the correct fields"""

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
    """Test that EngineFieldSearch.can_i_run() runs correctly when valid parameters and data are provided."""
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
    """Test that the EngineFieldSearch applies the correct search"""

    searcher = queries.FieldSearch(params)
    result = searcher.apply_transformation(data)

    assert result == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({}, {}, False),  # Empty params
        ({'offset': None}, {}, False),  # Key exist in params but is None
        ({'offset': 1}, {}, False),  # Key exists in params, data is a Dict
        ({'offset': 1}, [{}, {}], True)   # Key exists in params, data is List[Dict]
    ])
def test_offset_runs_when_valid(params, data, expected):
    """Test that EngineFieldOffset.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldOffset.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'offset': 0}, list(range(0, 10)), list(range(0, 10))),
        ({'offset': 2}, list(range(0, 10)), list(range(2, 10))),
        ({'offset': 9}, list(range(0, 10)), list(range(9, 10)))
    ]
)
def test_offset_correct_elements(params, data, expected):
    """Test that the EngineFieldOffset applies the correct offset"""

    transformation = queries.FieldOffset(params)
    result = transformation.apply_transformation(data)

    assert result == expected


@pytest.mark.parametrize("offset", [-20, -1])
def test_offset_raises_error_with_invalid_value(offset):
    """Test that the EngineFieldOffset raises an error with an invalid offset value"""

    with pytest.raises(WazuhError) as error_info:
        queries.FieldOffset({'offset': offset})

    assert error_info.value.code == 1400


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({}, {}, False),  # Empty params
        ({'limit': None}, {}, False),  # Key exist in params but is None
        ({'limit': 1}, {}, False),  # Key exists in params, data is a Dict
        ({'limit': 1}, [{}, {}], True)   # Key exists in params, data is List[Dict]
    ])
def test_limit_runs_when_valid(params, data, expected):
    """Test that EngineFieldLimit.can_i_run() runs correctly when valid parameters and data are provided."""
    assert queries.FieldLimit.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'limit': 10}, list(range(0, 20)), list(range(0, 10))),
        ({'limit': 1}, list(range(2, 20)), list(range(2, 3)))
    ])
def test_limit_correct_elements(params, data, expected):
    """Test that the EngineFieldLimit limits the number of elements"""

    limiter = queries.FieldLimit(params)
    result = limiter.apply_transformation(data)

    assert result == expected
    assert len(result) == params['limit']


@pytest.mark.parametrize("limit", [0, -2])
def test_limit_raises_error_with_invalid_value(limit):
    """Test that the EngineFieldLimit raises an error with an invalid limit value"""

    with pytest.raises(WazuhError) as error_info:
        queries.FieldLimit({'limit': limit})

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
    """Test that EngineFieldSort.can_i_run() runs correctly when valid parameters and data are provided."""
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
         [{'key': 'b'}, {'key': 'j'}, {'key': 'z'}])  # Sorting with one key with string values
    ]
)
def test_sort_correct_elements(params, data, expected):
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
    assert queries.FieldQuery.can_i_run(params, data) == expected


@pytest.mark.parametrize(
    "params",
    [
        {'q': 'example'},
        {'q': 'example='}
    ]
)
def test_query_has_a_valid_string(params):
    with pytest.raises(WazuhError) as error_info:
        queries.FieldQuery(params)

    assert error_info.value.code == 1407


@pytest.mark.parametrize(
    "params,data,expected",
    [
        ({'q': 'key=example'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': 2}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1},{'key': 'example', 'n': 3}]),
        ({'q': 'key=example,n=1'},
         [{'key': 'example', 'n': 1}, {'key': 'not_example', 'n': 2}, {'key': 'example', 'n': 3}],
         [{'key': 'example', 'n': 1}]),
    ]
)
def test_query_return_correct_elements(params, data, expected):
    query_transformation = queries.FieldQuery(params)
    result = query_transformation.apply_transformation(data)

    assert result == expected


def test_sequence_runs_all_valid_queries():
    class TransformationMock(queries.BaseQuery):
        """Mock implementation of a transformation for testing."""
        counter = 0

        def __init__(self, params):
            TransformationMock.counter += 1

        def apply_transformation(self, data):
            data['counter'] = TransformationMock.counter
            return data

        @staticmethod
        def can_i_run(params, data):
            return True

    list_of_queries = [TransformationMock, TransformationMock, TransformationMock]
    transformation_sequence = queries.EngineQuery(list_of_queries)
    result = transformation_sequence.apply_sequence({}, {})

    assert result['counter'] == len(list_of_queries)
