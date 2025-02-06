#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from copy import deepcopy
from unittest.mock import patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh import WazuhError, WazuhException
        from wazuh.core.results import (
            AffectedItemsWazuhResult,
            WazuhResult,
            _goes_before_than,
            merge,
            nested_itemgetter,
        )

param_name = ['affected_items', 'total_affected_items', 'sort_fields', 'sort_casting', 'sort_ascending',
              'all_msg', 'some_msg', 'none_msg']
WAZUH_EXCEPTION_CODE = 1725
FAILED_AGENT_ID = '999'


@pytest.fixture(scope='function')
def get_wazuh_result():
    return WazuhResult(dct={"data": {"items": [{"item1": "data1"}, {"item2": "OK"}], "message": "Everything ok"}},
                       str_priority=['KO', 'OK'])


@pytest.fixture(scope='function')
def get_wazuh_affected_item():
    def _get_affected(params=None):
        kwargs = {p_name: param for p_name, param in zip(param_name, params)}
        return AffectedItemsWazuhResult(**kwargs)

    return _get_affected


@pytest.fixture(scope='function')
def get_wazuh_failed_item():
    item = AffectedItemsWazuhResult()
    item.add_failed_item(id_=FAILED_AGENT_ID, error=WazuhException(WAZUH_EXCEPTION_CODE))
    return item


@pytest.mark.parametrize('dikt, priority', [
    ({"data": {"items": [{"item1": "data1"}, {"item2": "OK"}], "message": "Everything ok"}}, ['KO', 'OK']),
    ({"data": {"items": [{"item1": "data1"}, {"item2": "data2"}], "message": "Everything ok"}}, None),
])
def test_results_WazuhResult__merge_str(dikt, priority, get_wazuh_affected_item):
    """Test method `_merge_str` from `WazuhResult`.

    Parameters
    ----------
    dikt : dict
        Dict with basic information for the class declaration.
    priority : list
        Used to set the WazuhResult priority.
    """
    wazuh_result = WazuhResult(deepcopy(dikt), str_priority=priority)
    assert isinstance(wazuh_result, WazuhResult)
    item2 = wazuh_result.dikt['data']['items'][1]['item2']
    merge_result = wazuh_result._merge_str(item2, 'KO')
    assert merge_result == priority[0] if priority else '{}|{}'.format(item2, 'KO')


def test_results_WazuhResult_to_dict(get_wazuh_result):
    """Test method `to_dict` from `WazuhResult`."""
    dict_result = get_wazuh_result.to_dict()
    assert isinstance(dict_result, dict)
    assert (key == result_key for key, result_key in zip(['str_priority', 'result'], dict_result.keys()))


def test_results_WazuhResult_render(get_wazuh_result):
    """Test method `render` from `WazuhResult`."""
    render_result = get_wazuh_result.render()
    assert isinstance(render_result, dict)
    assert render_result == get_wazuh_result.dikt


def test_results_WazuhResult_decode_json(get_wazuh_result):
    """Test class method `decode_json` from `WazuhResult`."""
    wazuh_result = get_wazuh_result
    decoded_result = WazuhResult.decode_json(wazuh_result.to_dict())
    assert decoded_result == wazuh_result


@pytest.mark.parametrize('param_value', [
    # affected_items,total_affected_items, sort_fields, sort_casting, sort_ascending,
    # all_msg, some_msg, none_msg
    [['001', '002'], 2, None, ['int'], [True, True], 'Sample message', 'Sample message', 'Sample message'],
    [['001', '003'], None, None, ['int'], [True, False], 'Sample message', 'Sample message', 'Sample message'],
    [[], 0, None, None, ['int'], None, 'Sample message', 'Sample message', 'Sample message'],
    [['001'], None, None, ['str'], None, 'Sample message', 'Sample message', 'Sample message']
])
def test_results_AffectedItemsWazuhResult(get_wazuh_affected_item, param_value):
    """Test class `AffectedItemsWazuhResult`.

    Parameters
    ----------
    param_value : list
        List with param values for _init_.
    """
    affected_result = get_wazuh_affected_item(param_value)
    assert isinstance(affected_result, AffectedItemsWazuhResult)
    for value, dikt_value in zip(param_value, affected_result.dikt.values()):
        assert value == dikt_value


def test_results_AffectedItemsWazuhResult_add_failed_item():
    """Test method `add_failed_item` from class `AffectedItemsWazuhResult`."""
    affected_result = AffectedItemsWazuhResult()
    id_list = ['001', '002']
    # Add two failed items with different id but same exception
    for agent_id in id_list:
        affected_result.add_failed_item(id_=agent_id, error=WazuhException(WAZUH_EXCEPTION_CODE))

    assert affected_result.failed_items
    assert set(id_list) == next(iter(affected_result.failed_items.values()))


def test_results_AffectedItemsWazuhResult_add_failed_items_from(get_wazuh_failed_item):
    """Test method `add_failed_items_from` from class `AffectedItemsWazuhResult`."""
    affected_result = AffectedItemsWazuhResult()
    failed_result = get_wazuh_failed_item
    affected_result.add_failed_items_from(failed_result)
    assert affected_result.failed_items == failed_result.failed_items


def test_results_AffectedItemsWazuhResult_add_failed_items_from_exception():
    """Test raised exception from method `add_failed_items_from` from class `AffectedItemsWazuhResult`."""
    affected_result = AffectedItemsWazuhResult()
    with pytest.raises(WazuhException, match='.* 1000 .*'):
        affected_result.add_failed_items_from('Invalid type')


def test_results_AffectedItemsWazuhResult_remove_failed_items(get_wazuh_failed_item):
    """Test method `remove_failed_items` from class `AffectedItemsWazuhResult`."""
    failed_result = get_wazuh_failed_item
    failed_result.remove_failed_items(code={WAZUH_EXCEPTION_CODE})
    assert not failed_result.failed_items


def test_results_AffectedItemsWazuhResult___or__(get_wazuh_failed_item):
    """Test method `__or__` from class `AffectedItemsWazuhResult`."""
    agent_list_1 = ['001', '002']
    agent_list_2 = ['004', '003']
    affected_item_1 = AffectedItemsWazuhResult(affected_items=deepcopy(agent_list_1))
    affected_item_2 = AffectedItemsWazuhResult(affected_items=deepcopy(agent_list_2))
    failed_item = get_wazuh_failed_item

    # Expect 'affected_items': ['001', '002', '003']
    or_result_1 = affected_item_1 | affected_item_2
    assert set(agent_list_1 + agent_list_2) == set(or_result_1.affected_items)
    assert not or_result_1.failed_items

    # Expect new failed_item
    or_result_2 = or_result_1 | failed_item
    assert or_result_2.failed_items == failed_item.failed_items


@pytest.mark.parametrize('or_item, expected_result', [
    (WazuhError(WAZUH_EXCEPTION_CODE, ids=['001']), AffectedItemsWazuhResult),
    (WazuhError(WAZUH_EXCEPTION_CODE), WazuhException),
    (WazuhException(WAZUH_EXCEPTION_CODE), WazuhException),
    ({'Invalid type': None}, None)
])
def test_results_AffectedItemsWazuhResult___or___exceptions(or_item, expected_result):
    """Test raised exceptions from method `__or__` from class `AffectedItemsWazuhResult`."""
    affected_result = AffectedItemsWazuhResult()
    # Force an exception trying to use __or__ with an invalid type
    try:
        or_result = affected_result | or_item
        assert isinstance(or_result, expected_result)
    except WazuhException as e:
        if e.code != 1000:
            raise e


def test_results_AffectedItemsWazuhResult_to_dict():
    """Test method `to_dict` from class `AffectedItemsWazuhResult`."""
    affected_result = AffectedItemsWazuhResult()
    dict_item = affected_result.to_dict()
    assert isinstance(dict_item, dict)
    assert dict_item
    assert (field == dict_field for field, dict_field in zip(affected_result, dict_item))


def test_results_AffectedItemsWazuhResult_properties():
    """Test getters and setters from class `AffectedItemsWazuhResult`."""
    affected_result = AffectedItemsWazuhResult()
    # Lacks 'failed_items', 'total_failed_items' and 'message'
    property_list = ['affected_items', 'sort_fields', 'sort_casting', 'sort_ascending', 'total_affected_items',
                     'all_msg', 'some_msg', 'none_msg']
    values_list = [['001', '002'], 2, param_name, ['int'], [True, True], 'Sample message', 'Sample message',
                   'Sample message']

    assert len(property_list) == len(values_list)
    # Check getters and setters dynamically
    for key, value in zip(property_list, values_list):
        setattr(affected_result, key, value)
        assert value == getattr(affected_result, key)


def test_results_AffectedItemsWazuhResult_failed_items_properties(get_wazuh_failed_item):
    """Test `failed_items` properties from class `AffectedItemsWazuhResult`."""
    fail_items = get_wazuh_failed_item.failed_items
    total_fail_items = get_wazuh_failed_item.total_failed_items
    assert isinstance(fail_items, dict)
    assert total_fail_items == 1


def test_results_AffectedItemsWazuhResult_message_property():
    """Test `message` property from class `AffectedItemsWazuhResult`."""
    messages = {'none_msg': 'none_msg', 'all_msg': 'all_msg', 'some_msg': 'some_msg'}
    # Force every possible case since this property returns a different value depending on affected_items
    none_msg_result = AffectedItemsWazuhResult(**messages).message
    all_msg_result = AffectedItemsWazuhResult(**messages, affected_items=['001']).message
    aux_result = AffectedItemsWazuhResult(**messages, affected_items=['001'])
    aux_result.add_failed_item(WazuhException(WAZUH_EXCEPTION_CODE))
    some_msg_result = aux_result.message
    assert messages
    assert len(messages) == 3
    assert (msg == item_msg for msg, item_msg in zip(messages, [none_msg_result, all_msg_result, some_msg_result]))


@pytest.mark.parametrize('self_field, other_field, key, expected_result', [
    ('Sample1', 'Sample2', 'older_than', 'Sample1'),
    ('Sample1', 'Sample2', None, 'Sample1|Sample2')
])
def test_results_AffectedItemsWazuhResult__merge_str(self_field, other_field, key, expected_result):
    """Test method `_merge_str` from class `AffectedItemsWazuhResult`."""
    affected_result = AffectedItemsWazuhResult()
    merge_result = affected_result._merge_str(self_field, other_field, key=key)
    assert merge_result == expected_result


def test_results_AffectedItemsWazuhResult_encode_decode_json(get_wazuh_affected_item):
    """Test methods `encode_json` and `decode_json` from class `AffectedItemsWazuhResult`."""
    param_list = [['001', '002'], 2, None, ['int'], [True, True], 'Sample message', 'Sample message', 'Sample message']
    affected_result = get_wazuh_affected_item(param_list)
    affected_result.add_failed_item(id_=FAILED_AGENT_ID, error=WazuhException(WAZUH_EXCEPTION_CODE))
    # Use a complete AffectedIemsWazuhResult to encode a json and then decode it
    json_item = affected_result.encode_json()
    decoded_json = AffectedItemsWazuhResult.decode_json(json_item)
    assert affected_result == decoded_json


def test_results_AffectedItemsWazuhResult_render(get_wazuh_affected_item):
    """Test method `render` from class `AffectedItemsWazuhResult`."""
    param_list = [['001', '002'], 2, None, ['int'], [True, True], 'Sample message', 'Sample message', 'Sample message']
    affected_result = get_wazuh_affected_item(param_list)
    for agent_id in [FAILED_AGENT_ID, 'Invalid ID']:
        affected_result.add_failed_item(id_=agent_id, error=WazuhException(WAZUH_EXCEPTION_CODE))
    # Render a valid AffectedItemsWazuhResult and check it has all the expected fields
    render_result = affected_result.render()
    assert isinstance(render_result, dict)
    assert render_result
    assert (field in ['data', 'message'] for field in render_result)
    assert render_result['data']
    assert (field in ['affected_items', 'total_affected_items', 'total_failed_items', 'failed_items']
            for field in render_result['data'])


@pytest.mark.parametrize('item, expressions, expected_result', [
    ({'a': {'b': 3}, 'c.1': 5}, ['a.b', 'c\\.1'], (3, 5)),
    ({'a': {'b': 3}, 'c.1': 5}, ['a.b', 'f'], (3, None)),
    ([{'a': {'b': 3}, 'c.1': 5}], ['c\\.1'], [{'a': {'b': 3}, 'c.1': 5}])
])
def test_results_nested_itemgetter(item, expressions, expected_result):
    """Test function `nested_itemgetter` from module results

    Parameters
    ----------
    item : dict or list
        Dict to get data from. We use a list to force a TypeError.
    expressions : list(str)
        Expressions used to find certain data from `item`.
    expected_result : tuple
        Tuple with the expected result to assert if the function is working properly.
    """
    assert expected_result == nested_itemgetter(*expressions)(item)


@pytest.mark.parametrize('a, b, ascending, casters, expected_result', [
    (['sample'], ['elpmas'], None, None, False),
    (['sample'], ['elpmas'], [False], [list], True),
    (['sample'], ['elpmas'], [True], [str], False),
    (['elpmas'], ['sample'], [True], [None], True),
    ([None], [None], [True], [None], False),
    ([None], ['sample'], [True], [None], True),
    (['sample'], [None], [True], [None], False),
    (['equal'], ['equal'], None, [str], False)
])
def test_results__goes_before_than(a, b, ascending, casters, expected_result):
    """Test function `_goes_before_than` from module results.

    Parameters
    ----------
    a : tuple or list
        Tuple or list to be compared.
    b : tuple or list
        Tuple or list to be compared.
    ascending : list(bool)
        Tuple or list of booleans with a length equal to the minimum length between `a` and `b`. True if ascending,
        False otherwise.
    casters : iterable
        Iterable of callables with a length equal to the minimum length between `a` and `b`. The callable msut fit any
        class in builtins module.
    expected_result : bool
        Expected result after the method call.
    """
    assert _goes_before_than(a, b, ascending=ascending, casters=casters) == expected_result


@pytest.mark.parametrize('iterables, criteria, ascending, types, expected_result', [
    ((['001', '002'], ['003', '004']), None, [True], ['int'], ['001', '002', '003', '004']),
    ((['001', '002'], ['003', '004']), None, [False], ['int'], ['003', '004', '001', '002']),
    ((['001', '002'], ['003', '004']), ['1'], [True], ['int'], ['001', '002', '003', '004']),
])
def test_results_merge(iterables, criteria, ascending, types, expected_result):
    """Test function `merge` from module results.

    Parameters
    ----------
    iterables : list(list) or tuple(list)
        List of lists to be merged.
    criteria : list(str) or tuple(str)
        Expressions accepted by the `nested_itemgetter` function.
    ascending : list(bool) or tuple(bool)
        True for ascending, False otherwise.
    types : list(str) or tuple(str)
        Must fit a class in builtins.
    expected_result : list(str)
        Expected results after merge.
    """
    assert merge(*iterables, criteria=criteria, ascending=ascending, types=types) == expected_result
