#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from copy import deepcopy
from unittest.mock import patch

import pytest

from wazuh import WazuhException, WazuhInternalError, WazuhError

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.results import WazuhResult, AffectedItemsWazuhResult, _goes_before_than, nested_itemgetter


@pytest.mark.parametrize('dikt, priority', [
    ({"data": {"items": [{"item1": "data1"}, {"item2": "OK"}], "message": "Everything ok"}}, ['KO', 'OK']),
    ({"data": {"items": [{"item1": "data1"}, {"item2": "data2"}], "message": "Everything ok"}}, None),
])
def test_results_WazuhResult(dikt, priority):
    """Test class `WazuhResult` from results module.

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
    assert wazuh_result.to_dict() == {'str_priority': priority, 'result': dikt}
    assert wazuh_result.render() == dikt
    decode_result = wazuh_result.decode_json({'result': {'resultado': 1}, 'str_priority': ['prioridad']})
    assert (key in decode_result.dikt for key in ['dikt', 'priority'])
    assert isinstance(decode_result, WazuhResult)


param_name = ['affected_items', 'total_affected_items', 'sort_fields', 'sort_casting', 'sort_ascending',
                  'all_msg', 'some_msg', 'none_msg']


@pytest.mark.parametrize('param_value', [
    # affected_items,total_affected_items, sort_fields, sort_casting, sort_ascending,
    # all_msg, some_msg, none_msg
    [['001', '002'], 2, param_name, ['int'], [True, True], 'Sample message', 'Sample message', 'Sample message'],
    [['001', '003'], None, param_name, ['int'], [True, False], 'Sample message', 'Sample message', 'Sample message'],
    [[], 0, None, ['int'], None, 'Sample message', 'Sample message', 'Sample message'],
    [['001'], None, param_name, ['str'], None, 'Sample message', 'Sample message', 'Sample message']
])
def test_results_AffectedItemsWazuhResult(param_value):
    """Test class `AffectedItemsWazuhResult` from results module.

    Parameters
    ----------
    param_value : list
        List with all the values to be applied to the class declaration.
    """
    kwargs = {p_name: param for p_name, param in zip(param_name, param_value)}
    failed_result = AffectedItemsWazuhResult(affected_items=['005'], total_affected_items=1)
    failed_items = ['009', '010']
    exception_code = 1000

    for failed_id in failed_items:
        failed_result.add_failed_item(id_=failed_id, error=WazuhException(exception_code))
    affected_result = AffectedItemsWazuhResult()
    for key, value in kwargs.items():
        setattr(affected_result, key, value)
        assert kwargs[key] == getattr(affected_result, key)
    assert isinstance(affected_result, AffectedItemsWazuhResult)
    assert affected_result.affected_items == kwargs['affected_items']
    affected_result.total_affected_items = len(kwargs['affected_items'])
    assert affected_result.total_affected_items == len(kwargs['affected_items'])
    assert affected_result.total_failed_items == 0
    affected_result.add_failed_items_from(failed_result)
    if affected_result.message:
        assert affected_result.message == 'Sample message'
    with pytest.raises(WazuhException):
        affected_result.add_failed_items_from('This is not a valid object')
    assert affected_result.total_failed_items == len(failed_items)
    assert next(iter(affected_result.failed_items.values())) == set(failed_items)
    for key in kwargs.keys():
        assert key in affected_result.to_dict().keys()
    failed_result.remove_failed_items({exception_code})
    assert not failed_result.failed_items
    or_result = affected_result | failed_result
    assert isinstance(or_result, AffectedItemsWazuhResult)
    assert (agent_id in set(affected_result.affected_items + failed_result.affected_items)
            for agent_id in or_result.affected_items)
    assert or_result.total_affected_items == len(or_result.affected_items)
    assert (fail_item in set(affected_result.failed_items + failed_result.failed_items)
            for fail_item in or_result.failed_items)
    assert affected_result._merge_str('sample one', 'sample two', 'older_than') == 'sample one'
    assert affected_result._merge_str('sample one', 'sample two') == 'sample one|sample two'
    assert affected_result == affected_result.decode_json(affected_result.encode_json())
    rendered_result = affected_result.render()
    assert (field in rendered_result['data'] for field in
            ['affected_items', 'total_affected_items', 'total_failed_items', 'failed_items'])


@pytest.mark.parametrize('or_type, expected_result', [
    (WazuhError(code=1000), WazuhException),
    (WazuhError(code=1000, ids={'001', '002'}), AffectedItemsWazuhResult),
    (WazuhException(code=1000), WazuhException),
    ('Invalid type', None),
    ({}, None)
])
def test_results_exceptions(or_type, expected_result):
    """Test exceptions from `AffectedItemsWazuhResult.__or__`

    Parameters
    ----------
    or_type : WazuhException or WazuhError or set or str
        Object type that will be passed to the or operator.
    expected_result : WazuhException or AffectedItemsWazuhResult or None
        Expected result after the `or` operation. It depends on the exception.
    """
    affected_result = AffectedItemsWazuhResult()
    or_exception = None
    if isinstance(or_type, (WazuhException, AffectedItemsWazuhResult)):
        or_exception = affected_result | or_type
    else:
        with pytest.raises(WazuhInternalError):
            or_exception = affected_result | or_type
        return

    assert isinstance(or_exception, expected_result)


def test_results_render_exception():
    """Test exception from `render` method.

    This will expect a sorted list by ids without `key=int`.
    """
    except_render_result = AffectedItemsWazuhResult()
    id_list = ['a', 'c', 'b']
    for agent_id in id_list:
        except_render_result.add_failed_item(agent_id, WazuhException(1000))
    rended = except_render_result.render()
    assert rended['data']['failed_items'][0]['id'] == sorted(id_list)


@pytest.mark.parametrize('item, expressions, expected_result', [
    ({'a': {'b': 3}, 'c.1': 5}, ['a.b', 'c\\.1'], (3, 5)),
    ({'a': {'b': 3}, 'c.1': 5}, ['a.b', 'f'], (3, None)),
    ([{'a': {'b': 3}, 'c.1': 5}], ['c\\.1'], [{'a': {'b': 3}, 'c.1': 5}])
])
def test_results_nested_itemgetter(item, expressions, expected_result):
    """Test function `nested_itemgetter` from results module.

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
    """Test function `_goes_before_than` from results module.

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
    assert _goes_before_than(a, b, ascending=ascending, casters=casters) is expected_result
