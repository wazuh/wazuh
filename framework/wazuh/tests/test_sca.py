#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import call, patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.sca import get_sca_checks, get_sca_list
        from wazuh.core.results import AffectedItemsWazuhResult

        del sys.modules['wazuh.rbac.orm']

# Variables used for the get_sca_checks function test
TEST_SCA_CHECKS_IDS = {'items': [{'id': 1}, {'id': 2}, {'id': 3}], 'totalItems': 100}
TEST_SCA_CHECKS = {'items': [{'id': 1, 'field': 'test1'}, {'id': 2, 'field': 'test2'}, {'id': 3, 'field': 'test3'}],
                   'totalItems': 0}
TEST_SCA_CHECKS_COMPLIANCE = {'items': [{'id_check': 1, 'compliance.key': 'key_1_1', 'compliance.value': 'value_1_1'},
                                        {'id_check': 1, 'compliance.key': 'key_1_2', 'compliance.value': 'value_1_2'},
                                        {'id_check': 2, 'compliance.key': 'key_2_1', 'compliance.value': 'value_2_1'},
                                        {'id_check': 3, 'compliance.key': 'key_3_1', 'compliance.value': 'value_3_1'},
                                        {'id_check': 3, 'compliance.key': 'key_3_2', 'compliance.value': 'value_3_2'},
                                        {'id_check': 3, 'compliance.key': 'key_3_3', 'compliance.value': 'value_3_3'}],
                              'totalItems': 6}
TEST_SCA_CHECKS_RULES = {'items': [{'id_check': 1, 'rules.type': 'type_1_1', 'rules.rule': 'rule_1_1'},
                                   {'id_check': 2, 'rules.type': 'type_2_1', 'rules.rule': 'rule_2_1'},
                                   {'id_check': 2, 'rules.type': 'type_2_2', 'rules.rule': 'rule_2_2'},
                                   {'id_check': 3, 'rules.type': 'type_3_1', 'rules.rule': 'rule_3_1'}],
                         'totalItems': 4}

EXPECTED_SCA_CHECKS_ITEMS = [
    {
        'id': 1,
        'field': 'test1',
        'compliance': [{'key': 'key_1_1', 'value': 'value_1_1'}, {'key': 'key_1_2', 'value': 'value_1_2'}],
        'rules': [{'type': 'type_1_1', 'rule': 'rule_1_1'}]},
    {
        'id': 2,
        'field': 'test2',
        'compliance': [{'key': 'key_2_1', 'value': 'value_2_1'}],
        'rules': [{'type': 'type_2_1', 'rule': 'rule_2_1'}, {'type': 'type_2_2', 'rule': 'rule_2_2'}]},
    {
        'id': 3,
        'field': 'test3',
        'compliance': [{'key': 'key_3_1', 'value': 'value_3_1'}, {'key': 'key_3_2', 'value': 'value_3_2'},
                       {'key': 'key_3_3', 'value': 'value_3_3'}],
        'rules': [{'type': 'type_3_1', 'rule': 'rule_3_1'}]}
]


@patch('wazuh.core.sca.WazuhDBQuerySCA.run', return_value={'items': ['test_items'], 'totalItems': 100})
@patch('wazuh.core.sca.WazuhDBQuerySCA.__exit__')
@patch('wazuh.core.sca.WazuhDBQuerySCA.__init__', return_value=None)
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.sca.get_agents_info', return_value=['000'])
def test_get_sca_list(mock_get_agents_info, mock_get_basic_information, mock_WazuhDBQuerySCA__init__,
                      mock_WazuhDBQuerySCA__exit__, mock_WazuhDBQuerySCA_run):
    """Test that the get_sca_list function works properly."""

    params = {'offset': 5, 'limit': 20, 'sort': {'fields': ['name'], 'order': 'asc'},
              'search': {'negation': False, 'value': 'search_string'}, 'select': ['policy_id', 'name'],
              'distinct': False, 'filters': {'pass': 50}}
    result = get_sca_list(agent_list=['000'], q='name~value', **params)

    mock_WazuhDBQuerySCA__init__.assert_called_once_with(agent_id='000', query='name~value', count=True,
                                                         get_data=True, **params)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ['test_items']
    assert result.total_affected_items == 100


@patch('wazuh.sca.get_agents_info', return_value=[])
def test_get_sca_list_failed_item(mock_get_agents_info):
    """Test that the get_sca_list function works properly when there are failed items."""

    result = get_sca_list(agent_list=['000'])

    code = list(result.failed_items.keys())[0].code
    agent = list(result.failed_items.values())[0]
    assert code == 1701, f'"1701" code was expected but "{code}" was received.'
    assert agent == {'000'}, 'Set of agents IDs {"000"} was expected but ' \
                             f'"{agent}" was received.'
    assert isinstance(result, AffectedItemsWazuhResult)


@patch('wazuh.core.sca.WazuhDBQuerySCACheckRelational.run', side_effect=[TEST_SCA_CHECKS_COMPLIANCE,
                                                                         TEST_SCA_CHECKS_RULES])
@patch('wazuh.core.sca.WazuhDBQuerySCACheckRelational.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuerySCACheck.run', return_value=TEST_SCA_CHECKS)
@patch('wazuh.core.sca.WazuhDBQuerySCACheck.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuerySCACheckIDs.run', return_value=TEST_SCA_CHECKS_IDS)
@patch('wazuh.core.sca.WazuhDBQuerySCACheckIDs.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuery.__exit__')
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.sca.get_agents_info', return_value=['000'])
def test_get_sca_checks(mock_get_agents_info, mock_get_basic_information, mock_WazuhDBQuery__exit__,
                        mock_WazuhDBQuerySCACheckIDs__init__, mock_WazuhDBQuerySCACheckIDs_run,
                        mock_WazuhDBQuerySCACheck__init__, mock_WazuhDBQuerySCACheck_run,
                        mock_WazuhDBQuerySCACheckRelational__init__, mock_WazuhDBQuerySCACheckRelational_run):
    """Test that the get_sca_checks function works and uses each query class properly."""

    # Parameters and function execution
    policy_id, agent_id, offset, limit, filters, search, sort, q, distinct, select = \
        'test_policy_id', '000', 5, 10, {'rationale': 'rationale_test'}, \
        {'negation': False, 'value': 'search_string'}, {'fields': ['title'], 'order': 'asc'}, 'title~test', False, None

    result = get_sca_checks(policy_id=policy_id, agent_list=[agent_id], q=q, offset=offset, limit=limit,
                            sort=sort, search=search, filters=filters, distinct=distinct, select=select)

    # Assertions
    mock_WazuhDBQuerySCACheckIDs__init__.assert_called_once_with(agent_id=agent_id, offset=offset, limit=limit,
                                                                 filters=filters, search=search, query=q,
                                                                 policy_id=policy_id, sort=sort)
    id_check_list = [item['id'] for item in mock_WazuhDBQuerySCACheckIDs_run.return_value['items']]
    mock_WazuhDBQuerySCACheck__init__.assert_called_once_with(agent_id=agent_id, sort=sort, select=select,
                                                              sca_checks_ids=id_check_list)
    mock_WazuhDBQuerySCACheckRelational__init__.assert_has_calls(
        [call(agent_id=agent_id, table='sca_check_compliance', id_check_list=id_check_list, select=select),
         call(agent_id=agent_id, table='sca_check_rules', id_check_list=id_check_list, select=select)], any_order=False)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == EXPECTED_SCA_CHECKS_ITEMS
    assert result.total_affected_items == 100


@patch('wazuh.core.sca.WazuhDBQueryDistinctSCACheck.run', return_value={'items': ['test_items'], 'totalItems': 100})
@patch('wazuh.core.sca.WazuhDBQueryDistinctSCACheck.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuery.__exit__')
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.sca.get_agents_info', return_value=['000'])
def test_get_sca_checks_distinct(mock_get_agents_info, mock_get_basic_information, mock_WazuhDBQuery__exit__,
                                 mock_WazuhDBQueryDistinctSCACheck__init__, mock_WazuhDBQueryDistinctSCACheck_run):
    """Test that the get_sca_checks function works properly when distinct is True."""

    # Parameters and function execution
    policy_id, agent_id, offset, limit, filters, search, sort, q, distinct, select = \
        'test_policy_id', '000', 5, 10, {'rationale': 'rationale_test'}, \
        {'negation': False, 'value': 'search_string'}, {'fields': ['title'], 'order': 'asc'}, 'title~test', True, \
        ['test']

    result = get_sca_checks(policy_id=policy_id, agent_list=[agent_id], q=q, offset=offset, limit=limit,
                            sort=sort, search=search, filters=filters, distinct=distinct, select=select)

    # Assertions
    mock_WazuhDBQueryDistinctSCACheck__init__.assert_called_once_with(agent_id=agent_id, offset=offset, limit=limit,
                                                                      filters=filters, search=search, query=q,
                                                                      policy_id=policy_id, sort=sort, select=select)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == ['test_items']
    assert result.total_affected_items == 100


@pytest.mark.parametrize('select_parameter, exp_select_check, exp_select_compliance, exp_select_rules', [
    (None,
     None, None, None),
    (['title'],
     ['title'], ['id_check'], ['id_check']),
    (['id', 'title'],
     ['id', 'title'], ['id_check'], ['id_check']),
    (['rules.type'],
     [], ['id_check'], ['rules.type', 'id_check']),
    (['rules.rule', 'compliance.key'],
     [], ['compliance.key', 'id_check'], ['rules.rule', 'id_check']),
    (['title', 'description', 'rules.rule', 'compliance.key'],
     ['title', 'description'], ['compliance.key', 'id_check'], ['rules.rule', 'id_check'])
])
@patch('wazuh.core.sca.WazuhDBQuerySCACheckRelational.run')
@patch('wazuh.core.sca.WazuhDBQuerySCACheckRelational.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuerySCACheck.run')
@patch('wazuh.core.sca.WazuhDBQuerySCACheck.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuerySCACheckIDs.run', return_value=TEST_SCA_CHECKS_IDS)
@patch('wazuh.core.sca.WazuhDBQuerySCACheckIDs.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuery.__exit__')
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.sca.get_agents_info', return_value=['000'])
def test_get_sca_checks_select(mock_get_agents_info, mock_get_basic_information, mock_WazuhDBQuery__exit__,
                               mock_WazuhDBQuerySCACheckIDs__init__, mock_WazuhDBQuerySCACheckIDs_run,
                               mock_WazuhDBQuerySCACheck__init__, mock_WazuhDBQuerySCACheck_run,
                               mock_WazuhDBQuerySCACheckRelational__init__, mock_WazuhDBQuerySCACheckRelational_run,
                               select_parameter, exp_select_check, exp_select_compliance, exp_select_rules):
    """Test that the get_sca_checks function works properly when select is used."""

    # Parameters and function execution
    policy_id, agent_id = 'test_policy_id', '000'
    result = get_sca_checks(policy_id=policy_id, agent_list=[agent_id], select=select_parameter)

    # Assertions
    mock_WazuhDBQuerySCACheckIDs__init__.assert_called_once()
    mock_WazuhDBQuerySCACheck__init__.assert_called_once_with(agent_id=agent_id, select=exp_select_check, sort=None,
                                                              sca_checks_ids=[1, 2, 3])

    # Assert WazuhDBQuerySCACheckRelational__init__ was called only when necessary
    calls = []
    if exp_select_compliance and \
            ('compliance.key' in exp_select_compliance or 'compliance.value' in exp_select_compliance):
        calls.append(call(agent_id=agent_id, table="sca_check_compliance", id_check_list=[1, 2, 3],
                          select=exp_select_compliance))
    if exp_select_rules and \
            ('rules.type' in exp_select_rules or 'rules.rule' in exp_select_rules):
        calls.append(call(agent_id=agent_id, table="sca_check_rules", id_check_list=[1, 2, 3],
                          select=exp_select_rules))
    mock_WazuhDBQuerySCACheckRelational__init__.assert_has_calls(calls, any_order=False)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == []
    assert result.total_affected_items == 100


@patch('wazuh.sca.get_agents_info', return_value=[])
def test_get_sca_checks_failed_item(mock_get_agents_info):
    """Test that the get_sca_checks function works properly when there are failed items."""

    result = get_sca_checks(agent_list=['000'])

    code = list(result.failed_items.keys())[0].code
    agent = list(result.failed_items.values())[0]
    assert code == 1701, f'"1701" code was expected but "{code}" was received.'
    assert agent == {'000'}, 'Set of agents IDs {"000"} was expected but ' \
                             f'"{agent}" was received.'
    assert isinstance(result, AffectedItemsWazuhResult)
