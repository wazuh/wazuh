#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from functools import wraps
from unittest.mock import patch, MagicMock

import pytest

from wazuh import WazuhError

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        def RBAC_bypasser(**kwargs):
            def decorator(f):
                @wraps(f)
                def wrapper(*args, **kwargs):
                    return f(*args, **kwargs)
                return wrapper
            return decorator
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.syscheck import run, clear
        from wazuh.syscheck import AffectedItemsWazuhResult


def raise_wazuh_error(*mock_args, **mock_kwargs):
    raise WazuhError(1000)


def set_callable_list(mock_param_1, mock_param_2):
    callable_list.append((mock_param_1, mock_param_2))


callable_list = list()

test_result = [
    {'affected_items': ['001', '002'], 'total_affected_items': 2, 'failed_items': {}, 'total_failed_items': 0},
    {'affected_items': ['003', '008'], 'total_affected_items': 2, 'failed_items': {'001'}, 'total_failed_items': 1},
    {'affected_items': ['001'], 'total_affected_items': 1, 'failed_items': {'002', '003'},
     'total_failed_items': 2},
    # This result is used for exceptions
    {'affected_items': [], 'total_affected_items': 0, 'failed_items': {'001'}, 'total_failed_items': 1},
]


@pytest.mark.parametrize('agent_list, status_list, expected_result', [
    (['002', '001'], [{'status': status} for status in ['active', 'active']], test_result[0]),
    (['003', '001', '008'], [{'status': status} for status in ['active', 'disconnected', 'active']], test_result[1]),
    (['001', '002', '003'], [{'status': status} for status in ['active', 'disconnected', 'disconnected']],
     test_result[2]),
])
@patch('wazuh.syscheck.OssecQueue._connect')
@patch('wazuh.syscheck.OssecQueue.send_msg_to_agent', side_effect=set_callable_list)
@patch('wazuh.syscheck.OssecQueue.close')
def test_syscheck_run(mock_connect, mock_send, mock_close, agent_list, status_list, expected_result):
    with patch('wazuh.syscheck.Agent.get_basic_information', side_effect=status_list):
        result = run(agent_list=agent_list)
        for parameters in callable_list:
            assert (isinstance(p, str) for p in parameters)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_list, status_list, expected_result', [
    (['001'], [{'status': 'active'}], test_result[3])
])
@patch('wazuh.syscheck.OssecQueue', side_effect=raise_wazuh_error)
def test_syscheck_run_exception(mock_OssecQueue, agent_list, status_list, expected_result):
    with patch('wazuh.syscheck.Agent.get_basic_information', side_effect=status_list):
        result = run(agent_list=agent_list)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_list, expected_result, agent_info_list', [
    (['001', '002'], test_result[0], ['001', '002']),
    (['003', '001', '008'], test_result[1], ['003', '008'])
])
@patch('wazuh.wdb.WazuhDBConnection.__init__', return_value=None)
@patch('wazuh.wdb.WazuhDBConnection.execute', return_value=None)
def test_syscheck_clear(mock_wdb, mock_wdb_execute, agent_list, expected_result, agent_info_list):
    with patch('wazuh.syscheck.get_agents_info', return_value=agent_info_list):
        result = clear(agent_list=agent_list)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_list, expected_result, agent_info_list', [
    (['001'], test_result[3], ['001']),
])
@patch('wazuh.wdb.WazuhDBConnection.__init__', return_value=None)
@patch('wazuh.wdb.WazuhDBConnection.execute', side_effect=raise_wazuh_error)
def test_syscheck_clear_exception(mock_wdb, mock_execute, agent_list, expected_result, agent_info_list):
    with patch('wazuh.syscheck.get_agents_info', return_value=agent_info_list):
        result = clear(agent_list=agent_list)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']
