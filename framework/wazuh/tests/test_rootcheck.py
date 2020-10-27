#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock, call

import pytest

from wazuh.core.exception import WazuhError

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['api'] = MagicMock()
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import rootcheck
        from wazuh.core.rootcheck import fields
        from wazuh.core.tests.test_rootcheck import InitRootcheck, send_msg_to_wdb

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_data = InitRootcheck()


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=[None, None, WazuhError(2004)])
@patch('wazuh.rootcheck.get_agents_info', return_value=['000', '001', '002'])
@patch('socket.socket.connect')
def test_clear(mock_connect, mock_info, mock_wdbconn):
    """Test if function clear() returns expected result and if delete command is executed.

    The databases of 4 agents are requested to be cleared, 3 of them exists.
    Is expected 2 failed items:
        - 1 non existent agent
        - 1 exception when running execute() method.
    """
    result = rootcheck.clear(['000', '001', '002', '003']).render()

    assert result['data']['affected_items'] == ['000', '001']
    assert result['data']['total_affected_items'] == 2
    assert result['data']['total_failed_items'] == 2
    mock_wdbconn.assert_has_calls([call('agent 000 rootcheck delete'), call('agent 001 rootcheck delete')])


@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_last_scan(mock_connect, mock_send, mock_info):
    """Check if get_last_scan() returned results have expected format and content"""
    result = rootcheck.get_last_scan(['001']).render()['data']['affected_items'][0]
    assert result['start'] == '2020-10-27 12:19:40' and result['end'] == '2020-10-27 12:29:40'


@pytest.mark.parametrize('limit', [
    1, 3, None
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent(mock_connect, mock_send, mock_info, limit):
    """Check if returned information have correct format"""
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], limit=limit, filters={'status': 'all'}).render()['data']
    limit = limit if limit else 6
    assert len(result['affected_items']) == limit and result['total_affected_items'] == 6
    assert len(result['failed_items']) == 0 and result['total_failed_items'] == 0

    # Check returned keys are allowed (they exist in core/rootcheck -> fields)
    for item in result['affected_items']:
        for key in item.keys():
            assert key in fields


@pytest.mark.parametrize('select', [
    ['log'], ['log', 'pci_dss'], ['status'], None
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent_select(mock_connect, mock_send, mock_info, select):
    """Check if returned information have correct format"""
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], select=select, filters={'status': 'all'}).render()['data']
    select = select if select else list(fields.keys())

    # Check returned keys are specified inside 'select' field
    for item in result['affected_items']:
        for key in item.keys():
            assert key in select


# TODO:
#  - search
#  - sort
#  - query
#  - distinct
