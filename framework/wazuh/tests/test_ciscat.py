# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest
from .util import InitWDBSocketMock, test_data_path

from wazuh import ciscat


@pytest.fixture(scope='module')
def test_data():
    return InitWDBSocketMock(sql_schema_file='schema_ciscat_test.sql')


@patch('wazuh.syscollector.Agent')
@patch('wazuh.common.wdb_path', test_data_path)
@patch('socket.socket')
def test_print_db(socket_mock, agent_mock, test_data):
    """
    Tests getting ciscat database with default parameters
    """
    agent_mock.get_agents_overview.return_value = {'totalItems': 1, 'items': [{'id': '001'}]}
    with patch('wazuh.utils.WazuhDBConnection') as mock_db:
        mock_db.return_value = test_data

        results = ciscat.get_results_agent(agent_id='001')
        assert results['totalItems'] == 2
