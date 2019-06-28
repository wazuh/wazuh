#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh import syscollector
from unittest.mock import patch
import pytest
from wazuh import common
import os

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

@pytest.mark.parametrize("agent_id, select, status, older_than, offset, limit", [
    ('001', {'id', 'dateAdd'}, 'all', None, 0, None)
])
@patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
@patch("wazuh.agent.WazuhDBConnection.execute", return_value=[[[] for x in range(9)] for y in range(2)])
@patch("socket.socket.connect", return_value=None)
def test_get_item_agent(mock_connect, mock_exec, agent_id, select, status, older_than, offset, limit):
   syscollector.get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select={},
                         search={}, sort={}, filters={}, allowed_sort_fields={},
                         valid_select_fields={'hostname', 'os_version', 'os_name',
                      'architecture', 'os_major', 'os_minor', 'os_build',
                      'version', 'scan_time', 'scan_id'}, table='sys_osinfo', nested=False)
