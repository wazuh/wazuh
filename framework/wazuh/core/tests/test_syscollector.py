#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from functools import wraps
from unittest.mock import patch, MagicMock
from wazuh.tests.util import InitWDBSocketMock

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        sys.modules['api'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        def RBAC_bypasser(**kwargs_decorator):
            def decorator(f):
                @wraps(f)
                def wrapper(*args, **kwargs):
                    return f(*args, **kwargs)
                return wrapper
            return decorator
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.syscollector import *
        from wazuh import common


# Tests

@pytest.mark.parametrize("os_name", [
    'Windows',
    'Linux'
])
@patch('wazuh.core.core_agent.Agent.get_basic_information')
def test_get_valid_fields(mock_info, os_name):
    """Check get_valid_fields returns expected type and content

    Parameters
    ----------
    os_name : str
        Request information of this OS.
    """
    with patch('wazuh.core.core_agent.Agent.get_agent_attr', return_value=os_name):
        response = get_valid_fields(Type.OS, '0')
        assert isinstance(response, tuple) and isinstance(response[1], dict), 'Data type not expected'
        assert 'sys_osinfo' in response[0], f'"sys_osinfo" not contained in {response}'


@patch("wazuh.syscollector.get_agents_info", return_value=['000', '001'])
@patch("wazuh.core.core_agent.Agent.get_basic_information", return_value=None)
@patch('wazuh.core.core_agent.Agent.get_agent_attr', return_value='Linux')
def test_WazuhDBQuerySyscollector(mock_agent_attr, mock_basic_info, mock_agents_info):
    """Verify that the method connects correctly to the database and returns the correct type."""
    with patch('wazuh.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_syscollector_000.sql')
        db_query = WazuhDBQuerySyscollector(agent_id='000', offset=0, limit=common.database_limit, select=None,
                                            search=None, sort=None, filters=None,
                                            fields=get_valid_fields(Type.OS, '000')[1], table='sys_osinfo',
                                            array=True, nested=True, query='')
        db_query._filter_status(None)
        data = db_query.run()
        assert isinstance(db_query, WazuhDBQuerySyscollector) and isinstance(data, dict)
