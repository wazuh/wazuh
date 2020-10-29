#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.tests.util import InitWDBSocketMock
        from wazuh.ciscat import get_ciscat_results
        from wazuh.core.results import AffectedItemsWazuhResult


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.mark.parametrize('agent_id, exception', [
    (['001'], False),
    (['003'], True)
])
@patch('wazuh.core.common.wdb_path', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results(agents_info_mock, socket_mock, agent_id, exception):
    """Test function `get_ciscat_results` from ciscat module.

    Parameters
    ----------
    agent_id :  list
        List of agent IDs.
    exception : bool
        True if the code will go through an exception. False otherwise.
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_ciscat_test.sql')
        result = get_ciscat_results(agent_id)
        assert isinstance(result, AffectedItemsWazuhResult)
        if not exception:
            assert result.affected_items
            assert result.total_affected_items == 2
            assert result.total_failed_items == 0
        else:
            assert not result.affected_items
            assert result.total_failed_items == 1
            assert result.total_affected_items == 0
