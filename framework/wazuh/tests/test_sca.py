#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.sca import get_sca_list, fields_translation_sca, \
            get_sca_checks, fields_translation_sca_check, fields_translation_sca_check_compliance
        from wazuh.core import common, exception
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.core.exception import WazuhResourceNotFound
        from wazuh.tests.util import InitWDBSocketMock

        del sys.modules['wazuh.rbac.orm']


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_sca_data(*args, **kwargs):
    assert isinstance(args[0], str)
    query = re.search(r'^agent \d{3} sql (.+)$', args[0]).group(1)
    sca_db = sqlite3.connect(':memory:')
    try:
        cur = sca_db.cursor()
        with open(os.path.join(test_data_path, 'schema_sca_test.sql')) as f:
            cur.executescript(f.read())
        sca_db.row_factory = lambda c, r: dict(filter(lambda x: x[1] is not None,
                                                      zip([col[0] for col in c.description], r)))
        import logging
        logging.error(query)
        rows = sca_db.execute(query).fetchall()
        if len(rows) > 0 and 'COUNT(*)' in rows[0]:
            return rows[0]['COUNT(*)']
        return rows
    finally:
        sca_db.close()


# Aliases and ` are lost when sqlite db answers...
cols_returned_from_db_sca = [field.replace('`', '').replace('si.', '') for field in fields_translation_sca.keys()]
cols_returned_from_db_sca = [field.split(' as ')[1] if ' as ' in field else
                             field for field in cols_returned_from_db_sca]
cols_returned_from_db_sca_check = [field.replace('`', '').replace('sca.', '')
                                   for field in fields_translation_sca_check.keys()]


@patch("wazuh.core.sca.Agent.get_basic_information")
@patch("wazuh.sca.get_agents_info", return_value={'000'})
def test_get_sca_list(mock_agent, mock_sca_agent):
    """
    Checks data are properly loaded from database
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
        result = get_sca_list(agent_list=['000'])
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        assert len(result['affected_items']) > 0
        sca = result['affected_items'][0]
        assert isinstance(sca, dict)
        assert set(sca.keys()) == set(cols_returned_from_db_sca)

        result = get_sca_list(agent_list=['999'])
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        assert result['total_affected_items'] == 0
        assert len(result['affected_items']) == 0
        assert result['total_failed_items'] == 1
        assert len(result['failed_items']) == 1
        failed = result['failed_items']
        assert isinstance(list(failed.keys())[0], WazuhResourceNotFound)
        assert list(failed.keys())[0].to_dict()['code'] == 1701
        assert failed[list(failed.keys())[0]] == {'999'}


@patch("wazuh.core.sca.Agent.get_basic_information")
@patch("wazuh.sca.get_agents_info", return_value={'000'})
def test_get_sca_list_select_param(mock_agent, mock_sca_agent):
    """
    Checks only selected fields are loaded from database
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
        fields = ['name', 'policy_id']
        result = get_sca_list(agent_list=['000'], select=fields)
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        assert len(result['affected_items']) > 0
        sca = result['affected_items'][0]
        assert isinstance(sca, dict)
        assert set(sca.keys()) == set(fields)


@patch("wazuh.core.sca.Agent.get_basic_information")
@patch("wazuh.sca.get_agents_info", return_value={'000'})
def test_get_sca_list_search_param(mock_agent, mock_sca_agent):
    """
    Checks only selected fields are loaded from database
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
        search = {'value': 'debian', 'negation': False}
        result = get_sca_list(agent_list=['000'], search=search)
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        assert len(result['affected_items']) > 0

        search = {'value': 'foo', 'negation': False}
        result = get_sca_list(agent_list=['000'], search=search)
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        assert len(result['affected_items']) == 0

        search = {'value': 'foo', 'negation': True}
        result = get_sca_list(agent_list=['000'], search=search)
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        assert len(result['affected_items']) > 0


@patch("wazuh.core.sca.Agent.get_basic_information")
@patch("wazuh.sca.get_agents_info", return_value={'000'})
def test_get_sca_checks(mock_agent, mock_sca_agent):
    """
    Checks sca checks data are properly loaded from database
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
        result = get_sca_checks('cis_debian', agent_list=['000'])
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        sca = result['affected_items']
        assert isinstance(sca, list)
        assert len(sca) > 0
        assert set(sca[0].keys()).issubset(set(fields_translation_sca_check.keys()) | {'compliance', 'rules'})

        compliance = sca[0]['compliance']
        assert isinstance(compliance, list)
        assert len(compliance) > 0
        assert set(compliance[0].keys()) == set(fields_translation_sca_check_compliance.values())

        # Check 0 result
        result = get_sca_checks('not_exists', agent_list=['000'])
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        sca = result['affected_items']
        assert isinstance(sca, list)
        assert len(sca) == 0

        result = get_sca_checks('cis_debian', agent_list=['999'])
        assert isinstance(result, AffectedItemsWazuhResult)
        result = result.to_dict()
        assert isinstance(result['total_affected_items'], int)
        assert result['total_affected_items'] == 0
        assert len(result['affected_items']) == 0
        assert result['total_failed_items'] == 1
        assert len(result['failed_items']) == 1
        failed = result['failed_items']
        assert isinstance(list(failed.keys())[0], WazuhResourceNotFound)
        assert list(failed.keys())[0].to_dict()['code'] == 1701
        assert failed[list(failed.keys())[0]] == {'999'}


@patch("wazuh.core.sca.Agent.get_basic_information")
@patch("wazuh.sca.get_agents_info", return_value={'000'})
def test_sca_checks_select_and_q(mock_agent, mock_sca_agent):
    """
    Tests filtering using q parameter and selecting multiple fields
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
        result = get_sca_checks('cis_debian', agent_list=['000'], q="rules.type!=file",
                                select=['compliance', 'policy_id', 'result', 'rules']).to_dict()
        assert result['affected_items'][0]['rules'][0]['type'] != 'file'
        assert set(result['affected_items'][0].keys()).issubset({'compliance', 'policy_id', 'result', 'rules'})


@patch("wazuh.core.sca.Agent.get_basic_information")
@patch("wazuh.sca.get_agents_info", return_value={'000'})
def test_sca_failed_limit(mock_agent, mock_sca_agent):
    """
    Test failing using not correct limits
    """
    with patch('wazuh.core.sca.WazuhDBBackend') as mock_wdb:
        mock_wdb.return_value.connect_to_db.return_value.execute.side_effect = get_fake_sca_data
        with pytest.raises(exception.WazuhException, match=".* 1405 .*"):
            get_sca_list(agent_list=['000'], limit=common.maximum_database_limit + 1)

        with pytest.raises(exception.WazuhException, match=".* 1406 .*"):
            get_sca_list(agent_list=['000'], limit=0)


@patch("wazuh.core.sca.Agent.get_basic_information")
@patch("wazuh.sca.get_agents_info", return_value={'000'})
def test_sca_response_without_result(mock_agent, mock_sca_agent):
    """
    Test failing when WazuhDB don't return 'items' key into result
    """
    with patch('wazuh.core.sca.WazuhDBBackend') as mock_wdb:
        mock_wdb.return_value.connect_to_db.return_value.execute.side_effect = get_fake_sca_data
        with patch('wazuh.core.sca.WazuhDBQuerySCA.run', return_value={}):
            with pytest.raises(exception.WazuhException, match=".* 2007 .*"):
                get_sca_checks('not_exists', agent_list=['000'])
