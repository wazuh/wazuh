#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
import pytest
from wazuh import exception, common
from unittest import TestCase
from unittest.mock import patch
from .util import InitWDBSocketMock

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.security_configuration_assessment import WazuhDBQuerySCA, get_sca_list, fields_translation_sca,\
            get_sca_checks, fields_translation_sca_check, fields_translation_sca_check_compliance
        from wazuh import WazuhException

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_sca_data(*args, **kwargs):
    assert(isinstance(args[0], str))
    query = re.search(r'^agent \d{3} sql (.+)$', args[0]).group(1)
    sca_db = sqlite3.connect(':memory:')
    try:
        cur = sca_db.cursor()
        with open(os.path.join(test_data_path, 'schema_sca_test.sql')) as f:
            cur.executescript(f.read())
        sca_db.row_factory = lambda c, r: dict(filter(lambda x: x[1] is not None, zip([col[0] for col in c.description], r)))
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
cols_returned_from_db_sca = [field.split(' as ')[1] if ' as ' in field else field for field in cols_returned_from_db_sca]
cols_returned_from_db_sca_check = [field.replace('`', '').replace('sca.', '') for field in fields_translation_sca_check.keys()]


@patch("wazuh.security_configuration_assessment.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
class TestPolicyMonitoring(TestCase):

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_sca_list(self, mock):
        """
        Checks data are properly loaded from database
        """
        with patch('wazuh.utils.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
            result = get_sca_list('000')
            assert(isinstance(result, dict))
            assert('totalItems' in result)
            assert(isinstance(result['totalItems'], int))
            assert('items' in result)
            assert(len(result['items']) > 0)
            sca = result['items'][0]
            assert(isinstance(sca, dict))
            assert(set(sca.keys()) == set(cols_returned_from_db_sca))

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_sca_list_select_param(self, mock):
        """
        Checks only selected fields are loaded from database
        """
        with patch('wazuh.utils.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
            fields = {'fields': ['name', 'policy_id']}
            result = get_sca_list('000', select=fields)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) > 0)
            sca = result['items'][0]
            assert (isinstance(sca, dict))
            assert (set(sca.keys()) == set(fields['fields']))

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_sca_list_search_param(self, mock):
        """
        Checks only selected fields are loaded from database
        """
        with patch('wazuh.utils.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
            search = {'value': 'debian', 'negation': False}
            result = get_sca_list('000', search=search)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) > 0)

            search = {'value': 'foo', 'negation': False}
            result = get_sca_list('000', search=search)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) == 0)

            search = {'value': 'foo', 'negation': True}
            result = get_sca_list('000', search=search)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) > 0)

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_sca_checks(self, mock):
        """
        Checks sca checks data are properly loaded from database
        """
        with patch('wazuh.utils.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
            result = get_sca_checks('cis_debian', agent_id='000')
            assert(isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            sca = result['items']
            assert(isinstance(sca, list))
            assert(len(sca) > 0)
            assert(set(sca[0].keys()).issubset(set(fields_translation_sca_check.keys()) | {'compliance', 'rules'}))

            compliance = sca[0]['compliance']
            assert(isinstance(compliance, list))
            assert(len(compliance) > 0)
            assert(set(compliance[0].keys()) == set(fields_translation_sca_check_compliance.values()))

            # Check 0 result
            result = get_sca_checks('not_exists', agent_id='000')
            assert(isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            sca = result['items']
            assert(isinstance(sca, list))
            assert(len(sca) == 0)

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_sca_checks_select_and_q(self, mock):
        """
        Tests filtering using q parameter and selecting multiple fields
        """
        with patch('wazuh.utils.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_sca_test.sql')
            result = get_sca_checks('cis_debian', agent_id='000', q="rules.type!=file",
                                    select={'fields': ['compliance', 'policy_id', 'result', 'rules']})
            assert result['items'][0]['rules'][0]['type'] != 'file'
            assert set(result['items'][0].keys()).issubset({'compliance', 'policy_id', 'result', 'rules'})

    def test_sca_failed_limit(self):
        """
        Test failing using not correct limits
        """
        with patch('wazuh.security_configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_sca_data
            with pytest.raises(exception.WazuhException, match=".* 1405 .*"):
                get_sca_list(agent_id='000', limit=common.maximum_database_limit+1)

            with pytest.raises(exception.WazuhException, match=".* 1406 .*"):
                get_sca_list(agent_id='000', limit=0)

    def test_sca_response_without_result(self):
        """
        Test failing when WazuhDB don't return 'items' key into result
        """
        with patch('wazuh.security_configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_sca_data
            with patch('wazuh.security_configuration_assessment.WazuhDBQuerySCA.run', return_value={}):
                with pytest.raises(exception.WazuhException, match=".* 2007 .*"):
                    get_sca_checks('not_exists', agent_id='000')

