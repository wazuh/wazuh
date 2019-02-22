#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
from unittest import TestCase
from unittest.mock import patch

from wazuh import WazuhException
from wazuh.security_configuration_assessment import WazuhDBQuerySCA, get_sca_list, fields_translation_sca,\
    get_sca_checks, fields_translation_sca_check, fields_translation_sca_check_compliance

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_sca_data(*args, **kwargs):
    assert(isinstance(args[0], str))
    query = re.search(r'^agent \d{3} sql (.+)$', args[0]).group(1)
    try:
        conn = sqlite3.connect(os.path.join(test_data_path, '000.db'))
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        import logging
        logging.error(query)
        rows = conn.execute(query).fetchall()
        if len(rows) > 0 and 'COUNT(*)' in rows[0]:
            return rows[0]['COUNT(*)']
        return rows
    finally:
        conn.close()


# Aliases and ` are lost when sqlite db answers...
cols_returned_from_db_sca = [field.replace('`', '').replace('si.', '') for field in fields_translation_sca.values()]
cols_returned_from_db_sca = [field.split(' as ')[1] if ' as ' in field else field for field in cols_returned_from_db_sca]
cols_returned_from_db_sca_check = [field.replace('`', '').replace('sca.', '') for field in fields_translation_sca_check.values()]


class TestPolicyMonitoring(TestCase):

    @patch('socket.socket')
    def test_wazuhdbquerysca(self, mock):
        """
        Checks exception is raised when db not found
        """
        with patch('wazuh.common.wdb_path', '/do/not/exists'):
            with self.assertRaises(WazuhException):
                WazuhDBQuerySCA('000', 0, 500, None, None, None, '', True, True)
        with patch('wazuh.common.wdb_path', test_data_path):
            query = WazuhDBQuerySCA('000', 0, 500, None, None, None, '', True, True)
            assert(isinstance(query, WazuhDBQuerySCA))

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_sca_list(self, mock):
        """
        Checks data are properly loaded from database
        """
        with patch('wazuh.security_configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_sca_data
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
        with patch('wazuh.security_configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_sca_data
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
        with patch('wazuh.security_configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_sca_data
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
        with patch('wazuh.security_configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_sca_data
            result = get_sca_checks('cis_debian', agent_id='000')
            assert(isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            sca = result['items']
            assert(isinstance(sca, list))
            assert(len(sca) > 0)
            assert(set(sca[0].keys()) == set(cols_returned_from_db_sca_check) | {'compliance'})

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
