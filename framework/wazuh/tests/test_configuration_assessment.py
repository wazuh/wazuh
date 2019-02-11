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
from wazuh.configuration_assessment import WazuhDBQueryPM, get_ca_list, fields_translation_ca,\
    get_ca_checks, fields_translation_ca_check, fields_translation_ca_check_compliance

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_pm_data(*args, **kwargs):
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
cols_returned_from_db_pm = [field.replace('`', '').replace('si.', '') for field in fields_translation_ca.values()]
cols_returned_from_db_pm_check = [field.replace('`', '').replace('ca.', '') for field in fields_translation_ca_check.values()]


class TestPolicyMonitoring(TestCase):

    @patch('socket.socket')
    def test_wazuhdbquerypm(self, mock):
        """
        Checks exception is raised when db not found
        """
        with patch('wazuh.common.wdb_path', '/do/not/exists'):
            with self.assertRaises(WazuhException):
                WazuhDBQueryPM('000', 0, 500, None, None, None, '', True, True)
        with patch('wazuh.common.wdb_path', test_data_path):
            query = WazuhDBQueryPM('000', 0, 500, None, None, None, '', True, True)
            assert(isinstance(query, WazuhDBQueryPM))

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_list(self, mock):
        """
        Checks data are properly loaded from database
        """
        with patch('wazuh.configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            result = get_ca_list('000')
            assert(isinstance(result, dict))
            assert('totalItems' in result)
            assert(isinstance(result['totalItems'], int))
            assert('items' in result)
            assert(len(result['items']) > 0)
            pm = result['items'][0]
            assert(isinstance(pm, dict))
            assert(set(pm.keys()) == set(cols_returned_from_db_pm))

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_list_select_param(self, mock):
        """
        Checks only selected fields are loaded from database
        """
        with patch('wazuh.configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            fields = {'fields': ['name', 'policy_id']}
            result = get_ca_list('000', select=fields)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) > 0)
            pm = result['items'][0]
            assert (isinstance(pm, dict))
            assert (set(pm.keys()) == set(fields['fields']))

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_list_search_param(self, mock):
        """
        Checks only selected fields are loaded from database
        """
        with patch('wazuh.configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            search = {'value': 'debian', 'negation': False}
            result = get_ca_list('000', search=search)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) > 0)

            search = {'value': 'foo', 'negation': False}
            result = get_ca_list('000', search=search)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) == 0)

            search = {'value': 'foo', 'negation': True}
            result = get_ca_list('000', search=search)
            assert (isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            assert (len(result['items']) > 0)

    @patch('socket.socket')
    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_checks(self, mock):
        """
        Checks pm checks data are properly loaded from database
        """
        with patch('wazuh.configuration_assessment.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            result = get_ca_checks('cis_debian', agent_id='000')
            assert(isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            pm = result['items']
            assert(isinstance(pm, list))
            assert(len(pm) > 0)
            assert(set(pm[0].keys()) == set(cols_returned_from_db_pm_check) | {'compliance'})

            compliance = pm[0]['compliance']
            assert(isinstance(compliance, list))
            assert(len(compliance) > 0)
            assert(set(compliance[0].keys()) == set(fields_translation_ca_check_compliance.values()))

            # Check 0 result
            result = get_ca_checks('not_exists', agent_id='000')
            assert(isinstance(result, dict))
            assert ('totalItems' in result)
            assert (isinstance(result['totalItems'], int))
            assert ('items' in result)
            pm = result['items']
            assert(isinstance(pm, list))
            assert(len(pm) == 0)
