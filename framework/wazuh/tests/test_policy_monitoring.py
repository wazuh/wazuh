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
from wazuh.policy_monitoring import WazuhDBQueryPM, get_pm_list, fields_translation_pm,\
    get_pm_checks, fields_translation_pm_check

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_pm_data(*args, **kwargs):
    assert(isinstance(args[0], str))
    query = re.search(r'^agent \d{3} sql (.+)$', args[0]).group(1)
    try:
        conn = sqlite3.connect(os.path.join(test_data_path, '000.db'))
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        rows = conn.execute(query).fetchall()
        return rows
    finally:
        conn.close()


class TestPolicyMonitoring(TestCase):

    def test_wazuhdbquerypm(self):
        """
        Checks exception is raised when db not found
        """
        with patch('wazuh.common.wdb_path', '/do/not/exists'):
            with self.assertRaises(WazuhException):
                WazuhDBQueryPM('000', 0, 500, None, None, None, '', True, True)
        with patch('wazuh.common.wdb_path', test_data_path):
            print()
            query = WazuhDBQueryPM('000', 0, 500, None, None, None, '', True, True)
            assert(isinstance(query, WazuhDBQueryPM))

    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_list(self):
        """
        Checks data are properly loaded from database
        """
        with patch('wazuh.policy_monitoring.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            result = get_pm_list('000')
            assert(isinstance(result, list))
            assert(len(result) > 0)
            pm = result[0]
            assert(isinstance(pm, dict))
            assert(set(pm.keys()) == set(fields_translation_pm.values()))

    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_list_select_param(self):
        """
        Checks only selected fields are loaded from database
        """
        with patch('wazuh.policy_monitoring.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            fields = {'fields': ['scan_id', 'name']}
            result = get_pm_list('000', select=fields)
            assert (isinstance(result, list))
            assert (len(result) > 0)
            pm = result[0]
            assert (isinstance(pm, dict))
            assert (set(pm.keys()) == set(fields['fields']))

    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_list_search_param(self):
        """
        Checks only selected fields are loaded from database
        """
        with patch('wazuh.policy_monitoring.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            search = {'value': 'Apache', 'negation': False}
            result = get_pm_list('000', search=search)
            assert (isinstance(result, list))
            assert (len(result) > 0)

            search = {'value': 'foo', 'negation': False}
            result = get_pm_list('000', search=search)
            assert (isinstance(result, list))
            assert (len(result) == 0)

            search = {'value': 'foo', 'negation': True}
            result = get_pm_list('000', search=search)
            assert (isinstance(result, list))
            assert (len(result) > 0)

    @patch('wazuh.common.wdb_path', test_data_path)
    def test_get_pm_checks(self):
        """
        Checks pm checks data are properly loaded from database
        """
        with patch('wazuh.policy_monitoring.WazuhDBConnection') as mock_wdb:
            mock_wdb.return_value.execute.side_effect = get_fake_pm_data
            result = get_pm_checks("'CIS Checks for Apache Https Server'", agent_id='000')
            assert(isinstance(result, list))
            assert(len(result) > 0)
            pm = result[0]
            assert(isinstance(pm, dict))
            assert(set(pm.keys()) == set(fields_translation_pm_check.values()) | {'compliance'})
