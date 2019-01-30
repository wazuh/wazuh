#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest import TestCase
from unittest.mock import patch

from wazuh import WazuhException
from wazuh.policy_monitoring import WazuhDBQueryPM, get_pm_list


class TestPolicyMonitoring(TestCase):

    def test_wazuhdbquerypm(self):
        with self.assertRaises(WazuhException):
            WazuhDBQueryPM()
        with patch('wazuh.common.database_path_agents', './wazuh/tests/data'):
            query = WazuhDBQueryPM()
            assert(isinstance(query, WazuhDBQueryPM))

    def test_get_pm_list(self):
        with patch('wazuh.common.database_path_agents', './wazuh/tests/data'):
            result = get_pm_list('000')
            assert(result, list)
