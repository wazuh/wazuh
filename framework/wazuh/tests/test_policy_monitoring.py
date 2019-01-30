#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest import TestCase
from unittest.mock import patch

from wazuh import WazuhException
from wazuh.policy_monitoring import WazuhDBQueryPM, get_pm_list

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_pm_data():
    pass

class TestPolicyMonitoring(TestCase):

    def test_wazuhdbquerypm(self):
        with self.assertRaises(WazuhException):
            WazuhDBQueryPM('000', 0, 500, None, None, None, '', True, True)
        with patch('wazuh.common.database_path_agents', test_data_path):
            print()
            query = WazuhDBQueryPM('000', 0, 500, None, None, None, '', True, True)
            assert(isinstance(query, WazuhDBQueryPM))

    @patch('wazuh.policy_monitoring.WazuhDBConnection.__send', side_effect=get_fake_pm_data)
    @patch('wazuh.common.database_path_agents', test_data_path)
    def test_get_pm_list(self, mock1, mock2):
        result = get_pm_list('000')
        assert(result, list)
